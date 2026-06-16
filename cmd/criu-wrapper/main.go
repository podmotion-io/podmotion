// podmotion-criu-wrapper: ADR-0181 cgroup fd delivery shim.
//
// The exec chain is:
//   agent (Go) → nsenter --mount=<hostMntNS> -- podmotion-criu-wrapper --cgroup-fd=N:path … -- /usr/sbin/criu restore …
//
// Problem (ADR-0180 → ADR-0181): Go's cmd.ExtraFiles places the agent-held cgroup fds at
// child fd 3+i in the forked process — but the forked process is nsenter, not criu. nsenter
// opens its own descriptors (e.g. /proc/<pid>/ns/mnt for setns) starting at fd 3, displacing
// the cgroup fds Go placed there before nsenter execve()s into criu.
//
// Fix: nsenter execve()s this wrapper instead of criu directly. The wrapper runs entirely
// inside the already-joined host mount namespace. It opens each cgroup file fresh in its own
// fd table (nsenter's internal opens are already done and cannot displace them), dup3s each
// to the exact target fd number N, then execve()s criu with all --inherit-fd args unchanged.
// The wrapper owns and releases the cgroup fds; the agent holds none.
//
// OC-2 compliance: all opens happen in PHASE 1 (collect tmp fds), all dup3s in PHASE 2
// (place at target N), no interleaving. This makes placement order-independent.
//
// OC-3 compliance: temporaries use O_CLOEXEC; dup3 with flags=0 deposits N without
// O_CLOEXEC (so it survives execve). A sweep over /proc/self/fd sets FD_CLOEXEC on every
// inherited fd not in {0,1,2} ∪ {target Ns}.
//
// On any open failure: write to stderr and _exit(127) — never exec criu with a missing fd.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	args := os.Args[1:] // strip argv[0]

	// Parse --cgroup-fd=N:path arguments until we see "--".
	// Everything after "--" is the criu argv (argv[0] is the criu binary path).
	var cgroupFdSpecs []struct {
		targetN int
		path    string
	}
	separatorIdx := -1
	for i, a := range args {
		if a == "--" {
			separatorIdx = i
			break
		}
		const prefix = "--cgroup-fd="
		if !strings.HasPrefix(a, prefix) {
			// Unknown flag before "--": treat as start of criu argv (tolerate bare criu invocation).
			separatorIdx = i
			break
		}
		val := a[len(prefix):]
		colonIdx := strings.IndexByte(val, ':')
		if colonIdx < 0 {
			fmt.Fprintf(os.Stderr, "podmotion-criu-wrapper: malformed --cgroup-fd %q (expected N:path)\n", a)
			os.Exit(127)
		}
		n, err := strconv.Atoi(val[:colonIdx])
		if err != nil || n < 3 {
			fmt.Fprintf(os.Stderr, "podmotion-criu-wrapper: invalid fd number in --cgroup-fd %q (must be >= 3): %v\n", a, err)
			os.Exit(127)
		}
		cgroupFdSpecs = append(cgroupFdSpecs, struct {
			targetN int
			path    string
		}{n, val[colonIdx+1:]})
	}

	if separatorIdx < 0 {
		fmt.Fprintf(os.Stderr, "podmotion-criu-wrapper: missing \"--\" separator before criu argv\n")
		os.Exit(127)
	}
	// criuArgv is everything after "--": criuArgv[0] is the binary path.
	criuArgv := args[separatorIdx+1:]
	if len(criuArgv) == 0 {
		fmt.Fprintf(os.Stderr, "podmotion-criu-wrapper: no criu binary path after \"--\"\n")
		os.Exit(127)
	}
	criuBin := criuArgv[0]

	// OC-2 PHASE 1: open every cgroup file into a temporary high fd (O_RDONLY|O_CLOEXEC).
	// Collect (tmpFd, targetN) pairs. NO dup3 in this loop.
	type pair struct {
		tmp     int
		targetN int
	}
	var pairs []pair

	// Build a set of target Ns for the fd-table cleanliness sweep (OC-3).
	targetSet := make(map[int]bool, len(cgroupFdSpecs))
	for _, spec := range cgroupFdSpecs {
		targetSet[spec.targetN] = true
	}

	for _, spec := range cgroupFdSpecs {
		// Open into whatever fd the OS gives us (will be low; that is fine because we have
		// not placed any target N yet — no displacement risk in Phase 1).
		fd, err := syscall.Open(spec.path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "podmotion-criu-wrapper: open %q for fd[%d]: %v\n", spec.path, spec.targetN, err)
			// Close any already-opened temps before exiting.
			for _, p := range pairs {
				_ = syscall.Close(p.tmp)
			}
			os.Exit(127)
		}
		pairs = append(pairs, pair{fd, spec.targetN})
	}

	// OC-2 PHASE 2: for each (tmp, N), dup3(tmp, N, 0) to place at target N WITHOUT
	// O_CLOEXEC (so it survives the upcoming execve), then close(tmp).
	// NO opens in this loop.
	for _, p := range pairs {
		if err := syscall.Dup3(p.tmp, p.targetN, 0); err != nil {
			fmt.Fprintf(os.Stderr, "podmotion-criu-wrapper: dup3(%d -> %d): %v\n", p.tmp, p.targetN, err)
			os.Exit(127)
		}
		_ = syscall.Close(p.tmp)
	}

	// OC-3: sweep /proc/self/fd and set FD_CLOEXEC on every fd not in {0,1,2} ∪ {targets}.
	// This closes-on-exec any descriptor inherited from nsenter (e.g. /proc/<pid>/ns/mnt
	// handles) so they do not propagate into criu.
	fdDir, err := os.Open("/proc/self/fd")
	if err == nil {
		entries, _ := fdDir.Readdirnames(-1)
		_ = fdDir.Close()
		for _, name := range entries {
			fd, err := strconv.Atoi(name)
			if err != nil {
				continue
			}
			if fd <= 2 || targetSet[fd] {
				continue
			}
			// Skip the dirfd we just closed (it may appear momentarily).
			// Set FD_CLOEXEC; ignore errors (fd may already be closed).
			_, _ = fcntlSetCloexec(fd)
		}
	}

	// OC-2 PHASE 3: execve criu.
	if err := syscall.Exec(criuBin, criuArgv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "podmotion-criu-wrapper: exec %q: %v\n", criuBin, err)
		os.Exit(127)
	}
	// unreachable
}

// fcntlSetCloexec sets FD_CLOEXEC on the given fd via fcntl F_SETFD.
func fcntlSetCloexec(fd int) (int, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if errno != 0 {
		return 0, errno
	}
	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, flags|syscall.FD_CLOEXEC)
	if errno != 0 {
		return 0, errno
	}
	return int(flags | syscall.FD_CLOEXEC), nil
}

// Ensure filepath is used (for potential future use; imported for clarity).
var _ = filepath.Join
