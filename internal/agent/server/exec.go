/*
Copyright 2026 PodMotion Authors.
Licensed under the Apache License, Version 2.0.
*/

package server

import "os/exec"

// newExecCmd is a thin wrapper around exec.Command, kept in a separate file so
// tests can swap it out via a package-level variable if needed.
func newExecCmd(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
