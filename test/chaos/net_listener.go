//go:build chaos_test

/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
*/

package chaos

import "net"

// localListener opens a TCP listener on 127.0.0.1 with a random available port.
func localListener() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
