// Copyright 2026 PodMotion Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package network

import (
	"testing"
)

func TestTruncUID(t *testing.T) {
	tests := []struct {
		uid  string
		n    int
		want string
	}{
		{"550e8400-e29b-41d4-a716-446655440000", 8, "550e8400"},
		{"abc", 8, "abc"},
		{"abcdefgh", 8, "abcdefgh"},
		{"abcdefghi", 8, "abcdefgh"},
	}
	for _, tc := range tests {
		got := truncUID(tc.uid, tc.n)
		if got != tc.want {
			t.Errorf("truncUID(%q, %d) = %q; want %q", tc.uid, tc.n, got, tc.want)
		}
	}
}
