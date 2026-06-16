/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//go:build !linux

package network

// ProbeTCClsact returns false on non-Linux platforms (conservative, fail-safe). (ADR-0169)
func ProbeTCClsact() bool { return false }
