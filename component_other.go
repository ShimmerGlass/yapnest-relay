//go:build !linux

package main

import "syscall"

// userTimeout is Linux only; elsewhere, keepalive's probes are all there is.
func userTimeout(_, _ string, _ syscall.RawConn) error { return nil }
