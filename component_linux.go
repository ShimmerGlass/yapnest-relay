package main

import "syscall"

// tcpUserTimeout is TCP_USER_TIMEOUT from linux/tcp.h, which the syscall package lacks.
const tcpUserTimeout = 0x12

// userTimeout makes the kernel drop the connection when what the relay wrote stays unacknowledged for 60 s. TCP
// sends no keepalive probes while a write is waiting for its ACK, so without it a dead server is only noticed when
// retransmitting gives up, many minutes later.
func userTimeout(_, _ string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, 60_000)
	}); cerr != nil {
		return cerr
	}
	return err
}
