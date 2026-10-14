//go:build linux

package wireguard

import (
	"net"

	"golang.org/x/sys/unix"
)

func forceSocketBuffers(fd int) {
	// CAP_NET_ADMIN permits bypassing the system's rmem_max/wmem_max limits.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, socketBufferSize)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, socketBufferSize)
}

func setSocketBufferForce(udp *net.UDPConn) {
	raw, err := udp.SyscallConn()
	if err == nil {
		_ = raw.Control(func(fd uintptr) { forceSocketBuffers(int(fd)) })
	}
}
