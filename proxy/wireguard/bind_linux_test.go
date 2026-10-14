//go:build linux

package wireguard

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBindSocketBuffers(t *testing.T) {
	reference := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	if err := reference.SetReadBuffer(socketBufferSize); err != nil {
		t.Fatal(err)
	}
	if err := reference.SetWriteBuffer(socketBufferSize); err != nil {
		t.Fatal(err)
	}
	setSocketBufferForce(reference)
	_, _, actual := newThroughputBind(t, "udp4", "127.0.0.1:0")
	readBuffers := func(conn *net.UDPConn) [2]int {
		t.Helper()
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var sizes [2]int
		if err := raw.Control(func(fd uintptr) {
			for i, opt := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF} {
				var err error
				sizes[i], err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
				if err != nil {
					t.Error(err)
				}
			}
		}); err != nil {
			t.Fatal(err)
		}
		return sizes
	}
	want, got := readBuffers(reference), readBuffers(actual)
	if got[0] < want[0] || got[1] < want[1] {
		t.Fatalf("bind buffers=%v, want at least %v under current kernel limits/capabilities", got, want)
	}
}
