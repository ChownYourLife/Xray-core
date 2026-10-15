//go:build linux

package wireguard

import (
	"encoding/binary"
	"errors"
	"net"
	"unsafe"

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

const (
	maxGSOSegments = 64
	maxGSOPayload4 = 1<<16 - 1 - 20 - 8
	maxGSOPayload6 = 1<<16 - 1 - 8
)

func supportsGSO(udp *net.UDPConn) bool {
	raw, err := udp.SyscallConn()
	if err != nil {
		return false
	}
	supported := false
	_ = raw.Control(func(fd uintptr) {
		_, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		supported = err == nil
	})
	return supported
}

func (s *bindSocket) packMessages(m *bindMessages, bufs [][]byte) int {
	if len(bufs) < 2 || !s.gso.Load() {
		return m.packMessages(bufs)
	}
	maxPayload := maxGSOPayload6
	if m.addr.IP.To4() != nil {
		maxPayload = maxGSOPayload4
	}
	count := 0
	for i := 0; i < len(bufs); {
		size, total := len(bufs[i]), len(bufs[i])
		end := i + 1
		// Each iovec is an original datagram. The kernel concatenates them
		// before segmentation, without modifying even overlapping inputs.
		// An empty datagram must stay separate: UDP_SEGMENT size 0 is off.
		if size > 0 {
			for end < len(bufs) && end-i < maxGSOSegments {
				next := len(bufs[end])
				if next == 0 || next > size || total+next > maxPayload {
					break
				}
				total += next
				end++
				if next < size {
					break
				}
			}
		}
		message := &m.messages[count]
		message.Buffers = bufs[i:end]
		message.Addr = &m.addr
		message.OOB = nil
		if end-i > 1 {
			message.OOB = setGSOSize(m.control[count][:], size)
		}
		count++
		i = end
	}
	m.used = max(m.used, count)
	return count
}

func setGSOSize(control []byte, size int) []byte {
	control = control[:unix.CmsgSpace(2)]
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	header.Level = unix.SOL_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(control[unix.CmsgLen(0):], uint16(size))
	return control
}

// These errors identify missing offload support or a segment exceeding the path
// MTU. Plain UDP can still send (and, where allowed, fragment) those datagrams.
func gsoFailed(err error) bool {
	return errors.Is(err, unix.EIO) || errors.Is(err, unix.EMSGSIZE) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP)
}
