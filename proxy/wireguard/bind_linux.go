//go:build linux

package wireguard

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
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

// Keep the single-message syscall's iovecs with the existing pooled messages.
// SendmsgBuffers allocates an iovec slice for runs longer than two datagrams.
type bindSendmsg struct {
	iov   [maxGSOSegments]unix.Iovec
	hdr   unix.Msghdr
	addr4 unix.RawSockaddrInet4
	addr6 unix.RawSockaddrInet6
	write func(uintptr) bool
	err   error
}

func (m *bindSendmsg) send(fd uintptr) bool {
	for {
		_, _, errno := unix.Syscall(unix.SYS_SENDMSG, fd, uintptr(unsafe.Pointer(&m.hdr)), 0)
		if errno == unix.EINTR {
			continue
		}
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			return false // RawConn.Write waits for writability and honors deadlines.
		}
		if errno != 0 {
			m.err = os.NewSyscallError("sendmsg", errno)
		}
		return true
	}
}

func (s *bindSocket) sendBatch(m *bindMessages, count int) (int, error) {
	if count != 1 || len(m.messages[0].OOB) == 0 || s.raw == nil || m.addr.Zone != "" {
		return s.batch.WriteBatch(m.messages[:count], 0)
	}
	message := &m.messages[0]
	send := &m.send
	send.err = nil
	send.hdr = unix.Msghdr{}
	if ip := m.addr.IP.To4(); ip != nil {
		send.addr4 = unix.RawSockaddrInet4{Family: unix.AF_INET}
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&send.addr4.Port))[:], uint16(m.addr.Port))
		copy(send.addr4.Addr[:], ip)
		send.hdr.Name = (*byte)(unsafe.Pointer(&send.addr4))
		send.hdr.Namelen = unix.SizeofSockaddrInet4
	} else {
		send.addr6 = unix.RawSockaddrInet6{Family: unix.AF_INET6}
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&send.addr6.Port))[:], uint16(m.addr.Port))
		copy(send.addr6.Addr[:], m.addr.IP)
		send.hdr.Name = (*byte)(unsafe.Pointer(&send.addr6))
		send.hdr.Namelen = unix.SizeofSockaddrInet6
	}
	for i, buf := range message.Buffers {
		send.iov[i].Base = &buf[0] // GSO groups contain only nonempty datagrams.
		send.iov[i].SetLen(len(buf))
	}
	send.hdr.Iov = &send.iov[0]
	send.hdr.SetIovlen(len(message.Buffers))
	send.hdr.Control = &message.OOB[0]
	send.hdr.SetControllen(len(message.OOB))
	if send.write == nil {
		send.write = send.send
	}
	err := s.raw.Write(send.write)
	clear(send.iov[:len(message.Buffers)])
	if err != nil {
		return 0, err
	}
	if send.err != nil {
		return 0, send.err
	}
	return 1, nil
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
