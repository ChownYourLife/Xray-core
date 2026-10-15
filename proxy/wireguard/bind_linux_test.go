//go:build linux

package wireguard

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
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

type gsoTestStep struct {
	prefix int
	err    error
}

type gsoTestBatch struct {
	next interface {
		ReadBatch([]ipv4.Message, int) (int, error)
		WriteBatch([]ipv4.Message, int) (int, error)
	}
	steps   []gsoTestStep
	failGSO error
	mu      sync.Mutex
}

func (b *gsoTestBatch) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	return b.next.ReadBatch(messages, flags)
}

func (b *gsoTestBatch) WriteBatch(messages []ipv4.Message, flags int) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failGSO != nil {
		for _, message := range messages {
			if len(message.OOB) > 0 {
				return 0, b.failGSO
			}
		}
	}
	var injected error
	if len(b.steps) > 0 {
		step := b.steps[0]
		b.steps = b.steps[1:]
		if step.prefix < 0 {
			return step.prefix, step.err
		}
		messages = messages[:min(step.prefix, len(messages))]
		injected = step.err
	}
	if len(messages) == 0 {
		return 0, injected
	}
	n, err := b.next.WriteBatch(messages, flags)
	if err != nil {
		return n, err
	}
	return n, injected
}

func newGSOTestBind(t *testing.T, network, address string) (*bind, conn.ReceiveFunc, *net.UDPConn) {
	t.Helper()
	b, receive, udp := newThroughputBind(t, network, address)
	if !b.socket.Load().gso.Load() {
		t.Skip("kernel UDP_SEGMENT unavailable")
	}
	return b, receive, udp
}

func TestBindGSOScatterGather(t *testing.T) {
	for _, family := range []struct{ network, address string }{{"udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0"}} {
		t.Run(family.network, func(t *testing.T) {
			sender, _, _ := newGSOTestBind(t, family.network, family.address)
			receiver := newUDPClientTestSocket(t, family.network, family.address)
			if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			// The first two datagrams overlap and none has spare capacity.
			// Coalescing in-place would corrupt a later datagram or need a copy.
			backing := bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44}, 40)
			writes := [][]byte{backing[:64:64], backing[32:96:96], bytes.Repeat([]byte{0x55}, 15), {}, {}, bytes.Repeat([]byte{0x66}, 80), bytes.Repeat([]byte{0x77}, 81), bytes.Repeat([]byte{0x88}, 81)}
			expected := make([][]byte, len(writes))
			wantBytes := 0
			for i, packet := range writes {
				expected[i] = bytes.Clone(packet)
				wantBytes += len(packet)
			}
			var sent bindTestCounter
			sender.writeCounter = &sent
			if err := sender.Send(writes, &conn.StdNetEndpoint{AddrPort: receiver.LocalAddr().(*net.UDPAddr).AddrPort()}); err != nil {
				t.Fatal(err)
			}
			for i, want := range expected {
				packet := make([]byte, 256)
				n, _, err := receiver.ReadFromUDP(packet)
				if err != nil || !bytes.Equal(packet[:n], want) {
					t.Fatalf("packet %d: n=%d err=%v got=%x want=%x", i, n, err, packet[:n], want)
				}
				if !bytes.Equal(writes[i], want) {
					t.Fatalf("input %d mutated", i)
				}
			}
			if sent.Value() != int64(wantBytes) {
				t.Fatalf("sent bytes=%d, want %d", sent.Value(), wantBytes)
			}
		})
	}
}

func readGSOPackets(t *testing.T, receiver *net.UDPConn, want [][]byte) {
	t.Helper()
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 65535)
	for i, expected := range want {
		n, _, err := receiver.ReadFromUDP(packet)
		if err != nil || !bytes.Equal(packet[:n], expected) {
			t.Fatalf("packet %d: length=%d err=%v, want length=%d and exact payload", i, n, err, len(expected))
		}
	}
	if err := receiver.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := receiver.ReadFromUDP(packet); err == nil {
		t.Fatalf("unexpected extra datagram: length=%d", n)
	} else if !os.IsTimeout(err) {
		t.Fatal(err)
	}
}

func TestBindGSOPartialCompletion(t *testing.T) {
	packets := [][]byte{
		bytes.Repeat([]byte{0xa1}, 64), bytes.Repeat([]byte{0xa2}, 64),
		bytes.Repeat([]byte{0xb1}, 80), bytes.Repeat([]byte{0xb2}, 80),
		bytes.Repeat([]byte{0xc1}, 96),
	}
	for _, test := range []struct {
		name     string
		steps    []gsoTestStep
		packets  [][]byte
		wantSent int
		wantErr  error
		disabled bool
	}{
		{name: "short success", steps: []gsoTestStep{{prefix: 1}}, wantSent: 5},
		{name: "unsupported", steps: []gsoTestStep{{prefix: 1, err: unix.EIO}}, wantSent: 5, disabled: true},
		{name: "negative unsupported count", steps: []gsoTestStep{{prefix: -1, err: unix.EIO}}, wantSent: 5, disabled: true},
		{name: "negative unsupported after prefix", steps: []gsoTestStep{{prefix: 1}, {prefix: -1, err: unix.EIO}}, wantSent: 5, disabled: true},
		{name: "MTU", steps: []gsoTestStep{{prefix: 1, err: unix.EMSGSIZE}}, wantSent: 5, disabled: true},
		{name: "old kernel MTU", steps: []gsoTestStep{{prefix: 1, err: unix.EINVAL}}, wantSent: 5, disabled: true},
		{name: "protocol unavailable", steps: []gsoTestStep{{err: unix.ENOPROTOOPT}}, wantSent: 5, disabled: true},
		{name: "operation unsupported", steps: []gsoTestStep{{err: unix.EOPNOTSUPP}}, wantSent: 5, disabled: true},
		{name: "unrelated error", steps: []gsoTestStep{{prefix: 1, err: unix.EPERM}}, wantSent: 2, wantErr: unix.EPERM},
		{name: "negative unrelated count", steps: []gsoTestStep{{prefix: -1, err: unix.EPERM}}, wantErr: unix.EPERM},
		{name: "plain error", packets: [][]byte{packets[0], packets[1], {}, packets[2], packets[3]}, steps: []gsoTestStep{{prefix: 1, err: unix.EIO}}, wantSent: 2, wantErr: unix.EIO},
		{name: "fallback partial error", steps: []gsoTestStep{{prefix: 1, err: unix.EIO}, {prefix: 1, err: unix.ECONNREFUSED}}, wantSent: 3, wantErr: unix.ECONNREFUSED, disabled: true},
		{name: "negative fallback error", steps: []gsoTestStep{{prefix: 1, err: unix.EIO}, {prefix: -1, err: unix.ECONNREFUSED}}, wantSent: 2, wantErr: unix.ECONNREFUSED, disabled: true},
		{name: "zero progress", steps: []gsoTestStep{{}}, wantErr: io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			sender, _, _ := newGSOTestBind(t, "udp4", "127.0.0.1:0")
			receiver := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
			steps := append([]gsoTestStep(nil), test.steps...)
			for i := range steps {
				if steps[i].err != nil {
					steps[i].err = os.NewSyscallError("sendmmsg", steps[i].err)
				}
			}
			recorder := &gsoTestBatch{next: sender.socket.Load().batch, steps: steps}
			sender.socket.Load().batch = recorder
			var sent bindTestCounter
			sender.writeCounter = &sent
			ep := &conn.StdNetEndpoint{AddrPort: receiver.LocalAddr().(*net.UDPAddr).AddrPort()}
			writes := test.packets
			if writes == nil {
				writes = packets
			}
			if err := sender.Send(writes, ep); !errors.Is(err, test.wantErr) {
				t.Fatalf("send error=%v, want %v", err, test.wantErr)
			}
			readGSOPackets(t, receiver, writes[:test.wantSent])
			total := 0
			for _, packet := range writes[:test.wantSent] {
				total += len(packet)
			}
			if sent.Value() != int64(total) {
				t.Fatalf("sent bytes=%d, want %d", sent.Value(), total)
			}
			// Later sends must still succeed after disabling unsupported GSO.
			// Reintroducing offload would surface this unrelated error instead.
			if test.disabled {
				recorder.failGSO = unix.EPERM
			}
			next := [][]byte{bytes.Repeat([]byte{0xd1}, 32), bytes.Repeat([]byte{0xd2}, 32)}
			if err := sender.Send(next, ep); err != nil {
				t.Fatal(err)
			}
			readGSOPackets(t, receiver, next)
			if sent.Value() != int64(total+64) {
				t.Fatalf("later sent bytes=%d, want %d", sent.Value(), total+64)
			}
		})
	}
}

func TestBindGSOLimits(t *testing.T) {
	// The final, larger plain packet reuses a message slot after a GSO batch.
	// Stale UDP_SEGMENT metadata would split it into several datagrams.
	reused := make([]int, 65)
	for i := range reused {
		reused[i] = 16
	}
	reused[len(reused)-1] = 96
	for _, test := range []struct {
		name    string
		network string
		address string
		sizes   []int
		mapped  bool
	}{
		{name: "64 segments", network: "udp4", address: "127.0.0.1:0", sizes: make([]int, 65)},
		{name: "stale ancillary data across batches", network: "udp4", address: "127.0.0.1:0", sizes: reused},
		{name: "IPv4 payload limit", network: "udp4", address: "127.0.0.1:0", sizes: []int{32754, 32754}},
		{name: "mapped IPv4 payload limit", network: "udp4", address: "127.0.0.1:0", sizes: []int{32754, 32754}, mapped: true},
		{name: "IPv6 payload limit", network: "udp6", address: "[::1]:0", sizes: []int{32754, 32754}},
		{name: "IPv4 exact payload limit", network: "udp4", address: "127.0.0.1:0", sizes: []int{32753, 32753, 1}},
		{name: "large batch payload limit", network: "udp4", address: "127.0.0.1:0", sizes: make([]int, 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			sender, _, _ := newGSOTestBind(t, test.network, test.address)
			receiver := newUDPClientTestSocket(t, test.network, test.address)
			if err := receiver.SetReadBuffer(socketBufferSize); err != nil {
				t.Fatal(err)
			}
			writes := make([][]byte, len(test.sizes))
			for i, size := range test.sizes {
				if size == 0 {
					size = 8
					if len(test.sizes) == 64 {
						size = 1200
					}
				}
				writes[i] = bytes.Repeat([]byte{byte(i)}, size)
			}
			addr := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
			if test.mapped {
				addr = netip.AddrPortFrom(netip.AddrFrom16(addr.Addr().As16()), addr.Port())
			}
			if err := sender.Send(writes, &conn.StdNetEndpoint{AddrPort: addr}); err != nil {
				t.Fatal(err)
			}
			readGSOPackets(t, receiver, writes)
		})
	}
}

func TestBindGSOSendReceiveReuse(t *testing.T) {
	sender, _, socket := newGSOTestBind(t, "udp4", "127.0.0.1:0")
	receiver := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	ep := &conn.StdNetEndpoint{AddrPort: receiver.LocalAddr().(*net.UDPAddr).AddrPort()}
	for i := range 32 {
		writes := [][]byte{bytes.Repeat([]byte{byte(i + 1)}, 16), bytes.Repeat([]byte{byte(i + 2)}, 16)}
		if err := sender.Send(writes, ep); err != nil {
			t.Fatal(err)
		}
		readGSOPackets(t, receiver, writes)
		reply := bytes.Repeat([]byte{byte(i + 3)}, 96)
		if _, err := receiver.WriteToUDP(reply, socket.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		if err := socket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		reads, sizes, eps := benchmarkBuffers(2, 128)
		if n, err := sender.socket.Load().receive(reads, sizes, eps); n != 1 || err != nil || !bytes.Equal(reads[0][:sizes[0]], reply) {
			t.Fatalf("receive after GSO pool reuse: n=%d size=%d err=%v", n, sizes[0], err)
		}
		// A plain packet larger than the old segment size must not inherit
		// UDP_SEGMENT from the same pool and turn into several datagrams.
		if err := sender.Send([][]byte{reply}, ep); err != nil {
			t.Fatal(err)
		}
		readGSOPackets(t, receiver, [][]byte{reply})
	}
}

func TestBindGSOConcurrentDisable(t *testing.T) {
	sender, _, _ := newGSOTestBind(t, "udp4", "127.0.0.1:0")
	receiver := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	recorder := &gsoTestBatch{next: sender.socket.Load().batch, steps: []gsoTestStep{{err: unix.EIO}}}
	sender.socket.Load().batch = recorder
	var sent bindTestCounter
	sender.writeCounter = &sent
	ep := &conn.StdNetEndpoint{AddrPort: receiver.LocalAddr().(*net.UDPAddr).AddrPort()}
	done := make(chan error, 4)
	for worker := range 4 {
		go func() {
			writes := make([][]byte, 16)
			for i := range writes {
				writes[i] = bytes.Repeat([]byte{byte(worker*16 + i)}, 8)
			}
			done <- sender.Send(writes, ep)
		}()
	}
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	seen := make([]bool, 64)
	packet := make([]byte, 128)
	for range 64 {
		n, _, err := receiver.ReadFromUDP(packet)
		if err != nil || n != 8 || int(packet[0]) >= len(seen) || !bytes.Equal(packet[:n], bytes.Repeat(packet[:1], 8)) {
			t.Fatalf("concurrent packet: n=%d err=%v data=%x", n, err, packet[:n])
		}
		if seen[packet[0]] {
			t.Fatalf("duplicate concurrent packet %d", packet[0])
		}
		seen[packet[0]] = true
	}
	if sent.Value() != 64*8 {
		t.Fatalf("concurrent fallback sent bytes=%d, want %d", sent.Value(), 64*8)
	}
	recorder.failGSO = unix.EPERM
	next := [][]byte{bytes.Repeat([]byte{0xe1}, 8), bytes.Repeat([]byte{0xe2}, 8)}
	if err := sender.Send(next, ep); err != nil {
		t.Fatal(err)
	}
	readGSOPackets(t, receiver, next)
}

func TestBindGSOHighWaterReceiveReuse(t *testing.T) {
	sender, _, socket := newGSOTestBind(t, "udp4", "127.0.0.1:0")
	receiver := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	ep := &conn.StdNetEndpoint{AddrPort: receiver.LocalAddr().(*net.UDPAddr).AddrPort()}
	for range 4 {
		// An increasing-size batch uses many message slots, followed by a
		// compact GSO batch. Reusing the pool must release the earlier slots
		// too, not just those touched by the final send chunk.
		writes := make([][]byte, 66)
		expected := make([][]byte, len(writes))
		for i := range writes {
			size := 32 + i
			if i >= 64 {
				size = 128
			}
			writes[i] = bytes.Repeat([]byte{byte(i + 1)}, size)
			expected[i] = bytes.Clone(writes[i])
		}
		if err := sender.Send(writes, ep); err != nil {
			t.Fatal(err)
		}
		readGSOPackets(t, receiver, expected)
		for i := range 64 {
			if _, err := receiver.WriteToUDP(bytes.Repeat([]byte{byte(i)}, 128), socket.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
		}
		if err := socket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		reads, sizes, eps := benchmarkBuffers(64, 128)
		count := 0
		for count < 64 {
			n, err := sender.socket.Load().receive(reads[:64-count], sizes, eps)
			if err != nil {
				t.Fatal(err)
			}
			for i := range n {
				if sizes[i] != 128 || !bytes.Equal(reads[i][:sizes[i]], bytes.Repeat([]byte{byte(count + i)}, 128)) {
					t.Fatalf("pooled receive packet %d: length=%d or payload corrupted", count+i, sizes[i])
				}
			}
			count += n
		}
		for i := range writes {
			if !bytes.Equal(writes[i], expected[i]) {
				t.Fatalf("released send input %d overwritten by receive", i)
			}
		}
	}
}

func TestBindBatchKernelErrorAfterPrefix(t *testing.T) {
	sender, _, _ := newThroughputBind(t, "udp4", "127.0.0.1:0")
	receiver := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	var sent bindTestCounter
	sender.writeCounter = &sent
	prefix := [][]byte{bytes.Repeat([]byte{0xa1}, 64), bytes.Repeat([]byte{0xa2}, 64)}
	// The first messages really go out; an oversized plain datagram then
	// makes sendmmsg fail with EMSGSIZE and x/net's raw negative count.
	writes := append(prefix, make([]byte, 65536))
	err := sender.Send(writes, &conn.StdNetEndpoint{AddrPort: receiver.LocalAddr().(*net.UDPAddr).AddrPort()})
	if !errors.Is(err, unix.EMSGSIZE) {
		t.Fatalf("send error=%v, want EMSGSIZE", err)
	}
	readGSOPackets(t, receiver, prefix)
	if sent.Value() != 128 {
		t.Fatalf("sent bytes=%d, want 128", sent.Value())
	}
}
