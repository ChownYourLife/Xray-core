package wireguard

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// BenchmarkUDPManagerNewSession measures what one new UDP flow costs the
// inbound while it stays open: QUIC and DNS open many short flows, and each
// one lives until the connection idle timeout.
func BenchmarkUDPManagerNewSession(b *testing.B) {
	m := &udpManager{
		handler: func(conn net.Conn, dest net.Destination) {},
		m:       make(map[udpFlowKey]*udpConn),
	}
	dst := net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)
	payload := make([]byte, 1200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := net.UDPDestination(net.IPAddress([]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), net.Port(1024+i%60000))
		m.feed(src, dst, payload)
	}
}

func TestPacketQueueOrderAndClose(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 3; i++ {
		if !q.push(&packet{p: []byte{byte(i)}}) {
			t.Fatalf("push %d rejected", i)
		}
	}
	for i := 0; i < 3; i++ {
		p, ok := q.pop()
		if !ok || p.p[0] != byte(i) {
			t.Fatalf("pop %d: got %v, %v", i, p, ok)
		}
	}
	q.close()
	if _, ok := q.pop(); ok {
		t.Fatal("pop after close returned a packet")
	}
	if q.push(&packet{}) {
		t.Fatal("push after close accepted")
	}
}

func TestPacketQueueLimit(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < udpQueueLimit; i++ {
		if !q.push(&packet{}) {
			t.Fatalf("push %d rejected below the limit", i)
		}
	}
	if q.push(&packet{}) {
		t.Fatal("push above the limit accepted")
	}
}

func TestPacketQueueCloseUnblocksReader(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	done := make(chan bool)
	go func() {
		_, ok := q.pop()
		done <- ok
	}()
	q.close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("blocked pop returned a packet after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake the reader")
	}
}

func TestPacketQueueDropsDrainedStorage(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 100; i++ {
		q.push(&packet{})
	}
	for i := 0; i < 100; i++ {
		q.pop()
	}
	if q.items != nil {
		t.Fatalf("drained queue still holds %d slots", cap(q.items))
	}
}

func TestPacketQueuePopBatch(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	var dst [64]*packet
	if n := q.popBatch(nil); n != 0 {
		t.Fatalf("empty destination returned %d packets", n)
	}
	for i := range 70 {
		q.push(&packet{p: []byte{byte(i)}})
	}
	storage := q.items
	q.close()
	for offset := 0; offset < 70; {
		n := q.popBatch(dst[:])
		want := min(len(dst), 70-offset)
		if n != want {
			t.Fatalf("batch at %d: got %d, want %d", offset, n, want)
		}
		for i, p := range dst[:n] {
			if p.p[0] != byte(offset+i) {
				t.Fatalf("batch reordered packet %d", offset+i)
			}
		}
		offset += n
	}
	if n := q.popBatch(dst[:]); n != 0 {
		t.Fatalf("closed and drained queue returned %d packets", n)
	}
	for i, p := range storage {
		if p != nil {
			t.Fatalf("drained slot %d retains a packet", i)
		}
	}
	if q.items != nil {
		t.Fatal("drained queue retains storage")
	}
}

func TestPacketQueuePopBatchWaitsForPacket(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	done := make(chan int, 1)
	go func() {
		var dst [64]*packet
		done <- q.popBatch(dst[:])
	}()
	q.push(&packet{})
	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("batch returned %d packets", n)
		}
	case <-time.After(time.Second):
		t.Fatal("push did not wake the batch reader")
	}
	q.close()
}

func TestUDPConnReadMultiBufferBatches(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	c := &udpConn{queue: q}
	dest := net.UDPDestination(net.LocalHostIP, 53)
	for i := range 130 {
		q.push(&packet{p: []byte{byte(i)}, dest: &dest})
	}
	q.close()
	for offset := 0; offset < 130; {
		mb, err := c.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		want := min(64, 130-offset)
		if len(mb) != want {
			buf.ReleaseMulti(mb)
			t.Fatalf("batch at %d: got %d, want %d", offset, len(mb), want)
		}
		for i, b := range mb {
			if b.Len() != 1 || b.Bytes()[0] != byte(offset+i) || b.UDP != &dest {
				buf.ReleaseMulti(mb)
				t.Fatalf("batch lost packet data or destination at %d", offset+i)
			}
		}
		offset += len(mb)
		buf.ReleaseMulti(mb)
	}
	if _, err := c.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("closed/drained read: %v", err)
	}
}

func TestUDPConnReadMultiBufferSkipsOversizedPackets(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	c := &udpConn{queue: q}
	dest := net.UDPDestination(net.LocalHostIP, 53)
	q.push(&packet{p: make([]byte, buf.Size+1), dest: &dest})
	q.push(&packet{p: []byte("valid"), dest: &dest})
	q.close()
	mb, err := c.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 || string(mb[0].Bytes()) != "valid" {
		t.Fatal("oversized packet prevented the remaining batch from being returned")
	}
}
