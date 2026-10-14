package wireguard

import (
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

const benchBatch = 64

// Raw cost of queueing and draining a small burst, as one flow's reader does.
func BenchmarkQueueBurstChan(b *testing.B) {
	ch := make(chan *packet, udpQueueLimit)
	p := &packet{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < benchBatch; j++ {
			ch <- p
		}
		for j := 0; j < benchBatch; j++ {
			<-ch
		}
	}
}

func BenchmarkQueueBurstPacketQueue(b *testing.B) {
	q := newPacketQueue(udpQueueLimit)
	p := &packet{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < benchBatch; j++ {
			q.push(p)
		}
		for j := 0; j < benchBatch; j++ {
			q.pop()
		}
	}
}

func BenchmarkQueueBurstPacketQueueBatch(b *testing.B) {
	q := newPacketQueue(udpQueueLimit)
	p := &packet{}
	var packets [benchBatch]*packet
	b.ReportAllocs()
	for range b.N {
		for range benchBatch {
			q.push(p)
		}
		q.popBatch(packets[:])
	}
}

func BenchmarkUDPConnReadMultiBufferBatch(b *testing.B) {
	q := newPacketQueue(udpQueueLimit)
	c := &udpConn{queue: q}
	dest := net.UDPDestination(net.LocalHostIP, 53)
	p := &packet{p: make([]byte, throughputPacketSize), dest: &dest}
	b.SetBytes(benchBatch * throughputPacketSize)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for range benchBatch {
			q.push(p)
		}
		mb, err := c.ReadMultiBuffer()
		if err != nil || len(mb) != benchBatch {
			b.Fatalf("batch read: %d packets, %v", len(mb), err)
		}
		buf.ReleaseMulti(mb)
	}
}

// Producer and consumer on different goroutines; the producer yields when the
// queue is full instead of spinning, like a blocking channel send would.
func BenchmarkQueueStreamChan(b *testing.B) {
	ch := make(chan *packet, udpQueueLimit)
	p := &packet{}
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch <- p
	}
	close(ch)
	<-done
}

func BenchmarkQueueStreamPacketQueue(b *testing.B) {
	q := newPacketQueue(udpQueueLimit)
	p := &packet{}
	done := make(chan struct{})
	go func() {
		for {
			if _, ok := q.pop(); !ok {
				break
			}
		}
		close(done)
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for !q.push(p) {
			runtime.Gosched()
		}
	}
	q.close()
	<-done
}
