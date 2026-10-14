package inbound

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func newTestUDPWorker() *udpWorker {
	return &udpWorker{
		address:    net.LocalHostIP,
		activeConn: make(map[connID]*udpConn),
	}
}

func TestUDPConnectionBurst(t *testing.T) {
	worker := newTestUDPWorker()
	id := connID{src: net.UDPDestination(net.LocalHostIP, 12345)}
	conn, existing := worker.getConnection(id)
	if existing {
		t.Fatal("first connection lookup reported an existing connection")
	}
	defer conn.Close()

	const burstSize = 4 * 1024 * 1024
	const packetCount = burstSize / buf.Size
	for i := range packetCount {
		packet := buf.New()
		packet.Extend(buf.Size)
		packet.SetByte(0, byte(i))
		packet.UDP = &id.src
		if err := conn.writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			t.Fatal(err)
		}
	}

	received, err := conn.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(received)
	if got := received.Len(); got != burstSize {
		t.Fatalf("retained burst bytes = %d, want %d", got, burstSize)
	}
	if len(received) != packetCount {
		t.Fatalf("retained packet count = %d, want %d", len(received), packetCount)
	}
	for i, packet := range received {
		if packet.Byte(0) != byte(i) || packet.UDP != &id.src {
			t.Fatalf("packet %d lost its payload or destination", i)
		}
	}
}

func TestUDPConnectionConcurrentExistingLookup(t *testing.T) {
	worker := newTestUDPWorker()
	id := connID{src: net.UDPDestination(net.LocalHostIP, 12345)}
	conn, _ := worker.getConnection(id)
	defer conn.Close()
	atomic.StoreInt64(&conn.lastActivityTime, 0)

	// Existing lookups must finish even while another reader holds the map lock.
	worker.RLock()
	const callers = 32
	results := make(chan bool, callers)
	for range callers {
		go func() {
			for range 100 {
				got, existing := worker.getConnection(id)
				if got != conn || !existing {
					results <- false
					return
				}
			}
			results <- true
		}()
	}

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for range callers {
		select {
		case ok := <-results:
			if !ok {
				worker.RUnlock()
				t.Fatal("existing lookup returned a different or new connection")
			}
		case <-timer.C:
			worker.RUnlock()
			t.Fatal("existing lookup blocked while the map was read-locked")
		}
	}
	worker.RUnlock()
	if atomic.LoadInt64(&conn.lastActivityTime) == 0 {
		t.Fatal("existing lookup did not update activity")
	}
}

func TestUDPConnectionConcurrentCreation(t *testing.T) {
	worker := newTestUDPWorker()
	id := connID{src: net.UDPDestination(net.LocalHostIP, 12345)}
	const callers = 32
	type result struct {
		conn     *udpConn
		existing bool
	}
	results := make(chan result, callers)
	start := make(chan struct{})
	for range callers {
		go func() {
			<-start
			conn, existing := worker.getConnection(id)
			results <- result{conn: conn, existing: existing}
		}()
	}
	close(start)

	var conn *udpConn
	created := 0
	for range callers {
		got := <-results
		if conn == nil {
			conn = got.conn
			defer conn.Close()
		}
		if got.conn != conn {
			t.Fatal("concurrent lookup created more than one connection")
		}
		if !got.existing {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("new connection count = %d, want 1", created)
	}
}

func TestUDPConnectionReplacesClosed(t *testing.T) {
	worker := newTestUDPWorker()
	id := connID{src: net.UDPDestination(net.LocalHostIP, 12345)}
	closed, _ := worker.getConnection(id)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	conn, existing := worker.getConnection(id)
	defer conn.Close()
	if existing || conn == closed || conn.done.Done() {
		t.Fatal("lookup reused a closed connection")
	}
	if worker.activeConn[id] != conn {
		t.Fatal("replacement connection was not stored")
	}
}
