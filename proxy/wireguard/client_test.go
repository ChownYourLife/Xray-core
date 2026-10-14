package wireguard

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

func newUDPClientTestSocket(tb testing.TB, network, address string) *net.UDPConn {
	tb.Helper()
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		tb.Fatal(err)
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		if network == "udp6" {
			tb.Skipf("IPv6 loopback unavailable: %v", err)
		}
		tb.Fatal(err)
	}
	tb.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		tb.Fatal(err)
	}
	return conn
}

func TestUDPConnClientTargetsAndReplies(t *testing.T) {
	for _, family := range []struct{ network, address string }{{"udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0"}} {
		for _, fallback := range []bool{false, true} {
			name := family.network + "/native"
			if fallback {
				name = family.network + "/wrapped"
			}
			t.Run(name, func(t *testing.T) {
				local := newUDPClientTestSocket(t, family.network, family.address)
				primary := newUDPClientTestSocket(t, family.network, family.address)
				other := newUDPClientTestSocket(t, family.network, family.address)
				var pc net.PacketConn = local
				if fallback {
					pc = struct{ net.PacketConn }{local}
				}
				client := &UDPConnClient{PacketConn: pc, Dest: primary.LocalAddr().(*net.UDPAddr)}
				primaryDest := xnet.DestinationFromAddr(primary.LocalAddr())
				otherDest := xnet.DestinationFromAddr(other.LocalAddr())
				domainDest := xnet.UDPDestination(xnet.DomainAddress("target.example"), otherDest.Port)
				targets := []*xnet.Destination{nil, &primaryDest, &otherDest, &domainDest}
				mb := make(buf.MultiBuffer, 0, len(targets))
				for i, target := range targets {
					b := buf.New()
					b.Write([]byte{byte(i)})
					b.UDP = target
					mb = append(mb, b)
				}
				if err := client.WriteMultiBuffer(mb); err != nil {
					t.Fatal(err)
				}
				for i, target := range []*net.UDPConn{primary, primary, other, other} {
					var payload [8]byte
					n, source, err := target.ReadFromUDPAddrPort(payload[:])
					if err != nil || n != 1 || payload[0] != byte(i) {
						t.Fatalf("target packet %d: n=%d err=%v payload=%v", i, n, err, payload[:n])
					}
					if _, err := target.WriteToUDPAddrPort(payload[:n], source); err != nil {
						t.Fatal(err)
					}
					mb, err := client.ReadMultiBuffer()
					if err != nil {
						t.Fatal(err)
					}
					want := xnet.DestinationFromAddr(target.LocalAddr())
					valid := len(mb) == 1 && bytes.Equal(mb[0].Bytes(), []byte{byte(i)}) && *mb[0].UDP == want
					buf.ReleaseMulti(mb)
					if !valid {
						t.Fatalf("reply %d lost payload or source address", i)
					}
				}
			})
		}
	}
}
