package wireguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/tun"
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

type clientTestDNS struct {
	fail      atomic.Bool
	failAfter atomic.Int32
	calls     atomic.Int32
}

func (*clientTestDNS) Type() interface{} { return dns.ClientType() }
func (*clientTestDNS) Start() error      { return nil }
func (*clientTestDNS) Close() error      { return nil }
func (d *clientTestDNS) LookupIP(string, dns.IPOption) ([]xnet.IP, uint32, error) {
	calls := d.calls.Add(1)
	if d.fail.Load() || (d.failAfter.Load() > 0 && calls > d.failAfter.Load()) {
		return nil, 0, errors.New("endpoint lookup failed")
	}
	return []xnet.IP{xnet.ParseIP("127.0.0.1")}, 600, nil
}

// Suppress the netstack's automatic EventUp so tests reach IpcSet and Up
// separately. All packet reads and resource closure still use the real TUN.
type clientTestTUN struct {
	tun.Device
	events chan tun.Event
	closes atomic.Int32
}

func (t *clientTestTUN) Events() <-chan tun.Event { return t.events }
func (t *clientTestTUN) Close() error {
	if t.closes.Add(1) == 1 {
		close(t.events)
	}
	return t.Device.Close()
}

func clientTestKey(t *testing.T) (private, public string) {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key[:]), hex.EncodeToString(pub)
}

func newClientInitTestHandler(t *testing.T, endpoint string, d *clientTestDNS) (*Handler, *clientTestTUN) {
	t.Helper()
	private, _ := clientTestKey(t)
	_, public := clientTestKey(t)
	dev, tnet, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420, true)
	if err != nil {
		t.Fatal(err)
	}
	tracked := &clientTestTUN{Device: dev, events: make(chan tun.Event)}
	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		ctx:    ctx,
		cancel: cancel,
		conf: &DeviceConfig{
			SecretKey: private,
			Peers:     []*PeerConfig{{PublicKey: public, Endpoint: endpoint, AllowedIps: []string{"0.0.0.0/0"}}},
		},
		dns:            d,
		streamSettings: &internet.MemoryStreamConfig{},
		tun:            tracked,
		tnet:           tnet,
	}
	t.Cleanup(func() { h.Close() })
	return h, tracked
}

func assertClientHandshake(t *testing.T, h *Handler, endpoint *net.UDPConn) {
	t.Helper()
	c, err := h.tnet.Dial("udp", "10.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("init retry packet")); err != nil {
		t.Fatal(err)
	}
	var packet [2048]byte
	n, _, err := endpoint.ReadFromUDP(packet[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 148 || packet[0] != 1 {
		t.Fatalf("expected WireGuard handshake initiation, got %d bytes, type %d", n, packet[0])
	}
}

func assertClientClosed(t *testing.T, h *Handler, tracked *clientTestTUN) {
	t.Helper()
	owner := h.dev
	var socket net.PacketConn
	if owner != nil {
		if s := owner.Bind().(*bind).socket.Load(); s != nil {
			socket = s.c
		}
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if owner != nil {
		select {
		case <-owner.Wait():
		default:
			t.Fatal("Close did not finish closing the device owning the TUN")
		}
	}
	if tracked.closes.Load() != 1 {
		t.Fatalf("TUN closed %d times, want once", tracked.closes.Load())
	}
	if socket != nil {
		_, err := socket.WriteTo([]byte("closed"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("owned bind socket still usable after Close: %v", err)
		}
	}
	if err := h.init(context.Background()); err == nil {
		t.Fatal("closed handler accepted another initialization")
	}
	if err := h.Close(); err != nil || tracked.closes.Load() != 1 {
		t.Fatalf("repeated Close changed TUN ownership: closes=%d err=%v", tracked.closes.Load(), err)
	}
}

func TestClientInitRetryKeepsOneDevice(t *testing.T) {
	for _, boundary := range []string{"endpoint DNS", "private key"} {
		t.Run(boundary, func(t *testing.T) {
			endpoint := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
			d := &clientTestDNS{}
			h, tracked := newClientInitTestHandler(t, "wg.test:"+xnet.Port(endpoint.LocalAddr().(*net.UDPAddr).Port).String(), d)
			private := h.conf.SecretKey
			if boundary == "endpoint DNS" {
				d.fail.Store(true)
			} else {
				h.conf.SecretKey = "invalid"
			}
			owner := h.dev
			for i := range 3 {
				if err := h.init(context.Background()); err == nil {
					t.Fatal("IpcSet unexpectedly succeeded")
				}
				if h.configured || h.dev == nil {
					t.Fatal("failed IpcSet lost its device or marked it configured")
				}
				if i == 0 {
					owner = h.dev
				} else if h.dev != owner {
					t.Fatal("retry replaced the device owning the TUN")
				}
			}
			d.fail.Store(false)
			h.conf.SecretKey = private
			if err := h.init(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertClientHandshake(t, h, endpoint)
			assertClientClosed(t, h, tracked)
		})
	}
}

func TestClientInitRetriesUpWithoutReconfiguring(t *testing.T) {
	endpoint := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	d := &clientTestDNS{}
	d.failAfter.Store(1) // IpcSet resolves its peer; Up cannot resolve the bind socket.
	h, tracked := newClientInitTestHandler(t, "wg.test:"+xnet.Port(endpoint.LocalAddr().(*net.UDPAddr).Port).String(), d)
	if err := h.init(context.Background()); err == nil {
		t.Fatal("Up unexpectedly succeeded with a failed bind lookup")
	}
	if !h.configured || h.dev == nil {
		t.Fatal("successful IpcSet was not retained after Up failed")
	}
	owner := h.dev
	// If retry reapplies IpcSet, this invalid key prevents the handshake.
	h.conf.SecretKey = "invalid"
	d.failAfter.Store(0)
	if err := h.init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.dev != owner {
		t.Fatal("Up retry replaced the device owning the TUN")
	}
	assertClientHandshake(t, h, endpoint)
	assertClientClosed(t, h, tracked)
}

func TestClientCloseAfterFailedInit(t *testing.T) {
	for _, after := range []int32{0, 1} {
		t.Run(xnet.Port(after).String(), func(t *testing.T) {
			d := &clientTestDNS{}
			if after == 0 {
				d.fail.Store(true)
			} else {
				d.failAfter.Store(after)
			}
			h, tracked := newClientInitTestHandler(t, "wg.test:51820", d)
			if err := h.init(context.Background()); err == nil {
				t.Fatal("initialization unexpectedly succeeded")
			}
			assertClientClosed(t, h, tracked)
		})
	}
}

func TestClientEndpointResolvedByXrayDNS(t *testing.T) {
	endpoint := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	d := &clientTestDNS{}
	h, tracked := newClientInitTestHandler(t, "wg.test:"+xnet.Port(endpoint.LocalAddr().(*net.UDPAddr).Port).String(), d)
	if err := h.init(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertClientHandshake(t, h, endpoint)
	assertClientClosed(t, h, tracked)
}

func TestClientFinalMaskKeepsDomain(t *testing.T) {
	endpoint := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	d := &clientTestDNS{}
	h, tracked := newClientInitTestHandler(t, "wg.test:"+xnet.Port(endpoint.LocalAddr().(*net.UDPAddr).Port).String(), d)
	h.streamSettings.FinalMask = finalmask.NewFinalMask(nil, nil, nil, nil,
		func(_ context.Context, dest xnet.Destination) (xnet.PacketConn, xnet.Addr, error) {
			if !dest.Address.Family().IsDomain() || dest.Address.Domain() != "wg.test" {
				return nil, nil, errors.New("finalmask requires the original peer domain")
			}
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			return c, endpoint.LocalAddr(), err
		}, nil)
	if err := h.init(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertClientHandshake(t, h, endpoint)
	assertClientClosed(t, h, tracked)
}

func TestClientInitRetryAfterRequestCanceled(t *testing.T) {
	endpoint := newUDPClientTestSocket(t, "udp4", "127.0.0.1:0")
	resolver, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	resolverAddr := resolver.Addr().(*net.TCPAddr)
	resolver.Close()
	h, tracked := newClientInitTestHandler(t, endpoint.LocalAddr().String(), &clientTestDNS{})
	gateway := xnet.LocalHostIP
	h.streamSettings.FinalMask = finalmask.NewFinalMask(nil, nil, nil, nil,
		func(ctx context.Context, _ xnet.Destination) (xnet.PacketConn, xnet.Addr, error) {
			// Resolver setup inside a mask must retain socket routing values
			// without inheriting the first request's cancellation.
			outbounds := session.OutboundsFromContext(ctx)
			if len(outbounds) != 1 || outbounds[0].Gateway != gateway {
				return nil, nil, errors.New("lost outbound gateway")
			}
			c, err := internet.DialSystem(ctx, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(resolverAddr.Port)), nil)
			if err != nil {
				return nil, nil, err
			}
			c.Close()
			pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			return pc, endpoint.LocalAddr(), err
		}, nil)
	ctx, cancel := context.WithCancel(session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Gateway: gateway}}))
	defer cancel()
	if err := h.init(ctx); err == nil {
		t.Fatal("mask setup unexpectedly connected to the stopped resolver")
	}
	cancel() // Dispatch cancels this request after its failed Process returns.
	resolver, err = net.ListenTCP("tcp4", resolverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	accepted := make(chan error, 1)
	go func() {
		c, err := resolver.AcceptTCP()
		if err == nil {
			c.Close()
		}
		accepted <- err
	}()
	if err := h.init(context.Background()); err != nil {
		t.Fatalf("new request could not retry mask setup: %v", err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retry did not connect to the restored resolver")
	}
	assertClientHandshake(t, h, endpoint)
	assertClientClosed(t, h, tracked)
}

func TestClientCloseCancelsBindSetup(t *testing.T) {
	resolver, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	h, tracked := newClientInitTestHandler(t, "127.0.0.1:51820", &clientTestDNS{})
	setupStarted := make(chan struct{})
	h.streamSettings.FinalMask = finalmask.NewFinalMask(nil, nil, nil, nil,
		func(ctx context.Context, _ xnet.Destination) (xnet.PacketConn, xnet.Addr, error) {
			dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(resolver.Addr().(*net.TCPAddr).Port))
			c, err := internet.DialSystem(ctx, dest, nil)
			if err != nil {
				return nil, nil, err
			}
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			close(setupStarted)
			var reply [1]byte
			_, err = c.Read(reply[:]) // Resolver setup is waiting on the remote socket.
			return nil, nil, err
		}, nil)
	initDone := make(chan error, 1)
	go func() { initDone <- h.init(context.Background()) }()
	select {
	case <-setupStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("mask setup did not reach the resolver socket")
	}
	if err := resolver.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server, err := resolver.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	closeDone := make(chan error, 1)
	go func() { closeDone <- h.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel in-flight bind setup")
	}
	select {
	case err := <-initDone:
		if err == nil {
			t.Fatal("canceled resolver setup unexpectedly initialized the device")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight init did not stop after Close")
	}
	server.SetReadDeadline(time.Now().Add(3 * time.Second))
	var packet [1]byte
	if n, err := server.Read(packet[:]); n != 0 || err != io.EOF {
		t.Fatalf("resolver connection not released: n=%d err=%v", n, err)
	}
	if tracked.closes.Load() != 1 {
		t.Fatalf("Close did not release the TUN exactly once: %d", tracked.closes.Load())
	}
}
