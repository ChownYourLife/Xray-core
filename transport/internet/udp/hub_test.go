package udp

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestHubCapacity(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []HubOption
		want    int
	}{
		{name: "default", want: 4096},
		{name: "explicit", options: []HubOption{HubCapacity(17)}, want: 17},
	} {
		t.Run(test.name, func(t *testing.T) {
			hub, err := ListenUDP(context.Background(), net.LocalHostIP, 0, &internet.MemoryStreamConfig{}, test.options...)
			if err != nil {
				t.Fatal(err)
			}
			defer hub.Close()
			if got := cap(hub.Receive()); got != test.want {
				t.Fatalf("receive capacity = %d, want %d", got, test.want)
			}
			if hub.udpConn == nil {
				t.Fatal("system UDP listener did not use a UDPConn")
			}
		})
	}
}

type wrappedPacketConn struct {
	net.PacketConn
	destination net.Addr
}

func (c *wrappedPacketConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	c.destination = destination
	return c.PacketConn.WriteTo(payload, destination)
}

func TestHubWriteTo(t *testing.T) {
	for _, test := range []struct {
		name    string
		network string
		address net.Address
	}{
		{name: "IPv4", network: "udp4", address: net.LocalHostIP},
		{name: "IPv6", network: "udp6", address: net.LocalHostIPv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			receiver, err := net.ListenUDP(test.network, &net.UDPAddr{IP: test.address.IP()})
			if err != nil {
				if test.network == "udp6" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer receiver.Close()
			sender, err := net.ListenUDP(test.network, &net.UDPAddr{IP: test.address.IP()})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			destination := net.DestinationFromAddr(receiver.LocalAddr())
			payload := []byte("UDP reply")
			wrapped := &wrappedPacketConn{PacketConn: sender}
			for _, path := range []struct {
				name string
				hub  *Hub
			}{
				{name: "concrete", hub: &Hub{conn: sender, udpConn: sender}},
				{name: "wrapped", hub: &Hub{conn: wrapped}},
			} {
				t.Run(path.name, func(t *testing.T) {
					if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					n, err := path.hub.WriteTo(payload, destination)
					if err != nil {
						t.Fatal(err)
					}
					if n != len(payload) {
						t.Fatalf("written bytes = %d, want %d", n, len(payload))
					}
					var received [64]byte
					n, source, err := receiver.ReadFromUDP(received[:])
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(received[:n], payload) {
						t.Fatalf("received payload = %q, want %q", received[:n], payload)
					}
					if got, want := source.String(), sender.LocalAddr().String(); got != want {
						t.Fatalf("reply source = %s, want %s", got, want)
					}
					if path.name == "wrapped" {
						if got, want := wrapped.destination.String(), receiver.LocalAddr().String(); got != want {
							t.Fatalf("fallback destination = %s, want %s", got, want)
						}
					}
				})
			}
		})
	}
}
