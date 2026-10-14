//go:build !linux

package wireguard

import "net"

// Buffer forcing is Linux-specific; SetReadBuffer/SetWriteBuffer still apply.
func setSocketBufferForce(udp *net.UDPConn) {}
