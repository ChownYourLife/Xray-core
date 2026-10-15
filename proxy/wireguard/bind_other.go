//go:build !linux

package wireguard

import "net"

// Buffer forcing is Linux-specific; SetReadBuffer/SetWriteBuffer still apply.
func setSocketBufferForce(udp *net.UDPConn) {}

func supportsGSO(udp *net.UDPConn) bool { return false }

type bindSendmsg struct{}

func (s *bindSocket) sendBatch(m *bindMessages, count int) (int, error) {
	return s.batch.WriteBatch(m.messages[:count], 0)
}

func (s *bindSocket) packMessages(m *bindMessages, bufs [][]byte) int {
	return m.packMessages(bufs)
}

func gsoFailed(err error) bool { return false }
