package obfs

import "crypto/rand"

func GeneratePreamble(max int, template string) []byte {
	if max <= 0 {
		return nil
	}
	switch template {
	case "http2":
		return http2Preamble(max)
	case "tls13":
		return tls13Preamble(max)
	default:
		return randomPreamble(max)
	}
}

func randomPreamble(max int) []byte {
	size := 1
	if max > 1 {
		size = 1 + int(randByte()%byte(max))
	}
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return buf
}

func http2Preamble(max int) []byte {
	base := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if len(base) >= max {
		return base[:max]
	}
	padding := make([]byte, max-len(base))
	_, _ = rand.Read(padding)
	return append(base, padding...)
}

func tls13Preamble(max int) []byte {
	payloadLen := 64
	if max > 5 && max-5 < payloadLen {
		payloadLen = max - 5
	}
	if payloadLen < 8 {
		return randomPreamble(max)
	}
	base := []byte{0x16, 0x03, 0x01, byte(payloadLen >> 8), byte(payloadLen)}
	payload := make([]byte, payloadLen)
	_, _ = rand.Read(payload)
	return append(base, payload...)
}

func randByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}
