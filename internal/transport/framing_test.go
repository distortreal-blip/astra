package transport

import (
	"net"
	"testing"
)

func TestFramingRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cfg := FrameConfig{MinPad: 4, MaxPad: 8}
	wrapped := WrapConn(c1, cfg)
	readerWrapped := WrapConn(c2, cfg)

	payload := []byte("hello world")
	go func() {
		_, _ = wrapped.Write(payload)
	}()

	buf := make([]byte, 64)
	n, err := readerWrapped.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("unexpected payload: %s", string(buf[:n]))
	}
}
