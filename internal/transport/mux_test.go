package transport

import (
	"net"
	"testing"
	"time"
)

func TestMuxSession(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cfg := MuxConfig{MaxStreams: 4, MaxBufferPerStream: 8, MaxFrameSize: 1024}
	s1 := NewMuxSession(c1, cfg)
	s2 := NewMuxSession(c2, cfg)

	st1, err := s1.OpenStream(0)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	go func() {
		_, _ = st1.Write([]byte("ping"))
	}()

	st2, err := s2.AcceptStream()
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	buf := make([]byte, 16)
	st2.SetReadDeadline(time.Now().Add(time.Second))
	n, err := st2.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("unexpected payload: %s", string(buf[:n]))
	}
}
