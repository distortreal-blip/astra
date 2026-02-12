package transport

import (
	"context"
	"net"
	"time"
)

type TCPTransport struct {
	Timeout time.Duration
}

func (t TCPTransport) Name() string {
	return "tcp"
}

func (t TCPTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{}
	if t.Timeout > 0 {
		d.Timeout = t.Timeout
	}
	return d.DialContext(ctx, "tcp", addr)
}

func (t TCPTransport) Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
