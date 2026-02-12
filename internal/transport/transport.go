package transport

import (
	"context"
	"net"
)

type Transport interface {
	Name() string
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Listen(addr string) (net.Listener, error)
}
