package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type UDPTransport struct{}

func (u UDPTransport) Name() string { return "udp" }

func (u UDPTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "udp", addr)
}

func (u UDPTransport) Listen(addr string) (net.Listener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	l := &udpListener{
		pc:      pc,
		accept:  make(chan net.Conn, 32),
		conns:   map[string]*udpConn{},
		closeCh: make(chan struct{}),
	}
	go l.readLoop()
	return l, nil
}

type udpListener struct {
	pc      net.PacketConn
	accept  chan net.Conn
	conns   map[string]*udpConn
	mu      sync.Mutex
	closeCh chan struct{}
}

func (l *udpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closeCh:
		return nil, errors.New("listener closed")
	}
}

func (l *udpListener) Close() error {
	close(l.closeCh)
	return l.pc.Close()
}

func (l *udpListener) Addr() net.Addr {
	return l.pc.LocalAddr()
}

func (l *udpListener) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := l.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		l.mu.Lock()
		conn, ok := l.conns[addr.String()]
		if !ok {
			conn = newUDPConn(l.pc, addr)
			l.conns[addr.String()] = conn
			l.accept <- conn
		}
		l.mu.Unlock()
		conn.push(buf[:n])
	}
}

type udpConn struct {
	pc       net.PacketConn
	raddr    net.Addr
	readCh   chan []byte
	buf      []byte
	deadline time.Time
	mu       sync.Mutex
}

func newUDPConn(pc net.PacketConn, raddr net.Addr) *udpConn {
	return &udpConn{
		pc:     pc,
		raddr:  raddr,
		readCh: make(chan []byte, 128),
	}
}

func (c *udpConn) push(data []byte) {
	buf := make([]byte, len(data))
	copy(buf, data)
	c.readCh <- buf
}

func (c *udpConn) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		var data []byte
		select {
		case data = <-c.readCh:
		default:
			data = <-c.readCh
		}
		c.buf = data
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *udpConn) Write(p []byte) (int, error) {
	return c.pc.WriteTo(p, c.raddr)
}

func (c *udpConn) Close() error { return nil }
func (c *udpConn) LocalAddr() net.Addr {
	return c.pc.LocalAddr()
}
func (c *udpConn) RemoteAddr() net.Addr { return c.raddr }
func (c *udpConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}
func (c *udpConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return nil
}
func (c *udpConn) SetWriteDeadline(t time.Time) error {
	c.deadline = t
	return nil
}
