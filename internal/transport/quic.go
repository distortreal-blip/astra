package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type QUICTransport struct {
	ServerName string
	ALPN       []string
	Timeout    time.Duration
}

func (q QUICTransport) Name() string { return "quic" }

func (q QUICTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	timeout := q.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tlsCfg := &tls.Config{
		ServerName:         q.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         q.ALPN,
	}
	if tlsCfg.NextProtos == nil {
		tlsCfg.NextProtos = []string{"astra"}
	}
	conn, err := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{})
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	return &quicStreamConn{stream: stream, conn: conn, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

// quicConn is the interface we need from *quic.Conn for closing.
type quicConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	CloseWithError(quic.ApplicationErrorCode, string) error
}

func (q QUICTransport) Listen(addr string) (net.Listener, error) {
	certFile := getenv("ENTRY_TLS_CERT", "entry_cert.pem")
	keyFile := getenv("ENTRY_TLS_KEY", "entry_key.pem")
	host := getenv("ENTRY_TLS_HOST", "astra.local")
	cert, err := LoadOrCreateCert(certFile, keyFile, host)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   q.ALPN,
	}
	if tlsCfg.NextProtos == nil {
		tlsCfg.NextProtos = []string{"astra"}
	}
	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{})
	if err != nil {
		return nil, err
	}
	return &quicListener{Listener: ln}, nil
}

type quicStreamConn struct {
	stream *quic.Stream
	conn   quicConn
	local  net.Addr
	remote net.Addr
	once   sync.Once
}

func (c *quicStreamConn) Read(p []byte) (n int, err error)   { return c.stream.Read(p) }
func (c *quicStreamConn) Write(p []byte) (n int, err error)   { return c.stream.Write(p) }
func (c *quicStreamConn) LocalAddr() net.Addr                 { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *quicStreamConn) SetDeadline(t time.Time) error       { return c.stream.SetDeadline(t) }
func (c *quicStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

func (c *quicStreamConn) Close() error {
	var err error
	c.once.Do(func() {
		_ = c.stream.Close()
		err = c.conn.CloseWithError(0, "done")
	})
	return err
}

type quicListener struct {
	*quic.Listener
}

func (l *quicListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	return &quicStreamConn{stream: stream, conn: conn, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

func (l *quicListener) Close() error {
	return l.Listener.Close()
}

// Ensure quicStreamConn implements net.Conn (and io.Reader, io.Writer, io.Closer)
var _ net.Conn = (*quicStreamConn)(nil)
var _ io.Reader = (*quicStreamConn)(nil)
var _ io.Writer = (*quicStreamConn)(nil)
var _ io.Closer = (*quicStreamConn)(nil)
