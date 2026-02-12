package transport

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

type FrameConfig struct {
	MinPad int
	MaxPad int
}

func (c FrameConfig) Enabled() bool {
	return c.MaxPad > 0 && c.MaxPad >= c.MinPad
}

func WrapConn(conn net.Conn, cfg FrameConfig) net.Conn {
	if !cfg.Enabled() {
		return conn
	}
	return &framedConn{
		conn: conn,
		cfg:  cfg,
	}
}

type framedConn struct {
	conn net.Conn
	cfg  FrameConfig
	mu   sync.Mutex
	buf  []byte
}

func (f *framedConn) Read(p []byte) (int, error) {
	if len(f.buf) == 0 {
		header := make([]byte, 4)
		if _, err := io.ReadFull(f.conn, header); err != nil {
			return 0, err
		}
		payloadLen := int(binary.BigEndian.Uint16(header[:2]))
		padLen := int(binary.BigEndian.Uint16(header[2:4]))
		if payloadLen == 0 && padLen == 0 {
			return 0, io.EOF
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(f.conn, payload); err != nil {
			return 0, err
		}
		if padLen > 0 {
			if _, err := io.CopyN(io.Discard, f.conn, int64(padLen)); err != nil {
				return 0, err
			}
		}
		f.buf = payload
	}
	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	return n, nil
}

func (f *framedConn) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	padLen := 0
	if f.cfg.MaxPad > 0 {
		min := f.cfg.MinPad
		if min < 0 {
			min = 0
		}
		if f.cfg.MaxPad < min {
			min = f.cfg.MaxPad
		}
		padLen = min
		if f.cfg.MaxPad > min {
			extra := make([]byte, 1)
			_, _ = rand.Read(extra)
			padLen = min + int(extra[0])%(f.cfg.MaxPad-min+1)
		}
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[:2], uint16(len(p)))
	binary.BigEndian.PutUint16(header[2:4], uint16(padLen))
	if _, err := f.conn.Write(header); err != nil {
		return 0, err
	}
	if _, err := f.conn.Write(p); err != nil {
		return 0, err
	}
	if padLen > 0 {
		padding := make([]byte, padLen)
		_, _ = rand.Read(padding)
		if _, err := f.conn.Write(padding); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (f *framedConn) Close() error                       { return f.conn.Close() }
func (f *framedConn) LocalAddr() net.Addr                { return f.conn.LocalAddr() }
func (f *framedConn) RemoteAddr() net.Addr               { return f.conn.RemoteAddr() }
func (f *framedConn) SetDeadline(t time.Time) error      { return f.conn.SetDeadline(t) }
func (f *framedConn) SetReadDeadline(t time.Time) error  { return f.conn.SetReadDeadline(t) }
func (f *framedConn) SetWriteDeadline(t time.Time) error { return f.conn.SetWriteDeadline(t) }
