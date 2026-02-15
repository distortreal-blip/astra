package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	rudpTypeData byte = 0
	rudpTypeAck  byte = 1
	rudpTypePing byte = 2
	rudpTypePong byte = 3
)

type ReliableUDPTransport struct {
	RetransmitInterval time.Duration
	MaxInFlight        int
	MaxRetries         int
	IdleTimeout        time.Duration
	KeepaliveInterval  time.Duration
}

func (r ReliableUDPTransport) Name() string { return "rudp" }

func (r ReliableUDPTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	return newRUDPConn(conn.(net.PacketConn), conn.RemoteAddr(), r.retx(), r.maxInFlight(), r.maxRetries(), r.idleTimeout(), r.keepalive()), nil
}

func (r ReliableUDPTransport) Listen(addr string) (net.Listener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	l := &rudpListener{
		pc:          pc,
		accept:      make(chan net.Conn, 32),
		conns:       map[string]*rudpConn{},
		closeCh:     make(chan struct{}),
		retx:        r.retx(),
		maxIn:       r.maxInFlight(),
		maxRet:      r.maxRetries(),
		idleTimeout: r.idleTimeout(),
		keepalive:   r.keepalive(),
	}
	go l.readLoop()
	return l, nil
}

func (r ReliableUDPTransport) retx() time.Duration {
	if r.RetransmitInterval <= 0 {
		return 250 * time.Millisecond
	}
	return r.RetransmitInterval
}

func (r ReliableUDPTransport) maxInFlight() int {
	if r.MaxInFlight <= 0 {
		return 128
	}
	return r.MaxInFlight
}

func (r ReliableUDPTransport) maxRetries() int {
	if r.MaxRetries <= 0 {
		return 6
	}
	return r.MaxRetries
}

func (r ReliableUDPTransport) idleTimeout() time.Duration {
	if r.IdleTimeout <= 0 {
		return 2 * time.Minute
	}
	return r.IdleTimeout
}

func (r ReliableUDPTransport) keepalive() time.Duration {
	if r.KeepaliveInterval <= 0 {
		return 20 * time.Second
	}
	return r.KeepaliveInterval
}

type rudpListener struct {
	pc          net.PacketConn
	accept      chan net.Conn
	conns       map[string]*rudpConn
	mu          sync.Mutex
	closeCh     chan struct{}
	retx        time.Duration
	maxIn       int
	maxRet      int
	idleTimeout time.Duration
	keepalive   time.Duration
}

func (l *rudpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closeCh:
		return nil, errors.New("listener closed")
	}
}

func (l *rudpListener) Close() error {
	close(l.closeCh)
	return l.pc.Close()
}

func (l *rudpListener) Addr() net.Addr {
	return l.pc.LocalAddr()
}

func (l *rudpListener) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := l.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		l.mu.Lock()
		conn, ok := l.conns[addr.String()]
		if !ok {
			conn = newRUDPConn(l.pc, addr, l.retx, l.maxIn, l.maxRet, l.idleTimeout, l.keepalive)
			l.conns[addr.String()] = conn
			l.accept <- conn
		}
		l.mu.Unlock()
		conn.handlePacket(buf[:n])
	}
}

type rudpConn struct {
	pc            net.PacketConn
	raddr         net.Addr
	retx          time.Duration
	seq           uint32
	recv          uint32
	pending       map[uint32][]byte
	sent          map[uint32]*sentFrame
	mu            sync.Mutex
	readCh        chan []byte
	closed        chan struct{}
	maxRetries    int
	readDeadline  time.Time
	writeDeadline time.Time
	cwnd          int
	ssthresh      int
	inFlight      int
	cond          *sync.Cond
	srtt          time.Duration
	rttvar        time.Duration
	rto           time.Duration
	lastRecv      time.Time
	lastSend      time.Time
	idleTimeout   time.Duration
	keepalive     time.Duration
}

type sentFrame struct {
	data     []byte
	retries  int
	lastSent time.Time
	sentAt   time.Time
}

func newRUDPConn(pc net.PacketConn, raddr net.Addr, retx time.Duration, maxInFlight int, maxRetries int, idleTimeout time.Duration, keepalive time.Duration) *rudpConn {
	c := &rudpConn{
		pc:          pc,
		raddr:       raddr,
		retx:        retx,
		seq:         1,
		recv:        1,
		pending:     map[uint32][]byte{},
		sent:        map[uint32]*sentFrame{},
		readCh:      make(chan []byte, 256),
		closed:      make(chan struct{}),
		maxRetries:  maxRetries,
		cwnd:        4,
		ssthresh:    maxInFlight,
		rto:         retx,
		lastRecv:    time.Now(),
		lastSend:    time.Now(),
		idleTimeout: idleTimeout,
		keepalive:   keepalive,
	}
	if c.ssthresh <= 0 {
		c.ssthresh = 32
	}
	c.cond = sync.NewCond(&c.mu)
	go c.retransmitLoop()
	go c.keepaliveLoop()
	return c
}

func (c *rudpConn) handlePacket(p []byte) {
	if len(p) < 13 {
		return
	}
	typ := p[0]
	seq := binary.BigEndian.Uint32(p[1:5])
	ack := binary.BigEndian.Uint32(p[5:9])
	payloadLen := binary.BigEndian.Uint16(p[9:11])
	if typ == rudpTypeAck {
		c.mu.Lock()
		if _, ok := c.sent[ack]; ok {
			frame := c.sent[ack]
			delete(c.sent, ack)
			if frame != nil && !frame.sentAt.IsZero() {
				c.updateRTT(time.Since(frame.sentAt))
			}
			c.inFlight--
			if c.cwnd < c.ssthresh {
				c.cwnd++
			} else if c.cwnd > 0 {
				c.cwnd += 1 / c.cwnd
			}
			c.cond.Broadcast()
		}
		c.mu.Unlock()
		return
	}
	if typ == rudpTypeData {
		_ = ack
		c.lastRecv = time.Now()
		if int(payloadLen) > len(p[11:]) {
			return
		}
		payload := p[11 : 11+payloadLen]
		c.mu.Lock()
		if seq < c.recv {
			c.mu.Unlock()
			_ = c.sendAck(seq)
			return
		}
		if seq == c.recv {
			c.recv++
			c.readCh <- payload
			for {
				if buf, ok := c.pending[c.recv]; ok {
					delete(c.pending, c.recv)
					c.readCh <- buf
					c.recv++
				} else {
					break
				}
			}
		} else {
			c.pending[seq] = payload
		}
		c.mu.Unlock()
		_ = c.sendAck(seq)
	}
	if typ == rudpTypePing {
		c.lastRecv = time.Now()
		_ = c.sendPong()
	}
	if typ == rudpTypePong {
		c.lastRecv = time.Now()
	}
}

func (c *rudpConn) Read(p []byte) (int, error) {
	if !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
		return 0, timeoutErr{}
	}
	select {
	case data := <-c.readCh:
		n := copy(p, data)
		if n < len(data) {
			rest := append([]byte{}, data[n:]...)
			c.readCh <- rest
		}
		return n, nil
	case <-c.closed:
		return 0, errors.New("closed")
	case <-deadlineChan(c.readDeadline):
		return 0, timeoutErr{}
	}
}

func (c *rudpConn) writePacket(frame []byte) (int, error) {
	if u, ok := c.pc.(*net.UDPConn); ok && u.RemoteAddr() != nil {
		return u.Write(frame)
	}
	return c.pc.WriteTo(frame, c.raddr)
}

func (c *rudpConn) Write(p []byte) (int, error) {
	if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
		return 0, timeoutErr{}
	}
	c.mu.Lock()
	for c.inFlight >= c.cwnd && !c.isClosedLocked() {
		c.cond.Wait()
	}
	if c.isClosedLocked() {
		c.mu.Unlock()
		return 0, errors.New("closed")
	}
	seq := c.seq
	c.seq++
	c.inFlight++
	c.mu.Unlock()

	frame := make([]byte, 11+len(p))
	frame[0] = rudpTypeData
	binary.BigEndian.PutUint32(frame[1:5], seq)
	binary.BigEndian.PutUint32(frame[5:9], 0)
	binary.BigEndian.PutUint16(frame[9:11], uint16(len(p)))
	copy(frame[11:], p)
	if _, err := c.writePacket(frame); err != nil {
		c.mu.Lock()
		c.inFlight--
		c.cond.Broadcast()
		c.mu.Unlock()
		return 0, err
	}
	c.mu.Lock()
	now := time.Now()
	c.lastSend = now
	c.sent[seq] = &sentFrame{data: frame, retries: 0, lastSent: now, sentAt: now}
	c.mu.Unlock()
	return len(p), nil
}

func (c *rudpConn) sendAck(seq uint32) error {
	frame := make([]byte, 11)
	frame[0] = rudpTypeAck
	binary.BigEndian.PutUint32(frame[1:5], 0)
	binary.BigEndian.PutUint32(frame[5:9], seq)
	binary.BigEndian.PutUint16(frame[9:11], 0)
	_, err := c.writePacket(frame)
	return err
}

func (c *rudpConn) sendPong() error {
	frame := make([]byte, 11)
	frame[0] = rudpTypePong
	_, err := c.writePacket(frame)
	return err
}

func (c *rudpConn) retransmitLoop() {
	ticker := time.NewTicker(c.retx)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for seq, frame := range c.sent {
				if now.Sub(frame.lastSent) < c.rto {
					continue
				}
				if frame.retries >= c.maxRetries {
					delete(c.sent, seq)
					c.inFlight--
					c.cond.Broadcast()
					continue
				}
				frame.retries++
				frame.lastSent = now
				c.onLoss()
				_, _ = c.writePacket(frame.data)
			}
			c.mu.Unlock()
		case <-c.closed:
			return
		}
	}
}

func (c *rudpConn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
		return nil
	}
}

func (c *rudpConn) LocalAddr() net.Addr  { return c.pc.LocalAddr() }
func (c *rudpConn) RemoteAddr() net.Addr { return c.raddr }
func (c *rudpConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}
func (c *rudpConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}
func (c *rudpConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

func (c *rudpConn) updateRTT(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	if c.srtt == 0 {
		c.srtt = rtt
		c.rttvar = rtt / 2
	} else {
		alpha := 0.125
		beta := 0.25
		diff := c.srtt - rtt
		if diff < 0 {
			diff = -diff
		}
		c.rttvar = time.Duration((1-beta)*float64(c.rttvar) + beta*float64(diff))
		c.srtt = time.Duration((1-alpha)*float64(c.srtt) + alpha*float64(rtt))
	}
	rto := c.srtt + 4*c.rttvar
	if rto < 200*time.Millisecond {
		rto = 200 * time.Millisecond
	}
	if rto > 5*time.Second {
		rto = 5 * time.Second
	}
	c.rto = rto
}

func (c *rudpConn) onLoss() {
	if c.cwnd > 1 {
		c.ssthresh = c.cwnd / 2
		c.cwnd = 1
	}
}

func (c *rudpConn) keepaliveLoop() {
	if c.keepalive <= 0 {
		return
	}
	ticker := time.NewTicker(c.keepalive)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if c.idleTimeout > 0 && time.Since(c.lastRecv) > c.idleTimeout {
				_ = c.Close()
				return
			}
			if time.Since(c.lastSend) >= c.keepalive {
				_ = c.sendPing()
			}
		case <-c.closed:
			return
		}
	}
}

func (c *rudpConn) sendPing() error {
	frame := make([]byte, 11)
	frame[0] = rudpTypePing
	_, err := c.writePacket(frame)
	return err
}

func (c *rudpConn) isClosedLocked() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func deadlineChan(t time.Time) <-chan time.Time {
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	return time.After(d)
}
