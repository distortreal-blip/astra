package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	muxHeaderSize = 9
	muxTypeData   = 0
	muxTypeWindow = 1
)

type MuxConfig struct {
	MaxStreams         int
	MaxBufferPerStream int
	MaxFrameSize       int
	StreamWindow       int
	SessionWindow      int
}

type MuxSession struct {
	conn       net.Conn
	streams    map[uint32]*MuxStream
	queues     map[uint32]*streamQueue
	acceptCh   chan *MuxStream
	mu         sync.Mutex
	cond       *sync.Cond
	closed     bool
	closedCh   chan struct{}
	nextStream uint32
	cfg        MuxConfig
	sendWindow int
}

type streamQueue struct {
	priority    int
	queue       [][]byte
	queuedBytes int
	sendWindow  int
}

type MuxStream struct {
	id       uint32
	session  *MuxSession
	readCh   chan []byte
	buf      []byte
	mu       sync.Mutex
	closed   chan struct{}
	priority int
	maxFrame int
}

func NewMuxSession(conn net.Conn, cfg MuxConfig) *MuxSession {
	cfg = normalizeMuxConfig(cfg)
	s := &MuxSession{
		conn:       conn,
		streams:    map[uint32]*MuxStream{},
		queues:     map[uint32]*streamQueue{},
		acceptCh:   make(chan *MuxStream, 32),
		nextStream: 1,
		cfg:        cfg,
		sendWindow: cfg.SessionWindow,
		closedCh:   make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	go s.readLoop()
	go s.writeLoop()
	return s
}

func (s *MuxSession) OpenStream(priority int) (*MuxStream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("session closed")
	}
	if s.cfg.MaxStreams > 0 && len(s.streams) >= s.cfg.MaxStreams {
		return nil, errors.New("max streams reached")
	}
	id := s.nextStream
	s.nextStream++
	stream := newMuxStream(id, s, priority, s.cfg)
	s.streams[id] = stream
	s.queues[id] = &streamQueue{
		priority:   priority,
		queue:      [][]byte{},
		sendWindow: s.cfg.StreamWindow,
	}
	return stream, nil
}

func (s *MuxSession) AcceptStream() (*MuxStream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.closedCh:
		return nil, errors.New("session closed")
	}
}

func (s *MuxSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closedCh)
	s.cond.Broadcast()
	return nil
}

func (s *MuxSession) readLoop() {
	header := make([]byte, muxHeaderSize)
	for {
		if _, err := io.ReadFull(s.conn, header); err != nil {
			_ = s.Close()
			return
		}
		frameType := header[0]
		streamID := binary.BigEndian.Uint32(header[1:5])
		length := binary.BigEndian.Uint32(header[5:9])
		if length > 0 && s.cfg.MaxFrameSize > 0 && int(length) > s.cfg.MaxFrameSize {
			_, _ = io.CopyN(io.Discard, s.conn, int64(length))
			continue
		}
		switch frameType {
		case muxTypeWindow:
			if length != 4 {
				_, _ = io.CopyN(io.Discard, s.conn, int64(length))
				continue
			}
			payload := make([]byte, 4)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				_ = s.Close()
				return
			}
			delta := int(binary.BigEndian.Uint32(payload))
			s.applyWindowUpdate(streamID, delta)
		case muxTypeData:
			if length == 0 {
				continue
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				_ = s.Close()
				return
			}
			stream := s.getOrCreate(streamID)
			if stream != nil {
				stream.enqueue(payload)
			}
		default:
			if length > 0 {
				_, _ = io.CopyN(io.Discard, s.conn, int64(length))
			}
		}
	}
}

func (s *MuxSession) writeLoop() {
	for {
		s.mu.Lock()
		for !s.closed && !s.hasWritable() {
			s.cond.Wait()
		}
		if s.closed {
			s.mu.Unlock()
			return
		}
		streamID, chunk := s.nextChunk()
		s.mu.Unlock()
		if len(chunk) == 0 {
			continue
		}
		if err := s.writeFrame(muxTypeData, streamID, chunk); err != nil {
			_ = s.Close()
			return
		}
	}
}

func (s *MuxSession) hasWritable() bool {
	if s.sendWindow <= 0 {
		return false
	}
	for _, q := range s.queues {
		if q.queuedBytes > 0 && q.sendWindow > 0 {
			return true
		}
	}
	return false
}

func (s *MuxSession) nextChunk() (uint32, []byte) {
	var pickedID uint32
	var picked *streamQueue
	for id, q := range s.queues {
		if q.queuedBytes == 0 || q.sendWindow <= 0 {
			continue
		}
		if picked == nil || q.priority > picked.priority {
			picked = q
			pickedID = id
		}
	}
	if picked == nil || len(picked.queue) == 0 || s.sendWindow <= 0 {
		return 0, nil
	}
	data := picked.queue[0]
	max := len(data)
	if s.cfg.MaxFrameSize > 0 && max > s.cfg.MaxFrameSize {
		max = s.cfg.MaxFrameSize
	}
	if s.sendWindow < max {
		max = s.sendWindow
	}
	if picked.sendWindow < max {
		max = picked.sendWindow
	}
	chunk := data[:max]
	if max == len(data) {
		picked.queue = picked.queue[1:]
	} else {
		picked.queue[0] = data[max:]
	}
	picked.queuedBytes -= max
	picked.sendWindow -= max
	s.sendWindow -= max
	s.cond.Broadcast()
	return pickedID, chunk
}

func (s *MuxSession) writeFrame(frameType byte, streamID uint32, payload []byte) error {
	header := make([]byte, muxHeaderSize)
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:5], streamID)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))
	if _, err := s.conn.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *MuxSession) sendWindowUpdate(streamID uint32, delta int) {
	if delta <= 0 {
		return
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(delta))
	_ = s.writeFrame(muxTypeWindow, streamID, payload)
}

func (s *MuxSession) applyWindowUpdate(streamID uint32, delta int) {
	if delta <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if streamID == 0 {
		s.sendWindow += delta
		s.cond.Broadcast()
		return
	}
	if q, ok := s.queues[streamID]; ok {
		q.sendWindow += delta
		s.cond.Broadcast()
	}
}

func (s *MuxSession) getOrCreate(id uint32) *MuxStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.streams[id]; ok {
		return st
	}
	if s.cfg.MaxStreams > 0 && len(s.streams) >= s.cfg.MaxStreams {
		return nil
	}
	st := newMuxStream(id, s, 0, s.cfg)
	s.streams[id] = st
	s.queues[id] = &streamQueue{priority: 0, queue: [][]byte{}, sendWindow: s.cfg.StreamWindow}
	s.acceptCh <- st
	return st
}

func newMuxStream(id uint32, session *MuxSession, priority int, cfg MuxConfig) *MuxStream {
	bufSize := 256
	if cfg.MaxBufferPerStream > 0 {
		bufSize = cfg.MaxBufferPerStream
	}
	return &MuxStream{
		id:       id,
		session:  session,
		readCh:   make(chan []byte, bufSize),
		closed:   make(chan struct{}),
		priority: priority,
		maxFrame: cfg.MaxFrameSize,
	}
}

func (m *MuxStream) Read(p []byte) (int, error) {
	if len(m.buf) == 0 {
		select {
		case data := <-m.readCh:
			m.buf = data
		case <-m.closed:
			return 0, errors.New("stream closed")
		}
	}
	n := copy(p, m.buf)
	m.buf = m.buf[n:]
	if n > 0 {
		m.session.sendWindowUpdate(0, n)
		m.session.sendWindowUpdate(m.id, n)
	}
	return n, nil
}

func (m *MuxStream) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.maxFrame > 0 && len(p) > m.maxFrame {
		return 0, errors.New("frame too large")
	}
	err := m.session.enqueue(m.id, m.priority, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (m *MuxStream) Close() error {
	select {
	case <-m.closed:
		return nil
	default:
		close(m.closed)
		return nil
	}
}

func (m *MuxStream) LocalAddr() net.Addr                { return m.session.conn.LocalAddr() }
func (m *MuxStream) RemoteAddr() net.Addr               { return m.session.conn.RemoteAddr() }
func (m *MuxStream) SetDeadline(t time.Time) error      { return m.session.conn.SetDeadline(t) }
func (m *MuxStream) SetReadDeadline(t time.Time) error  { return m.session.conn.SetReadDeadline(t) }
func (m *MuxStream) SetWriteDeadline(t time.Time) error { return m.session.conn.SetWriteDeadline(t) }

func (m *MuxStream) enqueue(data []byte) {
	select {
	case m.readCh <- data:
	default:
		// backpressure: drop when buffer is full
	}
}

func (s *MuxSession) enqueue(streamID uint32, priority int, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session closed")
	}
	q, ok := s.queues[streamID]
	if !ok {
		q = &streamQueue{priority: priority, queue: [][]byte{}, sendWindow: s.cfg.StreamWindow}
		s.queues[streamID] = q
	}
	if s.cfg.MaxBufferPerStream > 0 && q.queuedBytes+len(data) > s.cfg.MaxBufferPerStream {
		for s.cfg.MaxBufferPerStream > 0 && q.queuedBytes+len(data) > s.cfg.MaxBufferPerStream && !s.closed {
			s.cond.Wait()
		}
		if s.closed {
			return errors.New("session closed")
		}
	}
	q.queue = append(q.queue, data)
	q.queuedBytes += len(data)
	s.cond.Broadcast()
	return nil
}

func normalizeMuxConfig(cfg MuxConfig) MuxConfig {
	if cfg.MaxFrameSize <= 0 {
		cfg.MaxFrameSize = 16 * 1024
	}
	if cfg.StreamWindow <= 0 {
		cfg.StreamWindow = 256 * 1024
	}
	if cfg.SessionWindow <= 0 {
		cfg.SessionWindow = 1024 * 1024
	}
	return cfg
}
