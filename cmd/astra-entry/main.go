package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"astra/internal/auth"
	"astra/internal/config"
	"astra/internal/protocol"
	"astra/internal/transport"
)

const (
	defaultAddr = "127.0.0.1:8443"
	nonceTTL    = 2 * time.Minute
)

var (
	usedNonces    = make(map[string]time.Time)
	identityCache = make(map[string]ed25519.PublicKey)
	authOKCount   uint64
	authDenyCount uint64
	rl            = newRateLimiter(60, 20)
	failBlock     = newFailBlocker(10, 10*time.Minute)
)

func main() {
	configPath := flag.String("config", getenv("ASTRA_CONFIG", "configs/astra-entry.json"), "config path")
	flagAddr := flag.String("addr", "", "ENTRY_ADDR")
	flagTransport := flag.String("transport", "", "ENTRY_TRANSPORT")
	flagNext := flag.String("next", "", "ENTRY_NEXT_ADDR")
	flagTLSALPN := flag.String("tls-alpn", "", "ENTRY_TLS_ALPN")
	flagRate := flag.String("rate", "", "ENTRY_RATE_LIMIT_PER_MIN")
	flagBurst := flag.String("burst", "", "ENTRY_RATE_BURST")
	flagFrameMin := flag.String("frame-min", "", "ASTRA_FRAME_MIN_PAD")
	flagFrameMax := flag.String("frame-max", "", "ASTRA_FRAME_MAX_PAD")
	flagMux := flag.String("mux", "", "ASTRA_MUX_ENABLED")
	flag.Parse()
	if err := config.ApplyEnvFile(*configPath); err != nil {
		panic(err)
	}
	config.ApplyOverrides(map[string]string{
		"ENTRY_ADDR":               *flagAddr,
		"ENTRY_TRANSPORT":          *flagTransport,
		"ENTRY_NEXT_ADDR":          *flagNext,
		"ENTRY_TLS_ALPN":           *flagTLSALPN,
		"ENTRY_RATE_LIMIT_PER_MIN": *flagRate,
		"ENTRY_RATE_BURST":         *flagBurst,
		"ASTRA_FRAME_MIN_PAD":      *flagFrameMin,
		"ASTRA_FRAME_MAX_PAD":      *flagFrameMax,
		"ASTRA_MUX_ENABLED":        *flagMux,
	})
	frameCfg := transport.FrameConfig{
		MinPad: getenvInt("ASTRA_FRAME_MIN_PAD", 0),
		MaxPad: getenvInt("ASTRA_FRAME_MAX_PAD", 0),
	}
	muxEnabled := getenvBool("ASTRA_MUX_ENABLED", false)
	muxCfg := muxConfigFromEnv()
	ln, err := listenTransport(getenv("ENTRY_TRANSPORT", "tcp"), getenv("ENTRY_ADDR", defaultAddr))
	if err != nil {
		panic(err)
	}

	fmt.Println("Astra Entry Node listening on", ln.Addr().String())
	go logStats(time.Duration(getenvInt("ENTRY_STATS_INTERVAL_SEC", 30)) * time.Second)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn, frameCfg, muxEnabled, muxCfg)
	}
}

func handle(conn net.Conn, frameCfg transport.FrameConfig, muxEnabled bool, muxCfg transport.MuxConfig) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	remoteKey := conn.RemoteAddr().String()
	if !rl.Allow(remoteKey, getenvInt("ENTRY_RATE_LIMIT_PER_MIN", 60), getenvInt("ENTRY_RATE_BURST", 20)) {
		atomic.AddUint64(&authDenyCount, 1)
		_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeRateLimited, Message: "rate limited"})
		return
	}

	req, err := protocol.ReadHandshake(reader)
	if err != nil {
		atomic.AddUint64(&authDenyCount, 1)
		_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeInvalidFormat, Message: "bad handshake"})
		return
	}

	if failBlock.IsBlocked(req.ClientID, getenvInt("ENTRY_FAIL_BLOCK_COUNT", 10), time.Duration(getenvInt("ENTRY_FAIL_BLOCK_TTL_SEC", 600))*time.Second) {
		atomic.AddUint64(&authDenyCount, 1)
		_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeClientBlocked, Message: "client blocked"})
		return
	}

	if req.Version != protocol.Version {
		atomic.AddUint64(&authDenyCount, 1)
		_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeInvalidFormat, Message: "version mismatch"})
		return
	}

	if protocol.IsClockSkew(req.Timestamp, 60*time.Second) {
		atomic.AddUint64(&authDenyCount, 1)
		_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeClockSkew, Message: "clock skew"})
		return
	}

	nonce := req.Nonce
	now := time.Now()
	if t, exists := usedNonces[nonce]; exists && now.Sub(t) < nonceTTL {
		atomic.AddUint64(&authDenyCount, 1)
		_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeNonceReplay, Message: "replay"})
		return
	}
	usedNonces[nonce] = now
	cleanupNonces()

	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		atomic.AddUint64(&authDenyCount, 1)
		_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeInvalidFormat, Message: "invalid public key"})
		return
	}
	pubKey := ed25519.PublicKey(pubBytes)
	if cached, exists := identityCache[req.ClientID]; exists {
		if !cached.Equal(pubKey) {
			atomic.AddUint64(&authDenyCount, 1)
			_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeInvalidSignature, Message: "key mismatch"})
			return
		}
	} else {
		identityCache[req.ClientID] = pubKey
	}

	if err := protocol.VerifySignature(req); err != nil {
		atomic.AddUint64(&authDenyCount, 1)
		failBlock.Record(req.ClientID)
		_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeInvalidSignature, Message: "signature invalid"})
		return
	}

	keyPair, err := auth.LoadOrCreateKeyPair(getenv("ENTRY_AUTH_KEY_FILE", "entry_auth_key.json"))
	if err != nil {
		atomic.AddUint64(&authDenyCount, 1)
		_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeTokenInvalid, Message: "auth key unavailable"})
		return
	}
	revocations := auth.NewRevocationStore(getenv("ENTRY_REVOKE_FILE", "revocations.json"))

	tokenStr := strings.TrimSpace(req.Token)
	var issuedToken string
	if tokenStr == "" {
		if !getenvBool("ENTRY_ALLOW_TRIAL", true) {
			atomic.AddUint64(&authDenyCount, 1)
			_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeTokenMissing, Message: "token required"})
			return
		}
		trialTTL := time.Duration(getenvInt("ENTRY_TRIAL_TTL_MIN", 30)) * time.Minute
		token := auth.NewToken(req.ClientID, "trial", true, trialTTL, 1)
		signed, err := auth.SignToken(token, keyPair.PrivateKey)
		if err != nil {
			atomic.AddUint64(&authDenyCount, 1)
			_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeTokenInvalid, Message: "token issue failed"})
			return
		}
		issuedToken = signed
	} else {
		token, err := auth.VerifyToken(tokenStr, keyPair.PublicKey)
		if err != nil {
			atomic.AddUint64(&authDenyCount, 1)
			failBlock.Record(req.ClientID)
			_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeTokenInvalid, Message: "token invalid"})
			return
		}
		if token.ClientID != req.ClientID {
			atomic.AddUint64(&authDenyCount, 1)
			failBlock.Record(req.ClientID)
			_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeTokenInvalid, Message: "token client mismatch"})
			return
		}
		if token.Expired(time.Now()) {
			atomic.AddUint64(&authDenyCount, 1)
			failBlock.Record(req.ClientID)
			_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeTokenExpired, Message: "token expired"})
			return
		}
		if revocations.IsClientRevoked(req.ClientID) || revocations.IsTokenRevoked(token.ID) {
			atomic.AddUint64(&authDenyCount, 1)
			failBlock.Record(req.ClientID)
			_ = protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusDeny, Code: protocol.CodeTokenRevoked, Message: "token revoked"})
			return
		}
	}

	if err := protocol.WriteResponse(writer, &protocol.HandshakeResponse{Status: protocol.StatusOK, Token: issuedToken}); err != nil {
		atomic.AddUint64(&authDenyCount, 1)
		return
	}
	atomic.AddUint64(&authOKCount, 1)
	failBlock.Clear(req.ClientID)

	nextAddr := getenv("ENTRY_NEXT_ADDR", "")
	if nextAddr == "" {
		nextAddr = getenv("RELAY_ADDR", "")
	}
	if nextAddr == "" {
		nextAddr = getenv("EXIT_ADDR", "")
	}
	clientConn := wrapBuffered(conn, reader)
	clientStream := transport.WrapConn(clientConn, frameCfg)
	if nextAddr == "" {
		if muxEnabled {
			handleMux(clientStream, "", muxCfg)
			return
		}
		echo(clientStream)
		return
	}
	if muxEnabled {
		handleMux(clientStream, nextAddr, muxCfg)
		return
	}
	proxy(clientStream, nextAddr)
}

func cleanupNonces() {
	now := time.Now()
	for n, t := range usedNonces {
		if now.Sub(t) > nonceTTL {
			delete(usedNonces, n)
		}
	}
}

func echo(conn net.Conn) {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = writer.WriteString(line)
		_ = writer.Flush()
	}
}

func proxy(client net.Conn, addr string) {
	target, err := dialForwardTransport(getenv("ENTRY_FORWARD_TRANSPORT", "tcp"), addr)
	if err != nil {
		log.Printf("proxy dial failed to %s: %v", addr, err)
		return
	}
	defer target.Close()
	go io.Copy(target, client)
	io.Copy(client, target)
}

func handleMux(client net.Conn, nextAddr string, cfg transport.MuxConfig) {
	session := transport.NewMuxSession(client, cfg)
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		go func(st *transport.MuxStream) {
			if nextAddr == "" {
				echo(st)
				return
			}
			proxy(st, nextAddr)
		}(stream)
	}
}

func muxConfigFromEnv() transport.MuxConfig {
	return transport.MuxConfig{
		MaxStreams:         getenvInt("ASTRA_MUX_MAX_STREAMS", 64),
		MaxBufferPerStream: getenvInt("ASTRA_MUX_BUFFER", 256),
		MaxFrameSize:       getenvInt("ASTRA_MUX_MAX_FRAME", 16*1024),
		StreamWindow:       getenvInt("ASTRA_MUX_STREAM_WINDOW", 256*1024),
		SessionWindow:      getenvInt("ASTRA_MUX_SESSION_WINDOW", 1024*1024),
	}
}

type bufferedConn struct {
	net.Conn
	buf *bufio.Reader
}

func wrapBuffered(conn net.Conn, reader *bufio.Reader) net.Conn {
	if reader.Buffered() == 0 {
		return conn
	}
	return &bufferedConn{Conn: conn, buf: reader}
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if b.buf != nil && b.buf.Buffered() > 0 {
		return b.buf.Read(p)
	}
	b.buf = nil
	return b.Conn.Read(p)
}

func listenTransport(name, addr string) (net.Listener, error) {
	switch name {
	case "quic":
		alpn := getenv("ENTRY_TLS_ALPN", "h2")
		alpns := strings.Split(alpn, ",")
		for i := range alpns {
			alpns[i] = strings.TrimSpace(alpns[i])
		}
		if len(alpns) == 0 || alpns[0] == "" {
			alpns = []string{"astra"}
		}
		return transport.QUICTransport{ALPN: alpns}.Listen(addr)
	case "rudp":
		return transport.ReliableUDPTransport{}.Listen(addr)
	case "udp":
		return transport.UDPTransport{}.Listen(addr)
	case "tls":
		alpn := getenv("ENTRY_TLS_ALPN", "h2")
		alpns := strings.Split(alpn, ",")
		for i := range alpns {
			alpns[i] = strings.TrimSpace(alpns[i])
		}
		return transport.TLSTransport{ALPN: alpns, Profile: "chrome"}.Listen(addr)
	default:
		return transport.TCPTransport{}.Listen(addr)
	}
}

func dialForwardTransport(name, addr string) (net.Conn, error) {
	switch name {
	case "quic":
		return transport.QUICTransport{ALPN: []string{"astra"}, Timeout: 10 * time.Second}.Dial(context.Background(), addr)
	case "rudp":
		return transport.ReliableUDPTransport{}.Dial(context.Background(), addr)
	case "udp":
		return transport.UDPTransport{}.Dial(context.Background(), addr)
	default:
		return transport.TCPTransport{}.Dial(context.Background(), addr)
	}
}

func logStats(interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		ok := atomic.LoadUint64(&authOKCount)
		deny := atomic.LoadUint64(&authDenyCount)
		fmt.Printf("stats auth_ok=%d auth_deny=%d\n", ok, deny)
	}
}

type rateLimiter struct {
	mu     sync.Mutex
	bucket map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(ratePerMin int, burst int) *rateLimiter {
	return &rateLimiter{
		bucket: map[string]*bucket{},
	}
}

func (r *rateLimiter) Allow(key string, ratePerMin int, burst int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ratePerMin <= 0 {
		ratePerMin = 60
	}
	if burst <= 0 {
		burst = 20
	}
	b, ok := r.bucket[key]
	if !ok {
		r.bucket[key] = &bucket{tokens: float64(burst - 1), last: time.Now()}
		return true
	}
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	refill := elapsed * float64(ratePerMin) / 60.0
	b.tokens = minFloat(float64(burst), b.tokens+refill)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

type failBlocker struct {
	mu       sync.Mutex
	failures map[string]failEntry
}

type failEntry struct {
	count int
	last  time.Time
}

func newFailBlocker(max int, ttl time.Duration) *failBlocker {
	return &failBlocker{
		failures: map[string]failEntry{},
	}
}

func (f *failBlocker) Record(clientID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := f.failures[clientID]
	entry.count++
	entry.last = time.Now()
	f.failures[clientID] = entry
}

func (f *failBlocker) Clear(clientID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.failures, clientID)
}

func (f *failBlocker) IsBlocked(clientID string, max int, ttl time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.failures[clientID]
	if !ok {
		return false
	}
	if ttl > 0 && time.Since(entry.last) > ttl {
		delete(f.failures, clientID)
		return false
	}
	return entry.count >= max
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return def
}

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "1" || strings.ToLower(v) == "true"
	}
	return def
}
