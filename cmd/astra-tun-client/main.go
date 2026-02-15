package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"astra/internal/client/identity"
	"astra/internal/config"
	"astra/internal/learning"
	"astra/internal/obfs"
	"astra/internal/protocol"
	"astra/internal/sni"
	"astra/internal/transport"
	"astra/internal/tun"

	"golang.org/x/net/http2/hpack"
)

const (
	defaultEntryAddr = "127.0.0.1:8443"
	identityFile     = "identity.dat"
	tokenFile        = "token.dat"
	learningFile     = "learning.json"
)

func main() {
	configPath := flag.String("config", getenv("ASTRA_CONFIG", "configs/astra-tun-client.json"), "config path")
	flag.Parse()
	if err := config.ApplyEnvFile(*configPath); err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunName := getenv("ASTRA_TUN_NAME", "Astra")
	tunMTU := getenvInt("ASTRA_TUN_MTU", 1400)
	tunAddr := getenv("ASTRA_TUN_ADDR", "10.10.0.2/24")
	tunGW := getenv("ASTRA_TUN_GW", "10.10.0.1")
	fullTunnel := getenv("ASTRA_FULL_TUNNEL", "1") == "1" || getenv("ASTRA_FULL_TUNNEL", "1") == "true"

	dev, err := tun.Create(tunName, tunMTU)
	if err != nil {
		log.Fatalf("tun create failed: %v", err)
	}

	shutdownOnce := sync.Once{}
	shutdown := func() {
		shutdownOnce.Do(func() {
			log.Printf("shutdown: removing routes, closing TUN...")
			RemoveAddedRoutes()
			_ = tun.Close(dev)
			log.Printf("shutdown done (routes removed, TUN closed)")
		})
	}
	defer shutdown()

	if runtime.GOOS == "windows" {
		if err := SetInterfaceAddress(dev.Name, tunAddr); err != nil {
			log.Fatalf("set TUN address: %v", err)
		}
		log.Printf("TUN address %s on %s", tunAddr, dev.Name)
		if err := RemoveAllRoutesForInterface(dev.Name); err != nil {
			log.Printf("warning: remove stale routes: %v", err)
		}
		if fullTunnel {
			if err := AddRoute(dev.Name, "0.0.0.0/0", tunGW); err != nil {
				log.Fatalf("add default route: %v", err)
			}
			log.Printf("route 0.0.0.0/0 via %s (full tunnel)", tunGW)
		}
	}

	log.Printf("TUN up: %s (mtu=%d)", dev.Name, dev.MTU)

	id, err := loadIdentity(identityFile)
	if err != nil {
		log.Fatal(err)
	}

	token := loadToken(tokenFile)
	networkID := getenv("ASTRA_NETWORK_ID", "")
	if networkID == "" {
		networkID = detectNetworkID()
	}

	entryAddr := getenv("ENTRY_ADDR", defaultEntryAddr)
	learn := learning.Load(learningFile)
	profiles := defaultProfiles()
	obfsCfg := obfs.Config{
		Mode:             obfs.ModePreamble,
		MaxPreamble:      getenvInt("OBFS_PREAMBLE_MAX", 64),
		PreambleTemplate: getenv("OBFS_PREAMBLE_TEMPLATE", "random"),
	}
	frameCfg := transport.FrameConfig{
		MinPad: getenvInt("ASTRA_FRAME_MIN_PAD", 16),
		MaxPad: getenvInt("ASTRA_FRAME_MAX_PAD", 64),
	}
	transports := parseTransports(getenv("ASTRA_TRANSPORTS", "quic,tcp,tls,rudp"))

	if frameCfg.MinPad > 0 || frameCfg.MaxPad > 0 {
		log.Printf("frame_padding: enabled min=%d max=%d", frameCfg.MinPad, frameCfg.MaxPad)
	} else {
		log.Printf("frame_padding: disabled")
	}

	var conn net.Conn
	var usedTransport string
	if c, resp, tr := tryConnectParallel(entryAddr, transports, learn, profiles, networkID, id, token, obfsCfg); c != nil && resp != nil {
		conn = c
		usedTransport = tr
		if resp.Token != "" {
			_ = os.WriteFile(tokenFile, []byte(resp.Token), 0600)
		}
	}
	if conn == nil {
		for _, transportName := range transports {
			profileOrder := rankProfilesForTransport(learn, profiles, transportName, networkID)
			for _, profile := range profileOrder {
				resp, c, _, err := attemptHandshake(entryAddr, transportName, profile, id, token, obfsCfg, networkID)
				key := learningKey(profile.ID, transportName, networkID)
				learn.Update(key, 0, err == nil && resp != nil && resp.Status == protocol.StatusOK)
				if err != nil {
					continue
				}
				if resp.Token != "" {
					_ = os.WriteFile(tokenFile, []byte(resp.Token), 0600)
				}
				if resp.Status != protocol.StatusOK {
					c.Close()
					continue
				}
				conn = c
				usedTransport = transportName
				break
			}
			if conn != nil {
				break
			}
		}
	}
	if conn == nil {
		log.Fatal("failed to connect to entry")
	}
	log.Printf("connected to entry %s transport=%s", entryAddr, usedTransport)
	defer conn.Close()

	stream := transport.WrapConn(conn, frameCfg)
	reader := bufio.NewReader(stream)
	writer := bufio.NewWriter(stream)
	writerMu := sync.Mutex{}

	// On signal: close conn so pumps exit, then defer runs (remove routes, close TUN).
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("received signal %v, disconnecting...", sig)
		cancel()
		conn.Close()
	}()

	keepAliveSec := getenvInt("ASTRA_KEEPALIVE_SEC", 3)
	jitterPct := getenvInt("ASTRA_KEEPALIVE_JITTER_PCT", 15)
	if keepAliveSec > 0 {
		if jitterPct > 0 {
			log.Printf("keepalive: interval=%ds jitter=±%d%%", keepAliveSec, jitterPct)
		}
		go keepAlive(writer, &writerMu, shutdown, time.Duration(keepAliveSec)*time.Second, jitterPct)
	} else {
		log.Printf("keepalive disabled (ASTRA_KEEPALIVE_SEC=0)")
	}
	if getenvInt("ASTRA_LOG_TUN_STATS_SEC", 5) > 0 {
		go logTunStats(time.Duration(getenvInt("ASTRA_LOG_TUN_STATS_SEC", 5)) * time.Second)
	}
	go pumpTunToConn(dev, writer, &writerMu, shutdown)
	pumpConnToTun(dev, reader)
}

var tunTxBytes uint64
var tunRxBytes uint64

func logTunStats(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		tx := atomic.LoadUint64(&tunTxBytes)
		rx := atomic.LoadUint64(&tunRxBytes)
		log.Printf("tun stats: tx=%d rx=%d", tx, rx)
	}
}

func keepAlive(writer *bufio.Writer, writerMu *sync.Mutex, closeFn func(), interval time.Duration, jitterPct int) {
	if jitterPct < 0 {
		jitterPct = 0
	}
	if jitterPct > 50 {
		jitterPct = 50
	}
	for {
		writerMu.Lock()
		err := writePacket(writer, nil)
		writerMu.Unlock()
		if err != nil {
			log.Printf("keepalive write error: %v", err)
			closeFn()
			return
		}
		delay := interval
		if jitterPct > 0 {
			// ±jitterPct%: delay in [interval*(1-pct/100), interval*(1+pct/100)]
			delta := int64(interval) * int64(jitterPct) / 100
			if delta > 0 {
				b := make([]byte, 8)
				rand.Read(b)
				n := binary.BigEndian.Uint64(b)
				offset := int64(n%(2*uint64(delta)+1)) - int64(delta)
				delay = interval + time.Duration(offset)
				if delay < interval/2 {
					delay = interval / 2
				}
			}
		}
		time.Sleep(delay)
	}
}

func pumpTunToConn(dev *tun.Device, writer *bufio.Writer, writerMu *sync.Mutex, closeFn func()) {
	buf := make([]byte, 65535)
	for {
		n, err := tun.ReadPacket(dev, buf)
		if err != nil {
			log.Printf("tun read error (disconnect reason): %v", err)
			closeFn()
			return
		}
		if n <= 0 || n > 0xffff {
			continue
		}
		atomic.AddUint64(&tunTxBytes, uint64(n))
		writerMu.Lock()
		err = writePacket(writer, buf[:n])
		writerMu.Unlock()
		if err != nil {
			log.Printf("tun->conn write error: %v", err)
			closeFn()
			return
		}
	}
}

func pumpConnToTun(dev *tun.Device, reader *bufio.Reader) {
	for {
		payload, err := readPacket(reader)
		if err != nil {
			log.Printf("conn read error (tunnel/entry closed): %v", err)
			return
		}
		if len(payload) == 0 {
			continue
		}
		atomic.AddUint64(&tunRxBytes, uint64(len(payload)))
		if _, err := tun.WritePacket(dev, payload); err != nil {
			log.Printf("conn->tun write error: %v", err)
			return
		}
	}
}

func writePacket(writer *bufio.Writer, payload []byte) error {
	if len(payload) > 0xffff {
		return nil
	}
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(payload)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := writer.Write(payload); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func readPacket(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header))
	if length <= 0 {
		return nil, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func loadIdentity(path string) (*identity.Identity, error) {
	if _, err := os.Stat(path); err == nil {
		return identity.LoadIdentity(path)
	}
	id, err := identity.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if err := id.Save(path); err != nil {
		return nil, err
	}
	return id, nil
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func loadToken(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(b))
}

func defaultProfiles() []sni.Profile {
	return []sni.Profile{
		{ID: "google-h2", ServerName: "google.com", ALPN: "h2", FingerprintID: "chrome"},
		{ID: "google-h1", ServerName: "google.com", ALPN: "http/1.1", FingerprintID: "chrome"},
		{ID: "gstatic-h2", ServerName: "gstatic.com", ALPN: "h2", FingerprintID: "chrome"},
		{ID: "youtube-h2", ServerName: "youtube.com", ALPN: "h2", FingerprintID: "chrome"},
		{ID: "android-h2", ServerName: "android.com", ALPN: "h2", FingerprintID: "android"},
		{ID: "play-h2", ServerName: "play.googleapis.com", ALPN: "h2", FingerprintID: "android"},
		{ID: "google-ff", ServerName: "google.com", ALPN: "h2", FingerprintID: "firefox"},
	}
}

func rankProfilesForTransport(store *learning.Store, profiles []sni.Profile, transportName string, networkID string) []sni.Profile {
	if store == nil {
		return profiles
	}
	ordered := make([]sni.Profile, 0, len(profiles))
	for _, p := range profiles {
		ordered = append(ordered, p)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return store.Score(learningKey(ordered[i].ID, transportName, networkID)) > store.Score(learningKey(ordered[j].ID, transportName, networkID))
	})
	return ordered
}

// tryConnectParallel tries the best profile of each transport in parallel; first success wins (faster connect).
func tryConnectParallel(entryAddr string, transports []string, learn *learning.Store, profiles []sni.Profile, networkID string, id *identity.Identity, token string, obfsCfg obfs.Config) (net.Conn, *protocol.HandshakeResponse, string) {
	type result struct {
		conn      net.Conn
		resp      *protocol.HandshakeResponse
		transport string
	}
	var winnerMu sync.Mutex
	var winner *result
	done := make(chan result, len(transports))
	for _, transportName := range transports {
		transportName := transportName
		profileOrder := rankProfilesForTransport(learn, profiles, transportName, networkID)
		if len(profileOrder) == 0 {
			done <- result{}
			continue
		}
		go func() {
			defer func() { done <- result{} }()
			for _, profile := range profileOrder {
				resp, c, _, err := attemptHandshake(entryAddr, transportName, profile, id, token, obfsCfg, networkID)
				key := learningKey(profile.ID, transportName, networkID)
				learn.Update(key, 0, err == nil && resp != nil && resp.Status == protocol.StatusOK)
				if err != nil || resp == nil || resp.Status != protocol.StatusOK {
					if c != nil {
						c.Close()
					}
					continue
				}
				winnerMu.Lock()
				if winner == nil {
					winner = &result{conn: c, resp: resp, transport: transportName}
					winnerMu.Unlock()
					return
				}
				winnerMu.Unlock()
				c.Close()
				return
			}
		}()
	}
	deadline := time.After(8 * time.Second)
	for i := 0; i < len(transports); i++ {
		select {
		case <-done:
			winnerMu.Lock()
			w := winner
			winnerMu.Unlock()
			if w != nil {
				return w.conn, w.resp, w.transport
			}
		case <-deadline:
			winnerMu.Lock()
			w := winner
			winnerMu.Unlock()
			if w != nil {
				return w.conn, w.resp, w.transport
			}
			return nil, nil, ""
		}
	}
	winnerMu.Lock()
	w := winner
	winnerMu.Unlock()
	if w != nil {
		return w.conn, w.resp, w.transport
	}
	return nil, nil, ""
}

func attemptHandshake(addr string, transportName string, profile sni.Profile, id *identity.Identity, token string, obfsCfg obfs.Config, networkID string) (*protocol.HandshakeResponse, net.Conn, time.Duration, error) {
	start := time.Now()
	log.Printf("trying transport=%s profile=%s", transportName, profile.ID)
	conn, err := dialTransport(transportName, addr, profile)
	if err != nil {
		log.Printf("transport=%s dial failed: %v", transportName, err)
		return nil, nil, 0, err
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	timestamp := time.Now().Unix()
	nonce := generateNonce()
	obfsMode := string(obfsCfg.Mode)
	if transportName == "tls" {
		obfsMode = string(obfs.ModeNone)
	}
	req := &protocol.HandshakeRequest{
		Version:   protocol.Version,
		ClientID:  id.ClientID,
		PublicKey: hex.EncodeToString(id.PublicKey),
		Timestamp: timestamp,
		Nonce:     nonce,
		Token:     token,
		NetworkID: networkID,
		ProfileID: profile.ID,
		Transport: transportName,
		ObfsMode:  obfsMode,
	}
	signature := id.Sign([]byte(protocol.SignPayload(req)))
	req.Signature = hex.EncodeToString(signature)

	preamble := []byte(nil)
	if obfsCfg.Enabled() && transportName != "tls" {
		preamble = obfs.GeneratePreamble(obfsCfg.MaxPreamble, obfsCfg.PreambleTemplate)
	}
	if transportName == "tls" {
		if err := writeTLSAppPreamble(writer, getenv("TLS_APP_PREAMBLE_TEMPLATE", "http2frames")); err != nil {
			conn.Close()
			log.Printf("transport=%s handshake write failed: %v", transportName, err)
			return nil, nil, time.Since(start), err
		}
	}
	if maxFrag := getenvInt("TLS_FRAGMENT_MAX", 0); transportName == "tls" && maxFrag > 0 {
		if err := writeHandshakeFragmented(writer, req, preamble, maxFrag); err != nil {
			conn.Close()
			log.Printf("transport=%s handshake write failed: %v", transportName, err)
			return nil, nil, time.Since(start), err
		}
	} else {
		if err := protocol.WriteHandshake(writer, req, preamble); err != nil {
			conn.Close()
			log.Printf("transport=%s handshake write failed: %v", transportName, err)
			return nil, nil, time.Since(start), err
		}
	}
	resp, err := protocol.ReadResponse(reader)
	if err != nil {
		conn.Close()
		log.Printf("transport=%s handshake failed: %v", transportName, err)
		return nil, nil, time.Since(start), err
	}
	if resp.Status != protocol.StatusOK {
		log.Printf("transport=%s denied: code=%s message=%s", transportName, resp.Code, resp.Message)
	}
	return resp, conn, time.Since(start), nil
}

func parseTransports(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{"tcp"}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"tcp"}
	}
	return out
}

func dialTransport(name, addr string, profile sni.Profile) (net.Conn, error) {
	dialTimeout := 2 * time.Second
	switch name {
	case "quic":
		alpn := profile.ALPN
		if alpn == "" {
			alpn = "h2"
		}
		return transport.QUICTransport{
			ServerName: profile.ServerName,
			ALPN:       []string{alpn, "http/1.1", "astra"},
			Timeout:    dialTimeout,
		}.Dial(context.Background(), addr)
	case "rudp":
		return transport.ReliableUDPTransport{}.Dial(context.Background(), addr)
	case "udp":
		return transport.UDPTransport{}.Dial(context.Background(), addr)
	case "tls":
		alpn := profile.ALPN
		if alpn == "" {
			alpn = "h2"
		}
		return transport.TLSTransport{
			ServerName: profile.ServerName,
			ALPN:       []string{alpn, "http/1.1"},
			Profile:    profile.FingerprintID,
			Timeout:    dialTimeout,
		}.Dial(context.Background(), addr)
	default:
		return transport.TCPTransport{Timeout: dialTimeout}.Dial(context.Background(), addr)
	}
}

func learningKey(profileID, transportName string, networkID string) string {
	if networkID == "" {
		networkID = "default"
	}
	return transportName + "|" + profileID + "|" + networkID
}

func writeTLSAppPreamble(writer *bufio.Writer, template string) error {
	switch template {
	case "http1":
		_, _ = writer.WriteString(buildHTTP1Preamble(getenvInt("TLS_HTTP1_PAD_BYTES", 0)))
	case "http2":
		_, _ = writer.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	case "http2frames":
		_, _ = writer.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		writeHTTP2Settings(writer)
		writeHTTP2Headers(writer, "example.com")
		writeHTTP2Data(writer, []byte("ping"))
		writeHTTP2Ping(writer)
	default:
		return nil
	}
	return writer.Flush()
}

func writeHTTP2Settings(writer *bufio.Writer) {
	payload := []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x64}
	writeHTTP2Frame(writer, 0x4, 0x0, 0, payload)
}

func writeHTTP2Ping(writer *bufio.Writer) {
	payload := []byte("12345678")
	writeHTTP2Frame(writer, 0x6, 0x0, 0, payload)
}

func writeHTTP2Frame(writer *bufio.Writer, frameType byte, flags byte, streamID uint32, payload []byte) {
	length := len(payload)
	header := []byte{
		byte(length >> 16), byte(length >> 8), byte(length),
		frameType,
		flags,
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
	}
	_, _ = writer.Write(header)
	_, _ = writer.Write(payload)
}

func writeHTTP2Headers(writer *bufio.Writer, authority string) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	_ = enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "Mozilla/5.0"})
	_ = enc.WriteField(hpack.HeaderField{Name: "accept", Value: "*/*"})
	writeHTTP2Frame(writer, 0x1, 0x4, 1, buf.Bytes())
}

func writeHTTP2Data(writer *bufio.Writer, data []byte) {
	writeHTTP2Frame(writer, 0x0, 0x1, 1, data)
}

func buildHTTP1Preamble(pad int) string {
	base := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
	if pad > 0 {
		random := make([]byte, pad)
		_, _ = rand.Read(random)
		base += "X-Pad: " + hex.EncodeToString(random) + "\r\n"
	}
	return base + "\r\n"
}

func writeHandshakeFragmented(writer *bufio.Writer, req *protocol.HandshakeRequest, preamble []byte, maxChunk int) error {
	if len(preamble) > 0 {
		if _, err := writer.Write(preamble); err != nil {
			return err
		}
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	for len(data) > 0 {
		chunk := maxChunk
		if chunk <= 0 || chunk > len(data) {
			chunk = len(data)
		}
		if _, err := writer.Write(data[:chunk]); err != nil {
			return err
		}
		data = data[chunk:]
	}
	return writer.Flush()
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

func detectNetworkID() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		switch {
		case strings.Contains(name, "wi-fi") || strings.Contains(name, "wifi") || strings.Contains(name, "wlan") || strings.Contains(name, "wireless"):
			return "wifi:" + iface.Name
		case strings.Contains(name, "wwan") || strings.Contains(name, "cell") || strings.Contains(name, "lte") || strings.Contains(name, "4g") || strings.Contains(name, "5g"):
			return "cell:" + iface.Name
		case strings.Contains(name, "eth"):
			return "eth:" + iface.Name
		}
	}
	return "unknown"
}
