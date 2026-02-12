package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"astra/internal/client/identity"
	"astra/internal/config"
	"astra/internal/learning"
	"astra/internal/obfs"
	"astra/internal/protocol"
	"astra/internal/selector"
	"astra/internal/sni"
	"astra/internal/transport"

	"golang.org/x/net/http2/hpack"
)

const (
	defaultEntryAddr = "127.0.0.1:8443"
	identityFile     = "identity.dat"
	tokenFile        = "token.dat"
	learningFile     = "learning.json"
	healthFile       = "nodes_health.json"
)

func main() {
	configPath := flag.String("config", getenv("ASTRA_CONFIG", "configs/astra-client.json"), "config path")
	flagEntry := flag.String("entry", "", "ENTRY_ADDR")
	flagTransports := flag.String("transports", "", "ASTRA_TRANSPORTS")
	flagNetworkID := flag.String("network", "", "ASTRA_NETWORK_ID")
	flagNodes := flag.String("nodes", "", "ASTRA_NODES")
	flagMux := flag.String("mux", "", "ASTRA_MUX_ENABLED")
	flagFrameMin := flag.String("frame-min", "", "ASTRA_FRAME_MIN_PAD")
	flagFrameMax := flag.String("frame-max", "", "ASTRA_FRAME_MAX_PAD")
	flagObfsMax := flag.String("obfs-max", "", "OBFS_PREAMBLE_MAX")
	flagObfsTpl := flag.String("obfs-template", "", "OBFS_PREAMBLE_TEMPLATE")
	flagTLSPre := flag.String("tls-preamble", "", "TLS_APP_PREAMBLE_TEMPLATE")
	flagTLSFrag := flag.String("tls-frag", "", "TLS_FRAGMENT_MAX")
	flag.Parse()
	if err := config.ApplyEnvFile(*configPath); err != nil {
		log.Fatalf("config load failed: %v", err)
	}
	config.ApplyOverrides(map[string]string{
		"ENTRY_ADDR":                *flagEntry,
		"ASTRA_TRANSPORTS":          *flagTransports,
		"ASTRA_NETWORK_ID":          *flagNetworkID,
		"ASTRA_NODES":               *flagNodes,
		"ASTRA_MUX_ENABLED":         *flagMux,
		"ASTRA_FRAME_MIN_PAD":       *flagFrameMin,
		"ASTRA_FRAME_MAX_PAD":       *flagFrameMax,
		"OBFS_PREAMBLE_MAX":         *flagObfsMax,
		"OBFS_PREAMBLE_TEMPLATE":    *flagObfsTpl,
		"TLS_APP_PREAMBLE_TEMPLATE": *flagTLSPre,
		"TLS_FRAGMENT_MAX":          *flagTLSFrag,
	})
	fmt.Println("Astra Client starting...")

	var id *identity.Identity
	var err error

	if _, err = os.Stat(identityFile); err == nil {
		id, err = identity.LoadIdentity(identityFile)
		fmt.Println("Loaded existing identity")
	} else {
		id, err = identity.GenerateIdentity()
		if err == nil {
			err = id.Save(identityFile)
			fmt.Println("Generated new identity")
		}
	}

	if err != nil {
		log.Fatal(err)
	}

	token := loadToken(tokenFile)
	networkID := getenv("ASTRA_NETWORK_ID", "")
	if networkID == "" {
		networkID = detectNetworkID()
	}
	entryAddr := getenv("ENTRY_ADDR", defaultEntryAddr)
	nodes := parseNodes(os.Getenv("ASTRA_NODES"))
	if len(nodes) > 0 && getenvBool("ASTRA_HEALTH_CHECKS", true) {
		health := selector.LoadHealth(healthFile)
		maxFails := getenvInt("ASTRA_NODE_MAX_FAILS", 3)
		ttl := time.Duration(getenvInt("ASTRA_NODE_HEALTH_TTL_SEC", 600)) * time.Second
		nodes = filterHealthyNodes(nodes, health, maxFails, ttl)
	}
	entryAddrs := pickEntryAddrs(nodes, entryAddr)

	learn := learning.Load(learningFile)
	profiles := defaultProfiles()
	obfsCfg := obfs.Config{
		Mode:             obfs.ModePreamble,
		MaxPreamble:      getenvInt("OBFS_PREAMBLE_MAX", 64),
		PreambleTemplate: getenv("OBFS_PREAMBLE_TEMPLATE", "random"),
	}
	frameCfg := transport.FrameConfig{
		MinPad: getenvInt("ASTRA_FRAME_MIN_PAD", 0),
		MaxPad: getenvInt("ASTRA_FRAME_MAX_PAD", 0),
	}
	muxEnabled := getenvBool("ASTRA_MUX_ENABLED", false)
	muxCfg := muxConfigFromEnv()
	transports := parseTransports(getenv("ASTRA_TRANSPORTS", "tcp,tls,udp"))
	maxAttempts := getenvInt("ASTRA_MAX_ATTEMPTS", 6)
	attempts := 0

	for _, addr := range entryAddrs {
		for _, transportName := range transports {
			profileOrder := rankProfilesForTransport(learn, profiles, transportName, networkID)
			for _, profile := range profileOrder {
				if attempts >= maxAttempts {
					break
				}
				attempts++
				resp, conn, rtt, err := attemptHandshake(addr, transportName, profile, id, token, obfsCfg, networkID)
				key := learningKey(profile.ID, transportName, networkID)
				learn.Update(key, rtt, err == nil && resp != nil && resp.Status == protocol.StatusOK)
				if err != nil {
					fmt.Printf("Handshake failed (%s/%s/%s): %v\n", addr, transportName, profile.ID, err)
					continue
				}
				if resp.Token != "" {
					_ = os.WriteFile(tokenFile, []byte(resp.Token), 0600)
					fmt.Println("Received and saved new token")
				}
				if resp.Status != protocol.StatusOK {
					fmt.Printf("Auth denied (%s/%s/%s): %s %s\n", addr, transportName, profile.ID, resp.Code, resp.Message)
					conn.Close()
					continue
				}
				fmt.Printf("Auth OK (%s/%s/%s)\n", addr, transportName, profile.ID)
				stream := transport.WrapConn(conn, frameCfg)
				var dataConn net.Conn = stream
				if muxEnabled {
					session := transport.NewMuxSession(stream, muxCfg)
					st, err := session.OpenStream(0)
					if err != nil {
						conn.Close()
						log.Fatalf("mux open failed: %v", err)
					}
					dataConn = st
				}
				reader := bufio.NewReader(dataConn)
				writer := bufio.NewWriter(dataConn)
				_, _ = writer.WriteString("PING\n")
				_ = writer.Flush()
				reply, _ := reader.ReadString('\n')
				fmt.Println("Server reply:", reply)
				conn.Close()
				return
			}
		}
	}

	log.Fatal("All handshake attempts failed")
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

func probeTCP(ctx context.Context, addr string) (time.Duration, error) {
	t := transport.TCPTransport{Timeout: 2 * time.Second}
	start := time.Now()
	conn, err := t.Dial(ctx, addr)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
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

func parseNodes(raw string) []selector.Node {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	nodes := make([]selector.Node, 0, len(parts))
	for _, p := range parts {
		fields := strings.SplitN(p, "|", 3)
		if len(fields) != 3 {
			continue
		}
		nodes = append(nodes, selector.Node{
			Role: selector.NodeRole(fields[0]),
			ID:   fields[1],
			Addr: fields[2],
		})
	}
	return nodes
}

func filterHealthyNodes(nodes []selector.Node, health *selector.HealthStore, maxFails int, ttl time.Duration) []selector.Node {
	if health == nil {
		return nodes
	}
	out := make([]selector.Node, 0, len(nodes))
	for _, n := range nodes {
		rtt, err := probeTCP(context.Background(), n.Addr)
		health.Update(n.ID, rtt, err == nil)
		if health.IsHealthy(n.ID, maxFails, ttl) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nodes
	}
	return out
}

func pickEntryAddrs(nodes []selector.Node, fallback string) []string {
	if len(nodes) == 0 {
		return []string{fallback}
	}
	entries := make([]selector.Node, 0)
	for _, n := range nodes {
		if n.Role == selector.RoleEntry {
			entries = append(entries, n)
		}
	}
	if len(entries) == 0 {
		return []string{fallback}
	}
	addrs := make([]string, 0, len(entries))
	for _, e := range entries {
		addrs = append(addrs, e.Addr)
	}
	return addrs
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

func attemptHandshake(addr string, transportName string, profile sni.Profile, id *identity.Identity, token string, obfsCfg obfs.Config, networkID string) (*protocol.HandshakeResponse, net.Conn, time.Duration, error) {
	start := time.Now()
	conn, err := dialTransport(transportName, addr, profile)
	if err != nil {
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
			return nil, nil, time.Since(start), err
		}
	}
	if maxFrag := getenvInt("TLS_FRAGMENT_MAX", 0); transportName == "tls" && maxFrag > 0 {
		if err := writeHandshakeFragmented(writer, req, preamble, maxFrag); err != nil {
			conn.Close()
			return nil, nil, time.Since(start), err
		}
	} else {
		if err := protocol.WriteHandshake(writer, req, preamble); err != nil {
			conn.Close()
			return nil, nil, time.Since(start), err
		}
	}
	resp, err := protocol.ReadResponse(reader)
	if err != nil {
		conn.Close()
		return nil, nil, time.Since(start), err
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
	switch name {
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
			Timeout:    4 * time.Second,
		}.Dial(context.Background(), addr)
	default:
		return transport.TCPTransport{Timeout: 4 * time.Second}.Dial(context.Background(), addr)
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

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "1" || strings.ToLower(v) == "true"
	}
	return def
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
