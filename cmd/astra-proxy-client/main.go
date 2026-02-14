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
	"io"
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
	"astra/internal/sni"
	"astra/internal/transport"

	"golang.org/x/net/http2/hpack"
)

const (
	defaultEntryAddr = "127.0.0.1:8443"
	identityFile     = "identity.dat"
	tokenFile        = "token.dat"
	learningFile     = "learning.json"
)

func main() {
	configPath := flag.String("config", getenv("ASTRA_CONFIG", "configs/astra-proxy-client.json"), "config path")
	flagListen := flag.String("listen", "", "PROXY_LISTEN")
	flagEntry := flag.String("entry", "", "ENTRY_ADDR")
	flag.Parse()
	if err := config.ApplyEnvFile(*configPath); err != nil {
		log.Fatalf("config load failed: %v", err)
	}
	config.ApplyOverrides(map[string]string{
		"PROXY_LISTEN": *flagListen,
		"ENTRY_ADDR":   *flagEntry,
	})

	listenAddr := getenv("PROXY_LISTEN", "127.0.0.1:1080")
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("proxy listen failed: %v", err)
	}
	fmt.Println("ASTRA proxy listening on", listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")
	if len(parts) < 2 || strings.ToUpper(parts[0]) != "CONNECT" {
		writeHTTPError(conn, "400 Bad Request")
		return
	}
	target := parts[1]
	if !strings.Contains(target, ":") {
		target = target + ":80"
	}
	if err := consumeProxyHeaders(reader); err != nil {
		return
	}

	serverConn, err := connectToEntry(target)
	if err != nil {
		writeHTTPError(conn, "502 Bad Gateway")
		return
	}
	defer serverConn.Close()

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go io.Copy(serverConn, reader)
	io.Copy(conn, serverConn)
}

func connectToEntry(target string) (net.Conn, error) {
	id, err := loadIdentity(identityFile)
	if err != nil {
		return nil, err
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
		MinPad: getenvInt("ASTRA_FRAME_MIN_PAD", 0),
		MaxPad: getenvInt("ASTRA_FRAME_MAX_PAD", 0),
	}
	transports := parseTransports(getenv("ASTRA_TRANSPORTS", "tcp"))

	var conn net.Conn
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
			break
		}
		if conn != nil {
			break
		}
	}
	if conn == nil {
		return nil, fmt.Errorf("failed to connect to entry")
	}

	stream := transport.WrapConn(conn, frameCfg)
	writer := bufio.NewWriter(stream)
	if _, err := writer.WriteString("CONNECT " + target + "\n"); err != nil {
		conn.Close()
		return nil, err
	}
	if err := writer.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return stream, nil
}

func writeHTTPError(conn net.Conn, status string) {
	_, _ = conn.Write([]byte("HTTP/1.1 " + status + "\r\n\r\n"))
}

func consumeProxyHeaders(reader *bufio.Reader) error {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
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
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "CONNECT"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
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
