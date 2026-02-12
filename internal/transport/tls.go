package transport

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

type TLSTransport struct {
	ServerName string
	ALPN       []string
	Profile    string
	Timeout    time.Duration
}

func (t TLSTransport) Name() string { return "tls" }

func (t TLSTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{}
	if t.Timeout > 0 {
		d.Timeout = t.Timeout
	}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &utls.Config{
		ServerName:         t.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         t.ALPN,
	}
	helloID := resolveHelloID(t.Profile)
	uconn := utls.UClient(rawConn, cfg, helloID)
	if err := uconn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return uconn, nil
}

func (t TLSTransport) Listen(addr string) (net.Listener, error) {
	certFile := getenv("ENTRY_TLS_CERT", "entry_cert.pem")
	keyFile := getenv("ENTRY_TLS_KEY", "entry_key.pem")
	host := getenv("ENTRY_TLS_HOST", "astra.local")
	cert, err := LoadOrCreateCert(certFile, keyFile, host)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   t.ALPN,
	}
	return tls.Listen("tcp", addr, cfg)
}

func resolveHelloID(profile string) utls.ClientHelloID {
	switch profile {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "chrome":
		fallthrough
	default:
		return utls.HelloChrome_Auto
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
