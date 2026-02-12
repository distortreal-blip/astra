package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func LoadOrCreateCert(certFile, keyFile, host string) (tls.Certificate, error) {
	if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		return cert, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certOut, err := os.Create(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer certOut.Close()
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer keyOut.Close()
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return tls.LoadX509KeyPair(certFile, keyFile)
}
