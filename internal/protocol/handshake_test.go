package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func TestHandshakeSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	req := &HandshakeRequest{
		Version:   Version,
		ClientID:  "client-1",
		PublicKey: hex.EncodeToString(pub),
		Timestamp: time.Now().Unix(),
		Nonce:     "nonce",
		Token:     "token",
		NetworkID: "wifi",
		ProfileID: "google-h2",
		Transport: "tls",
		ObfsMode:  "preamble",
	}
	sig := ed25519.Sign(priv, []byte(SignPayload(req)))
	req.Signature = hex.EncodeToString(sig)

	if err := VerifySignature(req); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	req.ProfileID = "tampered"
	if err := VerifySignature(req); err == nil {
		t.Fatalf("expected signature mismatch")
	}
}
