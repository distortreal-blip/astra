package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type Token struct {
	ID          string `json:"id"`
	ClientID    string `json:"client_id"`
	Plan        string `json:"plan"`
	Trial       bool   `json:"trial"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
	MaxSessions int    `json:"max_sessions"`
}

func NewToken(clientID, plan string, trial bool, ttl time.Duration, maxSessions int) *Token {
	now := time.Now().Unix()
	return &Token{
		ID:          newID(),
		ClientID:    clientID,
		Plan:        plan,
		Trial:       trial,
		IssuedAt:    now,
		ExpiresAt:   now + int64(ttl.Seconds()),
		MaxSessions: maxSessions,
	}
}

func SignToken(token *Token, priv ed25519.PrivateKey) (string, error) {
	payload, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return payloadB64 + "." + sigB64, nil
}

func VerifyToken(signed string, pub ed25519.PublicKey) (*Token, error) {
	parts := splitSignedToken(signed)
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}
	payloadB64 := parts[0]
	sigB64 := parts[1]
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, []byte(payloadB64), sig) {
		return nil, errors.New("invalid token signature")
	}
	var token Token
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (t *Token) Expired(now time.Time) bool {
	return now.Unix() > t.ExpiresAt
}
