package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
)

type Identity struct {
	ClientID   string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// GenerateIdentity
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	id := &Identity{
		ClientID:   uuid.New().String(),
		PrivateKey: priv,
		PublicKey:  pub,
	}

	return id, nil
}

// Save
func (i *Identity) Save(path string) error {
	data := i.ClientID + "\n" +
		hex.EncodeToString(i.PrivateKey) + "\n" +
		hex.EncodeToString(i.PublicKey)

	return os.WriteFile(path, []byte(data), 0600)
}

// Sign
func (i *Identity) Sign(data []byte) []byte {
	return ed25519.Sign(i.PrivateKey, data)
}

// Verify
func (i *Identity) Verify(data, signature []byte) bool {
	return ed25519.Verify(i.PublicKey, data, signature)
}

// LoadIdentity
func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("invalid identity file")
	}

	priv, err := hex.DecodeString(lines[1])
	if err != nil {
		return nil, err
	}

	pub, err := hex.DecodeString(lines[2])
	if err != nil {
		return nil, err
	}

	return &Identity{
		ClientID:   lines[0],
		PrivateKey: ed25519.PrivateKey(priv),
		PublicKey:  ed25519.PublicKey(pub),
	}, nil
}
