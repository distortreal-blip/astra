package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

type RevocationStore struct {
	path string
	mu   sync.Mutex
	data revocationData
}

type revocationData struct {
	RevokedClients map[string]bool `json:"revoked_clients"`
	RevokedTokens  map[string]bool `json:"revoked_tokens"`
}

func NewRevocationStore(path string) *RevocationStore {
	store := &RevocationStore{
		path: path,
		data: revocationData{
			RevokedClients: map[string]bool{},
			RevokedTokens:  map[string]bool{},
		},
	}
	store.load()
	return store
}

func (s *RevocationStore) IsClientRevoked(clientID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.RevokedClients[clientID]
}

func (s *RevocationStore) IsTokenRevoked(tokenID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.RevokedTokens[tokenID]
}

func (s *RevocationStore) RevokeClient(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.RevokedClients[clientID] = true
	s.persist()
}

func (s *RevocationStore) RevokeToken(tokenID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.RevokedTokens[tokenID] = true
	s.persist()
}

func (s *RevocationStore) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.data)
}

func (s *RevocationStore) persist() {
	b, _ := json.MarshalIndent(s.data, "", "  ")
	_ = os.WriteFile(s.path, b, 0600)
}

type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

type keyPairFile struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func LoadOrCreateKeyPair(path string) (*KeyPair, error) {
	if b, err := os.ReadFile(path); err == nil {
		var f keyPairFile
		if err := json.Unmarshal(b, &f); err == nil {
			pub, err1 := hex.DecodeString(f.PublicKey)
			priv, err2 := hex.DecodeString(f.PrivateKey)
			if err1 == nil && err2 == nil {
				return &KeyPair{
					PublicKey:  ed25519.PublicKey(pub),
					PrivateKey: ed25519.PrivateKey(priv),
				}, nil
			}
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f := keyPairFile{
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: hex.EncodeToString(priv),
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := os.WriteFile(path, b, 0600); err != nil {
		return nil, err
	}
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}
