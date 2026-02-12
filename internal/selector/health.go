package selector

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type HealthStore struct {
	path string
	mu   sync.Mutex
	data map[string]NodeHealth
}

type NodeHealth struct {
	FailCount int   `json:"fail_count"`
	LastRTTMs int64 `json:"last_rtt_ms"`
	UpdatedAt int64 `json:"updated_at"`
}

func LoadHealth(path string) *HealthStore {
	s := &HealthStore{
		path: path,
		data: map[string]NodeHealth{},
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	return s
}

func (s *HealthStore) Update(nodeID string, rtt time.Duration, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.data[nodeID]
	if ok {
		stats.FailCount = 0
		stats.LastRTTMs = rtt.Milliseconds()
	} else {
		stats.FailCount++
	}
	stats.UpdatedAt = time.Now().Unix()
	s.data[nodeID] = stats
	s.persist()
}

func (s *HealthStore) IsHealthy(nodeID string, maxFails int, maxAge time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats, ok := s.data[nodeID]
	if !ok {
		return true
	}
	if maxAge > 0 && time.Since(time.Unix(stats.UpdatedAt, 0)) > maxAge {
		return true
	}
	return stats.FailCount < maxFails
}

func (s *HealthStore) persist() {
	b, _ := json.MarshalIndent(s.data, "", "  ")
	_ = os.WriteFile(s.path, b, 0600)
}
