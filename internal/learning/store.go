package learning

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Store struct {
	path string
	mu   sync.Mutex
	data dataModel
}

type dataModel struct {
	Profiles map[string]profileStats `json:"profiles"`
}

type profileStats struct {
	SuccessCount int     `json:"success_count"`
	FailCount    int     `json:"fail_count"`
	LastRTTMs    int64   `json:"last_rtt_ms"`
	Score        float64 `json:"score"`
	UpdatedAt    int64   `json:"updated_at"`
}

func Load(path string) *Store {
	s := &Store{
		path: path,
		data: dataModel{Profiles: map[string]profileStats{}},
	}
	b, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	return s
}

func (s *Store) Score(profileID string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.data.Profiles[profileID]
	return stats.Score
}

func (s *Store) Update(profileID string, rtt time.Duration, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.data.Profiles[profileID]
	if success {
		stats.SuccessCount++
	} else {
		stats.FailCount++
	}
	stats.LastRTTMs = rtt.Milliseconds()
	stats.UpdatedAt = time.Now().Unix()
	stats.Score = computeScore(stats)
	s.data.Profiles[profileID] = stats
	s.persist()
}

func computeScore(stats profileStats) float64 {
	total := stats.SuccessCount + stats.FailCount
	if total == 0 {
		return 0
	}
	successRate := float64(stats.SuccessCount) / float64(total)
	latencyPenalty := 1.0
	if stats.LastRTTMs > 0 {
		latencyPenalty = 1000.0 / float64(stats.LastRTTMs+100)
	}
	return successRate * latencyPenalty
}

func (s *Store) persist() {
	b, _ := json.MarshalIndent(s.data, "", "  ")
	_ = os.WriteFile(s.path, b, 0600)
}
