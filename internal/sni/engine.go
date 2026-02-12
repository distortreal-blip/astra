package sni

import (
	"context"
	"time"
)

type Profile struct {
	ID            string
	ServerName    string
	ALPN          string
	FingerprintID string
	PacketSize    int
	TimingHint    time.Duration
}

type ProbeFunc func(ctx context.Context, addr string) (time.Duration, error)

type ScoreProvider interface {
	Score(profileID string) float64
	Update(profileID string, rtt time.Duration, success bool)
}

type Engine struct {
	Profiles []Profile
	Probe    ProbeFunc
	Scores   ScoreProvider
}

func (e *Engine) BestProfile(ctx context.Context, addr string) (Profile, time.Duration) {
	var best Profile
	var bestScore float64 = -1
	var bestRTT time.Duration

	for _, p := range e.Profiles {
		rtt, err := e.Probe(ctx, addr)
		success := err == nil
		if e.Scores != nil {
			e.Scores.Update(p.ID, rtt, success)
		}
		score := 0.0
		if e.Scores != nil {
			score = e.Scores.Score(p.ID)
		}
		if success && score >= bestScore {
			bestScore = score
			best = p
			bestRTT = rtt
		}
	}
	return best, bestRTT
}
