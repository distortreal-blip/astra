package selector

import (
	"context"
	"time"
)

type NodeRole string

const (
	RoleEntry NodeRole = "entry"
	RoleRelay NodeRole = "relay"
	RoleExit  NodeRole = "exit"
)

type Node struct {
	ID   string
	Addr string
	Role NodeRole
}

type ProbeFunc func(ctx context.Context, addr string) (time.Duration, error)

type Selector struct {
	Probe ProbeFunc
}

type Chain struct {
	Entry Node
	Relay Node
	Exit  Node
}

func (s *Selector) Select(nodes []Node) Chain {
	var entry Node
	var relay Node
	var exit Node
	entry = pickBest(nodes, RoleEntry, s.Probe)
	relay = pickBest(nodes, RoleRelay, s.Probe)
	exit = pickBest(nodes, RoleExit, s.Probe)
	return Chain{Entry: entry, Relay: relay, Exit: exit}
}

func pickBest(nodes []Node, role NodeRole, probe ProbeFunc) Node {
	var best Node
	var bestRTT time.Duration
	for _, n := range nodes {
		if n.Role != role {
			continue
		}
		if probe == nil {
			return n
		}
		rtt, err := probe(context.Background(), n.Addr)
		if err != nil {
			continue
		}
		if best.Addr == "" || rtt < bestRTT {
			best = n
			bestRTT = rtt
		}
	}
	return best
}
