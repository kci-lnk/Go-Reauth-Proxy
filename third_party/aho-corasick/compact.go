package aho_corasick

import "math"

// packedNFA is the immutable search representation. Construction still uses the
// upstream NFA; freezing copies its exact transitions, failure links and ordered
// matches into pointer-free arrays. Sparse headers, slice capacity and per-state
// allocation overhead disappear. The search algorithms in automaton.go are shared.
type packedNFA struct {
	matchKind                   matchKind
	startID                     stateID
	maxPatternLen, patternCount int
	prefil                      prefilter
	anchored                    bool
	states                      []packedState
	edges                       []packedTransition
	dense                       []uint32
	matches                     []pattern
}

type packedState struct {
	fail, edgeStart, edgeCount, matchStart, matchCount uint32
}

type packedTransition struct {
	next  uint32
	input byte
}

const packedDense = uint32(1 << 31)

func (n *iNFA) compact() imp {
	var edgeCount, denseCount, matchCount uint64
	for _, s := range n.states {
		if s.trans.sparse != nil {
			edgeCount += uint64(len(s.trans.sparse.inner))
		} else {
			denseCount += uint64(len(s.trans.dense.inner))
		}
		matchCount += uint64(len(s.matches))
	}
	// Oversized inputs retain the upstream representation, never truncated indexes.
	if uint64(len(n.states)) > math.MaxUint32 || edgeCount > math.MaxUint32 || denseCount > math.MaxUint32 || matchCount > math.MaxUint32 {
		return n
	}
	p := &packedNFA{matchKind: n.matchKind, startID: n.startID, maxPatternLen: n.maxPatternLen, patternCount: n.patternCount, prefil: n.prefil, anchored: n.anchored,
		states: make([]packedState, len(n.states)), edges: make([]packedTransition, int(edgeCount)), dense: make([]uint32, int(denseCount)), matches: make([]pattern, int(matchCount))}
	var ei, di, mi uint32
	for i, s := range n.states {
		state := packedState{fail: uint32(s.fail), matchStart: mi, matchCount: uint32(len(s.matches))}
		copy(p.matches[mi:], s.matches)
		mi += uint32(len(s.matches))
		if s.trans.sparse != nil {
			state.edgeStart = ei
			state.edgeCount = uint32(len(s.trans.sparse.inner))
			for _, e := range s.trans.sparse.inner {
				p.edges[ei] = packedTransition{uint32(e.s), e.b}
				ei++
			}
		} else {
			state.edgeStart = di
			state.edgeCount = packedDense
			for _, next := range s.trans.dense.inner {
				p.dense[di] = uint32(next)
				di++
			}
		}
		p.states[i] = state
	}
	return p
}

func (p *packedNFA) nextState(s *packedState, input byte) stateID {
	if s.edgeCount == packedDense {
		return stateID(p.dense[int(s.edgeStart)+int(input)])
	}
	for _, e := range p.edges[int(s.edgeStart) : int(s.edgeStart)+int(s.edgeCount)] {
		if e.input == input {
			return stateID(e.next)
		}
	}
	return failedStateID
}
