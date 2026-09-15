package aho_corasick

// Search delegates to the same automaton algorithms as the builder NFA.
func (n *packedNFA) FindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return findAtNoState(n, prefilterState, bytes, i)
}

func (n *packedNFA) Repr() *iRepr {
	return nil
}

func (n *packedNFA) MatchKind() *matchKind {
	return &n.matchKind
}

func (n *packedNFA) Anchored() bool {
	return n.anchored
}

func (n *packedNFA) Prefilter() prefilter {
	return n.prefil
}

func (n *packedNFA) StartState() stateID {
	return n.startID
}

func (n *packedNFA) IsValid(id stateID) bool {
	return int(id) < len(n.states)
}

func (n *packedNFA) IsMatchState(id stateID) bool {
	return n.states[id].matchCount != 0
}

func (n *packedNFA) IsMatchOrDeadState(id stateID) bool {
	return id == deadStateID || n.states[id].matchCount != 0
}

func (n *packedNFA) MatchCount(id stateID) int {
	return int(n.states[id].matchCount)
}

func (n *packedNFA) NextState(id stateID, b byte) stateID {
	for {
		state := &n.states[id]
		next := n.nextState(state, b)
		if next != failedStateID {
			return next
		}
		id = stateID(state.fail)
	}
}

func (n *packedNFA) NextStateNoFail(id stateID, b byte) stateID {
	next := n.NextState(id, b)
	if next == failedStateID {
		panic("automaton should never return fail_id for next state")
	}
	return next
}

func (n *packedNFA) StandardFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return standardFindAt(n, prefilterState, bytes, i, id)
}

func (n *packedNFA) StandardFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return standardFindAtImp(n, prefilterState, prefilter, bytes, i, id)
}

func (n *packedNFA) LeftmostFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAt(n, prefilterState, bytes, i, id)
}

func (n *packedNFA) LeftmostFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAtImp(n, prefilterState, prefilter, bytes, i, id)
}

func (n *packedNFA) LeftmostFindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return leftmostFindAtNoState(n, prefilterState, bytes, i)
}

func (n *packedNFA) LeftmostFindAtNoStateImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int) *Match {
	return leftmostFindAtNoStateImp(n, prefilterState, prefilter, bytes, i)
}

func (n *packedNFA) OverlappingFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID, i2 *int) *Match {
	return overlappingFindAt(n, prefilterState, bytes, i, id, i2)
}

func (n *packedNFA) EarliestFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return earliestFindAt(n, prefilterState, bytes, i, id)
}

func (n *packedNFA) FindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return findAt(n, prefilterState, bytes, i, id)
}

func (n *packedNFA) MaxPatternLen() int {
	return n.maxPatternLen
}

func (n *packedNFA) PatternCount() int {
	return n.patternCount
}

func (n *packedNFA) UsePrefilter() bool {
	p := n.Prefilter()
	if p == nil {
		return false
	}
	return !p.LooksForNonStartOfMatch()
}

func (n *packedNFA) GetMatch(id stateID, matchIndex int, end int) *Match {
	if int(id) >= len(n.states) {
		return nil
	}
	state := n.states[id]
	if matchIndex >= int(state.matchCount) {
		return nil
	}
	pat := n.matches[int(state.matchStart)+matchIndex]
	return &Match{
		pattern: pat.PatternID,
		len:     pat.PatternLength,
		end:     end,
	}
}
