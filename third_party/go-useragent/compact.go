package useragent

//go:generate go run generate_compact.go

import (
	"math"
	"unsafe"
)

// compactTrie freezes the builder's pointer tree into four pointer-free arrays.
// Single-child chains without results become radix edge labels. The original
// rune/state/precedence algorithm still consumes those labels one rune at a time
// (including its skip/unmatched-rune behavior). Breadth-first numbering keeps
// each retained node's children contiguous without a lookup map.
type compactTrie struct {
	nodes   []compactNode
	edges   []compactEdge
	results []resultItem
	labels  []rune
}

type compactNode struct {
	edgeStart, edgeCount     uint32
	resultStart, resultCount uint32
}

type compactEdge struct {
	next                   uint32
	r                      rune
	labelStart, labelCount uint32
}

func (trie *RuneTrie) freeze() {
	if trie.compact != nil {
		return
	}
	queue := []*RuneTrie{trie}
	var edges, results, labels uint64
	for i := 0; i < len(queue); i++ {
		node := queue[i]
		edges += uint64(len(node.childrenArr))
		results += uint64(len(node.result))
		// Keep the original representation for inputs beyond compact indexes.
		if edges >= math.MaxUint32 || results > math.MaxUint32 {
			return
		}
		for _, child := range node.childrenArr {
			node := child.node
			for len(node.result) == 0 && len(node.childrenArr) == 1 {
				labels++
				node = node.childrenArr[0].node
			}
			queue = append(queue, node)
		}
	}
	if labels > math.MaxUint32 {
		return
	}
	p := &compactTrie{
		nodes:   make([]compactNode, len(queue)),
		edges:   make([]compactEdge, int(edges)),
		results: make([]resultItem, int(results)),
		labels:  make([]rune, int(labels)),
	}
	var edgeOffset, resultOffset, labelOffset, nextID uint32
	nextID = 1
	for i, node := range queue {
		p.nodes[i] = compactNode{edgeOffset, uint32(len(node.childrenArr)), resultOffset, uint32(len(node.result))}
		for _, child := range node.childrenArr {
			start := labelOffset
			childNode := child.node
			for len(childNode.result) == 0 && len(childNode.childrenArr) == 1 {
				p.labels[labelOffset] = childNode.childrenArr[0].r
				labelOffset++
				childNode = childNode.childrenArr[0].node
			}
			p.edges[edgeOffset] = compactEdge{nextID, child.r, start, labelOffset - start}
			edgeOffset++
			nextID++
		}
		copy(p.results[resultOffset:], node.result)
		resultOffset += uint32(len(node.result))
	}
	trie.childrenArr = nil
	trie.result = nil
	trie.compact = p
}

func (p *compactTrie) resultsFor(id uint32) []resultItem {
	n := p.nodes[id]
	return p.results[int(n.resultStart) : int(n.resultStart)+int(n.resultCount)]
}

func (p *compactTrie) next(id uint32, r rune) (uint32, []rune, bool) {
	n := p.nodes[id]
	for _, edge := range p.edges[int(n.edgeStart) : int(n.edgeStart)+int(n.edgeCount)] {
		if edge.r == r {
			return edge.next, p.labels[int(edge.labelStart) : int(edge.labelStart)+int(edge.labelCount)], true
		}
	}
	return 0, nil, false
}

// Put remains supported on the public Trie. Expand only on an explicit mutation;
// normal Parser use never retains the construction graph.
func (trie *RuneTrie) expand() {
	p := trie.compact
	if p == nil {
		return
	}
	nodes := make([]RuneTrie, len(p.nodes))
	edges := make([]childNode, len(p.edges))
	for i, n := range p.nodes {
		start, end := int(n.edgeStart), int(n.edgeStart)+int(n.edgeCount)
		nodes[i].childrenArr = edges[start:end:end]
		for j := start; j < end; j++ {
			edge := p.edges[j]
			next := &nodes[edge.next]
			labels := p.labels[int(edge.labelStart) : int(edge.labelStart)+int(edge.labelCount)]
			for k := len(labels) - 1; k >= 0; k-- {
				next = &RuneTrie{childrenArr: []childNode{{node: next, r: labels[k]}}}
			}
			edges[j] = childNode{node: next, r: edge.r}
		}
		start, end = int(n.resultStart), int(n.resultStart)+int(n.resultCount)
		nodes[i].result = p.results[start:end:end]
	}
	*trie = nodes[0]
	nodes[0] = RuneTrie{}
}

func (p *compactTrie) memoryStats() MemoryStats {
	stats := MemoryStats{
		NodeSize: int(unsafe.Sizeof(RuneTrie{})) + int(unsafe.Sizeof(*p)) +
			len(p.nodes)*int(unsafe.Sizeof(compactNode{})),
		ChildrenArrSize: len(p.edges)*int(unsafe.Sizeof(compactEdge{})) + len(p.labels)*4,
		ResultSize:      len(p.results) * int(unsafe.Sizeof(resultItem{})),
		ChildrenCount:   len(p.edges),
		ResultCount:     len(p.results),
	}
	stats.TotalSize = stats.NodeSize + stats.ChildrenArrSize + stats.ResultSize
	return stats
}

func (p *compactTrie) nodeMemoryStats(id int) MemoryStats {
	n := p.nodes[id]
	s := MemoryStats{
		NodeSize:        int(unsafe.Sizeof(compactNode{})),
		ChildrenArrSize: int(n.edgeCount) * int(unsafe.Sizeof(compactEdge{})),
		ResultSize:      int(n.resultCount) * int(unsafe.Sizeof(resultItem{})),
		ChildrenCount:   int(n.edgeCount),
		ResultCount:     int(n.resultCount),
	}
	if id == 0 {
		s.NodeSize += int(unsafe.Sizeof(RuneTrie{})) + int(unsafe.Sizeof(*p))
	}
	for _, e := range p.edges[int(n.edgeStart) : int(n.edgeStart)+int(n.edgeCount)] {
		s.ChildrenArrSize += int(e.labelCount) * 4
	}
	s.TotalSize = s.NodeSize + s.ChildrenArrSize + s.ResultSize
	return s
}
