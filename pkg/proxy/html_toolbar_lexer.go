package proxy

import "bytes"

// htmlToolbarLexer tracks the HTML contexts in which a toolbar may be inserted.
// It keeps only bounded foreign tag names, so arbitrary nesting, comments,
// scripts or attributes cannot grow its memory. scan's caller retains a small
// lookahead across input chunks.
type htmlToolbarLexer struct {
	inTag               bool
	quote               byte
	attributeValue      uint8 // 1: before value; 2: unquoted value
	comment             bool
	cdata               bool
	declaration         bool
	raw                 string
	rawAfterTag         string
	scriptEscaped       bool
	scriptDoubleEscaped bool
	templateDepth       int
	templateDelta       int
	foreign             *htmlToolbarForeignState
	injectionDisabled   bool
	selectDepth         uint8
	selectDelta         int8
	sawFrameset         bool
	tagSlash            bool
	sawHTML             bool
}

// Allocated only for a response containing SVG or MathML; ordinary HTML does
// not pay for the fixed-depth matching stack.
type htmlToolbarForeignState struct {
	depth               int
	tags                [32]htmlToolbarForeignTag
	tag                 htmlToolbarForeignTag
	pending             bool
	closing             bool
	nameDone            bool
	textOnlyIntegration bool
}

type htmlToolbarForeignTag struct {
	name [32]byte
	len  uint8
}

type htmlToolbarInput struct{ prefix, chunk []byte }

func (s htmlToolbarInput) nextByte(i, limit int, target byte) int {
	if i < len(s.prefix) {
		end := min(limit, len(s.prefix))
		if n := bytes.IndexByte(s.prefix[i:end], target); n >= 0 {
			return i + n
		}
		i = end
	}
	if i < limit {
		if n := bytes.IndexByte(s.chunk[i-len(s.prefix):limit-len(s.prefix)], target); n >= 0 {
			return i + n
		}
	}
	return limit
}

func (s htmlToolbarInput) at(i int) byte {
	if i < len(s.prefix) {
		return s.prefix[i]
	}
	return s.chunk[i-len(s.prefix)]
}

func (s htmlToolbarInput) has(i int, text string) bool {
	if i+len(text) > len(s.prefix)+len(s.chunk) {
		return false
	}
	for j := range text {
		if lowerASCII(s.at(i+j)) != text[j] {
			return false
		}
	}
	return true
}

func (s htmlToolbarInput) hasExact(i int, text string) bool {
	if i+len(text) > len(s.prefix)+len(s.chunk) {
		return false
	}
	for j := range text {
		if s.at(i+j) != text[j] {
			return false
		}
	}
	return true
}

func (s htmlToolbarInput) tag(i int, name string, closing bool) bool {
	i++ // '<'
	if closing {
		if i >= len(s.prefix)+len(s.chunk) || s.at(i) != '/' {
			return false
		}
		i++
	}
	if !s.has(i, name) {
		return false
	}
	i += len(name)
	return i < len(s.prefix)+len(s.chunk) && htmlTagDelimiter(s.at(i))
}

func htmlTagDelimiter(c byte) bool {
	return c == '>' || c == '/' || htmlSpace(c)
}

func htmlSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f'
}

func (l *htmlToolbarLexer) canAppend() bool {
	return !l.injectionDisabled && l.sawHTML && !l.inTag && !l.comment && !l.cdata && l.raw == "" && l.templateDepth == 0 && !l.inForeignContent()
}

// scan returns the first closing body tag outside raw text, comments, quoted
// attributes and templates. Bytes beyond limit are lookahead, not consumed.
func (l *htmlToolbarLexer) scan(prefix, chunk []byte, limit int) int {
	s := htmlToolbarInput{prefix: prefix, chunk: chunk}
	for i := 0; i < limit; i++ {
		if l.injectionDisabled {
			return -1
		}
		c := s.at(i)
		if l.cdata {
			if c == ']' && s.has(i, "]]>") {
				l.cdata = false
			} else if c != ']' {
				i = s.nextByte(i+1, limit, ']') - 1
			}
			continue
		}
		if l.comment {
			if c == '-' && (s.has(i, "-->") || s.has(i, "--!>")) {
				l.comment = false
			} else if c != '-' {
				i = s.nextByte(i+1, limit, '-') - 1
			}
			continue
		}
		if l.inTag {
			if l.foreign != nil && l.foreign.pending && !l.foreign.nameDone {
				if c == '/' && l.foreign.tag.len == 0 && l.foreign.closing {
					continue
				}
				if htmlTagDelimiter(c) {
					l.foreign.nameDone = true
				} else if int(l.foreign.tag.len) < len(l.foreign.tag.name) {
					l.foreign.tag.name[l.foreign.tag.len] = lowerASCII(c)
					l.foreign.tag.len++
				} else {
					l.injectionDisabled = true
					return -1
				}
			}
			if l.quote != 0 {
				if c == l.quote {
					l.quote = 0
				}
			} else if c == '>' {
				l.inTag = false
				l.declaration = false
				l.attributeValue = 0
				l.finishForeignTag()
				l.raw = l.rawAfterTag
				l.rawAfterTag = ""
				l.templateDepth = max(0, l.templateDepth+l.templateDelta)
				l.templateDelta = 0
				if l.selectDelta > 0 {
					if l.selectDepth == 255 {
						l.injectionDisabled = true
					} else {
						l.selectDepth++
					}
				} else if l.selectDelta < 0 && l.selectDepth > 0 {
					l.selectDepth--
				}
				l.selectDelta, l.tagSlash = 0, false
			} else if l.declaration && (c == '\'' || c == '"') {
				l.quote = c
			} else {
				l.tagSlash = c == '/' && l.attributeValue != 2
				switch l.attributeValue {
				case 1:
					if !htmlSpace(c) {
						if c == '\'' || c == '"' {
							l.quote = c
							l.attributeValue = 0
						} else {
							l.attributeValue = 2
						}
					}
				case 2:
					if htmlSpace(c) {
						l.attributeValue = 0
					}
				default:
					if c == '=' {
						l.attributeValue = 1
					}
				}
			}
			continue
		}
		if l.raw != "" {
			if l.raw == "plaintext" {
				return -1
			}
			if c != '<' && (l.raw != "script" || c != '-') {
				next := s.nextByte(i+1, limit, '<')
				if l.raw == "script" {
					next = min(next, s.nextByte(i+1, next, '-'))
				}
				i = next - 1
				continue
			}
			// SVG/MathML may carry script text in a CDATA section. End-tag
			// literals inside it must not close the script or HTML body.
			if c == '<' && l.inForeignContent() && s.has(i, "<![cdata[") {
				if !s.hasExact(i, "<![CDATA[") {
					l.injectionDisabled = true
					return -1
				}
				l.cdata = true
				continue
			}
			if l.raw == "script" {
				if c == '<' && s.has(i, "<!--") {
					l.scriptEscaped = true
				} else if c == '-' && s.has(i, "-->") {
					l.scriptEscaped = false
					l.scriptDoubleEscaped = false
				} else if c == '<' && l.scriptEscaped && s.tag(i, "script", false) {
					l.scriptDoubleEscaped = true
				}
			}
			if c == '<' && s.tag(i, l.raw, true) {
				if l.scriptDoubleEscaped {
					l.scriptDoubleEscaped = false
					continue
				}
				l.raw = ""
				l.scriptEscaped = false
				l.inTag = true
				if l.inForeignContent() {
					l.beginForeignTag(true)
				}
			}
			continue
		}
		if c != '<' {
			i = s.nextByte(i+1, limit, '<') - 1
			continue
		}
		if i+1 < len(prefix)+len(chunk) {
			next := lowerASCII(s.at(i + 1))
			l.inTag = next >= 'a' && next <= 'z' || next == '/' || next == '!' || next == '?'
			if l.foreign != nil && l.foreign.textOnlyIntegration && l.inTag && next != '/' && !s.hasExact(i, "<![CDATA[") {
				// Plain text and CDATA do not change the namespace. Any child
				// element or declaration at an integration point is ambiguous.
				l.injectionDisabled = true
				return -1
			}
			if l.inForeignContent() && (next >= 'a' && next <= 'z' || next == '/') {
				l.beginForeignTag(next == '/')
			}
			switch next {
			case '!':
				if s.has(i, "<!--") {
					l.comment = true
					l.inTag = false
				} else if s.has(i, "<![cdata[") {
					if !l.inForeignContent() || !s.hasExact(i, "<![CDATA[") {
						// In HTML this begins a bogus comment, not CDATA. Do
						// not let a later script's literal ']]>' resume scanning.
						l.injectionDisabled = true
						return -1
					}
					l.cdata = true
					l.inTag = false
				} else if s.has(i, "<!doctype") {
					l.sawHTML = true
					l.declaration = true
				} else {
					// Unknown declarations are HTML bogus comments, whose
					// first '>' ends them even inside quotes.
					l.injectionDisabled = true
					return -1
				}
			case '?':
				l.injectionDisabled = true
				return -1
			case '/':
				if i+2 >= len(prefix)+len(chunk) || lowerASCII(s.at(i+2)) < 'a' || lowerASCII(s.at(i+2)) > 'z' {
					// Invalid end-tag openings use bogus-comment parsing too.
					l.injectionDisabled = true
					return -1
				}
				if s.tag(i, "body", true) && l.templateDepth == 0 && !l.inForeignContent() {
					return i
				}
				if s.tag(i, "template", true) {
					l.templateDelta = -1
				}
				if s.tag(i, "select", true) {
					l.selectDelta = -1
				}
			case 'h':
				l.sawHTML = l.sawHTML || s.tag(i, "html", false) || s.tag(i, "head", false)
			case 'b':
				l.sawHTML = l.sawHTML || s.tag(i, "body", false)
			case 't':
				if s.tag(i, "template", false) {
					l.templateDelta = 1
				} else {
					l.setRawTag(s, i, "textarea", "title")
				}
			case 's':
				if s.tag(i, "svg", false) {
					l.beginForeignTag(false)
				} else if s.tag(i, "select", false) {
					l.selectDelta = 1
				} else {
					l.setRawTag(s, i, "script", "style")
				}
			case 'm':
				if s.tag(i, "math", false) {
					l.beginForeignTag(false)
				}
			case 'f':
				l.sawFrameset = l.sawFrameset || s.tag(i, "frameset", false)
			case 'x':
				l.setRawTag(s, i, "xmp")
			case 'i':
				l.setRawTag(s, i, "iframe")
			case 'n':
				l.setRawTag(s, i, "noembed", "noframes", "noscript")
			case 'p':
				l.setRawTag(s, i, "plaintext")
			}
		}
	}
	return -1
}

func (l *htmlToolbarLexer) inForeignContent() bool {
	return l.foreign != nil && l.foreign.depth > 0
}

func (l *htmlToolbarLexer) beginForeignTag(closing bool) {
	if l.foreign == nil {
		l.foreign = &htmlToolbarForeignState{}
	}
	l.foreign.tag = htmlToolbarForeignTag{}
	l.foreign.pending = true
	l.foreign.closing = closing
	l.foreign.nameDone = false
}

func (l *htmlToolbarLexer) finishForeignTag() {
	if l.foreign == nil || !l.foreign.pending {
		return
	}
	l.foreign.pending = false
	name := string(l.foreign.tag.name[:l.foreign.tag.len])
	if l.foreign.closing {
		if l.foreign.textOnlyIntegration {
			if l.foreign.depth == 0 || l.foreign.tags[l.foreign.depth-1] != l.foreign.tag {
				l.injectionDisabled = true
				return
			}
			l.foreign.textOnlyIntegration = false
		}
		for i := l.foreign.depth - 1; i >= 0; i-- {
			if l.foreign.tags[i] == l.foreign.tag {
				l.foreign.depth = i
				return
			}
		}
		// An unmatched SVG/Math end tag cannot close the other namespace's
		// root. Other unmatched ends may instead close an HTML ancestor.
		if name != "svg" && name != "math" {
			l.injectionDisabled = true
		}
		return
	}
	if !l.inForeignContent() && (l.selectDepth > 0 || l.sawFrameset) {
		// These HTML insertion modes can ignore a foreign start tag. Do not
		// mistake a later HTML <script/> for a self-closing foreign script.
		l.injectionDisabled = true
		return
	}
	// Integration points may contain plain text/CDATA and their own end tag;
	// children require a tree builder. HTML breakout tokens also make the
	// namespace uncertain, so stop instead of risking insertion into a script.
	switch name {
	case "desc", "title":
		if !l.tagSlash {
			l.foreign.textOnlyIntegration = true
			l.rawAfterTag = ""
		}
	case "foreignobject", "mi", "mo", "mn", "ms", "mtext", "annotation-xml":
		if !l.tagSlash {
			l.injectionDisabled = true
		}
	case "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div", "dl", "dt", "em", "embed",
		"font", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li", "listing", "menu", "meta",
		"nobr", "ol", "p", "pre", "ruby", "s", "small", "span", "strong", "strike", "sub", "sup", "table", "tt", "u", "ul", "var":
		// A breakout is still processed as HTML when it carries '/>'.
		l.injectionDisabled = true
	}
	if l.tagSlash && l.rawAfterTag != "" {
		l.rawAfterTag = ""
	}
	if l.tagSlash {
		return
	}
	if l.foreign.depth == len(l.foreign.tags) {
		l.injectionDisabled = true
		return
	}
	l.foreign.tags[l.foreign.depth] = l.foreign.tag
	l.foreign.depth++
}

func (l *htmlToolbarLexer) setRawTag(s htmlToolbarInput, i int, names ...string) {
	for _, name := range names {
		if s.tag(i, name, false) {
			l.rawAfterTag = name
			return
		}
	}
}

func htmlToolbarInsertionOffset(body []byte) int {
	var lexer htmlToolbarLexer
	if i := lexer.scan(nil, body, len(body)); i >= 0 {
		return i
	}
	if lexer.canAppend() {
		return len(body)
	}
	return -1
}
