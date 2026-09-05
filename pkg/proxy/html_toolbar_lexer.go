package proxy

import "bytes"

// htmlToolbarLexer tracks the HTML contexts in which a toolbar may be inserted.
// It keeps no token text, so a huge comment, script or quoted attribute cannot
// grow its memory. scan's caller retains a small lookahead across input chunks.
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
	foreignDepth        int
	foreignDelta        int
	tagSlash            bool
	sawHTML             bool
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
	return l.sawHTML && !l.inTag && !l.comment && !l.cdata && l.raw == "" && l.templateDepth == 0 && l.foreignDepth == 0
}

// scan returns the first closing body tag outside raw text, comments, quoted
// attributes and templates. Bytes beyond limit are lookahead, not consumed.
func (l *htmlToolbarLexer) scan(prefix, chunk []byte, limit int) int {
	s := htmlToolbarInput{prefix: prefix, chunk: chunk}
	for i := 0; i < limit; i++ {
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
			if l.quote != 0 {
				if c == l.quote {
					l.quote = 0
				}
			} else if c == '>' {
				l.inTag = false
				l.declaration = false
				l.attributeValue = 0
				l.raw = l.rawAfterTag
				l.rawAfterTag = ""
				l.templateDepth = max(0, l.templateDepth+l.templateDelta)
				l.templateDelta = 0
				if l.foreignDelta <= 0 || !l.tagSlash {
					l.foreignDepth = max(0, l.foreignDepth+l.foreignDelta)
				}
				l.foreignDelta, l.tagSlash = 0, false
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
			if c == '<' && l.foreignDepth > 0 && s.has(i, "<![cdata[") {
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
			switch next {
			case '!':
				if s.has(i, "<!--") {
					l.comment = true
					l.inTag = false
				} else if s.has(i, "<![cdata[") {
					l.cdata = true
					l.inTag = false
				} else if s.has(i, "<!doctype") {
					l.sawHTML = true
					l.declaration = true
				}
			case '/':
				if s.tag(i, "body", true) && l.templateDepth == 0 && l.foreignDepth == 0 {
					return i
				}
				if s.tag(i, "template", true) {
					l.templateDelta = -1
				}
				if s.tag(i, "svg", true) || s.tag(i, "math", true) {
					l.foreignDelta = -1
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
					l.foreignDelta = 1
				} else {
					l.setRawTag(s, i, "script", "style")
				}
			case 'm':
				if s.tag(i, "math", false) {
					l.foreignDelta = 1
				}
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
