package staticserve

import (
	"bytes"
	"html/template"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type readmeRenderer struct {
	markdown  goldmark.Markdown
	sanitizer *bluemonday.Policy
}

func newReadmeRenderer() *readmeRenderer {
	policy := bluemonday.UGCPolicy()
	policy.RequireNoFollowOnLinks(true)
	policy.RequireNoReferrerOnLinks(true)
	policy.AddTargetBlankToFullyQualifiedLinks(true)
	return &readmeRenderer{
		markdown: goldmark.New(
			goldmark.WithExtensions(extension.GFM),
		),
		sanitizer: policy,
	}
}

func (renderer *readmeRenderer) render(root rootedFileOpener, name string) template.HTML {
	if renderer == nil || root == nil {
		return ""
	}
	file, err := openRootFileForRead(root, name)
	if err != nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxReadmeBytes {
		return ""
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxReadmeBytes+1))
	if err != nil || len(content) > MaxReadmeBytes || !utf8.Valid(content) {
		return ""
	}

	var rendered bytes.Buffer
	if err := renderer.markdown.Convert(content, &rendered); err != nil {
		return ""
	}
	// Goldmark's unsafe renderer is deliberately not enabled. The sanitizer is
	// retained as defense in depth for generated links and future extensions.
	safe := renderer.sanitizer.SanitizeBytes(rendered.Bytes())
	safe, err = rewriteSanitizedReadme(safe)
	if err != nil {
		return ""
	}
	return template.HTML(safe) // #nosec G203 -- safe is sanitized and structurally filtered.
}

func rewriteSanitizedReadme(content []byte) ([]byte, error) {
	contextNode := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := html.ParseFragment(bytes.NewReader(content), contextNode)
	if err != nil {
		return nil, err
	}
	filtered := nodes[:0]
	for _, node := range nodes {
		if rewriteReadmeNode(node) {
			filtered = append(filtered, node)
		}
	}
	nodes = filtered
	var output bytes.Buffer
	for _, node := range nodes {
		if err := html.Render(&output, node); err != nil {
			return nil, err
		}
	}
	return output.Bytes(), nil
}

func rewriteReadmeNode(node *html.Node) bool {
	if node == nil {
		return false
	}
	for child := node.FirstChild; child != nil; {
		next := child.NextSibling
		if !rewriteReadmeNode(child) {
			node.RemoveChild(child)
		}
		child = next
	}
	if node.Type != html.ElementNode {
		return true
	}
	switch node.DataAtom {
	case atom.Img:
		source := htmlAttribute(node, "src")
		if !sameOriginImageSource(source) {
			return false
		}
		removeHTMLAttribute(node, "srcset")
	case atom.A:
		ensureLinkRel(node, "noopener", "noreferrer")
	}
	return true
}

func sameOriginImageSource(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "//") || strings.Contains(value, "\\") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || !utf8.ValidString(parsed.Path) {
		return false
	}
	// Goldmark percent-encodes backslashes and control characters while
	// rendering Markdown destinations. Validate the parsed (decoded) path too;
	// checking only the serialized attribute would allow inputs such as
	// `\\host\image.png` to survive as `%5chost%5cimage.png`.
	for _, character := range parsed.Path {
		if character == '\\' || unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	// README images are passive content, so do not let them issue same-origin
	// GETs against gateway-owned endpoints (for example the GET logout route).
	// url.Parse has already decoded each percent escape into Path, which also
	// catches encoded spellings such as /%5f%5fauth__/.
	for _, component := range strings.Split(parsed.Path, "/") {
		if strings.HasPrefix(component, "__") {
			return false
		}
	}
	// Encoded path separators create decoding disagreements between URL routers
	// and file handlers (CVE-2026-55677 class). Literal '/' is allowed for
	// same-origin subpaths; an explicitly percent-encoded separator is not.
	if rawPath := parsed.RawPath; rawPath != "" && hasEncodedPathSeparatorOrControl(rawPath) {
		return false
	}
	return true
}

func hasEncodedPathSeparatorOrControl(value string) bool {
	for index := 0; index+2 < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		high, highOK := fromHex(value[index+1])
		low, lowOK := fromHex(value[index+2])
		if !highOK || !lowOK {
			continue
		}
		decoded := high<<4 | low
		if decoded == '/' || decoded == '\\' || decoded < 0x20 || decoded == 0x7f {
			return true
		}
		index += 2
	}
	return false
}

func fromHex(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func htmlAttribute(node *html.Node, name string) string {
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, name) {
			return attribute.Val
		}
	}
	return ""
}

func removeHTMLAttribute(node *html.Node, name string) {
	filtered := node.Attr[:0]
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, name) {
			continue
		}
		filtered = append(filtered, attribute)
	}
	node.Attr = filtered
}

func ensureLinkRel(node *html.Node, required ...string) {
	values := append([]string{"nofollow"}, required...)
	removeHTMLAttribute(node, "rel")
	node.Attr = append(node.Attr, html.Attribute{Key: "rel", Val: strings.Join(values, " ")})
}
