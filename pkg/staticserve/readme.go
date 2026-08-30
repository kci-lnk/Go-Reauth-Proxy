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
	goldmarkast "github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	goldmarktext "github.com/yuin/goldmark/text"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type readmeRenderer struct {
	markdown  goldmark.Markdown
	sanitizer *bluemonday.Policy
}

type markdownAlertDefinition struct {
	className string
	title     string
}

var markdownAlertDefinitions = map[string]markdownAlertDefinition{
	"[!NOTE]":      {className: "markdown-alert-note", title: "Note"},
	"[!TIP]":       {className: "markdown-alert-tip", title: "Tip"},
	"[!IMPORTANT]": {className: "markdown-alert-important", title: "Important"},
	"[!WARNING]":   {className: "markdown-alert-warning", title: "Warning"},
	"[!CAUTION]":   {className: "markdown-alert-caution", title: "Caution"},
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

	document := renderer.markdown.Parser().Parse(goldmarktext.NewReader(content))
	alerts := collectMarkdownAlerts(document, content)
	var rendered bytes.Buffer
	if err := renderer.markdown.Renderer().Render(&rendered, content, document); err != nil {
		return ""
	}
	// Goldmark's unsafe renderer is deliberately not enabled. The sanitizer is
	// retained as defense in depth for generated links and future extensions.
	safe := renderer.sanitizer.SanitizeBytes(rendered.Bytes())
	safe, err = rewriteSanitizedReadme(safe, alerts)
	if err != nil {
		return ""
	}
	return template.HTML(safe) // #nosec G203 -- safe is sanitized and structurally filtered.
}

func collectMarkdownAlerts(document goldmarkast.Node, source []byte) []markdownAlertDefinition {
	definitions := make([]markdownAlertDefinition, 0)
	_ = goldmarkast.Walk(document, func(node goldmarkast.Node, entering bool) (goldmarkast.WalkStatus, error) {
		if !entering || node.Kind() != goldmarkast.KindBlockquote {
			return goldmarkast.WalkContinue, nil
		}
		definition := markdownAlertDefinition{}
		if node.Parent() == nil || node.Parent().Kind() != goldmarkast.KindDocument {
			definitions = append(definitions, definition)
			return goldmarkast.WalkContinue, nil
		}
		paragraph := node.FirstChild()
		if paragraph == nil || paragraph.Kind() != goldmarkast.KindParagraph {
			definitions = append(definitions, definition)
			return goldmarkast.WalkContinue, nil
		}
		var firstLine strings.Builder
		lineComplete := false
		for child := paragraph.FirstChild(); child != nil; child = child.NextSibling() {
			textNode, ok := child.(*goldmarkast.Text)
			if !ok {
				break
			}
			firstLine.Write(textNode.Segment.Value(source))
			if textNode.SoftLineBreak() || textNode.HardLineBreak() || textNode.NextSibling() == nil {
				lineComplete = true
				break
			}
		}
		candidate, exists := markdownAlertDefinitions[firstLine.String()]
		if exists && lineComplete {
			definition = candidate
		}
		definitions = append(definitions, definition)
		return goldmarkast.WalkContinue, nil
	})
	return definitions
}

func rewriteSanitizedReadme(content []byte, alerts []markdownAlertDefinition) ([]byte, error) {
	contextNode := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := html.ParseFragment(bytes.NewReader(content), contextNode)
	if err != nil {
		return nil, err
	}
	filtered := nodes[:0]
	alertIndex := 0
	for _, node := range nodes {
		if rewriteReadmeNode(node, alerts, &alertIndex) {
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

func rewriteReadmeNode(node *html.Node, alerts []markdownAlertDefinition, alertIndex *int) bool {
	if node == nil {
		return false
	}
	alert := markdownAlertDefinition{}
	if node.Type == html.ElementNode && node.DataAtom == atom.Blockquote {
		if *alertIndex < len(alerts) {
			alert = alerts[*alertIndex]
		}
		*alertIndex++
	}
	for child := node.FirstChild; child != nil; {
		next := child.NextSibling
		if !rewriteReadmeNode(child, alerts, alertIndex) {
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
	case atom.Blockquote:
		if alert.title != "" {
			rewriteMarkdownAlert(node, alert)
		}
	}
	return true
}

func rewriteMarkdownAlert(blockquote *html.Node, definition markdownAlertDefinition) {
	paragraph := firstHTMLElementChild(blockquote)
	if paragraph == nil || paragraph.DataAtom != atom.P {
		return
	}
	markerText := firstDirectTextNode(paragraph)
	if markerText == nil {
		return
	}
	firstLine := markerText.Data
	remainder := ""
	if lineEnd := strings.IndexByte(firstLine, '\n'); lineEnd >= 0 {
		remainder = firstLine[lineEnd+1:]
		firstLine = strings.TrimSuffix(firstLine[:lineEnd], "\r")
	}
	candidate, ok := markdownAlertDefinitions[firstLine]
	if !ok || candidate != definition {
		return
	}
	markerText.Data = remainder
	if markerText.Data == "" {
		paragraph.RemoveChild(markerText)
	}
	if !hasMeaningfulHTMLContent(paragraph) {
		blockquote.RemoveChild(paragraph)
	}
	appendHTMLClasses(blockquote, "markdown-alert", definition.className)
	title := &html.Node{Type: html.ElementNode, Data: "p", DataAtom: atom.P, Attr: []html.Attribute{{Key: "class", Val: "markdown-alert-title"}}}
	title.AppendChild(&html.Node{Type: html.TextNode, Data: definition.title})
	blockquote.InsertBefore(title, blockquote.FirstChild)
}

func firstHTMLElementChild(node *html.Node) *html.Node {
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.ElementNode {
			return child
		}
		if child.Type == html.TextNode && strings.TrimSpace(child.Data) != "" {
			return nil
		}
	}
	return nil
}

func firstDirectTextNode(node *html.Node) *html.Node {
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			if strings.TrimSpace(child.Data) != "" {
				return child
			}
			continue
		}
		return nil
	}
	return nil
}

func hasMeaningfulHTMLContent(node *html.Node) bool {
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			if strings.TrimSpace(child.Data) != "" {
				return true
			}
			continue
		}
		if child.Type == html.ElementNode && child.DataAtom != atom.Br {
			return true
		}
	}
	return false
}

func appendHTMLClasses(node *html.Node, classes ...string) {
	existing := strings.Fields(htmlAttribute(node, "class"))
	seen := make(map[string]struct{}, len(existing)+len(classes))
	combined := make([]string, 0, len(existing)+len(classes))
	for _, className := range append(existing, classes...) {
		if _, ok := seen[className]; ok {
			continue
		}
		seen[className] = struct{}{}
		combined = append(combined, className)
	}
	removeHTMLAttribute(node, "class")
	node.Attr = append(node.Attr, html.Attribute{Key: "class", Val: strings.Join(combined, " ")})
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
