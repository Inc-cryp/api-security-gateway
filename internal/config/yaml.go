package config

import (
	"fmt"
	"strconv"
	"strings"
)

// This file implements the YAML subset the gateway accepts, plus a small
// decoder from the resulting generic tree into the typed Config.
//
// Supported:
//
//	key: value              scalar
//	key: "quoted value"     scalar, quotes stripped
//	key: 42 / 3.5 / true    scalar, decoded by the target field's type
//	key: [a, b, c]          inline string list
//	key:                    nested mapping (indented further)
//	key:                    sequence of scalars or mappings ("- " items)
//	# comment               full-line or trailing comment
//
// Anything else — tabs for indentation, anchors, flow mappings, block
// scalars — is reported as an error with its line number.

type node struct {
	// Exactly one of these is set.
	scalar string
	seq    []node
	keys   []string
	maps   map[string]node
	line   int
	kind   nodeKind
}

type nodeKind int

const (
	kindScalar nodeKind = iota
	kindMap
	kindSeq
)

func (n node) String() string {
	switch n.kind {
	case kindMap:
		return fmt.Sprintf("mapping (%d keys)", len(n.keys))
	case kindSeq:
		return fmt.Sprintf("sequence (%d items)", len(n.seq))
	default:
		return strconv.Quote(n.scalar)
	}
}

type rawLine struct {
	indent  int
	content string
	number  int
}

func parseYAML(src string) (node, error) {
	lines, err := lex(src)
	if err != nil {
		return node{}, err
	}
	if len(lines) == 0 {
		return node{kind: kindMap, line: 1}, nil
	}
	root, next, err := parseBlock(lines, 0, lines[0].indent)
	if err != nil {
		return node{}, err
	}
	if next != len(lines) {
		return node{}, fmt.Errorf("line %d: unexpected indentation", lines[next].number)
	}
	return root, nil
}

func lex(src string) ([]rawLine, error) {
	var out []rawLine
	for i, raw := range strings.Split(src, "\n") {
		number := i + 1
		if strings.ContainsRune(raw, '\t') {
			return nil, fmt.Errorf("line %d: tabs are not valid indentation", number)
		}
		trimmedRight := strings.TrimRight(raw, " \r")
		content := stripComment(trimmedRight)
		if strings.TrimSpace(content) == "" {
			continue
		}
		indent := len(content) - len(strings.TrimLeft(content, " "))
		out = append(out, rawLine{indent: indent, content: strings.TrimSpace(content), number: number})
	}
	return out, nil
}

// stripComment removes a trailing `#` comment, but only when the `#` starts a
// word — a `#` inside a quoted string or a URL fragment stays put.
func stripComment(line string) string {
	var quote rune
	for i, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#' && (i == 0 || line[i-1] == ' '):
			return line[:i]
		}
	}
	return line
}

func parseBlock(lines []rawLine, start, indent int) (node, int, error) {
	if start >= len(lines) {
		return node{}, start, fmt.Errorf("unexpected end of document")
	}
	if strings.HasPrefix(lines[start].content, "- ") || lines[start].content == "-" {
		return parseSeq(lines, start, indent)
	}
	return parseMap(lines, start, indent)
}

func parseMap(lines []rawLine, start, indent int) (node, int, error) {
	out := node{kind: kindMap, maps: map[string]node{}, line: lines[start].number}
	i := start
	for i < len(lines) {
		line := lines[i]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return node{}, i, fmt.Errorf("line %d: unexpected indentation", line.number)
		}
		key, rest, ok := splitKey(line.content)
		if !ok {
			return node{}, i, fmt.Errorf("line %d: expected `key: value`, got %q", line.number, line.content)
		}
		if _, dup := out.maps[key]; dup {
			return node{}, i, fmt.Errorf("line %d: duplicate key %q", line.number, key)
		}
		i++
		if rest != "" {
			out.maps[key] = scalarNode(rest, line.number)
			out.keys = append(out.keys, key)
			continue
		}
		if i < len(lines) && lines[i].indent > indent {
			child, next, err := parseBlock(lines, i, lines[i].indent)
			if err != nil {
				return node{}, i, err
			}
			out.maps[key] = child
			i = next
		} else {
			out.maps[key] = node{kind: kindScalar, line: line.number}
		}
		out.keys = append(out.keys, key)
	}
	return out, i, nil
}

func parseSeq(lines []rawLine, start, indent int) (node, int, error) {
	out := node{kind: kindSeq, line: lines[start].number}
	i := start
	for i < len(lines) {
		line := lines[i]
		if line.indent != indent || !(strings.HasPrefix(line.content, "- ") || line.content == "-") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(line.content, "-"))
		i++
		if item == "" {
			if i < len(lines) && lines[i].indent > indent {
				child, next, err := parseBlock(lines, i, lines[i].indent)
				if err != nil {
					return node{}, i, err
				}
				out.seq = append(out.seq, child)
				i = next
			} else {
				out.seq = append(out.seq, node{kind: kindScalar, line: line.number})
			}
			continue
		}
		// `- key: value` starts an inline mapping. Its remaining keys line up
		// with the first key, i.e. the column just past the dash.
		if key, rest, ok := splitKey(item); ok {
			offset := len(line.content) - len(strings.TrimLeft(line.content[1:], " "))
			itemIndent := indent + offset
			inline := rawLine{indent: itemIndent, content: key + ":" + rest, number: line.number}
			rest2 := append([]rawLine{inline}, lines[i:]...)
			child, next, err := parseMap(rest2, 0, itemIndent)
			if err != nil {
				return node{}, i, err
			}
			// parseMap consumed the synthesised first-key line plus any real
			// continuation lines, so the real lines consumed are next-1.
			consumed := next - 1
			out.seq = append(out.seq, child)
			i += consumed
			continue
		}
		out.seq = append(out.seq, scalarNode(item, line.number))
	}
	return out, i, nil
}

func scalarNode(value string, line int) node {
	return node{kind: kindScalar, scalar: unquote(strings.TrimSpace(value)), line: line}
}

func unquote(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			inner := value[1 : len(value)-1]
			if value[0] == '"' {
				if decoded, err := strconv.Unquote(value); err == nil {
					return decoded
				}
			}
			return inner
		}
	}
	return value
}

func splitKey(content string) (key, rest string, ok bool) {
	var quote rune
	for i, r := range content {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ':':
			key = strings.TrimSpace(content[:i])
			rest = strings.TrimSpace(content[i+1:])
			if key == "" {
				return "", "", false
			}
			return unquote(key), rest, true
		}
	}
	return "", "", false
}

func parseInlineList(value string) ([]string, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "[") {
		return nil, false
	}
	if !strings.HasSuffix(value, "]") {
		return nil, false
	}
	inner := strings.TrimSpace(value[1 : len(value)-1])
	if inner == "" {
		return []string{}, true
	}
	parts := strings.Split(inner, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, unquote(strings.TrimSpace(part)))
	}
	return out, true
}
