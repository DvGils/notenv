// Package dotenv parses the subset of .env syntax `notenv import` accepts.
// The dialect is documented and deliberately small. An importer for secrets
// must never guess:
//
//   - blank lines and full-line `#` comments are skipped; an unquoted value
//     may carry a trailing comment when whitespace precedes the `#`
//   - an optional `export ` prefix is dropped
//   - unquoted values are trimmed of surrounding whitespace
//   - single-quoted values are literal, double-quoted values understand the
//     \n, \r, \t, \", \\ escapes; both may span multiple lines
//   - there is no variable expansion of any kind: a secrets file is not a
//     shell script, and silently expanding `$X` would corrupt real values
//
// Anything else (a line without `=`, an unterminated quote, a stray escape)
// fails the parse with its line number, so an import is all-or-nothing.
package dotenv

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Pair is one assignment, in file order. A key assigned twice appears twice;
// the caller applies last-wins.
type Pair struct {
	Key   string
	Value string
	Line  int
}

// Parse reads assignments from r.
func Parse(r io.Reader) ([]Pair, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var pairs []Pair
	for line := 1; scanner.Scan(); line++ {
		raw := scanner.Text()
		if line == 1 {
			// Strip a leading UTF-8 BOM (Windows editors add one); it is not
			// whitespace, so it would otherwise become part of the first key.
			raw = strings.TrimPrefix(raw, "\ufeff")
		}
		text := strings.TrimSpace(raw)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		text = strings.TrimPrefix(text, "export ")
		key, rest, found := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if !found || !validKeyShape(key) {
			return nil, fmt.Errorf("line %d: not a KEY=VALUE assignment", line)
		}
		start := line
		value, consumed, err := parseValue(rest, scanner)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", start, err)
		}
		line += consumed
		pairs = append(pairs, Pair{Key: key, Value: value, Line: start})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return pairs, nil
}

// validKeyShape is a cheap structural check (no spaces, non-empty, no quotes);
// the caller applies the real environment-name validation and reports all
// offenders together.
func validKeyShape(key string) bool {
	return key != "" && !strings.ContainsAny(key, " \t'\"")
}

// parseValue interprets one value, pulling further lines from the scanner when
// a quoted value spans them. rest is the raw text after '=', untrimmed, so the
// whitespace before a trailing comment is still visible (Parse must not trim it
// away first, or `KEY= # later` would store the comment as the value). Returns
// the value and how many extra lines were consumed.
func parseValue(rest string, scanner *bufio.Scanner) (string, int, error) {
	trimmed := strings.TrimLeft(rest, " \t")
	if trimmed == "" {
		return "", 0, nil
	}
	// An empty value followed by a comment: whitespace separated '=' from '#', so
	// the value proper is empty and the rest is a comment. Without that separating
	// whitespace (`KEY=#x`) the '#' is part of the value, the same "whitespace
	// precedes the comment" rule the unquoted branch below applies.
	if trimmed[0] == '#' && len(trimmed) < len(rest) {
		return "", 0, nil
	}
	quote := trimmed[0]
	if quote != '\'' && quote != '"' {
		// Unquoted: cut a trailing comment (whitespace before '#'), then trim.
		v := rest
		if i := strings.Index(v, " #"); i >= 0 {
			v = v[:i]
		} else if i := strings.Index(v, "\t#"); i >= 0 {
			v = v[:i]
		}
		return strings.TrimSpace(v), 0, nil
	}

	body, consumed, err := collectQuoted(trimmed[1:], quote, scanner)
	if err != nil {
		return "", consumed, err
	}
	if quote == '\'' {
		return body, consumed, nil
	}
	out, err := unescape(body)
	return out, consumed, err
}

// collectQuoted accumulates until the closing quote, consuming extra lines as
// needed. Inside double quotes a backslash escapes the next character, so an
// escaped quote does not close.
func collectQuoted(first string, quote byte, scanner *bufio.Scanner) (string, int, error) {
	var b strings.Builder
	chunk, consumed := first, 0
	for {
		escaped := false
		for i := 0; i < len(chunk); i++ {
			c := chunk[i]
			switch {
			case escaped:
				escaped = false
			case quote == '"' && c == '\\':
				escaped = true
			case c == quote:
				if rest := strings.TrimSpace(chunk[i+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
					return "", consumed, fmt.Errorf("unexpected content after closing quote: %q", rest)
				}
				b.WriteString(chunk[:i])
				return b.String(), consumed, nil
			}
		}
		b.WriteString(chunk)
		b.WriteByte('\n')
		if !scanner.Scan() {
			return "", consumed, fmt.Errorf("unterminated %c-quoted value", quote)
		}
		consumed++
		chunk = scanner.Text()
	}
}

// unescape resolves the escapes double quotes support.
func unescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(s) {
			return "", fmt.Errorf("dangling backslash")
		}
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		default:
			return "", fmt.Errorf("unsupported escape \\%c (only \\n, \\r, \\t, \\\", \\\\)", s[i])
		}
	}
	return b.String(), nil
}
