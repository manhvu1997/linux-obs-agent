// internal/sqldigest/sqldigest.go

// Package sqldigest normalises SQL text into a stable "digest": literals
// become ?, value lists collapse, comments and whitespace disappear. Two
// executions of the same statement shape with different literal values
// produce the same digest, so per-digest totals reveal a query pattern that
// is cheap per call but expensive in aggregate.
//
// Database-agnostic: MySQL is the first user; PostgreSQL/others can reuse it.
package sqldigest

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Digest is the normalised form of one SQL statement.
type Digest struct {
	ID         string // HashID(Text)
	Text       string // normalised SQL, always valid UTF-8
	Normalized bool   // false when the whitespace-collapsed fallback was used
}

// HashID returns the first 16 hex characters of sha256(text).
func HashID(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:8])
}

// Normalize never panics and never fails. Text cut off mid-literal (the
// kernel captures at most 511 bytes) is handled: the unterminated literal
// becomes a single ?.
func Normalize(sql string) (d Digest) {
	sql = strings.ToValidUTF8(sql, "?")
	defer func() {
		if recover() != nil {
			text := strings.Join(strings.Fields(sql), " ")
			d = Digest{ID: HashID(text), Text: text, Normalized: false}
		}
	}()
	text := strings.Join(collapseLists(tokenize(sql)), " ")
	return Digest{ID: HashID(text), Text: text, Normalized: true}
}

func tokenize(s string) []string {
	var toks []string
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case isSpace(c):
			i++
		case c == '/' && i+1 < n && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return toks
			}
			i += 2 + end + 2
		case c == '#' || (c == '-' && i+1 < n && s[i+1] == '-' && (i+2 == n || isSpace(s[i+2]))):
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				return toks
			}
			i += end + 1
		case c == '\'' || c == '"':
			toks = append(toks, "?")
			j, ok := skipQuoted(s, i)
			if !ok {
				return toks
			}
			i = j
		case c == '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				return append(toks, s[i:])
			}
			toks = append(toks, s[i:i+end+2])
			i += end + 2
		case (c == 'x' || c == 'X' || c == 'b' || c == 'B') && i+1 < n && s[i+1] == '\'':
			toks = append(toks, "?")
			j, ok := skipQuoted(s, i+1)
			if !ok {
				return toks
			}
			i = j
		case isDigit(c) || (c == '.' && i+1 < n && isDigit(s[i+1])):
			toks = append(toks, "?")
			i = skipNumber(s, i)
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentPart(s[j]) {
				j++
			}
			w := strings.ToLower(s[i:j])
			if w == "true" || w == "false" || w == "null" {
				w = "?"
			}
			toks = append(toks, w)
			i = j
		case (c == '-' || c == '+') && i+1 < n && (isDigit(s[i+1]) || (s[i+1] == '.' && i+2 < n && isDigit(s[i+2]))) && unaryContext(toks):
			toks = append(toks, "?")
			i = skipNumber(s, i+1)
		default:
			if i+2 < n && s[i:i+3] == "<=>" {
				toks = append(toks, "<=>")
				i += 3
				continue
			}
			if i+1 < n {
				switch s[i : i+2] {
				case "<=", ">=", "<>", "!=", ":=", "||", "&&":
					toks = append(toks, s[i:i+2])
					i += 2
					continue
				}
			}
			toks = append(toks, s[i:i+1])
			i++
		}
	}
	return toks
}

// unaryContext reports whether a sign following toks is unary (part of a
// numeric literal) rather than a binary operator.
func unaryContext(toks []string) bool {
	if len(toks) == 0 {
		return true
	}
	switch toks[len(toks)-1] {
	case "(", ",", "=", "<", ">", "<=", ">=", "<>", "!=", "<=>", ":=", "||", "&&",
		"+", "-", "*", "/", "%",
		"in", "values", "and", "or", "not", "between", "then", "else", "when",
		"select", "set", "where", "limit", "offset", "like", "is", "on", "having":
		return true
	}
	return false
}

// skipQuoted returns the index just past the closing quote that matches
// s[i], honouring backslash escapes and doubled quotes. ok=false when the
// literal is unterminated (truncated capture).
func skipQuoted(s string, i int) (int, bool) {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case q:
			if j+1 < len(s) && s[j+1] == q {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return len(s), false
}

func skipNumber(s string, i int) int {
	n := len(s)
	if i+1 < n && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
		j := i + 2
		for j < n && isHex(s[j]) {
			j++
		}
		return j
	}
	j := i
	for j < n && (isDigit(s[j]) || s[j] == '.') {
		j++
	}
	if j < n && (s[j] == 'e' || s[j] == 'E') {
		k := j + 1
		if k < n && (s[k] == '+' || s[k] == '-') {
			k++
		}
		if k < n && isDigit(s[k]) {
			for k < n && isDigit(s[k]) {
				k++
			}
			j = k
		}
	}
	return j
}

// collapseLists rewrites `in ( ? , ? )` → `in ( ?+ )` and
// `values ( ?.. ) , ( ?.. )` → `values ( ?+ )`, so the number of list
// elements does not create distinct digests. Lists containing anything other
// than ? (e.g. NOW()) are left as-is.
func collapseLists(toks []string) []string {
	out := make([]string, 0, len(toks))
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		out = append(out, t)
		switch t {
		case "in":
			if end, ok := qList(toks, i+1); ok {
				out = append(out, "(", "?+", ")")
				i = end
			}
		case "values":
			last, j := -1, i+1
			for {
				end, ok := qList(toks, j)
				if !ok {
					break
				}
				last = end
				if end+2 < len(toks) && toks[end+1] == "," && toks[end+2] == "(" {
					j = end + 2
					continue
				}
				break
			}
			if last >= 0 {
				out = append(out, "(", "?+", ")")
				i = last
			}
		}
	}
	return out
}

// qList reports whether toks[start:] begins with `( ? [, ?]* )` and returns
// the index of the closing parenthesis.
func qList(toks []string, start int) (int, bool) {
	if start >= len(toks) || toks[start] != "(" {
		return 0, false
	}
	j := start + 1
	for {
		if j >= len(toks) || toks[j] != "?" {
			return 0, false
		}
		j++
		if j < len(toks) && toks[j] == ")" {
			return j, true
		}
		if j >= len(toks) || toks[j] != "," {
			return 0, false
		}
		j++
	}
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$' || c == '@' || c >= 0x80
}
func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }

// systemSchemas are the MySQL schemas that hold server metadata. Queries
// against them come from exporters and monitoring tools, not applications.
var systemSchemas = map[string]bool{
	"information_schema": true,
	"performance_schema": true,
	"sys":                true,
	"mysql":              true,
}

// ReferencesSystemSchema reports whether normalizedText (the space-separated
// output of Normalize) qualifies an object with a system schema, i.e. a token
// that is one of information_schema, performance_schema, sys or mysql
// (backticks stripped, case-insensitive) immediately followed by ".".
// A bare name ("select sys from t") or one AFTER the dot ("t . mysql", a
// column or table named mysql) is not a schema qualifier.
func ReferencesSystemSchema(normalizedText string) bool {
	toks := strings.Fields(normalizedText)
	for i := 0; i+1 < len(toks); i++ {
		if toks[i+1] != "." {
			continue
		}
		if systemSchemas[strings.ToLower(strings.Trim(toks[i], "`"))] {
			return true
		}
	}
	return false
}
