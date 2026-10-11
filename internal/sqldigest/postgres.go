package sqldigest

import "strings"

// Dialect selects the lexical rules NormalizeDialect applies.
type Dialect int

const (
	// MySQL: Normalize's rules ('…' and "…" are strings, `…` identifiers,
	// # comments).
	MySQL Dialect = iota
	// Postgres: "…" are identifiers, # is an operator, nested /* */ comments,
	// E'…' / B'…' / X'…' / U&'…' / $tag$…$tag$ literals, $n parameters.
	Postgres
)

// NormalizeDialect normalises sql with the rules of d. MySQL is exactly
// Normalize. Never panics, never fails.
func NormalizeDialect(sql string, d Dialect) (dg Digest) {
	if d != Postgres {
		return Normalize(sql)
	}
	sql = strings.ToValidUTF8(sql, "?")
	defer func() {
		if recover() != nil {
			text := strings.Join(strings.Fields(sql), " ")
			dg = Digest{ID: HashID(text), Text: text, Normalized: false}
		}
	}()
	text := strings.Join(collapseArrays(collapseLists(tokenizePG(sql))), " ")
	return Digest{ID: HashID(text), Text: text, Normalized: true}
}

// pgOps are Postgres multi-character operators kept as one token, longest
// first. Unlisted ones split into single characters, which is still stable.
var pgOps = []string{
	"->>", "#>>", "~~*", "!~~", "<->", "-|-",
	"::", "<=", ">=", "<>", "!=", "||", "->", "#>", "@>", "<@", "?|", "?&", "~~", "!~", "~*", ":=", "=>", "&&", "<<", ">>", "@@",
}

func isPGIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 0x80
}
func isPGIdentPart(c byte) bool { return isPGIdentStart(c) || isDigit(c) || c == '$' }

// identBefore reports whether s[i] continues an identifier (so a quote after
// it is not a string prefix such as E'…').
func identBefore(s string, i int) bool { return i > 0 && isPGIdentPart(s[i-1]) }

func tokenizePG(s string) []string {
	var toks []string
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case isSpace(c):
			i++
		case c == '/' && i+1 < n && s[i+1] == '*':
			j, ok := skipPGBlockComment(s, i)
			if !ok {
				return toks
			}
			i = j
		case c == '-' && i+1 < n && s[i+1] == '-':
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				return toks
			}
			i += end + 1
		case c == '\'':
			toks = append(toks, "?")
			j, ok := skipPGString(s, i, false)
			if !ok {
				return toks
			}
			i = j
		case (c == 'e' || c == 'E') && i+1 < n && s[i+1] == '\'' && !identBefore(s, i):
			toks = append(toks, "?")
			j, ok := skipPGString(s, i+1, true)
			if !ok {
				return toks
			}
			i = j
		case (c == 'b' || c == 'B' || c == 'x' || c == 'X' || c == 'n' || c == 'N') && i+1 < n && s[i+1] == '\'' && !identBefore(s, i):
			toks = append(toks, "?")
			j, ok := skipPGString(s, i+1, false)
			if !ok {
				return toks
			}
			i = j
		case (c == 'u' || c == 'U') && i+2 < n && s[i+1] == '&' && s[i+2] == '\'' && !identBefore(s, i):
			toks = append(toks, "?")
			j, ok := skipPGString(s, i+2, false)
			if !ok {
				return toks
			}
			i = j
		case c == '"':
			j, ok := skipPGQuotedIdent(s, i)
			if !ok {
				return append(toks, s[i:])
			}
			toks = append(toks, s[i:j])
			i = j
		case c == '$' && i+1 < n && isDigit(s[i+1]):
			toks = append(toks, "?")
			i += 2
			for i < n && isDigit(s[i]) {
				i++
			}
		case c == '$':
			j, isQuote, ok := skipDollarQuote(s, i)
			if !isQuote {
				toks = append(toks, "$")
				i++
				continue
			}
			toks = append(toks, "?")
			if !ok {
				return toks
			}
			i = j
		case isDigit(c) || (c == '.' && i+1 < n && isDigit(s[i+1])):
			toks = append(toks, "?")
			i = skipPGNumber(s, i)
		case isPGIdentStart(c):
			j := i + 1
			for j < n && isPGIdentPart(s[j]) {
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
			i = skipPGNumber(s, i+1)
		default:
			matched := false
			for _, op := range pgOps {
				if strings.HasPrefix(s[i:], op) {
					toks = append(toks, op)
					i += len(op)
					matched = true
					break
				}
			}
			if !matched {
				toks = append(toks, s[i:i+1])
				i++
			}
		}
	}
	return toks
}

// skipPGBlockComment returns the index just past the comment starting at
// s[i] ("/*"), honouring nesting. ok=false when unterminated.
func skipPGBlockComment(s string, i int) (int, bool) {
	depth := 0
	for j := i; j+1 < len(s); j++ {
		switch {
		case s[j] == '/' && s[j+1] == '*':
			depth++
			j++
		case s[j] == '*' && s[j+1] == '/':
			depth--
			j++
			if depth == 0 {
				return j + 1, true
			}
		}
	}
	return len(s), false
}

// skipPGString returns the index past the closing quote of the string whose
// opening quote is s[q]. A doubled quote is an escaped quote; with
// backslash (E'…') a backslash escapes the next byte.
func skipPGString(s string, q int, backslash bool) (int, bool) {
	for j := q + 1; j < len(s); j++ {
		switch {
		case backslash && s[j] == '\\':
			j++
		case s[j] == '\'':
			if j+1 < len(s) && s[j+1] == '\'' {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return len(s), false
}

// skipPGQuotedIdent returns the index past the closing " ("" is escaped).
func skipPGQuotedIdent(s string, i int) (int, bool) {
	for j := i + 1; j < len(s); j++ {
		if s[j] == '"' {
			if j+1 < len(s) && s[j+1] == '"' {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return len(s), false
}

// skipDollarQuote: s[i] == '$'. isQuote reports whether a $tag$ (or $$)
// opener starts here; ok whether its closing tag was found; j is the index
// past the closing tag.
func skipDollarQuote(s string, i int) (j int, isQuote, ok bool) {
	k := i + 1
	if k < len(s) && isPGIdentStart(s[k]) {
		k++
		for k < len(s) && (isPGIdentStart(s[k]) || isDigit(s[k])) {
			k++
		}
	}
	if k >= len(s) || s[k] != '$' {
		return 0, false, false
	}
	tag := s[i : k+1]
	end := strings.Index(s[k+1:], tag)
	if end < 0 {
		return len(s), true, false
	}
	return k + 1 + end + len(tag), true, true
}

// skipPGNumber: digits with optional '_' separators (PG 16+), a fraction, an
// exponent, or a 0x/0o/0b prefix.
func skipPGNumber(s string, i int) int {
	n := len(s)
	if i+1 < n && s[i] == '0' {
		switch s[i+1] {
		case 'x', 'X', 'o', 'O', 'b', 'B':
			j := i + 2
			for j < n && (isHex(s[j]) || s[j] == '_') {
				j++
			}
			return j
		}
	}
	j := i
	for j < n && (isDigit(s[j]) || s[j] == '.' || s[j] == '_') {
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

// collapseArrays rewrites `array [ ? , ? ]` → `array [ ?+ ]`.
func collapseArrays(toks []string) []string {
	out := make([]string, 0, len(toks))
	for i := 0; i < len(toks); i++ {
		out = append(out, toks[i])
		if toks[i] != "array" || i+1 >= len(toks) || toks[i+1] != "[" {
			continue
		}
		j := i + 2
		ok := false
		for j < len(toks) && toks[j] == "?" {
			j++
			if j < len(toks) && toks[j] == "]" {
				ok = true
				break
			}
			if j >= len(toks) || toks[j] != "," {
				break
			}
			j++
		}
		if ok {
			out = append(out, "[", "?+", "]")
			i = j
		}
	}
	return out
}

// ReferencesSystemCatalog reports whether a Postgres-normalised text reads a
// system catalog: a pg_catalog / information_schema qualifier followed by
// ".", or a pg_* relation directly after FROM or JOIN (pg_ is reserved for
// system schemas; a user table literally named pg_x is folded too).
func ReferencesSystemCatalog(normalizedText string) bool {
	toks := strings.Fields(normalizedText)
	for i, t := range toks {
		if (t == "pg_catalog" || t == "information_schema") && i+1 < len(toks) && toks[i+1] == "." {
			return true
		}
		if i > 0 && (toks[i-1] == "from" || toks[i-1] == "join") && strings.HasPrefix(t, "pg_") &&
			(i+1 >= len(toks) || toks[i+1] != ".") {
			return true
		}
	}
	return false
}
