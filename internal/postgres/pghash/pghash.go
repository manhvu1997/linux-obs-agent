// Package pghash is the reference implementation of the text hash the
// pg_query eBPF program computes (pg_text_hash in pg_query.bpf.c mirrors walk
// statement for statement; change both together).
//
// The hash is a pre-aggregation key and must be at least as conservative as
// sqldigest.NormalizeDialect(…, Postgres): equal hash ⇒ equal digest. Rule:
// FNV-1a 64 over the clipped text (stop at NUL, at most MaxText bytes), except
//   - a '…' string hashes as its opening quote only (content and closing
//     quote skipped; a doubled quote stays inside the string);
//   - a digit run starting after a non-identifier byte and followed by a
//     non-identifier byte (or the end) hashes as one NUL byte;
//   - "…" identifiers, /* */ comments and -- comments are hashed verbatim;
//   - EXACT mode — every remaining byte hashed verbatim — starts at the first
//     backslash (in code or in a string), at a quote preceded by E/e, at a $
//     followed by [A-Za-z_$] or a byte >= 0x80, and at a nested /* inside a
//     comment. No skipping can desynchronise after any of them.
//
// A result of 0 is returned as 1: the kernel uses hash 0 for "no text".
package pghash

const (
	MaxText  = 511
	offset64 = 0xcbf29ce484222325
	prime64  = 0x100000001b3
)

const (
	stCode = iota
	stStr
	stIdent
	stBlock
	stLine
	stDigits
	stExact
)

// Region is a skipped byte range: a digit run (Number) or a string's content.
type Region struct {
	Start, End int
	Number     bool
}

func fnv(h uint64, c byte) uint64 { return (h ^ uint64(c)) * prime64 }
func isDigit(c byte) bool         { return c >= '0' && c <= '9' }

// isIdent: Postgres identifier bytes (start or part), including '$'.
func isIdent(c byte) bool {
	l := c | 0x20
	return (l >= 'a' && l <= 'z') || isDigit(c) || c == '_' || c == '$' || c >= 0x80
}

// dollarTagStart: a byte after '$' that may start a dollar-quote tag (or $$).
func dollarTagStart(c byte) bool {
	l := c | 0x20
	return (l >= 'a' && l <= 'z') || c == '_' || c == '$' || c >= 0x80
}

func at(b []byte, i int) byte {
	if i < len(b) {
		return b[i]
	}
	return 0
}

func clip(b []byte) []byte {
	if len(b) > MaxText {
		b = b[:MaxText]
	}
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

func nonZero(h uint64) uint64 {
	if h == 0 {
		return 1
	}
	return h
}

// KernelHash returns the kernel's aggregation hash of a statement text.
func KernelHash(text []byte) uint64 {
	h, _ := walk(clip(text), false)
	return nonZero(h)
}

// ExactHash is the kernel's hash with literal skipping off (literal_skip = 0,
// the verifier fallback): plain FNV-1a 64 over the clipped bytes.
func ExactHash(text []byte) uint64 {
	h := uint64(offset64)
	for _, c := range clip(text) {
		h = fnv(h, c)
	}
	return nonZero(h)
}

// Regions returns the byte ranges KernelHash skips (for tests and tools).
func Regions(text []byte) []Region {
	_, r := walk(clip(text), true)
	return r
}

func walk(b []byte, want bool) (uint64, []Region) {
	var regions []Region
	h := uint64(offset64)
	var keep, skip uint64
	st := stCode
	var prev byte
	esc := false
	blockAt, runAt, strAt := 0, 0, 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		if st == stExact {
			h = fnv(h, c)
			continue
		}
		if st == stDigits {
			if isDigit(c) {
				keep = fnv(keep, c)
				prev = c
				continue
			}
			if isIdent(c) {
				h = keep
			} else {
				h = skip
				if want {
					regions = append(regions, Region{runAt, i, true})
				}
			}
			st = stCode
		}
		switch st {
		case stCode:
			switch {
			case c == '\\':
				h = fnv(h, c)
				st = stExact
			case c == '\'' && (prev == 'E' || prev == 'e'):
				h = fnv(h, c)
				st = stExact
			case c == '$' && dollarTagStart(at(b, i+1)):
				h = fnv(h, c)
				st = stExact
			case c == '\'':
				h = fnv(h, c)
				st, strAt, esc = stStr, i+1, false
			case c == '"':
				h = fnv(h, c)
				st = stIdent
			case c == '/' && at(b, i+1) == '*':
				h = fnv(h, c)
				st, blockAt = stBlock, i
			case c == '-' && at(b, i+1) == '-':
				h = fnv(h, c)
				st = stLine
			case isDigit(c) && !isIdent(prev):
				keep, skip = fnv(h, c), fnv(h, 0)
				st, runAt = stDigits, i
			default:
				h = fnv(h, c)
			}
		case stStr:
			switch {
			case esc:
				esc = false
			case c == '\\':
				h = fnv(h, c)
				st = stExact
			case c == '\'' && at(b, i+1) == '\'':
				esc = true // '' : the next byte is part of the string
			case c == '\'':
				st = stCode
				if want {
					regions = append(regions, Region{strAt, i, false})
				}
			}
		case stIdent:
			h = fnv(h, c)
			if c == '"' {
				st = stCode
			}
		case stBlock:
			h = fnv(h, c)
			switch {
			case c == '*' && prev == '/' && i >= blockAt+3:
				st = stExact // nested /* : Go nests, the kernel would not
			case c == '/' && prev == '*' && i >= blockAt+3:
				st = stCode
			}
		case stLine:
			h = fnv(h, c)
			if c == '\n' {
				st = stCode
			}
		}
		prev = c
	}
	switch st {
	case stDigits:
		h = skip
		if want {
			regions = append(regions, Region{runAt, len(b), true})
		}
	case stStr:
		if want {
			regions = append(regions, Region{strAt, len(b), false})
		}
	}
	return h, regions
}
