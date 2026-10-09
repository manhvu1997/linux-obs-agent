// Package sqlhash is the reference implementation of the text hash the
// mysql_query eBPF program computes in the kernel (text_hash in
// mysql_query.bpf.c mirrors KernelHash statement for statement).
//
// The hash is a pre-aggregation key: statements that differ only in the
// literals it skips are summed in one kernel map entry. It must therefore be
// strictly more conservative than sqldigest.Normalize — equal hash ⇒ equal
// digest — while several hashes may map to one digest (Go merges them).
//
// Rule: FNV-1a 64 over the captured text (stop at NUL, at most MaxText
// bytes), except
//   - a quoted string ('…' or "…", backslash escapes, doubled quote) hashes
//     as its opening quote byte only (' or "), its content and closing quote
//     are not hashed;
//   - a digit run that starts after a non-identifier byte and is followed by
//     a non-identifier byte (or the end) hashes as a single NUL byte, which
//     cannot occur in clipped text;
//   - Backtick identifiers and comments (/* */, #, "-- ") are hashed
//     verbatim, so a quote inside them never starts a string.
//
// The markers are chosen so neither can alias a literal '?' placeholder
// (sqldigest renders both literals as '?', so a literal '?' in the text must
// stay distinguishable) or each other: a literal quote in code always starts a
// string, and NUL never survives clipping.
package sqlhash

const (
	// MaxText is the number of text bytes the kernel captures (QUERY_MAX-1).
	MaxText = 511

	offset64 = 0xcbf29ce484222325
	prime64  = 0x100000001b3
)

const (
	stCode = iota
	stStr
	stTick
	stBlock
	stLine
	stDigits
)

// Region is a byte range [Start, End) that KernelHash does not hash byte by
// byte: a digit run (Number) hashes as one NUL byte; a quoted string's
// content is not hashed at all (nor is its closing quote at End), only its
// opening quote byte at Start-1.
type Region struct {
	Start, End int
	Number     bool // a digit run; otherwise a quoted string's content
}

func fnv(h uint64, c byte) uint64 { return (h ^ uint64(c)) * prime64 }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isIdent matches sqldigest's identifier bytes (start or part).
func isIdent(c byte) bool {
	l := c | 0x20
	return (l >= 'a' && l <= 'z') || isDigit(c) || c == '_' || c == '$' || c == '@' || c >= 0x80
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
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

// KernelHash returns the kernel's aggregation hash of a statement text.
func KernelHash(text []byte) uint64 {
	h, _ := walk(clip(text), false)
	return h
}

// ExactHash returns the kernel's hash when literal skipping is off
// (literal_skip = 0, the verifier fallback): plain FNV-1a 64 over the same
// clipped bytes as KernelHash.
func ExactHash(text []byte) uint64 {
	h := uint64(offset64)
	for _, c := range clip(text) {
		h = fnv(h, c)
	}
	return h
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
	var q, prev byte
	esc := false
	blockAt, runAt, strAt := 0, 0, 0
	for i := 0; i < len(b); i++ {
		c := b[i]
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
			case c == '\'' || c == '"':
				h = fnv(h, c)
				st, q, strAt = stStr, c, i+1
			case c == '`':
				h = fnv(h, c)
				st = stTick
			case c == '/' && at(b, i+1) == '*':
				h = fnv(h, c)
				st, blockAt = stBlock, i
			case c == '#' || (c == '-' && at(b, i+1) == '-' && (at(b, i+2) == 0 || isSpace(at(b, i+2)))):
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
				esc = true
			case c == q && at(b, i+1) == q:
				esc = true // doubled quote: the next byte is part of the string
			case c == q:
				st = stCode
				if want {
					regions = append(regions, Region{strAt, i, false})
				}
			}
		case stTick:
			h = fnv(h, c)
			if c == '`' {
				st = stCode
			}
		case stBlock:
			h = fnv(h, c)
			if c == '/' && prev == '*' && i >= blockAt+3 {
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
