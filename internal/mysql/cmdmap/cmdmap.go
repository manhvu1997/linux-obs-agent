// Package cmdmap maps a MySQL enum_server_command plus captured text to a
// command class and digest. Pure, so it is testable without eBPF.
package cmdmap

import (
	"fmt"
	"strings"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

const (
	ComQuery       = 3
	ComStmtExecute = 23
	QueryMax       = 512 // must equal QUERY_MAX in mysql_query.bpf.c
)

// Classify returns the command class ("query" | "stmt_execute" | "other"),
// its digest, a UTF-8-safe sample of the raw text, and whether the captured
// text was cut at the kernel buffer (QueryMax-1 bytes + NUL).
func Classify(command uint32, query string, queryLen uint32) (class string, d sqldigest.Digest, sample string, truncated bool) {
	switch command {
	case ComQuery:
		truncated = queryLen >= QueryMax
		if strings.TrimSpace(query) == "" {
			return "query", placeholder("<empty query>"), "", truncated
		}
		return "query", sqldigest.Normalize(query), strings.ToValidUTF8(query, "?"), truncated
	case ComStmtExecute:
		return "stmt_execute", placeholder("<COM_STMT_EXECUTE: prepared, text unavailable>"), "", false
	default:
		return "other", placeholder(fmt.Sprintf("<COM command %d>", command)), "", false
	}
}

func placeholder(text string) sqldigest.Digest {
	return sqldigest.Digest{ID: sqldigest.HashID(text), Text: text, Normalized: true}
}
