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
	ComStmtPrepare = 22
	ComStmtExecute = 23
	QueryMax       = 512 // must equal QUERY_MAX in mysql_query.bpf.c
)

// commandNames is MySQL 8.x enum_server_command (my_command.h), minus the
// commands that carry statement text (QUERY, STMT_PREPARE, STMT_EXECUTE).
var commandNames = map[uint32]string{
	0: "SLEEP", 1: "QUIT", 2: "INIT_DB", 4: "FIELD_LIST", 5: "CREATE_DB", 6: "DROP_DB",
	7: "REFRESH", 9: "STATISTICS", 11: "CONNECT", 13: "DEBUG", 14: "PING", 15: "TIME", 16: "DELAYED_INSERT",
	17: "CHANGE_USER", 18: "BINLOG_DUMP", 19: "TABLE_DUMP", 20: "CONNECT_OUT", 21: "REGISTER_REPLICA",
	24: "STMT_SEND_LONG_DATA", 25: "STMT_CLOSE", 26: "STMT_RESET", 27: "SET_OPTION", 28: "STMT_FETCH",
	29: "DAEMON", 30: "BINLOG_DUMP_GTID", 31: "RESET_CONNECTION", 32: "CLONE",
	33: "SUBSCRIBE_GROUP_REPLICATION_STREAM",
}

const (
	execNoTextTracking = "<COM_STMT_EXECUTE: prepared before agent start, text unavailable>"
	execNoText         = "<COM_STMT_EXECUTE: prepared, text unavailable>"
	emptyQuery         = "<empty query>"
)

// Classify returns the command class ("query" | "stmt_prepare" |
// "stmt_execute" | "other"), its digest, a UTF-8-safe sample of the raw
// text, and whether the captured text was cut at the kernel buffer
// (QueryMax-1 bytes + NUL).
//
// For COM_STMT_EXECUTE, query is the text recovered from the matching
// COM_STMT_PREPARE; its digest deliberately equals that of the same text sent
// as COM_QUERY. preparedTracking reports whether the kernel recovers prepared
// text at all; it only selects which "text unavailable" placeholder to use.
func Classify(command uint32, query string, queryLen uint32, preparedTracking bool) (class string, d sqldigest.Digest, sample string, truncated bool) {
	switch command {
	case ComQuery:
		truncated = queryLen >= QueryMax
		if strings.TrimSpace(query) == "" {
			return "query", placeholder(emptyQuery), "", truncated
		}
		return "query", sqldigest.Normalize(query), strings.ToValidUTF8(query, "?"), truncated
	case ComStmtPrepare:
		if strings.TrimSpace(query) == "" {
			return "stmt_prepare", placeholder("<COM_STMT_PREPARE>"), "", false
		}
		n := sqldigest.Normalize(query)
		text := "prepare: " + n.Text
		d = sqldigest.Digest{ID: sqldigest.HashID(text), Text: text, Normalized: n.Normalized}
		return "stmt_prepare", d, strings.ToValidUTF8(query, "?"), queryLen >= QueryMax
	case ComStmtExecute:
		if strings.TrimSpace(query) == "" {
			return "stmt_execute", placeholder(execPlaceholder(preparedTracking)), "", false
		}
		return "stmt_execute", sqldigest.Normalize(query), strings.ToValidUTF8(query, "?"), queryLen >= QueryMax
	default:
		if name, ok := commandNames[command]; ok {
			return "other", placeholder("<COM_" + name + ">"), "", false
		}
		return "other", placeholder(fmt.Sprintf("<COM command %d>", command)), "", false
	}
}

func placeholder(text string) sqldigest.Digest {
	return sqldigest.Digest{ID: sqldigest.HashID(text), Text: text, Normalized: true}
}

func execPlaceholder(preparedTracking bool) string {
	if preparedTracking {
		return execNoTextTracking
	}
	return execNoText
}

// SlowQueryText is the query shown for a slow-query event (only COM_QUERY
// and COM_STMT_EXECUTE emit one): the captured text, or — when there is
// none — the same placeholder Classify uses for that command's digest, so
// recent_slow_queries never holds an anonymous blank row.
func SlowQueryText(command uint32, query string, preparedTracking bool) string {
	if strings.TrimSpace(query) != "" {
		return query
	}
	if command == ComStmtExecute {
		return execPlaceholder(preparedTracking)
	}
	return emptyQuery
}
