package config

import (
	"log/slog"

	"gopkg.in/yaml.v3"
)

// removedKey is a config key that is no longer read; Replacement is the key
// that took over its role, "" when there is none.
type removedKey struct {
	Key         string
	Replacement string
}

// removedMySQLKeyList: keys under mysql: dropped with the node-relative
// statistics. yaml.Unmarshal ignores unknown keys, so without a warning an
// old config would silently lose its tuning.
var removedMySQLKeyList = []removedKey{
	{"culprit_cpu_share_percent", "cpu_culprit_percent_of_node_cpu_used"},
	{"culprit_min_cpu_percent", "cpu_culprit_min_node_cpu_used_percent"},
	{"victim_runq_ratio", "victim_wait_percent"},
	{"overload_min_node_cpu_percent", ""},
	{"top_n", ""},
	{"stale_seconds", ""},
}

// removedMySQLKeys returns the removed keys present under mysql: in the raw
// YAML, in removedMySQLKeyList order. Unparsable YAML yields none (the real
// parse reports the error).
func removedMySQLKeys(data []byte) []removedKey {
	var raw map[string]any
	if yaml.Unmarshal(data, &raw) != nil {
		return nil
	}
	mysql, ok := raw["mysql"].(map[string]any)
	if !ok {
		return nil
	}
	var out []removedKey
	for _, k := range removedMySQLKeyList {
		if _, present := mysql[k.Key]; present {
			out = append(out, k)
		}
	}
	return out
}

// warnRemovedKeys logs one warning per removed key present in the config.
func warnRemovedKeys(path string, data []byte) {
	for _, k := range removedMySQLKeys(data) {
		replacement := "no replacement"
		if k.Replacement != "" {
			replacement = "use mysql." + k.Replacement
		}
		slog.Warn("config: mysql."+k.Key+" is no longer used and is ignored; "+replacement,
			"file", path, "key", "mysql."+k.Key, "replacement", k.Replacement)
	}
}
