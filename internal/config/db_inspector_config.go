package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// DBInspectorConfig is the configuration for the db-inspector sidecar binary.
// It only contains the subset of fields needed by the slim sidecar — no trigger
// engine, eBPF manager, proc collector, fsync/writeback/disk scanner, etc.
type DBInspectorConfig struct {
	// LogLevel: debug | info | warn | error. Default "info".
	LogLevel string `yaml:"log_level"`
	// ListenAddr is the HTTP address for /healthz and /api/inspect.
	// Default ":9201".
	ListenAddr string `yaml:"listen_addr"`
	// Mongo controls the MongoDB slow-query tracer.
	Mongo MongoConfig `yaml:"mongo"`
	// Future: MySQL MySQLConfig `yaml:"mysql"`
}

// defaultDBInspectorConfig returns a DBInspectorConfig with safe defaults.
// MongoDB tracing is off by default; enable via MONGODB_TRACING_ENABLED=true
// or by setting mongo.enabled: true in the YAML file.
func defaultDBInspectorConfig() *DBInspectorConfig {
	return &DBInspectorConfig{
		LogLevel:   "info",
		ListenAddr: ":9201",
		Mongo: MongoConfig{
			Enabled:              false,
			Port:                 27017,
			SlowQueryThresholdMs: 2000,
			PollInterval:         5 * time.Second,
			TopN:                 20,
			StaleSeconds:         60,
			MaxRecentQueries:     100,
		},
	}
}

// LoadDBInspector reads a YAML config file and merges it over the defaults.
// If path is empty or the file does not exist the defaults are used.
// Environment variable overrides (MONGODB_TRACING_ENABLED, etc.) are applied
// after file parsing using the same logic as the main agent config.
func LoadDBInspector(path string) (*DBInspectorConfig, error) {
	cfg := defaultDBInspectorConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, err
			}
		}
	}
	// Reuse the same env-var override logic already defined in config.go.
	fullCfg := &Config{Mongo: cfg.Mongo}
	applyMongoEnvOverrides(fullCfg)
	cfg.Mongo = fullCfg.Mongo
	return cfg, nil
}
