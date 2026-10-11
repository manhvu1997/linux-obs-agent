package postgres

import "github.com/manhvu1997/linux-obs-agent/internal/config"

// OptionsFromConfig maps postgres: (and process.include_io) to Options.
func OptionsFromConfig(c *config.PostgresConfig, includeIO bool) Options {
	return Options{
		SlowQueryThresholdMs: c.SlowQueryThresholdMs,
		PollInterval:         c.PollInterval, DigestWindow: c.DigestWindow, DiscoverInterval: c.DiscoverInterval,
		ShedCooldown: c.ShedCooldown, SQLPollInterval: c.SQL.PollInterval,
		TopDigests: c.TopDigests, StickyDigestsMax: c.StickyDigestsMax, MaxRecentQueries: c.MaxRecentQueries,
		StickyDigestTTL:                c.StickyDigestTTL,
		CPUCulpritPercentOfNodeCPUUsed: c.CPUCulpritPercentOfNodeCPUUsed, CPUCulpritMinNodeCPUUsedPct: c.CPUCulpritMinNodeCPUUsedPercent,
		VictimWaitPercent: c.VictimWaitPercent, IOCulpritPercentOfDiskRead: c.IOCulpritPercentOfDiskRead,
		IOCulpritMinNodeDiskReadMBPerSec: c.IOCulpritMinNodeDiskReadMBPerSec, BackgroundDominantPercent: c.BackgroundDominantPercent,
		MaxStatementsPerSec: c.MaxStatementsPerSec,
		FoldSystemCatalogs:  c.FoldSystemCatalogs, SampleQueries: c.SampleQueries, EnableDelayAcct: c.EnableDelayAcct,
		IncludeIO: includeIO, SyncRepWait: c.SyncRepWait, BinaryPaths: c.BinaryPaths,
	}
}
