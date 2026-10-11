package overload

import (
	"fmt"
	"sort"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

// Wait is one commit-like wait an engine reports beside block I/O; it counts
// for the disk assessment.
type Wait struct {
	Key      string // accounting key, e.g. "commit_wait", "wal_wait"
	Victim   string // victim_of kind, also its name in texts: "commit", "wal"
	Optional bool   // skipped entirely while its accounting value is "not_attached"
	SetCount func(ev *model.OverloadEvidence, n int)
}

// Engine is what differs between database engines in an assessment: names in
// texts, the commit-like waits, where the family evidence goes, and whether
// background backends can be the verdict.
type Engine struct {
	Process            string // "mysqld" | "postgres"
	Report             string // "mysql_report" | "postgres_report"
	CheckProcess       string // "mysqld_top_consumer" | "postgres_top_consumer"
	NotEngine          model.OverloadVerdict
	NoDigestsHint      string // why there may be no digests (no-data summary)
	DiskBackgroundText string // who else reads (no-dominant-query disk summary)
	PagesAdvice        func(*float64) string
	CommitWaits        []Wait
	SetCPUFamily       func(ev *model.OverloadEvidence, fam string, cpuPercent float64)
	SetDiskFamily      func(ev *model.OverloadEvidence, fam string, mbPerSec float64)
	Background         bool // background_overload is possible (PostgreSQL)
}

// PostgreSQL accounting keys and victim kinds (postgres_report names).
const (
	PGAccountingWAL     = "wal_wait"
	PGAccountingSyncRep = "syncrep_wait"
	PGVictimWAL         = "wal"
	PGVictimSyncRep     = "syncrep"
)

var MySQLEngine = Engine{
	Process: "mysqld", Report: "mysql_report", CheckProcess: "mysqld_top_consumer",
	NotEngine:          model.OverloadNotMySQL,
	NoDigestsHint:      "mysql.emit_all_queries off, or no queries yet",
	DiskBackgroundText: "InnoDB background work or writes",
	PagesAdvice:        innodbPagesAdvice,
	CommitWaits: []Wait{{Key: querystats.AccountingKeyCommitWait, Victim: querystats.VictimCommit,
		SetCount: func(ev *model.OverloadEvidence, n int) { ev.CommitVictims = intp(n) }}},
	SetCPUFamily: func(ev *model.OverloadEvidence, fam string, cpu float64) {
		ev.MySQLFamily, ev.MySQLFamilyCPUPercent = fam, floatp(cpu)
	},
	SetDiskFamily: func(ev *model.OverloadEvidence, fam string, mb float64) {
		ev.MySQLFamily, ev.MySQLFamilyDiskReadMBPerSec = fam, floatp(mb)
	},
}

var PostgresEngine = Engine{
	Process: "postgres", Report: "postgres_report", CheckProcess: "postgres_top_consumer",
	NotEngine:          model.OverloadNotPostgres,
	NoDigestsHint:      "no statements traced yet, or tracing shed — see postgres_report.accounting.state",
	DiskBackgroundText: "autovacuum, checkpoints, I/O workers or writes",
	PagesAdvice:        pgPagesAdvice,
	CommitWaits: []Wait{
		{Key: PGAccountingWAL, Victim: PGVictimWAL,
			SetCount: func(ev *model.OverloadEvidence, n int) { ev.WALVictims = intp(n) }},
		{Key: PGAccountingSyncRep, Victim: PGVictimSyncRep, Optional: true,
			SetCount: func(ev *model.OverloadEvidence, n int) { ev.SyncRepVictims = intp(n) }},
	},
	SetCPUFamily: func(ev *model.OverloadEvidence, fam string, cpu float64) {
		ev.PostgresFamily, ev.PostgresFamilyCPUPercent = fam, floatp(cpu)
	},
	SetDiskFamily: func(ev *model.OverloadEvidence, fam string, mb float64) {
		ev.PostgresFamily, ev.PostgresFamilyDiskReadMBPerSec = fam, floatp(mb)
	},
	Background: true,
}

// BackendUsage is one PostgreSQL backend type's share of its cluster over the
// window. DiskReadMBPerSec is nil when per-process I/O is not measured.
type BackendUsage struct {
	Type             string
	CPUCores         float64
	DiskReadMBPerSec *float64
}

// Report is the engine-neutral view of one database report. Accounting keys
// and victim kinds use the engine's names.
type Report struct {
	WindowSeconds                int
	Node                         *model.MySQLNodeWindow
	QueryCPUCoveragePercent      *float64
	QueryDiskReadCoveragePercent *float64
	Thresholds                   *model.QueryRoleThresholds
	TopDigests                   []model.QueryDigestStats
	TopDigestsByDiskRead         []model.QueryDigestStats
	Victims                      map[string]int
	Accounting                   map[string]string

	// PostgreSQL only.
	Cluster       string
	ServerPID     uint32 // the postmaster: family lookup when there is no digest
	DiskEstimated bool
	Backends      []BackendUsage
}

func fromMySQL(a *model.MySQLAnalysis) Report {
	return Report{
		WindowSeconds: a.WindowSeconds, Node: a.Node,
		QueryCPUCoveragePercent: a.QueryCPUCoveragePercent, QueryDiskReadCoveragePercent: a.QueryDiskReadCoveragePercent,
		Thresholds: a.Thresholds, TopDigests: a.TopDigests, TopDigestsByDiskRead: a.TopDigestsByDiskRead,
		Victims: a.Victims, Accounting: a.Accounting,
	}
}

// AssessEngine assesses one report of engine e (Assess is the MySQL case).
// bgPercent is background_dominant_percent (ignored unless e.Background).
func AssessEngine(e Engine, rep Report, in Inputs, th Thresholds, bgPercent float64, now time.Time) *model.QueryOverload {
	cpu := assessCPU(e, &rep, in, th, bgPercent, now)
	disk := assessDisk(e, &rep, in, bgPercent, now)
	cpuSat, diskSat := cpu.Checks[0].Passed, disk.Checks[0].Passed
	switch {
	case cpuSat && diskSat:
		primary, secondary := cpu, disk
		if preferDisk(cpu, disk) {
			primary, secondary = disk, cpu
		}
		primary.Secondary = secondary
		return primary
	case diskSat:
		return disk
	default:
		return cpu
	}
}

// PickCluster chooses the reported assessment among PostgreSQL clusters: a
// query_*_overload verdict first, then background_overload, then a saturated
// node, then the larger culprit share; the others go to OtherClusters. The
// inputs are not modified.
func PickCluster(results []*model.QueryOverload) *model.QueryOverload {
	var rs []*model.QueryOverload
	for _, r := range results {
		if r != nil {
			rs = append(rs, r)
		}
	}
	if len(rs) == 0 {
		return nil
	}
	rank := func(r *model.QueryOverload) int {
		switch {
		case isOverload(r.Verdict):
			return 0
		case r.Verdict == model.OverloadBackground:
			return 1
		case len(r.Checks) > 0 && r.Checks[0].Passed:
			return 2
		}
		return 3
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if ri, rj := rank(rs[i]), rank(rs[j]); ri != rj {
			return ri < rj
		}
		return share(rs[i].Digest, rs[i].Resource == resourceDisk) > share(rs[j].Digest, rs[j].Resource == resourceDisk)
	})
	primary := *rs[0]
	primary.OtherClusters = nil
	for _, r := range rs[1:] {
		cp := *r
		cp.OtherClusters = nil
		primary.OtherClusters = append(primary.OtherClusters, &cp)
	}
	return &primary
}

// queryBackends are backend types whose work is attributed to digests (or is
// the postmaster itself): never a background verdict.
var queryBackends = map[string]bool{"client": true, "parallel_worker": true, "postmaster": true}

// dominantBackground returns the non-query backend type with the largest
// share of the cluster's CPU (or disk reads) when it reaches pct percent.
func dominantBackground(e Engine, rep *Report, disk bool, pct float64) (typ string, val, total float64, ok bool) {
	if !e.Background {
		return "", 0, 0, false
	}
	for _, b := range rep.Backends {
		v := b.CPUCores
		if disk {
			if b.DiskReadMBPerSec == nil {
				continue
			}
			v = *b.DiskReadMBPerSec
		}
		total += v
		if !queryBackends[b.Type] && v > val {
			typ, val = b.Type, v
		}
	}
	return typ, val, total, typ != "" && total > 0 && 100*val/total >= pct
}

func backgroundAdvice(typ string) string {
	switch typ {
	case "autovacuum":
		return "Autovacuum is doing the work: check table bloat (pg_stat_user_tables.n_dead_tup) and autovacuum_vacuum_cost_limit / autovacuum_max_workers; the autovacuum digests in top_digests name the tables."
	case "checkpointer":
		return "Checkpoints are doing the work: raise max_wal_size or checkpoint_timeout and check checkpoint_completion_target."
	case "io_worker":
		return "PostgreSQL I/O workers are reading for queries (io_method=worker): configure postgres.sql to see which digests' reads they serve."
	case "walsender":
		return "WAL senders are busy: check replication consumers and logical decoding."
	case "bgwriter":
		return "The background writer is flushing dirty buffers: check shared_buffers and bgwriter_lru_maxpages."
	case "walwriter":
		return "The WAL writer is busy: check the write rate and wal_writer_delay."
	}
	return fmt.Sprintf("Look at process_report for the %s processes.", typ)
}

// backgroundVerdict fills r for background_overload.
func backgroundVerdict(e Engine, r *model.QueryOverload, prefix, family, typ string, val, total float64, disk bool) {
	ev := &r.Evidence
	r.Verdict, r.Confidence = model.OverloadBackground, model.ConfidenceHigh
	ev.BackgroundType = typ
	pct := 100 * val / total
	if disk {
		ev.BackgroundDiskReadMBPerSec, ev.ClusterDiskReadMBPerSec = floatp(val), floatp(total)
		r.Summary = fmt.Sprintf("%s; no query dominates its reads: %s backends read %.1f of the cluster's %.1f MB/s (%.0f%%), and %s is the top disk reader. %s",
			prefix, typ, val, total, pct, family, backgroundAdvice(typ))
		return
	}
	ev.BackgroundCPUCores, ev.ClusterCPUCores = floatp(val), floatp(total)
	r.Summary = fmt.Sprintf("%s; no query dominates it: %s backends use %.1f of the cluster's %.1f cores (%.0f%%), and %s is the top CPU consumer. %s",
		prefix, typ, val, total, pct, family, backgroundAdvice(typ))
}

// familyCPU: pid's family, its CPU%, the top CPU family; known when both exist.
func familyCPU(in Inputs, pid uint32) (fam string, famCPU float64, top model.FamilyStats, known bool) {
	fam = in.PIDFamilies[pid]
	if fam == "" || len(in.Families) == 0 {
		return "", 0, model.FamilyStats{}, false
	}
	top = in.Families[0]
	for _, f := range in.Families {
		if f.Family == fam {
			famCPU = f.CPUPercent
			break
		}
	}
	return fam, famCPU, top, true
}

// familyDisk: pid's family read MB/s and the top disk-reading family; known
// only when some family has measured reads (process.include_io).
func familyDisk(in Inputs, pid uint32) (fam string, famRead float64, top model.FamilyStats, topRead float64, known bool) {
	fam = in.PIDFamilies[pid]
	if fam == "" {
		return "", 0, model.FamilyStats{}, 0, false
	}
	for _, f := range in.Families {
		if f.ReadBytesPerSec > top.ReadBytesPerSec {
			top = f
		}
		if f.Family == fam {
			famRead = f.ReadBytesPerSec / (1 << 20)
		}
	}
	if top.ReadBytesPerSec <= 0 {
		return fam, 0, model.FamilyStats{}, 0, false
	}
	return fam, famRead, top, top.ReadBytesPerSec / (1 << 20), true
}

// innodbPagesAdvice reads disk_read_pages_per_call (16 KiB pages).
func innodbPagesAdvice(v *float64) string {
	switch {
	case v == nil:
		return ""
	case *v <= 4:
		return ": reads look like buffer-pool misses — consider a larger innodb_buffer_pool_size"
	case *v >= 100:
		return ": reads look like a scan — EXPLAIN it, add an index or a LIMIT"
	}
	return ""
}

// pgPagesAdvice reads disk_read_pages_per_call (8 KiB pages).
func pgPagesAdvice(v *float64) string {
	switch {
	case v == nil:
		return ""
	case *v <= 4:
		return ": reads look like cache misses — consider more RAM or a larger shared_buffers"
	case *v >= 100:
		return ": reads look like a scan — EXPLAIN (ANALYZE, BUFFERS) it, add an index or a LIMIT"
	}
	return ""
}
