package postgres

import (
	"strings"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Backend types reported in cpu_by_backend_type / disk_read_by_backend_type.
const (
	BackendClient       = "client"
	BackendParallel     = "parallel_worker"
	BackendAutovacuum   = "autovacuum"
	BackendCheckpointer = "checkpointer"
	BackendBgwriter     = "bgwriter"
	BackendWalwriter    = "walwriter"
	BackendWalsender    = "walsender"
	BackendWalreceiver  = "walreceiver"
	BackendIOWorker     = "io_worker"
	BackendArchiver     = "archiver"
	BackendLogical      = "logical_replication"
	BackendPostmaster   = "postmaster"
	BackendOther        = "other"
)

// titlePrefixes map the start of a process title (after "postgres: " and an
// optional "<cluster_name>: ") to a backend type. PostgreSQL 16–19 titles.
var titlePrefixes = []struct{ prefix, typ string }{
	{"checkpointer", BackendCheckpointer},
	{"background writer", BackendBgwriter},
	{"walwriter", BackendWalwriter},
	{"autovacuum launcher", BackendAutovacuum},
	{"autovacuum worker", BackendAutovacuum},
	{"walsender", BackendWalsender},
	{"walreceiver", BackendWalreceiver},
	{"archiver", BackendArchiver},
	{"io worker", BackendIOWorker},
	{"parallel worker for PID", BackendParallel},
	{"logical replication", BackendLogical},
	{"startup", BackendOther},
	{"walsummarizer", BackendOther},
	{"slotsync worker", BackendOther},
	{"stats collector", BackendOther},
}

// BackendType classifies a postgres process title. A title that names no
// known type is a client backend when it looks like "user db host state"
// (at least three fields), else other.
func BackendType(cmdline string) string {
	rest, ok := strings.CutPrefix(cmdline, "postgres: ")
	if !ok {
		return BackendOther
	}
	if t, ok := matchTitle(rest); ok {
		return t
	}
	if i := strings.Index(rest, ": "); i >= 0 { // strip "<cluster_name>: "
		rest = rest[i+2:]
		if t, ok := matchTitle(rest); ok {
			return t
		}
	}
	if len(strings.Fields(rest)) >= 3 {
		return BackendClient
	}
	return BackendOther
}

func matchTitle(s string) (string, bool) {
	for _, p := range titlePrefixes {
		if strings.HasPrefix(s, p.prefix) {
			return p.typ, true
		}
	}
	return "", false
}

// usage is one scan's totals for one backend type of one cluster.
type usage struct {
	cores, readMBps, writeMBps float64
	procs                      int
}

type scan struct {
	at   time.Time
	byPM map[uint32]map[string]usage
}

// BackendLife are lifetime counters per type (Prometheus), integrated from
// the scans.
type BackendLife struct {
	CPUSeconds float64
	ReadBytes  float64
}

// backendAcc folds the scans between ClickHouse drains.
type backendAcc struct {
	cpuNs, readBytes, writeBytes float64
	procsMax                     int
}

// BackendSampler turns process-inspector scans into per-cluster, per-type
// CPU and storage reads over the digest window. Safe for concurrent use.
type BackendSampler struct {
	mu         sync.Mutex
	window     time.Duration
	ioMeasured bool
	scans      []scan
	lastAt     time.Time
	life       map[uint32]map[string]*BackendLife
	drainOn    bool
	drain      map[uint32]map[string]*backendAcc
}

// NewBackendSampler: ioMeasured is process.include_io (read rates are 0
// otherwise and must not be reported).
func NewBackendSampler(window time.Duration, ioMeasured bool) *BackendSampler {
	return &BackendSampler{window: window, ioMeasured: ioMeasured,
		life: map[uint32]map[string]*BackendLife{}, drain: map[uint32]map[string]*backendAcc{}}
}

// Observe folds one inspector scan. postmasters is the set of traced
// postmaster PIDs; numCPU converts CPU% (of all CPUs) to cores.
func (b *BackendSampler) Observe(all []model.ProcessStats, postmasters map[uint32]bool, numCPU int, at time.Time) {
	byPM := map[uint32]map[string]usage{}
	for _, p := range all {
		pm, typ := uint32(0), ""
		switch {
		case postmasters[p.PID]:
			pm, typ = p.PID, BackendPostmaster
		case postmasters[p.PPID]:
			pm, typ = p.PPID, BackendType(p.Cmdline)
		default:
			continue
		}
		m := byPM[pm]
		if m == nil {
			m = map[string]usage{}
			byPM[pm] = m
		}
		u := m[typ]
		u.cores += p.CPUPercent / 100 * float64(numCPU)
		u.readMBps += p.ReadBytesPerSec / (1 << 20)
		u.writeMBps += p.WriteBytesPerSec / (1 << 20)
		u.procs++
		m[typ] = u
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.lastAt.IsZero() && at.After(b.lastAt) {
		dt := at.Sub(b.lastAt).Seconds()
		for pm, m := range byPM {
			for typ, u := range m {
				l := b.lifeFor(pm, typ)
				l.CPUSeconds += u.cores * dt
				l.ReadBytes += u.readMBps * (1 << 20) * dt
				if b.drainOn {
					a := b.accFor(pm, typ)
					a.cpuNs += u.cores * dt * 1e9
					a.readBytes += u.readMBps * (1 << 20) * dt
					a.writeBytes += u.writeMBps * (1 << 20) * dt
					a.procsMax = max(a.procsMax, u.procs)
				}
			}
		}
	}
	b.lastAt = at
	b.scans = append(b.scans, scan{at: at, byPM: byPM})
	cut := at.Add(-b.window)
	i := 0
	for i < len(b.scans) && !b.scans[i].at.After(cut) {
		i++
	}
	b.scans = b.scans[i:]
}

func (b *BackendSampler) lifeFor(pm uint32, typ string) *BackendLife {
	m := b.life[pm]
	if m == nil {
		m = map[string]*BackendLife{}
		b.life[pm] = m
	}
	l := m[typ]
	if l == nil {
		l = &BackendLife{}
		m[typ] = l
	}
	return l
}

func (b *BackendSampler) accFor(pm uint32, typ string) *backendAcc {
	m := b.drain[pm]
	if m == nil {
		m = map[string]*backendAcc{}
		b.drain[pm] = m
	}
	a := m[typ]
	if a == nil {
		a = &backendAcc{}
		m[typ] = a
	}
	return a
}

// Window returns the average cores and storage read MB/s per type of one
// cluster over the scans in the window; reads is nil when not measured.
func (b *BackendSampler) Window(pm uint32) (cores, reads map[string]float64, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	cores = map[string]float64{}
	if b.ioMeasured {
		reads = map[string]float64{}
	}
	for _, s := range b.scans {
		m, found := s.byPM[pm]
		if !found {
			continue
		}
		n++
		for typ, u := range m {
			cores[typ] += u.cores
			if reads != nil {
				reads[typ] += u.readMBps
			}
		}
	}
	if n == 0 {
		return nil, nil, false
	}
	for typ := range cores {
		cores[typ] /= float64(n)
		if reads != nil {
			reads[typ] /= float64(n)
		}
	}
	return cores, reads, true
}

// Life returns a copy of one cluster's lifetime counters per type.
func (b *BackendSampler) Life(pm uint32) map[string]BackendLife {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]BackendLife{}
	for typ, l := range b.life[pm] {
		out[typ] = *l
	}
	return out
}

// Forget drops a postmaster that is gone.
func (b *BackendSampler) Forget(pm uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.life, pm)
	delete(b.drain, pm)
}

// EnableDrain starts folding scans for DrainBackends.
func (b *BackendSampler) EnableDrain() {
	b.mu.Lock()
	b.drainOn = true
	b.mu.Unlock()
}

// BackendDelta is one type's totals since the previous drain.
type BackendDelta struct {
	Postmaster            uint32
	Type                  string
	CPUNs                 uint64
	ReadBytes, WriteBytes uint64
	IOMeasured            bool
	ProcessesMax          int
}

// DrainBackends returns the totals since the previous call and resets them.
func (b *BackendSampler) DrainBackends() []BackendDelta {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []BackendDelta
	for pm, m := range b.drain {
		for typ, a := range m {
			out = append(out, BackendDelta{Postmaster: pm, Type: typ, CPUNs: uint64(a.cpuNs),
				ReadBytes: uint64(a.readBytes), WriteBytes: uint64(a.writeBytes), IOMeasured: b.ioMeasured, ProcessesMax: a.procsMax})
		}
	}
	b.drain = map[uint32]map[string]*backendAcc{}
	return out
}
