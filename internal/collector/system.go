package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// ─── Memory ──────────────────────────────────────────────────────────────────

// MemCollector reads /proc/meminfo.
type MemCollector struct{}

func NewMemCollector() *MemCollector { return &MemCollector{} }

func (m *MemCollector) Collect() (model.MemMetrics, error) {
	fields, err := readKeyValueKB("/proc/meminfo")
	if err != nil {
		return model.MemMetrics{}, fmt.Errorf("reading /proc/meminfo: %w", err)
	}

	kb := func(key string) uint64 { return fields[key] * 1024 }

	total := kb("MemTotal")
	free := kb("MemFree")
	buffers := kb("Buffers")
	cached := kb("Cached")
	available := kb("MemAvailable")
	used := total - free - buffers - cached

	swapTotal := kb("SwapTotal")
	swapFree := kb("SwapFree")
	swapUsed := swapTotal - swapFree

	var usagePct, swapPct float64
	if total > 0 {
		usagePct = 100 * float64(used) / float64(total)
	}
	if swapTotal > 0 {
		swapPct = 100 * float64(swapUsed) / float64(swapTotal)
	}

	return model.MemMetrics{
		TotalBytes:     total,
		UsedBytes:      used,
		FreeBytes:      free,
		BuffersBytes:   buffers,
		CachedBytes:    cached,
		AvailableBytes: available,
		UsagePercent:   usagePct,
		SwapTotalBytes: swapTotal,
		SwapUsedBytes:  swapUsed,
		SwapPercent:    swapPct,
		SlabBytes:      kb("Slab"),
	}, nil
}

// readKeyValueKB parses "Key: value kB" style files like /proc/meminfo.
func readKeyValueKB(path string) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := make(map[string]uint64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valStr := strings.Fields(strings.TrimSpace(parts[1]))[0]
		val, _ := strconv.ParseUint(valStr, 10, 64)
		m[key] = val
	}
	return m, sc.Err()
}

// ─── Disk ─────────────────────────────────────────────────────────────────────

// rawDiskStat is one line of /proc/diskstats.
type rawDiskStat struct {
	major, minor                        uint32
	name                                string
	readIOs, readMerges, readSectors    uint64
	readTicks                           uint64
	writeIOs, writeMerges, writeSectors uint64
	writeTicks                          uint64
	inFlight, ioTicks, timeInQueue      uint64
}

// DiskCollector computes rate-based disk metrics.
type DiskCollector struct {
	allowList map[string]bool
	prev      map[string]rawDiskStat
	prevTime  time.Time
}

func NewDiskCollector(devices []string) *DiskCollector {
	allow := make(map[string]bool, len(devices))
	for _, d := range devices {
		allow[d] = true
	}
	return &DiskCollector{allowList: allow, prev: make(map[string]rawDiskStat)}
}

func (d *DiskCollector) Collect() ([]model.DiskMetrics, error) {
	stats, err := readDiskStats()
	if err != nil {
		return nil, fmt.Errorf("reading /proc/diskstats: %w", err)
	}

	now := time.Now()
	elapsed := now.Sub(d.prevTime).Seconds()
	if d.prevTime.IsZero() {
		elapsed = 0
	}

	var result []model.DiskMetrics
	for dev, cur := range stats {
		if len(d.allowList) > 0 && !d.allowList[dev] {
			continue
		}
		// Skip partitions (sda1, nvme0n1p1, …)
		if isPartition(dev) {
			continue
		}

		m := model.DiskMetrics{
			Device:     dev,
			ReadBytes:  cur.readSectors * 512,
			WriteBytes: cur.writeSectors * 512,
			ReadOps:    cur.readIOs,
			WriteOps:   cur.writeIOs,
		}

		if prev, ok := d.prev[dev]; ok && elapsed > 0 {
			readBytesDelta := float64(cur.readSectors-prev.readSectors) * 512
			writeBytesDelta := float64(cur.writeSectors-prev.writeSectors) * 512
			readOpsDelta := float64(cur.readIOs - prev.readIOs)
			writeOpsDelta := float64(cur.writeIOs - prev.writeIOs)
			ioTicksDelta := float64(cur.ioTicks - prev.ioTicks)

			m.ReadBytesPerSec = readBytesDelta / elapsed
			m.WriteBytesPerSec = writeBytesDelta / elapsed
			m.ReadOpsPerSec = readOpsDelta / elapsed
			m.WriteOpsPerSec = writeOpsDelta / elapsed
			m.IOUtilPercent = 100 * ioTicksDelta / (elapsed * 1000)
			if m.IOUtilPercent > 100 {
				m.IOUtilPercent = 100
			}

			totalOps := readOpsDelta + writeOpsDelta
			if totalOps > 0 {
				waitTicks := float64(cur.readTicks + cur.writeTicks - prev.readTicks - prev.writeTicks)
				m.AvgWaitMs = waitTicks / totalOps
			}
		}

		result = append(result, m)
		d.prev[dev] = cur
	}
	d.prevTime = now
	return result, nil
}

func readDiskStats() (map[string]rawDiskStat, error) {
	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := make(map[string]rawDiskStat)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var s rawDiskStat
		_, err := fmt.Sscanf(sc.Text(),
			"%d %d %s %d %d %d %d %d %d %d %d %d %d %d",
			&s.major, &s.minor, &s.name,
			&s.readIOs, &s.readMerges, &s.readSectors, &s.readTicks,
			&s.writeIOs, &s.writeMerges, &s.writeSectors, &s.writeTicks,
			&s.inFlight, &s.ioTicks, &s.timeInQueue,
		)
		if err == nil {
			m[s.name] = s
		}
	}
	return m, sc.Err()
}

// isPartition returns true for sda1, nvme0n1p2-style names.
func isPartition(dev string) bool {
	base := filepath.Base(dev)
	if len(base) == 0 {
		return false
	}
	last := base[len(base)-1]
	return last >= '0' && last <= '9' && strings.ContainsAny(base, "0123456789")
}

// ─── Network ──────────────────────────────────────────────────────────────────

type rawNetStat struct {
	rxBytes, txBytes uint64
	rxPkts, txPkts   uint64
	rxErr, txErr     uint64
	rxDrop, txDrop   uint64
}

// NetCollector computes rate-based network metrics from /proc/net/dev.
type NetCollector struct {
	allowList map[string]bool
	prev      map[string]rawNetStat
	prevTime  time.Time
}

func NewNetCollector(ifaces []string) *NetCollector {
	allow := make(map[string]bool, len(ifaces))
	for _, i := range ifaces {
		allow[i] = true
	}
	return &NetCollector{allowList: allow, prev: make(map[string]rawNetStat)}
}

func (n *NetCollector) Collect() ([]model.NetMetrics, error) {
	stats, err := readNetDev()
	if err != nil {
		return nil, fmt.Errorf("reading /proc/net/dev: %w", err)
	}

	now := time.Now()
	elapsed := now.Sub(n.prevTime).Seconds()
	if n.prevTime.IsZero() {
		elapsed = 0
	}

	var result []model.NetMetrics
	for iface, cur := range stats {
		if iface == "lo" {
			continue
		}
		if len(n.allowList) > 0 && !n.allowList[iface] {
			continue
		}

		m := model.NetMetrics{
			Interface: iface,
			RxBytes:   cur.rxBytes,
			TxBytes:   cur.txBytes,
			RxPackets: cur.rxPkts,
			TxPackets: cur.txPkts,
			RxErrors:  cur.rxErr,
			TxErrors:  cur.txErr,
			RxDropped: cur.rxDrop,
			TxDropped: cur.txDrop,
		}

		if prev, ok := n.prev[iface]; ok && elapsed > 0 {
			m.RxBytesPerSec = float64(cur.rxBytes-prev.rxBytes) / elapsed
			m.TxBytesPerSec = float64(cur.txBytes-prev.txBytes) / elapsed
		}

		result = append(result, m)
		n.prev[iface] = cur
	}
	n.prevTime = now
	return result, nil
}

func readNetDev() (map[string]rawNetStat, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := make(map[string]rawNetStat)
	sc := bufio.NewScanner(f)
	// Skip header lines.
	sc.Scan()
	sc.Scan()
	for sc.Scan() {
		line := sc.Text()
		// Format: "  eth0:  1234 ..."
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colonIdx])
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 16 {
			continue
		}
		p := func(i int) uint64 {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			return v
		}
		m[iface] = rawNetStat{
			rxBytes: p(0), rxPkts: p(1), rxErr: p(2), rxDrop: p(3),
			txBytes: p(8), txPkts: p(9), txErr: p(10), txDrop: p(11),
		}
	}
	return m, sc.Err()
}

// ─── Load Average ─────────────────────────────────────────────────────────────

// ReadLoadAvg reads /proc/loadavg.
func ReadLoadAvg() (model.LoadMetrics, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return model.LoadMetrics{}, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return model.LoadMetrics{}, fmt.Errorf("unexpected /proc/loadavg format")
	}
	parse := func(s string) float64 {
		v, _ := strconv.ParseFloat(s, 64)
		return v
	}
	return model.LoadMetrics{
		Load1:  parse(fields[0]),
		Load5:  parse(fields[1]),
		Load15: parse(fields[2]),
	}, nil
}
