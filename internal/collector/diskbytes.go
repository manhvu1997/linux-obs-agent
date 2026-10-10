package collector

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// NodeDiskBytes is the cumulative bytes read and written by the node's
// physical disks since boot.
type NodeDiskBytes struct {
	ReadBytes, WriteBytes uint64
	Disks                 int
}

const sysBlock = "/sys/block"

// ReadNodeDiskBytes sums /proc/diskstats over physical disks only: stacked
// (dm, md) and virtual (loop, zram, …) devices report the same I/O again.
func ReadNodeDiskBytes() (NodeDiskBytes, error) {
	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return NodeDiskBytes{}, fmt.Errorf("reading /proc/diskstats: %w", err)
	}
	defer f.Close()
	return sumPhysicalDiskBytes(sysBlock, f)
}

func sumPhysicalDiskBytes(sys string, diskstats io.Reader) (NodeDiskBytes, error) {
	var out NodeDiskBytes
	sc := bufio.NewScanner(diskstats)
	for sc.Scan() {
		var s rawDiskStat
		if _, err := fmt.Sscanf(sc.Text(), "%d %d %s %d %d %d %d %d %d %d",
			&s.major, &s.minor, &s.name, &s.readIOs, &s.readMerges, &s.readSectors, &s.readTicks,
			&s.writeIOs, &s.writeMerges, &s.writeSectors); err != nil {
			continue
		}
		if !physicalDisk(sys, s.name) {
			continue
		}
		out.ReadBytes += s.readSectors * 512
		out.WriteBytes += s.writeSectors * 512
		out.Disks++
	}
	return out, sc.Err()
}

var (
	virtualDisk   = regexp.MustCompile(`^(loop|ram|zram|sr|fd|nbd)[0-9]+$`)
	namedPhysical = regexp.MustCompile(`^((sd|vd|xvd|hd)[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)$`)
)

// physicalDisk: a whole device under sys (/sys/block) with no slaves that is
// not virtual. Partitions are not listed under /sys/block. Without sysfs,
// fall back to the common whole-disk names.
func physicalDisk(sys, dev string) bool {
	if virtualDisk.MatchString(dev) || strings.ContainsRune(dev, '/') {
		return false
	}
	if _, err := os.Stat(sys); err != nil {
		return namedPhysical.MatchString(dev)
	}
	ents, err := os.ReadDir(filepath.Join(sys, dev, "slaves"))
	if err != nil {
		return false // not a whole device (a partition), or no slaves dir
	}
	return len(ents) == 0
}
