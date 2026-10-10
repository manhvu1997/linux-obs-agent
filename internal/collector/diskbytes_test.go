package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSys builds /sys/block/<dev>/slaves for each dev; slaves[dev] lists its members.
func fakeSys(t *testing.T, devs []string, slaves map[string][]string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range devs {
		dir := filepath.Join(root, d, "slaves")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, s := range slaves[d] {
			if err := os.WriteFile(filepath.Join(dir, s), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func TestPhysicalDisks(t *testing.T) {
	sys := fakeSys(t, []string{"sda", "nvme0n1", "dm-0", "md0", "loop0", "zram0", "sr0"},
		map[string][]string{"dm-0": {"sda2"}, "md0": {"sda3", "nvme0n1p1"}})
	for dev, want := range map[string]bool{
		"sda": true, "nvme0n1": true, // whole disks
		"sda2": false, "nvme0n1p1": false, // partitions: not under /sys/block
		"dm-0": false, "md0": false, // stacked on other devices
		"loop0": false, "zram0": false, "sr0": false, // virtual / optical
	} {
		if got := physicalDisk(sys, dev); got != want {
			t.Errorf("physicalDisk(%q) = %v, want %v", dev, got, want)
		}
	}
}

func TestPhysicalDisksWithoutSysfs(t *testing.T) {
	sys := filepath.Join(t.TempDir(), "missing")
	for dev, want := range map[string]bool{
		"sda": true, "vdb": true, "xvda": true, "nvme0n1": true, "mmcblk0": true,
		"sda1": false, "nvme0n1p1": false, "dm-0": false, "md0": false, "loop0": false,
	} {
		if got := physicalDisk(sys, dev); got != want {
			t.Errorf("no sysfs: physicalDisk(%q) = %v, want %v", dev, got, want)
		}
	}
}

func TestSumPhysicalDiskBytes(t *testing.T) {
	sys := fakeSys(t, []string{"sda", "dm-0"}, map[string][]string{"dm-0": {"sda1"}})
	stats := strings.NewReader(
		"   8       0 sda 100 0 2000 0 50 0 4000 0 0 0 0\n" +
			"   8       1 sda1 90 0 1800 0 40 0 3000 0 0 0 0\n" +
			" 253       0 dm-0 90 0 1800 0 40 0 3000 0 0 0 0\n")
	got, err := sumPhysicalDiskBytes(sys, stats)
	if err != nil || got.ReadBytes != 2000*512 || got.WriteBytes != 4000*512 || got.Disks != 1 {
		t.Fatalf("got %+v, %v; want sda only (1024000 / 2048000, 1 disk)", got, err)
	}
}
