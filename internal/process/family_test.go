package process

import (
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func TestFamilyKey(t *testing.T) {
	cases := []struct{ name, in, mode, want string }{
		{"v2 service", "0::/system.slice/mysql.service\n", FamilyBySystemdUnit, "mysql.service"},
		{"v2 session scope", "0::/user.slice/user-1000.slice/session-42.scope\n", FamilyBySystemdUnit, "session-42.scope"},
		{"service wins over nested scope", "0::/system.slice/php-fpm.service/init.scope\n", FamilyBySystemdUnit, "php-fpm.service"},
		{"kubepods scope", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podx.slice/cri-containerd-abc.scope\n",
			FamilyBySystemdUnit, "cri-containerd-abc.scope"},
		{"kernel thread root", "0::/\n", FamilyBySystemdUnit, "/"},
		{"v1 uses name=systemd", "12:cpu,cpuacct:/\n1:name=systemd:/system.slice/nginx.service\n", FamilyBySystemdUnit, "nginx.service"},
		{"hybrid prefers unified", "1:name=systemd:/system.slice/a.service\n0::/system.slice/a.service\n", FamilyBySystemdUnit, "a.service"},
		{"no unit falls back to path", "0::/custom/group\n", FamilyBySystemdUnit, "/custom/group"},
		{"cgroup mode", "0::/system.slice/mysql.service\n", FamilyByCgroup, "/system.slice/mysql.service"},
		{"unreadable", "", FamilyBySystemdUnit, UnknownFamily},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FamilyKey(c.in, c.mode); got != c.want {
				t.Fatalf("FamilyKey = %q, want %q", got, c.want)
			}
		})
	}
}

func TestBuildFamilies(t *testing.T) {
	procs := []model.ProcessStats{
		{PID: 1022, Comm: "php-fpm", Cmdline: "php-fpm: master process", Family: "php-fpm.service", StartTime: 100, CPUPercent: 1, MemRSSBytes: 10, MemPercent: 0.1},
		{PID: 1301, Comm: "php-fpm", Cmdline: "php-fpm: pool www", Family: "php-fpm.service", StartTime: 200, CPUPercent: 30, MemRSSBytes: 80, MemPercent: 0.8},
		{PID: 1302, Comm: "php-fpm", Cmdline: "php-fpm: pool www", Family: "php-fpm.service", StartTime: 201, CPUPercent: 33, MemRSSBytes: 90, MemPercent: 0.9},
		{PID: 2314, Comm: "mysqld", Cmdline: "/usr/sbin/mysqld", Family: "mysql.service", StartTime: 50, CPUPercent: 87, MemRSSBytes: 6000, MemPercent: 60},
		{PID: 7, Comm: "kworker/0:1", Cmdline: "", Family: "/", StartTime: 1},
	}
	fams := BuildFamilies(procs, 2)
	if len(fams) != 3 {
		t.Fatalf("want 3 families, got %d", len(fams))
	}
	var php model.FamilyStats
	for _, f := range fams {
		if f.Family == "php-fpm.service" {
			php = f
		}
		if f.Family == "/" && f.RootCmdline != "[kworker/0:1]" {
			t.Fatalf("kernel thread root cmdline = %q", f.RootCmdline)
		}
	}
	if php.ProcessCount != 3 || php.CPUPercent != 64 || php.MemRSSBytes != 180 {
		t.Fatalf("php totals wrong: %+v", php)
	}
	if php.RootPID != 1022 || php.RootCmdline != "php-fpm: master process" {
		t.Fatalf("root should be oldest process: %+v", php)
	}
	if len(php.TopMembers) != 2 || php.TopMembers[0].PID != 1302 || php.TopMembers[1].PID != 1301 {
		t.Fatalf("top members by CPU wrong: %+v", php.TopMembers)
	}
}
