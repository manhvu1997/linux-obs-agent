package mysql_query

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestStructHas(t *testing.T) {
	u64 := &btf.Int{Name: "u64", Size: 8}
	ioac := &btf.Struct{Name: "task_io_accounting", Size: 16, Members: []btf.Member{{Name: "rchar", Type: u64}, {Name: "read_bytes", Type: u64}}}
	task := &btf.Struct{Name: "task_struct", Members: []btf.Member{
		{Name: "ioac", Type: &btf.Typedef{Name: "ioac_t", Type: ioac}},
		{Name: "delays", Type: &btf.Pointer{Target: &btf.Struct{Name: "task_delay_info"}}},
	}}
	for _, c := range []struct {
		path []string
		want bool
	}{
		{[]string{"ioac", "read_bytes"}, true},
		{[]string{"ioac", "write_bytes"}, false},
		{[]string{"delays"}, true},
		{[]string{"sched_info"}, false},
	} {
		if got := structHas(task, c.path...); got != c.want {
			t.Errorf("structHas(task_struct, %v) = %v, want %v", c.path, got, c.want)
		}
	}
}
