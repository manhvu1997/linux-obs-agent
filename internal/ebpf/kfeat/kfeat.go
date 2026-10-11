package kfeat

import "github.com/cilium/ebpf/btf"

// StructHas reports whether the member path (each element a member of the
// previous member's struct type) exists in t. Typedefs and qualifiers are
// looked through; a pointer member ends the path (it exists).
func StructHas(t btf.Type, path ...string) bool {
	for _, name := range path {
		s, ok := btf.UnderlyingType(t).(*btf.Struct)
		if !ok {
			return false
		}
		found := false
		for _, m := range s.Members {
			if m.Name == name {
				t, found = m.Type, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// TaskFields reports which optional task_struct fields the running
// kernel has (kernel BTF). Errors read as "absent".
func TaskFields() (ioac, delays bool) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false, false
	}
	t, err := spec.AnyTypeByName("task_struct")
	if err != nil {
		return false, false
	}
	return StructHas(t, "ioac", "read_bytes") && StructHas(t, "ioac", "write_bytes"), StructHas(t, "delays")
}
