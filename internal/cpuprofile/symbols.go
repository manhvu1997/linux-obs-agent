package cpuprofile

import "time"

// Exported symbolization entry points.
//
// These wrap the package-internal resolvers so other report builders (notably
// internal/offcpu) share this package's kallsyms and per-PID ELF caches rather
// than building their own — the caches are the expensive part, not the lookup.

// ResolveKernel maps a kernel instruction pointer to a symbol name.
// Returns "" when the address cannot be resolved.
func ResolveKernel(addr uint64) string { return resolveKernel(addr) }

// ResolveUser maps a userspace instruction pointer in process tgid to a symbol
// name, using /proc/<tgid>/maps plus the ELF symbol tables of the mapped files.
// Returns "" when the address cannot be resolved.
func ResolveUser(tgid uint32, addr uint64) string { return resolveUser(tgid, addr) }

// PurgeUserCache evicts per-PID user symbol caches older than maxAge.
// Report builders should call this once per report to bound memory.
func PurgeUserCache(maxAge time.Duration) { purgeUserCache(maxAge) }
