# linux-obs-agent – Build & Runtime Failure Log

All errors encountered during the Docker build pipeline and Go compilation,
with root cause and the fix applied.

---

## 1. `bpftool: not found`

**Stage:** `docker build` – vmlinux.h generation step
**Error:**
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./internal/ebpf/headers/vmlinux.h
/bin/sh: 1: bpftool: not found
```
**Root cause:** `bpftool` is a virtual Debian package. The real binary is
installed by `linux-tools-generic` and lives at
`/usr/lib/linux-tools/<kernel-version>/bpftool` – not on `PATH`.
**Fix (`deploy/Dockerfile`):**
```dockerfile
RUN apt-get install -y linux-tools-generic linux-image-generic && \
    ln -s $(find /usr/lib/linux-tools -name bpftool | head -1) /usr/local/bin/bpftool
```

---

## 2. `/sys/kernel/btf/vmlinux` inaccessible during `docker build`

**Stage:** `docker build` – vmlinux.h generation
**Error:** `bpftool` ran but produced an empty / zero-byte `vmlinux.h`
because `/sys/kernel/btf/vmlinux` is a pseudo-file that requires a live
kernel and is not available inside a build container.
**Root cause:** `docker build` does not expose the host kernel's BTF sysfs.
**Fix (`deploy/Dockerfile`):** Dual-fallback strategy – try host BTF first,
fall back to BTF embedded in the installed `vmlinuz` kernel image:
```dockerfile
RUN mkdir -p internal/ebpf/headers && \
    VMLINUZ=$(ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1) && \
    { [ -f /sys/kernel/btf/vmlinux ] && \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c \
        > internal/ebpf/headers/vmlinux.h 2>/dev/null; } || \
    { [ -n "$VMLINUZ" ] && \
        bpftool btf dump file "$VMLINUZ" format c \
        > internal/ebpf/headers/vmlinux.h 2>/dev/null; } || \
    echo "Warning: bpftool vmlinux generation failed – using pre-built headers"
```

---

## 3. `redefinition of 'io_event'`

**Stage:** clang compilation of `io_latency.bpf.c`
**Error:**
```
internal/ebpf/io_latency/io_latency.bpf.c:XX:8: error: redefinition of 'io_event'
8 errors generated.
```
**Root cause:** `vmlinux.h` already defines `struct io_event` (Linux AIO
subsystem, line ~54396). The custom eBPF struct used the same name.
**Fix (`internal/ebpf/io_latency/io_latency.bpf.c`):**
Renamed `struct io_event` → `struct io_lat_event` throughout the C file.
**Fix (`internal/ebpf/io_latency/gen.go`):**
Updated bpf2go `-type` flag: `-type io_event` → `-type io_lat_event`.

---

## 4. `collect C types: not found` (runqlat, tcp_retransmit, cpu_profile)

**Stage:** `go generate` / bpf2go type collection
**Error:**
```
collect C types: not found [runqlat / tcp_retransmit / cpu_profile]
```
**Root cause:** Types used only as arguments to `bpf_ringbuf_reserve()`
(which returns `void *`) are NOT automatically emitted into the BPF program's
BTF section. bpf2go therefore cannot find the type to generate Go bindings.
**Fix:** Add a dummy global pointer in each `.bpf.c` file to force BTF
emission:
```c
// io_latency.bpf.c
struct io_lat_event *__io_lat_event_unused __attribute__((unused));

// runqlat.bpf.c
struct runq_event *__runq_event_unused __attribute__((unused));

// tcp_retransmit.bpf.c
struct retransmit_event *__retransmit_event_unused __attribute__((unused));

// cpu_profile.bpf.c
struct cpu_sample_event *__cpu_sample_event_unused __attribute__((unused));
```

---

## 5. Missing `go.sum` entries

**Stage:** `go build` inside Docker
**Error:**
```
missing go.sum entry for module providing package gopkg.in/yaml.v3
missing go.sum entry for module providing package github.com/prometheus/...
```
**Root cause:** `go.sum` was not committed / was incomplete. The Dockerfile
copied source files but did not regenerate the checksum database.
**Fix (`deploy/Dockerfile`):** Add `go mod tidy` after `COPY . .` and
before `make generate`:
```dockerfile
COPY . .
RUN go mod tidy
RUN make generate
```

---

## 6. `undefined: IoLatencyLoadOptions` / `undefined: ebpfLoadOptions`

**Stage:** `go build` – `internal/ebpf/io_latency/loader.go`
**Error:**
```
undefined: IoLatencyLoadOptions
```
**Root cause:** bpf2go v0.21.0 does not generate a public `XxxLoadOptions`
type. An older API pattern was referenced.
**Fix (`internal/ebpf/io_latency/loader.go`):**
Removed the `ebpfLoadOptions()` helper function and changed the call to:
```go
LoadIoLatencyObjects(&l.objs, nil)
```

---

## 7. `cannot use raw.Comm[:] (value of type []int8) as []byte`

**Stage:** `go build` – all four eBPF loader files
**Error:**
```
cannot use raw.Comm[:] (value of type []int8) as type []byte
```
**Root cause:** bpf2go maps C `char` arrays to Go `[N]int8`, not `[N]uint8`.
The `nullTermString` helper expected `[]byte`.
**Fix (all four loaders):** Changed `nullTermString` to accept `[]int8`:
```go
func nullTermString(b []int8) string {
    bs := make([]byte, 0, len(b))
    for _, v := range b {
        if v == 0 { break }
        bs = append(bs, byte(v))
    }
    return string(bs)
}
```

---

## 8. `undefined: link.AttachPerfEvent` / `undefined: link.PerfEventOptions`

**Stage:** `go build` – `internal/ebpf/cpu_profile/loader.go`
**Error:**
```
undefined: link.AttachPerfEvent
undefined: link.PerfEventOptions
```
**Root cause:** `link.AttachPerfEvent` and `link.PerfEventOptions` are
internal-only in cilium/ebpf v0.21.0 (exported only in later versions).
**Fix (`internal/ebpf/cpu_profile/loader.go`):**
Replaced with raw Linux ioctls:
```go
// Attach eBPF program to the perf event fd
unix.IoctlSetInt(int(fd), unix.PERF_EVENT_IOC_SET_BPF, l.objs.ProfileCpu.FD())
unix.IoctlSetInt(int(fd), unix.PERF_EVENT_IOC_ENABLE, 0)
l.perfFDs = append(l.perfFDs, int(fd))
```
Cleanup changed from closing `link.Link` objects to:
```go
unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
unix.Close(fd)
```

---

## 9. `undefined: loadXxxObjects` (lowercase `l`) for all four packages

**Stage:** `go build`
**Error:**
```
undefined: loadIoLatencyObjects
undefined: loadRunQLatObjects
undefined: loadCpuProfileObjects
undefined: loadTcpRetransmitObjects
```
**Root cause:** bpf2go generates `LoadXxxObjects` (uppercase `L`) when the
bpf2go program name is PascalCase. Calls were using lowercase `load`.
**Fix:** Changed all four calls to the uppercase form:
- `loadIoLatencyObjects` → `LoadIoLatencyObjects`
- `loadRunQLatObjects` → `LoadRunQLatObjects`
- `loadCpuProfileObjects` → `LoadCpuProfileObjects`
- `loadTcpRetransmitObjects` → `LoadTcpRetransmitObjects`

---

## 10. `l.links undefined` (cpu_profile loader)

**Stage:** `go build` – `internal/ebpf/cpu_profile/loader.go`
**Error:**
```
p.links undefined (type *Loader has no field or method links)
```
**Root cause:** When replacing `[]link.Link` with `[]int` (raw perf fds),
a log statement still referenced the old `l.links` field.
**Fix:** Updated the log line to use `l.perfFDs`:
```go
slog.Info("cpu_profile: started", "cpus", len(l.perfFDs), "hz", l.sampleHz)
```

---

## 11. `cannot use raw.Saddr[:4] (value of type []uint8) as []int8`

**Stage:** `go build` – `internal/ebpf/tcp_retransmit/loader.go`
**Error:**
```
cannot use raw.Saddr[:4] (value of type []uint8) as type []int8
```
**Root cause:** An `int8sToBytes` helper was added incorrectly. C `__u8`
arrays map to `[N]uint8` (not `int8`) in bpf2go. `net.IP` accepts `[]byte`
(`[]uint8`) directly.
**Fix:** Removed the `int8sToBytes` helper. Used the `uint8` slices directly:
```go
srcIP = net.IP(raw.Saddr[:4]).String()
dstIP = net.IP(raw.Daddr[:4]).String()
```

---

## 12. `IoLatencyIoEvent` type mismatch after rename

**Stage:** `go build` – `internal/ebpf/io_latency/loader.go`
**Error:**
```
undefined: IoLatencyIoEvent
```
**Root cause:** After renaming the C struct from `io_event` to `io_lat_event`,
bpf2go regenerated the Go type as `IoLatencyIoLatEvent`. The loader still
referenced the old name.
**Fix:** Updated the type reference:
```go
var raw IoLatencyIoLatEvent  // was: IoLatencyIoEvent
```

---

## Summary table

| # | File | Error | Fix |
|---|------|-------|-----|
| 1 | Dockerfile | `bpftool: not found` | Install `linux-tools-generic`, symlink binary |
| 2 | Dockerfile | vmlinux.h empty in container | Fallback to `/boot/vmlinuz-*` BTF source |
| 3 | io_latency.bpf.c | `redefinition of 'io_event'` | Rename to `io_lat_event` |
| 4 | *.bpf.c (×4) | `collect C types: not found` | Add dummy `struct Foo *__unused` globals |
| 5 | Dockerfile | Missing go.sum entries | Add `RUN go mod tidy` before `make generate` |
| 6 | io_latency/loader.go | `undefined: IoLatencyLoadOptions` | Remove helper, pass `nil` opts |
| 7 | all loaders (×4) | `[]int8` vs `[]byte` in nullTermString | Change signature to `[]int8` |
| 8 | cpu_profile/loader.go | `undefined: link.AttachPerfEvent` | Use raw `PERF_EVENT_IOC_*` ioctls |
| 9 | all loaders (×4) | `undefined: loadXxxObjects` | Capitalise → `LoadXxxObjects` |
| 10 | cpu_profile/loader.go | `l.links undefined` | Update log to `l.perfFDs` |
| 11 | tcp_retransmit/loader.go | `[]uint8` vs `[]int8` in Saddr/Daddr | Use `uint8` slice directly as `net.IP` |
| 12 | io_latency/loader.go | `undefined: IoLatencyIoEvent` | Update to `IoLatencyIoLatEvent` |
