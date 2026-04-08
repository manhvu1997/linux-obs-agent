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

## 13. `tcp_drop` events: `drop_reason` always 0 / `location` corrupted

**Stage:** Runtime – `kfree_skb` event data quality
**Symptoms:**
```json
{ "drop_reason": 0, "drop_reason_name": "NOT_SPECIFIED", "location": 1.844674407183263e+19 }
```
**Root cause:** The handler used `int handle_kfree_skb(u64 *ctx)` and read
`ctx[2]` for `enum skb_drop_reason`.  With the raw `u64 *ctx` pattern the BPF
verifier may not validate the access against the tracepoint's BTF prototype,
resulting in the wrong value being loaded.  The `location` (ctx[1]) similarly
returned a garbage/max-uint64 value.
**Fix (`tcp_retransmit.bpf.c`):**
Changed the handler to use `BPF_PROG` with typed arguments, which forces
BTF-typed access and correct enum extraction:
```c
SEC("tp_btf/kfree_skb")
int BPF_PROG(handle_kfree_skb, struct sk_buff *skb, void *location,
             enum skb_drop_reason reason)
{
    __u32 drop_reason = (__u32)reason;
    __u64 loc         = (__u64)(unsigned long)location;
    ...
}
```
Also added `location_hex` field (`0x%016x` formatted) in `TCPDropEvent` so
the address can be resolved with `grep <hex> /proc/kallsyms`.

---

## 14. `tcp_drop` IP extraction: improved reliability for sk-attached packets

**Stage:** Runtime – `kfree_skb` event IP addresses
**Background:** For locally-originated / locally-destined packets (e.g. loopback
envoy→statsd), both src and dst show the loopback address (127.0.0.1).  This is
*correct* — but reading IPs solely from the packet's network header is fragile
when `skb->network_header` has not been set at the drop point (returns 0 or
invalid offset, causing reads from wrong buffer position).
**Fix (`tcp_retransmit.bpf.c`):**
Two-strategy approach:
1. **If `skb->sk` is non-NULL**: read IPs and ports directly from the socket
   (`skc_rcv_saddr`/`skc_daddr`, `skc_num`/`skc_dport`).  This is canonical
   and works regardless of the packet's header state.
2. **Fallback**: parse `skb->head + skb->network_header` as before, but now
   with an explicit `nh_off == 0` guard and `bpf_probe_read_kernel` return-code
   check that discards the event on read failure.

---

## 15. `bad CO-RE relocation: invalid func unknown#N` in `trace_rq_complete`

**Stage:** Runtime – `io_latency` module load failure
**Error:**
```
trigger: activate failed  module=io_latency
err=starting module io_latency: loading eBPF objects:
  field TraceRqComplete: program trace_rq_complete: load program:
  bad CO-RE relocation: invalid func unknown#195896080
```
**Root cause:** `trace_rq_complete` was declared as:
```c
SEC("tracepoint/block/block_rq_complete")
int trace_rq_complete(struct trace_event_raw_block_rq_completion *ctx)
```
CO-RE relocation needs to find `struct trace_event_raw_block_rq_completion` in
the **running** kernel's BTF.  This struct name is auto-generated from the
`DECLARE_EVENT_CLASS(block_rq_completion, ...)` macro.  Before kernel 5.15 the
`block_rq_complete` tracepoint was defined with a plain `TRACE_EVENT` which
produces `struct trace_event_raw_block_rq_complete` (no `_ion` suffix) – a
completely different BTF type.  When vmlinux.h came from a 5.15+ kernel but the
agent runs on an older (or differently-patched) kernel, CO-RE fails with
`unknown#N`.

**Fix (`io_latency.bpf.c` + `loader.go`):**
Replaced the raw tracepoint programs with `fentry` hooks on stable kernel
functions that have been present since blk-mq became the default:
- `SEC("fentry/blk_mq_start_request")` — fires when request enters driver queue
- `SEC("fentry/blk_mq_end_request")` — fires on hardware completion

Keyed the `io_start` map by **request pointer** (cast to `__u64`) instead of
`{dev, sector}` — simpler and collision-free for in-flight requests.

Device number extraction uses CO-RE `bpf_core_field_exists(rq->part)` to
branch between kernel 5.12+ (`rq->part->bd_dev`) and older (`rq->rq_disk->major/first_minor`).

Loader changed from `link.Tracepoint(...)` to `link.AttachTracing(...)`.

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
| 13 | tcp_retransmit.bpf.c | `drop_reason=0`, corrupted `location` | Switch `handle_kfree_skb` to `BPF_PROG` with typed args |
| 14 | tcp_retransmit.bpf.c | IP extraction fragile when `network_header=0` | Use `skb->sk` first; fallback with `nh_off==0` guard |
| 15 | io_latency.bpf.c + loader.go | `bad CO-RE relocation: invalid func unknown#N` | Replace `tracepoint/block/*` with `fentry/blk_mq_start_request` + `fentry/blk_mq_end_request` |
| 16 | writeback/loader.go | `attaching tracepoint writeback/writeback_dirty_page: no such file or directory` on kernel 6.8 | See below |

---

### Bug 16 – `writeback_dirty_page` tracepoint removed in kernel ≥ 5.18

**Symptom (kernel 6.8.0-1015-gcp):**
```
level=ERROR msg="writeback analyzer error"
err="writeback: attaching tracepoint writeback/writeback_dirty_page:
     reading file \"/sys/kernel/tracing/events/writeback/writeback_dirty_page/id\":
     open /sys/kernel/tracing/events/writeback/writeback_dirty_page/id: no such file or directory"
```
Works fine on kernel 5.15.0-1083-gcp.

**Root cause:**
In Linux kernel ~5.18, the page-cache layer was converted from `struct page` to
`struct folio`.  As part of that change the `writeback/writeback_dirty_page`
tracepoint was removed and replaced by `writeback/writeback_dirty_folio`.
Kernel 5.15 still exposes `writeback_dirty_page`; kernel 6.8 only has
`writeback_dirty_folio`.

**Fix (`writeback.bpf.c` + `loader.go`):**

*C side* — added a second eBPF program with an identical body, attached to the
folio tracepoint.  Shared via a `static __always_inline` helper to avoid
duplication:
```c
static __always_inline int __wb_dirty_impl(void) { /* increment dirty_pages */ }

SEC("tracepoint/writeback/writeback_dirty_page")   // kernel < 5.18
int tp_writeback_dirty_page(void *ctx) { return __wb_dirty_impl(); }

SEC("tracepoint/writeback/writeback_dirty_folio")  // kernel >= 5.18
int tp_writeback_dirty_folio(void *ctx) { return __wb_dirty_impl(); }
```
Both programs are compiled into the object; the BPF verifier accepts both on
any kernel because neither program reads tracepoint context arguments.

*Go side* — `loader.go Start()` tries `writeback_dirty_folio` first; falls back
to `writeback_dirty_page` if the tracepoint doesn't exist:
```go
dirtyLnk, dirtyErr := link.Tracepoint("writeback", "writeback_dirty_folio",
    l.objs.TpWritebackDirtyFolio, nil)
if dirtyErr != nil {
    dirtyLnk, dirtyErr = link.Tracepoint("writeback", "writeback_dirty_page",
        l.objs.TpWritebackDirtyPage, nil)
}
```
The active tracepoint name is logged at startup (`dirty_hook` field) so it is
visible in production logs.
