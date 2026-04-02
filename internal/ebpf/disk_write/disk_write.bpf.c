// SPDX-License-Identifier: GPL-2.0
//
// disk_write.bpf.c – traces vfs_write() to capture per-process disk write
// bytes and the filename being written.
//
// Attachment: fentry/vfs_write (BTF-based, kernel >= 5.5).
//
// Why fentry instead of kprobe/BPF_KPROBE:
//   BPF_KPROBE reads function arguments from struct pt_regs using
//   architecture-specific field names (di/si/dx for x86_64, x0/x1/x2 for
//   arm64).  When vmlinux.h was generated on a different architecture than the
//   -D__TARGET_ARCH_* compile flag, those field names are absent and the build
//   fails with "no member named 'di' in struct pt_regs".
//   BPF_PROG on an fentry section receives typed arguments directly via BTF —
//   no pt_regs, no architecture-specific register names, no mismatch.
//
// Two BPF maps:
//   pid_bytes – HASH pid → u64  cumulative bytes per PID (for TopWriters).
//   events    – RINGBUF         one record per vfs_write call (real-time feed).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN  16
#define FILENAME_LEN   128
#define MAX_PIDS       4096

// ── Struct layout (must match rawDiskWriteEvent in loader.go) ─────────────────
//
//  offset  size  field
//  ------  ----  -----
//       0     4  pid
//       4     4  _pad   (explicit, keeps bytes at offset 8)
//       8     8  bytes
//      16    16  comm
//      32   128  filename
//  total: 160 bytes
//
struct disk_write_event {
    __u32 pid;
    __u32 _pad;
    __u64 bytes;
    __u8  comm[TASK_COMM_LEN];
    __u8  filename[FILENAME_LEN];
};

// Per-PID byte accumulator: pid → total bytes written since activation.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key,   __u32);
    __type(value, __u64);
} pid_bytes SEC(".maps");

// Ring buffer for individual write events consumed by user-space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// BPF_PROG passes BTF-typed arguments directly — no PT_REGS, no arch dependency.
SEC("fentry/vfs_write")
int BPF_PROG(trace_vfs_write,
             struct file *file,
             const char *buf,
             size_t count,
             loff_t *pos)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // ── per-PID byte accumulation ─────────────────────────────────────────
    __u64 *total = bpf_map_lookup_elem(&pid_bytes, &pid);
    if (total) {
        __sync_fetch_and_add(total, (__u64)count);
    } else {
        __u64 val = (__u64)count;
        bpf_map_update_elem(&pid_bytes, &pid, &val, BPF_NOEXIST);
    }

    // ── emit ring-buffer event ────────────────────────────────────────────
    struct disk_write_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid   = pid;
    e->_pad  = 0;
    e->bytes = (__u64)count;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Best-effort filename from dentry.  Returns empty string for
    // anonymous files, pipes, and sockets.
    const unsigned char *dname =
        BPF_CORE_READ(file, f_path.dentry, d_name.name);
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), dname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
