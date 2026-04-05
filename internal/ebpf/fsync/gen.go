package fsync

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -tags linux -type fsync_event -type fsync_pid_val Fsync fsync.bpf.c -- -I../headers
