package writeback

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -tags linux -type wb_pid_val -type wb_slow_event Writeback writeback.bpf.c -- -I../headers
