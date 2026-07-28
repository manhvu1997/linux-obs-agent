package runqlat

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -D__TARGET_ARCH_x86" -tags linux -type runq_event -type runq_pid_stat RunQLat runqlat.bpf.c -- -I../headers
