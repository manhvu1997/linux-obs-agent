package offcpu

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -D__TARGET_ARCH_x86" -tags linux -type offcpu_key -type offcpu_val OffCpu offcpu.bpf.c -- -I../headers
