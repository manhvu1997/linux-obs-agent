package netflow

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -D__TARGET_ARCH_x86" -tags linux -type flow_key -type flow_val Netflow netflow.bpf.c -- -I../headers
