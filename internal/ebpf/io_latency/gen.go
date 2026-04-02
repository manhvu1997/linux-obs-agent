package io_latency

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -tags linux -type io_event IoLatency io_latency.bpf.c -- -I../headers
