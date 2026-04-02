package cpu_profile

// Instruct the Go toolchain to compile the eBPF C program and generate
// Go scaffolding (counterObjects, loadCounterObjects, …) before building.
//
// Flags:
//   -cc clang          – use clang as the C compiler
//   -cflags            – pass through kernel CO-RE flags
//   -type              – export these C structs into the generated Go file
//   -tags linux        – generated files only build on Linux
//
//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -tags linux -type cpu_sample_event -type cpu_count_key CpuProfile cpu_profile.bpf.c -- -I../headers
