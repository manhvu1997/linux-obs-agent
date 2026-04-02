package disk_write

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -tags linux DiskWrite disk_write.bpf.c -- -I../headers
