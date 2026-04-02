package tcp_retransmit

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -tags linux -type retransmit_event TcpRetransmit tcp_retransmit.bpf.c -- -I../headers
