package pg_query

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -D__TARGET_ARCH_x86" -tags linux -type agg_key_t -type agg_val_t -type pg_session_t -type cluster_cfg_t PgQuery pg_query.bpf.c -- -I../headers
