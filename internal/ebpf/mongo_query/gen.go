package mongo_query

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -tags linux -type mongo_pid_stats_t -type mongo_slow_event_t -type mongo_pending_val_t MongoQuery mongo_query.bpf.c -- -I../headers
