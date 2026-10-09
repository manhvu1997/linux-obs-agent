package mysql_query

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -D__TARGET_ARCH_x86" -tags linux -type mysql_slow_event_t -type mysql_pid_stats_t -type mysql_cmd_event_t -type agg_key_t -type agg_val_t -type text_key_t MysqlQuery mysql_query.bpf.c -- -I../headers
