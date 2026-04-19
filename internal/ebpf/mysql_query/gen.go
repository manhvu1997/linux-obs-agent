package mysql_query

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -tags linux -type mysql_slow_event_t -type mysql_pid_stats_t MysqlQuery mysql_query.bpf.c -- -I../headers
