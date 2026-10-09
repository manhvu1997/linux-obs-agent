#!/usr/bin/env bash
# Runs the mysql_query eBPF integration tests against each MySQL release in
# Docker: attach to the container's mysqld through /proc/<pid>/root, send a
# COM_QUERY and a server-side prepared statement, check the events.
#
# Linux x86_64 only, as root (uprobes), after `make generate`:
#   sudo make test-mysql-matrix
#   sudo MYSQL_IMAGES="mysql:8.0.36 mysql:9.7" make test-mysql-matrix
set -euo pipefail

IMAGES=${MYSQL_IMAGES:-"mysql:5.7 mysql:8.0 mysql:8.4 mysql:9"}
GO=${GO:-go}
PORT=${MYSQL_MATRIX_PORT:-13306}
PASS=secret
NAME=obs-mysql-matrix

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

failed=()
for image in $IMAGES; do
	echo "=== $image"
	cleanup
	docker run -d --name "$NAME" --platform linux/amd64 -p "127.0.0.1:$PORT:3306" \
		-e MYSQL_ROOT_PASSWORD="$PASS" "$image" >/dev/null
	# The entrypoint first runs a temporary server without networking, then
	# execs the real one: a TCP login succeeds only against the real one.
	ready=
	for _ in $(seq 1 120); do
		if docker exec "$NAME" mysql -uroot -p"$PASS" -h127.0.0.1 -e 'SELECT 1' >/dev/null 2>&1; then
			ready=1
			break
		fi
		sleep 1
	done
	if [ -z "$ready" ]; then
		echo "$image: mysqld not ready after 120 s"
		failed+=("$image")
		continue
	fi
	pid=$(docker inspect -f '{{.State.Pid}}' "$NAME")
	if MYSQLD_PATH="/proc/$pid/root/usr/sbin/mysqld" \
		MYSQL_DSN="root:$PASS@tcp(127.0.0.1:$PORT)/" \
		"$GO" test -count=1 -tags ebpf_integration -run 'TestCmdEvent|TestPreparedStatement' -v ./internal/ebpf/mysql_query/; then
		echo "$image: PASS"
	else
		failed+=("$image")
	fi
done

if [ ${#failed[@]} -gt 0 ]; then
	echo "FAILED: ${failed[*]}"
	exit 1
fi
echo "all images passed: $IMAGES"
