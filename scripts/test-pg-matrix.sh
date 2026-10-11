#!/usr/bin/env bash
# Runs the pg_query eBPF integration tests against each PostgreSQL release in
# Docker: attach through the container's postmaster (/proc/<pid>/exe), run
# simple, extended, batch, parallel and long statements, check the kernel
# sums. A failing image is recorded and the loop continues; the exit status is
# non-zero if any image failed.
#
# Linux x86_64, as root, after `devbox run -- make generate` run as your user:
#   sudo GO="$(devbox run -- bash -c 'command -v go')" make test-pg-matrix
#   sudo PG_IMAGES="postgres:18 postgres:19" GO=… make test-pg-matrix
set -euo pipefail

IMAGES=${PG_IMAGES:-"postgres:16 postgres:17 postgres:18"}
GO=${GO:-go}
PORT=${PG_MATRIX_PORT:-15432}
PASS=secret
NAME=obs-pg-matrix

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

failed=()
for image in $IMAGES; do
	echo "=== $image"
	cleanup
	if ! docker run -d --name "$NAME" --platform linux/amd64 -p "127.0.0.1:$PORT:5432" \
		-e POSTGRES_PASSWORD="$PASS" "$image" >/dev/null; then
		echo "$image: FAILED (docker pull/run)"
		failed+=("$image")
		continue
	fi
	# The entrypoint first runs a temporary server without TCP; only the real
	# one accepts TCP connections.
	ready=
	for _ in $(seq 1 120); do
		if docker exec "$NAME" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
			ready=1
			break
		fi
		sleep 1
	done
	if [ -z "$ready" ]; then
		echo "$image: FAILED (postgres not ready after 120 s)"
		failed+=("$image")
		continue
	fi
	if ! pid=$(docker inspect -f '{{.State.Pid}}' "$NAME"); then
		echo "$image: FAILED (docker inspect)"
		failed+=("$image")
		continue
	fi
	if PG_POSTMASTER_PID="$pid" \
		PG_DSN="postgres://postgres:$PASS@127.0.0.1:$PORT/postgres?sslmode=disable" \
		"$GO" test -count=1 -tags ebpf_integration -run . -v ./internal/ebpf/pg_query/; then
		echo "$image: PASS"
	else
		echo "$image: FAILED (tests)"
		failed+=("$image")
	fi
done

if [ ${#failed[@]} -gt 0 ]; then
	echo "FAILED: ${failed[*]}"
	exit 1
fi
echo "all images passed: $IMAGES"
