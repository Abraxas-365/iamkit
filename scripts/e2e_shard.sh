#!/usr/bin/env bash
# Runs one shard of the Go e2e suite (tests/e2e).
#
#   scripts/e2e_shard.sh <index> <total>     e.g. scripts/e2e_shard.sh 1 4
#
# Tests are listed with `go test -list` and dealt out round-robin, so a new test
# lands in some shard without anyone maintaining a list. Every shard starts its
# own PostgreSQL container (the harness does that), so shards are independent.
# Extra arguments after the two numbers go to `go test`.
set -euo pipefail

index=${1:?shard index (1-based)}
total=${2:?shard count}
shift 2
if ! [[ $index =~ ^[0-9]+$ && $total =~ ^[0-9]+$ ]] || ((index < 1 || index > total)); then
  echo "usage: $0 <index 1..total> <total>" >&2
  exit 2
fi

cd "$(dirname "$0")/.."

# -list runs TestMain, which only starts Docker when IAMKIT_TEST_E2E=1.
names=$(env -u IAMKIT_TEST_E2E go test ./tests/e2e -list '^Test' | grep '^Test' | sort)
if [[ -z $names ]]; then
  echo "no e2e tests found" >&2
  exit 1
fi

picked=$(awk -v i="$index" -v n="$total" '(NR - 1) % n == i - 1' <<<"$names" | paste -sd'|' -)
count=$(tr '|' '\n' <<<"$picked" | wc -l | tr -d ' ')
echo "e2e shard $index/$total: $count of $(wc -l <<<"$names" | tr -d ' ') tests"

IAMKIT_TEST_E2E=1 exec go test -count=1 -timeout=20m -run "^(${picked})\$" "$@" ./tests/e2e
