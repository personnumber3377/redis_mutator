#!/bin/bash
set -euo pipefail

REDIS_ROOT="$HOME/redis"
TRACE_DIR="$HOME/redis_traces"

mkdir -p "$TRACE_DIR"

i=0

# Only unit tests
for testfile in "$REDIS_ROOT/tests/unit/"*.tcl; do
    base=$(basename "$testfile" .tcl)
    testname="unit/$base"

    out="$TRACE_DIR/trace_$(printf "%04d" "$i")_${base}.resp"

    echo "[*] Running $testname → $out"

    export REDIS_COMMAND_TRACE="$out"

    (
        cd "$REDIS_ROOT"
        ./runtest --single "$testname"
    ) || echo "[!] Test failed: $testname (continuing)"

    i=$((i+1))
done