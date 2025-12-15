#!/usr/bin/env bash
set -euo pipefail

# -------- CONFIG --------
INPUT_DIR="$HOME/redis_traces"
OUTPUT_DIR="./inputs"
CONVERTER="./.py"
EXT_IN=".resp"
EXT_OUT=".bin"
# ------------------------

mkdir -p "$OUTPUT_DIR"

shopt -s nullglob

for in_file in "$INPUT_DIR"/*"$EXT_IN"; do
    base=$(basename "$in_file" "$EXT_IN")
    out_file="$OUTPUT_DIR/$base$EXT_OUT"

    if [[ -f "$out_file" ]]; then
        echo "[=] Skipping $base (already converted)"
        continue
    fi

    echo "[*] Converting $base"
    python3 "$CONVERTER" "$in_file" "$out_file"
done

echo "[✓] Done"
