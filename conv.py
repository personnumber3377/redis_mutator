#!/usr/bin/env python3
import sys
from pathlib import Path

# ---------------- CONFIG ----------------
MIN_BLOCK = 6
MAX_BLOCK = 20
MAX_REPEAT_KEEP = 3     # keep first 3 identical blocks
MAX_ARG_LEN = 64        # truncate long arguments
# ---------------------------------------

def parse_resp(data: bytes):
    i = 0
    n = len(data)
    while i < n:
        if data[i:i+1] != b'*':
            raise ValueError("Bad RESP")
        i += 1
        end = data.index(b'\r\n', i)
        argc = int(data[i:end])
        i = end + 2
        argv = []
        for _ in range(argc):
            i += 1  # $
            end = data.index(b'\r\n', i)
            ln = int(data[i:end])
            i = end + 2
            argv.append(data[i:i+ln])
            i += ln + 2
        yield argv

def shape(argv):
    # opcode + argc only (THIS is the key insight)
    return (argv[0].lower(), len(argv))

def truncate_arg(a: bytes) -> bytes:
    if len(a) > MAX_ARG_LEN:
        return a[:MAX_ARG_LEN] + b"..."
    return a

def collapse_blocks(cmds):
    shapes = [shape(c) for c in cmds]
    out = []
    i = 0
    n = len(cmds)

    while i < n:
        collapsed = False

        for size in range(MIN_BLOCK, MAX_BLOCK + 1):
            if i + size * 2 > n:
                continue

            block = shapes[i:i+size]
            reps = 1

            while True:
                s = i + reps * size
                e = s + size
                if e > n or shapes[s:e] != block:
                    break
                reps += 1

            if reps > MAX_REPEAT_KEEP:
                keep = MAX_REPEAT_KEEP * size
                out.extend(cmds[i:i+keep])
                i += reps * size
                collapsed = True
                break

        if not collapsed:
            out.append(cmds[i])
            i += 1

    return out

def convert(resp_path: Path, out_path: Path):
    cmds = list(parse_resp(resp_path.read_bytes()))
    reduced = collapse_blocks(cmds)

    with out_path.open("wb") as f:
        for argv in reduced:
            argv2 = [truncate_arg(a) for a in argv]
            f.write(b" ".join(argv2) + b"\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: input.resp output.bin")
        sys.exit(1)

    convert(Path(sys.argv[1]), Path(sys.argv[2]))