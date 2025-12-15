#!/usr/bin/env python3
import sys
import re
from pathlib import Path

MAX_BLOCK = 25
MIN_BLOCK = 5
MAX_REPEAT_KEEP = 5   # keep first 5 fuzz iterations

NUM_RE = re.compile(rb'^-?\d+(\.\d+)?$')

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

def normalize_arg(a: bytes) -> bytes:
    if NUM_RE.match(a):
        return b'#'
    return a.lower()

def template(argv):
    return tuple(normalize_arg(a) for a in argv)

def collapse_blocks(cmds):
    out = []
    i = 0
    n = len(cmds)

    templates = [template(c) for c in cmds]

    while i < n:
        collapsed = False

        for size in range(MIN_BLOCK, MAX_BLOCK + 1):
            if i + size * 2 > n:
                continue

            block = templates[i:i+size]
            reps = 1

            while True:
                s = i + reps * size
                e = s + size
                if e > n or templates[s:e] != block:
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

def convert(resp_path, out_path):
    cmds = list(parse_resp(resp_path.read_bytes()))
    reduced = collapse_blocks(cmds)

    with out_path.open("wb") as f:
        for c in reduced:
            f.write(b" ".join(c) + b"\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: input.resp output.bin")
        sys.exit(1)
    convert(Path(sys.argv[1]), Path(sys.argv[2]))