#!/usr/bin/env python3
import sys
from pathlib import Path

# ---------------- CONFIG ----------------
MAX_REPEAT_BLOCKS = 2
MIN_BLOCK = 3
MAX_BLOCK = 12

MAX_ARGS_TOTAL = 64        # absolute cap per command
MAX_GEOADD_TRIPLES = 5    # lon lat member × N
MAX_ARG_LEN = 64
# --------------------------------------



'''
def parse_resp(data: bytes):
    i = 0
    n = len(data)
    while i < n:
        print("data[i-100:i+100]: "+str(data[i-100:i+100]))
        assert data[i:i+1] == b'*'
        i += 1
        end = data.index(b'\r\n', i)
        argc = int(data[i:end])
        i = end + 2
        argv = []
        for _ in range(argc):
            i += 1
            end = data.index(b'\r\n', i)
            ln = int(data[i:end])
            i = end + 2
            argv.append(data[i:i+ln])
            i += ln + 2
        yield argv
'''

'''
def parse_resp(data: bytes):
    i = 0
    n = len(data)

    while i < n:
        print("data[i-100:i+100]: "+str(data[i-100:i+100]))
        # Skip whitespace and newlines
        if data[i:i+1] in b"\r\n ":
            i += 1
            continue

        # Skip inline commands (e.g. "PING\r\n")
        if data[i:i+1] != b'*':
            end = data.find(b'\r\n', i)
            if end == -1:
                break
            i = end + 2
            continue

        # RESP array
        i += 1
        end = data.index(b'\r\n', i)
        argc = int(data[i:end])
        i = end + 2

        argv = []
        for _ in range(argc):
            if data[i:i+1] != b'$':
                # Malformed / partial frame → abort this command
                break

            i += 1
            end = data.index(b'\r\n', i)
            length = int(data[i:end])
            i = end + 2

            arg = data[i:i+length]
            argv.append(arg)
            i += length + 2  # data + CRLF

        if argv:
            yield argv
'''

def parse_resp(data: bytes):
    i = 0
    n = len(data)

    while i < n:
        # Skip whitespace
        if data[i:i+1] in b" \r\n":
            i += 1
            continue

        # Skip inline commands (e.g. PING\r\n)
        if data[i:i+1] not in (b'*',):
            end = data.find(b'\r\n', i)
            if end == -1:
                return
            i = end + 2
            continue

        # We saw '*', try to parse argc
        star = i
        i += 1
        end = data.find(b'\r\n', i)
        if end == -1:
            return

        try:
            argc = int(data[i:end])
        except ValueError:
            # Not a valid array header → resync
            i = star + 1
            continue

        i = end + 2
        argv = []
        ok = True

        for _ in range(argc):
            if i >= n or data[i:i+1] != b'$':
                ok = False
                break

            i += 1
            end = data.find(b'\r\n', i)
            if end == -1:
                return

            try:
                length = int(data[i:end])
            except ValueError:
                ok = False
                break

            i = end + 2
            if i + length + 2 > n:
                return

            arg = data[i:i+length]
            argv.append(arg)
            i += length + 2  # data + CRLF

        if ok and argv:
            yield argv
        # else: silently drop malformed command

def opcode(argv):
    return argv[0].lower()

def truncate_arg(a: bytes):
    return a if len(a) <= MAX_ARG_LEN else a[:MAX_ARG_LEN] + b"..."

def shrink_command(argv):
    op = opcode(argv)

    # GEOADD key lon lat member ...
    if op == b"geoadd" and len(argv) > 5:
        key = argv[1:2]
        triples = argv[2:]
        triples = triples[: MAX_GEOADD_TRIPLES * 3]
        argv = [argv[0]] + key + triples

    # Hard cap total args
    argv = argv[:MAX_ARGS_TOTAL]

    return [truncate_arg(a) for a in argv]

def collapse_blocks(cmds):
    ops = [opcode(c) for c in cmds]
    out = []
    i = 0

    while i < len(cmds):
        collapsed = False

        for size in range(MIN_BLOCK, MAX_BLOCK + 1):
            block = ops[i:i+size]
            if len(block) < size:
                continue

            reps = 1
            while ops[i + reps*size : i + (reps+1)*size] == block:
                reps += 1

            if reps > MAX_REPEAT_BLOCKS:
                for r in range(MAX_REPEAT_BLOCKS):
                    for j in range(size):
                        out.append(cmds[i + r*size + j])
                i += reps * size
                collapsed = True
                break

        if not collapsed:
            out.append(cmds[i])
            i += 1

    return out

def convert(inp: Path, outp: Path):
    cmds = list(parse_resp(inp.read_bytes()))
    cmds = collapse_blocks(cmds)

    with outp.open("wb") as f:
        for c in cmds:
            c = shrink_command(c)
            f.write(b" ".join(c) + b"\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: input.resp output.bin")
        sys.exit(1)
    convert(Path(sys.argv[1]), Path(sys.argv[2]))