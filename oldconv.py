#!/usr/bin/env python3
import sys
from pathlib import Path

def parse_resp(data: bytes):
    i = 0
    n = len(data)

    while i < n:
        if data[i:i+1] != b'*':
            raise ValueError(f"Expected '*', got {data[i:i+1]!r} at {i}")

        i += 1
        end = data.index(b'\r\n', i)
        argc = int(data[i:end])
        i = end + 2

        argv = []
        for _ in range(argc):
            if data[i:i+1] != b'$':
                raise ValueError(f"Expected '$', got {data[i:i+1]!r} at {i}")
            i += 1

            end = data.index(b'\r\n', i)
            length = int(data[i:end])
            i = end + 2

            arg = data[i:i+length]
            argv.append(arg)
            i += length + 2  # skip data + CRLF

        yield argv

def resp_file_to_inline(resp_path: Path, out_path: Path):
    data = resp_path.read_bytes()

    with out_path.open("wb") as out:
        for argv in parse_resp(data):
            # Join args with spaces, newline-terminate command
            out.write(b" ".join(argv) + b"\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} input.resp output.bin", file=sys.stderr)
        sys.exit(1)

    resp_file_to_inline(Path(sys.argv[1]), Path(sys.argv[2]))

