#!/usr/bin/env python3
"""Count tokens in generated JSON files with tiktoken.

Install the optional development dependency first:

    python3 -m pip install tiktoken

Examples:
    python3 scripts/token_count.py engagement.json
    python3 scripts/token_count.py --encoding cl100k_base *.json
"""

from __future__ import annotations

import argparse
import pathlib
import sys

try:
    import tiktoken
except ImportError:  # pragma: no cover - developer tool
    sys.exit("tiktoken is required: python3 -m pip install tiktoken")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=pathlib.Path)
    parser.add_argument(
        "--encoding",
        default="o200k_base",
        help="tiktoken encoding name (default: o200k_base)",
    )
    args = parser.parse_args()

    try:
        encoding = tiktoken.get_encoding(args.encoding)
    except ValueError as error:
        parser.error(str(error))

    failed = False
    for path in args.files:
        try:
            data = path.read_text(encoding="utf-8")
        except OSError as error:
            print(f"{path}: {error}", file=sys.stderr)
            failed = True
            continue
        tokens = len(encoding.encode(data))
        size = len(data.encode("utf-8"))
        print(f"{tokens:>10,} tokens  {size:>10,} bytes  {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
