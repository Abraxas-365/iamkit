"""Generates ``src/iamkit/_aresources.py`` (async) from ``src/iamkit/_resources.py`` (sync).

Run ``uv run python scripts/unasync.py`` after editing ``_resources.py``; ``--check`` verifies it is current.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "src" / "iamkit"
SOURCE = ROOT / "_resources.py"
TARGET = ROOT / "_aresources.py"

HEADER = '''"""Management resources (asynchronous). GENERATED from ``_resources.py`` by ``scripts/unasync.py``."""
'''


def _blocks(text: str) -> list[str]:
    """Splits the text before each method/function definition (the def line starts a block)."""
    return re.split(r"(?m)^(?=(?:    )?def )", text)


def _convert(block: str) -> str:
    match = re.match(r"(    )?def (\w+)", block)
    if not match:
        return block
    name = match.group(2)
    is_gen = re.search(r"^\s+yield\b", block, flags=re.M) is not None
    does_io = "self._c.request(" in block
    if is_gen:
        block = block.replace("-> Iterator[", "-> AsyncIterator[")
    elif name.startswith("iterate"):
        block = block.replace("-> Iterator[", "-> AsyncIterator[")  # returns the async generator: stays sync
    if (is_gen or does_io) and not name.startswith("__"):
        block = re.sub(r"^((?:    )?)def ", r"\1async def ", block, count=1)
    block = re.sub(r"(?m)^(\s*)for (\w+) in self\._c\.stream\(", r"\1async for \2 in self._c.stream(", block)
    block = re.sub(r"(return|=) self\._c\.request\(", r"\1 await self._c.request(", block)
    block = re.sub(r"(?m)^(\s*)self\._c\.request\(", r"\1await self._c.request(", block)
    return block


def transform(source: str) -> str:
    text = source.split('"""', 2)[2]  # drop the module docstring of the source
    text = "".join(_convert(b) for b in _blocks(text))
    text = re.sub(r"\bCore\b", "AsyncCore", text)
    text = text.replace("from collections.abc import Iterator,", "from collections.abc import AsyncIterator,")
    out = HEADER + text
    # keep the checked-in file in the repo's formatting (ruff format), so --check compares like with like
    formatted = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--stdin-filename", str(TARGET), "-"],
        input=out,
        capture_output=True,
        text=True,
        check=True,
    )
    return formatted.stdout


def main() -> int:
    generated = transform(SOURCE.read_text())
    if "--check" in sys.argv:
        if not TARGET.exists() or TARGET.read_text() != generated:
            print("_aresources.py is stale: run `uv run python scripts/unasync.py`", file=sys.stderr)
            return 1
        return 0
    TARGET.write_text(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
