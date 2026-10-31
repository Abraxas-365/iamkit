"""Generates the async twins from their sync sources:

* ``src/iamkit/_aresources.py`` from ``src/iamkit/_resources.py``
* ``src/iamkit/_aresource_server.py`` from ``src/iamkit/_resource_server.py``

Run ``uv run python scripts/unasync.py`` after editing a source; ``--check`` verifies the twins are current.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "src" / "iamkit"
SOURCE = ROOT / "_resources.py"
TARGET = ROOT / "_aresources.py"
RS_SOURCE = ROOT / "_resource_server.py"
RS_TARGET = ROOT / "_aresource_server.py"

HEADER = '''"""Management resources (asynchronous). GENERATED from ``_resources.py`` by ``scripts/unasync.py``."""
'''
RS_HEADER = '''"""Resource server (asynchronous). GENERATED from ``_resource_server.py`` by ``scripts/unasync.py``."""
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


def _format(out: str, target: Path) -> str:
    # keep the checked-in file in the repo's formatting (ruff format), so --check compares like with like
    formatted = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--stdin-filename", str(target), "-"],
        input=out,
        capture_output=True,
        text=True,
        check=True,
    )
    return formatted.stdout


def transform(source: str) -> str:
    text = source.split('"""', 2)[2]  # drop the module docstring of the source
    text = "".join(_convert(b) for b in _blocks(text))
    text = re.sub(r"\bCore\b", "AsyncCore", text)
    text = text.replace("from collections.abc import Iterator,", "from collections.abc import AsyncIterator,")
    return _format(HEADER + text, TARGET)


# The calls of the resource server that do I/O, and their awaited twins.
_RS_CALLS = (
    ("self._keys.get_key(", "await self._keys.aget_key("),
    ("self._oauth.introspect(", "await self._oauth.aintrospect("),
    ("self._check_live(", "await self._check_live("),
    ("self._keys.close()", "await self._keys.aclose()"),
    ("self._oauth.close()", "await self._oauth.aclose()"),
)


def _convert_rs(block: str) -> str:
    match = re.match(r"(    )?def (\w+)", block)
    if not match:
        return block
    does_io = any(call in block for call, _ in _RS_CALLS)
    for call, awaited in _RS_CALLS:
        block = block.replace(call, awaited)
    if does_io:
        block = re.sub(r"^((?:    )?)def ", r"\1async def ", block, count=1)
        block = block.replace("def close(", "def aclose(")
    return block


def transform_resource_server(source: str) -> str:
    text = source.split('"""', 2)[2]
    text = "".join(_convert_rs(b) for b in _blocks(text))
    text = re.sub(r"\bResourceServer\b(?!Base)", "AsyncResourceServer", text)
    text = text.replace("synchronous", "asynchronous")
    text = text.replace("claims = rs.verify(token)  ", "claims = await rs.verify(token)")
    text = text.replace(
        '__all__ = ["ResourceError", "AsyncResourceServer"]', '__all__ = ["AsyncResourceServer", "ResourceError"]'
    )
    return _format(RS_HEADER + text, RS_TARGET)


TWINS = (
    (SOURCE, TARGET, transform),
    (RS_SOURCE, RS_TARGET, transform_resource_server),
)


def main() -> int:
    stale = False
    for source, target, convert in TWINS:
        generated = convert(source.read_text())
        if "--check" in sys.argv:
            if not target.exists() or target.read_text() != generated:
                print(f"{target.name} is stale: run `uv run python scripts/unasync.py`", file=sys.stderr)
                stale = True
        else:
            target.write_text(generated)
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
