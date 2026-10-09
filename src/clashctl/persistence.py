"""Atomic local JSON writes shared by benchmark reports and the persistent cache."""

import json
import os
import tempfile
from pathlib import Path

from clashctl.models import JsonObject


def write_json_file(document: JsonObject, path: Path) -> None:
    write_text_file(
        json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n", path
    )


def write_text_file(content: str, path: Path) -> None:
    """Replace a private UTF-8 file atomically with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int
    filename: str
    descriptor, filename = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary: Path = Path(filename)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
