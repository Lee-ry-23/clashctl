"""Audit real release archives for unexpected files, machine paths, and credential patterns.

Run after uv build:
    uv run python tests/package_smoke.py --wheel dist/clashctl-0.1.0-py3-none-any.whl \
        --sdist dist/clashctl-0.1.0.tar.gz
This check does not read Clash configuration or contact a controller.
"""

import argparse
import re
import tarfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    data: bytes


def read_wheel(path: Path) -> tuple[ArchiveEntry, ...]:
    with zipfile.ZipFile(path) as archive:
        return tuple(
            ArchiveEntry(item.filename, archive.read(item))
            for item in archive.infolist()
            if not item.is_dir()
        )


def read_sdist(path: Path) -> tuple[ArchiveEntry, ...]:
    entries: list[ArchiveEntry] = []
    with tarfile.open(path, "r:gz") as archive:
        for item in archive.getmembers():
            if item.isdir():
                continue
            if not item.isfile():
                raise AssertionError(f"Source archive contains a non-regular file: {item.name}")
            source = archive.extractfile(item)
            if source is None:
                raise AssertionError(f"Cannot read source archive member: {item.name}")
            parts: tuple[str, ...] = PurePosixPath(item.name).parts
            if len(parts) < 2 or not parts[0].startswith("clashctl-"):
                raise AssertionError(f"Source archive has an unexpected root: {item.name}")
            with source:
                entries.append(ArchiveEntry("/".join(parts[1:]), source.read()))
    return tuple(entries)


def validate_path(path: str) -> None:
    parts: tuple[str, ...] = PurePosixPath(path).parts
    if (
        path.startswith("/")
        or ".." in parts
        or any(part.startswith("__pycache__") for part in parts)
    ):
        raise AssertionError(f"Unsafe archive path: {path}")


def validate_wheel_path(path: str) -> None:
    parts: tuple[str, ...] = PurePosixPath(path).parts
    if len(parts) == 2 and parts[0] == "clashctl" and parts[1].endswith(".py"):
        return
    if (
        len(parts) == 2
        and re.fullmatch(r"clashctl-[0-9][A-Za-z0-9.+_-]*\.dist-info", parts[0])
        and parts[1] in {"METADATA", "WHEEL", "RECORD", "entry_points.txt"}
    ):
        return
    raise AssertionError(f"Unexpected wheel file: {path}")


def validate_source_path(path: str) -> None:
    if path in {
        "README.md",
        "pyproject.toml",
        "uv.lock",
        ".gitignore",
        ".github/workflows/ci.yml",
        "PKG-INFO",
    }:
        return
    parts: tuple[str, ...] = PurePosixPath(path).parts
    if len(parts) == 3 and parts[:2] == ("src", "clashctl") and parts[2].endswith(".py"):
        return
    if len(parts) == 2 and parts[0] == "tests" and parts[1].endswith(".py"):
        return
    raise AssertionError(f"Unexpected source file: {path}")


def validate_content(entry: ArchiveEntry) -> None:
    patterns: tuple[tuple[str, bytes], ...] = (
        ("personal home path", rb"/(?:Users|home)/[A-Za-z0-9._-]+/"),
        ("machine temporary path", rb"/(?:private/)?var/folders/[A-Za-z0-9]+/"),
        ("GitHub credential", rb"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}"),
        ("API credential", rb"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
        ("private key", rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ("credential in URL", rb"https?://[^\s/:@]+:[^\s/@]+@"),
    )
    for description, pattern in patterns:
        if re.search(pattern, entry.data):
            raise AssertionError(f"Detected {description} in {entry.path}; contents withheld")


def validate_entries(entries: tuple[ArchiveEntry, ...], check_path: Callable[[str], None]) -> None:
    if not entries:
        raise AssertionError("Release archive is empty")
    if len({entry.path for entry in entries}) != len(entries):
        raise AssertionError("Release archive contains duplicate paths")
    for entry in entries:
        validate_path(entry.path)
        check_path(entry.path)
        validate_content(entry)


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--sdist", type=Path, required=True)
    arguments: argparse.Namespace = parser.parse_args()
    wheel: tuple[ArchiveEntry, ...] = read_wheel(arguments.wheel)
    source: tuple[ArchiveEntry, ...] = read_sdist(arguments.sdist)
    validate_entries(wheel, validate_wheel_path)
    validate_entries(source, validate_source_path)
    if "clashctl/__init__.py" not in {entry.path for entry in wheel}:
        raise AssertionError("Wheel is missing the application package")
    entry_points: bytes = next(
        entry.data for entry in wheel if entry.path.endswith("/entry_points.txt")
    )
    if b"clashctl = clashctl.cli:main" not in entry_points:
        raise AssertionError("Wheel is missing the clashctl console entry point")
    for path in ("README.md", "pyproject.toml", "uv.lock", "tests/package_smoke.py"):
        if path not in {entry.path for entry in source}:
            raise AssertionError(f"Source archive is missing {path}")
    print(f"PASS: wheel {len(wheel)} files, source {len(source)} files; privacy audit clean")


if __name__ == "__main__":
    main()
