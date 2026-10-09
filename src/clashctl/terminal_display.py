"""Stable terminal labels and explicit macOS clipboard I/O."""

import re
import shutil
import subprocess
import unicodedata

from prompt_toolkit.formatted_text import ANSI, fragment_list_to_text, to_formatted_text

from clashctl.models import ConfigurationError


def display_name(value: str) -> str:
    """Remove emoji and invisible format controls before measuring terminal columns.

    Regional flags occupy two Rich cells but four prompt_toolkit cells. Raw API
    names stay unchanged for selection, rule matching, and clipboard exports.
    """
    normalized: str = unicodedata.normalize("NFC", value)
    return "".join(
        character
        for character in normalized
        if unicodedata.category(character) not in {"So", "Cf"}
        and not 0xFE00 <= ord(character) <= 0xFE0F
        and not 0x1F3FB <= ord(character) <= 0x1F3FF
        and (character in {"\n", "\t"} or unicodedata.category(character) != "Cc")
    ).strip()


def node_label(value: str) -> str:
    """Put the base name first, the original multiplier next, and IPv6 last.

    Display formatting never changes raw names used by controllers or cached IDs.
    """
    label: str = display_name(value)
    ipv6: re.Match[str] | None = re.match(r"^\[v6\]\s*", label, flags=re.IGNORECASE)
    if ipv6 is not None:
        label = label[ipv6.end() :]
    multiplier: re.Match[str] | None = re.search(
        r"\s*\((\d+(?:\.\d+)?)x\)$", label, flags=re.IGNORECASE
    )
    if multiplier is not None:
        label = label[: multiplier.start()].rstrip() + "【" + multiplier.group(1) + "】"
    return label + (" [v6]" if ipv6 is not None else "")


def plain_text(value: str) -> str:
    return "\n".join(
        line.rstrip() for line in fragment_list_to_text(to_formatted_text(ANSI(value))).splitlines()
    ).strip()


def copy_to_clipboard(value: str) -> None:
    executable: str | None = shutil.which("pbcopy")
    if executable is None:
        raise ConfigurationError(
            "macOS pbcopy is unavailable. Ensure /usr/bin is in PATH to enable clipboard copying."
        )
    try:
        result: subprocess.CompletedProcess[str] = subprocess.run(
            [executable],
            input=value,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ConfigurationError(f"Cannot copy to the system clipboard: {error}") from error
    if result.returncode != 0:
        raise ConfigurationError(
            f"pbcopy failed: exit={result.returncode}, response={result.stderr[:500]}"
        )
