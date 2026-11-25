#!/usr/bin/env python3
"""Set values in a LinSec360 dotenv file without rewriting unrelated entries."""

from pathlib import Path
import argparse
import os
import re
import tempfile


KEY_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def read_env(path: Path) -> tuple[list[str], dict[str, int]]:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    positions: dict[str, int] = {}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        key = stripped.split("=", 1)[0].strip()
        if KEY_PATTERN.fullmatch(key):
            positions.setdefault(key, index)
    return lines, positions


def quote(value: str) -> str:
    """Return a POSIX-safe single-quoted dotenv value."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def set_values(path: Path, values: dict[str, str]) -> list[str]:
    if path.is_symlink():
        raise ValueError(f"refusing to update a symbolic link: {path}")
    for key in values:
        if not KEY_PATTERN.fullmatch(key):
            raise ValueError(f"invalid environment key: {key}")

    lines, positions = read_env(path)
    for key, value in values.items():
        replacement = f"{key}={quote(value)}"
        index = positions.get(key)
        if index is None:
            lines.append(replacement)
        else:
            lines[index] = replacement

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{path.name}-", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write("\n".join(lines) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise
    return sorted(values)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument(
        "values",
        nargs="+",
        metavar="KEY=VALUE",
        help="environment values to set; existing keys are replaced",
    )
    args = parser.parse_args()

    values: dict[str, str] = {}
    for item in args.values:
        key, separator, value = item.partition("=")
        if not separator:
            raise SystemExit(f"expected KEY=VALUE, got: {item}")
        values[key] = value

    updated = set_values(args.env_file, values)
    print("Updated: " + ", ".join(updated))


if __name__ == "__main__":
    main()
