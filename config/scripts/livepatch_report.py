#!/usr/bin/env python3
"""Report native Linux kernel live-patching state as JSON.

This script deliberately reports ``unknown`` when it cannot prove the state.
It never guesses exposure days: operators can write the number of days since the
vulnerable kernel was published to /var/lib/linsec/kernel-exposure-days, or pass
it through inventory. Otherwise the value stays null and LinSec360 shows it as
an explicit unknown KPI.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _sysfs_state() -> tuple[str, bool]:
    root = Path("/sys/kernel/livepatch")
    if not root.is_dir():
        return "unavailable", False
    modules = [path for path in root.iterdir() if path.is_dir()]
    if not modules:
        return "unavailable", False
    enabled = []
    for module in modules:
        try:
            value = (module / "enabled").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        enabled.append(value == "1")
    if any(enabled):
        return "applied", False
    return "pending", True


def _canonical_state() -> tuple[str, bool]:
    if shutil.which("canonical-livepatch") is None:
        return "unknown", False
    output = _run(["canonical-livepatch", "status", "--format=json"])
    if not output:
        return "unknown", False
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return "unknown", False
    status = str(payload.get("status") or payload.get("livepatch", {}).get("status") or "").lower()
    if status in {"applied", "enabled", "running"}:
        return "applied", False
    if status in {"pending", "available", "checking"}:
        return "pending", True
    if status in {"disabled", "unavailable", "unsupported"}:
        return "unavailable", False
    return "unknown", False


def _kpatch_state() -> tuple[str, bool]:
    if shutil.which("kpatch") is None:
        return "unknown", False
    output = _run(["kpatch", "list"])
    lines = [
        line
        for line in output.splitlines()
        if line.strip() and not line.lower().startswith("installed")
    ]
    if lines:
        return "applied", False
    return "unavailable", False


def _exposure_days() -> int | None:
    for source in (
        os.environ.get("LINSEC_KERNEL_EXPOSURE_DAYS"),
        Path("/var/lib/linsec/kernel-exposure-days").read_text().strip()
        if Path("/var/lib/linsec/kernel-exposure-days").is_file()
        else None,
    ):
        if source is None:
            continue
        try:
            value = int(source)
        except (TypeError, ValueError):
            continue
        if value >= 0:
            return value
    return None


def main() -> None:
    state, patch_available = _sysfs_state()
    if state == "unknown" or state == "unavailable":
        for candidate in (_canonical_state, _kpatch_state):
            candidate_state, candidate_available = candidate()
            if candidate_state != "unknown":
                state = candidate_state
                patch_available = patch_available or candidate_available
                break
    print(
        json.dumps(
            {
                "kernel": platform.release(),
                "livepatch_state": state,
                "patch_available": bool(patch_available),
                "exposure_days": _exposure_days(),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
