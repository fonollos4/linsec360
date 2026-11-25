#!/usr/bin/env python3
"""Filter a generated OpenSCAP bash remediation before it is applied.

The script is intentionally conservative:

* rule IDs matching a denied pattern remove the whole remediation block;
* individual shell lines matching a denied command pattern are removed as a
  second gate, even when the generated script has no per-rule markers.

It prints a JSON summary on stdout so Ansible can decide whether the filtered
script contains anything safe to apply. The script never executes remediation
commands itself.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RULE_MARKER = re.compile(r"^#\s*(xccdf_[^\s]+)")
FAILED_RESULTS = {"fail", "unknown", "error"}


def failed_rule_ids(results_path: Path) -> list[str]:
    """Return rule IDs whose result requires remediation."""
    try:
        root = ET.parse(results_path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise SystemExit(f"cannot read OpenSCAP results: {exc}") from exc

    ids: list[str] = []
    for element in root.iter():
        if not str(element.tag).endswith("rule-result"):
            continue
        result = ""
        for child in element:
            if str(child.tag).endswith("result"):
                result = (child.text or "").strip()
                break
        if result in FAILED_RESULTS:
            rule_id = element.get("idref") or ""
            if rule_id:
                ids.append(rule_id)
    return ids


def split_blocks(lines: list[str]) -> tuple[list[str], list[tuple[str | None, list[str]]]]:
    """Split a generated script into a header and (rule id, lines) blocks."""
    header: list[str] = []
    blocks: list[tuple[str | None, list[str]]] = []
    current_id: str | None = None
    for line in lines:
        match = RULE_MARKER.match(line.strip())
        if match:
            current_id = match.group(1)
            blocks.append((current_id, [line]))
        elif blocks:
            blocks[-1][1].append(line)
        else:
            header.append(line)
    if not blocks:
        body = [line for line in header if not line.startswith("#!")]
        header = [line for line in header if line.startswith("#!")]
        blocks = [(None, body)]
    return header, blocks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--fix", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    args = parser.parse_args()

    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    rule_patterns = [re.compile(p) for p in policy.get("denied_rule_patterns", [])]
    command_patterns = [re.compile(p) for p in policy.get("denied_command_patterns", [])]

    failed_ids = failed_rule_ids(args.results)
    denied_ids = [
        rule_id
        for rule_id in failed_ids
        if any(pattern.search(rule_id) for pattern in rule_patterns)
    ]
    denied_set = set(denied_ids)

    raw_lines = args.fix.read_text(encoding="utf-8").splitlines()
    header, blocks = split_blocks(raw_lines)

    kept_lines: list[str] = []
    removed_commands = 0
    included_rules: set[str] = set()
    for rule_id, lines in blocks:
        if rule_id is not None and rule_id in denied_set:
            continue
        for line in lines:
            if line.startswith("#!"):
                continue
            if any(pattern.search(line) for pattern in command_patterns):
                removed_commands += 1
                continue
            kept_lines.append(line)
            if rule_id is not None:
                included_rules.add(rule_id)

    output = [
        "#!/bin/bash",
        "# LinSec360: filtered OpenSCAP remediation. Generated file - do not edit.",
        "# Rules that could cut SSH or block Wazuh ports are excluded.",
    ]
    if denied_ids:
        output.append("# Excluded rule IDs: " + ", ".join(sorted(denied_set)))
    output.extend(kept_lines)
    args.output.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    args.output.chmod(0o700)

    summary = {
        "failed_rules": len(failed_ids),
        "excluded_rules": len(denied_set),
        "included_rules": len(included_rules) if any(rid for rid, _ in blocks) else len(kept_lines),
        "dangerous_lines_removed": removed_commands,
        "safe_to_apply": bool(kept_lines),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
