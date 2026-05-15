from __future__ import annotations

import csv
import hashlib
import json
import shutil
from pathlib import Path

from ghosttype.models import Finding

_FIELDS = [
    "tool",
    "source",
    "secret_type",
    "detector_name",
    "severity",
    "verified",
    "verification_error",
    "secret_value",
    "file_path",
    "position",
    "confidence",
    "context",
    "discovered_at",
    "extra_data",
]


def _finding_to_dict(f: Finding, redact: bool = False) -> dict:
    return {
        "tool": f.tool,
        "source": f.source,
        "secret_type": f.secret_type,
        "detector_name": f.detector_name,
        "severity": f.severity,
        "verified": f.verified,
        "verification_error": f.verification_error,
        "secret_value": "***REDACTED***" if redact else f.secret_value,
        "file_path": str(f.file_path),
        "position": f.position,
        "confidence": f.confidence,
        "context": f.context,
        "discovered_at": f.discovered_at.isoformat(),
        "extra_data": f.extra_data,
    }


def write_json(findings: list[Finding], path: Path, redact: bool = False) -> None:
    """Write findings to a JSON file (UTF-8, pretty-printed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([_finding_to_dict(f, redact=redact) for f in findings], indent=2),
        encoding="utf-8",
    )


def write_csv(findings: list[Finding], path: Path, redact: bool = False) -> None:
    """Write findings to a CSV file. `extra_data` is JSON-encoded into one cell."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDS)
        writer.writeheader()
        for f in findings:
            row = _finding_to_dict(f, redact=redact)
            row["extra_data"] = json.dumps(row.get("extra_data") or {}, sort_keys=True)
            writer.writerow(row)


def copy_sources(findings: list[Finding], sources_dir: Path) -> None:
    """Copy source conversation files for each finding into sources/<tool>/."""
    seen: set[Path] = set()
    for f in findings:
        if f.file_path in seen:
            continue
        seen.add(f.file_path)
        if not f.file_path.exists():
            continue
        dest_dir = sources_dir / f.tool
        dest_dir.mkdir(parents=True, exist_ok=True)
        file_hash = hashlib.sha256(str(f.file_path).encode()).hexdigest()[:12]
        dest = dest_dir / f"{file_hash}{f.file_path.suffix}"
        shutil.copy2(f.file_path, dest)
