from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
from pathlib import Path

from ghosttype.models import Finding

# Report files carry plaintext discovered credentials by design (the authorized
# pentest/DLP deliverable; --redact masks them when not needed). They are still
# written owner-only so the at-rest blast radius is the operator's account, not
# the filesystem's default umask. Created restricted via the opener, and
# re-restricted in case a prior run left a wider-mode file in place.
_OWNER_ONLY = 0o600


def _secure_opener(path: str, flags: int) -> int:
    return os.open(path, flags, _OWNER_ONLY)

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
    with open(path, "w", encoding="utf-8", opener=_secure_opener) as fh:
        fh.write(
            json.dumps(
                [_finding_to_dict(f, redact=redact) for f in findings], indent=2
            )
        )
    os.chmod(path, _OWNER_ONLY)


def write_csv(findings: list[Finding], path: Path, redact: bool = False) -> None:
    """Write findings to a CSV file. `extra_data` is JSON-encoded into one cell."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(
        path, "w", newline="", encoding="utf-8", opener=_secure_opener
    ) as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDS)
        writer.writeheader()
        for f in findings:
            row = _finding_to_dict(f, redact=redact)
            row["extra_data"] = json.dumps(row.get("extra_data") or {}, sort_keys=True)
            writer.writerow(row)
    os.chmod(path, _OWNER_ONLY)


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
