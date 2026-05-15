from __future__ import annotations

import csv
import hashlib
import json
import shutil
from pathlib import Path

from ghosttype.models import Finding

_FIELDS = [
    "tool",
    "secret_type",
    "severity",
    "secret_value",
    "file_path",
    "position",
    "confidence",
    "context",
    "discovered_at",
]


def _finding_to_dict(f: Finding, redact: bool = False) -> dict:
    """Convert a Finding to a dictionary for export.

    Args:
        f: The Finding to convert.
        redact: If True, replaces secret_value with a redaction marker.

    Returns:
        Dictionary with all finding fields.
    """
    return {
        "tool": f.tool,
        "secret_type": f.secret_type,
        "severity": f.severity,
        "secret_value": "***REDACTED***" if redact else f.secret_value,
        "file_path": str(f.file_path),
        "position": f.position,
        "confidence": f.confidence,
        "context": f.context,
        "discovered_at": f.discovered_at.isoformat(),
    }


def write_json(findings: list[Finding], path: Path, redact: bool = False) -> None:
    """Write findings to a JSON file.

    Creates parent directories if needed. By default, secret values are
    shown in plaintext; pass redact=True to replace them with a marker.

    Args:
        findings: List of Finding objects.
        path: Output file path.
        redact: If True, replace secret_value with "***REDACTED***".
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([_finding_to_dict(f, redact=redact) for f in findings], indent=2),
        encoding="utf-8",
    )


def write_csv(findings: list[Finding], path: Path, redact: bool = False) -> None:
    """Write findings to a CSV file.

    Creates parent directories if needed. By default, secret values are
    shown in plaintext; pass redact=True to replace them with a marker.

    Args:
        findings: List of Finding objects.
        path: Output file path.
        redact: If True, replace secret_value with "***REDACTED***".
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDS)
        writer.writeheader()
        for f in findings:
            writer.writerow(_finding_to_dict(f, redact=redact))


def copy_sources(findings: list[Finding], sources_dir: Path) -> None:
    """Copy source conversation files for each finding into sources/<tool>/.

    Deduplicates files by path; if multiple findings reference the same
    source file, only one copy is made. Files are named by SHA256 hash of
    the original path to avoid collisions.

    Args:
        findings: List of Finding objects with file_path references.
        sources_dir: Root directory for sources; subdirs created per tool.
    """
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
