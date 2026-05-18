from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
from pathlib import Path

from ghosttype.models import Finding

# Report files carry plaintext discovered credentials by design (the authorized
# pentest/DLP deliverable; --redact masks them when not needed). They are
# written owner-only so the at-rest blast radius is the operator's account,
# not the filesystem's default umask. The fd is restricted with fchmod BEFORE
# any bytes are written — this is race-free for both the new-file case (created
# 0600) and the prior-run-left-a-0644-file case (truncated empty, then chmod'd
# to 0600 while still empty, then the secret bytes are written). No
# write-then-chmod TOCTOU window where secret content sits world-readable.
_OWNER_ONLY = 0o600


def _secure_opener(path: str, flags: int) -> int:
    fd = os.open(path, flags, _OWNER_ONLY)
    os.fchmod(fd, _OWNER_ONLY)
    return fd

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


_REDACTED = "***REDACTED***"


def _scrub(obj, secret: str):
    """Recursively replace every occurrence of `secret` with the redaction
    marker. --redact must mask the secret *everywhere it appears*, not only in
    the secret_value field — the context window (and TruffleHog extra_data)
    embed the raw value verbatim, so a redacted report was still fully
    recoverable without this."""
    if not secret:
        return obj
    if isinstance(obj, str):
        return obj.replace(secret, _REDACTED)
    if isinstance(obj, dict):
        return {k: _scrub(v, secret) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v, secret) for v in obj]
    return obj


def finding_to_dict(f: Finding, redact: bool = False) -> dict:
    """Serialize a Finding to the report dict. Public serialization API —
    stdout, JSON file, and CSV all go through this so the schema and the
    --redact policy are defined in exactly one place."""
    return {
        "tool": f.tool,
        "source": f.source,
        "secret_type": f.secret_type,
        "detector_name": f.detector_name,
        "severity": f.severity,
        "verified": f.verified,
        # TruffleHog's live verifier echoes provider API error bodies here,
        # and some providers include the submitted token verbatim
        # (e.g. "invalid token 'ghp_…'"). --redact must scrub it like every
        # other field or a "redacted" report still leaks the credential.
        "verification_error": (
            _scrub(f.verification_error, f.secret_value)
            if redact
            else f.verification_error
        ),
        "secret_value": _REDACTED if redact else f.secret_value,
        "file_path": str(f.file_path),
        "position": f.position,
        "confidence": f.confidence,
        "context": _scrub(f.context, f.secret_value) if redact else f.context,
        "discovered_at": f.discovered_at.isoformat(),
        "extra_data": (
            _scrub(f.extra_data, f.secret_value) if redact else f.extra_data
        ),
    }


# Back-compat alias. The underscore name was the historical import path
# (cli.py, tests). `finding_to_dict` is now the public contract; keep the
# old name bound to it so a future report.py refactor can't silently break
# external callers.
_finding_to_dict = finding_to_dict


def write_json(findings: list[Finding], path: Path, redact: bool = False) -> None:
    """Write findings to a JSON file (UTF-8, pretty-printed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", opener=_secure_opener) as fh:
        fh.write(
            json.dumps(
                [finding_to_dict(f, redact=redact) for f in findings], indent=2
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
            row = finding_to_dict(f, redact=redact)
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
