"""TruffleHog subprocess engine — the credential detection + verification core.

ghosttype invokes the TruffleHog binary (`trufflehog`) as a subprocess in
`filesystem` mode against a temp directory containing one file per extracted
text chunk. Each result line is parsed back into a Finding, with the
originating ConversationRecord recovered via the deterministic filename.

Why subprocess: TruffleHog is Go. CGO bindings or a Python rewrite both wildly
outscope ghosttype's purpose (discover where AI tools store conversations).
Subprocess + NDJSON is the right boundary: TruffleHog owns detection and
verification; ghosttype owns discovery and reporting.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from ghosttype.models import ConversationRecord, Finding, TextChunk

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_CONTEXT_WINDOW = 200
_SAFE_NAME_RE = re.compile(r"[^\w.-]+")

# Detectors whose verified hits warrant `critical` severity. Anything else
# defaults to `high` when verified, `medium` when unverified.
_CRITICAL_DETECTORS = frozenset({
    "aws",
    "anthropic",
    "openai",
    "github",
    "githuboldformat",
    "githubapp",
    "stripe",
    "privatekey",
    "vault",
    "hashicorpvault",
    "gcpapikey",
    "gcp",
    "azurecontainerregistry",
    "azurestorage",
    "databricks",
    "snowflake",
})


class TruffleHogError(RuntimeError):
    """Base class for TruffleHog engine errors."""


class TruffleHogNotFoundError(TruffleHogError):
    """Raised when the TruffleHog binary cannot be located on PATH."""


class TruffleHogExecutionError(TruffleHogError):
    """Raised when the TruffleHog process exits non-zero with no findings."""


def resolve_binary(binary: str | None = None) -> str:
    """Resolve the TruffleHog binary path.

    Precedence: explicit arg > GHOSTTYPE_TRUFFLEHOG_BIN env > `trufflehog` on PATH.
    Raises TruffleHogNotFoundError with an actionable message if none works.
    """
    candidate = binary or os.environ.get("GHOSTTYPE_TRUFFLEHOG_BIN") or "trufflehog"
    resolved = shutil.which(candidate)
    if resolved is None:
        raise TruffleHogNotFoundError(
            f"TruffleHog binary not found: {candidate!r}\n"
            f"  Install: https://github.com/trufflesecurity/trufflehog#installation\n"
            f"  Or set GHOSTTYPE_TRUFFLEHOG_BIN to an explicit path.\n"
            f"  Or pass --trufflehog-binary /path/to/trufflehog."
        )
    return resolved


def trufflehog_version(binary: str | None = None) -> str:
    """Return the resolved `trufflehog --version` line. Raises on missing binary."""
    resolved = resolve_binary(binary)
    proc = subprocess.run(
        [resolved, "--version"], capture_output=True, text=True, timeout=10
    )
    # trufflehog prints version to stderr; fall back to stdout if empty.
    return (proc.stderr or proc.stdout).strip()


def _safe(s: str, maxlen: int = 64) -> str:
    cleaned = _SAFE_NAME_RE.sub("_", s).strip("_")
    return (cleaned[:maxlen] or "x")


def _stage_chunks(
    tmpdir: Path, scanner_name: str, chunks: Sequence[TextChunk]
) -> dict[str, tuple[ConversationRecord, TextChunk]]:
    """Write each chunk to a deterministic file under tmpdir.

    Returns a map from absolute file path (as TruffleHog will report it) to
    (record, chunk) so results can be threaded back to their origin.
    """
    index: dict[str, tuple[ConversationRecord, TextChunk]] = {}
    for i, chunk in enumerate(chunks):
        # Whitespace-only chunks can't carry a credential; staging them just
        # makes TruffleHog scan empty temp files.
        if not chunk.text.strip():
            continue
        rec = chunk.record
        name = (
            f"{_safe(scanner_name)}__"
            f"{_safe(rec.conversation_id)}__"
            f"{_safe(chunk.position)}__"
            f"{i:06d}.txt"
        )
        dst = tmpdir / name
        dst.write_text(chunk.text, encoding="utf-8")
        index[str(dst.resolve())] = (rec, chunk)
    return index


def _build_argv(
    binary: str,
    tmpdir: Path,
    *,
    verify: bool,
    only_verified: bool,
    concurrency: int,
    detector_timeout: str,
) -> list[str]:
    # Defense-in-depth for programmatic callers (the CLI guards this too, but
    # scan_chunks/_build_argv is a public entrypoint). verify=False emits
    # --no-verification; only_verified=True emits --results=verified; together
    # they filter out every finding and exit 0 — a silent false "all clear".
    if not verify and only_verified:
        raise ValueError(
            "only_verified=True is incompatible with verify=False: "
            "--no-verification marks every finding unverified and "
            "--results=verified then drops them all."
        )
    argv: list[str] = [
        binary,
        "filesystem",
        "--json",
        "--no-update",
        f"--concurrency={concurrency}",
        f"--detector-timeout={detector_timeout}",
    ]
    if not verify:
        argv.append("--no-verification")
    if only_verified:
        argv.append("--results=verified")
    else:
        # Surface every category by default. TruffleHog's own default is
        # `verified,unverified,unknown`; we make it explicit so behavior is
        # deterministic across versions.
        argv.append("--results=verified,unverified,unknown")
    argv.append(str(tmpdir))
    return argv


def _severity_for(detector_lower: str, verified: bool) -> str:
    if verified:
        return "critical" if detector_lower in _CRITICAL_DETECTORS else "high"
    return "high" if detector_lower in _CRITICAL_DETECTORS else "medium"


def _context_window(text: str, value: str, window: int) -> str:
    if not text or not value:
        return ""
    idx = text.find(value)
    if idx < 0:
        return text[:window]
    start = max(0, idx - window // 2)
    end = min(len(text), idx + len(value) + window // 2)
    return text[start:end]


def _parse_event(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        logger.debug("Skipping non-JSON trufflehog line: %r", line[:120])
        return None
    # TruffleHog emits result events with a DetectorName; anything else
    # (informational messages, summaries, errors as JSON) is ignored.
    if not isinstance(event, dict) or "DetectorName" not in event:
        return None
    return event


def scan_chunks(
    scanner_name: str,
    chunks: Sequence[TextChunk],
    *,
    verify: bool = True,
    only_verified: bool = False,
    binary: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    context_window: int = DEFAULT_CONTEXT_WINDOW,
    concurrency: int = 10,
    detector_timeout: str = "10s",
    verbose: bool = False,
) -> list[Finding]:
    """Run TruffleHog over the given chunks; return findings.

    Args:
        scanner_name: the ghosttype scanner tag (e.g. "claude_code").
        chunks: list of TextChunk produced by a scanner's extract_text().
        verify: if False, pass --no-verification (skip live verifier calls).
        only_verified: if True, pass --results=verified.
        binary: explicit path to trufflehog; otherwise discover via PATH.
        timeout: hard outer timeout in seconds for the subprocess.
        context_window: characters of surrounding context to capture per finding.
        concurrency: TruffleHog `--concurrency`.
        detector_timeout: TruffleHog `--detector-timeout`.

    Returns:
        list of Finding objects (possibly empty).

    Raises:
        TruffleHogNotFoundError: binary missing.
        TruffleHogExecutionError: subprocess exited non-zero with no findings.
    """
    if not chunks:
        return []

    resolved = resolve_binary(binary)
    tmpdir = Path(tempfile.mkdtemp(prefix="ghosttype-th-"))
    try:
        index = _stage_chunks(tmpdir, scanner_name, chunks)
        if not index:
            return []
        argv = _build_argv(
            resolved,
            tmpdir,
            verify=verify,
            only_verified=only_verified,
            concurrency=concurrency,
            detector_timeout=detector_timeout,
        )
        if verbose:
            logger.info(
                "trufflehog: scanning %d chunks from %s (verify=%s, only_verified=%s)",
                len(index), scanner_name, verify, only_verified,
            )
            logger.info("trufflehog argv: %s", " ".join(argv))
        else:
            logger.debug("Invoking trufflehog: %s", " ".join(argv))
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TruffleHogExecutionError(
                f"trufflehog timed out after {timeout}s on {tmpdir}"
            ) from exc
        if verbose and proc.stderr:
            # Surface TruffleHog's own info/error log lines so the user can
            # watch progress when running with --verbose.
            for stderr_line in proc.stderr.splitlines():
                logger.info("trufflehog: %s", stderr_line)

        findings: list[Finding] = []
        for raw_line in (proc.stdout or "").splitlines():
            event = _parse_event(raw_line)
            if event is None:
                continue
            path = (
                event.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("file")
            )
            line_num = (
                event.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("line")
            )
            mapped = index.get(path) if path else None
            if mapped is None and path:
                # TruffleHog may emit absolute paths with symlinks resolved
                # differently than what we wrote; try a basename match as a
                # last resort.
                base = Path(path).name
                for key, value in index.items():
                    if Path(key).name == base:
                        mapped = value
                        break
            if mapped is None:
                logger.debug("Trufflehog result without source mapping: %s", path)
                continue
            record, chunk = mapped

            detector_name = str(event.get("DetectorName") or "")
            detector_lower = detector_name.lower().replace(" ", "")
            secret_value = str(event.get("Raw") or event.get("RawV2") or "")
            verified = bool(event.get("Verified", False))
            verification_error = event.get("VerificationError") or None
            extra_data = event.get("ExtraData") or {}
            position = (
                f"{chunk.position}:line{line_num}"
                if line_num is not None
                else chunk.position
            )
            context = _context_window(chunk.text, secret_value, context_window)
            findings.append(
                Finding(
                    tool=scanner_name,
                    secret_type=detector_lower or "unknown",
                    secret_value=secret_value,
                    file_path=record.source_path,
                    position=position,
                    confidence="verified" if verified else "unverified",
                    context=context,
                    discovered_at=datetime.now(timezone.utc),
                    severity=_severity_for(detector_lower, verified),
                    verified=verified,
                    detector_name=detector_name,
                    verification_error=verification_error,
                    extra_data=dict(extra_data) if isinstance(extra_data, dict) else {},
                )
            )

        if proc.returncode not in (0, 183):
            # 0 = success no findings, 183 = trufflehog's "findings present"
            # exit (when --fail is set; we don't pass --fail but tolerate it).
            stderr_tail = (proc.stderr or "").strip().splitlines()[-10:]
            if not findings:
                raise TruffleHogExecutionError(
                    "trufflehog exited "
                    f"{proc.returncode} with no findings.\n"
                    f"argv: {' '.join(argv)}\n"
                    f"stderr (tail): {chr(10).join(stderr_tail)}"
                )
            # Findings WERE emitted but the process still failed (e.g. a
            # permission error part-way through the corpus). Previously the
            # `and not findings` guard swallowed this: a partial scan was
            # returned indistinguishably from a clean, complete one — the
            # worst failure mode for a secret scanner. Make it loud. The
            # logger has no handler by default, so this reaches stderr via
            # logging.lastResort even without --verbose.
            logger.warning(
                "trufflehog exited %d AFTER emitting %d finding(s) — the scan "
                "is PARTIAL and may have missed credentials in unscanned "
                "files. argv: %s | stderr (tail): %s",
                proc.returncode,
                len(findings),
                " ".join(argv),
                " / ".join(stderr_tail),
            )
        return findings
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
