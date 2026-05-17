from __future__ import annotations

import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

import click
from rich.columns import Columns
from rich.console import Console
from rich.table import Table

from ghosttype.models import Finding
from ghosttype.report import (
    copy_sources as copy_sources_fn,
    finding_to_dict,
    write_csv,
    write_json,
)
from ghosttype.scanner import Orchestrator
from ghosttype.trufflehog_engine import (
    DEFAULT_TIMEOUT_SECONDS,
    TruffleHogError,
    TruffleHogNotFoundError,
    resolve_binary,
    trufflehog_version,
)

VERSION = "0.4.0"
console = Console()

_GHOST = r'''
        .------.
       /        \
      |  o    o  |
      |    __    |
       \        /
        '------'
        /\/\/\/\
'''

_WORDMARK = r'''
       _               _   _
  __ _| |__   ___  ___| |_| |_ _   _ _ __   ___
 / _` | '_ \ / _ \/ __| __| __| | | | '_ \ / _ \
| (_| | | | | (_) \__ \ |_| |_| |_| | |_) |  __/
 \__, |_| |_|\___/|___/\__|\__|\__, | .__/ \___|
 |___/                         |___/|_|
'''


@click.group()
def cli() -> None:  # pragma: no cover - console-script entrypoint; subcommands tested directly
    """ghosttype - extract credentials from AI tool conversation history (TruffleHog-powered)."""


@cli.command()
def version() -> None:
    """Print version information."""
    console.print(f"[bold cyan]ghosttype[/bold cyan] [dim]v{VERSION}[/dim]")
    console.print(
        "[dim]credential scanner for AI tool conversation history "
        "(detection + verification by TruffleHog)[/dim]"
    )


@cli.command()
@click.option(
    "--trufflehog-binary",
    default=None,
    help="Path to the TruffleHog binary (overrides PATH and GHOSTTYPE_TRUFFLEHOG_BIN).",
)
def doctor(trufflehog_binary: str | None) -> None:
    """Check the environment ghosttype depends on (mainly TruffleHog)."""
    console.print(f"[bold]ghosttype[/bold] v{VERSION}")
    try:
        resolved = resolve_binary(trufflehog_binary)
        version_line = trufflehog_version(trufflehog_binary)
        console.print(f"  trufflehog binary: [green]{resolved}[/green]")
        console.print(f"  trufflehog version: [green]{version_line}[/green]")
    except TruffleHogNotFoundError as exc:
        console.print("[red]TruffleHog not found.[/red]")
        console.print(str(exc))
        sys.exit(2)
    except Exception as exc:  # pragma: no cover - defensive
        console.print(f"[red]doctor check failed:[/red] {exc}")
        sys.exit(2)

    from ghosttype.scanners import SCANNERS
    console.print()
    console.print("[bold]AI tools detected on this host:[/bold]")
    for scanner in SCANNERS:
        ok = scanner.is_available()
        marker = "[green]+[/green]" if ok else "[dim]-[/dim]"
        console.print(f"  {marker} {scanner.name:<14} {scanner.display_name}")


@cli.command()
@click.option(
    "--tool",
    default=None,
    type=click.Choice(["cursor", "chatgpt", "codex", "claude", "claude_code"]),
    help="Scan only this tool",
)
@click.option("--format", "fmt", default="both", type=click.Choice(["json", "csv", "both"]), show_default=True)
@click.option(
    "--output",
    default="./ghosttype_report",
    show_default=True,
    help="Output directory or - for stdout (JSON only)",
)
@click.option(
    "--engine",
    default="both",
    type=click.Choice(["both", "trufflehog", "patterns"]),
    show_default=True,
    help="Detection engine. 'both' (default) runs TruffleHog + the in-tree "
    "regex/heuristic patterns and merges (TruffleHog wins overlaps). "
    "'trufflehog' = verified detection only. 'patterns' = offline, no "
    "TruffleHog binary required, never verified.",
)
@click.option("--redact", is_flag=True, default=False, help="Redact secret values in output files")
@click.option("--context-window", default=200, show_default=True, help="Context characters around each match")
@click.option(
    "--copy-sources",
    is_flag=True,
    default=False,
    help="Copy source conversation files to output dir (may contain sensitive content)",
)
@click.option(
    "--min-confidence",
    default="unverified",
    type=click.Choice(["verified", "unverified", "high", "medium"]),
    show_default=True,
    help="Minimum confidence to include. 'verified' = TruffleHog-verified only. "
    "'unverified' includes both. ('high' and 'medium' are legacy aliases.)",
)
@click.option(
    "--only-verified",
    is_flag=True,
    default=False,
    help="Only emit findings TruffleHog actively verified (passes --results=verified).",
)
@click.option(
    "--no-verification",
    is_flag=True,
    default=False,
    help="Skip TruffleHog's live verifier calls. Faster, but every finding will be 'unverified'.",
)
@click.option(
    "--trufflehog-binary",
    default=None,
    help="Path to the TruffleHog binary (else PATH / GHOSTTYPE_TRUFFLEHOG_BIN).",
)
@click.option(
    "--trufflehog-timeout",
    default=DEFAULT_TIMEOUT_SECONDS,
    show_default=True,
    type=int,
    help="Hard outer timeout (seconds) for the TruffleHog subprocess.",
)
@click.option(
    "--allow-list",
    default=None,
    type=click.Path(exists=True),
    help="Path to file with known-safe values to suppress (one per line).",
)
@click.option("--stats-only", is_flag=True, default=False, help="Print summary statistics only, not full findings table")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress banner and progress messages (for scripting)")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Stream per-scanner chunk counts and TruffleHog's own stderr log.")
@click.option("--max-age-days", default=None, type=int, help="Only scan files modified within the last N days")
def scan(
    tool: str | None,
    fmt: str,
    output: str,
    engine: str,
    redact: bool,
    context_window: int,
    copy_sources: bool,
    min_confidence: str,
    only_verified: bool,
    no_verification: bool,
    trufflehog_binary: str | None,
    trufflehog_timeout: int,
    allow_list: str | None,
    stats_only: bool,
    quiet: bool,
    verbose: bool,
    max_age_days: int | None,
) -> None:
    """Scan AI tool conversation files for credentials and secrets.

    By default both engines run: TruffleHog (verified, structural) and the
    in-tree regex/heuristic patterns (offline, complementary). See --engine.
    """
    if only_verified and no_verification:
        # Both set => TruffleHog gets --no-verification (every finding marked
        # unverified) AND --results=verified (drops every unverified finding).
        # Net: an unconditional empty result with exit 0 — a silent false
        # "all clear". Refuse the combination instead of lying.
        raise click.UsageError(
            "--only-verified and --no-verification are mutually exclusive: "
            "--no-verification marks every finding unverified, then "
            "--only-verified filters them all out (a silent false negative)."
        )

    if verbose:
        import logging
        logging.basicConfig(level=logging.INFO, format="[ghosttype] %(message)s")
    stdout_mode = output == "-"

    if not quiet and not stdout_mode:
        _print_banner()

    if stdout_mode:
        out_dir = Path(tempfile.mkdtemp())
    else:
        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)

    if not quiet and not stdout_mode:
        console.print(f"[bold]ghosttype[/bold] scanning... output -> [cyan]{out_dir}[/cyan]")

    # Resolve trufflehog upfront so a missing binary fails fast (not after
    # discovering 500 conversation files). Skipped entirely for the
    # patterns-only engine, which needs no binary.
    resolved_binary: str | None = None
    if engine in ("both", "trufflehog"):
        binary_arg = trufflehog_binary or os.environ.get("GHOSTTYPE_TRUFFLEHOG_BIN")
        try:
            resolved_binary = resolve_binary(binary_arg)
        except TruffleHogNotFoundError as exc:
            if engine == "both":
                console.print(
                    "[yellow]TruffleHog not found — falling back to "
                    "patterns-only engine (no verification).[/yellow]\n"
                    f"[dim]{exc}[/dim]"
                )
                engine = "patterns"
            else:
                console.print(f"[red]{exc}[/red]")
                sys.exit(2)

    orch = Orchestrator(
        context_window=context_window,
        max_age_days=max_age_days,
        engine=engine,
        verify=not no_verification,
        only_verified=only_verified,
        trufflehog_binary=resolved_binary,
        timeout=trufflehog_timeout,
        verbose=verbose,
    )

    if not quiet:
        from ghosttype.scanners import SCANNERS

        active = [s for s in SCANNERS if (not tool or s.name == tool) and s.is_available()]
        console.print(
            f"[dim]Scanning {len(active)} tool(s): {', '.join(s.name for s in active)}[/dim]"
        )

    try:
        findings = orch.run(tool_filter=tool)
    except TruffleHogError as exc:
        console.print(f"[red]TruffleHog engine failed:[/red] {exc}")
        sys.exit(2)

    # Confidence filter, dual-engine aware:
    #   verified  -> only TruffleHog-verified findings
    #   high      -> verified TruffleHog OR high-confidence (regex) pattern hits;
    #                drops medium heuristic noise (legacy alias)
    #   unverified/medium -> keep everything (default)
    if min_confidence == "verified":
        findings = [f for f in findings if f.verified]
    elif min_confidence == "high":
        findings = [
            f for f in findings
            if f.verified or f.confidence in ("verified", "high")
        ]

    # Apply allow-list suppression
    suppressed_count = 0
    if allow_list:
        allowed: set[str] = set()
        with open(allow_list) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    allowed.add(line)
        suppressed_count = len([f for f in findings if f.secret_value in allowed])
        findings = [f for f in findings if f.secret_value not in allowed]
        if allowed and not quiet:
            console.print(f"[dim]Allow-list suppressed {suppressed_count} value(s)[/dim]")

    if not quiet:
        console.print(f"[dim]Scanned {orch.files_scanned} conversation file(s)[/dim]")
        if not findings:
            console.print("[yellow]No findings.[/yellow]")
        else:
            verified_count = sum(1 for f in findings if f.verified)
            console.print(
                f"[green]{len(findings)} finding(s) discovered "
                f"({verified_count} VERIFIED, {len(findings) - verified_count} unverified).[/green]"
            )

    if stdout_mode:
        # Always emit valid JSON — `[]` on zero findings, not an empty
        # string — so `ghosttype scan --output - | jq` never breaks.
        # Single serializer (report._finding_to_dict) so stdout, JSON file
        # and CSV share one schema AND one redaction policy.
        data = [finding_to_dict(f, redact=redact) for f in findings]
        sys.stdout.write(json.dumps(data, indent=2))
        sys.stdout.write("\n")
    elif findings:
        if fmt in ("json", "both"):
            write_json(findings, out_dir / "findings.json", redact=redact)
        if fmt in ("csv", "both"):
            write_csv(findings, out_dir / "findings.csv", redact=redact)
        if copy_sources:
            copy_sources_fn(findings, out_dir / "sources")
            if not quiet:
                console.print(f"[dim]Source files copied to {out_dir / 'sources'}[/dim]")
    else:
        if not quiet:
            console.print("[dim]No output files written.[/dim]")

    if not stdout_mode:
        if not stats_only:
            _print_summary(findings, orch.files_scanned)
        else:
            _print_stats_only(findings, orch.files_scanned)

    if findings:
        sys.exit(1)  # non-zero exit when credentials found - enables CI use


@cli.command("list-tools")
def list_tools() -> None:
    """Show which AI tools are detected on this machine."""
    _print_banner()
    from ghosttype.scanners import SCANNERS

    table = Table(title="AI Tools", show_header=True)
    table.add_column("Tool")
    table.add_column("Name")
    table.add_column("Status")

    for scanner in SCANNERS:
        available = scanner.is_available()
        status = "[green]detected[/green]" if available else "[dim]not found[/dim]"
        table.add_row(scanner.name, scanner.display_name, status)

    console.print(table)


def _print_banner() -> None:
    console.print(_GHOST, highlight=False, style="bold white")
    console.print(_WORDMARK, highlight=False, style="bold cyan")
    console.print(
        "  [dim]credential scanner for AI tool conversation history "
        "(TruffleHog-powered)[/dim]"
    )
    console.print(
        f"  [dim red]authorized use only[/dim red]  [dim]v{VERSION}[/dim]\n"
    )


def _print_summary(findings: list[Finding], files_scanned: int) -> None:
    if not findings:
        return

    table = Table(title="Findings Summary", show_header=True)
    table.add_column("Tool")
    table.add_column("Source")
    table.add_column("Detector")
    table.add_column("Severity")
    table.add_column("Verified")
    table.add_column("File")
    for f in findings:
        severity_style = (
            "bold red" if f.severity == "critical"
            else "yellow" if f.severity == "high"
            else "dim"
        )
        verified_cell = "[green]yes[/green]" if f.verified else "[dim]no[/dim]"
        source_cell = (
            "[cyan]trufflehog[/cyan]" if f.source == "trufflehog"
            else "[magenta]pattern[/magenta]"
        )
        table.add_row(
            f.tool,
            source_cell,
            f.detector_name or f.secret_type,
            f"[{severity_style}]{f.severity}[/{severity_style}]",
            verified_cell,
            f.file_path.name,
        )
    console.print(table)

    _print_stats_only(findings, files_scanned)


def _print_stats_only(findings: list[Finding], files_scanned: int) -> None:
    if not findings:
        return

    files_with_findings = len({f.file_path for f in findings})

    type_table = Table(title="By Detector", show_header=True, box=None)
    type_table.add_column("Detector", style="cyan")
    type_table.add_column("Count", justify="right")
    for stype, count in Counter(
        (f.detector_name or f.secret_type) for f in findings
    ).most_common():
        type_table.add_row(stype, str(count))

    tool_table = Table(title="By Tool", show_header=True, box=None)
    tool_table.add_column("Tool", style="green")
    tool_table.add_column("Count", justify="right")
    for tool, count in Counter(f.tool for f in findings).most_common():
        tool_table.add_row(tool, str(count))

    verified_table = Table(title="Verification", show_header=True, box=None)
    verified_table.add_column("State", style="magenta")
    verified_table.add_column("Count", justify="right")
    verified_count = sum(1 for f in findings if f.verified)
    verified_table.add_row("verified", str(verified_count))
    verified_table.add_row("unverified", str(len(findings) - verified_count))

    source_table = Table(title="By Source", show_header=True, box=None)
    source_table.add_column("Source", style="blue")
    source_table.add_column("Count", justify="right")
    for src, count in Counter(f.source for f in findings).most_common():
        source_table.add_row(src, str(count))

    console.print()
    console.print(Columns([type_table, tool_table, verified_table, source_table]))
    console.print(
        f"\n[dim]Files scanned: {files_scanned} | Files with findings: {files_with_findings}[/dim]"
    )
