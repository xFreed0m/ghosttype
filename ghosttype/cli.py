from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

import click
from rich.columns import Columns
from rich.console import Console
from rich.table import Table

from ghosttype.models import Finding
from ghosttype.report import copy_sources as copy_sources_fn, write_csv, write_json
from ghosttype.scanner import Orchestrator

console = Console()

_BANNER = r"""
    .---.                   _               _   _
   ( ^ ^ )   __ _  ___     | |_  _  _ _ __| |_| |_  _ _ __  ___
    \ ~ /   / _` |/ _ \    |  _|| || | '_ \  _|  _|| || | '_ \/ -_)
   (_)-(_)  \__, |\___/    |_|   \_,_| .__/\__|\___|\_,_| .__/\___|
    /   \   |___/                     |_|                |_|
   [_____]
   |_|_|_|
"""


@click.group()
def cli() -> None:
    """ghosttype - extract credentials from AI tool conversation history."""


@cli.command()
def version() -> None:
    """Print version information."""
    console.print("[bold cyan]ghosttype[/bold cyan] [dim]v0.2.0[/dim]")
    console.print("[dim]credential scanner for AI tool conversation history[/dim]")


@cli.command()
@click.option(
    "--tool",
    default=None,
    type=click.Choice(["cursor", "chatgpt", "codex", "claude", "claude_code"]),
    help="Scan only this tool",
)
@click.option("--format", "fmt", default="both", type=click.Choice(["json", "csv", "both"]), show_default=True)
@click.option("--output", default="./ghosttype_report", show_default=True, help="Output directory or - for stdout (JSON only)")
@click.option("--redact", is_flag=True, default=False, help="Redact secret values in output files")
@click.option("--context-window", default=200, show_default=True, help="Context characters around each match")
@click.option("--copy-sources", is_flag=True, default=False, help="Copy source conversation files to output dir (may contain sensitive content)")
@click.option(
    "--min-confidence",
    default="medium",
    type=click.Choice(["high", "medium"]),
    show_default=True,
    help="Minimum confidence level to include (high filters out heuristic matches)",
)
@click.option("--allow-list", default=None, type=click.Path(exists=True), help="Path to file with known-safe values to suppress (one per line)")
@click.option("--stats-only", is_flag=True, default=False, help="Print summary statistics only, not full findings table")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress banner and progress messages (for scripting)")
@click.option("--max-age-days", default=None, type=int, help="Only scan files modified within the last N days")
def scan(
    tool: str | None,
    fmt: str,
    output: str,
    redact: bool,
    context_window: int,
    copy_sources: bool,
    min_confidence: str,
    allow_list: str | None,
    stats_only: bool,
    quiet: bool,
    max_age_days: int | None,
) -> None:
    """Scan AI tool conversation files for credentials and secrets."""
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

    orch = Orchestrator(context_window=context_window, max_age_days=max_age_days)

    if not quiet:
        from ghosttype.scanners import SCANNERS
        active = [s for s in SCANNERS if (not tool or s.name == tool) and s.is_available()]
        console.print(f"[dim]Scanning {len(active)} tool(s): {', '.join(s.name for s in active)}[/dim]")

    findings = orch.run(tool_filter=tool)
    if min_confidence == "high":
        findings = [f for f in findings if f.confidence == "high"]

    # Apply allow-list suppression
    suppressed_count = 0
    if allow_list:
        allowed = set()
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
            console.print(f"[green]{len(findings)} finding(s) discovered.[/green]")

    if findings:
        if stdout_mode:
            # Write JSON to stdout only
            data = [
                {
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
                for f in findings
            ]
            sys.stdout.write(json.dumps(data, indent=2))
            sys.stdout.write("\n")
        else:
            if fmt in ("json", "both"):
                write_json(findings, out_dir / "findings.json", redact=redact)
            if fmt in ("csv", "both"):
                write_csv(findings, out_dir / "findings.csv", redact=redact)
            if copy_sources:
                copy_sources_fn(findings, out_dir / "sources")
                if not quiet:
                    console.print(f"[dim]Source files copied to {out_dir / 'sources'}[/dim]")
    else:
        if not quiet and not stdout_mode:
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
    console.print(_BANNER, highlight=False)
    console.print(
        "  [dim]credential scanner for AI tool conversation history[/dim]"
        "  [dim red]authorized use only[/dim red]  [dim]v0.2.0[/dim]\n"
    )


def _print_summary(findings: list[Finding], files_scanned: int) -> None:
    """Print detailed findings table plus statistics."""
    if not findings:
        return

    # Print detailed findings table
    table = Table(title="Findings Summary", show_header=True)
    table.add_column("Tool")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("File")
    for f in findings:
        severity_style = (
            "bold red" if f.severity == "critical"
            else "yellow" if f.severity == "high"
            else "dim"
        )
        table.add_row(
            f.tool,
            f.secret_type,
            f"[{severity_style}]{f.severity}[/{severity_style}]",
            f.confidence,
            f.file_path.name,
        )
    console.print(table)

    # Print statistics breakdown
    _print_stats_only(findings, files_scanned)


def _print_stats_only(findings: list[Finding], files_scanned: int) -> None:
    """Print summary statistics without the full findings table."""
    if not findings:
        return

    files_with_findings = len({f.file_path for f in findings})

    # By type breakdown
    type_table = Table(title="By Type", show_header=True, box=None)
    type_table.add_column("Type", style="cyan")
    type_table.add_column("Count", justify="right")
    for stype, count in Counter(f.secret_type for f in findings).most_common():
        type_table.add_row(stype, str(count))

    # By tool breakdown
    tool_table = Table(title="By Tool", show_header=True, box=None)
    tool_table.add_column("Tool", style="green")
    tool_table.add_column("Count", justify="right")
    for tool, count in Counter(f.tool for f in findings).most_common():
        tool_table.add_row(tool, str(count))

    console.print()
    console.print(Columns([type_table, tool_table]))
    console.print(f"\n[dim]Files scanned: {files_scanned} | Files with findings: {files_with_findings}[/dim]")
