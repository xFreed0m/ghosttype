from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from ghosttype.models import Finding
from ghosttype.report import copy_sources as copy_sources_fn, write_csv, write_json
from ghosttype.scanner import Orchestrator

console = Console()

_BANNER = """
   .--.        [bold cyan]ghosttype[/bold cyan] [dim]v0.1.0[/dim]
 .(    ).
(_      _)     [dim]credential scanner for AI tool conversations[/dim]
(  `~~~~'  )
`----------'   [dim red]authorized use only[/dim red]
"""


@click.group()
def cli() -> None:
    """ghosttype - extract credentials from AI tool conversation history."""


@cli.command()
@click.option(
    "--tool",
    default=None,
    type=click.Choice(["cursor", "chatgpt", "codex", "claude", "claude_code"]),
    help="Scan only this tool",
)
@click.option("--format", "fmt", default="both", type=click.Choice(["json", "csv", "both"]), show_default=True)
@click.option("--output", default="./ghosttype_report", show_default=True, help="Output directory")
@click.option("--no-redact", is_flag=True, default=False, help="Show plaintext secret values in output files")
@click.option("--context-window", default=200, show_default=True, help="Context characters around each match")
@click.option("--copy-sources", is_flag=True, default=False, help="Copy source conversation files to output dir (may contain sensitive content)")
@click.option(
    "--min-confidence",
    default="medium",
    type=click.Choice(["high", "medium"]),
    show_default=True,
    help="Minimum confidence level to include (high filters out heuristic matches)",
)
def scan(
    tool: str | None,
    fmt: str,
    output: str,
    no_redact: bool,
    context_window: int,
    copy_sources: bool,
    min_confidence: str,
) -> None:
    """Scan AI tool conversation files for credentials and secrets."""
    _print_banner()
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]ghosttype[/bold] scanning... output -> [cyan]{out_dir}[/cyan]")

    orch = Orchestrator(context_window=context_window)
    findings = orch.run(tool_filter=tool)
    if min_confidence == "high":
        findings = [f for f in findings if f.confidence == "high"]

    console.print(f"[dim]Scanned {orch.files_scanned} conversation file(s)[/dim]")
    if not findings:
        console.print("[yellow]No findings.[/yellow]")
    else:
        console.print(f"[green]{len(findings)} finding(s) discovered.[/green]")

    if findings:
        if fmt in ("json", "both"):
            write_json(findings, out_dir / "findings.json", redact=not no_redact)
        if fmt in ("csv", "both"):
            write_csv(findings, out_dir / "findings.csv", redact=not no_redact)
        if copy_sources:
            copy_sources_fn(findings, out_dir / "sources")
            console.print(f"[dim]Source files copied to {out_dir / 'sources'}[/dim]")
    else:
        console.print("[dim]No output files written.[/dim]")

    _print_summary(findings)


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
    console.print(_BANNER)


def _print_summary(findings: list[Finding]) -> None:
    if not findings:
        return
    table = Table(title="Findings Summary", show_header=True)
    table.add_column("Tool")
    table.add_column("Type")
    table.add_column("Confidence")
    table.add_column("File")
    for f in findings:
        table.add_row(f.tool, f.secret_type, f.confidence, f.file_path.name)
    console.print(table)
