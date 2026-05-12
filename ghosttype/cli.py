from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from ghosttype.report import copy_sources, write_csv, write_json
from ghosttype.scanner import Orchestrator

console = Console()


@click.group()
def cli() -> None:
    """ghosttype - extract credentials from AI tool conversation history."""


@cli.command()
@click.option("--tool", default=None, help="Scan only this tool (cursor, chatgpt, codex, claude, claude_code)")
@click.option("--format", "fmt", default="both", type=click.Choice(["json", "csv", "both"]), show_default=True)
@click.option("--output", default="./ghosttype_report", show_default=True, help="Output directory")
@click.option("--no-redact", is_flag=True, default=False, help="Show plaintext secret values in CSV")
@click.option("--context-window", default=200, show_default=True, help="Context characters around each match")
def scan(tool: str | None, fmt: str, output: str, no_redact: bool, context_window: int) -> None:
    """Scan AI tool conversation files for credentials and secrets."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]ghosttype[/bold] scanning... output -> [cyan]{out_dir}[/cyan]")

    orch = Orchestrator(context_window=context_window)
    findings = orch.run(tool_filter=tool)

    if not findings:
        console.print("[yellow]No findings.[/yellow]")
    else:
        console.print(f"[green]{len(findings)} finding(s) discovered.[/green]")

    if fmt in ("json", "both"):
        write_json(findings, out_dir / "findings.json")
    if fmt in ("csv", "both"):
        write_csv(findings, out_dir / "findings.csv", redact=not no_redact)

    if findings:
        copy_sources(findings, out_dir / "sources")

    _print_summary(findings)


@cli.command("list-tools")
def list_tools() -> None:
    """Show which AI tools are detected on this machine."""
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


def _print_summary(findings: list) -> None:
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
