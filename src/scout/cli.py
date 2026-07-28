'''
CLI. Just parse the parameters
Zero network logic, zero analisys
'''

from __future__ import annotations

import json

import typer

from rich.console import Console
from rich.table import Table

from scout.config import ScanConfig
from scout.orchestrator import scan as run_scan
from scout.probes import registry
from scout.report import console as report

app = typer.Typer(add_completion=False, help="Diagnoses anti-bot protections.")

@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL"),
    profiles: str = typer.Option(
        None, "--profiles", "-p", help="Profiles separate for ','"
    ),
    timeout: float = typer.Option(None, "--timeout", "-t"),
    delay: float = typer.Option(None, "--delay", "-d", help="Seconds between probes"),
    proxy: str = typer.Option(None, "--proxy"),
    as_json: bool = typer.Option(False, "--json", help="Output JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Raw header"),
) -> None:
    base = ScanConfig.from_env()
    config = ScanConfig(
        timeout=timeout if timeout is not None else base.timeout,
        probe_delay=delay if delay is not None else base.probe_delay,
        proxy=proxy or base.proxy,
    )
 
    seleccion = (
        tuple(p.strip() for p in profiles.split(",") if p.strip())
        if profiles
        else registry.DEFAULT_PROFILES
    )
 
    try:
        matrix = run_scan(url, profiles=seleccion, config=config)
    except (ValueError, KeyError) as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(code=2) from None
 
    if as_json:
        typer.echo(json.dumps(matrix.model_dump(mode="json"), indent=2, ensure_ascii=False))
        return
 
    report.render_matrix(matrix)
    report.render_diagnosis(matrix)
    if verbose:
        for r in matrix.results:
            report.render_headers(r)
 
 
@app.command()
def profiles() -> None:
    for name in registry.available():
        marca = "*" if name in registry.DEFAULT_PROFILES else " "
        typer.echo(f" {marca} {name}")
    typer.echo("\n* = To default")

@app.command()
def profiles() -> None:
    """List available profiles and how use them""" 
    console = Console()
    table = Table(title="Available profiles", header_style="bold")
    table.add_column("profile")
    table.add_column("impersonte browser")
    table.add_column("headers family")
    table.add_column("default", justify="center")
 
    for name in registry.available():
        info = registry.describe(name)
        browser = "nothing (honest control)" if info["impersonate"] == "-" else info["impersonate"]
        point = "[green]yes[/green]" if info["is_default"] else ""
        table.add_row(name, browser, info["family"], point)
 
    console.print(table)
 
    defaults = ", ".join(registry.DEFAULT_PROFILES)
    all = ",".join(registry.available())
    console.print("\n[bold]Use:[/bold]")
    console.print(f"  By defult probe with: [cyan]{defaults}[/cyan]")
    console.print("  To choice anothers, pass them separated by commas:")
    console.print(f"    [dim]scout scan <url> --profiles {all}[/dim]")
    console.print("  Just one profile:")
    console.print("    [dim]scout scan <url> --profiles chrome131[/dim]")

if __name__ == "__main__":
    app()
