'''
CLI. Just parse the parameters
Zero network logic, zero analisys
'''

from __future__ import annotations

import json

import typer

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
    if verbose:
        for r in matrix.results:
            report.render_headers(r)
 
 
@app.command()
def profiles() -> None:
    for name in registry.available():
        marca = "*" if name in registry.DEFAULT_PROFILES else " "
        typer.echo(f" {marca} {name}")
    typer.echo("\n* = To default")
 
 
if __name__ == "__main__":
    app()
