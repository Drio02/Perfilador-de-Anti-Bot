'''
Consolte report. Just raw data
'''

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from scout.models import ProbeMatrix, ProbeOutcome, ProbeResult

console = Console()

_STYLES: dict[ProbeOutcome, str] = {
    ProbeOutcome.RESPONSE: "green",
    ProbeOutcome.TLS_ERROR: "red",
    ProbeOutcome.CONNECTION_RESET: "red",
    ProbeOutcome.CONNECT_ERROR: "yellow",
    ProbeOutcome.DNS_ERROR: "yellow",
    ProbeOutcome.TIMEOUT: "yellow",
    ProbeOutcome.TOO_MANY_REDIRECTS: "yellow",
    ProbeOutcome.UNKNOWN_ERROR: "magenta",
}

def _status_cell(r: ProbeResult) -> str:
    if r.status_code is None:
        return "-"
    if r.looks_allowed:
        return f"[green]{r.status_code}[/green]"
    if r.looks_denied:
        return f"[red]{r.status_code}[/red]"
    return str(r.status_code)

def render_matrix(matrix: ProbeMatrix) -> None:
    table = Table(title=f"Probe of {matrix.target}", header_style="bold")
    table.add_column("perfil")
    table.add_column("outcome")
    table.add_column("status", justify="right")
    table.add_column("http")
    table.add_column("ms", justify="right")
    table.add_column("bytes", justify="right")
    table.add_column("sha256")
    table.add_column("server")

    for r in matrix.results:
        style = _STYLES.get(r.outcome, "white")
        table.add_row(
            r.profile,
            f"[{style}]{r.outcome.value}[/{style}]",
            _status_cell(r),
            r.http_version or "-",
            f"{r.elapsed_ms:.0f}",
            str(r.body_size) if r.body_size else "-",
            r.body_sha256[:12] if r.body_sha256 else "-",
            r.header("server") or "-",
        )

    console.print(table)
    _render_errors(matrix)

def _render_errors(matrix: ProbeMatrix) -> None:
    failes = [r for r in matrix.results if r.error_detail]
    if not failes:
        return
    console.print("\n[bold]Fails details[/bold]")
    for r in failes:
        console.print(f"  [dim]{r.profile}:[/dim] {r.error_detail}")

def render_headers(result: ProbeResult) -> None:
    """Raw headers for profiles. For --verbose."""
    if not result.headers:
        return
    table = Table(title=f"Headers · {result.profile}", header_style="bold")
    table.add_column("header")
    table.add_column("value", overflow="fold")
    for k, v in sorted(result.headers.items()):
        table.add_row(k, v)
    console.print(table)
