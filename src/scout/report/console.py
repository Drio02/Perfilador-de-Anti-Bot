'''
Consolte report. Just raw data
'''

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from scout.fingerprints.matcher import detect
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
    table.add_column("profile")
    table.add_column("outcome")
    table.add_column("status", justify="right")
    table.add_column("http")
    table.add_column("ms", justify="right")
    table.add_column("bytes", justify="right")
    table.add_column("sha256")
    table.add_column("server")
    table.add_column("defense")

 
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
            _defense_cell(r),
        )


    console.print(table)
    _render_errors(matrix)


def _defense_cell(r: ProbeResult) -> str:
    d = detect(r)
    if not d.matches:
        return "-"
    partes = []
    for m in d.matches:
        etq = m.name
        if m.vendor_id == d.enforcer_id:
            etq = f"[red]{etq} [!][/red]"
        elif m.is_bot_defense:
            etq = f"[yellow]{etq}[/yellow]"
        else:
            etq = f"[dim]{etq}[/dim]"
        partes.append(etq)
    return ", ".join(partes)


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

def render_diagnosis(matrix: ProbeMatrix) -> None:
    from rich.panel import Panel
 
    from scout.analysis.engine import analyze
 
    d = analyze(matrix)
 
    _VERDICT_STYLE = {
        "no_protection": "green",
        "tls_fingerprint": "yellow",
        "app_fingerprint": "yellow",
        "hard_challenge": "red",
        "shadow_ban": "red",
        "indeterminate": "dim",
    }
    style = _VERDICT_STYLE.get(d.defense_type.value, "white")
 
    lineas = [f"[bold {style}]{d.defense_type.value}[/bold {style}]  (confianza {d.confidence:.0%})"]
    if d.enforcer_id:
        lineas.append(f"enforcer: {d.enforcer_id}")
    if d.evidence:
        lineas.append("\n[bold]Evidencia:[/bold]")
        lineas += [f"  • {e}" for e in d.evidence]
    if d.caveats:
        lineas.append("\n[bold]Advertencias:[/bold]")
        lineas += [f"  ⚠ {c}" for c in d.caveats]
 
    console.print(Panel("\n".join(lineas), title="Diagnóstico", border_style=style))
