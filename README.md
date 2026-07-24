# Perfilador-de-Anti-Bot

Diagnostica qué protección anti-bot tiene un sitio web y recomienda la estrategia de scraping adecuada.

### Instalación

```
python -m venv .venv
source .venv/bin/activate   #Se recomienda usar en Linux
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .

```

## Phase 1 review, What we have (Temporal)

- **models.py**:	El vocabulario. ProbeResult, ProbeMatrix, ProbeOutcome
- **utils/http.py**:	Control experimental: URL canónica, cabeceras coherentes, ritmo
- **probes/base.py**"	Contrato cerrado. Cronómetro y red de seguridad que nadie puede saltarse
- **probes/naked.py**:	El grupo de control. httpx honesto
- **probes/registry.py**:	Mapa nombre → clase. El punto de extensión de la Fase 3
- **config.py**:	Variables de control, inmutables
- **orchestrator.py**:	El guardián: única pieza que construye perfiles
- **report/console.py**:	Datos crudos en tabla. Sin veredicto
cli.py	Solo parsea y delega