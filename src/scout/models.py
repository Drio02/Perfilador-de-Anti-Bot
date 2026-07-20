"""
Tests de models.py.

Estos tests no tocan la red. Ese es justamente el punto de haber definido los
contratos primero: podemos construir escenarios completos a mano y desarrollar
el motor de análisis contra ellos, sin sondear nada.
"""

from scout.models import ProbeMatrix, ProbeOutcome, ProbeResult


def _ok(profile: str, body: str = "<html>hola</html>", status: int = 200) -> ProbeResult:
    return ProbeResult.from_response(
        profile=profile,
        url="https://ejemplo.com",
        status_code=status,
        headers={"Server": "cloudflare", "CF-RAY": "abc123"},
        cookies={"__cf_bm": "xyz"},
        body=body,
        elapsed_ms=120.0,
        http_version="HTTP/2",
    )


def test_cabeceras_se_normalizan_a_minusculas():
    r = _ok("chrome124")
    assert r.header("CF-RAY") == "abc123"
    assert r.header("cf-ray") == "abc123"
    assert "server" in r.headers  # guardada en minúsculas


def test_hash_y_tamano_del_cuerpo():
    r = _ok("chrome124", body="abc")
    assert r.body_size == 3
    assert r.body_sha256.startswith("ba7816bf")  # sha256("abc")


def test_cuerpo_no_se_serializa():
    r = _ok("chrome124")
    assert r.body is not None
    assert "body" not in r.model_dump()  # excluido del informe


def test_fallo_es_resultado_de_primera_clase():
    r = ProbeResult.from_failure(
        profile="naked_python",
        url="https://ejemplo.com",
        outcome=ProbeOutcome.TLS_ERROR,
        error_detail="handshake abortado por el peer",
    )
    assert r.outcome.blocked_below_http
    assert not r.outcome.reached_application
    assert not r.looks_allowed


def test_403_no_es_un_error_de_sondeo():
    r = _ok("naked_python", status=403)
    assert r.outcome is ProbeOutcome.RESPONSE  # sí hubo respuesta
    assert r.looks_denied
    assert not r.looks_allowed


def test_escenario_filtrado_por_huella_tls():
    """El caso que da valor a toda la herramienta: mismo sitio, distinto trato."""
    m = ProbeMatrix(target="https://ejemplo.com")
    m.add(
        ProbeResult.from_failure(
            profile="naked_python",
            url="https://ejemplo.com",
            outcome=ProbeOutcome.TLS_ERROR,
            error_detail="reset durante handshake",
        )
    )
    m.add(_ok("chrome124"))

    assert m.allowed_profiles == ["chrome124"]
    assert not m.all_allowed and not m.none_allowed


def test_deteccion_de_contenido_degradado():
    """Dos 200, cuerpos distintos: a alguien le sirven otra cosa."""
    m = ProbeMatrix(target="https://ejemplo.com")
    m.add(_ok("naked_python", body="<html></html>"))
    m.add(_ok("chrome124", body="<html>contenido real y largo</html>"))

    assert m.all_allowed  # ambos "pasaron"...
    assert len(set(m.body_hashes.values())) == 2  # ...pero no vieron lo mismo


def test_resultado_es_inmutable():
    r = _ok("chrome124")
    try:
        r.status_code = 500
    except Exception:
        return
    raise AssertionError("ProbeResult debería ser inmutable")