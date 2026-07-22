import time

import pytest

from scout.models import ProbeOutcome
from scout.probes.base import Probe, RawResponse
from scout.utils.http import (
    HEADERS_CHROME,
    RateLimiter,
    headers_for,
    normalize_url,
    registrable_target,
)


@pytest.mark.parametrize(
    "entrada,esperado",
    [
        ("ejemplo.com", "https://ejemplo.com/"),
        ("https://EJEMPLO.com", "https://ejemplo.com/"),
        ("https://ejemplo.com:443/x", "https://ejemplo.com/x"),
        ("http://ejemplo.com:80/x", "http://ejemplo.com/x"),
        ("https://ejemplo.com:8443/x", "https://ejemplo.com:8443/x"),
        ("https://ejemplo.com/x#ancla", "https://ejemplo.com/x"),
        ("  https://ejemplo.com/x  ", "https://ejemplo.com/x"),
    ],
)
def test_normalizacion(entrada, esperado):
    assert normalize_url(entrada) == esperado


def test_query_no_se_toca():
    url = "https://ejemplo.com/buscar?z=1&a=2&t=%20"
    assert normalize_url(url) == url


def test_path_conserva_mayusculas():
    assert normalize_url("https://EJEMPLO.com/Producto") == "https://ejemplo.com/Producto"


@pytest.mark.parametrize("mala", ["", "   ", "ftp://ejemplo.com", "https://"])
def test_urls_invalidas_fallan_pronto(mala):
    with pytest.raises(ValueError):
        normalize_url(mala)


def test_registrable_target():
    assert registrable_target("ejemplo.com/a/b?c=1") == "https://ejemplo.com"


def test_naked_no_lleva_disfraz():
    assert headers_for("naked") == {}


def test_headers_for_devuelve_copia():
    h = headers_for("chrome")
    h["user-agent"] = "manipulado"
    assert HEADERS_CHROME["user-agent"] != "manipulado"


def test_orden_de_cabeceras_se_conserva():
    claves = list(headers_for("chrome").keys())
    assert claves[0] == "sec-ch-ua"
    assert claves.index("user-agent") < claves.index("accept")


def test_ninguna_familia_declara_accept_encoding():
    for familia in ("naked", "chrome", "firefox", "safari"):
        assert "accept-encoding" not in headers_for(familia)


def test_firefox_no_manda_sec_ch_ua():
    assert "sec-ch-ua" not in headers_for("firefox")


def test_familia_desconocida_falla():
    with pytest.raises(KeyError):
        headers_for("netscape")


def test_primera_llamada_no_espera():
    rl = RateLimiter(min_interval=0.2)
    assert rl.wait() == 0.0


def test_segunda_llamada_espera():
    rl = RateLimiter(min_interval=0.15)
    rl.wait()
    inicio = time.monotonic()
    dormido = rl.wait()
    transcurrido = time.monotonic() - inicio
    assert dormido > 0
    assert transcurrido >= 0.14


class FakeProbe(Probe):
    name = "fake"
    family = "chrome"

    def __init__(self, *, respuesta=None, excepcion=None, demora=0.0, **kw):
        super().__init__(**kw)
        self.respuesta = respuesta
        self.excepcion = excepcion
        self.demora = demora
        self.headers_recibidas = None
        self.url_recibida = None

    def _execute(self, url, headers):
        self.url_recibida = url
        self.headers_recibidas = headers
        if self.demora:
            time.sleep(self.demora)
        if self.excepcion:
            raise self.excepcion
        return self.respuesta

    def _classify(self, exc):
        if isinstance(exc, TimeoutError):
            return ProbeOutcome.TIMEOUT, str(exc)
        if isinstance(exc, ConnectionResetError):
            return ProbeOutcome.CONNECTION_RESET, str(exc)
        return super()._classify(exc)


def _respuesta_ok(body="<html>ok</html>", status=200):
    return RawResponse(
        status_code=status,
        headers={"Server": "cloudflare", "CF-RAY": "abc"},
        body=body,
        cookies={"__cf_bm": "x"},
        http_version="HTTP/2",
    )


def test_el_perfil_recibe_la_url_ya_normalizada():
    p = FakeProbe(respuesta=_respuesta_ok(), rate_limiter=RateLimiter(0))
    p.run("EJEMPLO.com")
    assert p.url_recibida == "https://ejemplo.com/"


def test_el_perfil_recibe_las_cabeceras_de_su_familia():
    p = FakeProbe(respuesta=_respuesta_ok(), rate_limiter=RateLimiter(0))
    p.run("ejemplo.com")
    assert "sec-ch-ua" in p.headers_recibidas


def test_respuesta_ok_se_envuelve_bien():
    p = FakeProbe(respuesta=_respuesta_ok(), rate_limiter=RateLimiter(0))
    r = p.run("ejemplo.com")
    assert r.profile == "fake"
    assert r.outcome is ProbeOutcome.RESPONSE
    assert r.looks_allowed
    assert r.header("cf-ray") == "abc"
    assert r.body_sha256 is not None


def test_excepcion_no_aborta_la_tanda():
    p = FakeProbe(excepcion=ConnectionResetError("reset"), rate_limiter=RateLimiter(0))
    r = p.run("ejemplo.com")
    assert r.outcome is ProbeOutcome.CONNECTION_RESET
    assert r.outcome.blocked_below_http
    assert "reset" in r.error_detail


def test_excepcion_no_clasificada_no_se_adivina():
    p = FakeProbe(excepcion=ValueError("raro"), rate_limiter=RateLimiter(0))
    r = p.run("ejemplo.com")
    assert r.outcome is ProbeOutcome.UNKNOWN_ERROR
    assert "ValueError" in r.error_detail


def test_el_cronometro_no_incluye_la_espera_del_limiter():
    rl = RateLimiter(min_interval=0.3)
    rl.wait()
    p = FakeProbe(respuesta=_respuesta_ok(), rate_limiter=rl)
    inicio = time.monotonic()
    r = p.run("ejemplo.com")
    reloj_de_pared = (time.monotonic() - inicio) * 1000
    assert reloj_de_pared >= 250
    assert r.elapsed_ms < 100


def test_el_cronometro_mide_la_peticion_de_verdad():
    p = FakeProbe(respuesta=_respuesta_ok(), demora=0.12, rate_limiter=RateLimiter(0))
    r = p.run("ejemplo.com")
    assert r.elapsed_ms >= 110


def test_el_cronometro_tambien_mide_los_fallos():
    p = FakeProbe(excepcion=TimeoutError("agotado"), demora=0.1, rate_limiter=RateLimiter(0))
    r = p.run("ejemplo.com")
    assert r.outcome is ProbeOutcome.TIMEOUT
    assert r.elapsed_ms >= 90
