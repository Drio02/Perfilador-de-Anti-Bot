import httpx
import pytest
import respx

from scout.models import ProbeOutcome
from scout.probes.naked import NakedProbe
from scout.utils.http import RateLimiter

URL = "https://ejemplo.com/"


def _probe():
    return NakedProbe(rate_limiter=RateLimiter(0), timeout=5.0)


@respx.mock
def test_respuesta_200_se_envuelve():
    respx.get(URL).mock(
        return_value=httpx.Response(200, html="<html>ok</html>", headers={"Server": "nginx"})
    )
    r = _probe().run(URL)
    assert r.outcome is ProbeOutcome.RESPONSE
    assert r.looks_allowed
    assert r.header("server") == "nginx"
    assert r.body_sha256 is not None


@respx.mock
def test_403_es_respuesta_no_error():
    respx.get(URL).mock(return_value=httpx.Response(403, text="denegado"))
    r = _probe().run(URL)
    assert r.outcome is ProbeOutcome.RESPONSE
    assert r.looks_denied


@respx.mock
def test_redirecciones_se_registran():
    respx.get(URL).mock(
        return_value=httpx.Response(302, headers={"Location": "https://ejemplo.com/final"})
    )
    respx.get("https://ejemplo.com/final").mock(return_value=httpx.Response(200, text="ok"))
    r = _probe().run(URL)
    assert r.final_url == "https://ejemplo.com/final"
    assert r.redirect_chain == [URL]


@respx.mock
@pytest.mark.parametrize(
    "exc,esperado",
    [
        (httpx.ConnectError("SSL: handshake failure"), ProbeOutcome.TLS_ERROR),
        (httpx.ConnectError("Name or service not known"), ProbeOutcome.DNS_ERROR),
        (httpx.ConnectError("Connection refused"), ProbeOutcome.CONNECT_ERROR),
        (httpx.ConnectTimeout("agotado"), ProbeOutcome.TIMEOUT),
        (httpx.ReadTimeout("lento"), ProbeOutcome.TIMEOUT),
        (httpx.TooManyRedirects("bucle"), ProbeOutcome.TOO_MANY_REDIRECTS),
        (httpx.RemoteProtocolError("reset"), ProbeOutcome.CONNECTION_RESET),
    ],
)
def test_clasificacion_de_errores(exc, esperado):
    respx.get(URL).mock(side_effect=exc)
    r = _probe().run(URL)
    assert r.outcome is esperado
    assert r.error_detail


@respx.mock
def test_el_fallo_no_propaga():
    respx.get(URL).mock(side_effect=httpx.ConnectError("SSL error"))
    r = _probe().run(URL)
    assert r.outcome.blocked_below_http
