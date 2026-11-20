import httpx
import pytest

from app.identity.types import VerifiedIdentity
from app.security.ratelimit import RateLimiter
from app.sources.base import Category, SourceError
from app.sources.xposedornot import XON_API, XposedOrNotSource

ME = VerifiedIdentity(user_id=1, email="yo@example.com")

FOUND = {
    "BreachMetrics": {"risk": [{"risk_label": "Low", "risk_score": 3}]},
    "BreachesSummary": {"site": "SweClockers"},
    "ExposedBreaches": {
        "breaches_details": [
            {
                "breach": "SweClockers",
                "details": "En 2015 <b>SweClockers</b> sufrió una filtración.",
                "domain": "sweclockers.com",
                "industry": "Electronics",
                "logo": "Sweclockers.png",
                "password_risk": "plaintext",
                "references": "",
                "searchable": "Yes",
                "verified": "Yes",
                "xposed_data": "Usernames;Email addresses;Passwords",
                "xposed_date": "2015",
                "xposed_records": 254967,
            }
        ]
    },
    "ExposedPastes": None,
    "PasteMetrics": None,
    "PastesSummary": {"cnt": 0, "domain": "", "tmpstmp": ""},
}
NOT_FOUND = {
    "BreachMetrics": None,
    "BreachesSummary": {"site": ""},
    "ExposedBreaches": None,
    "ExposedPastes": None,
    "PasteMetrics": None,
    "PastesSummary": {"cnt": 0, "domain": "", "tmpstmp": ""},
}


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def source(sleeps):
    async def fake_sleep(seconds):
        sleeps.append(seconds)

    return XposedOrNotSource(client=httpx.AsyncClient(), user_agent="ua-test", sleep=fake_sleep)


async def test_parsea_brechas(source, respx_mock):
    route = respx_mock.get(XON_API).respond(200, json=FOUND)
    [finding] = await source.collect(ME)
    request = route.calls.last.request
    assert request.url.params["email"] == "yo@example.com"
    assert request.headers["user-agent"] == "ua-test"
    assert finding.category is Category.BREACHES and finding.code == "breach.exposed"
    assert finding.title == "SweClockers"
    assert finding.detail == "En 2015 SweClockers sufrió una filtración."
    assert finding.data["data_classes"] == ["Usernames", "Email addresses", "Passwords"]
    assert finding.data["data_classes_es"] == ["nombres de usuario", "emails", "contraseñas"]
    assert finding.data["breach_date"] == "2015"
    assert finding.data["password_risk"] == "plaintext"
    assert finding.data["is_verified"] is True


async def test_sin_brechas_200_con_nulos(source, respx_mock):
    respx_mock.get(XON_API).respond(200, json=NOT_FOUND)
    assert await source.collect(ME) == []


async def test_sin_brechas_404(source, respx_mock):
    respx_mock.get(XON_API).respond(404, json={"Error": "Not found"})
    assert await source.collect(ME) == []


async def test_429_no_reintenta(source, respx_mock, sleeps):
    route = respx_mock.get(XON_API).respond(429)
    with pytest.raises(SourceError, match="límite gratuito"):
        await source.collect(ME)
    assert route.call_count == 1 and sleeps == []


async def test_5xx_reintenta_con_backoff(source, respx_mock, sleeps):
    respx_mock.get(XON_API).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json=NOT_FOUND)]
    )
    assert await source.collect(ME) == []
    assert len(sleeps) == 1


async def test_respeta_el_cupo_gratuito_antes_de_llamar(respx_mock, redis):
    route = respx_mock.get(XON_API).respond(200, json=NOT_FOUND)
    source = XposedOrNotSource(
        client=httpx.AsyncClient(), user_agent="ua", quota=RateLimiter(redis)
    )
    for _ in range(25):
        await source.collect(ME)
    with pytest.raises(SourceError, match="límite gratuito"):
        await source.collect(ME)
    assert route.call_count == 25
