import re
from collections.abc import Iterator
from dataclasses import dataclass, field

import fakeredis
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.identity.types import VerifiedIdentity
from app.jobs.store import ResultStore
from app.jobs.worker import run_source_job
from app.main import create_app
from app.security.middleware import CSRF_COOKIE
from app.sources.hibp import HibpSource

BASE_URL = "https://testserver"


@dataclass
class FakeMailer:
    sent: list[tuple[str, str, str]] = field(default_factory=list)

    async def send(self, to: str, subject: str, body: str) -> None:
        self.sent.append((to, subject, body))

    def last_otp(self) -> str:
        match = re.search(r"Código: (\d{6})", self.sent[-1][2])
        assert match
        return match.group(1)

    def last_link_token(self) -> str:
        match = re.search(r"/verificar#t=(\S+)", self.sent[-1][2])
        assert match
        return match.group(1)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        environment="test",
        secret_key="clave-de-prueba-" + "x" * 32,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        public_base_url=BASE_URL,
        hibp_api_key="clave-hibp-de-prueba",
        rate_limit_global_per_minute=1000,
        mail_backend="console",
    )


@pytest.fixture
def mailer() -> FakeMailer:
    return FakeMailer()


@pytest.fixture
def redis() -> fakeredis.aioredis.FakeRedis:
    return fakeredis.aioredis.FakeRedis()


@dataclass
class InlineJobQueue:
    """Ejecuta el job en el momento con el mismo código que el worker de arq."""

    ctx: dict
    calls: list[tuple[str, str, VerifiedIdentity]] = field(default_factory=list)

    async def enqueue(self, job_id: str, source_name: str, identity: VerifiedIdentity) -> None:
        self.calls.append((job_id, source_name, identity))
        await run_source_job(
            self.ctx,
            job_id=job_id,
            source_name=source_name,
            user_id=identity.user_id,
            email=identity.email,
        )

    async def close(self) -> None:
        return None


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def hibp_source(settings, sleeps) -> HibpSource:
    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    return HibpSource(
        api_key=settings.hibp_api_key.get_secret_value(),
        user_agent=settings.hibp_user_agent,
        client=httpx.AsyncClient(),
        max_retries=settings.hibp_max_retries,
        sleep=fake_sleep,
    )


@pytest.fixture
def job_queue(redis, settings, hibp_source) -> InlineJobQueue:
    store = ResultStore(redis, settings.result_ttl_seconds)
    return InlineJobQueue({"store": store, "sources": {hibp_source.name: hibp_source}})


@pytest.fixture
def app(settings, redis, mailer, job_queue) -> FastAPI:
    return create_app(settings, redis=redis, mailer=mailer, job_queue=job_queue)


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app, base_url=BASE_URL) as test_client:
        yield test_client


def csrf(client: TestClient) -> dict[str, str]:
    if CSRF_COOKIE not in client.cookies:
        client.get("/healthz")
        client.get("/api/me")
    return {"X-CSRF-Token": client.cookies[CSRF_COOKIE]}


def post(client: TestClient, path: str, **kwargs):
    headers = {**csrf(client), **kwargs.pop("headers", {})}
    return client.post(path, headers=headers, **kwargs)


def login(client: TestClient, mailer: FakeMailer, email: str = "yo@example.com") -> None:
    assert post(client, "/api/auth/start", json={"email": email}).status_code == 202
    response = post(
        client, "/api/auth/verify-code", json={"email": email, "code": mailer.last_otp()}
    )
    assert response.status_code == 200, response.text
