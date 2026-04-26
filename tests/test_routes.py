from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from fastapi_auth.config import AuthConfig
from fastapi_auth.routes import include_auth_router

from tests.conftest import User

pytestmark = pytest.mark.asyncio

GOOD_PW = "correcthorsebatterystaple"


@pytest_asyncio.fixture
async def app(db_session: AsyncSession) -> FastAPI:
    async def _session_dep() -> AsyncIterator[AsyncSession]:
        yield db_session

    config = AuthConfig(
        secret_key="x" * 32,
        user_model=User,
        db_session_dep=_session_dep,
        cookie_secure=False,  # tests run over plain HTTP
    )
    fastapi_app = FastAPI()
    include_auth_router(fastapi_app, config)
    return fastapi_app


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


async def _register(
    client: AsyncClient,
    *,
    email: str = "alice@example.com",
    password: str = GOOD_PW,
) -> dict[str, Any]:
    r = await client.post(
        "/auth/register", json={"email": email, "password": password}
    )
    assert r.status_code == 201, r.text
    return r.json()


class TestRegister:
    async def test_returns_token_and_user(self, client: AsyncClient) -> None:
        r = await client.post(
            "/auth/register",
            json={"email": "alice@example.com", "password": GOOD_PW},
        )
        assert r.status_code == 201
        body = r.json()
        assert isinstance(body["token"], str) and len(body["token"]) > 20
        assert body["user"]["email"] == "alice@example.com"
        assert "id" in body["user"]

    async def test_sets_session_cookie(self, client: AsyncClient) -> None:
        r = await client.post(
            "/auth/register",
            json={"email": "alice@example.com", "password": GOOD_PW},
        )
        assert "session" in r.cookies

    async def test_duplicate_email_409(self, client: AsyncClient) -> None:
        await _register(client)
        r = await client.post(
            "/auth/register",
            json={"email": "alice@example.com", "password": GOOD_PW},
        )
        assert r.status_code == 409

    async def test_invalid_email_422(self, client: AsyncClient) -> None:
        r = await client.post(
            "/auth/register",
            json={"email": "not-an-email", "password": GOOD_PW},
        )
        assert r.status_code == 422


class TestLogin:
    async def test_correct_password(self, client: AsyncClient) -> None:
        await _register(client)
        r = await client.post(
            "/auth/login",
            json={"email": "alice@example.com", "password": GOOD_PW},
        )
        assert r.status_code == 200
        body = r.json()
        assert "token" in body
        assert body["user"]["email"] == "alice@example.com"

    async def test_wrong_password_401(self, client: AsyncClient) -> None:
        await _register(client)
        r = await client.post(
            "/auth/login",
            json={"email": "alice@example.com", "password": "wrong-pw"},
        )
        assert r.status_code == 401

    async def test_unknown_email_401(self, client: AsyncClient) -> None:
        r = await client.post(
            "/auth/login",
            json={"email": "ghost@example.com", "password": GOOD_PW},
        )
        assert r.status_code == 401

    async def test_login_issues_distinct_session(
        self, client: AsyncClient
    ) -> None:
        reg = await _register(client)
        r = await client.post(
            "/auth/login",
            json={"email": "alice@example.com", "password": GOOD_PW},
        )
        assert r.json()["token"] != reg["token"]


class TestMe:
    async def test_via_bearer_only(self, client: AsyncClient) -> None:
        body = await _register(client)
        token = body["token"]
        client.cookies.clear()
        r = await client.get(
            "/auth/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200
        assert r.json()["email"] == "alice@example.com"

    async def test_via_cookie_only(self, client: AsyncClient) -> None:
        await _register(client)
        # No bearer header — cookie jar carries the session cookie automatically.
        r = await client.get("/auth/me")
        assert r.status_code == 200
        assert r.json()["email"] == "alice@example.com"

    async def test_no_token_401(self, client: AsyncClient) -> None:
        r = await client.get("/auth/me")
        assert r.status_code == 401

    async def test_garbage_token_401(self, client: AsyncClient) -> None:
        r = await client.get(
            "/auth/me", headers={"Authorization": "Bearer not-a-real-token"}
        )
        assert r.status_code == 401


class TestLogout:
    async def test_revokes_session(self, client: AsyncClient) -> None:
        body = await _register(client)
        token = body["token"]
        r = await client.post(
            "/auth/logout", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 204
        client.cookies.clear()
        r = await client.get(
            "/auth/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 401

    async def test_no_token_still_204(self, client: AsyncClient) -> None:
        r = await client.post("/auth/logout")
        assert r.status_code == 204
