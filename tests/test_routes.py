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
async def reset_calls() -> list[tuple[Any, str]]:
    return []


@pytest_asyncio.fixture
async def app(
    db_session: AsyncSession, reset_calls: list[tuple[Any, str]]
) -> FastAPI:
    async def _session_dep() -> AsyncIterator[AsyncSession]:
        yield db_session

    async def _capture_reset(user: Any, token: str) -> None:
        reset_calls.append((user, token))

    config = AuthConfig(
        secret_key="x" * 32,
        user_model=User,
        db_session_dep=_session_dep,
        send_password_reset=_capture_reset,
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

    async def test_email_is_case_insensitive(
        self, client: AsyncClient
    ) -> None:
        # Register with mixed case, login with different mixed case → success.
        r = await client.post(
            "/auth/register",
            json={"email": "Alice@Example.com", "password": GOOD_PW},
        )
        assert r.status_code == 201
        r = await client.post(
            "/auth/login",
            json={"email": "ALICE@example.COM", "password": GOOD_PW},
        )
        assert r.status_code == 200

    async def test_duplicate_email_different_case_409(
        self, client: AsyncClient
    ) -> None:
        await _register(client, email="alice@example.com")
        r = await client.post(
            "/auth/register",
            json={"email": "ALICE@EXAMPLE.COM", "password": GOOD_PW},
        )
        assert r.status_code == 409


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


class TestRefresh:
    async def test_happy_path(self, client: AsyncClient) -> None:
        body = await _register(client)
        old_token = body["token"]
        client.cookies.clear()
        r = await client.post(
            "/auth/refresh",
            headers={"Authorization": f"Bearer {old_token}"},
        )
        assert r.status_code == 200
        new_token = r.json()["token"]
        assert new_token != old_token
        # Old token is dead.
        r = await client.get(
            "/auth/me", headers={"Authorization": f"Bearer {old_token}"}
        )
        assert r.status_code == 401
        # New token is alive.
        r = await client.get(
            "/auth/me", headers={"Authorization": f"Bearer {new_token}"}
        )
        assert r.status_code == 200

    async def test_via_cookie(self, client: AsyncClient) -> None:
        await _register(client)
        r = await client.post("/auth/refresh")
        assert r.status_code == 200

    async def test_no_token_401(self, client: AsyncClient) -> None:
        r = await client.post("/auth/refresh")
        assert r.status_code == 401

    async def test_garbage_token_401(self, client: AsyncClient) -> None:
        r = await client.post(
            "/auth/refresh",
            headers={"Authorization": "Bearer not-real"},
        )
        assert r.status_code == 401

    async def test_reuse_revokes_whole_family(
        self, client: AsyncClient
    ) -> None:
        body = await _register(client)
        t1 = body["token"]
        client.cookies.clear()
        r = await client.post(
            "/auth/refresh", headers={"Authorization": f"Bearer {t1}"}
        )
        t2 = r.json()["token"]
        r = await client.post(
            "/auth/refresh", headers={"Authorization": f"Bearer {t2}"}
        )
        t3 = r.json()["token"]
        # Attacker replays t1 — must 401 AND revoke t3 too.
        r = await client.post(
            "/auth/refresh", headers={"Authorization": f"Bearer {t1}"}
        )
        assert r.status_code == 401
        r = await client.get(
            "/auth/me", headers={"Authorization": f"Bearer {t3}"}
        )
        assert r.status_code == 401

    async def test_revoked_token_401(self, client: AsyncClient) -> None:
        body = await _register(client)
        token = body["token"]
        await client.post(
            "/auth/logout", headers={"Authorization": f"Bearer {token}"}
        )
        client.cookies.clear()
        r = await client.post(
            "/auth/refresh", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 401


class TestPasswordResetRequest:
    async def test_calls_callback_for_existing_user(
        self,
        client: AsyncClient,
        reset_calls: list[tuple[Any, str]],
    ) -> None:
        await _register(client)
        r = await client.post(
            "/auth/password-reset/request",
            json={"email": "alice@example.com"},
        )
        assert r.status_code == 204
        assert len(reset_calls) == 1
        user, token = reset_calls[0]
        assert user.email == "alice@example.com"
        assert isinstance(token, str) and token.count(".") == 2

    async def test_does_not_leak_unknown_email(
        self,
        client: AsyncClient,
        reset_calls: list[tuple[Any, str]],
    ) -> None:
        r = await client.post(
            "/auth/password-reset/request",
            json={"email": "ghost@example.com"},
        )
        assert r.status_code == 204
        assert reset_calls == []

    async def test_response_body_empty(self, client: AsyncClient) -> None:
        await _register(client)
        r = await client.post(
            "/auth/password-reset/request",
            json={"email": "alice@example.com"},
        )
        assert r.status_code == 204
        assert r.content == b""


class TestPasswordResetConfirm:
    async def test_updates_password(
        self,
        client: AsyncClient,
        reset_calls: list[tuple[Any, str]],
    ) -> None:
        await _register(client)
        await client.post(
            "/auth/password-reset/request",
            json={"email": "alice@example.com"},
        )
        token = reset_calls[0][1]
        r = await client.post(
            "/auth/password-reset/confirm",
            json={"token": token, "new_password": "newcorrecthorse"},
        )
        assert r.status_code == 204
        # Old password fails
        r = await client.post(
            "/auth/login",
            json={"email": "alice@example.com", "password": GOOD_PW},
        )
        assert r.status_code == 401
        # New password works
        r = await client.post(
            "/auth/login",
            json={
                "email": "alice@example.com",
                "password": "newcorrecthorse",
            },
        )
        assert r.status_code == 200

    async def test_revokes_existing_sessions(
        self,
        client: AsyncClient,
        reset_calls: list[tuple[Any, str]],
    ) -> None:
        body = await _register(client)
        old_session_token = body["token"]
        await client.post(
            "/auth/password-reset/request",
            json={"email": "alice@example.com"},
        )
        reset_token = reset_calls[0][1]
        await client.post(
            "/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": "newcorrecthorse"},
        )
        client.cookies.clear()
        r = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {old_session_token}"},
        )
        assert r.status_code == 401

    async def test_invalid_token_400(self, client: AsyncClient) -> None:
        r = await client.post(
            "/auth/password-reset/confirm",
            json={"token": "garbage", "new_password": "newcorrecthorse"},
        )
        assert r.status_code == 400

    async def test_expired_token_400(self, client: AsyncClient) -> None:
        from datetime import timedelta
        from uuid import uuid4

        from fastapi_auth.tokens import create_password_reset_token

        # secret_key matches the test fixture
        token = create_password_reset_token(
            uuid4(), "x" * 32, timedelta(seconds=-1)
        )
        r = await client.post(
            "/auth/password-reset/confirm",
            json={"token": token, "new_password": "newcorrecthorse"},
        )
        assert r.status_code == 400

    async def test_min_password_length_422(
        self,
        client: AsyncClient,
        reset_calls: list[tuple[Any, str]],
    ) -> None:
        await _register(client)
        await client.post(
            "/auth/password-reset/request",
            json={"email": "alice@example.com"},
        )
        token = reset_calls[0][1]
        r = await client.post(
            "/auth/password-reset/confirm",
            json={"token": token, "new_password": "short"},
        )
        assert r.status_code == 422

    async def test_token_is_single_use(
        self,
        client: AsyncClient,
        reset_calls: list[tuple[Any, str]],
    ) -> None:
        # First confirm succeeds; replay of the same token must 400.
        await _register(client)
        await client.post(
            "/auth/password-reset/request",
            json={"email": "alice@example.com"},
        )
        token = reset_calls[0][1]
        r = await client.post(
            "/auth/password-reset/confirm",
            json={"token": token, "new_password": "newcorrecthorse"},
        )
        assert r.status_code == 204
        r = await client.post(
            "/auth/password-reset/confirm",
            json={"token": token, "new_password": "anothernewpw1"},
        )
        assert r.status_code == 400
