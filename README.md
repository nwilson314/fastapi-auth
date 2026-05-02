# fastapi-auth

Drop-in session auth for FastAPI apps using SQLModel + Postgres.

- Argon2id password hashing
- Opaque session tokens (sha256 hashes stored, plaintext returned)
- Bearer header **and** cookie transport — same endpoints serve web and mobile
- Session rotation with reuse detection
- Password reset via short-lived JWT (library calls your hook; never returns the token in the HTTP body)

Status: feature-complete for v0.1; not yet validated by a real consumer install.

---

## Installation

Not on PyPI yet. Install from git:

```sh
uv add "fastapi-auth @ git+https://github.com/<your-org>/fastapi-auth.git"
# or
pip install "fastapi-auth @ git+https://github.com/<your-org>/fastapi-auth.git"
```

Requires Python ≥3.12 and Postgres (the schema uses `timestamptz`; SQLite won't work).

---

## Quick start

```python
from datetime import timedelta

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from fastapi_auth import AuthConfig, AuthUser, current_user, include_auth_router
import fastapi_auth.models  # registers auth_sessions on SQLModel.metadata


# 1. Define your User table by mixing in AuthUser.
class User(AuthUser, table=True):
    display_name: str | None = None  # any extra fields you want


# 2. Create an async engine and session dep. If you already have one in your
#    app, REUSE IT — just make sure expire_on_commit=False (see Gotchas).
engine: AsyncEngine = create_async_engine(
    "postgresql+asyncpg://user:pw@host/db"
)


async def db_session():
    async with AsyncSession(engine, expire_on_commit=False) as s:
        yield s


# 3. Wire the password-reset email hook (library never sends email itself).
async def send_password_reset(user: User, token: str) -> None:
    reset_url = f"https://yourapp.com/reset-password?token={token}"
    await my_email_service.send(
        to=user.email,
        subject="Reset your password",
        body=f"Open: {reset_url}",
    )


# 4. Build the config.
config = AuthConfig(
    secret_key="<32+ bytes — use secrets.token_urlsafe(32)>",
    user_model=User,
    db_session_dep=db_session,
    send_password_reset=send_password_reset,
    # Cross-origin web client? See "Cookies & cross-origin" below.
    cookie_secure=True,
    cookie_samesite="lax",
)

# 5. Mount the auth routes and protect your own routes.
app = FastAPI()
include_auth_router(app, config)

user_dep = current_user(config)


@app.get("/me-extended")
async def me(user: User = Depends(user_dep)):
    return {"id": user.id, "display_name": user.display_name}
```

---

## Database & migrations

The library declares one table — `auth_sessions` — on `SQLModel.metadata`. Your
`User` table inherits from `AuthUser` so it lives on the same metadata.

**Dev quickstart (no migrations):**

```python
async with engine.begin() as conn:
    await conn.run_sync(SQLModel.metadata.create_all)
```

**Production (Alembic):** in your `alembic/env.py`, import `fastapi_auth.models`
**before** `target_metadata = SQLModel.metadata` so autogenerate sees
`auth_sessions`. Without this, `alembic revision --autogenerate` will silently
omit the auth tables.

```python
# alembic/env.py
import fastapi_auth.models  # noqa: F401  — must come before target_metadata
from sqlmodel import SQLModel
import myapp.models  # noqa: F401  — your own tables

target_metadata = SQLModel.metadata
```

`auth_sessions.user_id` is **not** a foreign key (so the library doesn't have to
guess your user table's name). The column is indexed for performance.

---

## Cookies & cross-origin

The defaults (`cookie_secure=True`, `cookie_samesite="lax"`) are right for an
API and web client served from the **same origin** over HTTPS.

If your web client is on a **different origin** (e.g. `app.example.com` calling
`api.example.com`, or any localhost dev where ports differ), you need:

```python
config = AuthConfig(
    ...,
    cookie_secure=True,           # required when samesite="none"
    cookie_samesite="none",       # browser sends cookie cross-site
    cookie_domain=".example.com", # set so both subdomains share the cookie
)
```

And on the FastAPI side, configure CORS to allow credentials:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],  # not "*" with credentials
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

The web client must also send credentials: `fetch(url, { credentials: "include" })`.

For **local HTTP development only**, set `cookie_secure=False` — browsers drop
secure cookies on plain HTTP. **Never ship `False` to prod.**

For **mobile clients**, ignore cookies entirely: use the `token` from the
`/auth/login` response body and send `Authorization: Bearer <token>` on every
request. The library accepts both transports on every protected endpoint.

---

## Recommended client behavior

**Refresh strategy.** The session token returned by `/auth/login` is good for
30 days by default (configurable). Treat any 401 from a protected route as
"my token may have rotated" and try `/auth/refresh` once before sending the
user back to login:

```js
async function authedFetch(url, opts = {}) {
  let r = await fetch(url, { ...opts, credentials: "include" });
  if (r.status !== 401) return r;
  const refresh = await fetch("/auth/refresh", {
    method: "POST",
    credentials: "include",
  });
  if (!refresh.ok) {
    window.location = "/login";
    return r;
  }
  return fetch(url, { ...opts, credentials: "include" });
}
```

**Reuse detection.** If `/auth/refresh` returns 401, every session in that
chain has been revoked (the library treats a replayed already-rotated token as
evidence of theft). The user must log in again.

**Logout.** `POST /auth/logout` revokes the current session and clears the
cookie. Idempotent — a 204 response means "you're logged out," not "you
weren't logged in."

---

## Gotchas (things you must get right)

These aren't enforced by the type system; getting them wrong fails at
runtime, sometimes obscurely.

### `secret_key` must be ≥32 bytes

Used to sign password-reset JWTs (HS256). `AuthConfig` rejects shorter keys at
construction. Use `secrets.token_urlsafe(32)` or load from a real secret store.

### `db_session_dep` must yield `AsyncSession(engine, expire_on_commit=False)`

Default SQLAlchemy expires loaded attributes after `commit()`. Routes commit,
then read fields like `user.id` to build the response. Without
`expire_on_commit=False`, that read triggers a sync lazy-load inside an async
context and you get `MissingGreenlet` errors.

### Reuse your existing session dep

If your app already has an async session dep, pass it as `db_session_dep`. You
don't need a separate one for auth. Just make sure the existing dep:

- yields with `expire_on_commit=False`
- does **not** call `commit()` itself (the library commits its own writes)

### Don't commit in your session dep

The library's routes call `await s.commit()` themselves. Your session dep
should yield the session and otherwise leave transaction control alone. If
your dep auto-commits on success, you may get double-commit warnings or
state-management surprises.

### Register `fastapi_auth.models` before metadata is read

For Alembic autogenerate, your `env.py` must import `fastapi_auth.models`
before assigning `target_metadata = SQLModel.metadata`. Otherwise the
`auth_sessions` table won't appear in generated migrations.

---

## `AuthConfig` reference

| Field | Type | Default | Notes |
|---|---|---|---|
| `secret_key` | `str` | — | ≥32 bytes |
| `user_model` | `type[AuthUser]` | — | Your `class User(AuthUser, table=True)` |
| `db_session_dep` | `Callable[[], Awaitable[AsyncSession]]` | — | See gotchas |
| `send_password_reset` | `Callable[[AuthUser, str], Awaitable[None]]` | — | Required. Called with `(user, reset_token)` server-side. |
| `session_lifetime` | `timedelta` | `30 days` | Cookie max-age and DB `expires_at` |
| `password_reset_lifetime` | `timedelta` | `30 minutes` | Reset-token TTL |
| `cookie_name` | `str` | `"session"` | |
| `cookie_domain` | `str \| None` | `None` | Set for cross-subdomain cookie sharing |
| `cookie_secure` | `bool` | `True` | Set `False` only for local HTTP |
| `cookie_samesite` | `str` | `"lax"` | `"lax"` / `"strict"` / `"none"` |

---

## Endpoints (mounted by `include_auth_router`)

| Method | Path | Body | Returns |
|---|---|---|---|
| `POST` | `/auth/register` | `{email, password}` | 201; `{token, user}` + cookie. Password ≥8 chars. |
| `POST` | `/auth/login` | `{email, password}` | 200; `{token, user}` + cookie |
| `POST` | `/auth/logout` | — | 204; clears cookie + revokes session |
| `POST` | `/auth/refresh` | — | 200; `{token, user}` + new cookie; rotates, detects reuse |
| `POST` | `/auth/password-reset/request` | `{email}` | 204; invokes `send_password_reset` callback if email exists |
| `POST` | `/auth/password-reset/confirm` | `{token, new_password}` | 204; updates hash, revokes all sessions. Password ≥8 chars. |
| `GET`  | `/auth/me` | — | 200; `{id, email}` |

`/auth/me` returns the library-defined minimal user shape. For your custom
user fields, write your own route using `Depends(current_user(config))`.

All protected endpoints accept `Authorization: Bearer <token>` **or** the
session cookie. Bearer wins if both are present.

---

## Wiring password-reset emails

The library never sends email — you provide a server-side hook that does.
`/auth/password-reset/request` generates a short-lived JWT and invokes your
callback; the token is **never** included in the HTTP response body. The
endpoint always returns `204` regardless of whether the email exists, to
avoid leaking account presence. Your callback is only invoked for real users.

```python
async def send_password_reset(user: User, token: str) -> None:
    reset_url = f"https://yourapp.com/reset-password?token={token}"
    await my_email_service.send(
        to=user.email,
        subject="Reset your password",
        body=f"Click here: {reset_url}",
    )

config = AuthConfig(..., send_password_reset=send_password_reset)
```

---

## Tests

Tests use `testcontainers[postgres]` — Docker must be running.

```sh
uv run pytest
```
