# fastapi-auth

Drop-in session auth for FastAPI apps using SQLModel + Postgres.

- Argon2id password hashing
- Opaque session tokens (sha256 hashes stored, plaintext returned)
- Bearer header **and** cookie transport — same endpoints serve web and mobile
- Session rotation with reuse detection (Phase 5)
- Password reset via short-lived JWT (Phase 6)

Status: **work-in-progress**. Phases 1–4 done (skeleton, primitives, models + storage, FastAPI routes).

## Minimal consumer setup

```python
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from fastapi_auth import AuthConfig, AuthUser, current_user, include_auth_router
import fastapi_auth.models  # registers auth_sessions on SQLModel.metadata


class User(AuthUser, table=True):
    display_name: str | None = None  # your fields here


engine: AsyncEngine = create_async_engine("postgresql+asyncpg://...")


async def db_session():
    # MUST use expire_on_commit=False — see "Gotchas" below.
    async with AsyncSession(engine, expire_on_commit=False) as s:
        yield s


config = AuthConfig(
    secret_key="<32+ bytes>",
    user_model=User,
    db_session_dep=db_session,
)

app = FastAPI()
include_auth_router(app, config)

# Drop on any of your routes:
user_dep = current_user(config)


@app.get("/me-extended")
async def me(user: User = Depends(user_dep)):
    return {"id": user.id, "display_name": user.display_name}
```

## Gotchas (things you must get right)

These aren't enforced by the type system; getting them wrong fails at runtime, sometimes obscurely.

### `secret_key` must be ≥32 bytes

Used to sign password-reset JWTs (HS256). `AuthConfig` rejects shorter keys at construction. Use `secrets.token_urlsafe(32)` or similar.

### `db_session_dep` must yield `AsyncSession(engine, expire_on_commit=False)`

Default SQLAlchemy expires loaded attributes after `commit()`. Routes commit, then read fields like `user.id` to build the response. Without `expire_on_commit=False`, that read triggers a sync lazy-load inside an async context and you get `MissingGreenlet` errors.

### Don't commit in your session dep

The library's routes call `await s.commit()` themselves. Your session dep should yield the session and otherwise leave transaction control alone.

### Cookie defaults assume HTTPS

`cookie_secure=True` by default. For local HTTP dev, override with `cookie_secure=False` or your browser will silently drop the cookie. **Don't ship `False` to prod.**

### Register `fastapi_auth.models` with your metadata

The `auth_sessions` table lives in `SQLModel.metadata` once `fastapi_auth.models` is imported. If you use Alembic autogenerate, make sure your `env.py` imports the module so the table shows up in migrations.

## `AuthConfig` reference

| Field | Type | Default | Notes |
|---|---|---|---|
| `secret_key` | `str` | — | ≥32 bytes |
| `user_model` | `type[AuthUser]` | — | Your `class User(AuthUser, table=True)` |
| `db_session_dep` | `Callable[[], Awaitable[AsyncSession]]` | — | See gotchas |
| `session_lifetime` | `timedelta` | `30 days` | Cookie max-age and DB `expires_at` |
| `cookie_name` | `str` | `"session"` | |
| `cookie_domain` | `str \| None` | `None` | |
| `cookie_secure` | `bool` | `True` | Set `False` only for local HTTP |
| `cookie_samesite` | `str` | `"lax"` | `"lax"` / `"strict"` / `"none"` |

## Endpoints (mounted by `include_auth_router`)

| Method | Path | Body | Returns |
|---|---|---|---|
| `POST` | `/auth/register` | `{email, password}` | `{token, user}` + cookie |
| `POST` | `/auth/login` | `{email, password}` | `{token, user}` + cookie |
| `POST` | `/auth/logout` | — | 204, clears cookie + revokes session |
| `GET`  | `/auth/me` | — | `{id, email}` |

`/auth/me` returns the library-defined minimal user shape. For your custom user fields, write your own route using `Depends(current_user(config))`.

## Tests

Tests use `testcontainers[postgres]` — Docker must be running.

```sh
uv run pytest
```
