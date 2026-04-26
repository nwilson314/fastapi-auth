from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlmodel.ext.asyncio.session import AsyncSession
    from fastapi_auth.models import AuthUser


@dataclass(frozen=True, slots=True)
class AuthConfig:
    secret_key: str
    user_model: type[AuthUser]
    db_session_dep: Callable[[], Awaitable[AsyncSession]]
    session_lifetime: timedelta = timedelta(days=30)
    cookie_name: str = "session"
    cookie_domain: str | None = None
    cookie_secure: bool = True
    cookie_samesite: str = "lax"

    def __post_init__(self) -> None:
        if len(self.secret_key.encode("utf-8")) < 32:
            raise ValueError("secret_key must be at least 32 bytes for HS256")
