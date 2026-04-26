from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from fastapi_auth.config import AuthConfig
from fastapi_auth.models import AuthUser, Session
from fastapi_auth.tokens import generate_session_token, hash_token


async def get_user_by_email(
    s: AsyncSession,
    email: str,
    config: AuthConfig,
) -> AuthUser | None:
    result = await s.exec(
        select(config.user_model).where(config.user_model.email == email)
    )

    return result.first()


async def get_user_by_id(
    s: AsyncSession,
    user_id: UUID,
    config: AuthConfig,
) -> AuthUser | None:
    return await s.get(config.user_model, user_id)


async def create_user(
    s: AsyncSession,
    config: AuthConfig,
    *,
    email: str,
    password_hash: str,
    **extra: Any,
) -> AuthUser:
    user = config.user_model(email=email, password_hash=password_hash, **extra)

    s.add(user)
    await s.flush()
    return user


class SessionReuseError(Exception):
    """Raised when a revoked token is presented; entire family is revoked."""


async def create_session(
    s: AsyncSession,
    user_id: UUID,
    lifetime: timedelta,
) -> tuple[str, Session]:

    plaintext, token_hash = generate_session_token()
    session = Session(
        user_id=user_id,
        token_hash=token_hash,
        family_id=uuid4(),
        parent_id=None,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + lifetime,
    )

    s.add(session)
    await s.flush()
    return plaintext, session


async def rotate_session(
    s: AsyncSession,
    old_token_plain: str,
    lifetime: timedelta,
) -> tuple[str, Session]:
    old = await _get_session_by_token(s, old_token_plain)

    if old is None:
        raise SessionReuseError("unknown token")

    if old.revoked_at is not None:
        # Reuse: kill the whole family
        await _revoke_family(s, old.family_id)
        raise SessionReuseError("token already rotated")

    if old.expires_at < datetime.now(UTC):
        raise SessionReuseError("token expired")

    plaintext, token_hash = generate_session_token()
    new = Session(
        user_id=old.user_id,
        token_hash=token_hash,
        family_id=old.family_id,
        parent_id=old.id,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + lifetime,
    )

    old.revoked_at = datetime.now(UTC)
    s.add(new)
    await s.flush()
    return plaintext, new


async def revoke_session(
    s: AsyncSession,
    token_plain: str,
) -> None:
    session = await _get_session_by_token(s, token_plain)

    if session and session.revoked_at is None:
        session.revoked_at = datetime.now(UTC)
        await s.flush()


async def revoke_all_sessions(
    s: AsyncSession,
    user_id: UUID,
) -> None:
    result = await s.exec(
        select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
    )

    now = datetime.now(UTC)
    for session in result.all():
        session.revoked_at = now
    await s.flush()


async def _get_session_by_token(
    s: AsyncSession,
    token_plain: str,
) -> Session | None:
    token_hash = hash_token(token_plain)
    result = await s.exec(select(Session).where(Session.token_hash == token_hash))
    return result.first()


async def _revoke_family(
    s: AsyncSession,
    family_id: UUID,
) -> None:
    result = await s.exec(
        select(Session).where(
            Session.family_id == family_id, Session.revoked_at.is_(None)
        )
    )

    now = datetime.now(UTC)
    for session in result.all():
        session.revoked_at = now
