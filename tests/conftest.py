from collections.abc import AsyncIterator, Awaitable, Callable, Iterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from testcontainers.postgres import PostgresContainer

import fastapi_auth.models  # noqa: F401  — registers Session on metadata
from fastapi_auth.config import AuthConfig
from fastapi_auth.models import AuthUser


class User(AuthUser, table=True):
    """Concrete User table for tests — mirrors how a consumer wires it."""


async def _unused_session_dep() -> AsyncSession:  # pragma: no cover
    raise RuntimeError("not used in storage-layer tests")


@pytest.fixture
def auth_config() -> AuthConfig:
    return AuthConfig(
        secret_key="x" * 32,
        user_model=User,
        db_session_dep=_unused_session_dep,
    )


@pytest.fixture(scope="session")
def postgres_url() -> Iterator[str]:
    with PostgresContainer("postgres:16-alpine", driver="asyncpg") as pg:
        yield pg.get_connection_url()


@pytest_asyncio.fixture
async def db_session(postgres_url: str) -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(postgres_url)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    try:
        async with AsyncSession(engine) as s:
            yield s
            await s.rollback()
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.drop_all)
        await engine.dispose()
