from datetime import datetime, UTC
from uuid import UUID, uuid4

from sqlalchemy import DateTime
from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AuthUser(SQLModel):
    """
    Mixin for the consumer's User table.

    Usage:
    ```python
    class User(AuthUser, table=True):
        display_name: str # user fields here
    ```
    """

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True)
    password_hash: str = Field(nullable=False)
    created_at: datetime = Field(
        default_factory=_utcnow, sa_type=DateTime(timezone=True)
    )
    updated_at: datetime = Field(
        default_factory=_utcnow, sa_type=DateTime(timezone=True)
    )


class Session(SQLModel, table=True):
    """ """

    __tablename__ = "auth_sessions"  # attempt to avoid user table name conflicts
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(index=True)
    token_hash: str = Field(unique=True, index=True)
    family_id: UUID = Field(index=True)
    parent_id: UUID | None = Field(default=None)
    created_at: datetime = Field(
        default_factory=_utcnow, sa_type=DateTime(timezone=True)
    )
    expires_at: datetime = Field(sa_type=DateTime(timezone=True))
    revoked_at: datetime | None = Field(
        default=None, sa_type=DateTime(timezone=True)
    )
