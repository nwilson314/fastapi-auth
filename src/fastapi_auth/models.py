from datetime import datetime, UTC
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, Index, text
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
    password_version: int = Field(default=0, nullable=False)
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
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
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    revoked_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    __table_args__ = (
        # A session can be the parent of at most one child, ever.
        # (Revoked children still count — once a parent is rotated, it's
        # rotated permanently. Concurrent rotation attempts of the same
        # parent collide on this index even if the winning child is later
        # revoked.)
        Index(
            "uniq_child_per_parent",
            "parent_id",
            unique=True,
            postgresql_where=text("parent_id IS NOT NULL"),
        ),
    )
