from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from fastapi_auth.config import AuthConfig
from fastapi_auth.models import Session
from fastapi_auth.storage import (
    SessionReuseError,
    create_session,
    create_user,
    get_user_by_email,
    get_user_by_id,
    revoke_all_sessions,
    revoke_session,
    rotate_session,
)
from fastapi_auth.tokens import hash_token

pytestmark = pytest.mark.asyncio


async def _make_user(
    s: AsyncSession,
    config: AuthConfig,
    *,
    email: str = "alice@example.com",
    password_hash: str = "hash",
):
    return await create_user(
        s, config, email=email, password_hash=password_hash
    )


class TestUserStorage:
    async def test_create_user_basic(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await create_user(
            db_session,
            auth_config,
            email="alice@example.com",
            password_hash="hash",
        )
        assert user.id is not None
        assert user.email == "alice@example.com"
        assert user.password_hash == "hash"

    async def test_get_user_by_email_found(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        await _make_user(db_session, auth_config, email="bob@example.com")
        found = await get_user_by_email(db_session, "bob@example.com", auth_config)
        assert found is not None
        assert found.email == "bob@example.com"

    async def test_get_user_by_email_not_found(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        assert (
            await get_user_by_email(db_session, "ghost@example.com", auth_config)
            is None
        )

    async def test_get_user_by_id_found(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        found = await get_user_by_id(db_session, user.id, auth_config)
        assert found is not None
        assert found.id == user.id

    async def test_get_user_by_id_not_found(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        assert await get_user_by_id(db_session, uuid4(), auth_config) is None

    async def test_create_user_duplicate_email_raises(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        await _make_user(db_session, auth_config, email="dup@example.com")
        with pytest.raises(IntegrityError):
            await _make_user(db_session, auth_config, email="dup@example.com")


class TestCreateSession:
    async def test_returns_plaintext_and_session(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        plain, sess = await create_session(db_session, user.id, timedelta(days=1))
        assert isinstance(plain, str) and len(plain) > 20
        assert sess.user_id == user.id
        assert sess.parent_id is None
        assert sess.revoked_at is None

    async def test_token_hash_matches_plaintext(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        plain, sess = await create_session(db_session, user.id, timedelta(days=1))
        assert sess.token_hash == hash_token(plain)

    async def test_expires_at_in_future(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        _, sess = await create_session(db_session, user.id, timedelta(days=7))
        assert sess.expires_at > datetime.now(UTC)

    async def test_two_sessions_distinct_families(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        _, s1 = await create_session(db_session, user.id, timedelta(days=1))
        _, s2 = await create_session(db_session, user.id, timedelta(days=1))
        assert s1.family_id != s2.family_id


class TestRotateSession:
    async def test_happy_path(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        plain, old = await create_session(db_session, user.id, timedelta(days=1))
        new_plain, new = await rotate_session(
            db_session, plain, timedelta(days=1)
        )
        assert new_plain != plain
        assert new.family_id == old.family_id
        assert new.parent_id == old.id
        await db_session.refresh(old)
        assert old.revoked_at is not None

    async def test_unknown_token_raises(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        with pytest.raises(SessionReuseError):
            await rotate_session(db_session, "nope", timedelta(days=1))

    async def test_expired_token_raises(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        plain, _ = await create_session(db_session, user.id, timedelta(seconds=-1))
        with pytest.raises(SessionReuseError):
            await rotate_session(db_session, plain, timedelta(days=1))

    async def test_reuse_revokes_whole_family(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        plain1, s1 = await create_session(db_session, user.id, timedelta(days=1))
        plain2, _ = await rotate_session(db_session, plain1, timedelta(days=1))
        await rotate_session(db_session, plain2, timedelta(days=1))

        with pytest.raises(SessionReuseError):
            await rotate_session(db_session, plain1, timedelta(days=1))

        result = await db_session.exec(
            select(Session).where(Session.family_id == s1.family_id)
        )
        sessions = list(result.all())
        assert len(sessions) == 3
        assert all(s.revoked_at is not None for s in sessions)


class TestRevokeSession:
    async def test_marks_revoked(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        plain, sess = await create_session(db_session, user.id, timedelta(days=1))
        await revoke_session(db_session, plain)
        await db_session.refresh(sess)
        assert sess.revoked_at is not None

    async def test_unknown_token_is_noop(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        await revoke_session(db_session, "nope")  # must not raise

    async def test_already_revoked_is_idempotent(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        plain, sess = await create_session(db_session, user.id, timedelta(days=1))
        await revoke_session(db_session, plain)
        await db_session.refresh(sess)
        first = sess.revoked_at
        await revoke_session(db_session, plain)
        await db_session.refresh(sess)
        assert sess.revoked_at == first


class TestRevokeAllSessions:
    async def test_revokes_all_for_user(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        _, s1 = await create_session(db_session, user.id, timedelta(days=1))
        _, s2 = await create_session(db_session, user.id, timedelta(days=1))
        await revoke_all_sessions(db_session, user.id)
        await db_session.refresh(s1)
        await db_session.refresh(s2)
        assert s1.revoked_at is not None
        assert s2.revoked_at is not None

    async def test_does_not_touch_other_users(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        alice = await _make_user(db_session, auth_config, email="alice@x.com")
        bob = await _make_user(db_session, auth_config, email="bob@x.com")
        _, _ = await create_session(db_session, alice.id, timedelta(days=1))
        _, bob_sess = await create_session(db_session, bob.id, timedelta(days=1))
        await revoke_all_sessions(db_session, alice.id)
        await db_session.refresh(bob_sess)
        assert bob_sess.revoked_at is None

    async def test_does_not_re_revoke(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        user = await _make_user(db_session, auth_config)
        plain, sess = await create_session(db_session, user.id, timedelta(days=1))
        await revoke_session(db_session, plain)
        await db_session.refresh(sess)
        original = sess.revoked_at
        await revoke_all_sessions(db_session, user.id)
        await db_session.refresh(sess)
        assert sess.revoked_at == original


class TestRotationRaceProtection:
    async def test_index_blocks_two_children_per_parent(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        # Two children of the same parent must collide regardless of
        # whether the first is revoked.
        user = await _make_user(db_session, auth_config)
        _, parent = await create_session(db_session, user.id, timedelta(days=1))

        child1 = Session(
            user_id=user.id,
            token_hash="hash-child-1",
            family_id=parent.family_id,
            parent_id=parent.id,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        db_session.add(child1)
        await db_session.flush()

        child2 = Session(
            user_id=user.id,
            token_hash="hash-child-2",
            family_id=parent.family_id,
            parent_id=parent.id,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        db_session.add(child2)
        with pytest.raises(IntegrityError):
            await db_session.flush()

    async def test_index_blocks_second_child_even_when_first_is_revoked(
        self, db_session: AsyncSession, auth_config: AuthConfig
    ) -> None:
        # The reviewer's expanded race: even if the first child gets
        # revoked, no second child of the same parent may be inserted.
        user = await _make_user(db_session, auth_config)
        _, parent = await create_session(db_session, user.id, timedelta(days=1))

        child1 = Session(
            user_id=user.id,
            token_hash="hash-child-1",
            family_id=parent.family_id,
            parent_id=parent.id,
            expires_at=datetime.now(UTC) + timedelta(days=1),
            revoked_at=datetime.now(UTC),  # already revoked
        )
        db_session.add(child1)
        await db_session.flush()

        child2 = Session(
            user_id=user.id,
            token_hash="hash-child-2",
            family_id=parent.family_id,
            parent_id=parent.id,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        db_session.add(child2)
        with pytest.raises(IntegrityError):
            await db_session.flush()
