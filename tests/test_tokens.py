import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest

from fastapi_auth.tokens import (
    InvalidPasswordResetToken,
    create_password_reset_token,
    generate_session_token,
    hash_token,
    verify_password_reset_token,
)


@pytest.fixture
def secret_key() -> str:
    return "test-secret-key-not-used-in-prod"


@pytest.fixture
def user_id() -> UUID:
    return uuid4()


class TestGenerateSessionToken:
    def test_returns_two_strings(self) -> None:
        plaintext, hashed = generate_session_token()
        assert isinstance(plaintext, str)
        assert isinstance(hashed, str)

    def test_hash_matches_plaintext(self) -> None:
        """The returned hash must equal hash_token(plaintext) so DB lookups work."""
        plaintext, hashed = generate_session_token()
        assert hashed == hash_token(plaintext)

    def test_subsequent_calls_differ(self) -> None:
        """Each call must produce a fresh random token."""
        a_plain, a_hash = generate_session_token()
        b_plain, b_hash = generate_session_token()
        assert a_plain != b_plain
        assert a_hash != b_hash

    def test_plaintext_has_sufficient_entropy(self) -> None:
        """token_urlsafe(32) → ~43-char string. Guard against accidental shrinkage."""
        plaintext, _ = generate_session_token()
        assert len(plaintext) >= 40

    def test_plaintext_is_url_safe(self) -> None:
        """Cookie- and header-safe alphabet only: A-Z a-z 0-9 - _"""
        plaintext, _ = generate_session_token()
        allowed = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
        assert set(plaintext) <= allowed

    def test_many_calls_are_unique(self) -> None:
        """100 calls should produce 100 distinct tokens (random collision is astronomical)."""
        tokens = {generate_session_token()[0] for _ in range(100)}
        assert len(tokens) == 100


class TestHashToken:
    def test_deterministic(self) -> None:
        assert hash_token("abc") == hash_token("abc")

    def test_different_inputs_different_outputs(self) -> None:
        assert hash_token("abc") != hash_token("abd")

    def test_returns_sha256_hex(self) -> None:
        """SHA-256 output is 64 hex characters."""
        result = hash_token("anything")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_empty_string(self) -> None:
        # SHA-256("") is well-known; we don't pin the value, but it must work.
        result = hash_token("")
        assert len(result) == 64

    def test_unicode_input(self) -> None:
        result = hash_token("пароль🔐")
        assert len(result) == 64


class TestCreatePasswordResetToken:
    def test_returns_string(self, user_id: UUID, secret_key: str) -> None:
        token = create_password_reset_token(user_id, secret_key, timedelta(minutes=15))
        assert isinstance(token, str)

    def test_token_has_three_segments(self, user_id: UUID, secret_key: str) -> None:
        """JWT format: header.payload.signature"""
        token = create_password_reset_token(user_id, secret_key, timedelta(minutes=15))
        assert token.count(".") == 2

    def test_uses_hs256(self, user_id: UUID, secret_key: str) -> None:
        token = create_password_reset_token(user_id, secret_key, timedelta(minutes=15))
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "HS256"

    def test_payload_contains_required_claims(
        self, user_id: UUID, secret_key: str
    ) -> None:
        token = create_password_reset_token(user_id, secret_key, timedelta(minutes=15))
        claims = jwt.decode(token, secret_key, algorithms=["HS256"])
        assert claims["sub"] == str(user_id)
        assert claims["purpose"] == "password_reset"
        assert "iat" in claims
        assert "exp" in claims
        assert claims["exp"] > claims["iat"]

    def test_different_users_different_tokens(self, secret_key: str) -> None:
        token_a = create_password_reset_token(
            uuid4(), secret_key, timedelta(minutes=15)
        )
        token_b = create_password_reset_token(
            uuid4(), secret_key, timedelta(minutes=15)
        )
        assert token_a != token_b


class TestVerifyPasswordResetToken:
    def test_roundtrip_returns_user_id(self, user_id: UUID, secret_key: str) -> None:
        token = create_password_reset_token(user_id, secret_key, timedelta(minutes=15))
        assert verify_password_reset_token(token, secret_key) == (user_id, 0)

    def test_rejects_wrong_secret(self, user_id: UUID, secret_key: str) -> None:
        token = create_password_reset_token(user_id, secret_key, timedelta(minutes=15))
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(token, "different-secret-also-32-bytes!!")

    def test_rejects_tampered_signature(self, user_id: UUID, secret_key: str) -> None:
        token = create_password_reset_token(user_id, secret_key, timedelta(minutes=15))
        # Flip a character in the middle of the signature (not the last:
        # base64url's last char only encodes 2 bits and can collide on decode).
        head, _, sig = token.rpartition(".")
        mid = len(sig) // 2
        tampered = f"{head}.{sig[:mid]}{'A' if sig[mid] != 'A' else 'B'}{sig[mid + 1:]}"
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(tampered, secret_key)

    def test_rejects_tampered_payload(self, user_id: UUID, secret_key: str) -> None:
        """Modifying the payload must invalidate the signature."""
        token = create_password_reset_token(user_id, secret_key, timedelta(minutes=15))
        header, payload, signature = token.split(".")
        # Replace the payload segment with one for a different user.
        evil_payload = (
            base64.urlsafe_b64encode(
                json.dumps({"sub": str(uuid4()), "purpose": "password_reset"}).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        forged = f"{header}.{evil_payload}.{signature}"
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(forged, secret_key)

    def test_rejects_expired_token(self, user_id: UUID, secret_key: str) -> None:
        token = create_password_reset_token(user_id, secret_key, timedelta(seconds=-1))
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(token, secret_key)

    def test_rejects_malformed_token(self, secret_key: str) -> None:
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token("not-a-jwt", secret_key)

    def test_rejects_empty_string(self, secret_key: str) -> None:
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token("", secret_key)

    def test_rejects_wrong_purpose(self, user_id: UUID, secret_key: str) -> None:
        """A JWT with valid signature but wrong purpose claim must be rejected."""
        payload = {
            "sub": str(user_id),
            "purpose": "email_verification",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
        }
        token = jwt.encode(payload, secret_key, algorithm="HS256")
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(token, secret_key)

    def test_rejects_missing_purpose(self, user_id: UUID, secret_key: str) -> None:
        payload = {
            "sub": str(user_id),
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
        }
        token = jwt.encode(payload, secret_key, algorithm="HS256")
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(token, secret_key)

    def test_rejects_malformed_sub(self, secret_key: str) -> None:
        payload = {
            "sub": "not-a-uuid",
            "purpose": "password_reset",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
        }
        token = jwt.encode(payload, secret_key, algorithm="HS256")
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(token, secret_key)

    def test_rejects_missing_sub(self, secret_key: str) -> None:
        payload = {
            "purpose": "password_reset",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
        }
        token = jwt.encode(payload, secret_key, algorithm="HS256")
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(token, secret_key)

    def test_rejects_alg_none_attack(self, user_id: UUID, secret_key: str) -> None:
        """The classic JWT algorithm-confusion attack: forge a token with alg=none.

        Our verify_password_reset_token must reject this because we pin algorithms=["HS256"].
        """
        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
            .rstrip(b"=")
            .decode()
        )
        payload = (
            base64.urlsafe_b64encode(
                json.dumps({"sub": str(user_id), "purpose": "password_reset"}).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        forged = f"{header}.{payload}."
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(forged, secret_key)

    def test_rejects_wrong_algorithm(self, user_id: UUID, secret_key: str) -> None:
        """A token signed with HS512 must be rejected even with the right secret."""
        payload = {
            "sub": str(user_id),
            "purpose": "password_reset",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
        }
        hs512_key = secret_key * 2
        token = jwt.encode(payload, hs512_key, algorithm="HS512")
        with pytest.raises(InvalidPasswordResetToken):
            verify_password_reset_token(token, hs512_key)
