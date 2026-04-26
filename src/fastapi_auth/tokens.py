from datetime import datetime, timedelta, UTC
import hashlib
import jwt
import secrets
from uuid import UUID

_ALGORITHM = "HS256"
_PURPOSE = "password_reset"


def generate_session_token() -> tuple[str, str]:
    plaintext = secrets.token_urlsafe(32)
    return plaintext, hash_token(plaintext)


def hash_token(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()


class InvalidPasswordResetToken(Exception):
    pass


def create_password_reset_token(user_id: UUID, secret_key: str, ttl: timedelta) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "purpose": _PURPOSE,
        "iat": now,
        "exp": now + ttl,
    }

    return jwt.encode(payload, secret_key, algorithm=_ALGORITHM)


def verify_password_reset_token(token: str, secret_key: str) -> UUID:
    try:
        claims = jwt.decode(token, secret_key, algorithms=[_ALGORITHM])
    except jwt.PyJWTError as e:
        raise InvalidPasswordResetToken(str(e))
    if claims.get("purpose") != _PURPOSE:
        raise InvalidPasswordResetToken("Invalid purpose")

    try:
        return UUID(claims["sub"])
    except (KeyError, ValueError) as e:
        raise InvalidPasswordResetToken("malformed sub claim") from e
