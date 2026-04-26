import pytest

from fastapi_auth.hashing import hash_password, verify_password


def test_hash_verify_roundtrip() -> None:
    encoded = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", encoded) is True


def test_verify_rejects_wrong_password() -> None:
    encoded = hash_password("correct horse battery staple")
    assert verify_password("wrong password", encoded) is False


def test_verify_is_case_sensitive() -> None:
    encoded = hash_password("Password123")
    assert verify_password("password123", encoded) is False


def test_hash_is_non_deterministic() -> None:
    """Two hashes of the same plaintext must differ — proves a fresh salt is used."""
    a = hash_password("same-password")
    b = hash_password("same-password")
    assert a != b


def test_hash_uses_argon2id() -> None:
    encoded = hash_password("anything")
    assert encoded.startswith("$argon2id$")


def test_verify_rejects_garbage_encoded() -> None:
    """Malformed encoded string must return False, not raise."""
    assert verify_password("anything", "not-a-real-hash") is False


def test_verify_rejects_empty_encoded() -> None:
    assert verify_password("anything", "") is False


def test_verify_rejects_truncated_hash() -> None:
    encoded = hash_password("password")
    truncated = encoded[: len(encoded) // 2]
    assert verify_password("password", truncated) is False


def test_verify_rejects_modified_hash() -> None:
    """Flipping a character in the hash segment must fail verification."""
    encoded = hash_password("password")
    flipped_char = "A" if encoded[-1] != "A" else "B"
    tampered = encoded[:-1] + flipped_char
    assert verify_password("password", tampered) is False


def test_hash_verify_empty_password() -> None:
    """Library does not enforce a minimum length — that's the consumer's job."""
    encoded = hash_password("")
    assert verify_password("", encoded) is True
    assert verify_password("not empty", encoded) is False


def test_hash_verify_unicode_password() -> None:
    pw = "пароль🔐密码"
    encoded = hash_password(pw)
    assert verify_password(pw, encoded) is True
    assert verify_password("пароль🔐密馬", encoded) is False


def test_hash_verify_long_password() -> None:
    """Argon2 has no bcrypt-style 72-byte truncation — long passwords must work fully."""
    pw = "a" * 1000 + "b"
    encoded = hash_password(pw)
    assert verify_password(pw, encoded) is True
    # If truncation were happening, this would also pass — make sure it doesn't.
    assert verify_password("a" * 1000 + "c", encoded) is False


@pytest.mark.parametrize(
    "password",
    [
        "simple",
        "with spaces and punctuation!",
        "1234567890",
        "$dollarsigns$everywhere$",
        "newlines\nare\nfine",
        "tabs\tare\ttoo",
    ],
)
def test_hash_verify_various_inputs(password: str) -> None:
    encoded = hash_password(password)
    assert verify_password(password, encoded) is True
