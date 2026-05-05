"""Unit tests for app.core.security.

Each test covers one security property of the primitives defined in that
module.  All tests are synchronous and pure — no database, no Redis, no HTTP.
Fixtures from conftest.py are not used here.

The Settings instance is constructed inline with a fixed test secret that
satisfies the 32-character minimum enforced by the jwt_secret_must_be_strong
validator.
"""

from datetime import timedelta

import jwt
from jwt import InvalidTokenError

from app.core.config import Settings
from app.core.security import (
    create_access_token,
    create_step_up_token,
    decode_access_token,
    decode_step_up_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    is_password_strong,
    verify_password,
)

_TEST_SETTINGS = Settings(
    database_url="postgresql+asyncpg://test:test@localhost:5432/test",  # type: ignore[arg-type]
    redis_url="redis://:testpass@localhost:6379/0",  # type: ignore[arg-type]
    jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long-for-hs256",
    environment="test",
)


def test_hash_password_produces_argon2_hash() -> None:
    """Hash must start with '$argon2', confirming Argon2id algorithm (SR-02)."""
    hashed = hash_password("SomePassword1!")
    assert hashed.startswith("$argon2")


def test_hash_password_is_not_plaintext() -> None:
    """Stored hash must differ from plaintext — passwords never stored as-is (SR-02)."""
    plain = "SomePassword1!"
    hashed = hash_password(plain)
    assert hashed != plain


def test_verify_password_correct() -> None:
    """verify_password returns True when the plaintext matches the hash (SR-02)."""
    plain = "CorrectPassword1!"
    hashed = hash_password(plain)
    assert verify_password(plain, hashed) is True


def test_verify_password_wrong() -> None:
    """verify_password returns False when the plaintext does not match (SR-02)."""
    hashed = hash_password("CorrectPassword1!")
    assert verify_password("WrongPassword1!", hashed) is False


def test_verify_password_never_raises() -> None:
    """verify_password returns False (never raises) on malformed hash
    — prevents error-path enumeration (SR-02)."""
    result = verify_password("anything", "this-is-not-a-valid-hash-at-all")
    assert result is False


def test_is_password_strong_accepts_valid() -> None:
    """Password meeting all SR-01 criteria is accepted."""
    assert is_password_strong("ValidPass1!@") is True


def test_is_password_strong_rejects_short() -> None:
    """Password shorter than 12 characters is rejected (SR-01 minimum length)."""
    assert is_password_strong("ShortPass1!") is False


def test_is_password_strong_rejects_no_uppercase() -> None:
    """Password with no uppercase letter is rejected (SR-01)."""
    assert is_password_strong("nouppercase1!") is False


def test_is_password_strong_rejects_no_digit() -> None:
    """Password with no digit is rejected (SR-01)."""
    assert is_password_strong("NoDigitHere!!") is False


def test_is_password_strong_rejects_no_special() -> None:
    """Password with no special character is rejected (SR-01)."""
    assert is_password_strong("NoSpecialChar1") is False


def test_create_access_token_contains_expected_claims() -> None:
    """Access token payload must carry sub, role, session_id,
    jti, typ, iat, exp (SR-06)."""
    token = create_access_token(
        subject="user-id-123",
        role="user",
        session_id="session-id-abc",
        settings=_TEST_SETTINGS,
    )
    payload = jwt.decode(
        token,
        _TEST_SETTINGS.jwt_secret_key,
        algorithms=[_TEST_SETTINGS.jwt_algorithm],
    )

    assert payload["sub"] == "user-id-123"
    assert payload["role"] == "user"
    assert payload["session_id"] == "session-id-abc"
    assert "jti" in payload
    assert payload["typ"] == "access"
    assert "exp" in payload
    assert "iat" in payload


def test_create_access_token_expires_at_configured_ttl() -> None:
    """Token exp must equal iat plus the configured TTL (max 15 minutes, SR-06)."""
    token = create_access_token(
        subject="user-id-123",
        role="user",
        session_id="session-id-abc",
        settings=_TEST_SETTINGS,
    )
    payload = jwt.decode(
        token,
        _TEST_SETTINGS.jwt_secret_key,
        algorithms=[_TEST_SETTINGS.jwt_algorithm],
    )

    expected_lifetime_seconds = _TEST_SETTINGS.access_token_expire_minutes * 60
    actual_lifetime_seconds = payload["exp"] - payload["iat"]

    assert abs(actual_lifetime_seconds - expected_lifetime_seconds) <= 2


def test_decode_access_token_valid() -> None:
    """decode_access_token returns correct payload for a valid token (SR-06)."""
    token = create_access_token(
        subject="user-abc",
        role="admin",
        session_id="sess-xyz",
        settings=_TEST_SETTINGS,
    )
    payload = decode_access_token(token, _TEST_SETTINGS)

    assert payload["sub"] == "user-abc"
    assert payload["role"] == "admin"
    assert payload["session_id"] == "sess-xyz"
    assert payload["typ"] == "access"


def test_decode_access_token_expired() -> None:
    """decode_access_token raises InvalidTokenError for an expired token (SR-06)."""
    from datetime import datetime, timezone

    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": "user-abc",
        "role": "user",
        "session_id": "sess-xyz",
        "jti": "test-jti",
        "typ": "access",
        "iat": now - timedelta(seconds=2),
        "exp": now - timedelta(seconds=1),
    }
    expired_token = jwt.encode(
        payload,
        _TEST_SETTINGS.jwt_secret_key,
        algorithm=_TEST_SETTINGS.jwt_algorithm,
    )

    try:
        decode_access_token(expired_token, _TEST_SETTINGS)
        assert False, "Expected InvalidTokenError was not raised"  # noqa: B011
    except InvalidTokenError:
        pass


def test_decode_access_token_wrong_signature() -> None:
    """decode_access_token raises InvalidTokenError on a tampered signature (SR-06)."""
    token = create_access_token(
        subject="user-abc",
        role="user",
        session_id="sess-xyz",
        settings=_TEST_SETTINGS,
    )
    parts = token.split(".")
    parts[2] = parts[2][:-4] + "XXXX"
    tampered_token = ".".join(parts)

    try:
        decode_access_token(tampered_token, _TEST_SETTINGS)
        assert False, "Expected InvalidTokenError was not raised"  # noqa: B011
    except InvalidTokenError:
        pass


def test_decode_access_token_rejects_wrong_typ() -> None:
    """decode_access_token raises InvalidTokenError when typ is not 'access'
    — prevents step-up token reuse (SR-06, SR-13)."""
    from datetime import datetime, timezone

    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": "user-abc",
        "role": "user",
        "session_id": "sess-xyz",
        "jti": "test-jti",
        "typ": "step_up",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    step_up_token = jwt.encode(
        payload,
        _TEST_SETTINGS.jwt_secret_key,
        algorithm=_TEST_SETTINGS.jwt_algorithm,
    )

    try:
        decode_access_token(step_up_token, _TEST_SETTINGS)
        assert False, "Expected InvalidTokenError was not raised"  # noqa: B011
    except InvalidTokenError:
        pass


def test_generate_refresh_token_is_urlsafe_string() -> None:
    """generate_refresh_token returns a non-empty,
    whitespace-free URL-safe string (SR-07)."""
    token = generate_refresh_token()
    assert isinstance(token, str)
    assert len(token) > 0
    assert " " not in token
    assert "\n" not in token
    assert "\t" not in token


def test_generate_refresh_token_is_unique() -> None:
    """Two calls to generate_refresh_token must return different values
    (SR-07: unpredictable tokens)."""
    token_a = generate_refresh_token()
    token_b = generate_refresh_token()
    assert token_a != token_b


def test_hash_token_is_hex_string() -> None:
    """hash_token returns a 64-character lowercase hex string
    (SHA-256, SR-07, SR-03)."""
    digest = hash_token("some-raw-token-value")
    assert isinstance(digest, str)
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_hash_token_is_deterministic() -> None:
    """hash_token is deterministic — same input always yields
    the same lookup key (SR-07, SR-03)."""
    raw = "deterministic-token-input"
    assert hash_token(raw) == hash_token(raw)


def test_hash_token_different_inputs_differ() -> None:
    """hash_token produces different digests for different inputs (SR-07, SR-03)."""
    assert hash_token("token-one") != hash_token("token-two")


def test_create_step_up_token_contains_expected_claims() -> None:
    """Step-up token payload must carry sub, jti,
    typ='step_up', iat, exp (SR-13, SR-14)."""
    token, jti = create_step_up_token(subject="user-id-123", settings=_TEST_SETTINGS)
    payload = jwt.decode(
        token,
        _TEST_SETTINGS.jwt_secret_key,
        algorithms=[_TEST_SETTINGS.jwt_algorithm],
    )

    assert payload["sub"] == "user-id-123"
    assert payload["typ"] == "step_up"
    assert payload["jti"] == jti
    assert "exp" in payload
    assert "iat" in payload


def test_create_step_up_token_expires_at_configured_ttl() -> None:
    """Step-up token exp must equal iat plus
    step_up_token_expire_minutes (max 5 min, SR-13)."""
    token, _ = create_step_up_token(subject="user-id-123", settings=_TEST_SETTINGS)
    payload = jwt.decode(
        token,
        _TEST_SETTINGS.jwt_secret_key,
        algorithms=[_TEST_SETTINGS.jwt_algorithm],
    )

    expected_lifetime_seconds = _TEST_SETTINGS.step_up_token_expire_minutes * 60
    actual_lifetime_seconds = payload["exp"] - payload["iat"]

    assert abs(actual_lifetime_seconds - expected_lifetime_seconds) <= 2


def test_create_step_up_token_returns_unique_jtis() -> None:
    """Two calls must produce different JTIs
    — predictable JTIs could be pre-empted (SR-14)."""
    _, jti_a = create_step_up_token(subject="user-id-123", settings=_TEST_SETTINGS)
    _, jti_b = create_step_up_token(subject="user-id-123", settings=_TEST_SETTINGS)
    assert jti_a != jti_b


def test_decode_step_up_token_valid() -> None:
    """decode_step_up_token returns correct payload for a valid token (SR-13)."""
    token, jti = create_step_up_token(subject="user-xyz", settings=_TEST_SETTINGS)
    payload = decode_step_up_token(token, _TEST_SETTINGS)

    assert payload["sub"] == "user-xyz"
    assert payload["typ"] == "step_up"
    assert payload["jti"] == jti


def test_decode_step_up_token_expired() -> None:
    """decode_step_up_token raises InvalidTokenError for an expired token (SR-13)."""
    from datetime import datetime, timezone

    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": "user-xyz",
        "jti": "test-jti",
        "typ": "step_up",
        "iat": now - timedelta(seconds=2),
        "exp": now - timedelta(seconds=1),
    }
    expired_token = jwt.encode(
        payload,
        _TEST_SETTINGS.jwt_secret_key,
        algorithm=_TEST_SETTINGS.jwt_algorithm,
    )

    try:
        decode_step_up_token(expired_token, _TEST_SETTINGS)
        assert False, "Expected InvalidTokenError was not raised"  # noqa: B011
    except InvalidTokenError:
        pass


def test_decode_step_up_token_rejects_access_token() -> None:
    """decode_step_up_token raises InvalidTokenError when typ is 'access'
    — prevents bearer token reuse (SR-13)."""
    access_token = create_access_token(
        subject="user-xyz",
        role="user",
        session_id="sess-abc",
        settings=_TEST_SETTINGS,
    )

    try:
        decode_step_up_token(access_token, _TEST_SETTINGS)
        assert False, "Expected InvalidTokenError was not raised"  # noqa: B011
    except InvalidTokenError:
        pass


def test_decode_step_up_token_rejects_tampered_signature() -> None:
    """decode_step_up_token raises InvalidTokenError on a tampered signature (SR-13)."""
    token, _ = create_step_up_token(subject="user-xyz", settings=_TEST_SETTINGS)
    parts = token.split(".")
    parts[2] = parts[2][:-4] + "XXXX"
    tampered = ".".join(parts)

    try:
        decode_step_up_token(tampered, _TEST_SETTINGS)
        assert False, "Expected InvalidTokenError was not raised"  # noqa: B011
    except InvalidTokenError:
        pass
