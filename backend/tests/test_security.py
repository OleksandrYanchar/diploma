"""Unit tests for app.core.security.

Each test covers one security property of the primitives defined in that
module.  All tests are synchronous and pure — no database, no Redis, no HTTP.
Fixtures from conftest.py are not used here.

The Settings instance is constructed inline with a fixed test secret that
satisfies the 32-character minimum enforced by the jwt_secret_must_be_strong
validator.
"""

from __future__ import annotations

from datetime import timedelta

import jwt
from jwt import InvalidTokenError

from app.core.config import Settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    is_password_strong,
    verify_password,
)

# ---------------------------------------------------------------------------
# Shared test Settings instance
#
# Constructed once at module level because Settings is immutable for our
# purposes and these tests do not need per-test isolation of configuration.
# ---------------------------------------------------------------------------
_TEST_SETTINGS = Settings(
    database_url="postgresql+asyncpg://test:test@localhost:5432/test",  # type: ignore[arg-type]
    redis_url="redis://:testpass@localhost:6379/0",  # type: ignore[arg-type]
    jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long-for-hs256",
    environment="test",
)

# ---------------------------------------------------------------------------
# hash_password
# ---------------------------------------------------------------------------


def test_hash_password_produces_argon2_hash() -> None:
    """The hash string must start with '$argon2', confirming Argon2id is used.

    Security property (SR-02): passwords must be hashed with Argon2id, not a
    weaker algorithm.  The passlib canonical format includes the algorithm
    identifier as the first segment of the hash string.
    """
    hashed = hash_password("SomePassword1!")
    assert hashed.startswith("$argon2")


def test_hash_password_is_not_plaintext() -> None:
    """The stored hash must differ from the original password.

    Security property (SR-02): plaintext passwords must never be stored.
    """
    plain = "SomePassword1!"
    hashed = hash_password(plain)
    assert hashed != plain


# ---------------------------------------------------------------------------
# verify_password
# ---------------------------------------------------------------------------


def test_verify_password_correct() -> None:
    """verify_password returns True when the plaintext matches the hash.

    Security property (SR-02): the verification path must accept correct
    credentials so that legitimate users can authenticate.
    """
    plain = "CorrectPassword1!"
    hashed = hash_password(plain)
    assert verify_password(plain, hashed) is True


def test_verify_password_wrong() -> None:
    """verify_password returns False when the plaintext does not match.

    Security property (SR-02): wrong passwords must be rejected to prevent
    unauthorised access.
    """
    hashed = hash_password("CorrectPassword1!")
    assert verify_password("WrongPassword1!", hashed) is False


def test_verify_password_never_raises() -> None:
    """verify_password returns False (not raises) given a malformed hash.

    Security property (SR-02): authentication code that raises on bad input
    can be exploited to enumerate valid accounts via error-path differences.
    A boolean return on all inputs prevents this.
    """
    result = verify_password("anything", "this-is-not-a-valid-hash-at-all")
    assert result is False


# ---------------------------------------------------------------------------
# is_password_strong
# ---------------------------------------------------------------------------


def test_is_password_strong_accepts_valid() -> None:
    """A password meeting all SR-01 criteria is accepted.

    Security property (SR-01): strong passwords must pass the policy check so
    that the registration flow does not block valid credentials.
    """
    assert is_password_strong("ValidPass1!@") is True


def test_is_password_strong_rejects_short() -> None:
    """A password shorter than 12 characters is rejected.

    Security property (SR-01): minimum length of 12 characters is required.
    """
    # 11 characters, otherwise policy-compliant
    assert is_password_strong("ShortPass1!") is False


def test_is_password_strong_rejects_no_uppercase() -> None:
    """A password with no uppercase letter is rejected.

    Security property (SR-01): at least one uppercase letter is required.
    """
    assert is_password_strong("nouppercase1!") is False


def test_is_password_strong_rejects_no_digit() -> None:
    """A password with no digit is rejected.

    Security property (SR-01): at least one decimal digit is required.
    """
    assert is_password_strong("NoDigitHere!!") is False


def test_is_password_strong_rejects_no_special() -> None:
    """A password with no special character is rejected.

    Security property (SR-01): at least one special (non-alphanumeric)
    character is required.
    """
    assert is_password_strong("NoSpecialChar1") is False


# ---------------------------------------------------------------------------
# create_access_token
# ---------------------------------------------------------------------------


def test_create_access_token_contains_expected_claims() -> None:
    """The access token payload must contain all required claims.

    Security property (SR-06): tokens must carry sub, role, session_id, jti,
    typ, iat, and exp so that every authenticated request can be fully
    validated without a database lookup.
    """
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
    """The token's exp claim must equal iat plus the configured TTL.

    Security property (SR-06): the maximum access token lifetime is 15 minutes.
    The exp claim must reflect the configured TTL precisely so that the token
    cannot outlive its intended window.
    """
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


# ---------------------------------------------------------------------------
# decode_access_token
# ---------------------------------------------------------------------------


def test_decode_access_token_valid() -> None:
    """decode_access_token returns the correct payload for a valid token.

    Security property (SR-06): a freshly issued access token must decode
    successfully and its claims must match the values used at issuance.
    """
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
    """decode_access_token raises InvalidTokenError for an expired token.

    Security property (SR-06): expired tokens must be unconditionally rejected.
    A token with exp in the past must never be accepted, regardless of
    signature validity.
    """
    # Issue a token that expired one second in the past by using a negative TTL.
    # We craft the payload manually to set exp = iat - 1 second.
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
    """decode_access_token raises InvalidTokenError when the signature is tampered.

    Security property (SR-06): a token signed with a different key must be
    rejected.  This guards against forgery by any party that does not hold the
    server's signing secret.
    """
    token = create_access_token(
        subject="user-abc",
        role="user",
        session_id="sess-xyz",
        settings=_TEST_SETTINGS,
    )
    # Corrupt the signature segment (last part of the compact JWS)
    parts = token.split(".")
    parts[2] = parts[2][:-4] + "XXXX"
    tampered_token = ".".join(parts)

    try:
        decode_access_token(tampered_token, _TEST_SETTINGS)
        assert False, "Expected InvalidTokenError was not raised"  # noqa: B011
    except InvalidTokenError:
        pass


def test_decode_access_token_rejects_wrong_typ() -> None:
    """decode_access_token raises InvalidTokenError when typ is not 'access'.

    Security property (SR-06 + SR-13): a step-up token (typ='step_up') must
    not be accepted as a bearer token.  The typ check prevents an attacker
    from reusing a step-up token to authenticate as a regular access token,
    which would bypass the TOTP re-verification requirement.
    """
    from datetime import datetime, timezone

    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": "user-abc",
        "role": "user",
        "session_id": "sess-xyz",
        "jti": "test-jti",
        "typ": "step_up",  # wrong type
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


# ---------------------------------------------------------------------------
# generate_refresh_token
# ---------------------------------------------------------------------------


def test_generate_refresh_token_is_urlsafe_string() -> None:
    """generate_refresh_token returns a non-empty string with no whitespace.

    Security property (SR-07): the raw refresh token must be a well-formed
    opaque string suitable for transmission in an HTTP cookie value.
    """
    token = generate_refresh_token()
    assert isinstance(token, str)
    assert len(token) > 0
    assert " " not in token
    assert "\n" not in token
    assert "\t" not in token


def test_generate_refresh_token_is_unique() -> None:
    """Two calls to generate_refresh_token must return different values.

    Security property (SR-07): refresh tokens must be unpredictable.  If two
    successive calls returned the same value, the token space would be
    predictable and could be enumerated by an attacker.
    """
    token_a = generate_refresh_token()
    token_b = generate_refresh_token()
    assert token_a != token_b


# ---------------------------------------------------------------------------
# hash_token
# ---------------------------------------------------------------------------


def test_hash_token_is_hex_string() -> None:
    """hash_token returns a 64-character lowercase hex string (SHA-256 digest).

    Security property (SR-07, SR-03): the stored hash must be a fixed-length
    hex string so that it can serve as a stable database lookup key.
    """
    digest = hash_token("some-raw-token-value")
    assert isinstance(digest, str)
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_hash_token_is_deterministic() -> None:
    """hash_token produces the same output for the same input on repeated calls.

    Security property (SR-07, SR-03): the hash function is used as a lookup
    key.  It must be deterministic so that hashing a token received from a
    client yields the same digest that was stored at issuance time.
    """
    raw = "deterministic-token-input"
    assert hash_token(raw) == hash_token(raw)


def test_hash_token_different_inputs_differ() -> None:
    """hash_token produces different outputs for different inputs.

    Security property (SR-07, SR-03): if two different tokens produced the
    same hash, one token could be used to look up and invalidate a different
    token — a hash collision attack on the token store.
    """
    assert hash_token("token-one") != hash_token("token-two")
