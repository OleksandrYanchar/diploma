"""Authentication router — registration, verification, login, refresh, and logout.

Exposes:
- POST /auth/register     -- create a new user account (SR-01, SR-02, SR-03)
- GET  /auth/verify-email -- consume the email verification token (SR-03)
- POST /auth/login        -- authenticate and receive JWT + refresh token
                             (SR-02, SR-05, SR-06, SR-07, SR-10, SR-16)
- POST /auth/refresh      -- rotate refresh token and issue new access token
                             (SR-07, SR-08, SR-10, SR-16)
- POST /auth/logout       -- terminate session, revoke tokens
                             (SR-09, SR-10, SR-16)

Route handlers are intentionally thin: they extract HTTP inputs, delegate all
business logic to ``auth.service``, and format the response.  No security
decisions are made here.

Security note: /register, /verify-email, /login, and /refresh are unauthenticated
by design -- /refresh accepts an expired access token intentionally, so it cannot
require a valid Bearer credential.  /logout requires a valid Bearer token via
``get_current_user``.  Rate limiting is enforced at the Nginx layer (SR-15).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.service import login as login_service
from app.auth.service import logout as logout_service
from app.auth.service import refresh_tokens as refresh_tokens_service
from app.auth.service import register_user, verify_email
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.redis import get_redis
from app.core.security import decode_access_token
from app.dependencies.auth import get_current_user
from app.models.user import User
from app.schemas.auth import LoginRequest, LogoutRequest, RefreshRequest, TokenResponse
from app.schemas.user import UserCreate, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UserResponse:
    """Register a new user account and issue an email verification token.

    Delegates to ``register_user`` in the auth service.  On success, returns
    the public user representation (no hashed_password, no mfa_secret).

    The raw verification token is delivered out-of-band (printed to stdout in
    demo mode; sent via SMTP in production).

    Args:
        body:     Validated ``UserCreate`` payload (email + password).
        db:       Injected async database session.
        settings: Injected application settings.

    Returns:
        A ``UserResponse`` for the newly created user with HTTP 201.

    Raises:
        HTTPException 422: Weak password or invalid email format.
        HTTPException 409: Email address already registered.
    """
    user = await register_user(
        email=body.email,
        password=body.password,
        db=db,
        settings=settings,
    )
    return UserResponse.model_validate(user)


@router.get(
    "/verify-email",
    summary="Verify email address via one-time token",
    status_code=status.HTTP_200_OK,
)
async def verify_email_endpoint(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Verify a user's email address using the one-time verification token.

    The token is received as a query parameter (e.g. from an email link).
    Delegates to ``verify_email`` in the auth service, which hashes the raw
    token and performs a constant-time lookup against the stored hash (SR-03).

    The token is single-use: on success it is cleared from the database so
    that replay attempts return HTTP 400.

    Args:
        token: The raw verification token from the query string.
        db:    Injected async database session.

    Returns:
        A success message dict with HTTP 200.

    Raises:
        HTTPException 400: Invalid, expired, or already used token.
    """
    await verify_email(token=token, db=db)
    return {"message": "Email verified successfully."}


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and receive access + refresh tokens",
)
async def login(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    """Authenticate a user with email and password and issue a session.

    Delegates to ``login`` in the auth service, which performs credential
    verification, account lockout enforcement, optional MFA gating, session
    creation in Redis, and audit log writes.

    On success, returns a short-lived JWT access token (SR-06) and an opaque
    refresh token (SR-07).  The refresh token is stored in the DB as a
    SHA-256 hash only -- the raw value is returned here once and never persisted.

    Args:
        body:     Validated ``LoginRequest`` payload (email + password; optional
                  TOTP code for MFA accounts in Phase 3).
        db:       Injected async database session.
        redis:    Injected Redis client for session storage (SR-10).
        settings: Injected application settings.

    Returns:
        A ``TokenResponse`` containing ``access_token``, ``refresh_token``,
        ``token_type="bearer"``, and ``expires_in`` (seconds).

    Raises:
        HTTPException 401: Invalid credentials (wrong email or wrong password).
        HTTPException 403: Account deactivated or temporarily locked (SR-05).
        HTTPException 200: MFA is enabled; client must supply TOTP code (SR-04).
    """
    access_token, raw_refresh = await login_service(
        email=body.email,
        password=body.password,
        db=db,
        redis=redis,
        settings=settings,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate refresh token and issue a new access + refresh token pair",
)
async def refresh(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    """Rotate the client's refresh token and issue a new token pair.

    This endpoint is intentionally unauthenticated: its entire purpose is to
    renew an expired or expiring access token.  The access token is NOT required
    in the Authorization header here — the refresh token in the request body is
    the sole credential.

    The service layer enforces:
    - SR-07: The old refresh token is marked revoked immediately on use.  A new
      opaque refresh token with a fresh session_id replaces it.
    - SR-08: If the presented refresh token is already revoked, the Redis session
      for that token's session_id is destroyed before the 401 is returned.  This
      ensures that a token-theft scenario cannot be exploited silently.
    - SR-10: The Redis session is rotated to a new session_id on every successful
      refresh.  The old session key is deleted.
    - SR-16: A TOKEN_REFRESHED audit log entry is written on success.

    Args:
        body:     Validated ``RefreshRequest`` containing the raw refresh token.
        db:       Injected async database session.
        redis:    Injected Redis client for session management.
        settings: Injected application settings (signing key, token lifetimes).

    Returns:
        A ``TokenResponse`` with a new ``access_token``, new ``refresh_token``,
        ``token_type="bearer"``, and ``expires_in`` (seconds).

    Raises:
        HTTPException 401: Token not found, already used (SR-08), or expired.
    """
    new_access_token, new_raw_refresh = await refresh_tokens_service(
        raw_refresh_token=body.refresh_token,
        db=db,
        redis=redis,
        settings=settings,
    )
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_raw_refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Terminate the current session and revoke tokens",
)
async def logout(
    body: LogoutRequest,
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    """Terminate the authenticated user's session and revoke both tokens.

    Blacklists the access token JTI in Redis (SR-09), revokes the refresh
    token in the database (SR-07), deletes the Redis session record (SR-10),
    and writes a LOGOUT audit log entry (SR-16).

    The access token is supplied via the ``Authorization: Bearer`` header and
    is validated by both ``get_current_user`` and a second
    ``decode_access_token`` call to extract the raw payload (JTI and
    session_id) needed for revocation.  The double decode is safe and correct
    -- both calls validate against the same signing key and the overhead is
    negligible.

    The refresh token is supplied in the request body and is revoked by its
    SHA-256 hash.  If it is already revoked (e.g. from a prior logout or
    rotation), the step is skipped silently.

    Args:
        body:         Validated ``LogoutRequest`` containing the raw refresh token.
        current_user: Authenticated User provided by ``get_current_user``.
        credentials:  Raw Bearer credentials extracted by ``HTTPBearer``.
        db:           Injected async database session.
        redis:        Injected Redis client for blacklist and session operations.
        settings:     Injected application settings (signing key, algorithm).

    Returns:
        A success message dict with HTTP 200.

    Raises:
        HTTPException 401: Token invalid, expired, revoked, or session gone.
        HTTPException 403: Authorization header absent (HTTPBearer behaviour).
    """
    # Decode the access token a second time to obtain the raw payload dict.
    # get_current_user already validated the token; this call is guaranteed to
    # succeed because the same token just passed the dependency.  We need the
    # payload directly (jti, exp, session_id) for the revocation operations.
    try:
        payload = decode_access_token(credentials.credentials, settings)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        ) from exc

    await logout_service(
        user=current_user,
        raw_refresh_token=body.refresh_token,
        access_token_payload=payload,
        db=db,
        redis=redis,
    )
    return {"message": "Logged out successfully."}
