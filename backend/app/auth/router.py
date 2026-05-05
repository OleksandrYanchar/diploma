"""Authentication router — registration, verification, login, refresh, logout, and MFA.

Route handlers are intentionally thin: they extract HTTP inputs, delegate all
business logic to ``auth.service``, and format the response.  No security
decisions are made here.

Security note: /register, /verify-email, /login, /refresh, /password/reset/request,
and /password/reset/confirm are unauthenticated by design.  /logout, /mfa/setup,
/mfa/enable, /mfa/disable, /password/change, and /step-up require a valid Bearer
token via ``get_current_user``.  /step-up additionally requires ``require_verified``.
Rate limiting is enforced at the Nginx layer (SR-15).
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.service import (
    change_password,
    confirm_password_reset,
    disable_mfa,
    enable_mfa,
    register_user,
    request_password_reset,
    setup_mfa,
    verify_email,
    verify_step_up,
)
from app.auth.service import login as login_service
from app.auth.service import logout as logout_service
from app.auth.service import refresh_tokens as refresh_tokens_service
from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.redis import get_redis
from app.core.security import decode_access_token
from app.dependencies.auth import get_current_user, require_verified
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    MFADisableRequest,
    MFAEnableRequest,
    MFARequiredResponse,
    MFASetupResponse,
    PasswordChangeRequest,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    RefreshRequest,
    StepUpRequest,
    StepUpResponse,
    TokenResponse,
)
from app.schemas.user import UserCreate, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    request: Request,
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
        request:  The incoming FastAPI Request, used to extract IP and
                  User-Agent for audit logging (SR-16).
        body:     Validated ``UserCreate`` payload (email + password).
        db:       Injected async database session.
        settings: Injected application settings.

    Returns:
        A ``UserResponse`` for the newly created user with HTTP 201.

    Raises:
        HTTPException 422: Weak password or invalid email format.
        HTTPException 409: Email address already registered.
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    user = await register_user(
        email=body.email,
        password=body.password,
        db=db,
        settings=settings,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return UserResponse.model_validate(user)


@router.get(
    "/verify-email",
    summary="Verify email address via one-time token",
    status_code=status.HTTP_200_OK,
)
async def verify_email_endpoint(
    request: Request,
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
        request: The incoming FastAPI Request, used to extract IP and
                 User-Agent for audit logging (SR-16).
        token:   The raw verification token from the query string.
        db:      Injected async database session.

    Returns:
        A success message dict with HTTP 200.

    Raises:
        HTTPException 400: Invalid, expired, or already used token.
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    await verify_email(
        token=token,
        db=db,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return {"message": "Email verified successfully."}


@router.post(
    "/login",
    response_model=None,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and receive access + refresh tokens",
)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
) -> TokenResponse | MFARequiredResponse:
    """Authenticate a user with email and password and issue a session.

    Delegates to ``login`` in the auth service, which performs credential
    verification, account lockout enforcement, MFA gating, session creation
    in Redis, and audit log writes.

    On success, returns a short-lived JWT access token (SR-06) and an opaque
    refresh token (SR-07).  The refresh token is stored in the DB as a
    SHA-256 hash only — the raw value is returned here once and never persisted.

    When the account has MFA enabled the service returns the sentinel
    ``(None, None)`` — no session is created and no tokens are issued.  This
    endpoint then returns an ``MFARequiredResponse`` (HTTP 200) so that the
    client can prompt the user for their TOTP code and re-submit.  The TOTP
    verification path is implemented in Phase 3.

    Args:
        request:  The incoming FastAPI Request, used to extract IP and
                  User-Agent for audit logging (SR-16).
        body:     Validated ``LoginRequest`` payload (email + password; optional
                  TOTP code for MFA accounts in Phase 3).
        db:       Injected async database session.
        redis:    Injected Redis client for session storage (SR-10).
        settings: Injected application settings.

    Returns:
        ``TokenResponse`` (access_token, refresh_token, token_type, expires_in)
        on successful authentication, or ``MFARequiredResponse`` (mfa_required,
        message) when the account requires a TOTP code.

    Raises:
        HTTPException 401: Invalid credentials (wrong email or wrong password).
        HTTPException 403: Account deactivated or temporarily locked (SR-05).
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    access_token, raw_refresh = await login_service(
        email=body.email,
        password=body.password,
        db=db,
        redis=redis,
        settings=settings,
        totp_code=body.totp_code,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if access_token is None:
        return MFARequiredResponse()

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
    request: Request,
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
        request:  The incoming FastAPI Request, used to extract IP and
                  User-Agent for audit logging (SR-16).
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
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    new_access_token, new_raw_refresh = await refresh_tokens_service(
        raw_refresh_token=body.refresh_token,
        db=db,
        redis=redis,
        settings=settings,
        ip_address=ip_address,
        user_agent=user_agent,
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
    request: Request,
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
        request:      The incoming FastAPI Request, used to extract IP and
                      User-Agent for audit logging (SR-16).
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
    try:
        payload = decode_access_token(credentials.credentials, settings)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        ) from exc

    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    await logout_service(
        user=current_user,
        raw_refresh_token=body.refresh_token,
        access_token_payload=payload,
        db=db,
        redis=redis,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return {"message": "Logged out successfully."}


@router.post(
    "/mfa/setup",
    response_model=MFASetupResponse,
    status_code=status.HTTP_200_OK,
    summary="Initiate TOTP MFA enrollment and receive secret + QR code",
)
async def mfa_setup(
    request: Request,
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> MFASetupResponse:
    """Initiate TOTP MFA enrollment for the authenticated user.

    Generates a fresh TOTP secret, stores it on the user record, emits an
    audit log entry (SR-16), and returns the secret plus a base64-encoded QR
    code PNG for scanning with an authenticator app.

    The secret is returned exactly once in this response.  It is never
    returned again by any subsequent API call (SR-04).  The QR code embeds the
    raw secret and is equally sensitive; both must be transmitted over TLS.

    MFA is not active after this call.  The user must call POST /auth/mfa/enable
    (Phase 4) with a valid TOTP code to confirm enrollment and activate the gate.

    Args:
        request:      The incoming FastAPI Request, used to extract IP and
                      User-Agent for audit logging (SR-16).
        current_user: Authenticated User provided by ``get_current_user``.
        db:           Injected async database session.
        settings:     Injected application settings (app_name used as issuer).

    Returns:
        An ``MFASetupResponse`` containing ``secret``, ``qr_code_base64``, and
        ``issuer`` with HTTP 200.

    Raises:
        HTTPException 400: MFA is already enabled on this account.
        HTTPException 401: Missing or invalid Authorization token.
        HTTPException 403: Authorization header absent (HTTPBearer behaviour).
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    secret, qr_code_base64 = await setup_mfa(
        user=current_user,
        db=db,
        settings=settings,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return MFASetupResponse(
        secret=secret,
        qr_code_base64=qr_code_base64,
        issuer=settings.app_name,
    )


@router.post(
    "/mfa/enable",
    status_code=status.HTTP_200_OK,
    summary="Confirm TOTP enrollment and activate the MFA gate",
)
async def mfa_enable(
    request: Request,
    body: MFAEnableRequest,
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Verify the first TOTP code and activate MFA on the authenticated account.

    The user must have already called POST /auth/mfa/setup to receive a secret
    and scan the QR code before calling this endpoint.  Submitting a valid TOTP
    code confirms that the authenticator app is correctly configured and activates
    the MFA gate (SR-04).

    On success, ``user.mfa_enabled`` is set to True and an MFA_ENABLED audit log
    entry is written (SR-16).  All subsequent logins for this account will require
    a TOTP code in addition to the password.

    On invalid code, an MFA_FAILED audit log entry is committed before the 401
    is returned (SR-16).

    Args:
        request:      The incoming FastAPI Request, used to extract IP and
                      User-Agent for audit logging (SR-16).
        body:         Validated ``MFAEnableRequest`` containing the TOTP code.
        current_user: Authenticated User provided by ``get_current_user``.
        db:           Injected async database session.

    Returns:
        A success message dict with HTTP 200.

    Raises:
        HTTPException 400: MFA setup was never initiated, or MFA is already enabled.
        HTTPException 401: TOTP code is invalid (MFA_FAILED audit log written).
        HTTPException 403: Authorization header absent (HTTPBearer behaviour).
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    await enable_mfa(
        user=current_user,
        totp_code=body.totp_code,
        db=db,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return {"detail": "MFA enabled successfully"}


@router.post(
    "/mfa/disable",
    status_code=status.HTTP_200_OK,
    summary="Disable MFA after verifying password and current TOTP code",
)
async def mfa_disable(
    request: Request,
    body: MFADisableRequest,
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Deactivate the MFA gate on the authenticated account.

    Requires both the account password and a current valid TOTP code to
    prevent an attacker who holds a stolen access token from silently
    disabling MFA (SR-04).

    On success, ``user.mfa_enabled`` is set to False, ``user.mfa_secret``
    is cleared, and an MFA_DISABLED audit log entry is written (SR-16).

    On an invalid TOTP code, an MFA_FAILED audit log entry is committed
    before the 401 is returned (SR-16).

    Args:
        request:      The incoming FastAPI Request, used to extract IP and
                      User-Agent for audit logging (SR-16).
        body:         Validated ``MFADisableRequest`` (password + totp_code).
        current_user: Authenticated User provided by ``get_current_user``.
        db:           Injected async database session.

    Returns:
        A success message dict with HTTP 200.

    Raises:
        HTTPException 400: MFA is not currently enabled on this account.
        HTTPException 401: Password is incorrect.
        HTTPException 401: TOTP code is invalid (MFA_FAILED audit log written).
        HTTPException 403: Authorization header absent (HTTPBearer behaviour).
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    await disable_mfa(
        user=current_user,
        password=body.password,
        totp_code=body.totp_code,
        db=db,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return {"detail": "MFA disabled successfully"}


@router.post(
    "/password/change",
    status_code=status.HTTP_200_OK,
    summary="Change the authenticated user's password",
)
async def password_change(
    request: Request,
    body: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Change the authenticated user's password.

    Verifies the current password, enforces the SR-01 strength policy on the
    new password, and writes a PASSWORD_CHANGED audit log entry on success
    (SR-16).  Existing sessions are NOT revoked — see ADR-21 for rationale.

    Requires authentication (AUTHENTICATED access level per API_SCOPE.md).
    Email verification is not required for this endpoint.

    Args:
        request:      The incoming FastAPI Request, used to extract IP and
                      User-Agent for audit logging (SR-16).
        body:         Validated ``PasswordChangeRequest`` (current_password +
                      new_password).
        current_user: Authenticated User provided by ``get_current_user``.
        db:           Injected async database session.

    Returns:
        A success message dict with HTTP 200.

    Raises:
        HTTPException 401: Current password is incorrect.
        HTTPException 422: New password fails the SR-01 strength policy.
        HTTPException 403: Authorization header absent (HTTPBearer behaviour).
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    await change_password(
        user=current_user,
        current_password=body.current_password,
        new_password=body.new_password,
        db=db,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return {"detail": "Password changed successfully"}


@router.post(
    "/step-up",
    response_model=StepUpResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify TOTP and issue a short-lived step-up token",
)
async def step_up(
    request: Request,
    body: StepUpRequest,
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
) -> StepUpResponse:
    """Verify a fresh TOTP code and issue a short-lived step-up JWT.

    The step-up token authorises a single sensitive operation (e.g. a funds
    transfer) within a short time window.  It is separate from the regular
    access token so that the TOTP re-verification requirement is enforced at
    the sensitive endpoint, not just at login time (SR-13).

    The issued token has ``typ="step_up"`` and cannot be submitted as a
    regular bearer credential — ``decode_access_token`` rejects it on
    ``typ`` mismatch.  The JTI is stored in Redis under ``step_up:{jti}``
    with a TTL equal to the token lifetime; ``require_step_up`` (Phase 6)
    will consume it exactly once (SR-14).

    MFA must be enabled on the account; without an enrolled second factor
    there is no TOTP code to verify and the endpoint returns 403.

    Args:
        request:      The incoming FastAPI Request, used to extract IP and
                      User-Agent for audit logging (SR-16).
        body:         Validated ``StepUpRequest`` containing the TOTP code.
        current_user: Authenticated User provided by ``get_current_user``.
        _verified:    Enforces email verification via ``require_verified`` (SR-03).
        db:           Injected async database session.
        redis:        Injected Redis client for step-up token storage (SR-14).
        settings:     Injected application settings (signing key, token lifetime).

    Returns:
        A ``StepUpResponse`` containing ``step_up_token`` and ``expires_in``
        (seconds) with HTTP 200.

    Raises:
        HTTPException 401: Missing or invalid bearer token.
        HTTPException 401: TOTP code invalid (STEP_UP_FAILED audit log written).
        HTTPException 403: Email not verified, or MFA not enabled on account.
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    token = await verify_step_up(
        user=current_user,
        totp_code=body.totp_code,
        db=db,
        redis=redis,
        settings=settings,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return StepUpResponse(
        step_up_token=token,
        expires_in=settings.step_up_token_expire_minutes * 60,
    )


@router.post(
    "/password/reset/request",
    status_code=status.HTTP_200_OK,
    summary="Request a password reset link",
)
async def password_reset_request(
    request: Request,
    body: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    """Issue a one-time password reset token for the given email address.

    This endpoint is intentionally unauthenticated: users who cannot log in
    (because they have forgotten their password) must be able to reach it.

    Enforces SR-18 non-enumeration: the response is always HTTP 200 with the
    same message body regardless of whether the email exists in the database.
    An attacker cannot distinguish a known account from an unknown one by
    observing the response.

    The raw reset token is delivered out-of-band (printed to stdout in demo
    mode; sent via SMTP in production).  The token is never included in the
    HTTP response body.

    Args:
        request:  The incoming FastAPI Request, used to extract IP and
                  User-Agent for audit logging (SR-16).
        body:     Validated ``PasswordResetRequest`` containing the email address.
        db:       Injected async database session.
        settings: Injected application settings.

    Returns:
        A fixed success message dict with HTTP 200 regardless of email existence.
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    await request_password_reset(
        email=body.email,
        db=db,
        settings=settings,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    # SR-18: identical response for both known and unknown email addresses.
    return {"message": "If that email is registered, a reset link has been sent"}


@router.post(
    "/password/reset/confirm",
    status_code=status.HTTP_200_OK,
    summary="Verify a password reset token and set a new password",
)
async def password_reset_confirm(
    request: Request,
    body: PasswordResetConfirmRequest,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    """Verify a one-time password reset token and update the account password.

    This endpoint is intentionally unauthenticated: users who cannot log in
    must be able to complete the reset flow without a Bearer token.

    On success, the service (SR-18):
    - Sets the new password as an Argon2id hash (SR-01, SR-02).
    - Clears the reset token fields so the token cannot be reused.
    - Bulk-deletes all RefreshToken rows for the user (SR-07).
    - Revokes all active Redis sessions for the user (SR-10).
    - Writes a PASSWORD_RESET_COMPLETED audit log entry (SR-16).

    On failure the service raises an HTTPException which propagates directly:
    - HTTP 400: token not found or expired (SR-18).
    - HTTP 422: new password fails the SR-01 strength policy.

    Args:
        request:  The incoming FastAPI Request, used to extract IP and
                  User-Agent for audit logging (SR-16).
        body:     Validated ``PasswordResetConfirmRequest`` (token + new_password).
        db:       Injected async database session.
        redis:    Injected Redis client for session revocation (SR-10).
        settings: Injected application settings (token TTL, password policy).

    Returns:
        A success message dict with HTTP 200.

    Raises:
        HTTPException 400: Invalid or expired reset token.
        HTTPException 422: New password fails the SR-01 strength policy.
    """
    ip_address = request.headers.get("X-Real-IP") or (
        request.client.host if request.client else None
    )
    user_agent = request.headers.get("User-Agent")
    await confirm_password_reset(
        token=body.token,
        new_password=body.new_password,
        db=db,
        redis=redis,
        settings=settings,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return {"message": "Password reset successful"}
