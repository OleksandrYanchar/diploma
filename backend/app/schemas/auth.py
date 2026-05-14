"""Pydantic schemas for authentication flows.

Covers login, token responses, token refresh, logout, MFA, step-up
authentication, and password management.

Security properties:
- ``TokenResponse`` contains only the access token; the refresh token is
  delivered exclusively via an HttpOnly ``Set-Cookie`` header (SR-07).
  Removing the refresh token from the JSON body prevents JavaScript from
  reading it, which eliminates the XSS token-theft vector.
- ``LoginRequest`` accepts only email + password at the schema level; TOTP
  code is optional because the MFA step may be a separate round-trip (SR-04).
- ``StepUpRequest`` carries only the TOTP code; the user identity is derived
  from the JWT access token on the server side, not from client-supplied data.
- ``RefreshRequest`` and ``LogoutRequest`` are intentionally absent: the
  refresh token is read from the ``zt_rt`` HttpOnly cookie on the server side,
  so no client-supplied body field is needed or accepted for those endpoints.
"""

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Request body for POST /auth/login."""

    email: EmailStr
    password: str = Field(min_length=1)
    totp_code: str | None = Field(
        default=None,
        min_length=6,
        max_length=8,
        pattern=r"^[0-9]{6,8}$",
        description="Six-to-eight digit TOTP code.  Required when MFA is enabled.",
    )


class MFARequiredResponse(BaseModel):
    """Returned when login succeeds on password but MFA code is required.

    The client should prompt the user for their TOTP code and re-submit the
    login request with ``totp_code`` populated.
    """

    mfa_required: bool = True
    message: str = "TOTP code required to complete login."


class TokenResponse(BaseModel):
    """Returned on successful login or token refresh.

    Contains only the short-lived JWT access token.  The opaque refresh token
    is delivered separately via an HttpOnly ``Set-Cookie: zt_rt=...`` header
    so that JavaScript cannot read it, eliminating the XSS token-theft vector
    (SR-07).  The access token is short-lived (SR-06) and must be kept in
    memory by the client — not in localStorage.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds.")


class MFASetupResponse(BaseModel):
    """Response for POST /auth/mfa/setup.

    Returns the TOTP secret and a base64-encoded QR code PNG image.
    The secret is returned only once here; subsequent API calls never
    return it (SR-04).
    """

    secret: str = Field(
        description="Base32-encoded TOTP secret.  Store in an authenticator app.",
    )
    qr_code_base64: str = Field(description="Base64-encoded PNG of the TOTP QR code.")
    issuer: str = Field(description="Issuer name shown in the authenticator app.")


class MFAEnableRequest(BaseModel):
    """Request body for POST /auth/mfa/enable.

    The user must provide their first valid TOTP code to confirm enrollment.
    This proves they have successfully scanned the QR code (SR-04).
    """

    totp_code: str = Field(
        min_length=6,
        max_length=8,
        pattern=r"^[0-9]{6,8}$",
    )


class MFADisableRequest(BaseModel):
    """Request body for POST /auth/mfa/disable.

    Requires password confirmation to prevent an attacker with a stolen
    access token from silently disabling MFA (SR-04).
    """

    password: str = Field(min_length=1)
    totp_code: str = Field(
        min_length=6,
        max_length=8,
        pattern=r"^[0-9]{6,8}$",
    )


class StepUpRequest(BaseModel):
    """Request body for POST /auth/step-up.

    The user provides a fresh TOTP code to receive a short-lived step-up JWT
    that authorises a single sensitive operation (SR-13).
    """

    totp_code: str = Field(
        min_length=6,
        max_length=8,
        pattern=r"^[0-9]{6,8}$",
    )


class StepUpResponse(BaseModel):
    """Response for POST /auth/step-up.

    Returns a step-up JWT valid for 5 minutes and one use only (SR-13, SR-14).
    The client must include this in the ``X-Step-Up-Token`` header of the
    sensitive operation request.
    """

    step_up_token: str
    expires_in: int = Field(description="Step-up token lifetime in seconds.")


class PasswordChangeRequest(BaseModel):
    """Request body for POST /auth/password/change."""

    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=12)


class PasswordResetRequest(BaseModel):
    """Request body for POST /auth/password/reset/request."""

    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    """Request body for POST /auth/password/reset/confirm."""

    token: str = Field(
        min_length=1,
        description="Raw password reset token from the email link.",
    )
    new_password: str = Field(min_length=12)


class EmailVerifyRequest(BaseModel):
    """Query parameters for GET /auth/verify-email are extracted in the route
    handler; this schema is for documentation and potential body alternatives.
    """

    token: str = Field(min_length=1, description="Email verification token.")
