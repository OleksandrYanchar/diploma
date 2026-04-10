"""Pydantic schemas for authentication flows.

Covers login, token responses, token refresh, logout, MFA, step-up
authentication, and password management.

Security properties:
- ``TokenResponse`` never exposes the raw refresh token hash; only the raw
  token (issued once at login/refresh) is returned to the client (SR-07).
- ``LoginRequest`` accepts only email + password at the schema level; TOTP
  code is optional because the MFA step may be a separate round-trip (SR-04).
- ``StepUpRequest`` carries only the TOTP code; the user identity is derived
  from the JWT access token on the server side, not from client-supplied data.
"""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Request body for POST /auth/login."""

    email: EmailStr
    password: str = Field(min_length=1)
    # TOTP code is optional at the schema level; the service layer raises 401
    # if it is absent when the account has MFA enabled (SR-04).
    totp_code: str | None = Field(
        default=None,
        min_length=6,
        max_length=8,
        description="Six-digit TOTP code.  Required when MFA is enabled.",
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

    Contains the raw access token (JWT) and the raw refresh token (opaque).
    Both are single-use in the sense that the refresh token is rotated on
    every use and the access token is short-lived (SR-06, SR-07).
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds.")


class RefreshRequest(BaseModel):
    """Request body for POST /auth/refresh."""

    refresh_token: str = Field(
        min_length=1,
        description="The raw refresh token received at login.",
    )


class LogoutRequest(BaseModel):
    """Request body for POST /auth/logout.

    The access token comes from the Authorization header; only the refresh
    token needs to be supplied in the body so it can be revoked.
    """

    refresh_token: str = Field(min_length=1)


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

    totp_code: str = Field(min_length=6, max_length=8)


class MFADisableRequest(BaseModel):
    """Request body for POST /auth/mfa/disable.

    Requires password confirmation to prevent an attacker with a stolen
    access token from silently disabling MFA (SR-04).
    """

    password: str = Field(min_length=1)
    totp_code: str = Field(min_length=6, max_length=8)


class StepUpRequest(BaseModel):
    """Request body for POST /auth/step-up.

    The user provides a fresh TOTP code to receive a short-lived step-up JWT
    that authorises a single sensitive operation (SR-13).
    """

    totp_code: str = Field(min_length=6, max_length=8)


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
