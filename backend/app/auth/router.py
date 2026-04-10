"""Authentication router — registration and email verification endpoints.

Exposes:
- POST /auth/register  — create a new user account (SR-01, SR-02, SR-03)
- GET  /auth/verify-email — consume the email verification token (SR-03)

Route handlers are intentionally thin: they extract HTTP inputs, delegate all
business logic to ``auth.service``, and format the response.  No security
decisions are made here.

Security note: both endpoints are unauthenticated by design (no
``get_current_user`` dependency).  They are the entry points for account
creation and are intentionally public.  Rate limiting is enforced at the Nginx
layer (SR-15).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.service import register_user, verify_email
from app.core.config import Settings, get_settings
from app.core.database import get_db
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
