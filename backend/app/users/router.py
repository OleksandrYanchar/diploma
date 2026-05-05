"""Users router — Phase 4.

Route handlers are intentionally thin: they extract HTTP inputs, delegate all
business logic to dependencies, and format the response.  No security decisions
are made here.

Security note: GET /users/me requires authentication (a valid JWT validated by
``get_current_user``) but does NOT require email verification.  Per Phase 4
policy and API_SCOPE.md, unverified users may read their own profile so that
they can see their verification status and act on it.
"""

from fastapi import APIRouter, Depends

from app.dependencies.auth import get_current_user
from app.models.user import User
from app.schemas.user import UserResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=200,
    summary="Return the authenticated user's own profile",
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the authenticated user's own profile.

    Requires authentication (JWT validated by ``get_current_user``).
    Email verification is NOT required — unverified users may inspect their
    own profile to confirm their account state (SR-03, Phase 4 policy).

    Args:
        current_user: Authenticated ``User`` provided by ``get_current_user``.
                      The dependency enforces all seven Zero Trust checks
                      (signature, expiry, JTI blacklist, Redis session, DB
                      lookup, active state, lockout state) before this handler
                      is reached.

    Returns:
        A ``UserResponse`` containing the caller's public profile with HTTP 200.

    Raises:
        HTTPException 401: Token is invalid, expired, revoked, or session is
            absent.
        HTTPException 403: Authorization header is missing (HTTPBearer
            behaviour) or account is deactivated/locked.
    """
    return UserResponse.model_validate(current_user)
