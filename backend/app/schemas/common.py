"""Common Pydantic schemas shared across multiple modules.

Contains generic response envelopes and reusable field types that are used by
more than one domain schema module.
"""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Response schema for GET /health.

    The health endpoint is the only public endpoint in Phase 1.  It confirms
    that the FastAPI application is running and reachable through Nginx.
    """

    status: str = Field(examples=["ok"])
    version: str = Field(examples=["0.1.0"])


class MessageResponse(BaseModel):
    """Generic single-message response for operations that return no resource.

    Used for confirmations such as logout, password change, or MFA disable
    where the HTTP status code is meaningful but no resource is returned.
    """

    message: str = Field(examples=["Operation completed successfully."])


class ErrorDetail(BaseModel):
    """Structured error detail included in error responses."""

    code: str = Field(examples=["TOKEN_EXPIRED"])
    message: str = Field(examples=["The access token has expired."])
