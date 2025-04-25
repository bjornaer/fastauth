from pydantic import BaseModel, Field


class User(BaseModel):
    """Base user model for authentication"""

    id: str
    username: str
    email: str | None = None
    roles: list[str] = Field(default_factory=list)


class TokenData(BaseModel):
    """Data extracted from a verified JWT token"""

    user_id: str
    roles: list[str] = Field(default_factory=list)


class TokenResponse(BaseModel):
    """Response model for token operations"""

    access_token: str
    refresh_token: str
    token_type: str
