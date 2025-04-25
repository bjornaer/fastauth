from collections.abc import Callable

from fastapi import Depends, HTTPException, Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from .models import TokenData
from .token import verify_token


def _get_token_from_request(request: Request) -> str | None:
    """Extract token from request (header, cookie, or query param)"""
    # Try Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.replace("Bearer ", "")

    # Try cookie
    token = request.cookies.get("access_token")
    if token:
        return token

    # Try query parameter
    token = request.query_params.get("access_token")
    if token:
        return token

    return None


def require_auth(auto_error: bool = True) -> Callable:
    """Dependency for routes that require authentication"""

    async def dependency(request: Request) -> TokenData:
        # Check if authentication was already performed by middleware
        if hasattr(request.state, "user"):
            return request.state.user

        # Try to authenticate
        token = _get_token_from_request(request)
        if not token:
            if auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

        # Verify token
        token_data = verify_token(token)
        # Store in request state for future use
        request.state.user = token_data
        return token_data

    return dependency


def require_role(roles: list[str], require_all: bool = False):
    """Dependency for routes that require specific role(s)"""

    async def dependency(token_data: TokenData = Depends(require_auth())) -> TokenData:
        if not token_data:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_roles = set(token_data.roles)
        required_roles = set(roles)

        if require_all:
            # User must have all specified roles
            if not required_roles.issubset(user_roles):
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required roles: {', '.join(roles)}",
                )
        else:
            # User must have at least one of the specified roles
            if not user_roles.intersection(required_roles):
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required one of: {', '.join(roles)}",
                )

        return token_data

    return dependency
