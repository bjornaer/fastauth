from collections.abc import Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_401_UNAUTHORIZED

from .token import verify_token


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        exclude_paths: list[str] = None,
        token_getter: Callable[[Request], str | None] = None,
    ):
        super().__init__(app)
        self.exclude_paths = exclude_paths or []
        self.token_getter = token_getter or self._default_token_getter

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip authentication for excluded paths
        path = request.url.path
        if any(path.startswith(excluded) for excluded in self.exclude_paths):
            return await call_next(request)

        # Try to get token
        token = self.token_getter(request)

        # If no token is found, we don't authenticate yet (let the route dependency handle it)
        if not token:
            return await call_next(request)

        try:
            # Verify token and add user info to request state
            token_data = verify_token(token)
            request.state.user = token_data
            return await call_next(request)
        except Exception:
            # Authentication failed
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid authentication credentials"},
                headers={"WWW-Authenticate": "Bearer"},
            )

    @staticmethod
    def _default_token_getter(request: Request) -> str | None:
        """
        Default token getter that tries to extract token from:
        1. Authorization header (Bearer token)
        2. Cookie named 'access_token'
        3. Query parameter 'access_token'
        """
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


def register_auth_middleware(
    app: FastAPI,
    exclude_paths: list[str] = None,
    token_getter: Callable[[Request], str | None] | None = None,
) -> None:
    """Register the authentication middleware with a FastAPI app"""
    app.add_middleware(
        AuthMiddleware,
        exclude_paths=exclude_paths or ["/docs", "/redoc", "/openapi.json"],
        token_getter=token_getter,
    )
