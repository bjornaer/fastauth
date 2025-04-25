import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import Cookie, Header, HTTPException, Request, status

# Re-export the storage manager
from .token import _ensure_token_manager

# Store CSRF tokens in memory (in production, use a proper storage backend)
_csrf_tokens: dict[str, dict[str, str]] = {}


def generate_csrf_token(user_id: str, max_age_hours: int = 24) -> str:
    """Generate a CSRF token for a user"""
    token = secrets.token_hex(32)

    # Store token hash for verification
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Get storage
    manager = _ensure_token_manager()
    storage = manager.token_storage

    # Calculate expiration
    expires_at = datetime.now(UTC) + timedelta(hours=max_age_hours)

    # Store token
    storage.store_csrf_token(user_id, token_hash, expires_at)

    # Clear old tokens for this user
    storage.clear_old_csrf_tokens(user_id, max_age_hours)

    return token


def verify_csrf_token(user_id: str, token: str) -> bool:
    """Verify a CSRF token for a user"""
    if not user_id or not token:
        return False

    # Get token hash
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Get storage
    manager = _ensure_token_manager()
    storage = manager.token_storage

    # Verify token
    return storage.verify_csrf_token(user_id, token_hash)


def clear_old_tokens(user_id: str | None = None, max_age_hours: int = 24) -> None:
    """Clear old tokens for a user or all users"""
    manager = _ensure_token_manager()
    storage = manager.token_storage

    storage.clear_old_csrf_tokens(user_id, max_age_hours)


def csrf_protection(cookie_name: str = "csrf_token", header_name: str = "X-CSRF-Token"):
    """Dependency for CSRF protection"""

    async def dependency(
        request: Request,
        csrf_cookie: str | None = Cookie(None, alias=cookie_name),
        csrf_header: str | None = Header(None, alias=header_name),
    ):
        # Safe methods don't need CSRF protection
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return True

        # Check if authentication was performed
        if not hasattr(request.state, "user"):
            # No authenticated user, no CSRF check needed
            return True

        user_id = request.state.user.user_id

        # For stateless auth, get token from either header or cookie
        token = csrf_header or csrf_cookie

        if not token:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing")

        if not verify_csrf_token(user_id, token):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")

        return True

    return dependency
