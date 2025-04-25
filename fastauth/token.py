import importlib.util
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

from fastapi import HTTPException, status
from jose import JWTError, jwt
from pydantic import ValidationError

from .models import TokenData, TokenResponse, User
from .storage import MemoryTokenStorage, RedisTokenStorage, TokenStorage

# Module-level variables
_token_manager: Optional["TokenManager"] = None
_token_storage: TokenStorage | None = None

# Try to load redis if available
_redis_available = importlib.util.find_spec("redis") is not None


class TokenManager:
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
        token_storage: TokenStorage | None = None,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.token_storage = token_storage or MemoryTokenStorage()

    def create_token(
        self,
        data: dict[str, Any],
        token_type: str = "access",
        add_timestamp_offset: bool = False,
    ) -> str:
        """Create a new token"""
        to_encode = data.copy()

        # Add a small random offset to ensure different tokens
        offset_seconds = 0
        if add_timestamp_offset:
            import random

            offset_seconds = random.randint(1, 10)

        if token_type == "access":
            expire = datetime.now(UTC) + timedelta(minutes=self.access_token_expire_minutes, seconds=offset_seconds)
        else:
            expire = datetime.now(UTC) + timedelta(days=self.refresh_token_expire_days, seconds=offset_seconds)

        to_encode.update({"exp": expire})

        # Add token version if user_id is present
        if "sub" in to_encode:
            user_id = to_encode["sub"]
            token_version = self.token_storage.get_user_token_version(user_id)
            to_encode["ver"] = token_version

        encoded_jwt: str = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_access_token(self, data: dict[str, Any]) -> str:
        """Create a new access token"""
        to_encode = data.copy()
        expire = datetime.now(UTC) + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire})

        # Add token version if user_id is present
        if "sub" in to_encode:
            user_id = to_encode["sub"]
            token_version = self.token_storage.get_user_token_version(user_id)
            to_encode["ver"] = token_version

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_refresh_token(self, data: dict[str, Any]) -> Any:
        """Create a new refresh token"""
        to_encode = data.copy()
        expire = datetime.now(UTC) + timedelta(days=self.refresh_token_expire_days)
        to_encode.update({"exp": expire})

        # Add token version if user_id is present
        if "sub" in to_encode:
            user_id = to_encode["sub"]
            token_version = self.token_storage.get_user_token_version(user_id)
            to_encode["ver"] = token_version

        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def verify_token(self, token: str) -> TokenData:
        """Verify a token and return the decoded payload"""
        try:
            # Decode the token
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            user_id: str = payload.get("sub")
            roles: list[str] = payload.get("roles", [])
            token_version: int = payload.get("ver", 0)

            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Check if token is revoked
            if self.token_storage.is_token_revoked(token, user_id):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Check token version
            current_version = self.token_storage.get_user_token_version(user_id)
            if token_version < current_version:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token version is outdated, please login again",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            token_data = TokenData(user_id=user_id, roles=roles)
            return token_data

        except (JWTError, ValidationError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e

    def generate_tokens(self, user: User) -> TokenResponse:
        """Generate both access and refresh tokens for a user"""
        access_token_data = {"sub": str(user.id), "roles": user.roles, "type": "access"}

        refresh_token_data = {"sub": str(user.id), "type": "refresh"}

        access_token = self.create_token(access_token_data)
        refresh_token = self.create_token(refresh_token_data)

        return TokenResponse(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

    def rotate_tokens(self, user: User) -> TokenResponse:
        """
        Generate new tokens with a new version, effectively invalidating all previous tokens
        """
        # Increment the user's token version
        self.token_storage.increment_user_token_version(user.id)

        # Generate new tokens with the updated version
        return self.generate_tokens(user)


# Updated setup function to support Redis
def setup_token_manager(
    secret_key: str,
    algorithm: str = "HS256",
    access_token_expire_minutes: int = 30,
    refresh_token_expire_days: int = 7,
    redis_url: str | None = None,
) -> None:
    """Setup the token manager with configuration"""
    global _token_manager, _token_storage

    # Configure storage
    if redis_url and _redis_available:
        import redis

        redis_client = redis.from_url(redis_url)
        _token_storage = RedisTokenStorage(redis_client)
    else:
        _token_storage = MemoryTokenStorage()

    # Create token manager
    _token_manager = TokenManager(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
        token_storage=_token_storage,
    )


def _ensure_token_manager() -> TokenManager:
    """Ensure the token manager is configured"""
    if _token_manager is None:
        raise RuntimeError("Token manager not initialized. Call setup_token_manager first.")
    return _token_manager


def generate_token(user: User) -> TokenResponse:
    """Generate access and refresh tokens for a user"""
    manager = _ensure_token_manager()
    return manager.generate_tokens(user)


def verify_token(token: str) -> TokenData:
    """Verify a token and return token data"""
    manager = _ensure_token_manager()
    return manager.verify_token(token)


def refresh_token(refresh_token_str: str, user: User) -> TokenResponse:
    """Refresh access token using a refresh token"""
    manager = _ensure_token_manager()

    try:
        payload = jwt.decode(refresh_token_str, manager.secret_key, algorithms=[manager.algorithm])
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = payload.get("sub")
        if str(user_id) != str(user.id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token belongs to another user",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify token version if present
        if "ver" in payload:
            current_version = manager.token_storage.get_user_token_version(user_id)
            if payload.get("ver") != current_version:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token version is outdated",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        # Generate fresh tokens - make sure they're actually new tokens
        # by adding a small timestamp offset to ensure different expiration times
        access_token = manager.create_token(
            {"sub": user.id, "roles": user.roles, "type": "access"}, add_timestamp_offset=True
        )

        refresh_token = manager.create_token(
            {"sub": user.id, "type": "refresh"}, token_type="refresh", add_timestamp_offset=True
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    except (JWTError, ValidationError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


def revoke_token(token: str, revoke_refresh: bool = False) -> None:
    """Revoke a specific token"""
    manager = _ensure_token_manager()

    try:
        # Extract user_id from token
        payload = jwt.decode(token, manager.secret_key, algorithms=[manager.algorithm])
        user_id = payload.get("sub")

        # Add to revoked tokens
        manager.token_storage.add_revoked_token(token, user_id)

    except (JWTError, ValidationError):
        # If token can't be decoded, still revoke it
        manager.token_storage.add_revoked_token(token)


def revoke_all_user_tokens(user_id: str) -> None:
    """Revoke all tokens for a specific user"""
    manager = _ensure_token_manager()
    manager.token_storage.revoke_all_user_tokens(str(user_id))


def rotate_user_tokens(user: User) -> TokenResponse:
    """
    Rotate tokens for a user, invalidating all previous tokens
    """
    manager = _ensure_token_manager()
    return manager.rotate_tokens(user)


def is_token_revoked(token: str) -> bool:
    """Check if a token has been revoked"""
    if _token_manager is None:
        raise RuntimeError("Token manager not initialized. Call setup_token_manager first.")

    try:
        payload = jwt.decode(token, _token_manager.secret_key, algorithms=[_token_manager.algorithm])
        user_id = payload.get("sub")
        return _token_manager.token_storage.is_token_revoked(token, user_id)
    except (JWTError, ValidationError):
        # If token can't be decoded, consider it invalid but not necessarily revoked
        return False


def clear_expired_revocations() -> None:
    """Clear expired tokens from revocation list to free memory"""
    if _token_manager is None:
        return

    current_time = time.time()
    _token_manager.token_storage.clear_expired_tokens(current_time)
