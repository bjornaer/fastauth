from datetime import datetime, timedelta
from typing import Any

from fastapi import HTTPException, status
from jose import JWTError, jwt
from pydantic import ValidationError

from .models import TokenData, TokenResponse, User


class TokenManager:
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days

    def create_access_token(self, data: dict[str, Any]) -> str:
        """Create a new access token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_refresh_token(self, data: dict[str, Any]) -> str:
        """Create a new refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def verify_token(self, token: str) -> TokenData:
        """Verify a token and return the decoded payload"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            user_id: str = payload.get("sub")
            roles: list[str] = payload.get("roles", [])

            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
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

        access_token = self.create_access_token(access_token_data)
        refresh_token = self.create_refresh_token(refresh_token_data)

        return TokenResponse(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

    def refresh_tokens(self, refresh_token: str, user: User) -> TokenResponse:
        """Generate new tokens using a refresh token"""
        try:
            payload = jwt.decode(refresh_token, self.secret_key, algorithms=[self.algorithm])

            # Verify it's a refresh token
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            user_id = payload.get("sub")

            # Verify the user_id matches
            if user_id != str(user.id):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token does not match user",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Generate new tokens
            return self.generate_tokens(user)

        except (JWTError, ValidationError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e


# Module-level functions that will be exposed
_token_manager: TokenManager | None = None


def setup_token_manager(
    secret_key: str,
    algorithm: str = "HS256",
    access_token_expire_minutes: int = 30,
    refresh_token_expire_days: int = 7,
) -> None:
    """Setup the token manager with configuration"""
    global _token_manager
    _token_manager = TokenManager(
        secret_key=secret_key,
        algorithm=algorithm,
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
    )


def _ensure_token_manager() -> TokenManager | None:
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
    """Refresh an access token using a refresh token"""
    manager = _ensure_token_manager()

    try:
        # Verify the refresh token
        payload = jwt.decode(refresh_token_str, manager.secret_key, algorithms=[manager.algorithm])

        # Check if it's a refresh token
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if the user ID matches
        if payload.get("sub") != str(user.id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token does not match user",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Generate new tokens with current timestamp
        # This ensures we get a different token than before
        return manager.generate_tokens(user)

    except (JWTError, ValidationError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
