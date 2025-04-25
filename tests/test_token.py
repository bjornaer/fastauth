import pytest
from fastapi import HTTPException
from jose import jwt

from fastauth.models import User
from fastauth.token import generate_token, refresh_token, setup_token_manager, verify_token


@pytest.fixture
def test_user():
    return User(id="user123", username="testuser", roles=["user"])


@pytest.fixture
def admin_user():
    return User(id="admin456", username="adminuser", roles=["admin", "user"])


@pytest.fixture
def setup_tokens():
    # Setup token manager with a test secret key
    setup_token_manager(
        secret_key="test_secret_key",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
    )


class TestTokenFunctions:
    def test_token_generation(self, test_user, setup_tokens):
        # Test generating tokens
        token_response = generate_token(test_user)

        # Check response structure
        assert token_response.token_type == "bearer"
        assert token_response.access_token is not None
        assert token_response.refresh_token is not None

        # Validate access token content
        payload = jwt.decode(token_response.access_token, "test_secret_key", algorithms=["HS256"])
        assert payload["sub"] == test_user.id
        assert payload["roles"] == test_user.roles
        assert payload["type"] == "access"
        assert "exp" in payload

        # Validate refresh token content
        payload = jwt.decode(token_response.refresh_token, "test_secret_key", algorithms=["HS256"])
        assert payload["sub"] == test_user.id
        assert payload["type"] == "refresh"
        assert "exp" in payload

    def test_token_verification(self, test_user, setup_tokens):
        # Generate token
        token_response = generate_token(test_user)

        # Verify token
        token_data = verify_token(token_response.access_token)

        # Check token data
        assert token_data.user_id == test_user.id
        assert token_data.roles == test_user.roles

    def test_token_verification_invalid(self, setup_tokens):
        # Test with invalid token
        with pytest.raises(HTTPException) as exc_info:
            verify_token("invalid.token.string")

        assert exc_info.value.status_code == 401
        assert "Invalid authentication credentials" in exc_info.value.detail

    def test_token_refresh(self, test_user, setup_tokens):
        # Generate initial tokens
        token_response = generate_token(test_user)

        # Refresh tokens
        new_token_response = refresh_token(token_response.refresh_token, test_user)

        # Verify new tokens
        assert new_token_response.access_token != token_response.access_token
        assert new_token_response.refresh_token != token_response.refresh_token

        # Verify new token content
        payload = jwt.decode(new_token_response.access_token, "test_secret_key", algorithms=["HS256"])
        assert payload["sub"] == test_user.id
        assert payload["roles"] == test_user.roles

    def test_token_refresh_invalid(self, test_user, setup_tokens):
        # Test with invalid refresh token
        with pytest.raises(HTTPException) as exc_info:
            refresh_token("invalid.token.string", test_user)

        assert exc_info.value.status_code == 401
        assert "Invalid refresh token" in exc_info.value.detail

    def test_token_refresh_wrong_user(self, test_user, admin_user, setup_tokens):
        # Generate token for one user
        token_response = generate_token(test_user)

        # Try to refresh with different user
        with pytest.raises(HTTPException) as exc_info:
            refresh_token(token_response.refresh_token, admin_user)

        assert exc_info.value.status_code == 401
        assert "Token does not match user" in exc_info.value.detail
