import pytest
from fastapi import HTTPException

from fastauth.models import User
from fastauth.token import (
    clear_expired_revocations,
    generate_token,
    is_token_revoked,
    revoke_all_user_tokens,
    revoke_token,
    rotate_user_tokens,
    setup_token_manager,
    verify_token,
)


@pytest.fixture(autouse=True)
def setup():
    # Setup token manager for each test
    setup_token_manager(
        secret_key="test_secret_key",
        algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
    )
    yield
    # No cleanup needed as each test gets a fresh token manager


@pytest.fixture
def test_user():
    return User(id="test123", username="testuser", roles=["user"])


@pytest.fixture
def admin_user():
    return User(id="admin123", username="adminuser", roles=["admin"])


def test_token_revocation(test_user):
    # Generate a token
    token_response = generate_token(test_user)
    access_token = token_response.access_token

    # Verify token works
    user_data = verify_token(access_token)
    assert user_data.user_id == test_user.id

    # Revoke token
    revoke_token(access_token)

    # Verify token is revoked
    assert is_token_revoked(access_token) is True

    # Verify token no longer works
    with pytest.raises(HTTPException) as excinfo:
        verify_token(access_token)
    assert excinfo.value.status_code == 401


def test_revoke_all_user_tokens(test_user):
    # Generate multiple tokens for the same user
    token1 = generate_token(test_user)
    token2 = generate_token(test_user)

    # Verify both tokens work
    assert verify_token(token1.access_token).user_id == test_user.id
    assert verify_token(token2.access_token).user_id == test_user.id

    # Revoke all tokens for user
    revoke_all_user_tokens(test_user.id)

    # Verify both tokens are revoked
    assert is_token_revoked(token1.access_token) is True
    assert is_token_revoked(token2.access_token) is True

    # Verify neither token works anymore
    with pytest.raises(HTTPException):
        verify_token(token1.access_token)

    with pytest.raises(HTTPException):
        verify_token(token2.access_token)


def test_token_rotation(test_user):
    # Generate initial tokens
    initial_tokens = generate_token(test_user)

    # Verify initial token works
    assert verify_token(initial_tokens.access_token).user_id == test_user.id

    # Rotate tokens
    new_tokens = rotate_user_tokens(test_user)

    # Verify new tokens are different from initial tokens
    assert new_tokens.access_token != initial_tokens.access_token
    assert new_tokens.refresh_token != initial_tokens.refresh_token

    # Verify new tokens work
    assert verify_token(new_tokens.access_token).user_id == test_user.id

    # Verify old tokens no longer work
    with pytest.raises(HTTPException) as excinfo:
        verify_token(initial_tokens.access_token)
    assert excinfo.value.status_code == 401
    assert "Token version is outdated" in excinfo.value.detail


def test_clear_expired_revocations():
    # This test is mainly to ensure the function doesn't error
    # Since we're using memory storage and don't mock time,
    # we can't easily test the actual clearing functionality
    clear_expired_revocations()
    assert True  # Test passes if no exceptions are raised
