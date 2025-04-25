from datetime import UTC, datetime, timedelta

import pytest

from fastauth.storage import MemoryTokenStorage


@pytest.fixture
def memory_storage():
    return MemoryTokenStorage()


def test_revoked_token_tracking(memory_storage):
    # Add a revoked token
    memory_storage.add_revoked_token("token1")

    # Check it's revoked
    assert memory_storage.is_token_revoked("token1") is True

    # Check another token is not revoked
    assert memory_storage.is_token_revoked("token2") is False


def test_user_specific_revocation(memory_storage):
    # Add a revoked token for a specific user
    memory_storage.add_revoked_token("token1", "user1")

    # Check it's revoked globally and for the user
    assert memory_storage.is_token_revoked("token1") is True
    assert memory_storage.is_token_revoked("token1", "user1") is True

    # Check another token is not revoked for this user
    assert memory_storage.is_token_revoked("token2", "user1") is False


def test_revoke_all_user_tokens(memory_storage):
    # Add some tokens
    memory_storage.add_revoked_token("token1", "user1")

    # Revoke all for user
    memory_storage.revoke_all_user_tokens("user1")

    # Check a token we haven't specifically added is now considered revoked
    assert memory_storage.is_token_revoked("different_token", "user1") is True

    # But not for a different user
    assert memory_storage.is_token_revoked("different_token", "user2") is False


def test_token_versioning(memory_storage):
    # Check default version
    assert memory_storage.get_user_token_version("user1") == 0

    # Increment version
    new_version = memory_storage.increment_user_token_version("user1")
    assert new_version == 1

    # Check version is updated
    assert memory_storage.get_user_token_version("user1") == 1

    # Increment again
    new_version = memory_storage.increment_user_token_version("user1")
    assert new_version == 2
    assert memory_storage.get_user_token_version("user1") == 2


def test_csrf_token_storage(memory_storage):
    user_id = "user1"
    token_hash = "hash123"
    expires_at = datetime.now(UTC) + timedelta(hours=1)

    # Store token
    memory_storage.store_csrf_token(user_id, token_hash, expires_at)

    # Verify token
    assert memory_storage.verify_csrf_token(user_id, token_hash) is True

    # Verify wrong hash fails
    assert memory_storage.verify_csrf_token(user_id, "wrong_hash") is False

    # Verify for wrong user fails
    assert memory_storage.verify_csrf_token("wrong_user", token_hash) is False


def test_csrf_token_expiration(memory_storage):
    user_id = "user1"
    token_hash = "hash123"

    # Create an already expired token
    expired_at = datetime.now(UTC) - timedelta(hours=1)

    # Store token
    memory_storage.store_csrf_token(user_id, token_hash, expired_at)

    # Verify expired token fails
    assert memory_storage.verify_csrf_token(user_id, token_hash) is False


def test_clear_old_csrf_tokens(memory_storage):
    user_id = "user1"

    # Store an expired token
    expired_token = "expired_hash"
    expired_at = datetime.now(UTC) - timedelta(hours=1)
    memory_storage.store_csrf_token(user_id, expired_token, expired_at)

    # Store a valid token
    valid_token = "valid_hash"
    valid_at = datetime.now(UTC) + timedelta(hours=1)
    memory_storage.store_csrf_token(user_id, valid_token, valid_at)

    # Clear old tokens
    memory_storage.clear_old_csrf_tokens(user_id)

    # Verify expired token is gone, valid token remains
    assert memory_storage.verify_csrf_token(user_id, expired_token) is False
    assert memory_storage.verify_csrf_token(user_id, valid_token) is True
