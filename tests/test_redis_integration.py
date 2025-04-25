# ruff: noqa
from unittest.mock import MagicMock, patch

import pytest

from fastauth.storage import MemoryTokenStorage, RedisTokenStorage
from fastauth.token import _token_manager, _token_storage, setup_token_manager

# Use a cleaner way to determine if redis is available
redis_available = False
try:
    import redis

    redis_available = True
except ImportError:
    pass

# Mark tests to be skipped if redis is not available
pytestmark = pytest.mark.skipif(not redis_available, reason="Redis package not installed")


@pytest.fixture(autouse=True)
def reset_token_manager():
    """Reset the token manager before and after each test"""
    # Reset before test
    from fastauth.token import _token_manager, _token_storage

    # global _token_storage, _token_manager
    _token_storage = None
    _token_manager = None

    yield

    # Reset after test
    from fastauth.token import _token_manager, _token_storage

    _token_storage = None
    _token_manager = None


@patch("redis.from_url")
def test_redis_connection_used(mock_redis_from_url):
    """Test that Redis client is created when redis_url is provided"""
    # Setup mock
    mock_redis_client = MagicMock()
    mock_redis_from_url.return_value = mock_redis_client

    # Call setup with Redis URL
    setup_token_manager(secret_key="test_key", redis_url="redis://localhost:6379/0")

    # Import here to get fresh reference to the module variable
    from fastauth.token import _token_storage

    # Verify Redis client was created
    mock_redis_from_url.assert_called_once_with("redis://localhost:6379/0")

    # Verify we're using RedisTokenStorage
    assert isinstance(_token_storage, RedisTokenStorage)


@patch("fastauth.token._redis_available", False)
def test_fallback_to_memory_when_redis_not_available():
    """Test that MemoryTokenStorage is used when redis is not available"""
    # Reset the storage to ensure fresh state
    from fastauth.token import _token_manager, _token_storage

    # global _token_storage, _token_manager
    _token_storage = None
    _token_manager = None

    # Call setup with Redis URL
    setup_token_manager(secret_key="test_key", redis_url="redis://localhost:6379/0")

    # Import here to get fresh reference to the module variable
    from fastauth.token import _token_storage

    # Verify we're using MemoryTokenStorage
    assert isinstance(_token_storage, MemoryTokenStorage)


def test_memory_storage_used_when_no_redis_url():
    """Test that MemoryTokenStorage is used when no redis_url is provided"""
    # Call setup without Redis URL
    setup_token_manager(
        secret_key="test_key",
    )

    # Import here to get fresh reference to the module variable
    from fastauth.token import _token_storage

    # Verify we're using MemoryTokenStorage
    assert isinstance(_token_storage, MemoryTokenStorage)
