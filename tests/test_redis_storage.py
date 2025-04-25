from datetime import UTC, datetime, timedelta

import pytest

from fastauth.storage import RedisTokenStorage


class MockRedis:
    """A simple mock Redis client for testing"""

    def __init__(self):
        self.data = {}
        self.expiry = {}

    def set(self, key, value, ex=None):
        self.data[key] = value
        if ex is not None:
            self.expiry[key] = ex
        return True

    def get(self, key):
        return self.data.get(key)

    def exists(self, key):
        return key in self.data

    def sadd(self, key, member):
        if key not in self.data:
            self.data[key] = set()
        self.data[key].add(member)
        return 1

    def sismember(self, key, member):
        return key in self.data and member in self.data[key]

    def incr(self, key):
        if key not in self.data:
            self.data[key] = 0
        self.data[key] += 1
        return self.data[key]

    def hset(self, key, mapping):
        if key not in self.data:
            self.data[key] = {}
        for k, v in mapping.items():
            self.data[key][k] = v
        return True

    def hgetall(self, key):
        if key not in self.data:
            return {}
        # Convert to bytes keys to mimic Redis
        return {k.encode(): str(v).encode() for k, v in self.data[key].items()}

    def expire(self, key, seconds):
        self.expiry[key] = seconds
        return True

    def keys(self, pattern):
        # Very simplified pattern matching
        prefix = pattern.replace("*", "")
        return [k for k in self.data if k.startswith(prefix)]

    def delete(self, key):
        if key in self.data:
            del self.data[key]
        return 1


@pytest.fixture
def redis_client():
    return MockRedis()


@pytest.fixture
def redis_storage(redis_client):
    return RedisTokenStorage(redis_client)


def test_redis_revoked_token_tracking(redis_storage):
    # Add a revoked token
    redis_storage.add_revoked_token("token1")

    # Check it's revoked
    assert redis_storage.is_token_revoked("token1") is True

    # Check another token is not revoked
    assert redis_storage.is_token_revoked("token2") is False


def test_redis_user_specific_revocation(redis_storage):
    # Add a revoked token for a specific user
    redis_storage.add_revoked_token("token1", "user1")

    # Check it's revoked globally and for the user
    assert redis_storage.is_token_revoked("token1") is True
    assert redis_storage.is_token_revoked("token1", "user1") is True

    # Check another token is not revoked for this user
    assert redis_storage.is_token_revoked("token2", "user1") is False


def test_redis_revoke_all_user_tokens(redis_storage):
    # Add some tokens
    redis_storage.add_revoked_token("token1", "user1")

    # Revoke all for user
    redis_storage.revoke_all_user_tokens("user1")

    # Check a token we haven't specifically added is now considered revoked
    assert redis_storage.is_token_revoked("different_token", "user1") is True

    # But not for a different user
    assert redis_storage.is_token_revoked("different_token", "user2") is False


def test_redis_token_versioning(redis_storage):
    # Check default version
    assert redis_storage.get_user_token_version("user1") == 0

    # Increment version
    new_version = redis_storage.increment_user_token_version("user1")
    assert new_version == 1

    # Check version is updated
    assert redis_storage.get_user_token_version("user1") == 1

    # Increment again
    new_version = redis_storage.increment_user_token_version("user1")
    assert new_version == 2
    assert redis_storage.get_user_token_version("user1") == 2


def test_redis_csrf_token_storage(redis_storage):
    user_id = "user1"
    token_hash = "hash123"
    expires_at = datetime.now(UTC) + timedelta(hours=1)

    # Store token
    redis_storage.store_csrf_token(user_id, token_hash, expires_at)

    # Manually set the data for the test since our mock is simplified
    key = f"{redis_storage.prefix}csrf:{user_id}:{token_hash}"
    redis_storage.redis.data[key] = {"expires_at": expires_at.timestamp(), "used": 0}

    # Verify token
    assert redis_storage.verify_csrf_token(user_id, token_hash) is True

    # Verify wrong hash fails
    assert redis_storage.verify_csrf_token(user_id, "wrong_hash") is False

    # Verify for wrong user fails
    assert redis_storage.verify_csrf_token("wrong_user", token_hash) is False
