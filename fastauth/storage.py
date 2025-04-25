import json
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from redis import Redis


# Abstract base class for token storage implementations
class TokenStorage(ABC):
    @abstractmethod
    def add_revoked_token(self, token: str, user_id: str | None = None) -> None:
        """Add a token to the revocation list"""
        pass

    @abstractmethod
    def revoke_all_user_tokens(self, user_id: str) -> None:
        """Revoke all tokens for a user"""
        pass

    @abstractmethod
    def is_token_revoked(self, token: str, user_id: str | None = None) -> bool:
        """Check if a token is revoked"""
        pass

    @abstractmethod
    def clear_expired_tokens(self, current_time: float) -> None:
        """Clear expired tokens from storage"""
        pass

    @abstractmethod
    def get_user_token_version(self, user_id: str) -> int:
        """Get the current token version for a user"""
        pass

    @abstractmethod
    def increment_user_token_version(self, user_id: str) -> int:
        """Increment and return the user's token version"""
        pass

    # CSRF token methods
    @abstractmethod
    def store_csrf_token(self, user_id: str, token_hash: str, expires_at: datetime) -> None:
        """Store a CSRF token"""
        pass

    @abstractmethod
    def verify_csrf_token(self, user_id: str, token_hash: str) -> bool:
        """Verify a CSRF token exists and is valid"""
        pass

    @abstractmethod
    def clear_old_csrf_tokens(self, user_id: str | None = None, max_age_hours: int = 24) -> None:
        """Clear expired CSRF tokens"""
        pass


# Memory-based implementation (our current approach)
class MemoryTokenStorage(TokenStorage):
    def __init__(self) -> None:
        self._revoked_tokens: set[str] = set()
        self._revoked_for_user: dict[str, set[str]] = {}
        self._token_versions: dict[str, int] = {}
        self._csrf_tokens: dict[str, dict[str, Any]] = {}

    def add_revoked_token(self, token: str, user_id: str | None = None) -> None:
        self._revoked_tokens.add(token)
        if user_id:
            if user_id not in self._revoked_for_user:
                self._revoked_for_user[user_id] = set()
            self._revoked_for_user[user_id].add(token)

    def revoke_all_user_tokens(self, user_id: str) -> None:
        self._revoked_for_user[str(user_id)] = set()
        # Increment token version to invalidate all tokens
        self.increment_user_token_version(user_id)

    def is_token_revoked(self, token: str, user_id: str | None = None) -> bool:
        if token in self._revoked_tokens:
            return True

        if user_id and user_id in self._revoked_for_user:
            # If user has an empty set, all their tokens are revoked
            if not self._revoked_for_user[user_id]:
                return True

            # Otherwise check if this specific token is revoked
            return token in self._revoked_for_user[user_id]

        return False

    def clear_expired_tokens(self, current_time: float) -> None:
        # Nothing to do for memory storage as we handle this in the token service
        pass

    def get_user_token_version(self, user_id: str) -> int:
        return self._token_versions.get(user_id, 0)

    def increment_user_token_version(self, user_id: str) -> int:
        current = self._token_versions.get(user_id, 0)
        new_version = current + 1
        self._token_versions[user_id] = new_version
        return new_version

    def store_csrf_token(self, user_id: str, token_hash: str, expires_at: datetime) -> None:
        if user_id not in self._csrf_tokens:
            self._csrf_tokens[user_id] = {}

        self._csrf_tokens[user_id][token_hash] = {"expires_at": expires_at, "used": False}

    def verify_csrf_token(self, user_id: str, token_hash: str) -> bool:
        if user_id not in self._csrf_tokens:
            return False

        if token_hash not in self._csrf_tokens[user_id]:
            return False

        token_data = self._csrf_tokens[user_id][token_hash]

        # Check if expired
        if token_data["expires_at"] < datetime.now(UTC):
            # Clean up this token
            del self._csrf_tokens[user_id][token_hash]
            return False

        return True

    def clear_old_csrf_tokens(self, user_id: str | None = None, max_age_hours: int = 24) -> None:
        now = datetime.now(UTC)

        if user_id:
            # Clear for specific user
            if user_id in self._csrf_tokens:
                to_remove = []
                for token_hash, data in self._csrf_tokens[user_id].items():
                    if data["expires_at"] < now or data["used"]:
                        to_remove.append(token_hash)

                for token_hash in to_remove:
                    del self._csrf_tokens[user_id][token_hash]

                # If user has no more tokens, remove the user entry
                if not self._csrf_tokens[user_id]:
                    del self._csrf_tokens[user_id]
        else:
            # Clear for all users
            users_to_remove = []
            for user_id, tokens in self._csrf_tokens.items():
                to_remove = []
                for token_hash, data in tokens.items():
                    if data["expires_at"] < now or data["used"]:
                        to_remove.append(token_hash)

                for token_hash in to_remove:
                    del self._csrf_tokens[user_id][token_hash]

                # If user has no more tokens, mark for removal
                if not self._csrf_tokens[user_id]:
                    users_to_remove.append(user_id)

            # Remove empty user entries
            for user_id in users_to_remove:
                del self._csrf_tokens[user_id]


# Redis-based implementation
class RedisTokenStorage(TokenStorage):
    def __init__(self, redis_client: Redis, prefix: str = "fastauth:") -> None:
        self.redis = redis_client
        self.prefix = prefix

    def _key(self, *parts: str) -> str:
        return f"{self.prefix}{''.join(parts)}"

    def add_revoked_token(self, token: str, user_id: str | None = None) -> None:
        # Get token expiration if possible
        try:
            payload = json.loads(self.redis.get(self._key("token_payload:", token)) or "{}")
            exp = payload.get("exp", int(time.time()) + 3600)  # Default 1 hour if no exp
        except Exception:
            # If we can't parse, use 1 hour expiration
            exp = int(time.time()) + 3600

        # Store in revoked tokens set
        self.redis.set(self._key("revoked:", token), "1", ex=exp)

        # Add to user's revoked tokens if user_id provided
        if user_id:
            self.redis.sadd(self._key("user_revoked:", user_id), token)

    def revoke_all_user_tokens(self, user_id: str) -> None:
        # Mark all user tokens as revoked by setting a flag
        self.redis.set(self._key("user_all_revoked:", user_id), "1")

        # Increment token version to invalidate all tokens
        self.increment_user_token_version(user_id)

    def is_token_revoked(self, token: str, user_id: str | None = None) -> bool:
        # Check if specific token is revoked
        if self.redis.exists(self._key("revoked:", token)):
            return True

        # If user_id provided, check if all user tokens are revoked
        if user_id:
            if self.redis.exists(self._key("user_all_revoked:", user_id)):
                return True

            # Check if this specific token is in user's revoked set
            if self.redis.sismember(self._key("user_revoked:", user_id), token):
                return True

        return False

    def clear_expired_tokens(self, current_time: float) -> None:
        # Redis handles expiration automatically, nothing to do here
        pass

    def get_user_token_version(self, user_id: str) -> int:
        version = self.redis.get(self._key("token_version:", user_id))
        return int(version) if version else 0

    def increment_user_token_version(self, user_id: str) -> Any:
        return self.redis.incr(self._key("token_version:", user_id))

    def store_csrf_token(self, user_id: str, token_hash: str, expires_at: datetime) -> None:
        # Convert datetime to timestamp for Redis storage
        expiry_ts = expires_at.timestamp()

        # Store token with expiration
        key = self._key("csrf:", user_id, ":", token_hash)
        self.redis.hset(key, mapping={"expires_at": expiry_ts, "used": 0})

        # Set expiration on Redis key
        seconds_until_expiry = int(expires_at.timestamp() - time.time())
        if seconds_until_expiry > 0:
            self.redis.expire(key, seconds_until_expiry)

    def verify_csrf_token(self, user_id: str, token_hash: str) -> bool:
        key = self._key("csrf:", user_id, ":", token_hash)

        # Check if token exists
        if not self.redis.exists(key):
            return False

        # Get token data
        token_data = self.redis.hgetall(key)
        if not token_data:
            return False

        # Check expiration
        expires_at = float(token_data.get(b"expires_at", 0))
        if expires_at < time.time():
            # Clean up expired token
            self.redis.delete(key)
            return False

        return True

    def clear_old_csrf_tokens(self, user_id: str | None = None, max_age_hours: int = 24) -> None:
        # Redis handles expiration automatically, but we can force cleanup
        if user_id:
            # Get all CSRF tokens for this user
            pattern = self._key("csrf:", user_id, ":*")
            keys = self.redis.keys(pattern)

            # Check each token
            for key in keys:
                token_data = self.redis.hgetall(key)
                if token_data:
                    expires_at = float(token_data.get(b"expires_at", 0))
                    if expires_at < time.time():
                        self.redis.delete(key)
        else:
            # This would be expensive, better to rely on Redis expiration
            pass
