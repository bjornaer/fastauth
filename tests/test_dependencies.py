import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastauth.dependencies import require_auth, require_role
from fastauth.models import User
from fastauth.token import generate_token, setup_token_manager


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


@pytest.fixture
def app():
    return FastAPI()


@pytest.fixture
def client(app, setup_tokens):
    @app.get("/auth-required")
    async def auth_required(token_data=Depends(require_auth())):
        return {"user_id": token_data.user_id, "roles": token_data.roles}

    @app.get("/auth-optional")
    async def auth_optional(token_data=Depends(require_auth(auto_error=False))):
        if token_data:
            return {"authenticated": True, "user_id": token_data.user_id}
        return {"authenticated": False}

    @app.get("/admin-only")
    async def admin_only(token_data=Depends(require_role(["admin"]))):
        return {"message": "Admin access granted", "user_id": token_data.user_id}

    @app.get("/user-or-admin")
    async def user_or_admin(token_data=Depends(require_role(["user", "admin"]))):
        return {"message": "Access granted", "user_id": token_data.user_id}

    @app.get("/admin-and-user")
    async def admin_and_user(token_data=Depends(require_role(["admin", "user"], require_all=True))):
        return {"message": "Full access granted", "user_id": token_data.user_id}

    return TestClient(app)


class TestDependencies:
    def test_require_auth_no_token(self, client):
        # Test auth-required route with no token
        response = client.get("/auth-required")
        assert response.status_code == 401
        assert "Not authenticated" in response.json()["detail"]

        # Test auth-optional route with no token
        response = client.get("/auth-optional")
        assert response.status_code == 200
        assert response.json() == {"authenticated": False}

    def test_require_auth_with_token(self, client, test_user):
        # Generate token
        token_response = generate_token(test_user)

        # Set Authorization header
        headers = {"Authorization": f"Bearer {token_response.access_token}"}

        # Test auth-required route with valid token
        response = client.get("/auth-required", headers=headers)
        assert response.status_code == 200
        assert response.json() == {"user_id": test_user.id, "roles": test_user.roles}

        # Test auth-optional route with valid token
        response = client.get("/auth-optional", headers=headers)
        assert response.status_code == 200
        assert response.json() == {"authenticated": True, "user_id": test_user.id}

    def test_require_role_no_token(self, client):
        # Test role-protected routes with no token
        response = client.get("/admin-only")
        assert response.status_code == 401
        assert "Not authenticated" in response.json()["detail"]

    def test_require_role_insufficient_permissions(self, client, test_user):
        # Generate token for regular user
        token_response = generate_token(test_user)  # regular user without admin role

        # Set Authorization header
        headers = {"Authorization": f"Bearer {token_response.access_token}"}

        # Test admin-only route with regular user
        response = client.get("/admin-only", headers=headers)
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]

        # Test admin-and-user route with regular user
        response = client.get("/admin-and-user", headers=headers)
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]

    def test_require_role_with_proper_permissions(self, client, test_user, admin_user):
        # Test user_or_admin with regular user
        user_token = generate_token(test_user)
        headers = {"Authorization": f"Bearer {user_token.access_token}"}

        response = client.get("/user-or-admin", headers=headers)
        assert response.status_code == 200
        assert response.json()["message"] == "Access granted"

        # Test admin routes with admin user
        admin_token = generate_token(admin_user)
        headers = {"Authorization": f"Bearer {admin_token.access_token}"}

        # Test admin-only route
        response = client.get("/admin-only", headers=headers)
        assert response.status_code == 200
        assert response.json()["message"] == "Admin access granted"

        # Test admin-and-user route (require all roles)
        response = client.get("/admin-and-user", headers=headers)
        assert response.status_code == 200
        assert response.json()["message"] == "Full access granted"
