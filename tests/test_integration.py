import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastauth import User, generate_token, register_auth_middleware, require_auth, require_role, setup_token_manager


@pytest.fixture
def test_user():
    return User(id="user123", username="testuser", roles=["user"])


@pytest.fixture
def admin_user():
    return User(id="admin456", username="adminuser", roles=["admin", "user"])


@pytest.fixture
def app():
    # Create FastAPI app
    app = FastAPI()

    # Setup token manager
    setup_token_manager(
        secret_key="test_secret_key",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
    )

    # Register middleware
    register_auth_middleware(app, exclude_paths=["/public", "/login"])

    # Add routes
    @app.post("/login")
    async def login(username: str, password: str):
        # Simplified login
        if username == "admin" and password == "admin123":
            user = User(id="admin456", username="admin", roles=["admin", "user"])
        elif username == "user" and password == "user123":
            user = User(id="user123", username="user", roles=["user"])
        else:
            return {"error": "Invalid credentials"}

        tokens = generate_token(user)
        return tokens

    @app.get("/public")
    async def public_route():
        return {"message": "This is a public route"}

    @app.get("/protected")
    async def protected_route(user_data=Depends(require_auth())):
        return {"message": "This is a protected route", "user_id": user_data.user_id}

    @app.get("/admin")
    async def admin_route(user_data=Depends(require_role(["admin"]))):
        return {"message": "Admin access granted", "user_id": user_data.user_id}

    @app.get("/user-details")
    async def user_details(user_data=Depends(require_auth())):
        return {"user_id": user_data.user_id, "roles": user_data.roles}

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


class TestIntegration:
    def test_public_route(self, client):
        response = client.get("/public")
        assert response.status_code == 200
        assert response.json() == {"message": "This is a public route"}

    def test_protected_route_without_auth(self, client):
        response = client.get("/protected")
        assert response.status_code == 401
        assert "Not authenticated" in response.json()["detail"]

    def test_login_and_access_protected(self, client):
        # Login as regular user
        login_response = client.post("/login", params={"username": "user", "password": "user123"})
        assert login_response.status_code == 200
        tokens = login_response.json()

        # Access protected route with token
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        response = client.get("/protected", headers=headers)
        assert response.status_code == 200
        assert response.json()["message"] == "This is a protected route"

        # Try to access admin route
        response = client.get("/admin", headers=headers)
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]

    def test_login_as_admin(self, client):
        # Login as admin
        login_response = client.post("/login", params={"username": "admin", "password": "admin123"})
        assert login_response.status_code == 200
        tokens = login_response.json()

        # Access admin route with token
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        response = client.get("/admin", headers=headers)
        assert response.status_code == 200
        assert response.json()["message"] == "Admin access granted"

        # Check user details
        response = client.get("/user-details", headers=headers)
        assert response.status_code == 200
        assert response.json()["roles"] == ["admin", "user"]

    def test_invalid_login(self, client):
        login_response = client.post("/login", params={"username": "invalid", "password": "wrong"})
        assert login_response.status_code == 200  # We're returning a JSON error, not 401
        assert "error" in login_response.json()
