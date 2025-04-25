import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastauth.middleware import register_auth_middleware
from fastauth.models import User
from fastauth.token import generate_token, setup_token_manager


@pytest.fixture
def test_user():
    return User(id="user123", username="testuser", roles=["user"])


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
    register_auth_middleware(
        app,
        exclude_paths=["/public", "/excluded"],
    )

    @app.get("/protected")
    async def protected_route():
        return {"message": "This is protected"}

    @app.get("/public")
    async def public_route():
        return {"message": "This is public"}

    @app.get("/excluded")
    async def excluded_route():
        return {"message": "This is excluded"}

    return TestClient(app)


class TestAuthMiddleware:
    def test_excluded_paths(self, client):
        # Test accessing excluded paths without authentication
        response = client.get("/public")
        assert response.status_code == 200
        assert response.json() == {"message": "This is public"}

        response = client.get("/excluded")
        assert response.status_code == 200
        assert response.json() == {"message": "This is excluded"}

    def test_protected_route_no_token(self, client):
        # Test accessing protected route without token
        # This should pass through middleware (no auth check)
        # and fail at the route level if auth is required
        response = client.get("/protected")
        assert response.status_code == 200
        assert response.json() == {"message": "This is protected"}

    def test_protected_route_with_valid_token(self, client, test_user):
        # Generate token
        token_response = generate_token(test_user)

        # Set Authorization header
        headers = {"Authorization": f"Bearer {token_response.access_token}"}

        # Access protected route
        response = client.get("/protected", headers=headers)
        assert response.status_code == 200
        assert response.json() == {"message": "This is protected"}

    def test_protected_route_with_invalid_token(self, client):
        # Set invalid Authorization header
        headers = {"Authorization": "Bearer invalid.token.string"}

        # Access protected route with invalid token
        response = client.get("/protected", headers=headers)
        assert response.status_code == 401
        assert "Invalid authentication credentials" in response.json()["detail"]

    def test_custom_token_getter(self, app, setup_tokens):
        # Define custom token getter
        def custom_token_getter(request):
            return request.headers.get("X-Custom-Token")

        # Register middleware with custom token getter
        register_auth_middleware(
            app,
            token_getter=custom_token_getter,
        )

        client = TestClient(app)

        # Create a test route
        @app.get("/custom-auth")
        async def custom_auth_route():
            return {"message": "Custom auth route"}

        # Generate token
        test_user = User(id="user123", username="testuser", roles=["user"])
        token_response = generate_token(test_user)

        # Set custom header
        headers = {"X-Custom-Token": token_response.access_token}

        # Access route with custom token
        response = client.get("/custom-auth", headers=headers)
        assert response.status_code == 200
        assert response.json() == {"message": "Custom auth route"}
