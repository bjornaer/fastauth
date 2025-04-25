# FastAPI Auth Middleware

A simple and powerful authentication middleware for FastAPI applications with JWT and role-based access control.

## Features

- JWT-based authentication
- Token generation, verification, and refresh
- Zero-query authentication for protected routes
- Role-based access control
- Easily customizable token extraction

## Installation

```bash
pip install fastauth
```

or with poetry

```bash
poetry add fastauth
```

## Quick Start

```python
from fastapi import FastAPI, Depends, HTTPException
from fastauth import (
register_auth_middleware,
setup_token_manager,
require_auth,
require_role,
generate_token,
User
)

app = FastAPI()

# Setup token manager
setup_token_manager(
    secret_key="your_secret_key",
    algorithm="HS256",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7
)

# register auth middleware
register_auth_middleware(
    app,
    exclude_paths=["/public", "/login"],
    token_getter=None  # Optional custom token getter
)

# generate token
tokens = generate_token(User(
    id="user123",
    username="admin", 
    roles=["admin"]
))

# Example login endpoint
@app.post("/login")
async def login(username: str, password: str):
    # Your authentication logic here
    # ...
    # If authentication successful, create a user object
    user = User(
        id="user123",
        username=username,
        roles=["user"] # Assign roles as needed
    )
    # Generate tokens
    tokens = generate_token(user)
    return tokens

# Protected route

@app.get("/protected")
async def protected_route(user_data = Depends(require_auth())):
    return {"message": "This is a protected route", "user_id": user_data.user_id}

# Protected route with role-based access control

@app.get("/admin")
async def admin_route(user_data = Depends(require_role(["admin"]))):
    return {"message": "Admin access granted", "user_id": user_data.user_id}

# Route that requires multiple roles (all of them)

@app.get("/super-admin")
async def super_admin_route(user_data = Depends(require_role(["admin", "super"], require_all=True))):
    return {"message": "Super admin access granted", "user_id": user_data.user_id}

# Public route

@app.get("/public")
async def public_route():
    return {"message": "This is a public route"}
```


## Advanced Usage

### Custom Token Extraction

You can customize how tokens are extracted from requests:

```python
def custom_token_getter(request):
    # Your custom logic here
    return request.headers.get("X-Custom-Token")

# register auth middleware
register_auth_middleware(app, token_getter=custom_token_getter)
```


### Refresh Tokens

```python
from fastauth import refresh_token
@app.post("/refresh-token")
async def refresh_tokens(refresh_token_str: str, user_id: str):
    # Get user from your database
    user = get_user_from_db(user_id)
    # Create User object from your user model
    auth_user = User(
        id=user.id,
        username=user.username,
        roles=user.roles
    )
    # Refresh the tokens
    new_tokens = refresh_token(refresh_token_str, auth_user)
    return new_tokens
```


### Token Revocation

```python
from fastauth import revoke_token, revoke_all_user_tokens

@app.post("/logout")
async def logout(token: str, user_data = Depends(require_auth())):
    # Revoke the current token
    revoke_token(token)
    return {"message": "Logged out successfully"}

@app.post("/logout-all-devices")
async def logout_all_devices(user_data = Depends(require_auth())):
    # Revoke all tokens for this user
    revoke_all_user_tokens(user_data.user_id)
    return {"message": "Logged out from all devices"}
```

### CSRF Protection

```python
from fastapi import Depends, Cookie, Response
from fastauth import generate_csrf_token, csrf_protection

# Apply CSRF protection middleware to all routes
app.middleware("http")(csrf_protection())

@app.post("/login")
async def login(username: str, password: str, response: Response):
    # Your authentication logic
    # ...
    
    # Generate tokens
    user = User(id="user123", username=username, roles=["user"])
    tokens = generate_token(user)
    
    # Generate CSRF token
    csrf_token = generate_csrf_token(user.id)
    
    # Set CSRF token as cookie
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=True,
        samesite="strict",
        secure=True  # For HTTPS
    )
    
    return tokens

# Protected route with CSRF protection
@app.post("/update-profile", dependencies=[Depends(csrf_protection())])
async def update_profile(data: dict, user_data = Depends(require_auth())):
    # This route is protected by both authentication and CSRF protection
    return {"message": "Profile updated"}
```

### Redis Backend

FastAuth can use Redis for token storage, which is recommended for production environments:

```python
from fastauth import setup_token_manager

# Setup with Redis
setup_token_manager(
    secret_key="your_secret_key",
    algorithm="HS256", 
    redis_url="redis://localhost:6379/0"  # Will use Redis if available
)
```

### Token Rotation

For enhanced security, you can force token rotation which invalidates all previous tokens:

```python
from fastauth import rotate_user_tokens

@app.post("/security/rotate-tokens")
async def rotate_tokens(user = Depends(require_auth())):
    # Get user from your database
    db_user = get_user_from_db(user.user_id)
    
    # Create User object
    auth_user = User(
        id=db_user.id,
        username=db_user.username,
        roles=db_user.roles
    )
    
    # Rotate tokens
    new_tokens = rotate_user_tokens(auth_user)
    
    return new_tokens
```

### Periodic Token Cleanup

Set up automatic cleanup of expired tokens:

```python
from fastapi import FastAPI
from fastauth import setup_token_manager
from fastauth.tasks import setup_periodic_tasks

app = FastAPI()

# Setup token manager
setup_token_manager(
    secret_key="your_secret_key",
    algorithm="HS256"
)

# Setup token cleanup every hour (3600 seconds)
setup_periodic_tasks(app, cleanup_interval_seconds=3600)
```

## License

MIT
