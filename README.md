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
from fastapi_auth_middleware import (
register_auth_middleware,
setup_token_manager,
require_auth,
require_role,
generate_token,
User
)
app = FastAPI()

# Setup token manager
token_manager = setup_token_manager(
    secret_key="your_secret_key",
    algorithm="HS256",
)

# Register auth middleware
register_auth_middleware(
    app,
    token_manager,
    auth_scheme="Bearer",
    auth_header="Authorization",
)

# Generate token
token = generate_token(
    User(username="admin", role="admin"),
    token_manager,
)
```

Example login endpoint

```python
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
```

Protected route

```python
@app.get("/protected")
async def protected_route(user_data = Depends(require_auth())):
return {"message": "This is a protected route", "user_id": user_data.user_id}
```

Protected route with role-based access control

```python
@app.get("/admin")
async def admin_route(user_data = Depends(require_role(["admin"]))):
return {"message": "Admin access granted", "user_id": user_data.user_id}
```

Route that requires multiple roles (all of them)

```python
@app.get("/super-admin")
async def super_admin_route(user_data = Depends(require_role(["admin", "super"], require_all=True))):
return {"message": "Super admin access granted", "user_id": user_data.user_id}
```

Public route

```python
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
register_auth_middleware(app, token_getter=custom_token_getter)
```


### Refresh Tokens

```python
from fastapi_auth_middleware import refresh_token
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


## License

MIT
