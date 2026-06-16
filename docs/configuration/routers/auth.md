# Auth router

The auth router will generate `/login` and `/logout` routes for a given [authentication backend](../authentication/index.md).

Check the [routes usage](../../usage/routes.md) to learn how to use them.

## Setup

```py
import uuid

from fastapi import FastAPI
from fastapi_users import FastAPIUsers

from .db import User

fastapi_users = FastAPIUsers[User, uuid.UUID](
    get_user_manager,
    [auth_backend],
)

app = FastAPI()
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/jwt",
    tags=["auth"],
)
```

### Optional: user verification

You can require the user to be **verified** (i.e. `is_verified` property set to `True`) to allow login. You have to set the `requires_verification` parameter to `True` on the router instantiation method:

```py
app.include_router(
    fastapi_users.get_auth_router(auth_backend, requires_verification=True),
    prefix="/auth/jwt",
    tags=["auth"],
)
```

### Debug mode

The auth router respects the `debug_enabled` flag set on the authentication backend. When enabled, successful login and logout responses will include a `X-FastAPI-Users-Backend` header with the backend name, which is helpful when multiple backends are registered:

```python
auth_backend_debug = AuthenticationBackend(
    name="jwt-debug",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy,
    debug_enabled=True,
)

app.include_router(
    fastapi_users.get_auth_router(auth_backend_debug),
    prefix="/auth/jwt",
    tags=["auth"],
)
```

This header is **only** added to successful responses (200, 204), not to error responses (400, 401, 403, etc.), to avoid frontend misinterpretation.
