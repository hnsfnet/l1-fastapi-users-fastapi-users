import secrets
from typing import Literal
from urllib.parse import urlsplit

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from httpx_oauth.integrations.fastapi import OAuth2AuthorizeCallback
from httpx_oauth.oauth2 import BaseOAuth2, OAuth2Token
from pydantic import BaseModel

from fastapi_users import models, schemas
from fastapi_users.authentication import AuthenticationBackend, Authenticator, Strategy
from fastapi_users.exceptions import UserAlreadyExists
from fastapi_users.jwt import SecretType, decode_jwt, generate_jwt
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.router.common import ErrorCode, ErrorModel

STATE_TOKEN_AUDIENCE = "fastapi-users:oauth-state"
CSRF_TOKEN_KEY = "csrftoken"
CSRF_TOKEN_COOKIE_NAME = "fastapiusersoauthcsrf"
NEXT_URL_STATE_KEY = "next"
NEXT_URL_HEADER_NAME = "X-FastAPI-Users-Next-URL"


class OAuth2AuthorizeResponse(BaseModel):
    authorization_url: str


class OAuthNextUrlResponse(BaseModel):
    detail: str


def generate_state_token(
    data: dict[str, str], secret: SecretType, lifetime_seconds: int = 3600
) -> str:
    data["aud"] = STATE_TOKEN_AUDIENCE
    return generate_jwt(data, secret, lifetime_seconds)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def validate_next_url(next_url: str) -> str:
    normalized = next_url.strip()
    if normalized == "":
        raise ValueError("next_url must not be empty")

    parsed = urlsplit(normalized)
    if parsed.scheme or parsed.netloc or normalized.startswith("//"):
        raise ValueError("next_url must be a relative path")

    if not normalized.startswith("/"):
        raise ValueError("next_url must start with '/'")

    return normalized


def clear_csrf_cookie(
    response: Response,
    cookie_name: str,
    cookie_path: str,
    cookie_domain: str | None,
    cookie_secure: bool,
    cookie_httponly: bool,
    cookie_samesite: Literal["lax", "strict", "none"],
) -> None:
    response.set_cookie(
        cookie_name,
        "",
        max_age=0,
        path=cookie_path,
        domain=cookie_domain,
        secure=cookie_secure,
        httponly=cookie_httponly,
        samesite=cookie_samesite,
    )


def append_next_url_header(response: Response, next_url: str | None) -> Response:
    if next_url:
        response.headers[NEXT_URL_HEADER_NAME] = next_url
    return response


def get_oauth_router(
    oauth_client: BaseOAuth2,
    backend: AuthenticationBackend[models.UP, models.ID],
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    state_secret: SecretType,
    redirect_url: str | None = None,
    associate_by_email: bool = False,
    is_verified_by_default: bool = False,
    *,
    csrf_token_cookie_name: str = CSRF_TOKEN_COOKIE_NAME,
    csrf_token_cookie_path: str = "/",
    csrf_token_cookie_domain: str | None = None,
    csrf_token_cookie_secure: bool = True,
    csrf_token_cookie_httponly: bool = True,
    csrf_token_cookie_samesite: Literal["lax", "strict", "none"] = "lax",
) -> APIRouter:
    """Generate a router with the OAuth routes."""
    router = APIRouter()
    callback_route_name = f"oauth:{oauth_client.name}.{backend.name}.callback"

    if redirect_url is not None:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            redirect_url=redirect_url,
        )
    else:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            route_name=callback_route_name,
        )

    @router.get(
        "/authorize",
        name=f"oauth:{oauth_client.name}.{backend.name}.authorize",
        response_model=OAuth2AuthorizeResponse,
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "example": {"detail": ErrorCode.OAUTH_INVALID_STATE}
                    }
                },
            }
        },
    )
    async def authorize(
        request: Request,
        response: Response,
        scopes: list[str] = Query(None),
        next_url: str | None = None,
    ) -> OAuth2AuthorizeResponse:
        if redirect_url is not None:
            authorize_redirect_url = redirect_url
        else:
            authorize_redirect_url = str(request.url_for(callback_route_name))

        csrf_token = generate_csrf_token()
        state_data: dict[str, str] = {CSRF_TOKEN_KEY: csrf_token}
        if next_url is not None:
            try:
                state_data[NEXT_URL_STATE_KEY] = validate_next_url(next_url)
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ErrorCode.OAUTH_INVALID_STATE,
                ) from exc
        state = generate_state_token(state_data, state_secret)
        authorization_url = await oauth_client.get_authorization_url(
            authorize_redirect_url,
            state,
            scopes,
        )

        response.set_cookie(
            csrf_token_cookie_name,
            csrf_token,
            max_age=3600,
            path=csrf_token_cookie_path,
            domain=csrf_token_cookie_domain,
            secure=csrf_token_cookie_secure,
            httponly=csrf_token_cookie_httponly,
            samesite=csrf_token_cookie_samesite,
        )

        return OAuth2AuthorizeResponse(authorization_url=authorization_url)

    @router.get(
        "/callback",
        name=callback_route_name,
        description="The response varies based on the authentication backend used.",
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            "INVALID_STATE_TOKEN": {
                                "summary": "Invalid state token.",
                                "value": None,
                            },
                            ErrorCode.LOGIN_BAD_CREDENTIALS: {
                                "summary": "User is inactive.",
                                "value": {"detail": ErrorCode.LOGIN_BAD_CREDENTIALS},
                            },
                            ErrorCode.ACCESS_TOKEN_DECODE_ERROR: {
                                "summary": "Access token is error.",
                                "value": {
                                    "detail": ErrorCode.ACCESS_TOKEN_DECODE_ERROR
                                },
                            },
                            ErrorCode.ACCESS_TOKEN_ALREADY_EXPIRED: {
                                "summary": "Access token is already expired.",
                                "value": {
                                    "detail": ErrorCode.ACCESS_TOKEN_ALREADY_EXPIRED
                                },
                            },
                        }
                    }
                },
            },
        },
    )
    async def callback(
        request: Request,
        response: Response,
        access_token_state: tuple[OAuth2Token, str] = Depends(
            oauth2_authorize_callback
        ),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
        strategy: Strategy[models.UP, models.ID] = Depends(backend.get_strategy),
    ):
        token, state = access_token_state

        try:
            state_data = decode_jwt(state, state_secret, [STATE_TOKEN_AUDIENCE])
        except jwt.DecodeError as exc:
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACCESS_TOKEN_DECODE_ERROR,
            ) from exc
        except jwt.ExpiredSignatureError as exc:
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACCESS_TOKEN_ALREADY_EXPIRED,
            ) from exc

        cookie_csrf_token = request.cookies.get(csrf_token_cookie_name)
        state_csrf_token = state_data.get(CSRF_TOKEN_KEY)
        if (
            not cookie_csrf_token
            or not state_csrf_token
            or not secrets.compare_digest(cookie_csrf_token, state_csrf_token)
        ):
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_INVALID_STATE,
            )

        account_id, account_email = await oauth_client.get_id_email(
            token["access_token"]
        )

        if account_email is None:
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL,
            )

        try:
            user = await user_manager.oauth_callback(
                oauth_client.name,
                token["access_token"],
                account_id,
                account_email,
                token.get("expires_at"),
                token.get("refresh_token"),
                request,
                associate_by_email=associate_by_email,
                is_verified_by_default=is_verified_by_default,
            )
        except UserAlreadyExists as exc:
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_USER_ALREADY_EXISTS,
            ) from exc

        if not user.is_active:
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.LOGIN_BAD_CREDENTIALS,
            )

        auth_response = await backend.login(strategy, user)
        clear_csrf_cookie(
            auth_response,
            csrf_token_cookie_name,
            csrf_token_cookie_path,
            csrf_token_cookie_domain,
            csrf_token_cookie_secure,
            csrf_token_cookie_httponly,
            csrf_token_cookie_samesite,
        )
        append_next_url_header(auth_response, state_data.get(NEXT_URL_STATE_KEY))
        await user_manager.on_after_login(user, request, auth_response)
        return auth_response

    return router


def get_oauth_associate_router(
    oauth_client: BaseOAuth2,
    authenticator: Authenticator[models.UP, models.ID],
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    user_schema: type[schemas.U],
    state_secret: SecretType,
    redirect_url: str | None = None,
    requires_verification: bool = False,
    *,
    csrf_token_cookie_name: str = CSRF_TOKEN_COOKIE_NAME,
    csrf_token_cookie_path: str = "/",
    csrf_token_cookie_domain: str | None = None,
    csrf_token_cookie_secure: bool = True,
    csrf_token_cookie_httponly: bool = True,
    csrf_token_cookie_samesite: Literal["lax", "strict", "none"] = "lax",
) -> APIRouter:
    """Generate a router with the OAuth routes to associate an authenticated user."""
    router = APIRouter()

    get_current_active_user = authenticator.current_user(
        active=True, verified=requires_verification
    )

    callback_route_name = f"oauth-associate:{oauth_client.name}.callback"

    if redirect_url is not None:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            redirect_url=redirect_url,
        )
    else:
        oauth2_authorize_callback = OAuth2AuthorizeCallback(
            oauth_client,
            route_name=callback_route_name,
        )

    @router.get(
        "/authorize",
        name=f"oauth-associate:{oauth_client.name}.authorize",
        response_model=OAuth2AuthorizeResponse,
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "example": {"detail": ErrorCode.OAUTH_INVALID_STATE}
                    }
                },
            }
        },
    )
    async def authorize(
        request: Request,
        response: Response,
        scopes: list[str] = Query(None),
        next_url: str | None = None,
        user: models.UP = Depends(get_current_active_user),
    ) -> OAuth2AuthorizeResponse:
        if redirect_url is not None:
            authorize_redirect_url = redirect_url
        else:
            authorize_redirect_url = str(request.url_for(callback_route_name))

        csrf_token = generate_csrf_token()
        state_data: dict[str, str] = {"sub": str(user.id), CSRF_TOKEN_KEY: csrf_token}
        if next_url is not None:
            try:
                state_data[NEXT_URL_STATE_KEY] = validate_next_url(next_url)
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ErrorCode.OAUTH_INVALID_STATE,
                ) from exc
        state = generate_state_token(state_data, state_secret)
        authorization_url = await oauth_client.get_authorization_url(
            authorize_redirect_url,
            state,
            scopes,
        )

        response.set_cookie(
            csrf_token_cookie_name,
            csrf_token,
            max_age=3600,
            path=csrf_token_cookie_path,
            domain=csrf_token_cookie_domain,
            secure=csrf_token_cookie_secure,
            httponly=csrf_token_cookie_httponly,
            samesite=csrf_token_cookie_samesite,
        )

        return OAuth2AuthorizeResponse(authorization_url=authorization_url)

    @router.get(
        "/callback",
        response_model=user_schema,
        name=callback_route_name,
        description="The response varies based on the authentication backend used.",
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            "INVALID_STATE_TOKEN": {
                                "summary": "Invalid state token.",
                                "value": None,
                            },
                            ErrorCode.ACCESS_TOKEN_DECODE_ERROR: {
                                "summary": "Access token is error.",
                                "value": {
                                    "detail": ErrorCode.ACCESS_TOKEN_DECODE_ERROR
                                },
                            },
                            ErrorCode.ACCESS_TOKEN_ALREADY_EXPIRED: {
                                "summary": "Access token is already expired.",
                                "value": {
                                    "detail": ErrorCode.ACCESS_TOKEN_ALREADY_EXPIRED
                                },
                            },
                        }
                    }
                },
            },
        },
    )
    async def callback(
        request: Request,
        response: Response,
        user: models.UP = Depends(get_current_active_user),
        access_token_state: tuple[OAuth2Token, str] = Depends(
            oauth2_authorize_callback
        ),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        token, state = access_token_state

        try:
            state_data = decode_jwt(state, state_secret, [STATE_TOKEN_AUDIENCE])
        except jwt.DecodeError as exc:
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACCESS_TOKEN_DECODE_ERROR,
            ) from exc
        except jwt.ExpiredSignatureError as exc:
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACCESS_TOKEN_ALREADY_EXPIRED,
            ) from exc

        cookie_csrf_token = request.cookies.get(csrf_token_cookie_name)
        state_csrf_token = state_data.get(CSRF_TOKEN_KEY)
        if (
            not cookie_csrf_token
            or not state_csrf_token
            or not secrets.compare_digest(cookie_csrf_token, state_csrf_token)
        ):
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_INVALID_STATE,
            )

        if state_data["sub"] != str(user.id):
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

        account_id, account_email = await oauth_client.get_id_email(
            token["access_token"]
        )

        if account_email is None:
            clear_csrf_cookie(
                response,
                csrf_token_cookie_name,
                csrf_token_cookie_path,
                csrf_token_cookie_domain,
                csrf_token_cookie_secure,
                csrf_token_cookie_httponly,
                csrf_token_cookie_samesite,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL,
            )

        user = await user_manager.oauth_associate_callback(
            user,
            oauth_client.name,
            token["access_token"],
            account_id,
            account_email,
            token.get("expires_at"),
            token.get("refresh_token"),
            request,
        )

        clear_csrf_cookie(
            response,
            csrf_token_cookie_name,
            csrf_token_cookie_path,
            csrf_token_cookie_domain,
            csrf_token_cookie_secure,
            csrf_token_cookie_httponly,
            csrf_token_cookie_samesite,
        )
        append_next_url_header(response, state_data.get(NEXT_URL_STATE_KEY))
        return user_schema.model_validate(user)

    return router
