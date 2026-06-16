from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel

from fastapi_users import exceptions, models, schemas
from fastapi_users.authentication import Authenticator
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.router.common import ErrorCode, ErrorModel

SENSITIVE_UPDATE_FIELDS = {"password", "hashed_password", "token", "access_token", "refresh_token"}


class UserUpdateFieldChange(BaseModel):
    before: Any
    after: Any


class UserUpdateSummary(BaseModel):
    changed_fields: dict[str, UserUpdateFieldChange]
    unchanged_fields: list[str]
    side_effect_fields: list[str]
    message: str


class UserUpdateResult(BaseModel):
    user: Any
    summary: UserUpdateSummary


def get_users_router(
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    user_schema: type[schemas.U],
    user_update_schema: type[schemas.UU],
    authenticator: Authenticator[models.UP, models.ID],
    requires_verification: bool = False,
) -> APIRouter:
    """Generate a router with the authentication routes."""
    router = APIRouter()

    get_current_active_user = authenticator.current_user(
        active=True, verified=requires_verification
    )
    get_current_superuser = authenticator.current_user(
        active=True, verified=requires_verification, superuser=True
    )

    def get_tracked_fields(update_dict: dict[str, Any]) -> list[str]:
        tracked_fields = [
            field for field in update_dict.keys() if field not in SENSITIVE_UPDATE_FIELDS
        ]
        if "email" in tracked_fields and "is_verified" not in tracked_fields:
            tracked_fields.append("is_verified")
        return tracked_fields

    def snapshot_user_fields(user: models.UP, tracked_fields: list[str]) -> dict[str, Any]:
        return {field: getattr(user, field, None) for field in tracked_fields}

    def build_update_summary(
        before_values: dict[str, Any],
        updated_user: models.UP,
        update_dict: dict[str, Any],
    ) -> UserUpdateSummary:
        tracked_fields = list(before_values.keys())
        changed_fields: dict[str, UserUpdateFieldChange] = {}
        unchanged_fields: list[str] = []
        side_effect_fields: list[str] = []

        for field in tracked_fields:
            before = before_values[field]
            after = getattr(updated_user, field, None)
            if before != after:
                changed_fields[field] = UserUpdateFieldChange(before=before, after=after)
                if field not in update_dict:
                    side_effect_fields.append(field)
            else:
                unchanged_fields.append(field)

        return UserUpdateSummary(
            changed_fields=changed_fields,
            unchanged_fields=unchanged_fields,
            side_effect_fields=side_effect_fields,
            message="updated" if changed_fields else "no_changes",
        )

    def build_update_response(
        before_values: dict[str, Any],
        updated_user: models.UP,
        update_dict: dict[str, Any],
        include_update_summary: bool,
    ):
        serialized_user = user_schema.model_validate(updated_user)
        if not include_update_summary:
            return serialized_user

        return UserUpdateResult(
            user=serialized_user,
            summary=build_update_summary(before_values, updated_user, update_dict),
        )

    async def get_user_or_404(
        id: str,
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ) -> models.UP:
        try:
            parsed_id = user_manager.parse_id(id)
            return await user_manager.get(parsed_id)
        except (exceptions.UserNotExists, exceptions.InvalidID) as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from e

    @router.get(
        "/me",
        response_model=user_schema,
        name="users:current_user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
        },
    )
    async def me(
        user: models.UP = Depends(get_current_active_user),
    ):
        return user_schema.model_validate(user)

    @router.patch(
        "/me",
        response_model=None,
        dependencies=[Depends(get_current_active_user)],
        name="users:patch_current_user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS: {
                                "summary": "A user with this email already exists.",
                                "value": {
                                    "detail": ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS
                                },
                            },
                            ErrorCode.UPDATE_USER_INVALID_PASSWORD: {
                                "summary": "Password validation failed.",
                                "value": {
                                    "detail": {
                                        "code": ErrorCode.UPDATE_USER_INVALID_PASSWORD,
                                        "reason": "Password should be"
                                        "at least 3 characters",
                                    }
                                },
                            },
                        }
                    }
                },
            },
        },
    )
    async def update_me(
        request: Request,
        user_update: user_update_schema,  # type: ignore
        include_update_summary: bool = Query(False),
        user: models.UP = Depends(get_current_active_user),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        update_dict = user_update.create_update_dict()
        tracked_fields = get_tracked_fields(update_dict)
        before_values = snapshot_user_fields(user, tracked_fields)
        try:
            updated_user = await user_manager.update(
                user_update, user, safe=True, request=request
            )
            return build_update_response(
                before_values,
                updated_user,
                update_dict,
                include_update_summary,
            )
        except exceptions.InvalidPasswordException as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": ErrorCode.UPDATE_USER_INVALID_PASSWORD,
                    "reason": e.reason,
                },
            )
        except exceptions.UserAlreadyExists:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS,
            )

    @router.get(
        "/{id}",
        response_model=user_schema,
        dependencies=[Depends(get_current_superuser)],
        name="users:user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
            status.HTTP_403_FORBIDDEN: {
                "description": "Not a superuser.",
            },
            status.HTTP_404_NOT_FOUND: {
                "description": "The user does not exist.",
            },
        },
    )
    async def get_user(user=Depends(get_user_or_404)):
        return user_schema.model_validate(user)

    @router.patch(
        "/{id}",
        response_model=None,
        dependencies=[Depends(get_current_superuser)],
        name="users:patch_user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
            status.HTTP_403_FORBIDDEN: {
                "description": "Not a superuser.",
            },
            status.HTTP_404_NOT_FOUND: {
                "description": "The user does not exist.",
            },
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS: {
                                "summary": "A user with this email already exists.",
                                "value": {
                                    "detail": ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS
                                },
                            },
                            ErrorCode.UPDATE_USER_INVALID_PASSWORD: {
                                "summary": "Password validation failed.",
                                "value": {
                                    "detail": {
                                        "code": ErrorCode.UPDATE_USER_INVALID_PASSWORD,
                                        "reason": "Password should be"
                                        "at least 3 characters",
                                    }
                                },
                            },
                        }
                    }
                },
            },
        },
    )
    async def update_user(
        user_update: user_update_schema,  # type: ignore
        request: Request,
        include_update_summary: bool = Query(False),
        user=Depends(get_user_or_404),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        update_dict = user_update.create_update_dict_superuser()
        tracked_fields = get_tracked_fields(update_dict)
        before_values = snapshot_user_fields(user, tracked_fields)
        try:
            updated_user = await user_manager.update(
                user_update, user, safe=False, request=request
            )
            return build_update_response(
                before_values,
                updated_user,
                update_dict,
                include_update_summary,
            )
        except exceptions.InvalidPasswordException as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": ErrorCode.UPDATE_USER_INVALID_PASSWORD,
                    "reason": e.reason,
                },
            )
        except exceptions.UserAlreadyExists:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS,
            )

    @router.delete(
        "/{id}",
        status_code=status.HTTP_204_NO_CONTENT,
        response_class=Response,
        dependencies=[Depends(get_current_superuser)],
        name="users:delete_user",
        responses={
            status.HTTP_401_UNAUTHORIZED: {
                "description": "Missing token or inactive user.",
            },
            status.HTTP_403_FORBIDDEN: {
                "description": "Not a superuser.",
            },
            status.HTTP_404_NOT_FOUND: {
                "description": "The user does not exist.",
            },
        },
    )
    async def delete_user(
        request: Request,
        user=Depends(get_user_or_404),
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
    ):
        await user_manager.delete(user, request=request)
        return None

    return router
