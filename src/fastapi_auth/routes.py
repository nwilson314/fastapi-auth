from datetime import UTC, datetime

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy.exc import IntegrityError
from sqlmodel import col, update
from sqlmodel.ext.asyncio.session import AsyncSession

from fastapi_auth.config import AuthConfig
from fastapi_auth.dependencies import current_user
from fastapi_auth.hashing import hash_password, verify_password
from fastapi_auth.models import AuthUser
from fastapi_auth.schemas import (
    AuthResponse,
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RegisterRequest,
    UserPublic,
)
from fastapi_auth.storage import (
    SessionReuseError,
    create_session,
    create_user,
    get_user_by_email,
    get_user_by_id,
    revoke_all_sessions,
    revoke_session,
    rotate_session,
)
from fastapi_auth.tokens import (
    InvalidPasswordResetToken,
    create_password_reset_token,
    verify_password_reset_token,
)
from fastapi_auth.transport import attach_token, clear_cookie, extract_token


def include_auth_router(app: FastAPI, config: AuthConfig) -> None:
    router = APIRouter(prefix="/auth", tags=["auth"])
    user_dep = current_user(config)

    @router.post("/register", status_code=status.HTTP_201_CREATED)
    async def register(
        body: RegisterRequest,
        response: Response,
        s: AsyncSession = Depends(config.db_session_dep),
    ) -> AuthResponse:
        if await get_user_by_email(s, body.email, config) is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "email already registered"
            )
        try:
            user = await create_user(
                s,
                config,
                email=body.email,
                password_hash=hash_password(body.password),
            )
        except IntegrityError:
            # Race: another request inserted the same email between our check
            # and our flush. Roll back and surface the same 409.
            await s.rollback()
            raise HTTPException(
                status.HTTP_409_CONFLICT, "email already registered"
            )
        token, _ = await create_session(s, user.id, config.session_lifetime)
        await s.commit()
        attach_token(response, token, config)
        return AuthResponse(
            token=token, user=UserPublic(id=user.id, email=user.email)
        )

    @router.post("/login")
    async def login(
        body: LoginRequest,
        response: Response,
        s: AsyncSession = Depends(config.db_session_dep),
    ) -> AuthResponse:
        user = await get_user_by_email(s, body.email, config)
        if user is None or not verify_password(body.password, user.password_hash):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "invalid credentials"
            )
        token, _ = await create_session(s, user.id, config.session_lifetime)
        await s.commit()
        attach_token(response, token, config)
        return AuthResponse(
            token=token, user=UserPublic(id=user.id, email=user.email)
        )

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(
        request: Request,
        response: Response,
        s: AsyncSession = Depends(config.db_session_dep),
    ) -> None:
        token = extract_token(request, config)
        if token:
            await revoke_session(s, token)
            await s.commit()
        clear_cookie(response, config)

    @router.get("/me")
    async def me(user: AuthUser = Depends(user_dep)) -> UserPublic:
        return UserPublic(id=user.id, email=user.email)

    @router.post("/refresh")
    async def refresh(
        request: Request,
        response: Response,
        s: AsyncSession = Depends(config.db_session_dep),
    ) -> AuthResponse:
        token = extract_token(request, config)
        if not token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED)
        try:
            new_token, new_session = await rotate_session(
                s, token, config.session_lifetime
            )
        except SessionReuseError:
            # rotate_session may have revoked the family already — persist that.
            await s.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED)
        user = await get_user_by_id(s, new_session.user_id, config)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED)
        await s.commit()
        attach_token(response, new_token, config)
        return AuthResponse(
            token=new_token, user=UserPublic(id=user.id, email=user.email)
        )

    @router.post(
        "/password-reset/request", status_code=status.HTTP_204_NO_CONTENT
    )
    async def password_reset_request(
        body: PasswordResetRequest,
        s: AsyncSession = Depends(config.db_session_dep),
    ) -> None:
        user = await get_user_by_email(s, body.email, config)
        if user is None:
            # Don't leak account existence — silent success.
            return
        token = create_password_reset_token(
            user.id,
            config.secret_key,
            config.password_reset_lifetime,
            password_version=user.password_version,
        )
        await config.send_password_reset(user, token)

    @router.post(
        "/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT
    )
    async def password_reset_confirm(
        body: PasswordResetConfirm,
        s: AsyncSession = Depends(config.db_session_dep),
    ) -> None:
        try:
            user_id, token_pwv = verify_password_reset_token(
                body.token, config.secret_key
            )
        except InvalidPasswordResetToken:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "invalid or expired token"
            )
        # Atomic single-use enforcement: row-level conditional UPDATE.
        # Two concurrent confirms with the same token: one matches
        # (rowcount=1), the other doesn't (rowcount=0).
        result = await s.exec(
            update(config.user_model)
            .where(
                col(config.user_model.id) == user_id,
                col(config.user_model.password_version) == token_pwv,
            )
            .values(
                password_hash=hash_password(body.new_password),
                password_version=token_pwv + 1,
                updated_at=datetime.now(UTC),
            )
        )
        if result.rowcount == 0:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "invalid or expired token"
            )
        await revoke_all_sessions(s, user_id)
        await s.commit()

    app.include_router(router)
