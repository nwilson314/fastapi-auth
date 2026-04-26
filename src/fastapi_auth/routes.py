from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlmodel.ext.asyncio.session import AsyncSession

from fastapi_auth.config import AuthConfig
from fastapi_auth.dependencies import current_user
from fastapi_auth.hashing import hash_password, verify_password
from fastapi_auth.models import AuthUser
from fastapi_auth.schemas import (
    AuthResponse,
    LoginRequest,
    RegisterRequest,
    UserPublic,
)
from fastapi_auth.storage import (
    create_session,
    create_user,
    get_user_by_email,
    revoke_session,
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
        user = await create_user(
            s,
            config,
            email=body.email,
            password_hash=hash_password(body.password),
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

    app.include_router(router)
