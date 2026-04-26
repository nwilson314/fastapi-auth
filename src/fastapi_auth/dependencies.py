from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from sqlmodel.ext.asyncio.session import AsyncSession

from fastapi_auth.config import AuthConfig
from fastapi_auth.models import AuthUser
from fastapi_auth.storage import get_session_by_token, get_user_by_id
from fastapi_auth.transport import extract_token


def current_user(config: AuthConfig) -> Callable:
    """Returns a FastAPI dependency that resolves to the authenticated user.
    
    Usage:
        ```python
        user_dep = current_user(config)
        @app.get("/me")
        async def me(user: User = Depends(user_dep)): ...
        ```
    """

    async def _current_user(
        request: Request,
        s: AsyncSession = Depends(config.db_session_dep),
    ) -> AuthUser:
        token = extract_token(request, config)
        if not token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED)
        
        sess = await get_session_by_token(s, token)
        now = datetime.now(UTC)
        if sess is None or sess.revoked_at is not None or sess.expires_at < now:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED)
        
        user = await get_user_by_id(s, sess.user_id, config)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED)
        
        return user
    
    return _current_user