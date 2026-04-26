from fastapi import Request, Response
from fastapi_auth.config import AuthConfig


_BEARER_PREFIX = "Bearer "


def extract_token(request: Request, config: AuthConfig) -> str | None:
    """Bearer header first cookie fallback"""

    auth = request.headers.get("authorization", "")
    if auth.startswith(_BEARER_PREFIX):
        token = auth[len(_BEARER_PREFIX):].strip()
        return token or None

    return request.cookies.get(config.cookie_name) or None


def attach_token(response: Response, token: str, config: AuthConfig) -> None:
    response.set_cookie(
        key=config.cookie_name,
        value=token,
        max_age=int(config.session_lifetime.total_seconds()),
        domain=config.cookie_domain,
        secure=config.cookie_secure,
        samesite=config.cookie_samesite,
        httponly=True,
    )


def clear_cookie(response: Response, config: AuthConfig) -> None:
    response.delete_cookie(
        key=config.cookie_name,
        domain=config.cookie_domain,
        secure=config.cookie_secure,
        samesite=config.cookie_samesite,
        httponly=True,
    )