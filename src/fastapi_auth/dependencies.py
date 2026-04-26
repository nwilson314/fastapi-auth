from fastapi_auth.models import AuthUser


def current_user() -> AuthUser:
    raise NotImplementedError("current_user is not implemented")
