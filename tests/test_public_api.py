def test_public_api_imports() -> None:
    from fastapi_auth import AuthConfig, AuthUser, current_user, include_auth_router

    assert AuthConfig and AuthUser and current_user and include_auth_router
