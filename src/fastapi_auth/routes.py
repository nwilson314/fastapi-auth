from fastapi import FastAPI
from fastapi_auth.config import AuthConfig


def include_auth_router(app: FastAPI, config: AuthConfig) -> None:
    raise NotImplementedError("include_auth_router is not implemented")
