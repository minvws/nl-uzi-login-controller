import logging

import uvicorn
from fastapi import FastAPI, HTTPException
from starlette.staticfiles import StaticFiles

from app.dependencies import config
from app.exceptions.app_exception_handler import (
    general_exception_handler,
    http_exception_handler,
)
from app.models.docs_config import DocsConfig
from app.routers import session
from app.routers import login
from app.routers.docs_router import DocsRouter
from app.routers.main import router as main_router
from app.utils import get_version_from_config


def run_app() -> FastAPI:
    loglevel = logging.getLevelName(
        config.get("app", "loglevel", fallback="debug").upper()
    )
    if isinstance(loglevel, str):
        raise ValueError(f"Invalid loglevel {loglevel.upper()}")

    logging.basicConfig(level=loglevel, datefmt="%m/%d/%Y %I:%M:%S %p")

    version = get_version_from_config(config)
    docs_config = DocsConfig.from_config(config)

    fastapi = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=docs_config.openapi_endpoint,
        version=version,
    )
    fastapi.include_router(main_router)
    fastapi.include_router(session.router)
    fastapi.include_router(login.router)
    if docs_config.enabled:
        docs_router = DocsRouter(docs_config)
        fastapi.include_router(docs_router.get_docs_router())
    fastapi.add_exception_handler(Exception, general_exception_handler)
    fastapi.add_exception_handler(HTTPException, http_exception_handler)
    fastapi.mount("/static", StaticFiles(directory="static", html=True), name="static")
    return fastapi


def kwargs_from_config() -> dict:
    kwargs = {
        "host": config.get("uvicorn", "host"),
        "port": config.getint("uvicorn", "port"),
        "reload": config.getboolean("uvicorn", "reload"),
        "proxy_headers": True,
        "workers": config.getint("uvicorn", "workers"),
    }
    reload_includes = config.get("uvicorn", "reload_includes", fallback=None)
    if reload_includes is not None and reload_includes != "":
        kwargs["reload_includes"] = config.get("uvicorn", "reload_includes").split(" ")
    if config.getboolean("uvicorn", "use_ssl"):
        kwargs["ssl_keyfile"] = (
            config.get("uvicorn", "base_dir") + "/" + config.get("uvicorn", "key_file")
        )
        kwargs["ssl_certfile"] = (
            config.get("uvicorn", "base_dir") + "/" + config.get("uvicorn", "cert_file")
        )
    return kwargs


if __name__ == "__main__":
    uvicorn.run("app.main:run_app", **kwargs_from_config())
