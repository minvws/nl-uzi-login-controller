from fastapi import APIRouter, Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
)
from starlette.responses import HTMLResponse

from app.models.docs_config import DocsConfig


class DocsRouter:
    _docs_config: DocsConfig

    def __init__(self, docs_config: DocsConfig):
        self._docs_config = docs_config

    def get_docs_router(self) -> APIRouter:
        docs_router = APIRouter()

        if self._docs_config.swagger_ui_endpoint:
            docs_router.add_route(
                path=self._docs_config.swagger_ui_endpoint,
                endpoint=self.custom_swagger_ui_html,
                include_in_schema=False,
            )

        if self._docs_config.redoc_endpoint:
            docs_router.add_route(
                path=self._docs_config.redoc_endpoint,
                endpoint=self.redoc_html,
                include_in_schema=False,
            )

        return docs_router

    async def custom_swagger_ui_html(
        self,
        _request: Request,
    ) -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url=self._docs_config.openapi_endpoint or "",
            title="Swagger UI",
            swagger_js_url="static/assets/swagger-ui-bundle.js",
            swagger_css_url="static/assets/swagger-ui.css",
            swagger_favicon_url="static/img/favicon.ico",
        )

    async def redoc_html(
        self,
        _request: Request,
    ) -> HTMLResponse:
        return get_redoc_html(
            openapi_url=self._docs_config.openapi_endpoint or "",
            title="ReDoc",
            redoc_js_url="static/assets/redoc.standalone.js",
            redoc_favicon_url="static/img/favicon.ico",
            with_google_fonts=False,
        )
