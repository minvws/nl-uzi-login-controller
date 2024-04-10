from __future__ import annotations

from configparser import ConfigParser
from typing import Optional


class DocsConfig:
    _enabled: bool
    _swagger_ui_endpoint: Optional[str]
    _redoc_endpoint: Optional[str]
    _openapi_endpoint: Optional[str]

    def __init__(
        self,
        enabled: bool,
        swagger_ui_endpoint: Optional[str],
        redoc_endpoint: Optional[str],
        openapi_endpoint: Optional[str],
    ):
        self._enabled = enabled
        self._swagger_ui_endpoint = swagger_ui_endpoint
        self._redoc_endpoint = redoc_endpoint
        self._openapi_endpoint = openapi_endpoint

    @classmethod
    def from_config(cls, config: ConfigParser) -> DocsConfig:
        return cls(
            enabled=config.getboolean("docs", "enabled", fallback=False),
            swagger_ui_endpoint=config.get(
                "docs", "swagger_ui_endpoint", fallback=None
            ),
            redoc_endpoint=config.get("docs", "redoc_endpoint", fallback=None),
            openapi_endpoint=config.get("docs", "openapi_endpoint", fallback=None),
        )

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def swagger_ui_endpoint(self) -> Optional[str]:
        if not self.openapi_endpoint:
            return None

        return self._swagger_ui_endpoint

    @property
    def redoc_endpoint(self) -> Optional[str]:
        if not self.openapi_endpoint:
            return None

        return self._redoc_endpoint

    @property
    def openapi_endpoint(self) -> Optional[str]:
        if not self._enabled:
            return None

        return self._openapi_endpoint
