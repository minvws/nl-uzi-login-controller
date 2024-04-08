from typing import Dict, Any


class ViteManifestService:
    def __init__(self, base_url: str, manifest: Dict[str, Dict[str, Any]]):
        self._base_url = self._get_url_with_trailing_slash(base_url)
        self._manifest = manifest

    def get_manifest(self) -> Dict[str, Dict[str, Any]]:
        return self._manifest

    def get_asset_url(self, input_path: str) -> str:
        if input_path not in self._manifest:
            raise ValueError(f"No asset found for input path: {input_path}")

        return self._get_url_for_asset(self._manifest[input_path]["file"])

    def _get_url_for_asset(self, asset_path: str) -> str:
        return self._base_url + asset_path

    @staticmethod
    def _get_url_with_trailing_slash(url: str) -> str:
        if url.endswith("/"):
            return url

        return url + "/"
