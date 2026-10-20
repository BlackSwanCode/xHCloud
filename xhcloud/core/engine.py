import httpx
import yaml
from pathlib import Path

class XHCloudConfig:
    def __init__(self, config_path="config.yaml"):
        self.config = self._load_config(config_path)

    def _load_config(self, path):
        if Path(path).exists():
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        return {
            "proxy": None,
            "timeout": 10,
            "threads": 50,
            "user_agent": "xHCloud/1.0 (Cloud Pentest Suite)",
            "verify_ssl": False
        }

class XHCloudEngine:
    def __init__(self, dashboard, config: XHCloudConfig):
        self.dashboard = dashboard
        self.config = config
        self.client = self._setup_client()

    def _setup_client(self):
        # On récupère l'URL du proxy (peut être None)
        proxy_url = self.config.config.get("proxy")
        
        return httpx.AsyncClient(
            proxy=proxy_url,  # <-- CORRECTION ICI : 'proxy' au lieu de 'proxies'
            timeout=self.config.config.get("timeout"),
            headers={"User-Agent": self.config.config.get("user_agent")},
            verify=self.config.config.get("verify_ssl"),
            follow_redirects=True
        )

    async def close(self):
        await self.client.aclose()
