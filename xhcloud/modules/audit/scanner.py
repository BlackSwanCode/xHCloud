import asyncio
from urllib.parse import urljoin
from typing import List
from xhcloud.core.engine import XHCloudEngine
from xhcloud.core.ui import XHCloudDashboard

class AuditScanner:
    def __init__(self, engine: XHCloudEngine, dashboard: XHCloudDashboard):
        self.engine = engine
        self.dashboard = dashboard
        self.semaphore = asyncio.Semaphore(engine.config.config.get("threads", 50))
        
        # Fichiers sensibles issus de AdvBuckets & AzApi3c
        self.sensitive_paths = [
            "/.git/config", "/.git/HEAD",
            "/.env", "/.aws/credentials",
            "/swagger.json", "/v2/api-docs", "/swagger-ui.html",
            "/.well-known/security.txt", "/phpinfo.php"
        ]
        
        # En-têtes de sécurité issus de QwCloud3a1b
        self.required_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy"
        ]

    async def scan_target(self, url: str):
        """Orchestre l'audit de surface d'une cible."""
        await self._check_sensitive_files(url)
        await self._check_security_headers(url)

    async def _check_sensitive_files(self, base_url: str):
        """Vérifie l'exposition de fichiers CVS, de config ou de documentation."""
        async with self.semaphore:
            for path in self.sensitive_paths:
                target = urljoin(base_url, path)
                try:
                    response = await self.engine.client.get(target)
                    if response.status_code == 200:
                        # Vérification basique pour éviter les faux positifs (ex: page 404 customisée)
                        if ".git" in path and "[core]" in response.text:
                            self.dashboard.add_vulnerability("Critical", "Audit", target, "Dépôt .git exposé")
                        elif ".env" in path and ("=" in response.text or "DB_" in response.text):
                            self.dashboard.add_vulnerability("Critical", "Audit", target, "Fichier .env exposé")
                        elif "swagger" in path or "api-docs" in path:
                            self.dashboard.add_vulnerability("Medium", "Audit", target, "Documentation API publique (Swagger/OpenAPI)")
                except Exception:
                    pass

    async def _check_security_headers(self, url: str):
        """Vérifie la présence des en-têtes de sécurité HTTP recommandés."""
        async with self.semaphore:
            try:
                response = await self.engine.client.get(url)
                headers = response.headers
                missing_headers = [h for h in self.required_headers if h not in headers]
                
                if missing_headers:
                    # On ne remonte que les manquants les plus critiques pour ne pas spammer le dashboard
                    critical_missing = [h for h in missing_headers if h in ["Strict-Transport-Security", "Content-Security-Policy"]]
                    if critical_missing:
                        self.dashboard.add_vulnerability(
                            "Low", 
                            "Audit", 
                            url, 
                            f"En-têtes de sécurité manquants: {', '.join(critical_missing)}"
                        )
            except Exception:
                pass
