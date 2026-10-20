import asyncio
import re
from urllib.parse import urlparse
from typing import List, Dict
from core.engine import XHCloudEngine
from core.ui import XHCloudDashboard

# Moteur de Mutation Cross-Cloud (Inspiré de AdvBuckets)
MUTATION_MAP = {
    r"\.s3\.amazonaws\.com": [".blob.core.windows.net", ".cloudfront.net"],
    r"\.blob\.core\.windows\.net": [".s3.amazonaws.com", ".azureedge.net"],
    r"\.azurewebsites\.net": [".blob.core.windows.net", ".azurefunctions.net", ".azure-api.net"],
    r"\.cloudfront\.net": [".s3.amazonaws.com"],
    r"storage\.googleapis\.com": [".blob.core.windows.net", ".s3.amazonaws.com"]
}

class StorageScanner:
    def __init__(self, engine: XHCloudEngine, dashboard: XHCloudDashboard):
        self.engine = engine
        self.dashboard = dashboard

    def _mutate_url(self, url: str) -> List[str]:
        """Génère des URLs mutées pour tester les TakeOvers et mauvaises configs cross-cloud."""
        mutated_urls = []
        for pattern, replacements in MUTATION_MAP.items():
            if re.search(pattern, url):
                for repl in replacements:
                    new_url = re.sub(pattern, repl, url)
                    mutated_urls.append(new_url)
        return mutated_urls

    async def check_aws_s3(self, url: str):
        """Check AWS S3 Public Listing (Issu de AwsBucket1a & QwCloud)."""
        try:
            # Test de listing anonyme
            response = await self.engine.client.get(f"{url}/?list-type=2")
            if response.status_code == 200 and "<Contents>" in response.text:
                self.dashboard.add_vulnerability("Critical", "AWS S3", url, "Anonymous List Access (Public Bucket)")
            elif response.status_code == 403:
                pass # Sécurisé
        except Exception:
            pass

    async def check_azure_blob(self, url: str):
        """Check Azure Blob Public Access (Issu de AzBlob1a)."""
        try:
            # Extraction du conteneur pour tester le listing
            parsed = urlparse(url)
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) > 0:
                container_url = f"{parsed.scheme}://{parsed.netloc}/{path_parts[0]}?restype=container&comp=list"
                response = await self.engine.client.get(container_url)
                if response.status_code == 200 and "EnumerationResults" in response.text:
                    self.dashboard.add_vulnerability("Critical", "Azure Blob", url, "Anonymous Container List")
        except Exception:
            pass

    async def check_gcp_gcs(self, url: str):
        """Check GCP Storage Public Access (Issu de GcpBucket1a)."""
        try:
            response = await self.engine.client.get(f"{url}/?prefix=&delimiter=/")
            if response.status_code == 200 and "Contents" in response.text:
                self.dashboard.add_vulnerability("Critical", "GCP GCS", url, "Anonymous Bucket Access")
        except Exception:
            pass

    async def scan_url(self, url: str, enable_mutation: bool = True):
        """Orchestre le scan d'une URL et applique les mutations si demandé."""
        urls_to_scan = [url]
        
        if enable_mutation:
            urls_to_scan.extend(self._mutate_url(url))

        for target in urls_to_scan:
            parsed = urlparse(target)
            hostname = parsed.netloc
            
            # Routage vers le bon check
            if "s3.amazonaws.com" in hostname or ".s3." in hostname:
                await self.check_aws_s3(target)
            elif "blob.core.windows.net" in hostname:
                await self.check_azure_blob(target)
            elif "storage.googleapis.com" in hostname:
                await self.check_gcp_gcs(target)
            else:
                # Fallback: Test générique de directory listing
                try:
                    resp = await self.engine.client.get(target)
                    if resp.status_code == 200 and ("Index of /" in resp.text or "ListBucketResult" in resp.text):
                        self.dashboard.add_vulnerability("High", "Generic", target, "Directory Listing Enabled")
                except Exception:
                    pass
