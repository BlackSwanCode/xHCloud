import asyncio
import re
import socket
from typing import Set, List, Dict
from rich.console import Console
from xhcloud.core.engine import XHCloudEngine
from xhcloud.core.ui import XHCloudDashboard

console = Console()

# Dictionnaire massif issu de hedgehog2b, optimisé pour xHCloud
CLOUD_PROVIDERS = {
    'aws': {
        'domains': ['amazonaws.com', 'cloudfront.net', 'elasticbeanstalk.com'],
        'regions': ['us-east-1', 'eu-west-1', 'ap-southeast-1'], # Subset for demo
        'services': ['s3', 'execute-api', 'lambda-url', 'cloudfront']
    },
    'azure': {
        'domains': ['azurewebsites.net', 'azure-api.net', 'blob.core.windows.net', 'azurefunctions.net'],
        'services': ['azure-api', 'azurewebsites', 'blob.core', 'azurefunctions']
    },
    'gcp': {
        'domains': ['googleapis.com', 'cloudfunctions.net', 'appspot.com', 'storage.googleapis.com'],
        'services': ['cloudfunctions', 'run', 'appengine', 'storage']
    }
}

class CloudReconGenerator:
    def __init__(self, engine: XHCloudEngine, dashboard: XHCloudDashboard):
        self.engine = engine
        self.dashboard = dashboard

    def extract_company_name(self, hostname: str) -> str:
        """Extrait le nom de base (entreprise) depuis un hostname."""
        hostname = re.sub(r'^https?://', '', hostname).split('/')[0]
        parts = hostname.split('.')
        tlds = ['co', 'com', 'org', 'net', 'io', 'ai']
        if len(parts) > 2 and parts[-2] in tlds:
            return parts[-3]
        return parts[-2] if len(parts) >= 2 else parts[0]

    def generate_permutations(self, base_name: str, keywords: List[str] = None) -> Set[str]:
        """Génère les variantes de base + mots-clés (issu de tenrec3a)."""
        variants = {base_name}
        if keywords:
            for kw in keywords:
                variants.add(f"{kw}-{base_name}")
                variants.add(f"{base_name}-{kw}")
                variants.add(f"{kw}{base_name}")
        return variants

    def generate_cloud_targets(self, company_name: str, providers: List[str], keywords: List[str] = None) -> Dict[str, Set[str]]:
        """Génère la matrice de cibles pour les providers sélectionnés."""
        targets = {}
        base_variants = self.generate_permutations(company_name, keywords)
        
        for provider in providers:
            if provider not in CLOUD_PROVIDERS:
                continue
            config = CLOUD_PROVIDERS[provider]
            provider_targets = set()
            
            for variant in base_variants:
                for domain in config['domains']:
                    provider_targets.add(f"{variant}.{domain}")
                for service in config.get('services', []):
                    for domain in config['domains']:
                        provider_targets.add(f"{variant}.{service}.{domain}")
            targets[provider] = provider_targets
        return targets

    async def resolve_dns_batch(self, hostnames: Set[str], task_id) -> List[str]:
        """Résolution DNS asynchrone ultra-rapide pour filtrer les cibles mortes."""
        resolved = []
        sem = asyncio.Semaphore(100) # Limite de concurrence DNS
        
        async def check_dns(host):
            async with sem:
                try:
                    # Utilisation de asyncio.to_thread pour ne pas bloquer l'event loop
                    await asyncio.to_thread(socket.gethostbyname, host)
                    resolved.append(host)
                    self.dashboard.update_task(task_id, advance=1)
                except socket.gaierror:
                    self.dashboard.update_task(task_id, advance=1)

        tasks = [check_dns(host) for host in hostnames]
        await asyncio.gather(*tasks)
        return resolved
