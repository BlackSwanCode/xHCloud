import typer
import asyncio
from pathlib import Path
from core.ui import XHCloudDashboard, console
from core.engine import XHCloudEngine, XHCloudConfig
from modules.recon.generator import CloudReconGenerator
from modules.storage.scanner import StorageScanner

app = typer.Typer(help="☁️ xHCloud : Suite unifiée de pentest Cloud & API ultra-puissante.")

@app.command()
def recon(
    target: str = typer.Argument(..., help="Domaine cible ou fichier de domaines"),
    providers: str = typer.Option("aws,azure,gcp", "--providers", "-p", help="Providers à scanner (csv)"),
    use_keywords: bool = typer.Option(False, "--keywords", "-k", help="Activer les mutations par mots-clés"),
    dns_check: bool = typer.Option(True, "--dns/--no-dns", help="Vérifier la résolution DNS")
):
    """🕵️ Module RECON : Génération et résolution de cibles Cloud Cross-Provider."""
    console.print("[bold neon_green]🚀 Initialisation du module RECON...[/]")
    
    config = XHCloudConfig()
    dashboard = XHCloudDashboard()
    engine = XHCloudEngine(dashboard, config)
    generator = CloudReconGenerator(engine, dashboard)
    
    # Chargement des cibles
    targets = [target] if Path(target).is_file() == False else Path(target).read_text().splitlines()
    prov_list = [p.strip() for p in providers.split(',')]
    
    dashboard.start()
    
    try:
        asyncio.run(run_recon(generator, dashboard, engine, targets, prov_list, dns_check))
    finally:
        dashboard.stop()
        asyncio.run(engine.close())

async def run_recon(generator, dashboard, engine, targets, providers, dns_check):
    all_targets = set()
    task_gen = dashboard.add_task("[cyan]Génération des permutations Cloud", total=len(targets))
    
    for t in targets:
        company = generator.extract_company_name(t)
        perms = generator.generate_cloud_targets(company, providers)
        for prov, urls in perms.items():
            all_targets.update(urls)
        dashboard.update_task(task_gen, advance=1)
        
    dashboard.add_vulnerability("Info", "RECON", "Moteur", f"{len(all_targets)} URLs générées")

    if dns_check:
        task_dns = dashboard.add_task("[magenta]Résolution DNS Asynchrone", total=len(all_targets))
        resolved = await generator.resolve_dns_batch(all_targets, task_dns)
        dashboard.add_vulnerability("High", "RECON", "DNS", f"{len(resolved)} hôtes actifs trouvés")
        
        # Sauvegarde pour la phase 2
        with open("xhcloud_recon_output.txt", "w") as f:
            f.write("\n".join(resolved))

@app.command()
def storage(
    targets_file: str = typer.Argument(..., help="Fichier d'URLs de buckets à scanner"),
    mutate: bool = typer.Option(True, "--mutate/--no-mutate", help="Activer la mutation Cross-Cloud"),
    threads: int = typer.Option(50, "--threads", "-t", help="Niveau de concurrence")
):
    """📦 Module STORAGE : Audit des buckets et mutation Cross-Cloud."""
    console.print("[bold neon_green]📦 Initialisation du module STORAGE...[/]")
    
    config = XHCloudConfig()
    config.config["threads"] = threads
    dashboard = XHCloudDashboard()
    engine = XHCloudEngine(dashboard, config)
    scanner = StorageScanner(engine, dashboard)
    
    urls = Path(targets_file).read_text().splitlines()
    dashboard.start()
    
    try:
        asyncio.run(run_storage_scan(scanner, dashboard, urls, mutate))
    finally:
        dashboard.stop()
        asyncio.run(engine.close())

async def run_storage_scan(scanner, dashboard, urls, mutate):
    task = dashboard.add_task("[yellow]Scan des Stockages Cloud", total=len(urls))
    
    # Création d'un semaphore pour limiter la concurrence HTTP
    sem = asyncio.Semaphore(scanner.engine.config.config.get("threads", 50))
    
    async def bounded_scan(url):
        async with sem:
            await scanner.scan_url(url, enable_mutation=mutate)
            dashboard.update_task(task, advance=1)

    await asyncio.gather(*[bounded_scan(url) for url in urls])

if __name__ == "__main__":
    app()
