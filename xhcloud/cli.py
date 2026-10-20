import typer
import asyncio
from pathlib import Path
from core.ui import XHCloudDashboard, console
from core.engine import XHCloudEngine, XHCloudConfig
from modules.recon.generator import CloudReconGenerator
from modules.storage.scanner import StorageScanner
from modules.audit.scanner import AuditScanner
from core.reporter import ReportGenerator

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

@app.command()
def api(
    targets_file: str = typer.Argument(..., help="Fichier contenant les URLs d'API à scanner"),
    aggressive: bool = typer.Option(False, "--aggressive", "-a", help="Activer les tests de fuzzing lourds (Batch GraphQL, Blind NoSQL)"),
    threads: int = typer.Option(30, "--threads", "-t", help="Niveau de concurrence (réduit par défaut pour les API)")
):
    """🌐 Module API & SERVERLESS : Scan GraphQL, NoSQL, et configurations Serverless."""
    console.print("[bold neon_green]🌐 Initialisation du module API & SERVERLESS...[/]")
    
    config = XHCloudConfig()
    config.config["threads"] = threads # Plus bas pour les API pour éviter les WAF
    dashboard = XHCloudDashboard()
    engine = XHCloudEngine(dashboard, config)
    scanner = APIScanner(engine, dashboard)
    
    urls = Path(targets_file).read_text().splitlines()
    dashboard.start()
    
    try:
        asyncio.run(run_api_scan(scanner, dashboard, urls, aggressive))
    finally:
        dashboard.stop()
        asyncio.run(engine.close())

async def run_api_scan(scanner, dashboard, urls, aggressive):
    task = dashboard.add_task("[magenta]Audit des API & Serverless", total=len(urls))
    
    async def bounded_scan(url):
        async with scanner.semaphore:
            await scanner.scan_target(url)
            dashboard.update_task(task, advance=1)
            
            # Si mode agressif, on ajoute des checks supplémentaires ici
            if aggressive:
                pass # Placeholder pour fuzzing profond

    await asyncio.gather(*[bounded_scan(url) for url in urls])

@app.command()
def audit(
    targets_file: str = typer.Argument(..., help="Fichier d'URLs à auditer (headers, fichiers sensibles)"),
    report_format: str = typer.Option("html", "--report", "-r", help="Format du rapport (html, json, ou les deux: all)")
):
    """🛡️ Module AUDIT : Vérification des headers de sécurité et exposition de fichiers sensibles."""
    console.print("[bold neon_green]🛡️ Initialisation du module AUDIT...[/]")
    
    config = XHCloudConfig()
    dashboard = XHCloudDashboard()
    engine = XHCloudEngine(dashboard, config)
    scanner = AuditScanner(engine, dashboard)
    
    urls = Path(targets_file).read_text().splitlines()
    dashboard.start()
    
    try:
        asyncio.run(run_audit_scan(scanner, dashboard, urls))
    finally:
        dashboard.stop()
        asyncio.run(engine.close())
        
        # Génération du rapport à la fin du scan
        if report_format in ["html", "all"]:
            reporter = ReportGenerator(dashboard.findings, targets_file)
            html_file = reporter.generate_html()
            console.print(f"[bold green]📄 Rapport HTML généré : {html_file}[/]")
        if report_format in ["json", "all"]:
            reporter = ReportGenerator(dashboard.findings, targets_file)
            json_file = reporter.generate_json()
            console.print(f"[bold green]📄 Rapport JSON généré : {json_file}[/]")

async def run_audit_scan(scanner, dashboard, urls):
    task = dashboard.add_task("[blue]Audit de surface (Headers & CVS)", total=len(urls))
    
    async def bounded_scan(url):
        async with scanner.semaphore:
            await scanner.scan_target(url)
            dashboard.update_task(task, advance=1)

    await asyncio.gather(*[bounded_scan(url) for url in urls])


if __name__ == "__main__":
    app()
