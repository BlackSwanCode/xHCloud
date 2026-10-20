import typer
import asyncio
import traceback
from pathlib import Path

from xhcloud.modules.api.scanner import APIScanner
from xhcloud.core.ui import XHCloudDashboard, console
from xhcloud.core.engine import XHCloudEngine, XHCloudConfig
from xhcloud.core.reporter import ReportGenerator
from xhcloud.modules.recon.generator import CloudReconGenerator
from xhcloud.modules.storage.scanner import StorageScanner
from xhcloud.modules.audit.scanner import AuditScanner

app = typer.Typer(help="☁️ xHCloud : Suite unifiée de pentest Cloud & API ultra-puissante.")

@app.command()
def recon(
    target: str = typer.Argument(..., help="Domaine cible ou fichier de domaines"),
    providers: str = typer.Option("aws,azure,gcp", "--providers", "-p", help="Providers à scanner (csv)"),
    use_keywords: bool = typer.Option(False, "--keywords", "-k", help="Activer les mutations par mots-clés"),
    dns_check: bool = typer.Option(True, "--dns/--no-dns", help="Vérifier la résolution DNS")
):
    console.print("[bold neon_green]🚀 Initialisation du module RECON...[/]")
    
    config = XHCloudConfig()
    dashboard = XHCloudDashboard()
    engine = XHCloudEngine(dashboard, config)
    generator = CloudReconGenerator(engine, dashboard)
    
    is_file = Path(target).is_file()
    targets = Path(target).read_text().splitlines() if is_file else [target]
    prov_list = [p.strip() for p in providers.split(',')]
    
    console.print(f"[cyan]→ Cibles à traiter : {len(targets)}[/]")
    console.print(f"[cyan]→ Providers : {', '.join(prov_list)}[/]")
    console.print("[cyan]→ Démarrage du Dashboard... (Appuyez sur Ctrl+C pour arrêter)[/]")
    
    dashboard.start()
    
    try:
        asyncio.run(run_recon(generator, dashboard, engine, targets, prov_list, dns_check))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️ Interruption par l'utilisateur.[/]")
    except Exception as e:
        console.print(f"\n[bold red]❌ Erreur fatale : {e}[/]")
        traceback.print_exc()
    finally:
        dashboard.stop()
        asyncio.run(engine.close())
        
    console.print("\n" + "="*60)
    console.print(f"[bold green]✅ Scan RECON terminé ![/]")
    console.print(f"[bold cyan]📊 {len(dashboard.findings)} événement(s) enregistré(s) dans le moteur.[/]")
    console.print(f"[bold green]📄 Résultats sauvegardés dans : [underline]xhcloud_recon_output.txt[/][/]")
    console.print("="*60)

async def run_recon(generator, dashboard, engine, targets, providers, dns_check):
    all_targets = set()
    task_gen = dashboard.add_task("[cyan]Génération des permutations Cloud", total=len(targets))
    
    for t in targets:
        company = generator.extract_company_name(t)
        perms = generator.generate_cloud_targets(company, providers)
        for prov, urls in perms.items():
            all_targets.update(urls)
        dashboard.update_task(task_gen, advance=1)
        
    dashboard.add_vulnerability("Info", "RECON", "Moteur", f"{len(all_targets)} URLs générées au total")

    if dns_check:
        task_dns = dashboard.add_task("[magenta]Résolution DNS Asynchrone", total=len(all_targets))
        resolved = await generator.resolve_dns_batch(all_targets, task_dns)
        dashboard.add_vulnerability("High", "RECON", "DNS", f"{len(resolved)} hôtes actifs trouvés")
        
        with open("xhcloud_recon_output.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(resolved))
    else:
        with open("xhcloud_recon_output.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(all_targets))

@app.command()
def storage(
    targets_file: str = typer.Argument(..., help="Fichier d'URLs de buckets à scanner"),
    mutate: bool = typer.Option(True, "--mutate/--no-mutate", help="Activer la mutation Cross-Cloud"),
    threads: int = typer.Option(50, "--threads", "-t", help="Niveau de concurrence")
):
    console.print("[bold neon_green]📦 Initialisation du module STORAGE...[/]")
    config = XHCloudConfig()
    config.config["threads"] = threads
    dashboard = XHCloudDashboard()
    engine = XHCloudEngine(dashboard, config)
    scanner = StorageScanner(engine, dashboard)
    
    urls = Path(targets_file).read_text().splitlines()
    console.print(f"[cyan]→ {len(urls)} URLs à scanner.[/]")
    
    dashboard.start()
    try:
        asyncio.run(run_storage_scan(scanner, dashboard, urls, mutate))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️ Interruption par l'utilisateur.[/]")
    except Exception as e:
        console.print(f"\n[bold red]❌ Erreur fatale : {e}[/]")
        traceback.print_exc()
    finally:
        dashboard.stop()
        asyncio.run(engine.close())
        
    console.print("\n" + "="*60)
    console.print(f"[bold green]✅ Scan STORAGE terminé ! {len(dashboard.findings)} trouvaille(s).[/]")
    console.print("="*60)

async def run_storage_scan(scanner, dashboard, urls, mutate):
    task = dashboard.add_task("[yellow]Scan des Stockages Cloud", total=len(urls))
    sem = asyncio.Semaphore(scanner.engine.config.config.get("threads", 50))
    
    async def bounded_scan(url):
        if not url.strip(): return
        async with sem:
            await scanner.scan_url(url.strip(), enable_mutation=mutate)
            dashboard.update_task(task, advance=1)

    await asyncio.gather(*[bounded_scan(url) for url in urls])

@app.command()
def api(
    targets_file: str = typer.Argument(..., help="Fichier contenant les URLs d'API à scanner"),
    aggressive: bool = typer.Option(False, "--aggressive", "-a", help="Activer les tests de fuzzing lourds"),
    threads: int = typer.Option(30, "--threads", "-t", help="Niveau de concurrence")
):
    console.print("[bold neon_green]🌐 Initialisation du module API & SERVERLESS...[/]")
    config = XHCloudConfig()
    config.config["threads"] = threads
    dashboard = XHCloudDashboard()
    engine = XHCloudEngine(dashboard, config)
    scanner = APIScanner(engine, dashboard) # Assurez-vous d'importer APIScanner en haut du fichier si vous l'utilisez
    
    urls = Path(targets_file).read_text().splitlines()
    console.print(f"[cyan]→ {len(urls)} APIs à scanner.[/]")
    
    dashboard.start()
    try:
        asyncio.run(run_api_scan(scanner, dashboard, urls, aggressive))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️ Interruption par l'utilisateur.[/]")
    except Exception as e:
        console.print(f"\n[bold red]❌ Erreur fatale : {e}[/]")
        traceback.print_exc()
    finally:
        dashboard.stop()
        asyncio.run(engine.close())
        
    console.print("\n" + "="*60)
    console.print(f"[bold green]✅ Scan API terminé ! {len(dashboard.findings)} trouvaille(s).[/]")
    console.print("="*60)

async def run_api_scan(scanner, dashboard, urls, aggressive):
    task = dashboard.add_task("[magenta]Audit des API & Serverless", total=len(urls))
    async def bounded_scan(url):
        if not url.strip(): return
        async with scanner.semaphore:
            await scanner.scan_target(url.strip())
            dashboard.update_task(task, advance=1)
    await asyncio.gather(*[bounded_scan(url) for url in urls])

@app.command()
def audit(
    targets_file: str = typer.Argument(..., help="Fichier d'URLs à auditer"),
    report_format: str = typer.Option("html", "--report", "-r", help="Format du rapport (html, json, ou all)")
):
    console.print("[bold neon_green]🛡️ Initialisation du module AUDIT...[/]")
    config = XHCloudConfig()
    dashboard = XHCloudDashboard()
    engine = XHCloudEngine(dashboard, config)
    scanner = AuditScanner(engine, dashboard)
    
    urls = Path(targets_file).read_text().splitlines()
    console.print(f"[cyan]→ {len(urls)} URLs à auditer.[/]")
    
    dashboard.start()
    try:
        asyncio.run(run_audit_scan(scanner, dashboard, urls))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️ Interruption par l'utilisateur.[/]")
    except Exception as e:
        console.print(f"\n[bold red]❌ Erreur fatale : {e}[/]")
        traceback.print_exc()
    finally:
        dashboard.stop()
        asyncio.run(engine.close())
        
        if report_format in ["html", "all"]:
            reporter = ReportGenerator(dashboard.findings, targets_file)
            html_file = reporter.generate_html()
            console.print(f"[bold green]📄 Rapport HTML généré : {html_file}[/]")
        if report_format in ["json", "all"]:
            reporter = ReportGenerator(dashboard.findings, targets_file)
            json_file = reporter.generate_json()
            console.print(f"[bold green]📄 Rapport JSON généré : {json_file}[/]")
            
    console.print("\n" + "="*60)
    console.print(f"[bold green]✅ Audit terminé ! {len(dashboard.findings)} événement(s).[/]")
    console.print("="*60)

async def run_audit_scan(scanner, dashboard, urls):
    task = dashboard.add_task("[blue]Audit de surface (Headers & CVS)", total=len(urls))
    async def bounded_scan(url):
        if not url.strip(): return
        async with scanner.semaphore:
            await scanner.scan_target(url.strip())
            dashboard.update_task(task, advance=1)
    await asyncio.gather(*[bounded_scan(url) for url in urls])

if __name__ == "__main__":
    app()
