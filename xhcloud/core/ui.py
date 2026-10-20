from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich.align import Align

console = Console()

class XHCloudDashboard:
    def __init__(self):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[bold blue]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console
        )
        self.vuln_table = Table(title="🚨 Vulnérabilités Détectées en Temps Réel", expand=True)
        self.vuln_table.add_column("Sévérité", justify="center", style="bold", width=10)
        self.vuln_table.add_column("Module", style="cyan", width=15)
        self.vuln_table.add_column("Cible", style="magenta", width=40)
        self.vuln_table.add_column("Détails", style="green")
        
        self.stats = {"targets": 0, "requests": 0, "vulns": 0}
        self.findings = [] # Liste pour stocker les résultats pour le rapport
        self.live = None

    def generate_layout(self):
        layout = Layout()
        layout.split_column(
            Layout(Panel(Align.center(Text("☁️  xHCloud - Ultra Cloud Pentest Suite  ☁️", style="bold neon_green")), title="Banner"), size=3),
            Layout(self.progress, name="progress", size=4),
            Layout(Panel(self.vuln_table, title="Live Findings", border_style="blue"), name="findings")
        )
        return layout

    def start(self):
        self.live = Live(self.generate_layout(), console=console, refresh_per_second=10, screen=True)
        self.live.start()

    def stop(self):
        if self.live:
            self.live.stop()

    def add_task(self, description, total):
        return self.progress.add_task(f"[cyan]{description}", total=total)

    def update_task(self, task_id, advance=1):
        self.progress.update(task_id, advance=advance)
        self.stats["requests"] += advance

    def add_vulnerability(self, severity, module, target, details):
        color_map = {
            "Critical": "bold red blink",
            "High": "red",
            "Medium": "yellow",
            "Low": "blue",
            "Info": "dim cyan"
        }
        style = color_map.get(severity, "white")
        self.vuln_table.add_row(
            f"[{style}]{severity}[/{style}]",
            module,
            target,
            details
        )
        # Sauvegarde pour le rapport final
        self.findings.append({
            "severity": severity,
            "module": module,
            "target": target,
            "details": details
        })
        self.stats["vulns"] += 1
        self.live.update(self.generate_layout())