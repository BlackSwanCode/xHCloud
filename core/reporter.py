import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict

class ReportGenerator:
    def __init__(self, findings: List[Dict], target_info: str):
        self.findings = findings
        self.target_info = target_info

    def generate_html(self, output_path: str = "xhcloud_report.html"):
        """Génère un rapport HTML élégant et coloré."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            severity_counts[f.get("severity", "Info")] += 1

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>xHCloud - Rapport d'Audit Cloud</title>
    <style>
        :root {{ --bg: #1e1e2e; --text: #cdd6f4; --crit: #f38ba8; --high: #fab387; --med: #f9e2af; --low: #89b4fa; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }}
        .header {{ text-align: center; padding: 20px; border-bottom: 2px solid #313244; margin-bottom: 20px; }}
        .stats {{ display: flex; justify-content: center; gap: 20px; margin: 20px 0; }}
        .stat-box {{ padding: 15px 30px; border-radius: 8px; font-weight: bold; font-size: 1.2em; }}
        .crit {{ background: rgba(243, 139, 168, 0.2); color: var(--crit); border: 1px solid var(--crit); }}
        .high {{ background: rgba(250, 179, 135, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .med {{ background: rgba(249, 226, 175, 0.2); color: var(--med); border: 1px solid var(--med); }}
        .low {{ background: rgba(137, 180, 250, 0.2); color: var(--low); border: 1px solid var(--low); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #181825; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #313244; }}
        th {{ background: #313244; color: #cba6f7; }}
        .sev-crit {{ color: var(--crit); font-weight: bold; }}
        .sev-high {{ color: var(--high); font-weight: bold; }}
        .sev-med {{ color: var(--med); }}
        .sev-low {{ color: var(--low); }}
    </style>
</head>
<body>
    <div class="header">
        <h1>☁️ xHCloud Security Report</h1>
        <p>Cible : <strong>{self.target_info}</strong> | Date : {datetime.now().strftime('%d/%m/%Y à %H:%M')}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box crit">Critical: {severity_counts['Critical']}</div>
        <div class="stat-box high">High: {severity_counts['High']}</div>
        <div class="stat-box med">Medium: {severity_counts['Medium']}</div>
        <div class="stat-box low">Low: {severity_counts['Low']}</div>
    </div>

    <table>
        <thead>
            <tr><th>Sévérité</th><th>Module</th><th>Cible</th><th>Détails</th></tr>
        </thead>
        <tbody>
"""
        # Tri des findings par sévérité
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.get("severity", "Info"), 5))

        for f in sorted_findings:
            sev_class = f"sev-{f.get('severity', 'Info').lower()}"
            html += f"""
            <tr>
                <td class="{sev_class}">{f.get('severity', 'Info')}</td>
                <td>{f.get('module', 'Unknown')}</td>
                <td style="font-family: monospace; font-size: 0.9em;">{f.get('target', 'N/A')}</td>
                <td>{f.get('details', 'N/A')}</td>
            </tr>"""
        
        html += """
        </tbody>
    </table>
</body>
</html>"""
        
        Path(output_path).write_text(html, encoding="utf-8")
        return output_path

    def generate_json(self, output_path: str = "xhcloud_report.json"):
        """Génère un rapport JSON pour l'ingestion dans d'autres outils (SIEM, etc.)."""
        data = {
            "target": self.target_info,
            "timestamp": datetime.now().isoformat(),
            "findings": self.findings
        }
        Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        return output_path
