import json
import subprocess
import requests
import gzip
import shutil
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

# --- Threat Intelligence Sources ---
CSV_FILE = "epss_scores-current.csv"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API = "https://api.osv.dev/v1/vulns/"

class SBOMEnricher:
    def __init__(self):
        self.kev_ids = set()
        self.epss_data = {}

    def update_feeds(self):
        """Downloads and prepares KEV and EPSS data."""
        console.print("[bold blue][*] Updating Security Feeds...[/bold blue]")
        
        # Update KEV
        try:
            r = requests.get(KEV_URL)
            data = r.json()
            self.kev_ids = {v['cveID'] for v in data.get('vulnerabilities', [])}
            console.print("[green]✔[/green] KEV data updated.")
        except Exception as e:
            console.print(f"[red]✘[/red] Failed to update KEV: {e}")

        # Update EPSS (Local CSV cache)
        if not os.path.exists(CSV_FILE):
            console.print("[yellow][*] Downloading EPSS scores (this may take a moment)...[/yellow]")
            try:
                with requests.get(EPSS_URL, stream=True) as r:
                    with open("epss.gz", 'wb') as f:
                        shutil.copyfileobj(r.raw, f)
                with gzip.open("epss.gz", 'rb') as f_in:
                    with open(CSV_FILE, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.remove("epss.gz")
            except Exception as e:
                console.print(f"[red]✘[/red] Failed to update EPSS: {e}")

        # Load EPSS into memory for fast lookup
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, 'r') as f:
                for line in f:
                    if line.startswith("CVE-"):
                        parts = line.split(",")
                        # CVE, EPSS, Percentile
                        self.epss_data[parts[0]] = (parts[1], parts[2].strip())

    def get_osv_details(self, vuln_id):
        """Fetch summary from OSV.dev"""
        try:
            r = requests.get(f"{OSV_API}{vuln_id}", timeout=5)
            if r.status_code == 200:
                return r.json().get('summary', 'No summary available')
        except:
            pass
        return "N/A"

    def run_grype(self, target):
        """Runs Grype and returns the JSON matches."""
        console.print(f"[bold blue][*] Running Grype scan on:[/bold blue] {target}")
        result = subprocess.run(
            ["grype", target, "-o", "json"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            console.print("[bold red]Error running Grype. Is it installed?[/bold red]")
            sys.exit(1)
        return json.loads(result.stdout)

    def enrich_and_display(self, grype_data):
        matches = grype_data.get('matches', [])
        table = Table(title="Enriched SBOM (Grype + KEV + EPSS + OSV)")

        table.add_column("CVE ID", style="cyan", no_wrap=True)
        table.add_column("Package", style="magenta")
        table.add_column("Severity", style="bold")
        table.add_column("EPSS %", justify="right")
        table.add_column("KEV", justify="center")
        table.add_column("OSV Summary", ratio=1)

        # We use a ThreadPool to fetch OSV summaries in parallel
        vuln_ids = [m['vulnerability']['id'] for m in matches]
        
        with Progress() as progress:
            task = progress.add_task("[green]Enriching data...", total=len(matches))
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                osv_summaries = list(executor.map(self.get_osv_details, vuln_ids))

            for i, match in enumerate(matches):
                v = match['vulnerability']
                cve = v['id']
                pkg = match['artifact']['name']
                severity = v['severity']
                
                # Severity Color Logic
                sev_map = {"Critical": "[bold red]CRITICAL[/bold red]", "High": "[bold orange3]HIGH[/bold orange3]", "Medium": "[yellow]MEDIUM[/yellow]"}
                sev_display = sev_map.get(severity, severity)

                # KEV Logic
                is_kev = "[bold red]YES[/bold red]" if cve in self.kev_ids else "[grey]no[/grey]"

                # EPSS Logic
                epss_val, _ = self.epss_data.get(cve, ("0.0", ""))
                epss_percent = float(epss_val) * 100
                epss_display = f"{epss_percent:.2f}%"
                if epss_percent > 10:
                    epss_display = f"[bold red]{epss_display}[/bold red]"

                table.add_row(
                    cve,
                    pkg,
                    sev_display,
                    epss_display,
                    is_kev,
                    osv_summaries[i]
                )
                progress.update(task, advance=1)

        console.print(table)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[bold red]Usage: python enricher.py <image-name>[/bold red]")
        sys.exit(1)

    target_image = sys.argv[1]
    enricher = SBOMEnricher()
    enricher.update_feeds()
    
    sbom = enricher.run_grype(target_image)
    enricher.enrich_and_display(sbom)
