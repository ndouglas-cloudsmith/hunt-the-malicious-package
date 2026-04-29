import json
import subprocess
import requests
import gzip
import shutil
import os
import sys
import csv
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

# --- Threat Intelligence Sources ---
CSV_FILE = "epss_scores-current.csv"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Exploit-DB official index
EDB_URL = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
EDB_FILE = "exploitdb_index.csv"
OSV_API = "https://api.osv.dev/v1/vulns/"

class SBOMEnricher:
    def __init__(self):
        self.kev_ids = set()
        self.epss_data = {}
        self.exploit_map = {}

    def update_feeds(self):
        console.print("[bold blue][*] Updating Security Feeds...[/bold blue]")
        
        # 1. Update KEV
        try:
            r = requests.get(KEV_URL)
            self.kev_ids = {v['cveID'] for v in r.json().get('vulnerabilities', [])}
            console.print("[green]✔[/green] KEV updated.")
        except: console.print("[red]✘[/red] KEV update failed.")

        # 2. Update ExploitDB (New)
        try:
            r = requests.get(EDB_URL)
            with open(EDB_FILE, 'wb') as f:
                f.write(r.content)
            # Build a map of CVE -> Exploit Title
            with open(EDB_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    codes = row.get('codes', '')
                    if "CVE-" in codes:
                        for cve in codes.split(";"):
                            if cve.startswith("CVE-"):
                                self.exploit_map[cve.strip()] = row.get('description', 'Exploit Available')
            console.print("[green]✔[/green] ExploitDB index updated.")
        except Exception as e:
            console.print(f"[red]✘[/red] ExploitDB update failed: {e}")

        # 3. Update EPSS
        if not os.path.exists(CSV_FILE):
            try:
                r = requests.get(EPSS_URL)
                with open("epss.gz", 'wb') as f: f.write(r.content)
                with gzip.open("epss.gz", 'rb') as f_in, open(CSV_FILE, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove("epss.gz")
            except: pass

        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, 'r') as f:
                for line in f:
                    if line.startswith("CVE-"):
                        p = line.split(",")
                        self.epss_data[p[0]] = (p[1], p[2].strip())

    def get_osv_details(self, vuln_id):
        try:
            r = requests.get(f"{OSV_API}{vuln_id}", timeout=3)
            return r.json().get('summary', 'N/A') if r.status_code == 200 else "N/A"
        except: return "N/A"

    def run_grype(self, target):
        result = subprocess.run(["grype", target, "-o", "json"], capture_output=True, text=True)
        return json.loads(result.stdout)

    def enrich_and_display(self, grype_data):
        matches = grype_data.get('matches', [])
        table = Table(title="Enriched SBOM (Grype + KEV + EPSS + ExploitDB)")

        table.add_column("CVE ID", style="cyan")
        table.add_column("Package", style="magenta")
        table.add_column("Severity", style="bold")
        table.add_column("EPSS %", justify="right")
        table.add_column("ExploitDB", justify="center")
        table.add_column("KEV", justify="center")
        table.add_column("OSV Summary", ratio=1)

        vuln_ids = [m['vulnerability']['id'] for m in matches]
        
        with Progress() as progress:
            task = progress.add_task("[green]Processing...", total=len(matches))
            with ThreadPoolExecutor(max_workers=10) as executor:
                osv_summaries = list(executor.map(self.get_osv_details, vuln_ids))

            for i, match in enumerate(matches):
                v = match['vulnerability']
                cve = v['id']
                
                # ExploitDB Lookup
                has_exploit = "[bold red]YES[/bold red]" if cve in self.exploit_map else "[grey]no[/grey]"
                is_kev = "[bold red]YES[/bold red]" if cve in self.kev_ids else "[grey]no[/grey]"

                # EPSS Formatting
                epss_val, _ = self.epss_data.get(cve, ("0.0", ""))
                epss_p = float(epss_val) * 100
                epss_color = "red" if epss_p > 10 else "white"

                table.add_row(
                    cve,
                    match['artifact']['name'],
                    v['severity'],
                    f"[{epss_color}]{epss_p:.2f}%[/{epss_color}]",
                    has_exploit,
                    is_kev,
                    osv_summaries[i]
                )
                progress.update(task, advance=1)

        console.print(table)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sbom-enricher.py <image>")
        sys.exit(1)

    en = SBOMEnricher()
    en.update_feeds()
    data = en.run_grype(sys.argv[1])
    en.enrich_and_display(data)
