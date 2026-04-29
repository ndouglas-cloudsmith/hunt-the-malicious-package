# Hunt The Malicious Package
Lab for findings malicious packages in SBOM and lockfiles using OSV API

Getting familiar with Open Source Vulnerabilities (OSV)
===============

OSV provides an easy-to-use API for querying all known vulnerabilities by either a ```commit hash```, or a ```package version```. This first command shows you the output when querying via ```commit hash```.
```
curl -d \
  '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
  "https://api.osv.dev/v1/query"  | jq .
```

For our purposes, we're going to interact with this API via the ```package versioning```. This approach provides some flexibility as you don't need to know specific commit hash values. For example, let's look for ```jinja2``` packages in the ```PyPI``` ecosystem:
```
curl -d \
  '{"version": "2.4.1",
    "package": {"name": "jinja2", "ecosystem": "PyPI"}}' \
  "https://api.osv.dev/v1/query"  | jq .
```

While OSV was designed initially for understanding vulnerabilities in open-source software dependencies sourced from upstream ecosystems like ```PyPI``` and ```npm```, you'll find out in the next section that this API also  extends to the ```malicious packages``` project maintained by the **[OpenSSF](https://openssf.org/blog/2023/10/12/introducing-openssfs-malicious-packages-repository)**.


Finding Malicious Packages using OSV API
===============

To find malicious packages using the **[OSV API](https://google.github.io/osv.dev/api)** (```api.osv.dev```), we need to query a package ```name```, ```version``` and ```ecosystem``` in which the open-source package exists.
<br/><br/>
For example, let's look at the ```npm``` package called ```supplychain-firewall-benchmark-hello```. The output should map it to a **MALICIOUS** package identifier - **[MAL-2025-48401](https://osv.dev/vulnerability/MAL-2025-48401)**
```
curl -s -d \
  '{"version": "1.10.2",
    "package": {"name": "supplychain-firewall-benchmark-hello", "ecosystem": "npm"}}' \
  "https://api.osv.dev/v1/query" | jq .
```
It's worth pointing out that the malicious package advisory should link back to a Github-hosted database of malicious package reports like this: <br/>
https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/supplychain-firewall-benchmark-hello/MAL-2025-48401.json
<br/><br/>

In March 2026, there was a significant supply chain compromise on the ```npm``` package **[axios](https://cloudsmith.com/blog/axios-npm-attack-response)** on versions ```1.4.1``` and ```0.30.4```.
<br/><br/>
If a vulnerability affects multiple versions of the same package, you want to scan multiple package names and versions at the same time. To do this use the **[querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)** API endpoint.

```
curl -s -d \
  '{"queries": [
    {"version": "1.4.1", "package": {"name": "axios", "ecosystem": "npm"}},
    {"version": "0.30.4", "package": {"name": "axios", "ecosystem": "npm"}}
  ]}' \
  "https://api.osv.dev/v1/querybatch" | jq .
```
In this case, the output provides multiple GitHub Security Advisories (**[GHSAs](https://github.com/advisories)**) for the packages in question.  You can ```curl``` any one of the individual GHSA links from the output to get deeper insight into why OSV flagged that package. The following command demonstrates this:
```
curl -s "https://api.osv.dev/v1/vulns/GHSA-43fc-jf86-j433" | jq .
```

While scanning generically for a package name works, if you run the command below you'll notice that the API returns a load of ```vulnerability``` noise as well as  the ```malware``` related findings.
```
curl -s -d \
  '{"package": {"name": "axios", "ecosystem": "npm"}}' \
  "https://api.osv.dev/v1/query" | jq .
```

If you want to inspect the malware insights *only*, you can use **[jq](https://jqlang.org)** to filter the JSON output to only provide responses starting with ```MAL-```. The command below demonstrates this.
```
curl -s -d   '{"package": {"name": "axios", "ecosystem": "npm"}}'   "https://api.osv.dev/v1/query" | \
  jq '.vulns[] | select(.id | startswith("MAL-"))'
```

By now you should have a decent understanding of how to use to OSV.dev API. In the next section, we will automate the usage of this API to scan for malicious dependencies in running workloads.


Deploying a workload in Kubernetes
===============

Here we have a virtual machine running a Kubernetes cluster. We should already have a few pods running in it. You can check using the command below:
```
kubectl get pods -A -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,IMAGES:.spec.containers[*].image'
```

Now that we know everything is up and running, we are going to introduce a new, lightweight Python workload into our cluster:
```
kubectl apply -f https://raw.githubusercontent.com/ndouglas-cloudsmith/exploit-check/refs/heads/main/python-deployment.yaml
kubectl get pods --show-labels -w
```

Once deployed, let's move on to the next section.


Creating malicious software dependencies in pods
===============

By exporting the pod label to an environmental variable called ```APP_LABEL```, we can make changes to pods in the default namespace with that label.
```
APP_LABEL="app=python-app"
```

The ```pip list``` command allows us to list the Python dependencies in the container.  **[pip](https://pypi.org/project/pip)** is the package installer for Python. You can use pip to install packages from the Python Package Index and other indexes.
```
kubectl get pods -l $APP_LABEL -o name | xargs -I{} kubectl exec {} -- pip list
```

Rather than actually downloading known, dangerous malware via ```pip install```, we can just create the fake (dummy) malware inside our running container:
```
kubectl get pods -l $APP_LABEL -o name | xargs -I{} kubectl exec {} -- mkdir -p /usr/local/lib/python3.11/site-packages/reuests-71.71.72.dist-info
kubectl get pods -l $APP_LABEL -o name | xargs -I{} kubectl exec {} -- sh -c "echo 'Metadata-Version: 2.1\nName: reuests\nVersion: 71.71.72' > /usr/local/lib/python3.11/site-packages/reuests-71.71.72.dist-info/METADATA"
kubectl get pods -l $APP_LABEL -o name | xargs -I{} kubectl exec {} -- sh -c "echo 'reuests' > /usr/local/lib/python3.11/site-packages/reuests-71.71.72.dist-info/top_level.txt"
kubectl get pods -l $APP_LABEL -o name | xargs -I{} kubectl exec {} -- pip list | grep --color=always -E 'reuests|71\.71\.72|$'
```

The dependency added ```reuests``` is clearly an example of a **[typosquatted](https://cloudsmith.com/blog/typosquatting-the-ghcr-registry)** software package. <br/>

In some cases a developer will make typographical errors - accidentally dropping a letter from a legitimate package name like ```requests```. <br/>

In this scenario, adversaries upload similarly-titled package software dependency names to open-source upstreams like **[PyPI](https://pypi.org/search/?q=reuests)** in the hope that an organization unintentionally downloads the malicious package.

Scanning for malware in running workloads
===============

We can use the **OSV.dev** (OpenSSF Malicious Packages included) API in an automated script.
```
wget https://raw.githubusercontent.com/ndouglas-cloudsmith/exploit-check/refs/heads/main/osv-kubernetes.py
```

You can of course read the below script. It's open-source and publicly-accessible on Nigel's Github. <br/>
Can you see where the legitimate ```requests``` package is imported and used within this script?
```
cat osv-kubernetes.py | grep --color=always -E 'requests|"https://api.osv.dev/v1/vulns/\{vuln_id\}"|$'
```

Once you are ready to test it out, run the command below to scan all pods specifically in the ```default``` network namespace:
```
python3 osv-kubernetes.py --namespace default
```

Congrats! You should have found the typosquatted malware dependency classified under **MAL-2022-7441** in your running pod. <br/>
The sensible next step would be to delete the pod deployment, and make sure our container build is not referencing any known-to-be-bad open-source dependencies.
```
kubectl delete -f https://raw.githubusercontent.com/ndouglas-cloudsmith/exploit-check/refs/heads/main/python-deployment.yaml
```

Getting familar with OSV-Scanner
===============

We will need to use **[Golang](https://go.dev/)** to install ```osv-scanner```. Make sure it's already installed:
```
go version
```

**[OSV‑Scanner](https://google.github.io/osv-scanner)** provides an officially supported frontend to the OSV database that connects a project’s list of dependencies with the vulnerabilities, and indicators of malicious intent, that affect them. To install OSV-Scanner, use the following command:
```
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2
```

See if the ```osv-scanner``` was successfully installed:
```
osv-scanner --version
```

Downloading a sample ```requirements.txt``` file:
```
wget https://raw.githubusercontent.com/ndouglas-cloudsmith/malicious-package-policy/refs/heads/main/osv-api/requirements.txt
```

Scan a local file or directory recursively. In this case, we're going to scan the ```requirements.txt``` file, using the following command:
```
osv-scanner -r requirements.txt
```

Looking at the output table in this scenario, osv-scanner should have found **MALWARE** classified under [MAL-2026-2144](https://osv.dev/MAL-2026-2144) for the software dependency ```litellm==1.82.7``` in the Python ```requirements.txt``` file:
```
cat requirements.txt | grep --color=always -E "litellm==[^ ]*|$"
```

Generate an SBOM with Syft and scan it with OSV
===============

Since we are already working with Python, we can use **[Syft](https://github.com/anchore/syft)** to scan your directory and produce a standard format like **[CycloneDX](https://cyclonedx.org)** or **[SPDX](https://spdx.dev)**. You can install Syft with a one-line command:

```
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

We already started working with the requirements.txt file in the last section. Now let's generate a simple **SBOM** on that requirements.txt file. Use the following command to initiate that process in Syft:
```
syft packages requirements.txt -o cyclonedx-json=sbom.cdx.json
osv-scanner -L sbom.cdx.json
```

You can read the JSON file with ```cat```, but, as you will see, this isn't particularly easy to read:
```
cat sbom.cdx.json
```

Instead, let's use **jq** to pretty-print the output in proper JSON formatting. Now that SBOM file becomes much clearer and understandable:
```
jq . sbom.cdx.json
```

You'll probably notice from the output that this Software Bill of Materials is in **CycloneDX** format with software dependencies (properties) being grouped into **components**, such as ```files``` and ```libraries```.

Scanning Lockfiles with OSV-Scanner
===============

These apps are now available
    - ```pip-compile```
    - ```pip-sync```
    
```
pipx install pip-tools
```

Download a sample ```requirements.in``` file
```
wget https://raw.githubusercontent.com/ndouglas-cloudsmith/hunt-the-malicious-package/refs/heads/main/requirements.in
```

Compile to a Lockfile
```
pip-compile requirements.in --output-file requirements.txt.lock
```

Scan ```Lockfile```
```
mv requirements.txt.lock requirements-lock.txt
osv-scanner -L requirements-lock.txt
```

So in short, only works for ```JSON``` or ```TXT``` formats:
```
osv-scanner --lockfile=package-lock.json
```

License Analysis with OSV-Scanner
===============

Check your dependencies' licenses using ```deps.dev``` data. For a summary:
```
osv-scanner --licenses .
```
To check everything in the local directory against an allowed license list (```SPDX``` format):
```
osv-scanner --licenses="MIT,Apache-2.0" .
```

pip-audit is informed by OSV metadata
===============

There are community tools that use OSV. <br/>
https://google.github.io/osv.dev/third-party/#third-party-tools

```
pip-audit --desc -f json 2>/dev/null | jq '.dependencies[] | select(.vulns | length > 0) | {name, version, vulnerabilities: [.vulns[] | {id, fix: .fix_versions[0]}]}'
```

SBOM threat intelligence enrichment
===============

Create a directory and test out the script in this folder:
```
mkdir sbom-enrichment
cd sbom-enrichment
```

Download the ```sbom enrichment``` script. This python script will scan a container image, generate the SBOM, and enrich the vulnerability intelligence data:
```
wget https://raw.githubusercontent.com/ndouglas-cloudsmith/hunt-the-malicious-package/refs/heads/main/sbom-enricher.py
```

The script requires two specific python dependencies - other than the obvious ```grype``` scanner for SBOM generation
```
python3 -m pip install requests rich --break-system-packages
```

Generate an SBOM natively in ```CycloneDX``` format using ```Grype```:
```
grype alpine:latest -o cyclonedx-json > sbom.json
```

Enrich the SBOM findings for the same **container image** name - **[alpine:latest](https://hub.docker.com/_/alpine)**
```
python3 sbom-enricher.py alpine:latest
```

Cleanup script:
```
rm -v -- exploitdb_exploits.csv epss_scores-current.csv epss_scores-current.csv.gz known_exploited_vulnerabilities.json && kubectl delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.13/deploy/gatekeeper.yaml
```
