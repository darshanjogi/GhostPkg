import requests
import re
import urllib.parse
import argparse

def print_banner():
    print("\n🕵️ GhostPkg – Dependency Confusion Scanner\n")

# ----------------- CONFIG -----------------
GITHUB_TOKEN = "ghp_***************************"  # Replace with your github token
PAGES = 2  # How many GitHub pages to scan
# ------------------------------------------

HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}
NPM_URL = "https://registry.npmjs.org/{}"
PYPI_URL = "https://pypi.org/pypi/{}/json"
GOMOD_URL = "https://proxy.golang.org/{}/@v/list"

def github_search_packages(org, query, pages=2, per_page=50):
    found = set()
    print(f"[+] GitHub search: {query}")
    for page in range(1, pages + 1):
        url = f"https://api.github.com/search/code?q={query}&per_page={per_page}&page={page}"
        res = requests.get(url, headers=HEADERS)
        if res.status_code != 200:
            print("[-] GitHub API error:", res.status_code, res.text)
            break
        results = res.json().get("items", [])
        for item in results:
            raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            try:
                content = requests.get(raw_url).text
                found.update(re.findall(r"(?:require|from|import)\s*['\"]([^'\"]+)['\"]", content))
                found.update(re.findall(r"(?:import|from)\s+([a-zA-Z0-9_\.]+)", content))
                found.update(re.findall(r'import\s+["`]([^"`]+)["`]', content))
            except:
                continue
    return list(set(found))

def check_npm(pkg):
    encoded = urllib.parse.quote(pkg, safe='@/')
    r = requests.get(NPM_URL.format(encoded))
    return r.status_code == 404, pkg

def check_pypi(pkg):
    name = pkg.replace(".", "-").replace("_", "-").lower()
    r = requests.get(PYPI_URL.format(name))
    return r.status_code == 404, name

def check_gomod(pkg):
    encoded = urllib.parse.quote(pkg, safe='/')
    r = requests.get(GOMOD_URL.format(encoded))
    return r.status_code == 404, pkg

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Dependency Confusion Scanner")
    parser.add_argument("--org", required=True, help="GitHub organization name")
    parser.add_argument("--output", help="Output file to save vulnerable packages")
    args = parser.parse_args()
    ORG = args.org
    out = []

    npm_query = f'org:{ORG} in:file language:JavaScript'
    pypi_query = f'org:{ORG} in:file language:Python'
    go_query = f'org:{ORG} in:file language:Go'

    npm_pkgs = github_search_packages(ORG, npm_query, pages=PAGES)
    pypi_pkgs = github_search_packages(ORG, pypi_query, pages=PAGES)
    go_pkgs = github_search_packages(ORG, go_query, pages=PAGES)

    print("\n--- NPM CHECK ---")
    for pkg in npm_pkgs:
        if "/" in pkg or "." in pkg:
            vuln, name = check_npm(pkg)
            line = f"[{'!!' if vuln else 'OK'}] {name} {'not found' if vuln else 'exists'} on NPM"
            print(line)
            if vuln: out.append(f"NPM: {name}")

    print("\n--- PYPI CHECK ---")
    for pkg in pypi_pkgs:
        if "." in pkg or "_" in pkg:
            vuln, name = check_pypi(pkg)
            line = f"[{'!!' if vuln else 'OK'}] {name} {'not found' if vuln else 'exists'} on PyPI"
            print(line)
            if vuln: out.append(f"PYPI: {name}")

    print("\n--- GO MODULE CHECK ---")
    for pkg in go_pkgs:
        if "." in pkg or "/" in pkg:
            vuln, name = check_gomod(pkg)
            line = f"[{'!!' if vuln else 'OK'}] {name} {'not found' if vuln else 'exists'} on proxy.golang.org"
            print(line)
            if vuln: out.append(f"GO: {name}")

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(out))
        print(f"\n[+] Vulnerable packages saved to {args.output}")

if __name__ == "__main__":
    main()
