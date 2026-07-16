#!/usr/bin/env python3
"""
RToolkit Kali-Pro v1.0 — Deep Kali Linux Scanner
Mengintegrasikan tools Kali Linux untuk scanning dan enumeration mendalam:
nuclei, dirsearch, ffuf, paramspider, whatweb, nmap, subfinder, httpx, sqlmap, nikto

Output: Tabel hasil scanning + payload exploit untuk setiap kerentanan
"""

import os, sys, json, subprocess, tempfile, datetime, re, shutil, time, signal
from pathlib import Path
from urllib.parse import urlparse, quote

# Colors
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; C = "\033[96m"
M = "\033[95m"; W = "\033[97m"; N = "\033[0m"; DIM = "\033[2m"; BOLD = "\033[1m"

RESULTS_DIR = Path("kali_results")
REPORT = {
    "target": "", "timestamp": "",
    "technologies": [],
    "directories": [],
    "parameters": [],
    "vulnerabilities": [],   # {url, name, severity, detail, exploit_cmd}
    "open_ports": [],
    "subdomains": [],
    "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
}

SEVERITY_COLORS = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": B, "INFO": C}

def c(text, color):
    return f"{color}{text}{N}"

def banner():
    os.system('clear')
    print(f"""{R}
╔══════════════════════════════════════════════════════════════╗
║{W}  ██████╗ ████████╗ ██████╗  ██████╗ ██╗  ██╗██╗     ██╗████████╗{R} ║
║{W}  ██╔══██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║ ██╔╝██║     ██║╚══██╔══╝{R} ║
║{W}  ██████╔╝   ██║   ██║   ██║██║   ██║█████╔╝ ██║     ██║   ██║   {R} ║
║{W}  ██╔══██╗   ██║   ██║   ██║██║   ██║██╔═██╗ ██║     ██║   ██║   {R} ║
║{W}  ██║  ██║   ██║   ╚██████╔╝╚██████╔╝██║  ██╗███████╗██║   ██║   {R} ║
║{W}  ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝   {R} ║
║{Y}     Kali-Pro v1.0 — nuclei | dirsearch | ffuf | paramspider | nmap{R} ║
╚══════════════════════════════════════════════════════════════╝{N}""")

def check_tools():
    """Check which Kali tools are installed."""
    tools = {
        "nuclei": False, "dirsearch": False, "ffuf": False, "whatweb": False,
        "nmap": False, "subfinder": False, "httpx": False, "nikto": False,
        "sqlmap": False, "paramspider": False, "gobuster": False, "wpscan": False,
    }
    print(f"\n  {c('[+] Checking Kali Tools', G)}")
    for tool in tools:
        path = shutil.which(tool)
        available = path is not None
        tools[tool] = available
        icon = c("✓", G) if available else c("✗", R)
        print(f"    {icon} {tool}")
    return tools

def run_cmd(cmd, timeout=120, desc=""):
    """Run a shell command and return (stdout, stderr, success)."""
    if desc:
        print(f"  {c(f'→ {desc}', C)}")
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return proc.stdout, proc.stderr, proc.returncode == 0
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", False
    except Exception as e:
        return "", str(e), False

def print_table(headers, rows, title=None, color=C):
    """Print formatted table."""
    if not rows:
        return
    col_widths = [len(h) + 2 for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            clean = re.sub(r'\x1b\[[0-9;]*m', '', str(cell))
            col_widths[i] = max(col_widths[i], len(clean) + 2)
    sep = '+' + '+'.join('─' * w for w in col_widths) + '+'
    if title:
        print(f"\n  {c(title, color)}")
    print(f"  {c(sep, DIM)}")
    hdr = ' │ '.join(h.center(col_widths[i]) for i, h in enumerate(headers))
    print(f"  {c('│', DIM)} {hdr} {c('│', DIM)}")
    print(f"  {c(sep, DIM)}")
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            cell_s = str(cell)
            clean = re.sub(r'\x1b\[[0-9;]*m', '', cell_s)
            pad = col_widths[i] - len(clean) - 2
            cells.append(cell_s + ' ' * pad)
        print(f"  {c('│', DIM)} {' │ '.join(cells)} {c('│', DIM)}")
    print(f"  {c(sep, DIM)}")

# ============ PHASE 1: RECONNAISSANCE ============

def phase_recon(domain):
    print(f"\n{c('='*65, Y)}")
    print(f"  {c('PHASE 1: RECONNAISSANCE', BOLD)}")
    print(f"{c('='*65, Y)}")

    target_ip = ""
    try:
        import socket
        target_ip = socket.gethostbyname(domain)
        print(f"\n  {c('[+] Target IP:', G)} {c(target_ip, W)}")
    except:
        print(f"  {c('[!] Could not resolve domain', R)}")

    # 1a. nmap port scan
    tools_available = check_tools()
    if tools_available["nmap"]:
        print(f"\n  {c('[+] Nmap Port Scan', G)}")
        stdout, _, ok = run_cmd(
            f"nmap -sS -sV -T4 --top-ports 100 --open -oN {RESULTS_DIR}/nmap.txt {domain}",
            300, "nmap SYN scan on top 100 ports"
        )
        if ok and stdout:
            ports = []
            for line in stdout.split('\n'):
                m = re.search(r'^(\d+)/tcp\s+open\s+(\S+)', line)
                if m:
                    port_num = m.group(1)
                    service = m.group(2)
                    ports.append([c(port_num, W), c(service, G)])
                    REPORT["open_ports"].append(f"{port_num}/tcp ({service})")
            if ports:
                print_table(["Port", "Service"], ports, "[OPEN PORTS]")
            # Save full output
            with open(f"{RESULTS_DIR}/nmap.txt", 'w') as f:
                f.write(stdout)
    else:
        print(f"  {c('  ✗ nmap not installed, skipping port scan', R)}")

    # 1b. whatweb tech detection
    if tools_available["whatweb"]:
        print(f"\n  {c('[+] WhatWeb Technology Detection', G)}")
        stdout, _, ok = run_cmd(
            f"whatweb -a 3 --log-json={RESULTS_DIR}/whatweb.json {domain}",
            120, "whatweb technology fingerprinting"
        )
        if ok and stdout:
            techs = []
            for line in stdout.split('\n'):
                line = line.strip()
                if line and '[' in line:
                    techs.append([c(line[:100], W), c(line[100:120] if len(line) > 100 else "", DIM)])
                    # Parse technologies
                    for t in re.findall(r'(\w[\w+]*)\[([^\]]+)\]', line):
                        REPORT["technologies"].append(f"{t[0]}: {t[1]}")
            if not techs:
                techs.append([c(stdout.strip()[:120], W), ""])
            print_table(["Fingerprint", ""], techs, "[TECHNOLOGIES]")
    else:
        print(f"  {c('  ✗ whatweb not installed', R)}")

    # 1c. subdomain discovery
    if tools_available["subfinder"]:
        print(f"\n  {c('[+] Subfinder Subdomain Discovery', G)}")
        stdout, _, ok = run_cmd(
            f"subfinder -d {domain} -silent -o {RESULTS_DIR}/subdomains.txt",
            120, "subfinder passive subdomain enum"
        )
        if ok and stdout:
            subs = stdout.strip().split('\n')
            sub_table = []
            for s in subs[:30]:
                s = s.strip()
                if s:
                    sub_table.append([c(s, W)])
                    REPORT["subdomains"].append(s)
            if sub_table:
                print_table(["Subdomain"], sub_table, f"[SUBDOAINS ({len(subs)} found, showing 30)]")

    # 1d. httpx probing
    if tools_available["httpx"] and REPORT["subdomains"]:
        print(f"\n  {c('[+] Httpx HTTP Probing', G)}")
        stdout, _, ok = run_cmd(
            f"httpx -l {RESULTS_DIR}/subdomains.txt -silent -status-code -title -o {RESULTS_DIR}/httpx.txt",
            120, "httpx probing live subdomains"
        )
        if ok and stdout:
            live = []
            for line in stdout.strip().split('\n'):
                parts = line.split()
                if parts:
                    live.append([c(parts[0][:60], G) if '200' in line else c(parts[0][:60], Y), " ".join(parts[1:])[:60]])
            if live:
                print_table(["URL", "Info"], live, "[LIVE HOSTS]")

    return tools_available


# ============ PHASE 2: DIRECTORY ENUMERATION ============

def phase_directories(domain, tools):
    print(f"\n{c('='*65, Y)}")
    print(f"  {c('PHASE 2: DIRECTORY & FILE ENUMERATION', BOLD)}")
    print(f"{c('='*65, Y)}")

    url = f"https://{domain}"

    # 2a. dirsearch
    if tools.get("dirsearch"):
        print(f"\n  {c('[+] Dirsearch Web Path Discovery', G)}")
        stdout, _, ok = run_cmd(
            f"dirsearch -u {url} -w /usr/share/wordlists/dirb/common.txt "
            f"-e php,asp,aspx,txt,conf,db,sql,bak,zip,tar,log,json -t 50 "
            f"--format plain -o {RESULTS_DIR}/dirsearch.txt 2>/dev/null",
            300, "dirsearch directory bruteforce"
        )
        if stdout:
            dirs = []
            seen_urls = set()
            for line in stdout.split('\n'):
                if any(s in line.lower() for s in ['200', '301', '302', '401', '403', '500']):
                    parts = line.strip().split()
                    if parts:
                        u = parts[-1]
                        status = parts[-2] if len(parts) >= 2 else ""
                        if u and u not in seen_urls:
                            seen_urls.add(u)
                            sz = len(u)
                            sc = G if status in ['200', '301', '302'] else Y
                            dirs.append([c(status, sc), c(u[:80], W)])
                            REPORT["directories"].append({"url": u, "status": status})
            if dirs:
                print_table(["Status", "URL"], dirs[:25], f"[DIRS FOUND ({len(dirs)} total, showing 25)]")

    # 2b. ffuf for deeper paths
    if tools.get("ffuf"):
        print(f"\n  {c('[+] Ffuf Deep Content Discovery', G)}")
        stdout, _, ok = run_cmd(
            f"ffuf -u {url}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt "
            f"-t 80 -c -o {RESULTS_DIR}/ffuf.json -of json -s 2>/dev/null",
            300, "ffuf FUZZ on medium wordlist"
        )
        # Parse ffuf JSON output
        ffuf_file = RESULTS_DIR / "ffuf.json"
        if ffuf_file.exists():
            try:
                data = json.loads(ffuf_file.read_text())
                ffuf_results = []
                for r in data.get("results", []):
                    status = r.get("status", 0)
                    if status in [200, 301, 302, 401, 403]:
                        ffuf_results.append([c(str(status), G if status in [200, 301, 302] else Y),
                                            c(r.get("url", "")[:80], W)])
                        REPORT["directories"].append({"url": r.get("url", ""), "status": status})
                if ffuf_results:
                    print_table(["Status", "URL"], ffuf_results[:20], f"[FFUF PATHS ({len(ffuf_results)} total, showing 20)]")
            except: pass

    # 2c. gobuster (fallback)
    if tools.get("gobuster") and not tools.get("dirsearch"):
        print(f"\n  {c('[+] Gobuster Directory Bruteforce', G)}")
        stdout, _, ok = run_cmd(
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt "
            f"-t 50 -l -o {RESULTS_DIR}/gobuster.txt 2>/dev/null",
            300, "gobuster directory bruteforce"
        )
        if stdout:
            dirs = []
            for line in stdout.split('\n'):
                m = re.search(r'^/(\S+)\s+\(Status:\s*(\d+)\)', line)
                if m:
                    path = "/" + m.group(1)
                    status = m.group(2)
                    sc = G if status in ['200', '301', '302'] else Y
                    dirs.append([c(status, sc), c(f"{url}{path}", W)])
                    REPORT["directories"].append({"url": f"{url}{path}", "status": int(status)})
            if dirs:
                print_table(["Status", "URL"], dirs[:25], f"[GOBUSTER ({len(dirs)} found, showing 25)]")


# ============ PHASE 3: PARAMETER DISCOVERY ============

def phase_parameters(domain, tools):
    print(f"\n{c('='*65, Y)}")
    print(f"  {c('PHASE 3: PARAMETER DISCOVERY', BOLD)}")
    print(f"{c('='*65, Y)}")

    url = f"https://{domain}"

    # 3a. paramspider
    if tools.get("paramspider"):
        print(f"\n  {c('[+] ParamSpider Parameter Discovery', G)}")
        stdout, _, ok = run_cmd(
            f"paramspider -d {domain} --level high -o {RESULTS_DIR}/params.txt 2>/dev/null",
            180, "paramspider crawling for parameters"
        )
        params_file = RESULTS_DIR / "params.txt"
        if params_file.exists():
            content = params_file.read_text()
            params = []
            seen = set()
            for line in content.split('\n'):
                line = line.strip()
                if line and line not in seen:
                    seen.add(line)
                    params.append([c(line[:100], W)])
                    # Extract parameter names
                    parsed = urlparse(line)
                    if parsed.query:
                        for param in parsed.query.split('&'):
                            pname = param.split('=')[0]
                            if pname not in REPORT["parameters"]:
                                REPORT["parameters"].append(pname)
            if params:
                print_table(["URL with Parameters"], params[:20], f"[PARAMS ({len(params)} found, showing 20)]")

    # 3b. ffuf parameter fuzzing
    if tools.get("ffuf"):
        print(f"\n  {c('[+] Ffuf Parameter Fuzzing', G)}")
        # Try common params on main page
        common_params = ["id", "page", "q", "s", "search", "cat", "file", "load",
                        "action", "do", "exec", "cmd", "template", "include", "path"]
        found_params = []
        for p in common_params[:10]:
            stdout, _, _ = run_cmd(
                f"ffuf -u '{url}?{p}=FUZZ' -w /usr/share/wordlists/dirb/common.txt "
                f"-t 50 -c -s -mr 'error|warning|notice|sql|exception|stack' 2>/dev/null",
                120, f"fuzzing parameter: {p}"
            )
            if stdout and len(stdout.strip()) > 0:
                found_params.append([c(p, G), c("Reflected/Error detected", R)])
                if p not in REPORT["parameters"]:
                    REPORT["parameters"].append(p)
        if found_params:
            print_table(["Parameter", "Finding"], found_params, "[POTENTIALLY VULNERABLE PARAMS]")


# ============ PHASE 4: VULNERABILITY SCANNING ============

def phase_vuln_scan(domain, tools):
    print(f"\n{c('='*65, Y)}")
    print(f"  {c('PHASE 4: VULNERABILITY SCANNING', BOLD)}")
    print(f"{c('='*65, Y)}")

    url = f"https://{domain}"

    # 4a. nuclei scan
    if tools.get("nuclei"):
        print(f"\n  {c('[+] Nuclei Vulnerability Scanner', G)}")

        # Critical/High severity templates first
        for severity, label in [("critical", "CRITICAL"), ("high", "HIGH"), ("medium", "MEDIUM")]:
            print(f"\n  {c(f'  Scanning for {label.upper()} vulnerabilities...', C)}")
            stdout, _, ok = run_cmd(
                f"nuclei -u {url} -severity {severity} -silent -json -o {RESULTS_DIR}/nuclei_{severity}.json 2>/dev/null",
                300, f"nuclei {label} severity templates"
            )
            # Parse JSON output
            nuc_file = RESULTS_DIR / f"nuclei_{severity}.json"
            if nuc_file.exists():
                findings = nuc_file.read_text().strip().split('\n')
                vuln_table = []
                for line in findings:
                    try:
                        data = json.loads(line)
                        vuln_url = data.get("matched-at", data.get("url", ""))
                        vuln_name = data.get("info", {}).get("name", "Unknown")
                        sev = data.get("info", {}).get("severity", "medium").upper()
                        ext_ref = data.get("info", {}).get("reference", "")
                        curl_cmd = f"curl -s '{vuln_url}'"

                        # Build exploit payload
                        exploit = f"# Exploit: {vuln_name}\n{curl_cmd}"
                        if ext_ref:
                            exploit += f"\n# Reference: {ext_ref}"

                        color = SEVERITY_COLORS.get(sev, W)
                        vuln_table.append([
                            c(vuln_name[:50], color),
                            c(sev, color),
                            c(vuln_url[:70], W),
                            c(exploit[:80], DIM)
                        ])
                        REPORT["vulnerabilities"].append({
                            "url": vuln_url, "name": vuln_name,
                            "severity": sev, "detail": data,
                            "exploit_cmd": curl_cmd
                        })
                    except:
                        pass
                if vuln_table:
                    print_table(["Vulnerability", "Severity", "URL", "Exploit/Ref"], vuln_table,
                               f"[NUCLEI {label.upper()} FINDINGS]")

        # Run all-severity scan too
        print(f"\n  {c('  Full nuclei scan (all templates)...', C)}")
        stdout, _, ok = run_cmd(
            f"nuclei -u {url} -silent -json -o {RESULTS_DIR}/nuclei_all.json 2>/dev/null",
            300, "nuclei all severity scan"
        )
        nuc_all = RESULTS_DIR / "nuclei_all.json"
        if nuc_all.exists():
            findings = nuc_all.read_text().strip().split('\n')
            for line in findings:
                try:
                    data = json.loads(line)
                    sev = data.get("info", {}).get("severity", "info").upper()
                    vuln_url = data.get("matched-at", data.get("url", ""))
                    vuln_name = data.get("info", {}).get("name", "Unknown")

                    # Deduplicate
                    existing = [v for v in REPORT["vulnerabilities"] if v["url"] == vuln_url and v["name"] == vuln_name]
                    if not existing:
                        REPORT["vulnerabilities"].append({
                            "url": vuln_url, "name": vuln_name,
                            "severity": sev, "detail": data,
                            "exploit_cmd": f"curl -s '{vuln_url}'"
                        })
                except:
                    pass

    # 4b. nikto scan
    if tools.get("nikto"):
        print(f"\n  {c('[+] Nikto Web Server Scan', G)}")
        stdout, _, ok = run_cmd(
            f"nikto -h {url} -Format json -output {RESULTS_DIR}/nikto.json 2>/dev/null",
            300, "nikto web server vulnerability scan"
        )
        nikto_file = RESULTS_DIR / "nikto.json"
        if nikto_file.exists():
            try:
                data = json.loads(nikto_file.read_text())
                nikto_items = []
                for item in data if isinstance(data, list) else data.get("items", []):
                    if isinstance(item, dict):
                        vuln_url = item.get("url", url)
                        vuln_msg = item.get("message", item.get("description", ""))
                        nikto_items.append([c(vuln_msg[:60], Y), c(vuln_url[:80], W), c("MANUAL", DIM)])
                        REPORT["vulnerabilities"].append({
                            "url": vuln_url, "name": vuln_msg[:80],
                            "severity": "MEDIUM", "detail": vuln_msg,
                            "exploit_cmd": f"# Manual check required\ncurl -v '{vuln_url}'"
                        })
                if nikto_items:
                    print_table(["Finding", "URL", "Exploit"], nikto_items[:15], "[NIKTO FINDINGS]")
            except: pass

    # 4c. Check .env, .git, config files
    print(f"\n  {c('[+] Critical File Exposure Check', G)}")
    sensitive_paths = [
        "/.env", "/.git/config", "/.git/HEAD", "/admin/.env", "/backup/.env",
        "/phpinfo.php", "/info.php", "/wp-content/debug.log", "/wp-config.php.bak",
        "/config.php", "/database.yml", "/dump.sql", "/backup.sql", "/.htaccess",
        "/server-status", "/.aws/credentials", "/.azure/access.json",
        "/.gitlab-ci.yml", "/Jenkinsfile", "/Dockerfile", "/docker-compose.yml",
        "/terraform.tfstate", "/s3.yml", "/.s3cfg", "/storage/logs/laravel.log",
    ]
    import requests, urllib3
    urllib3.disable_warnings()
    exposed = []
    for path in sensitive_paths:
        try:
            r = requests.get(f"{url}{path}", timeout=3, verify=False, allow_redirects=False,
                           headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code in [200, 401, 403]:
                body_lower = r.text.lower()
                # Skip WAF block pages
                if "request rejected" in body_lower and len(r.text) < 500:
                    continue
                exposed.append([
                    c("EXPOSED", R) if r.status_code == 200 else c("RESTRICTED", Y),
                    c(path, W),
                    c(str(r.status_code), G if r.status_code == 200 else Y),
                    c(f"{len(r.text)}B", DIM)
                ])
                sev = "CRITICAL" if r.status_code == 200 else "HIGH"
                REPORT["vulnerabilities"].append({
                    "url": f"{url}{path}", "name": f"Sensitive File: {path}",
                    "severity": sev, "detail": f"HTTP {r.status_code}, {len(r.text)} bytes",
                    "exploit_cmd": f"curl -s '{url}{path}'"
                })
        except: pass
    if exposed:
        print_table(["Status", "Path", "HTTP", "Size"], exposed, "[SENSITIVE FILE EXPOSURE]")

    # 4d. wpscan (if WordPress detected)
    has_wp = any("WordPress" in t for t in REPORT["technologies"])
    if tools.get("wpscan") and has_wp:
        print(f"\n  {c('[+] WPScan WordPress Vulnerability Scan', G)}")
        stdout, _, ok = run_cmd(
            f"wpscan --url {url} --no-update --format json -o {RESULTS_DIR}/wpscan.json 2>/dev/null",
            300, "wpscan WordPress vulnerability scan"
        )
        wpscan_file = RESULTS_DIR / "wpscan.json"
        if wpscan_file.exists():
            try:
                data = json.loads(wpscan_file.read_text())
                wp_vulns = []
                for vuln_type in ["vulnerabilities", "plugin_vulnerabilities", "theme_vulnerabilities"]:
                    for v in data.get(vuln_type, []):
                        if isinstance(v, dict):
                            vuln_name = v.get("title", v.get("name", "Unknown"))
                            fixed_in = v.get("fixed_in", "N/A")
                            wp_vulns.append([
                                c(vuln_name[:55], R),
                                c(f"Fixed: {fixed_in}" if fixed_in != "N/A" else "No fix", Y),
                                c("wpscan --url URL --plugins-detection aggressive", DIM)
                            ])
                            REPORT["vulnerabilities"].append({
                                "url": url, "name": f"WP: {vuln_name}",
                                "severity": "HIGH", "detail": f"Fixed in: {fixed_in}",
                                "exploit_cmd": f"# {vuln_name}\n# Fixed in: {fixed_in}"
                            })
                if wp_vulns:
                    print_table(["Vulnerability", "Details", "Remediation"], wp_vulns[:10], "[WP VULNS]")
            except: pass

    # 4e. SQLMap (if SQLi suspected)
    sql_params = [p for p in REPORT["parameters"] if p.lower() in ["id", "page", "q", "s", "search", "cat", "file", "load", "action", "exec", "cmd"]]
    if tools.get("sqlmap") and sql_params:
        print(f"\n  {c('[+] SQLMap Injection Test', G)}")
        for p in sql_params[:3]:
            print(f"    Testing param: {c(p, W)}")
            stdout, _, ok = run_cmd(
                f"sqlmap -u '{url}?{p}=1' --batch --level 2 --risk 1 "
                f"--output-dir={RESULTS_DIR}/sqlmap 2>/dev/null",
                180, f"sqlmap testing parameter: {p}"
            )
            if stdout and ("vulnerable" in stdout.lower() or "identified" in stdout.lower()):
                # Extract injection details
                for line in stdout.split('\n'):
                    if "Parameter:" in line and "GET" in line:
                        REPORT["vulnerabilities"].append({
                            "url": f"{url}?{p}=1", "name": f"SQL Injection ({p})",
                            "severity": "CRITICAL",
                            "detail": line.strip(),
                            "exploit_cmd": f"sqlmap -u '{url}?{p}=1' --batch --dbs"
                        })
                        print(f"    {c(f'  ⚡ SQLi FOUND on param: {p}!', R)}")
                        sqli_url = f"{url}?{p}=1"
                        print(f"    {c(f'  → sqlmap -u {sqli_url} --dbs', Y)}")


# ============ PHASE 5: REPORTING ============

def generate_summary():
    print(f"\n{c('='*65, Y)}")
    print(f"  {c('PHASE 5: EXPLOITATION & SUMMARY', BOLD)}")
    print(f"{c('='*65, Y)}")

    # Count severities
    for v in REPORT["vulnerabilities"]:
        s = v.get("severity", "INFO").upper()
        if s in REPORT["summary"]:
            REPORT["summary"][s] += 1
        REPORT["summary"]["total"] += 1

    # Summary stats
    vulns = REPORT["vulnerabilities"]
    total = len(vulns)
    crit = REPORT["summary"]["critical"]
    high = REPORT["summary"]["high"]
    med = REPORT["summary"]["medium"]
    low = REPORT["summary"]["low"]
    info = REPORT["summary"]["info"]

    print(f"""\n  {c('╔════════════════════════════════════════════════════╗', Y)}
  {c('║', Y)}  {c('📊 SCAN SUMMARY', BOLD)}                          {c('║', Y)}
  {c('╠════════════════════════════════════════════════════╣', Y)}
  {c('║', Y)}  Target:    {c(REPORT['target'], W)}                    {c('║', Y)}
  {c('║', Y)}  Total:     {c(str(total), W)} vulns {' ' * (25-len(str(total)))} {c('║', Y)}
  {c('║', Y)}  Critical:  {c(str(crit), R)}                             {c('║', Y)}
  {c('║', Y)}  High:      {c(str(high), R)}                             {c('║', Y)}
  {c('║', Y)}  Medium:    {c(str(med), Y)}                             {c('║', Y)}
  {c('║', Y)}  Low:       {c(str(low), B)}                             {c('║', Y)}
  {c('╚════════════════════════════════════════════════════╝', Y)}""")

    # Show exploitation table for ALL findings
    if vulns:
        print(f"\n  {c('[⚡] EXPLOITATION PAYLOADS', R)}{c(' — Kirim ke URL yang rentan', Y)}")
        print(f"  {c('─'*65, DIM)}")

        # Group by severity
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_vulns = [v for v in vulns if v.get("severity", "INFO").upper() == sev]
            if not sev_vulns:
                continue
            color = SEVERITY_COLORS.get(sev, W)
            exploit_rows = []
            for v in sev_vulns:
                vuln_url = v.get("url", "")
                vuln_name = v.get("name", "Unknown")
                exploit = v.get("exploit_cmd", "# No exploit available")
                exploit_rows.append([
                    c(vuln_name[:45], color),
                    c(vuln_url[:60], W),
                    c(exploit[:60], DIM)
                ])
            print_table(["Vulnerability", "Vulnerable URL", "Exploit Command"],
                       exploit_rows, f"[{sev} EXPLOITS]")

    # Direct curl commands for each finding
    print(f"\n  {c('[⚡] DIRECT CURL EXPLOIT COMMANDS', R)}")
    print(f"  {c('─'*65, DIM)}")
    for v in vulns[:10]:
        sev = v.get("severity", "INFO").upper()
        color = SEVERITY_COLORS.get(sev, W)
        if sev in ["CRITICAL", "HIGH"]:
            vname = v.get("name", "Unknown")[:55]
            vurl = v.get("url", "")
            vcmd = v.get("exploit_cmd", "N/A")[:100]
            print(f"  {c(f'[{sev}]', color)} {c(vname, W)}")
            print(f"        {c('URL:', DIM)} {c(vurl, G)}")
            print(f"        {c('CMD:', DIM)} {c(vcmd, Y)}")
            print()

    # Save JSON report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = RESULTS_DIR / f"kali_report_{REPORT['target'].replace('.', '_')}_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(REPORT, f, indent=2, default=str)
    print(f"\n  {c(f'📄 JSON Report: {json_file}', G)}")


# ============ MAIN ============

def main():
    banner()
    RESULTS_DIR.mkdir(exist_ok=True)

    target = input(f"\n  {c('Target (domain or URL)', C)}: ").strip()
    if not target:
        return

    # Clean target
    domain = target.replace('https://', '').replace('http://', '').split('/')[0].split('?')[0]
    REPORT["target"] = domain
    REPORT["timestamp"] = datetime.datetime.now().isoformat()

    print(f"\n  {c(f'Target: {domain}', W)}")
    print(f"  {c(f'Results dir: {RESULTS_DIR}', DIM)}")

    tools = phase_recon(domain)
    phase_directories(domain, tools)
    phase_parameters(domain, tools)
    phase_vuln_scan(domain, tools)
    generate_summary()

    print(f"\n  {c('✅ Scan complete!', G)}")
    print(f"  {c(f'Results saved to {RESULTS_DIR}/', DIM)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('[!] Interrupted by user', Y)}")
        sys.exit(0)
    except Exception as e:
        print(f"\n  {c(f'[!] Error: {e}', R)}")
        import traceback; traceback.print_exc()
        sys.exit(1)
