# AGENTS.md — RedTeam-Tools Repository Instructions

## Repository Overview
Red team toolkit with two main entrypoints targeting different environments:

| Tool | Lines | Functions | Approach |
|------|-------|-----------|----------|
| **`rtoolkit-kali.py`** | ~2192 | 54 | **MASTER**: Kali binary wrapper + pure Python fallbacks. Linear 6-phase pipeline with CLI args support. |
| **`rtoolkit.py`** | ~1704 | 37 | **Lightweight**: Pure-Python only. Interactive menu (choose phase 1-6). Portable, no binaries needed. |
| `gen_cve.py` | ~200 | 1 | Generates `cve_data.json` (476 CVEs across 10 software types) |
| `cve_data.json` | — | — | CVE database: apache, nginx, iis, php, mysql, postgresql, openssh, wordpress, joomla, drupal |

## rtoolkit-kali.py — Full Details

### CLI Arguments (v4.0+)
```bash
python rtoolkit-kali.py -t example.com                    # scan target
python rtoolkit-kali.py -t example.com -p 1 3 5           # run only phases 1, 3, 5
python rtoolkit-kali.py -t example.com --quick            # skip deep scans
python rtoolkit-kali.py -t example.com --json             # JSON report only (no HTML)
python rtoolkit-kali.py -t example.com --silent           # suppress all stdout
python rtoolkit-kali.py                                   # interactive mode (prompt)
```

### Pipeline Phases

| Phase | Sub-Phase | What It Does | Tool/Module |
|-------|-----------|-------------|-------------|
| **1a** | Nmap Deep | SYN scan + service version + default scripts (top 1000 ports) | `nmap` / pure Python |
| **1a** | Nmap Extra | OS detection + `--script vuln` + traceroute (top 2000 ports) | `nmap` |
| **1b** | Banner Grab | HTTP/SSH/PgSQL/MySQL protocol probes + version extraction + CVE matching | `probe_http/ssh/pgsql/mysql` |
| **1c** | Subdomain Enum | Passive enumeration + crt.sh + DNS resolution | `subfinder`, `crt.sh`, `subdomain_enum()` |
| **1d** | Live Host Probe | HTTP/HTTPS probe + katana crawling + whatweb tech detection | `httpx`, `katana`, `whatweb` |
| **1e** | TLS Version Check | SSL/TLS handshake per version, flags TLSv1.0/1.1 as HIGH | `check_tls_versions()` |
| **1c** | Deep Tech Detection | CMS (WP/Joomla/Drupal), JS frameworks (React/Vue/Angular), cookies, CDN, WP plugins/themes, HTTP security headers (score X/9) + enhanced CVE matching | `detect_tech_version()`, `match_cves_enhanced()` |
| **1d** | Cascading Scan | TCP port scan + tech detection on each subdomain (up to 5) | `port_scan()`, `detect_tech_version()` |
| **2a** | Directory Discovery | Directory bruteforce | `dirsearch`, `ffuf`, `gobuster` |
| **2b** | Deep Dir Bruteforce | Recursive 2-level bruteforce (300+ paths) + HTML link crawling | `dir_bruteforce()` |
| **2** | Parameter Discovery | Parameter extraction from HTML forms, URL query strings | `arjun`, `x8`, `paramspider`, `param_extract()` |
| **3a** | Nuclei Scan | CVE template scanning (CRITICAL/HIGH/MEDIUM) | `nuclei` |
| **3b** | Nikto Scan | Web server misconfiguration scanning | `nikto` |
| **3c** | Sensitive File Check | Checks 60+ sensitive paths (`.env`, `.git/config`, `wp-config.php`, etc.) with **auto WAF bypass** trigger | `requests` + `fetch_sensitive_with_bypass()` |
| **3d** | SQLi Detection | Time-based + error-based (5 DB types: MySQL/MSSQL/Oracle/PostgreSQL/SQLite) + `sqlmap` | `sqli_detect()`, `sqlmap` |
| **3e** | WPScan | WordPress vulnerability scanning (auto-detected via tech/URL) | `wpscan` |
| **4** | Database Exploit | PostgreSQL/MySQL/MSSQL credential brute-force + command execution | `probe_pgsql/mysql`, socket |
| **5** | Exploit | Reverse shell commands (nc, bash, python, php, perl, ruby, socat, powershell) + DB exploit commands | template engine |
| **6** | Reporting | Summary stats + HTML report (with Remediation recommendations + SQLi section) + JSON report | |

### Pure Python Features (no binary required)
- `dns_lookup(domain)` — A/MX/NS/TXT/CNAME records
- `subdomain_enum(domain)` — 150+ wordlist bruteforce via `socket.gethostbyname`
- `param_extract(url)` — HTML form + URL query param extraction
- `sqli_detect(url)` — Time-based (SLEEP/pg_sleep/WAITFOR) + error-based patterns for 5 DBs
- `detect_tech_version(url)` — CMS, JS framework, cookies, CDN, WP plugins/themes
- `match_cves_enhanced(techs)` — CVE matching with 23 WP plugin CVEs
- `dir_bruteforce(url)` — Recursive 2-level dir bruteforce (300+ paths)
- `fetch_sensitive_with_bypass(url, path)` — 30+ WAF bypass techniques (raw sockets)
- `check_tls_versions(host)` — SSL/TLS handshake per version
- `check_http_security_headers(url)` — 9 security headers with score

### Config File (`~/.rtoolkit/config.json`)
Auto-created on first run:
```json
{
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
  "nmap_full_scan": false
}
```

### Output Files (in `kali_results/`)
| File Pattern | Content |
|-------------|---------|
| `nmap_deep_{domain}.txt` | Deep port scan (service+script) |
| `nmap_extra_{domain}.txt` | Extra scan (OS+vuln scripts) |
| `subdomains.txt` | Raw subdomain list |
| `httpx.txt` | Live host probe results |
| `whatweb.json` | WhatWeb tech detection |
| `dirsearch_{domain}.txt` | Directory enumeration |
| `katana.txt` | Katana endpoint crawl |
| `nuclei_{protocol}_{domain}.txt` | Nuclei findings |
| `nikto_{domain}.txt` | Nikto findings |
| `sqlmap_{domain}/` | SQLMap session directory |
| `RToolkit_Report_{domain}_{ts}.html` | HTML report (vulns + CVEs + SQLi + Remediation) |
| `RToolkit_Report_{domain}_{ts}.json` | JSON report |

### Environment Protection
- Auto-detects tmux (`check_tmux()`) — warns if not in tmux session
- Checks SSH keepalive (`check_ssh_keepalive()`) — recommends `fix-ssh-dc.sh`
- Uses `run_cmd_stream()` for real-time SSH-safe output on long commands
- **colorama** auto-detected with fallback to raw ANSI codes

### Key Constraints & Gotchas
- **Kali PEP 668**: System Python blocks `pip install`. Use `apt install python3-<pkg>` or a clean venv.
- **Missing binaries** show `✗` in tool check line (tool continues with fallbacks)
- **External tool versions matter**: nuclei templates, sqlmap options, wordlist paths assume standard Kali layout.
- **Nmap extra scan** (`--script vuln`) can be slow on targets with many ports
- **Chain scanning**: all phases are sequential; use `-p` to skip phases and `--quick` to skip deep scans

## rtoolkit.py — Pure Python Details

### Interactive Menu
```
╔═══════════════════════════╗
║   RToolkit v2.0           ║
╚═══════════════════════════╝
1. Reconnaissance & Mapping
2. Vulnerability Scanning
3. Exploitation
4. Post-Exploitation
5. Reporting
6. Run All Phases (1-5)
0. Exit
```

### Feature Comparison

| Feature | rtoolkit.py | rtoolkit-kali.py |
|---------|:-----------:|:----------------:|
| Binary tools (nmap/sqlmap/nuclei) | ✗ | ✓ (14 tools) |
| Pure Python port scan | ✓ | ✓ |
| Interactive menu | ✓ | ✗ (CLI args only) |
| CLI arguments | ✗ | ✓ (`-t -p --quick --json`) |
| Streaming output | ✗ | ✓ |
| Concurrent phases | ✗ | ✓ (nmap + subdomain) |
| Config file | ✗ | ✓ |
| tmux/SSH protection | ✗ | ✓ |
| Colorama cross-platform | ✓ | ✓ |
| Timer decorator | ✗ | ✓ |
| Database exploitation | ✗ | ✓ (PgSQL/MySQL/MSSQL) |
| Reverse shell commands | ✓ | ✓ |
| WAF bypass (30+ techs) | ✓ | ✓ |
| Deep tech detection | ✓ | ✓ |
| Enhanced SQLi (5 DBs) | ✓ | ✓ |
| Dir bruteforce (recursive) | ✓ | ✓ |
| Subdomain cascade scan | ✓ | ✓ |
| DNS lookup | ✓ | ✓ |
| HTTP security headers | ✓ | ✓ |
| TLS version check | ✗ | ✓ |
| HTML report with remediation | ✓ | ✓ |
| WP plugin CVE mapping | 23 plugins | 23 plugins |
| SSL/TLS version check | ✗ | ✓ |
| Katana crawling | ✗ | ✓ |

## Common Tasks
- **Add tool to README**: Edit `README.md` table of contents + tool section; keep `[🔙](#tool-list)` anchors.
- **Update CVE data**: Edit `gen_cve.py` dict → run `python gen_cve.py`.
- **Fix Kali tool paths**: Update wordlist paths in `~/.rtoolkit/config.json`.
- **Run single phase**: `python rtoolkit-kali.py -t example.com -p 3`.
- **Fix SSH disconnect**: Run `bash fix-ssh-dc.sh` or use `tmux new -s redteam`.
- **Skip deep scans**: `python rtoolkit-kali.py -t example.com --quick`.

## Environment Notes
- `rtoolkit.py` works offline for most phases (uses crt.sh, socket, stdlib).
- `rtoolkit-kali.py` requires internet for nuclei template updates, subfinder sources, crt.sh.
- Both write JSON/HTML reports to current directory.
- `colorama` in `requirements.txt` is optional — both tools work without it (fallback to ANSI codes).
- `fix-ssh-dc.sh` fixes: disable sleep/suspend, SSH keepalive client+server+kernel, WiFi power saving, creates `rtoolkit-tmux` launcher.
