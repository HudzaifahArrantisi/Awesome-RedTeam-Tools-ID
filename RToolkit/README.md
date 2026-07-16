# RToolkit - Unified Red Team Toolkit

🔥 Gabungan 150+ tools red team dari [RedTeam-Tools](https://github.com/A-poc/RedTeam-Tools) menjadi **1 tools** dengan 5 fase utama.

## Fitur

| Fase | Deskripsi |
|------|-----------|
| **🔍 Reconnaissance & Mapping** | DNS lookup, subdomain enum, port scanning, directory bruteforce, cert transparency, technology detection |
| **🛡️ Vulnerability Analysis** | SSL/TLS check, security headers, CORS misconfig, subdomain takeover, common web vulns |
| **💥 Exploitation** | Reverse shell generator (11 jenis), msfvenom commands, default cred checker |
| **🔧 Post-Exploitation & PrivEsc** | Windows & Linux privesc checklist, sensitive file finder, enum commands |
| **📄 Reporting** | HTML report interaktif, JSON report, severity summary, remediations |

## Instalasi

```bash
pip install -r requirements.txt
```

## Cara Pakai

```bash
python rtoolkit.py
```

Masukkan target domain/URL, lalu pilih menu:
- `1` - Reconnaissance
- `2` - Vulnerability Scan
- `3` - Exploitation
- `4` - Post-Exploitation
- `5` - Report
- `6` - **Run All** (Full pipeline)

## Tools yang diintegrasikan (dari RedTeam-Tools)

- **Recon**: spiderfoot, reconftw, subzy, crt.sh, gobuster, feroxbuster, dnsrecon, shodan, AORT, skanuvaty, gowitness
- **Vuln Scan**: nuclei, spoofcheck, Dismap
- **Exploit**: msfvenom, hydra, responder
- **Post-Exploit**: mimikatz, PEASS, Sherlock, Watson, BeRoot, PowerSploit
- **C2/Exfil**: empire, hoaxshell, dnscat2, cloakify

## Disclaimer

Untuk tujuan pendidikan dan authorized security testing saja.
