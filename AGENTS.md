# AGENTS.md — RedTeam-Tools Repository Instructions

## Repository Overview
A red team toolkit with two main entrypoints:
- **`rtoolkit.py`** — Pure-Python toolkit (5 phases: Recon, Vuln Scan, Exploitation, Post-Exploitation, Reporting). No external binaries required.
- **`rtoolkit-kali.py`** — Kali Linux wrapper that calls installed binaries (nuclei, dirsearch, ffuf, subfinder, httpx, nmap, nikto, sqlmap, arjun, x8, endpoints-extractor, whatweb, gobuster, wpscan, paramspider).

Also includes: `gen_cve.py` (generates `cve_data.json`), `README.md` (150+ tool reference), `CLAUDE.md`.

## Running the Tools

### rtoolkit.py (Pure Python)
```bash
# Kali/Debian (system packages — avoids PEP 668 venv issues)
sudo apt install python3-requests python3-colorama python3-urllib3 python3-whois python3-requests-html python3-publicsuffixlist
python rtoolkit.py

# Or with venv (if not using --system-site-packages)
python3 -m venv venv && source venv/bin/activate
python -m pip install -r requirements.txt
python rtoolkit.py
```
Interactive menu: enter target domain → choose phase (1-6, where 6 = Run All).

### rtoolkit-kali.py (Kali Binary Wrapper)
```bash
# Requires Kali tools installed:
# nuclei, dirsearch, ffuf, subfinder, httpx, nmap, nikto, sqlmap, arjun, x8, whatweb, gobuster, wpscan, paramspider, endpoints-extractor
python rtoolkit-kali.py
```
Prompts for target domain, runs all 5 phases automatically, outputs to `kali_results/`.

### gen_cve.py
```bash
python gen_cve.py  # Regenerates cve_data.json (embedded in rtoolkit.py)
```

## Key Constraints & Gotchas
- **Kali PEP 668**: System Python blocks `pip install`. Use `apt install python3-<pkg>` or a clean venv (`python3 -m venv venv --without-pip` not needed; default venv works if not created with `--system-site-packages`).
- **rtoolkit-kali.py** fails silently if binaries missing — check output for `✗` marks.
- **No test/lint/build pipeline** — this is a documentation + script repo.
- **External tool versions matter**: nuclei templates, sqlmap options, wordlist paths (`/usr/share/wordlists/...`) assume standard Kali layout.

## File Purposes
| File | Purpose |
|------|---------|
| `rtoolkit-kali.py` | **MASTER tool** — semua fitur: recon, port scan, banner grab, CVE match, dir bruteforce, SQLi, nuclei/nikto/wp scan, DB exploit, reverse shell, reporting. Auto-detect Kali binaries, fallback pure Python. |
| `rtoolkit.py` | Lightweight pure-Python alternative (portable, no binaries needed) |
| `gen_cve.py` | Builds `cve_data.json` for version→CVE mapping |
| `cve_data.json` | CVE database (476 entries across 10 software types) |
| `README.md` | 150+ tool reference by MITRE ATT&CK phase |
| `requirements.txt` | Python deps for rtoolkit.py |
| `CLAUDE.md` | Repo docs for Claude Code |

## Common Tasks
- **Add tool to README**: Edit `README.md` table of contents + tool section; keep `[🔙](#tool-list)` anchors.
- **Update CVE data**: Edit `gen_cve.py` dict → run `python gen_cve.py`.
- **Fix Kali tool paths**: Update wordlist paths in `rtoolkit-kali.py` if not on standard Kali.
- **Run single phase**: In `rtoolkit.py`, call `run_recon(target)` etc. directly from REPL.

## Environment Notes
- `rtoolkit.py` works offline for most phases (uses crt.sh, socket, stdlib).
- `rtoolkit-kali.py` requires internet for nuclei template updates, subfinder sources.
- Both write JSON reports to `kali_results/` or print to stdout.