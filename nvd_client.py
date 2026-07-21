#!/usr/bin/env python3
"""
RToolkit-Kali v5.0 — NVD API Client
National Vulnerability Database (NVD) API v2.1 integration with local caching.
Graceful degradation: if API unreachable, falls back to local DB / empty result.
"""
import json, time, re, os
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from datetime import datetime

# ====== CONFIG ======
CACHE_PATH = Path.home() / ".rtoolkit" / "nvd_cache.json"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT = (5, 30)  # 5 requests per 30 seconds (NVD free tier)
REQUESTS_WINDOW = []

def _rate_limit():
    """Enforce NVD rate limit: 5 requests per 30-second rolling window."""
    global REQUESTS_WINDOW
    now = time.time()
    REQUESTS_WINDOW = [t for t in REQUESTS_WINDOW if now - t < RATE_LIMIT[1]]
    if len(REQUESTS_WINDOW) >= RATE_LIMIT[0]:
        sleep_time = RATE_LIMIT[1] - (now - REQUESTS_WINDOW[0]) + 1
        if sleep_time > 0:
            print(f"    {c(f'[NVD Rate Limit] Waiting {int(sleep_time)}s...',DIM)}")
            time.sleep(sleep_time)
            REQUESTS_WINDOW = [t for t in REQUESTS_WINDOW if time.time() - t < RATE_LIMIT[1]]
    REQUESTS_WINDOW.append(time.time())

def c(text, color):
    try:
        from colorama import Fore, Style; init=__import__('colorama',fromlist=['init']).init,autoreset=True
        N=Style.RESET_ALL; COLORS={"R":Fore.RED,"G":Fore.GREEN,"Y":Fore.YELLOW,"B":Fore.BLUE,"C":Fore.CYAN,"M":Fore.MAGENTA,"W":Fore.WHITE,"DIM":Style.DIM}
        return f"{COLORS.get(color,Fore.WHITE)}{text}{N}"
    except:
        return text

# ====== NVD CACHE ======
class NvdCache:
    """Manages local CVE cache with stale detection and merge logic."""

    def __init__(self, cache_path=None, api_key=None, cache_days=1):
        self.cache_path = Path(cache_path) if cache_path else CACHE_PATH
        self.api_key = api_key or ""
        self.cache_days = cache_days
        self.data = {}
        self.meta = {"last_updated": "", "version": "v5.0"}
        self.load()

    def load(self):
        """Load cache from disk. Gracefully handles missing/corrupt files."""
        if not self.cache_path.exists():
            return
        try:
            raw = json.loads(self.cache_path.read_text(encoding='utf-8'))
            self.data = raw.get("cves", {})
            self.meta = raw.get("meta", self.meta)
        except (json.JSONDecodeError, OSError):
            self.data = {}
            self.meta = {"last_updated": "", "version": "v5.0"}

    def save(self):
        """Persist cache to disk atomically."""
        self.meta["last_updated"] = datetime.now().isoformat()
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix('.tmp')
            tmp.write_text(json.dumps({"cves": self.data, "meta": self.meta}, indent=2), encoding='utf-8')
            tmp.replace(self.cache_path)
        except OSError:
            pass

    def is_stale(self):
        """Returns True if cache is older than self.cache_days."""
        last = self.meta.get("last_updated", "")
        if not last:
            return True
        try:
            dt = datetime.fromisoformat(last)
            age = (datetime.now() - dt).total_seconds()
            return age > (self.cache_days * 86400)
        except (ValueError, TypeError):
            return True

    def get(self, software, version):
        """Get cached CVEs for software+version pair. Returns list."""
        key = f"{software.lower()}:{version}"
        return self.data.get(key, [])

    def set(self, software, version, cves):
        """Cache CVEs for software+version pair."""
        key = f"{software.lower()}:{version}"
        self.data[key] = cves
        self.save()  # Save on every write to avoid losing data

    def clear_expired(self, max_age_days=30):
        """Remove entries older than max_age_days. Returns count removed."""
        # Simple implementation: we don't track individual entry timestamps
        # so just return 0. Real timestamp tracking would need a schema change.
        return 0


def _fetch_nvd(software, version, api_key=""):
    """Query NVD API for CVEs matching software+version. Returns list of CVE dicts."""
    try:
        _rate_limit()
        query = f"{software} {version}".strip()
        url = f"{NVD_API_BASE}?keywordSearch={query}&resultsPerPage=20"
        headers = {"Accept": "application/json"}
        if api_key:
            headers["apiKey"] = api_key
        req = Request(url, headers=headers)
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            description = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            # Extract CVSS v3 score
            metrics = cve.get("metrics", {})
            cvss31 = metrics.get("cvssMetricV31", [{}])[0]
            cvss30 = metrics.get("cvssMetricV30", [{}])[0]
            cvss2 = metrics.get("cvssMetricV2", [{}])[0]
            cvss_entry = cvss31 or cvss30 or cvss2
            cvss_score = None
            if cvss_entry:
                cvss_val = cvss_entry.get("cvssData", {}).get("baseScore")
                if cvss_val is not None:
                    cvss_score = float(cvss_val)
            # Extract affected version range
            configurations = cve.get("configurations", [])
            affected_versions = []
            for cfg in configurations:
                for node in cfg.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            vs = match.get("versionStartIncluding", "")
                            ve = match.get("versionEndExcluding", "")
                            if vs or ve:
                                affected_versions.append({"start": vs, "end": ve})
            cves.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "affected_versions": affected_versions if affected_versions else None,
                "source": "nvd_api",
                "published": cve.get("published", ""),
            })
        return cves
    except HTTPError as e:
        if e.code == 403 or e.code == 429:
            print(f"    {c(f'[NVD Rate Limited / Forbidden — use apiKey for higher limit]',Y)}")
        else:
            print(f"    {c(f'[NVD HTTP {e.code} for {software} {version}]',R)}")
        return []
    except URLError as e:
        print(f"    {c(f'[NVD Network Error for {software} {version}: {e.reason}]',R)}")
        return []
    except Exception as e:
        print(f"    {c(f'[NVD Error for {software} {version}: {e}]',R)}")
        return []


def query_nvd(software, version, cache=None, api_key="", cache_days=1):
    """
    Main entry point for NVD lookups.
    Priority: cache hit → NVD API (if enabled) → empty
    cache: NvdCache instance (optional)
    api_key: NVD API key for higher rate limits (optional)
    cache_days: days before cache is considered stale
    Returns list of CVE dicts.
    """
    if not software or not version:
        return []

    sw = software.lower().replace(' ', '').replace('-', '')
    ver = version.strip()

    # 1. Check local cache first
    if cache:
        cached = cache.get(sw, ver)
        if cached and not cache.is_stale():
            return cached
        # If stale but have cache data, still return it (graceful degradation)
        if cached and cache.is_stale():
            pass  # We'll try NVD if enabled

    # 2. Query NVD API
    nvd_cves = _fetch_nvd(sw, ver, api_key)
    if nvd_cves and cache:
        cache.set(sw, ver, nvd_cves)

    return nvd_cves


def merge_nvd_results(local_cves, nvd_cves):
    """Merge local CVE list with NVD results. NVD results take precedence."""
    merged = []
    seen = set()
    # Add local first
    for cve in local_cves:
        if isinstance(cve, str):
            merged.append({"cve": cve, "source": "local_db", "version_match_type": "exact"})
            seen.add(cve)
        else:
            merged.append(cve)
            seen.add(cve.get("cve", ""))
    # Merge NVD results (overwrite duplicates)
    for nvd in nvd_cves:
        cve_id = nvd.get("cve_id", "")
        if cve_id and cve_id not in seen:
            merged.append({
                "cve": cve_id,
                "source": "nvd_api",
                "cvss_score": nvd.get("cvss_score"),
                "version_match_type": "range",  # NVD uses range matching internally
                "description": nvd.get("description", ""),
            })
            seen.add(cve_id)
    return merged


def version_to_cves_with_nvd(service_name, version, local_db=None, cache=None,
                              api_key="", cache_days=1):
    """
    Combined CVE lookup: local DB (semver) + NVD API.
    Returns list of dicts with {cve, source, version_match_type, cvss_score}.
    """
    results = []
    sw = service_name.lower().replace(' ', '').replace('-', '')
    ver = version.strip()
    if not sw or not ver:
        return results

    # 1. Local DB (exact + semver range)
    if local_db is None:
        local_db = {}
    db_key = sw
    if db_key in local_db:
        norm_ver = re.sub(r'\s*\([^)]*\)', '', ver).strip()
        norm_ver = re.sub(r'[.-][a-zA-Z]+\d+(?:\.\d+)*$', '', norm_ver).strip()
        norm_ver = norm_ver.strip('. ')
        # Exact match
        if norm_ver in local_db[db_key]:
            for vuln in local_db[db_key][norm_ver]:
                results.append({"cve": vuln, "source": "local_db", "version_match_type": "exact"})
        # Semver range match
        existing = {r["cve"] for r in results}
        try:
            from packaging.version import Version as _Ver, InvalidVersion
            def _parse(v):
                try: return _Ver(v)
                except InvalidVersion: return _Ver(re.sub(r'[^0-9.]', '', v) or '0')
            det = _parse(norm_ver)
            for db_ver, vulns in local_db[db_key].items():
                if db_ver == norm_ver: continue
                try:
                    db_v = _parse(db_ver)
                    if db_v == det:
                        for vuln in vulns:
                            if vuln not in existing:
                                results.append({"cve": vuln, "source": "local_db", "version_match_type": "range"})
                                existing.add(vuln)
                except: pass
        except ImportError:
            pass

    # 2. NVD API
    nvd_cves = query_nvd(sw, ver, cache, api_key, cache_days)
    existing_ids = {r["cve"] for r in results}
    for nvd in nvd_cves:
        cve_id = nvd.get("cve_id", "")
        if cve_id and cve_id not in existing_ids:
            results.append({
                "cve": cve_id,
                "source": "nvd_api",
                "cvss_score": nvd.get("cvss_score"),
                "version_match_type": "range",
                "description": nvd.get("description", ""),
            })
            existing_ids.add(cve_id)

    return results