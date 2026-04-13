"""
IntelliPen - Smart Recon Engine
محرك الاستطلاع الذكي - يجمع معلومات شاملة عن الهدف
"""

import requests
import socket
import ssl
import json
import re
import time
import dns.resolver
import whois
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime
import concurrent.futures
import threading

# تجاهل تحذيرات SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

COMMON_DIRS = [
    "admin", "administrator", "login", "panel", "dashboard", "wp-admin",
    "phpmyadmin", "cpanel", "webmail", "mail", "api", "api/v1", "api/v2",
    "backup", "backups", "db", "database", "config", "configuration",
    "upload", "uploads", "files", "file", "images", "img", "assets",
    "js", "css", "includes", "inc", "lib", "library", "vendor",
    "test", "tests", "dev", "development", "staging", "old", "new",
    "robots.txt", "sitemap.xml", ".git", ".env", "web.config",
    "phpinfo.php", "info.php", "readme.txt", "README.md", "CHANGELOG.md",
    "wp-config.php", "config.php", "settings.php", "database.php",
    "install", "setup", "register", "signup", "user", "users",
    "account", "accounts", "profile", "profiles", "member", "members",
    "search", "contact", "about", "help", "support", "faq",
    "logout", "signout", "reset", "forgot", "password",
    "ajax", "xhr", "graphql", "rest", "soap", "wsdl",
    ".htaccess", ".htpasswd", "server-status", "server-info",
    "crossdomain.xml", "clientaccesspolicy.xml", "security.txt",
]

SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".env.backup",
    "config.json", "config.yaml", "config.yml", "settings.json",
    "database.yml", "database.json", "db.json",
    "wp-config.php", "config.php", "configuration.php",
    "web.config", "app.config", "appsettings.json",
    "id_rsa", "id_rsa.pub", "authorized_keys",
    "backup.sql", "backup.zip", "backup.tar.gz", "dump.sql",
    "phpinfo.php", "info.php", "test.php",
    "composer.json", "package.json", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".dockerignore",
    "Makefile", "Gruntfile.js", "Gulpfile.js",
    ".git/config", ".git/HEAD", ".svn/entries",
]

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "WordPress"],
    "Joomla": ["Joomla!", "/components/com_", "/modules/mod_"],
    "Drupal": ["Drupal", "/sites/default/", "drupal.js"],
    "Laravel": ["laravel_session", "XSRF-TOKEN", "Laravel"],
    "Django": ["csrfmiddlewaretoken", "django", "__django_"],
    "React": ["react", "ReactDOM", "__REACT_"],
    "Angular": ["ng-version", "angular", "ng-app"],
    "Vue.js": ["vue", "__vue__", "v-app"],
    "jQuery": ["jquery", "jQuery"],
    "Bootstrap": ["bootstrap", "Bootstrap"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "ASP.NET": ["X-Powered-By: ASP.NET", "ASP.NET", "__VIEWSTATE", "ASPNET"],
    "Node.js": ["X-Powered-By: Express", "node.js"],
    "Python/Flask": ["Werkzeug", "Flask"],
    "Ruby on Rails": ["X-Runtime", "X-Powered-By: Phusion Passenger"],
    "Apache": ["Apache", "Server: Apache"],
    "Nginx": ["nginx", "Server: nginx"],
    "IIS": ["Microsoft-IIS", "X-Powered-By: ASP.NET"],
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "MySQL": ["mysql", "MySQL"],
    "PostgreSQL": ["postgresql", "postgres"],
}


class ReconEngine:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url.rstrip("/")
        self.parsed = urlparse(target_url)
        self.domain = self.parsed.netloc
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.timeout = timeout
        self.results = {
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "ip_info": {},
            "whois_info": {},
            "dns_records": {},
            "ssl_info": {},
            "http_headers": {},
            "technologies": [],
            "directories": [],
            "sensitive_files": [],
            "links": [],
            "forms": [],
            "emails": [],
            "comments": [],
            "js_endpoints": [],
            "subdomains": [],
            "open_ports": [],
        }
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False

    def log(self, msg, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {msg}")

    def get_ip_info(self):
        """جمع معلومات IP"""
        try:
            self.log(f"Resolving IP for {self.domain}...")
            ip = socket.gethostbyname(self.domain)
            self.results["ip_info"]["ip"] = ip
            # جلب معلومات الموقع الجغرافي
            try:
                r = self.session.get(f"http://ip-api.com/json/{ip}", timeout=5)
                if r.status_code == 200:
                    geo = r.json()
                    self.results["ip_info"].update({
                        "country": geo.get("country", "Unknown"),
                        "city": geo.get("city", "Unknown"),
                        "isp": geo.get("isp", "Unknown"),
                        "org": geo.get("org", "Unknown"),
                        "lat": geo.get("lat", 0),
                        "lon": geo.get("lon", 0),
                    })
            except:
                pass
            self.log(f"IP: {ip}", "SUCCESS")
        except Exception as e:
            self.log(f"IP resolution failed: {e}", "ERROR")

    def get_whois(self):
        """جمع معلومات WHOIS"""
        try:
            self.log(f"Fetching WHOIS for {self.domain}...")
            w = whois.whois(self.domain)
            self.results["whois_info"] = {
                "registrar": str(w.registrar) if w.registrar else "Unknown",
                "creation_date": str(w.creation_date) if w.creation_date else "Unknown",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "Unknown",
                "name_servers": list(w.name_servers) if w.name_servers else [],
                "status": str(w.status) if w.status else "Unknown",
                "emails": list(w.emails) if w.emails else [],
            }
            self.log("WHOIS data retrieved", "SUCCESS")
        except Exception as e:
            self.log(f"WHOIS failed: {e}", "WARNING")

    def get_dns_records(self):
        """جمع سجلات DNS"""
        self.log(f"Fetching DNS records for {self.domain}...")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=5)
                self.results["dns_records"][rtype] = [str(r) for r in answers]
            except:
                pass
        self.log(f"DNS records: {list(self.results['dns_records'].keys())}", "SUCCESS")

    def get_ssl_info(self):
        """جمع معلومات شهادة SSL"""
        if self.parsed.scheme != "https":
            return
        try:
            self.log("Fetching SSL certificate info...")
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(self.timeout)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                self.results["ssl_info"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [x[1] for x in cert.get("subjectAltName", [])],
                }
            self.log("SSL info retrieved", "SUCCESS")
        except Exception as e:
            self.log(f"SSL info failed: {e}", "WARNING")

    def analyze_http_headers(self):
        """تحليل رؤوس HTTP"""
        try:
            self.log("Analyzing HTTP headers...")
            r = self.session.get(self.target_url, timeout=self.timeout, allow_redirects=True)
            headers = dict(r.headers)
            self.results["http_headers"] = {
                "status_code": r.status_code,
                "server": headers.get("Server", "Unknown"),
                "x_powered_by": headers.get("X-Powered-By", "Not disclosed"),
                "content_type": headers.get("Content-Type", "Unknown"),
                "x_frame_options": headers.get("X-Frame-Options", "MISSING [!]"),
                "x_xss_protection": headers.get("X-XSS-Protection", "MISSING [!]"),
                "x_content_type_options": headers.get("X-Content-Type-Options", "MISSING [!]"),
                "strict_transport_security": headers.get("Strict-Transport-Security", "MISSING [!]"),
                "content_security_policy": headers.get("Content-Security-Policy", "MISSING [!]"),
                "referrer_policy": headers.get("Referrer-Policy", "MISSING [!]"),
                "permissions_policy": headers.get("Permissions-Policy", "MISSING [!]"),
                "all_headers": headers,
            }
            # كشف التقنيات من الرؤوس
            header_str = str(headers).lower()
            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in header_str:
                        if tech not in self.results["technologies"]:
                            self.results["technologies"].append(tech)
            self.log(f"HTTP headers analyzed. Status: {r.status_code}", "SUCCESS")
            return r.text
        except Exception as e:
            self.log(f"HTTP headers analysis failed: {e}", "ERROR")
            return ""

    def analyze_page_content(self, html):
        """تحليل محتوى الصفحة"""
        if not html:
            return
        try:
            self.log("Analyzing page content...")
            soup = BeautifulSoup(html, "lxml")

            # كشف التقنيات من المحتوى
            html_lower = html.lower()
            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in html_lower:
                        if tech not in self.results["technologies"]:
                            self.results["technologies"].append(tech)

            # جمع الروابط
            for a in soup.find_all("a", href=True):
                href = a["href"]
                full_url = urljoin(self.base_url, href)
                if self.domain in full_url and full_url not in self.results["links"]:
                    self.results["links"].append(full_url)

            # جمع النماذج (Forms)
            for form in soup.find_all("form"):
                form_data = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET").upper(),
                    "inputs": [],
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    form_data["inputs"].append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "id": inp.get("id", ""),
                    })
                self.results["forms"].append(form_data)

            # جمع البريد الإلكتروني
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html)
            self.results["emails"] = list(set(emails))

            # جمع التعليقات HTML
            comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
            self.results["comments"] = [c.strip() for c in comments if len(c.strip()) > 5]

            # استخراج نقاط نهاية API من JavaScript
            js_patterns = [
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/v\d+/[^"\']+)["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ]
            for pattern in js_patterns:
                matches = re.findall(pattern, html)
                for match in matches:
                    if match not in self.results["js_endpoints"]:
                        self.results["js_endpoints"].append(match)

            # تحليل ملفات JS الخارجية
            for script in soup.find_all("script", src=True):
                js_url = urljoin(self.base_url, script["src"])
                if self.domain in js_url:
                    try:
                        js_r = self.session.get(js_url, timeout=5)
                        if js_r.status_code == 200:
                            for pattern in js_patterns:
                                matches = re.findall(pattern, js_r.text)
                                for match in matches:
                                    if match not in self.results["js_endpoints"]:
                                        self.results["js_endpoints"].append(match)
                    except:
                        pass

            self.log(f"Found {len(self.results['links'])} links, {len(self.results['forms'])} forms", "SUCCESS")
        except Exception as e:
            self.log(f"Page analysis failed: {e}", "ERROR")

    def enumerate_directories(self):
        """تعداد الدلائل والملفات"""
        self.log(f"Enumerating {len(COMMON_DIRS)} directories/files...")
        found = []

        def check_path(path):
            try:
                url = f"{self.base_url}/{path}"
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 201, 301, 302, 403, 401]:
                    entry = {
                        "path": path,
                        "url": url,
                        "status": r.status_code,
                        "size": len(r.content),
                        "interesting": r.status_code in [200, 201, 403, 401],
                    }
                    found.append(entry)
                    status_icon = "🔴" if r.status_code == 200 else "🟡"
                    self.log(f"  {status_icon} [{r.status_code}] {path}", "FOUND")
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_path, COMMON_DIRS)

        self.results["directories"] = found
        self.log(f"Directory enumeration complete. Found: {len(found)}", "SUCCESS")

    def check_sensitive_files(self):
        """فحص الملفات الحساسة"""
        self.log(f"Checking {len(SENSITIVE_FILES)} sensitive files...")
        found = []

        def check_file(fname):
            try:
                url = f"{self.base_url}/{fname}"
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 0:
                    entry = {
                        "file": fname,
                        "url": url,
                        "status": r.status_code,
                        "size": len(r.content),
                        "preview": r.text[:200] if r.text else "",
                        "severity": "CRITICAL",
                    }
                    found.append(entry)
                    self.log(f"  🚨 SENSITIVE FILE FOUND: {fname} ({len(r.content)} bytes)", "CRITICAL")
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            executor.map(check_file, SENSITIVE_FILES)

        self.results["sensitive_files"] = found
        self.log(f"Sensitive file check complete. Found: {len(found)}", "SUCCESS")

    def scan_common_ports(self):
        """فحص المنافذ الشائعة"""
        self.log("Scanning common ports...")
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017]
        open_ports = []
        ip = self.results["ip_info"].get("ip", self.domain)

        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    service_map = {
                        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
                        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
                        8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 27017: "MongoDB",
                    }
                    open_ports.append({
                        "port": port,
                        "service": service_map.get(port, "Unknown"),
                        "state": "OPEN",
                    })
                    self.log(f"  🟢 Port {port} ({service_map.get(port, 'Unknown')}) - OPEN", "FOUND")
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            executor.map(check_port, ports)

        self.results["open_ports"] = open_ports
        self.log(f"Port scan complete. Open ports: {len(open_ports)}", "SUCCESS")

    def run(self):
        """تشغيل عملية الاستطلاع الكاملة"""
        self.log(f"🚀 Starting IntelliPen Recon on: {self.target_url}", "START")
        self.log("=" * 60)

        start_time = time.time()

        self.get_ip_info()
        self.get_whois()
        self.get_dns_records()
        self.get_ssl_info()
        html = self.analyze_http_headers()
        self.analyze_page_content(html)
        self.enumerate_directories()
        self.check_sensitive_files()
        self.scan_common_ports()

        elapsed = time.time() - start_time
        self.results["scan_duration"] = f"{elapsed:.2f}s"
        self.results["summary"] = {
            "technologies_found": len(self.results["technologies"]),
            "directories_found": len(self.results["directories"]),
            "sensitive_files_found": len(self.results["sensitive_files"]),
            "forms_found": len(self.results["forms"]),
            "links_found": len(self.results["links"]),
            "open_ports": len(self.results["open_ports"]),
            "js_endpoints": len(self.results["js_endpoints"]),
        }

        self.log("=" * 60)
        self.log(f"✅ Recon complete in {elapsed:.2f}s", "DONE")
        self.log(f"📊 Summary: {self.results['summary']}")

        return self.results


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    engine = ReconEngine(target)
    results = engine.run()
    print(json.dumps(results, indent=2, default=str))
