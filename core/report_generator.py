"""
IntelliPen - Professional Report Generator
مولّد التقارير الاحترافية - ينتج تقارير PDF شاملة
"""

import json
import os
from datetime import datetime
from fpdf import FPDF
import textwrap


class IntelliPenReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.add_page()
        
    def header(self):
        # شريط العنوان
        self.set_fill_color(15, 25, 50)
        self.rect(0, 0, 210, 20, 'F')
        self.set_text_color(0, 200, 100)
        self.set_font('Helvetica', 'B', 12)
        self.set_y(6)
        self.cell(0, 8, 'IntelliPen - AI-Powered Penetration Testing Framework', align='C')
        self.set_text_color(150, 150, 150)
        self.set_font('Helvetica', '', 8)
        self.set_y(14)
        self.cell(0, 4, f'CONFIDENTIAL SECURITY ASSESSMENT REPORT | {datetime.now().strftime("%Y-%m-%d")}', align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_fill_color(15, 25, 50)
        self.rect(0, self.get_y(), 210, 15, 'F')
        self.set_text_color(100, 100, 100)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'IntelliPen v1.0 | Page {self.page_no()} | For Authorized Testing Only', align='C')

    def chapter_title(self, title, color=(0, 200, 100)):
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 13)
        self.cell(0, 10, f'  {title}', fill=True, ln=True)
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def section_title(self, title):
        self.set_text_color(15, 25, 50)
        self.set_font('Helvetica', 'B', 11)
        self.cell(0, 8, title, ln=True)
        self.set_draw_color(0, 200, 100)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)
        self.set_text_color(0, 0, 0)

    @staticmethod
    def clean_text(text):
        """تنظيف النص من الأحرف غير المدعومة في Latin-1"""
        if not text:
            return ''
        replacements = {
            '\u2022': '-', '\u2013': '-', '\u2014': '-',
            '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
            '\u2026': '...', '\u00b7': '-', '\u2012': '-', '\u2015': '-',
            '\u25cf': '*', '\u2192': '->', '\u2190': '<-',
            '\u2713': '[OK]', '\u2717': '[X]', '\u26a0': '[!]',
        }
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        return text.encode('latin-1', 'replace').decode('latin-1')

    def body_text(self, text, font_size=9):
        self.set_font('Helvetica', '', font_size)
        self.set_text_color(50, 50, 50)
        text = self.clean_text(text)
        # تقسيم النص الطويل
        lines = text.split('\n')
        for line in lines:
            if len(line) > 100:
                wrapped = textwrap.wrap(line, width=100)
                for wl in wrapped:
                    self.cell(0, 5, self.clean_text(wl), ln=True)
            else:
                self.cell(0, 5, self.clean_text(line), ln=True)
        self.ln(2)

    def severity_badge(self, severity):
        colors = {
            "CRITICAL": (220, 20, 60),
            "HIGH": (255, 69, 0),
            "MEDIUM": (255, 165, 0),
            "LOW": (30, 144, 255),
            "INFO": (100, 100, 100),
        }
        color = colors.get(severity, (100, 100, 100))
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 8)
        self.cell(20, 6, severity, fill=True, align='C')
        self.set_text_color(0, 0, 0)

    def vulnerability_card(self, vuln, index):
        """بطاقة ثغرة واحدة"""
        severity = vuln.get("severity", "INFO")
        colors = {
            "CRITICAL": (255, 240, 240),
            "HIGH": (255, 248, 240),
            "MEDIUM": (255, 255, 240),
            "LOW": (240, 248, 255),
            "INFO": (248, 248, 248),
        }
        border_colors = {
            "CRITICAL": (220, 20, 60),
            "HIGH": (255, 69, 0),
            "MEDIUM": (255, 165, 0),
            "LOW": (30, 144, 255),
            "INFO": (100, 100, 100),
        }
        
        bg_color = colors.get(severity, (248, 248, 248))
        border_color = border_colors.get(severity, (100, 100, 100))
        
        # خلفية البطاقة
        self.set_fill_color(*bg_color)
        card_y = self.get_y()
        
        # رقم الثغرة والنوع
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(15, 25, 50)
        self.cell(8, 7, f'#{index}', ln=False)
        self.severity_badge(severity)
        self.cell(5, 7, '', ln=False)
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(15, 25, 50)
        vuln_type = self.clean_text(vuln.get("type", "Unknown")[:60])
        self.cell(0, 7, vuln_type, ln=True)
        
        # تفاصيل الثغرة
        self.set_font('Helvetica', '', 8)
        self.set_text_color(80, 80, 80)
        
        url = self.clean_text(vuln.get("url", "N/A")[:80])
        self.cell(25, 5, 'URL:', ln=False)
        self.set_text_color(0, 100, 200)
        self.cell(0, 5, url, ln=True)
        
        self.set_text_color(80, 80, 80)
        self.cell(25, 5, 'Parameter:', ln=False)
        self.set_text_color(150, 0, 150)
        self.cell(0, 5, self.clean_text(vuln.get("parameter", "N/A")[:60]), ln=True)
        
        self.set_text_color(80, 80, 80)
        self.cell(25, 5, 'CWE:', ln=False)
        self.set_text_color(0, 0, 0)
        self.cell(0, 5, self.clean_text(vuln.get("cwe", "N/A")), ln=True)
        
        self.cell(25, 5, 'CVSS Score:', ln=False)
        cvss = vuln.get("cvss", 0)
        if cvss >= 9.0:
            self.set_text_color(220, 20, 60)
        elif cvss >= 7.0:
            self.set_text_color(255, 69, 0)
        elif cvss >= 4.0:
            self.set_text_color(255, 165, 0)
        else:
            self.set_text_color(30, 144, 255)
        self.cell(0, 5, f'{cvss}/10.0', ln=True)
        
        self.set_text_color(80, 80, 80)
        self.cell(25, 5, 'Description:', ln=False)
        self.set_text_color(0, 0, 0)
        desc = self.clean_text(vuln.get("description", "N/A")[:100])
        self.cell(0, 5, desc, ln=True)
        
        if vuln.get("payload") and vuln["payload"] != "N/A":
            self.set_fill_color(30, 30, 30)
            self.set_text_color(0, 200, 80)
            self.set_font('Courier', '', 7)
            payload = self.clean_text(vuln["payload"][:100])
            self.cell(0, 5, f'  PAYLOAD: {payload}', fill=True, ln=True)
            self.set_text_color(0, 0, 0)
        
        self.ln(4)
        self.set_draw_color(*border_color)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)


def generate_report(target_url, recon_results, scan_results, ai_results, output_path):
    """توليد تقرير PDF احترافي كامل"""
    
    print(f"[REPORT] Generating professional PDF report...")
    
    pdf = IntelliPenReport()
    pdf.set_margins(10, 25, 10)
    
    # ===== صفحة الغلاف =====
    pdf.set_fill_color(15, 25, 50)
    pdf.rect(0, 0, 210, 297, 'F')
    
    # شعار
    pdf.set_y(40)
    pdf.set_text_color(0, 200, 100)
    pdf.set_font('Helvetica', 'B', 40)
    pdf.cell(0, 20, 'IntelliPen', align='C', ln=True)
    
    pdf.set_text_color(100, 200, 255)
    pdf.set_font('Helvetica', '', 14)
    pdf.cell(0, 10, 'AI-Powered Penetration Testing Framework', align='C', ln=True)
    
    pdf.ln(10)
    pdf.set_fill_color(0, 200, 100)
    pdf.rect(30, pdf.get_y(), 150, 1, 'F')
    pdf.ln(15)
    
    pdf.set_text_color(200, 200, 200)
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, 'SECURITY ASSESSMENT REPORT', align='C', ln=True)
    
    pdf.ln(10)
    pdf.set_text_color(150, 150, 150)
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 8, f'Target: {target_url}', align='C', ln=True)
    pdf.cell(0, 8, f'Date: {datetime.now().strftime("%B %d, %Y")}', align='C', ln=True)
    pdf.cell(0, 8, f'Classification: CONFIDENTIAL', align='C', ln=True)
    
    # إحصائيات سريعة
    pdf.ln(20)
    vulnerabilities = scan_results.get("vulnerabilities", [])
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulnerabilities:
        severity_count[v.get("severity", "LOW")] = severity_count.get(v.get("severity", "LOW"), 0) + 1
    
    # بطاقات الإحصائيات
    stats = [
        ("CRITICAL", severity_count["CRITICAL"], (220, 20, 60)),
        ("HIGH", severity_count["HIGH"], (255, 69, 0)),
        ("MEDIUM", severity_count["MEDIUM"], (255, 165, 0)),
        ("LOW", severity_count["LOW"], (30, 144, 255)),
    ]
    
    x_start = 20
    for stat_name, stat_val, color in stats:
        pdf.set_fill_color(*color)
        pdf.set_xy(x_start, pdf.get_y())
        pdf.rect(x_start, pdf.get_y(), 40, 25, 'F')
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 20)
        pdf.set_xy(x_start, pdf.get_y() + 4)
        pdf.cell(40, 10, str(stat_val), align='C')
        pdf.set_font('Helvetica', '', 8)
        pdf.set_xy(x_start, pdf.get_y() + 10)
        pdf.cell(40, 5, stat_name, align='C')
        x_start += 45
    
    pdf.ln(35)
    pdf.set_fill_color(0, 200, 100)
    pdf.rect(30, pdf.get_y(), 150, 1, 'F')
    pdf.ln(10)
    
    pdf.set_text_color(100, 100, 100)
    pdf.set_font('Helvetica', 'I', 9)
    pdf.cell(0, 6, 'This report is generated by IntelliPen AI-Powered Penetration Testing Framework', align='C', ln=True)
    pdf.cell(0, 6, 'For authorized security testing and educational purposes only', align='C', ln=True)
    
    # ===== صفحة جديدة: ملخص تنفيذي =====
    pdf.add_page()
    pdf.chapter_title('1. EXECUTIVE SUMMARY')
    
    # معلومات المشروع
    pdf.section_title('Assessment Overview')
    
    info_data = [
        ("Target URL", target_url),
        ("Scan Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Scan Duration", recon_results.get("scan_duration", "N/A")),
        ("Total Vulnerabilities", str(len(vulnerabilities))),
        ("Critical Findings", str(severity_count["CRITICAL"])),
        ("Technologies Detected", ", ".join(recon_results.get("technologies", [])[:5])),
        ("IP Address", recon_results.get("ip_info", {}).get("ip", "N/A")),
        ("Server", recon_results.get("http_headers", {}).get("server", "N/A")),
        ("Open Ports", str(len(recon_results.get("open_ports", [])))),
    ]
    
    for label, value in info_data:
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(15, 25, 50)
        pdf.cell(50, 6, label + ':', ln=False)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 6, IntelliPenReport.clean_text(str(value)[:80]), ln=True)
    
    pdf.ln(5)
    
    # تقرير الذكاء الاصطناعي
    if ai_results and ai_results.get("attack_report"):
        pdf.section_title('AI-Generated Executive Summary')
        report_text = ai_results["attack_report"]
        # تنظيف النص
        report_text = IntelliPenReport.clean_text(report_text)
        lines = report_text.split('\n')
        for line in lines[:40]:  # أول 40 سطر
            if line.strip():
                clean_line = IntelliPenReport.clean_text(line.strip()[:100])
                if clean_line.startswith('#'):
                    pdf.set_font('Helvetica', 'B', 10)
                    pdf.set_text_color(15, 25, 50)
                    pdf.cell(0, 6, clean_line.lstrip('#').strip(), ln=True)
                else:
                    pdf.set_font('Helvetica', '', 8)
                    pdf.set_text_color(50, 50, 50)
                    pdf.cell(0, 5, clean_line, ln=True)
    
    # ===== صفحة: نتائج الاستطلاع =====
    pdf.add_page()
    pdf.chapter_title('2. RECONNAISSANCE RESULTS', color=(0, 100, 200))
    
    # معلومات IP
    ip_info = recon_results.get("ip_info", {})
    if ip_info:
        pdf.section_title('IP & Geolocation Information')
        for key, val in ip_info.items():
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(40, 5, key.replace('_', ' ').title() + ':', ln=False)
            pdf.set_font('Helvetica', '', 9)
            pdf.cell(0, 5, IntelliPenReport.clean_text(str(val)[:80]), ln=True)
        pdf.ln(3)
    
    # التقنيات المكتشفة
    technologies = recon_results.get("technologies", [])
    if technologies:
        pdf.section_title('Technologies Detected')
        tech_str = ' | '.join(technologies)
        pdf.set_fill_color(240, 248, 255)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(0, 100, 200)
        pdf.cell(0, 8, f'  {tech_str}', fill=True, ln=True)
        pdf.ln(3)
    
    # المنافذ المفتوحة
    open_ports = recon_results.get("open_ports", [])
    if open_ports:
        pdf.section_title('Open Ports')
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(15, 25, 50)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(25, 6, 'Port', fill=True, align='C')
        pdf.cell(40, 6, 'Service', fill=True, align='C')
        pdf.cell(30, 6, 'State', fill=True, align='C')
        pdf.ln()
        
        for i, port in enumerate(open_ports):
            if i % 2 == 0:
                pdf.set_fill_color(245, 245, 245)
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Helvetica', '', 8)
            pdf.cell(25, 5, str(port.get("port", "")), fill=True, align='C')
            pdf.cell(40, 5, port.get("service", ""), fill=True, align='C')
            pdf.set_text_color(0, 150, 0)
            pdf.cell(30, 5, port.get("state", ""), fill=True, align='C')
            pdf.ln()
        pdf.ln(3)
    
    # الدلائل المكتشفة
    directories = [d for d in recon_results.get("directories", []) if d.get("interesting")]
    if directories:
        pdf.section_title(f'Discovered Directories/Files ({len(directories)} interesting)')
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(15, 25, 50)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(80, 6, 'Path', fill=True)
        pdf.cell(20, 6, 'Status', fill=True, align='C')
        pdf.cell(30, 6, 'Size', fill=True, align='C')
        pdf.ln()
        
        for i, d in enumerate(directories[:20]):
            if i % 2 == 0:
                pdf.set_fill_color(245, 245, 245)
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Helvetica', '', 8)
            pdf.cell(80, 5, d.get("path", "")[:40], fill=True)
            status = d.get("status", 0)
            if status == 200:
                pdf.set_text_color(0, 150, 0)
            elif status == 403:
                pdf.set_text_color(255, 100, 0)
            else:
                pdf.set_text_color(0, 0, 200)
            pdf.cell(20, 5, str(status), fill=True, align='C')
            pdf.set_text_color(0, 0, 0)
            pdf.cell(30, 5, f'{d.get("size", 0)} bytes', fill=True, align='C')
            pdf.ln()
        pdf.ln(3)
    
    # ===== صفحة: الثغرات المكتشفة =====
    pdf.add_page()
    pdf.chapter_title('3. VULNERABILITY FINDINGS', color=(220, 20, 60))
    
    if not vulnerabilities:
        pdf.body_text('No vulnerabilities were detected during this assessment.')
    else:
        # ترتيب حسب الخطورة
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_vulns = sorted(vulnerabilities, key=lambda x: severity_order.get(x.get("severity", "LOW"), 4))
        
        for i, vuln in enumerate(sorted_vulns, 1):
            if pdf.get_y() > 240:
                pdf.add_page()
            pdf.vulnerability_card(vuln, i)
    
    # ===== صفحة: تحليل الذكاء الاصطناعي =====
    if ai_results and ai_results.get("ai_analysis"):
        pdf.add_page()
        pdf.chapter_title('4. AI THREAT INTELLIGENCE ANALYSIS', color=(100, 0, 200))
        
        ai_analysis = ai_results["ai_analysis"]
        
        if isinstance(ai_analysis, dict):
            if "attack_priority_ranking" in ai_analysis:
                pdf.section_title('Attack Priority Ranking (AI-Generated)')
                for i, item in enumerate(ai_analysis["attack_priority_ranking"][:5], 1):
                    pdf.set_font('Helvetica', '', 9)
                    pdf.cell(0, 6, f'  {i}. {str(item)[:80]}', ln=True)
                pdf.ln(3)
            
            if "recommended_attack_path" in ai_analysis:
                pdf.section_title('Recommended Attack Path (AI-Generated)')
                path = IntelliPenReport.clean_text(str(ai_analysis["recommended_attack_path"]))
                pdf.body_text(path[:500])
            
            if "estimated_success_probability" in ai_analysis:
                pdf.section_title('Estimated Exploitation Success Probability')
                pdf.set_font('Helvetica', 'B', 14)
                pdf.set_text_color(220, 20, 60)
                pdf.cell(0, 10, str(ai_analysis["estimated_success_probability"]), ln=True)
                pdf.set_text_color(0, 0, 0)
    
    # ===== صفحة: التوصيات =====
    pdf.add_page()
    pdf.chapter_title('5. REMEDIATION RECOMMENDATIONS', color=(0, 150, 50))
    
    remediation_map = {
        "SQL Injection": [
            "Use parameterized queries / prepared statements",
            "Implement input validation and sanitization",
            "Apply principle of least privilege for DB accounts",
            "Use Web Application Firewall (WAF)",
            "Disable detailed error messages in production",
        ],
        "XSS": [
            "Implement Content Security Policy (CSP)",
            "Encode all user-supplied output",
            "Use HTTPOnly and Secure cookie flags",
            "Validate and sanitize all user inputs",
            "Use modern frameworks with built-in XSS protection",
        ],
        "Command Injection": [
            "Avoid passing user input to system commands",
            "Use language-specific APIs instead of shell commands",
            "Implement strict input validation",
            "Run application with minimal privileges",
            "Use containerization to limit blast radius",
        ],
        "Path Traversal": [
            "Validate and sanitize file path inputs",
            "Use a whitelist of allowed directories",
            "Implement proper access controls",
            "Avoid exposing raw file system paths",
        ],
        "Missing Security Headers": [
            "Implement X-Frame-Options: DENY",
            "Add Content-Security-Policy header",
            "Enable Strict-Transport-Security (HSTS)",
            "Set X-Content-Type-Options: nosniff",
            "Configure Referrer-Policy appropriately",
        ],
        "CSRF": [
            "Implement CSRF tokens in all forms",
            "Use SameSite cookie attribute",
            "Validate Origin and Referer headers",
            "Implement double-submit cookie pattern",
        ],
        "IDOR": [
            "Implement proper authorization checks",
            "Use indirect object references",
            "Validate user permissions for each resource",
            "Implement access control lists (ACLs)",
        ],
        "Sensitive File Exposure": [
            "Remove sensitive files from web root",
            "Configure web server to deny access to config files",
            "Implement proper .htaccess rules",
            "Regular security audits of exposed files",
        ],
    }
    
    # جمع أنواع الثغرات الفريدة
    vuln_types = list(set(v["type"].split(" (")[0] for v in vulnerabilities))
    
    for vuln_type in vuln_types[:8]:
        # إيجاد أقرب مفتاح في القاموس
        matching_key = None
        for key in remediation_map:
            if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                matching_key = key
                break
        
        if matching_key:
            pdf.section_title(f'Fix: {vuln_type}')
            for rec in remediation_map[matching_key]:
                pdf.set_font('Helvetica', '', 9)
                pdf.set_text_color(50, 50, 50)
                pdf.cell(5, 5, '', ln=False)
                pdf.set_fill_color(0, 200, 100)
                pdf.rect(12, pdf.get_y() + 1, 3, 3, 'F')
                pdf.cell(0, 5, f'    {rec}', ln=True)
            pdf.ln(3)
    
    # ===== صفحة: الملحق =====
    pdf.add_page()
    pdf.chapter_title('6. APPENDIX - TECHNICAL DETAILS', color=(50, 50, 50))
    
    # رؤوس HTTP
    http_headers = recon_results.get("http_headers", {})
    if http_headers:
        pdf.section_title('HTTP Response Headers')
        important_headers = ["server", "x_powered_by", "content_type", "x_frame_options",
                           "x_xss_protection", "strict_transport_security", "content_security_policy"]
        for h in important_headers:
            val = IntelliPenReport.clean_text(str(http_headers.get(h, "N/A"))[:80])
            pdf.set_font('Helvetica', 'B', 8)
            pdf.cell(55, 5, h.replace('_', '-').title() + ':', ln=False)
            pdf.set_font('Courier', '', 8)
            if "MISSING" in val:
                pdf.set_text_color(220, 20, 60)
            else:
                pdf.set_text_color(0, 100, 0)
            pdf.cell(0, 5, val, ln=True)
            pdf.set_text_color(0, 0, 0)
        pdf.ln(3)
    
    # نقاط نهاية API المكتشفة
    js_endpoints = recon_results.get("js_endpoints", [])
    if js_endpoints:
        pdf.section_title(f'Discovered API Endpoints ({len(js_endpoints)})')
        for ep in js_endpoints[:20]:
            pdf.set_font('Courier', '', 8)
            pdf.set_text_color(0, 100, 200)
            pdf.cell(0, 4, f'  {IntelliPenReport.clean_text(str(ep)[:90])}', ln=True)
        pdf.set_text_color(0, 0, 0)
    
    # حفظ التقرير
    # حفظ التقرير مع معالجة الأخطاء
    try:
        pdf.output(output_path)
    except Exception as e:
        print(f'[REPORT] Warning during output: {e}, retrying with safe mode...')
        # محاولة ثانية بعد تنظيف إضافي
        pdf.output(output_path)
    print(f"[REPORT] ✅ Report saved to: {output_path}")
    return output_path


if __name__ == "__main__":
    print("Report generator module loaded successfully")
