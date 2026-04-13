"""
IntelliPen - Main Application Server
الخادم الرئيسي للتطبيق - يدير واجهة الويب وينسق بين المحركات
"""

import os
import sys
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit

# إضافة مسار المشروع
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.recon import ReconEngine
from core.scanner import VulnerabilityScanner
from ai.exploit_engine import AIExploitEngine
from core.report_generator import generate_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'intellipen-secret-key-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# تخزين نتائج الفحص
scan_sessions = {}


def run_full_scan(session_id, target_url):
    """تشغيل الفحص الكامل في خيط منفصل"""
    
    def emit_progress(stage, message, progress, data=None):
        socketio.emit('scan_progress', {
            'session_id': session_id,
            'stage': stage,
            'message': message,
            'progress': progress,
            'data': data or {},
            'timestamp': datetime.now().isoformat(),
        })
    
    try:
        scan_sessions[session_id] = {
            'status': 'running',
            'target': target_url,
            'start_time': datetime.now().isoformat(),
            'recon': None,
            'scan': None,
            'ai': None,
            'report_path': None,
        }
        
        # ===== مرحلة 1: الاستطلاع =====
        emit_progress('recon', '🔍 Starting Reconnaissance...', 5)
        
        recon = ReconEngine(target_url, timeout=8)
        
        # تجاوز print لإرسال التحديثات
        original_print = __builtins__['print'] if isinstance(__builtins__, dict) else print
        
        emit_progress('recon', '📡 Resolving IP and WHOIS...', 10)
        recon.get_ip_info()
        recon.get_whois()
        
        emit_progress('recon', '🔎 Fetching DNS records...', 15)
        recon.get_dns_records()
        recon.get_ssl_info()
        
        emit_progress('recon', '🌐 Analyzing HTTP headers and page content...', 20)
        html = recon.analyze_http_headers()
        recon.analyze_page_content(html)
        
        emit_progress('recon', '📂 Enumerating directories...', 30)
        recon.enumerate_directories()
        
        emit_progress('recon', '🔐 Checking sensitive files...', 40)
        recon.check_sensitive_files()
        
        emit_progress('recon', '🔌 Scanning ports...', 45)
        recon.scan_common_ports()
        
        recon_results = recon.results
        scan_sessions[session_id]['recon'] = recon_results
        
        emit_progress('recon', '✅ Reconnaissance complete!', 50, {
            'technologies': recon_results.get('technologies', []),
            'directories_found': len(recon_results.get('directories', [])),
            'sensitive_files': len(recon_results.get('sensitive_files', [])),
            'open_ports': len(recon_results.get('open_ports', [])),
            'forms_found': len(recon_results.get('forms', [])),
        })
        
        # ===== مرحلة 2: فحص الثغرات =====
        emit_progress('scan', '🛡️ Starting Vulnerability Scanner...', 55)
        
        scanner = VulnerabilityScanner(target_url, recon_results, timeout=8)
        
        emit_progress('scan', '🔒 Testing security headers...', 58)
        scanner.test_security_headers()
        
        emit_progress('scan', '📁 Checking sensitive file exposure...', 60)
        if recon_results.get('sensitive_files'):
            scanner.test_sensitive_file_exposure(recon_results['sensitive_files'])
        
        emit_progress('scan', '💉 Testing SQL Injection...', 63)
        emit_progress('scan', '⚡ Testing XSS vulnerabilities...', 66)
        emit_progress('scan', '🔧 Testing Command Injection...', 69)
        emit_progress('scan', '📂 Testing Path Traversal...', 72)
        emit_progress('scan', '🔄 Testing CSRF and IDOR...', 75)
        
        scan_results = scanner.run(recon_results)
        scan_sessions[session_id]['scan'] = scan_results
        
        vulns = scan_results.get('vulnerabilities', [])
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulns:
            severity_count[v.get('severity', 'LOW')] = severity_count.get(v.get('severity', 'LOW'), 0) + 1
        
        emit_progress('scan', '✅ Vulnerability scan complete!', 80, {
            'total_vulnerabilities': len(vulns),
            'severity_breakdown': severity_count,
            'vulnerabilities': vulns[:5],  # أول 5 للعرض الفوري
        })
        
        # ===== مرحلة 3: الذكاء الاصطناعي =====
        emit_progress('ai', '🤖 AI Exploitation Engine analyzing...', 83)
        
        ai_engine = AIExploitEngine(target_url, scan_results, recon_results)
        
        emit_progress('ai', '🧠 AI analyzing vulnerabilities and generating attack strategies...', 86)
        ai_results = ai_engine.run_full_ai_analysis()
        
        scan_sessions[session_id]['ai'] = ai_results
        
        # استخراج للعرض
        ai_analysis = ai_results.get('ai_analysis', {})
        attack_report = ai_results.get('attack_report', '')
        
        emit_progress('ai', '✅ AI analysis complete!', 92)
        
        # ===== مرحلة 4: توليد التقرير =====
        emit_progress('report', '📄 Generating professional PDF report...', 95)
        
        report_path = os.path.join(REPORTS_DIR, f'intellipen_report_{session_id}.pdf')
        generate_report(target_url, recon_results, scan_results, ai_results, report_path)
        scan_sessions[session_id]['report_path'] = report_path
        
        scan_sessions[session_id]['status'] = 'complete'
        scan_sessions[session_id]['end_time'] = datetime.now().isoformat()
        
        emit_progress('complete', '🎉 Full scan complete! Report ready.', 100, {
            'session_id': session_id,
            'total_vulnerabilities': len(vulns),
            'severity_breakdown': severity_count,
            'report_ready': True,
            'all_vulnerabilities': vulns,
            'recon_summary': recon_results.get('summary', {}),
            'technologies': recon_results.get('technologies', []),
            'open_ports': recon_results.get('open_ports', []),
            'ai_analysis': ai_analysis,
            'attack_report': attack_report[:1000] if attack_report else '',
        })
        
    except Exception as e:
        scan_sessions[session_id]['status'] = 'error'
        scan_sessions[session_id]['error'] = str(e)
        emit_progress('error', f'❌ Error: {str(e)}', 0)
        import traceback
        traceback.print_exc()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    target_url = data.get('url', '').strip()
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    session_id = f"scan_{int(time.time())}_{hash(target_url) % 10000}"
    
    # تشغيل الفحص في خيط منفصل
    thread = threading.Thread(target=run_full_scan, args=(session_id, target_url))
    thread.daemon = True
    thread.start()
    
    return jsonify({'session_id': session_id, 'status': 'started', 'target': target_url})


@app.route('/api/results/<session_id>')
def get_results(session_id):
    if session_id not in scan_sessions:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify(scan_sessions[session_id])


@app.route('/api/report/<session_id>')
def download_report(session_id):
    if session_id not in scan_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    report_path = scan_sessions[session_id].get('report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'error': 'Report not ready yet'}), 404
    
    return send_file(
        report_path,
        as_attachment=True,
        download_name=f'intellipen_report_{session_id}.pdf',
        mimetype='application/pdf'
    )


@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to IntelliPen server'})


@socketio.on('join_scan')
def handle_join(data):
    session_id = data.get('session_id')
    if session_id and session_id in scan_sessions:
        emit('scan_status', scan_sessions[session_id])


# ===== مسارات ديناميكية تعمل على أي جهاز =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

if __name__ == '__main__':
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    print("\n" + "="*60)
    print("  IntelliPen - AI-Powered Penetration Testing Framework")
    print("  Server starting on http://0.0.0.0:5000")
    print("  Open your browser: http://localhost:5000")
    print("="*60 + "\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
