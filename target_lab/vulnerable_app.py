"""
IntelliPen - Vulnerable Target Lab
تطبيق ويب متعمد الثغرات لاختبار قدرات IntelliPen
DISCLAIMER: For educational and testing purposes only!
"""

from flask import Flask, request, jsonify, make_response
import sqlite3
import os
import subprocess

app = Flask(__name__)

# إنشاء قاعدة بيانات SQLite مع بيانات تجريبية
def init_db():
    conn = sqlite3.connect('/tmp/vuln_lab.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS products 
                 (id INTEGER PRIMARY KEY, name TEXT, price REAL, description TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS orders 
                 (id INTEGER PRIMARY KEY, user_id INTEGER, product_id INTEGER, amount REAL)''')
    
    # بيانات تجريبية
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123!', 'admin@vulnlab.com', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'john', 'password123', 'john@example.com', 'user')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'alice', 'alice2024', 'alice@example.com', 'user')")
    c.execute("INSERT OR IGNORE INTO products VALUES (1, 'Product A', 99.99, 'Test product')")
    c.execute("INSERT OR IGNORE INTO products VALUES (2, 'Product B', 149.99, 'Another product')")
    c.execute("INSERT OR IGNORE INTO orders VALUES (1, 1, 1, 99.99)")
    c.execute("INSERT OR IGNORE INTO orders VALUES (2, 2, 2, 149.99)")
    conn.commit()
    conn.close()

init_db()

# ===== الصفحة الرئيسية =====
@app.route('/')
def index():
    return '''<!DOCTYPE html>
<html>
<head>
    <title>VulnLab - Test Application</title>
    <meta name="generator" content="PHP/7.4.3">
</head>
<body>
<h1>Welcome to VulnLab</h1>
<p>Powered by Apache/2.4.41 (Ubuntu)</p>
<!-- TODO: Remove debug mode before production -->
<!-- DB: mysql://admin:secret123@localhost/vulndb -->
<form action="/login" method="POST">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
</form>
<form action="/search" method="GET">
    <input type="text" name="q" placeholder="Search products...">
    <button type="submit">Search</button>
</form>
<a href="/user?id=1">My Profile</a> | 
<a href="/products">Products</a> |
<a href="/api/v1/users">API</a>
</body>
</html>'''

# ===== ثغرة SQL Injection في تسجيل الدخول =====
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return '''<form action="/login" method="POST">
            <input name="username"><input name="password" type="password">
            <button>Login</button></form>'''
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # ثغرة SQL Injection متعمدة!
    conn = sqlite3.connect('/tmp/vuln_lab.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    try:
        c.execute(query)
        user = c.fetchone()
        conn.close()
        
        if user:
            resp = make_response(f'<h1>Welcome {user[1]}!</h1><p>Role: {user[4]}</p>')
            resp.set_cookie('session', f'user_id={user[0]}')  # بدون HttpOnly
            return resp
        else:
            return '<h1>Login Failed</h1><p>Invalid credentials</p>'
    except Exception as e:
        conn.close()
        # كشف خطأ SQL متعمد
        return f'<h1>Database Error</h1><pre>SQLite error: {str(e)}\nQuery: {query}</pre>', 500

# ===== ثغرة XSS في البحث =====
@app.route('/search')
def search():
    q = request.args.get('q', '')
    
    conn = sqlite3.connect('/tmp/vuln_lab.db')
    c = conn.cursor()
    c.execute("SELECT * FROM products WHERE name LIKE ?", (f'%{q}%',))
    products = c.fetchall()
    conn.close()
    
    # ثغرة XSS متعمدة - عرض المدخل مباشرة بدون تنظيف
    return f'''<html><body>
    <h1>Search Results for: {q}</h1>
    <p>Found {len(products)} results</p>
    {"".join(f"<div><b>{p[1]}</b> - ${p[2]}</div>" for p in products)}
    <form action="/search" method="GET">
        <input name="q" value="{q}">
        <button>Search Again</button>
    </form>
    </body></html>'''

# ===== ثغرة IDOR في الملف الشخصي =====
@app.route('/user')
def user_profile():
    user_id = request.args.get('id', '1')
    
    conn = sqlite3.connect('/tmp/vuln_lab.db')
    c = conn.cursor()
    # ثغرة IDOR - لا يوجد تحقق من صلاحية المستخدم
    c.execute(f"SELECT * FROM users WHERE id={user_id}")
    user = c.fetchone()
    conn.close()
    
    if user:
        return f'''<html><body>
        <h1>User Profile</h1>
        <p>ID: {user[0]}</p>
        <p>Username: {user[1]}</p>
        <p>Password: {user[2]}</p>
        <p>Email: {user[3]}</p>
        <p>Role: {user[4]}</p>
        </body></html>'''
    return '<h1>User not found</h1>', 404

# ===== ثغرة Command Injection =====
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # ثغرة Command Injection متعمدة!
    try:
        result = subprocess.check_output(f'ping -c 1 {host}', shell=True, 
                                          stderr=subprocess.STDOUT, timeout=5)
        return f'<pre>{result.decode()}</pre>'
    except Exception as e:
        return f'<pre>Error: {str(e)}</pre>'

# ===== ثغرة Path Traversal =====
@app.route('/file')
def read_file():
    filename = request.args.get('name', 'readme.txt')
    # ثغرة Path Traversal متعمدة!
    try:
        with open(f'/var/www/{filename}', 'r') as f:
            return f'<pre>{f.read()}</pre>'
    except FileNotFoundError:
        try:
            with open(filename, 'r') as f:
                return f'<pre>{f.read()}</pre>'
        except:
            return '<p>File not found</p>', 404
    except Exception as e:
        return f'<p>Error: {str(e)}</p>', 500

# ===== API بدون مصادقة (IDOR في API) =====
@app.route('/api/v1/users')
def api_users():
    conn = sqlite3.connect('/tmp/vuln_lab.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email, role FROM users")
    users = [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/api/v1/users/<int:user_id>')
def api_user(user_id):
    conn = sqlite3.connect('/tmp/vuln_lab.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return jsonify({"id": user[0], "username": user[1], "password": user[2], 
                        "email": user[3], "role": user[4]})
    return jsonify({"error": "Not found"}), 404

@app.route('/api/v1/orders/<int:order_id>')
def api_order(order_id):
    conn = sqlite3.connect('/tmp/vuln_lab.db')
    c = conn.cursor()
    c.execute("SELECT * FROM orders WHERE id=?", (order_id,))
    order = c.fetchone()
    conn.close()
    if order:
        return jsonify({"id": order[0], "user_id": order[1], "product_id": order[2], "amount": order[3]})
    return jsonify({"error": "Not found"}), 404

# ===== نموذج بدون CSRF Token =====
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if request.method == 'POST':
        amount = request.form.get('amount', '0')
        to_user = request.form.get('to', '')
        # لا يوجد CSRF token!
        return f'<h1>Transfer of ${amount} to {to_user} completed!</h1>'
    return '''<form action="/transfer" method="POST">
        <input name="amount" placeholder="Amount">
        <input name="to" placeholder="Recipient">
        <button>Transfer</button>
    </form>'''

# ===== معلومات حساسة مكشوفة =====
@app.route('/admin')
def admin():
    # لوحة إدارة بدون مصادقة
    return '''<html><body>
    <h1>Admin Panel</h1>
    <p>Server: Apache/2.4.41</p>
    <p>PHP Version: 7.4.3</p>
    <p>DB: SQLite 3.31.1</p>
    <p>Debug Mode: ON</p>
    <p>Secret Key: super_secret_key_2024!</p>
    <a href="/api/v1/users">View All Users</a>
    </body></html>'''

if __name__ == '__main__':
    print("🎯 VulnLab Target started on http://0.0.0.0:8888")
    app.run(host='0.0.0.0', port=8888, debug=False)
