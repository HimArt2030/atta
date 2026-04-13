# IntelliPen — إطار اختبار اختراق ذكي مؤتمت

> **تحذير أخلاقي وقانوني:** هذه الأداة مخصصة لاختبار الاختراق الأخلاقي (Ethical Penetration Testing) فقط. استخدامها على أنظمة دون إذن صريح وخطي من المالك يُعدّ جريمة جنائية في معظم دول العالم. المطور غير مسؤول عن أي استخدام غير مشروع.

---

## نظرة عامة

**IntelliPen** هو إطار عمل متكامل لاختبار الاختراق يجمع بين:
- محرك استطلاع ذكي يجمع معلومات شاملة عن الهدف
- محرك فحص ديناميكي يكتشف الثغرات بحمولات حقيقية
- محرك ذكاء اصطناعي محلي يحلل الثغرات ويولد استراتيجيات الاستغلال
- واجهة ويب تفاعلية بتحديثات في الوقت الفعلي
- مولّد تقارير PDF احترافي

---

## المتطلبات

| المتطلب | الإصدار |
|---|---|
| Python | 3.9 أو أحدث |
| نظام التشغيل | Kali Linux / Ubuntu / Debian |
| الذاكرة | 512 MB كحد أدنى |
| الاتصال | إنترنت (للفحص على مواقع خارجية) |

---

## التثبيت السريع على Kali Linux

```bash
# 1. فك ضغط المشروع
unzip IntelliPen_Project.zip
cd intellipen

# 2. تشغيل سكريبت التثبيت التلقائي
chmod +x install.sh
sudo bash install.sh

# 3. تشغيل IntelliPen
python3 app.py
```

ثم افتح المتصفح على: **http://localhost:5000**

---

## التثبيت اليدوي (إذا فشل التلقائي)

```bash
# تثبيت المكتبات يدوياً
pip3 install flask flask-socketio requests beautifulsoup4 fpdf2 colorama dnspython

# أو في Kali الجديد (2024+)
pip3 install --break-system-packages flask flask-socketio requests beautifulsoup4 fpdf2 colorama dnspython

# تشغيل المشروع
python3 app.py
```

---

## طريقة الاستخدام

### 1. الفحص عبر الواجهة الرسومية
1. افتح المتصفح على `http://localhost:5000`
2. أدخل رابط الهدف في حقل "Target URL"
3. اضغط "Start Scan"
4. تابع النتائج في الوقت الفعلي
5. حمّل التقرير PDF عند الانتهاء

### 2. الفحص عبر API مباشرة
```bash
# بدء فحص
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://TARGET_URL"}'

# الحصول على النتائج (استبدل SESSION_ID بالمعرف المُعاد)
curl http://localhost:5000/api/results/SESSION_ID

# تحميل التقرير PDF
curl -O http://localhost:5000/api/report/SESSION_ID
```

---

## مواقع اختبار مجانية مرخصة

يمكن استخدام هذه المواقع المخصصة للاختبار بشكل قانوني:

| الموقع | الوصف |
|---|---|
| `http://testphp.vulnweb.com` | موقع Acunetix الرسمي للاختبار (PHP + MySQL) |
| `http://testhtml5.vulnweb.com` | موقع HTML5 مع ثغرات متعددة |
| `http://testasp.vulnweb.com` | موقع ASP.NET للاختبار |
| `http://dvwa.co.uk` | Damn Vulnerable Web Application |
| `http://localhost:8888` | بيئة الاختبار المحلية المرفقة مع المشروع |

---

## تشغيل بيئة الاختبار المحلية (VulnLab)

```bash
# في نافذة طرفية منفصلة
python3 target_lab/vulnerable_app.py

# ثم افحصها من IntelliPen
# الهدف: http://localhost:8888
```

---

## هيكل المشروع

```
intellipen/
├── app.py                    # الخادم الرئيسي (Flask + SocketIO)
├── install.sh                # سكريبت التثبيت التلقائي
├── core/
│   ├── recon.py              # محرك الاستطلاع الذكي
│   ├── scanner.py            # محرك فحص الثغرات
│   └── report_generator.py  # مولّد التقارير PDF
├── ai/
│   └── exploit_engine.py    # محرك الذكاء الاصطناعي المحلي
├── templates/
│   └── index.html           # واجهة المستخدم الرسومية
├── target_lab/
│   └── vulnerable_app.py    # هدف اختبار محلي مليء بالثغرات
├── reports/                 # التقارير المولَّدة (PDF)
└── logs/                    # سجلات النظام
```

---

## الثغرات التي يكتشفها النظام

| الثغرة | الوصف | الخطورة |
|---|---|---|
| SQL Injection | حقن SQL (Error/Union/Time-based) | Critical/High |
| XSS Reflected | حقن JavaScript منعكس | High |
| XSS Stored | حقن JavaScript مخزن | High |
| IDOR | الوصول المباشر للكائنات | High |
| CSRF | تزوير الطلبات عبر المواقع | Medium |
| Path Traversal | اجتياز المسارات | High |
| Command Injection | حقن أوامر النظام | Critical |
| Security Headers | رؤوس أمنية مفقودة | Medium/Low |
| Sensitive Files | ملفات حساسة مكشوفة | Medium |
| Open Ports | منافذ مفتوحة غير ضرورية | Info |

---

## استكشاف الأخطاء الشائعة

**المشكلة:** `ModuleNotFoundError: No module named 'flask'`
```bash
pip3 install --break-system-packages flask flask-socketio
```

**المشكلة:** `Address already in use` (المنفذ 5000 مشغول)
```bash
# إيقاف العملية التي تستخدم المنفذ
sudo lsof -ti:5000 | xargs kill -9
python3 app.py
```

**المشكلة:** الفحص يتوقف أو لا يُكمل
```bash
# تحقق من السجلات
tail -f logs/server.log
```

---

## المطور

مشروع تخرج — تخصص الأمن السيبراني الهجومي
تم البناء بالكامل باستخدام Python 3.11 من الصفر دون أدوات جاهزة.
