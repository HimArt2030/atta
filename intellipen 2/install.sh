#!/bin/bash
# ============================================================
# IntelliPen - Auto Installer for Kali Linux
# سكريبت التثبيت التلقائي لـ Kali Linux
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ██╗███╗   ██╗████████╗███████╗██╗     ██╗     ██╗██████╗ ███████╗███╗   ██╗"
echo "  ██║████╗  ██║╚══██╔══╝██╔════╝██║     ██║     ██║██╔══██╗██╔════╝████╗  ██║"
echo "  ██║██╔██╗ ██║   ██║   █████╗  ██║     ██║     ██║██████╔╝█████╗  ██╔██╗ ██║"
echo "  ██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██║     ██║██╔═══╝ ██╔══╝  ██║╚██╗██║"
echo "  ██║██║ ╚████║   ██║   ███████╗███████╗███████╗██║██║     ███████╗██║ ╚████║"
echo "  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═══╝"
echo -e "${NC}"
echo -e "${BOLD}  AI-Powered Penetration Testing Framework v1.0${NC}"
echo -e "${YELLOW}  For Authorized Security Testing Only${NC}"
echo ""

# التحقق من صلاحيات الجذر
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] يُنصح بالتشغيل كـ root أو باستخدام sudo${NC}"
fi

echo -e "${GREEN}[*] بدء تثبيت IntelliPen...${NC}"
echo ""

# تحديث النظام
echo -e "${CYAN}[1/5] تحديث قوائم الحزم...${NC}"
apt-get update -qq 2>/dev/null || true

# تثبيت Python3 و pip إذا لم يكونا موجودَين
echo -e "${CYAN}[2/5] التحقق من Python3...${NC}"
if ! command -v python3 &> /dev/null; then
    apt-get install -y python3 python3-pip 2>/dev/null
fi

# تثبيت المكتبات المطلوبة
echo -e "${CYAN}[3/5] تثبيت مكتبات Python...${NC}"
PACKAGES="flask flask-socketio requests beautifulsoup4 fpdf2 colorama dnspython python-whois"

pip3 install $PACKAGES 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [+] تم تثبيت جميع المكتبات بنجاح${NC}"
else
    echo -e "${YELLOW}    [!] محاولة التثبيت بـ --break-system-packages ...${NC}"
    pip3 install --break-system-packages $PACKAGES 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}    [+] تم تثبيت جميع المكتبات بنجاح${NC}"
    else
        echo -e "${RED}    [-] فشل التثبيت. جرب يدوياً: pip3 install --break-system-packages $PACKAGES${NC}"
    fi
fi

# إنشاء المجلدات المطلوبة
echo -e "${CYAN}[4/5] إنشاء مجلدات المشروع...${NC}"
mkdir -p reports logs data

# التحقق من الملفات الأساسية
echo -e "${CYAN}[5/5] التحقق من ملفات المشروع...${NC}"
MISSING=0
for f in app.py core/recon.py core/scanner.py core/report_generator.py ai/exploit_engine.py templates/index.html; do
    if [ ! -f "$f" ]; then
        echo -e "${RED}    [-] ملف مفقود: $f${NC}"
        MISSING=1
    else
        echo -e "${GREEN}    [+] $f${NC}"
    fi
done

echo ""
if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}${BOLD}[✓] التثبيت اكتمل بنجاح!${NC}"
    echo ""
    echo -e "${CYAN}لتشغيل IntelliPen:${NC}"
    echo -e "    ${BOLD}python3 app.py${NC}"
    echo ""
    echo -e "${CYAN}ثم افتح المتصفح على:${NC}"
    echo -e "    ${BOLD}http://localhost:5000${NC}"
    echo ""
    echo -e "${YELLOW}[!] تحذير: استخدم هذه الأداة على أنظمة تملك إذناً صريحاً باختبارها فقط.${NC}"
else
    echo -e "${RED}[!] بعض الملفات مفقودة. تأكد من فك ضغط الأرشيف بالكامل.${NC}"
fi
