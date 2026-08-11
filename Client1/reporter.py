#!/usr/bin/env python3
"""
reporter.py
-----------
Belirli araliklarla (config.json -> report_interval_seconds) PDF guvenlik
raporu uretir ve yoneticiye e-posta ile gonderir.

Bu surede HICBIR tespit olmadiysa mail ATILMAZ, sadece log'a yazilir
(bu karar watcher.py tarafinda verilir, bu dosya sadece uretim/gonderim yapar).

Icerik:
  - Bilgisayar adi, aktif kullanici, sistem/servis uptime'i, macOS surumu
    (macOS komutlariyla toplanir: scutil, stat, sysctl)
  - Tespit edilen dosyalarin tablosu (dosya adi, konum, zararli turu)
  - Gmail SMTP (App Password, port 587/STARTTLS) uzerinden PDF eklentili mail
"""

import os
import platform
import re
import smtplib
import ssl
import subprocess
import sys
import time
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.graphics.shapes import Drawing, Circle, Polygon, String
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    Image,
)

# ---------------------------------------------------------------------------
# Turkce karakter destegi (i, I, s, g, c gibi harfler ReportLab'in
# varsayilan Helvetica fontunda SIYAH KUTUCUK olarak cikiyor). Bunun
# Çalışan dosyanın (Client1) bir üst dizinine çıkıp assets klasörünü hedefliyoruz.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"

# İcine projeye gomulu DejaVu Sans fontunu kaydediyoruz - hem "normal"
# hem "kalın" turu, böylece <b>...</b> etiketleri de doğru çalışır.
#
# PyInstaller --onefile ile derlenmis halde calisirken font dosyalari
# sys._MEIPASS altindaki gecici klasore cikartilir; normal calismada
# script'in kendi klasorundedir.
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    _FONT_DIR = Path(sys._MEIPASS) / "fonts"
else:
    _FONT_DIR = ASSETS_DIR / "fonts"

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    SEAL_LOGO_PATH = Path(sys._MEIPASS) / "sentinel_seal.png"
else:
    SEAL_LOGO_PATH = ASSETS_DIR / "sentinel_seal.png"

FONT_NAME = "Helvetica"
FONT_NAME_BOLD = "Helvetica-Bold"

try:
    pdfmetrics.registerFont(TTFont("DejaVuSans", str(_FONT_DIR / "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", str(_FONT_DIR / "DejaVuSans-Bold.ttf")))
    pdfmetrics.registerFontFamily(
        "DejaVuSans",
        normal="DejaVuSans",
        bold="DejaVuSans-Bold",
        italic="DejaVuSans",
        boldItalic="DejaVuSans-Bold",
    )
    FONT_NAME = "DejaVuSans"
    FONT_NAME_BOLD = "DejaVuSans-Bold"
except Exception:
    # Font dosyalari bulunamazsa Helvetica'ya duser (Turkce karakterler
    # bozuk gorunebilir ama PDF uretimi yine de basarisiz olmaz).
    pass


# ---------------------------------------------------------------------------
# Sistem bilgisi toplama (macOS komutlari kullanilir)
# ---------------------------------------------------------------------------
def get_computer_name() -> str:
    """macOS'ta Sistem Ayarlari'nda gorunen bilgisayar adini doner."""
    try:
        result = subprocess.run(
            ["scutil", "--get", "ComputerName"],
            capture_output=True, text=True, timeout=5,
        )
        name = result.stdout.strip()
        return name if name else platform.node()
    except Exception:
        return platform.node()


def get_active_user() -> str:
    """
    O an Mac'te konsolda oturum acmis (aktif) kullaniciyi doner.
    os.getlogin() launchd servisleri icinde guvenilir calismayabilir,
    bu yuzden /dev/console'un sahibine bakiyoruz - bu daima dogru sonucu verir.
    """
    try:
        result = subprocess.run(
            ["stat", "-f%Su", "/dev/console"],
            capture_output=True, text=True, timeout=5,
        )
        user = result.stdout.strip()
        return user if user else "bilinmiyor"
    except Exception:
        return "bilinmiyor"


def get_macos_version() -> str:
    try:
        version = platform.mac_ver()[0]
        return f"macOS {version}" if version else "bilinmiyor"
    except Exception:
        return "bilinmiyor"


def format_duration(seconds) -> str:
    """Saniyeyi 'X gun Y saat Z dakika' formatina cevirir."""
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    parts = []
    if days:
        parts.append(f"{days} gun")
    if hours:
        parts.append(f"{hours} saat")
    parts.append(f"{minutes} dakika")
    return " ".join(parts)


def get_system_uptime() -> str:
    """Mac'in ne zamandir acik oldugunu (sistem uptime) doner."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "kern.boottime"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"sec\s*=\s*(\d+)", result.stdout)
        if match:
            boot_ts = int(match.group(1))
            return format_duration(time.time() - boot_ts)
    except Exception:
        pass
    return "bilinmiyor"


# ---------------------------------------------------------------------------
# Sayfa altbilgisi: sol altta uretim tarihi, sag altta "Sayfa X/Y".
# Toplam sayfa sayisini (Y) once bilmemiz gerektigi icin (coklu sayfa
# raporlarda), ReportLab'in standart iki-gecisli (two-pass) NumberedCanvas
# teknigini kullaniyoruz.
# ---------------------------------------------------------------------------
class NumberedCanvas(pdfcanvas.Canvas):
    def __init__(self, *args, **kwargs):
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []
        self._generated_at = time.strftime("%d.%m.%Y %H:%M")

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total_pages)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_footer(self, total_pages):
        self.setFont(FONT_NAME, 8)
        self.setFillColor(colors.HexColor(COLOR_GREY_LIGHT))
        page_width = A4[0]
        # Sol alt: uretim tarihi
        self.drawString(1.5 * cm, 1 * cm, f"Üretim: {self._generated_at}")
        # Sag alt: sayfa numarasi
        self.drawRightString(
            page_width - 1.5 * cm, 1 * cm,
            f"Sayfa {self._pageNumber}/{total_pages}",
        )


# ---------------------------------------------------------------------------
# Renk paleti: koyu teal (siber guvenlik/endpoint security urunlerinde
# yaygin kullanilan bir renk ailesi - CrowdStrike, Darktrace gibi urunler
# de benzer tonlar kullanir).
# ---------------------------------------------------------------------------
COLOR_PRIMARY = "#0F3D3E"       # koyu teal - basliklar, tablo header
COLOR_PRIMARY_LIGHT = "#E4F1F0"  # acik teal tonu - tablo zebra satirlari
COLOR_ACCENT = "#1F7A6C"        # orta teal - alt basliklar/vurgular
COLOR_GREY = "#666666"          # meta bilgi metni
COLOR_GREY_LIGHT = "#999999"    # altbilgi


# ---------------------------------------------------------------------------
# Logo/rozet: SentinEL icin basit, vektorel bir kalkan rozeti cizer -
# harici gorsel dosyasina ihtiyac yok, PyInstaller derlemesinde ekstra
# dosya eklemeye gerek kalmaz, her zaman ayni netlikte gorunur.
# ---------------------------------------------------------------------------
def _make_shield_logo(size=42) -> Drawing:
    d = Drawing(size, size)
    primary = colors.HexColor(COLOR_PRIMARY)
    accent = colors.HexColor(COLOR_ACCENT)

    w, h = size, size
    shield_points = [
        w * 0.5, h * 0.98,
        w * 0.92, h * 0.80,
        w * 0.92, h * 0.42,
        w * 0.5, h * 0.02,
        w * 0.08, h * 0.42,
        w * 0.08, h * 0.80,
    ]
    d.add(Polygon(shield_points, fillColor=primary, strokeColor=None))

    inner_points = [
        w * 0.5, h * 0.90,
        w * 0.82, h * 0.75,
        w * 0.82, h * 0.45,
        w * 0.5, h * 0.10,
        w * 0.18, h * 0.45,
        w * 0.18, h * 0.75,
    ]
    d.add(Polygon(inner_points, fillColor=None, strokeColor=accent, strokeWidth=1))

    d.add(String(
        w * 0.5, h * 0.36, "S",
        fontName=FONT_NAME_BOLD, fontSize=size * 0.42,
        fillColor=colors.white, textAnchor="middle",
    ))
    return d

# reporter.py — _make_shield_logo fonksiyonundan sonra
def _make_seal_image(size_cm=2.8):
    """
    Sag ust kosede 'onay muhru' gibi duran, projeye eklenen ozel logo.
    Dosya bulunamazsa (assets/ eksikse) sessizce bos bir hucre doner,
    PDF uretimi hata vermez.
    """
    if SEAL_LOGO_PATH.exists():
        return Image(str(SEAL_LOGO_PATH), width=size_cm * cm, height=size_cm * cm)
    return ""




# ---------------------------------------------------------------------------
# PDF uretimi
# ---------------------------------------------------------------------------
def build_pdf_report(detections: list, meta: dict, output_path: Path) -> Path:
    """
    detections: SADECE zararli cikan dosyalar -
                [{"file_name":.., "location":.., "threat_label":..}, ...]
    meta: {"computer_name":.., "user":.., "system_uptime":.., "service_uptime":..,
           "os_version":.., "report_range":.., "total_scanned":..}
    """
    output_path.parent.mkdir(exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        leftMargin=1.5 * cm, rightMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontName=FONT_NAME_BOLD,
        fontSize=18, textColor=colors.HexColor(COLOR_PRIMARY), spaceAfter=4, alignment=0,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], fontName=FONT_NAME,
        fontSize=11, textColor=colors.HexColor(COLOR_GREY), spaceAfter=18, alignment=0,
    )
    info_style = ParagraphStyle(
        "InfoBlock", parent=styles["Normal"], fontName=FONT_NAME, fontSize=10, leading=16, alignment=0,
    )
    heading_style = ParagraphStyle(
        "SectionHeading", parent=styles["Heading2"], fontName=FONT_NAME_BOLD,
        fontSize=13, textColor=colors.HexColor(COLOR_PRIMARY), spaceBefore=10, spaceAfter=8, alignment=0,
    )

    elements = []

    # Logo + baslik yan yana (tek satirlik, kenarliksiz bir tablo ile hizalaniyor)
    title_block = [
        Paragraph("<b>SentinEL Endpoint Security</b>", title_style),
        Paragraph(
            f"Son Bir Saatlik Güvenlik Raporu &nbsp;|&nbsp; {meta.get('report_range', '')}",
            subtitle_style,
        ),
    ]
    header_table = Table(
        [[_make_shield_logo(42), title_block, _make_seal_image()]],
        colWidths=[1.6 * cm, None, 3.2 * cm],
    )
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 8),
        ("ALIGN", (2, 0), (2, 0), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 0.5 * cm))

    info_lines = [
        f"<b>Bilgisayar Adı:</b> {meta.get('computer_name', '-')}",
        f"<b>Kullanıcı:</b> {meta.get('user', '-')}",
        f"<b>Sistem Uptime:</b> {meta.get('system_uptime', '-')}",
        f"<b>Servis Çalışma Süresi:</b> {meta.get('service_uptime', '-')}",
        f"<b>İşletim Sistemi:</b> {meta.get('os_version', '-')}",
        f"<b>Rapor Aralığı:</b> {meta.get('report_range', '-')}",
        f"<b>Bu Aralıkta Taranan Dosya:</b> {meta.get('total_scanned', 0)}",
    ]
    for line in info_lines:
        elements.append(Paragraph(line, info_style))

    elements.append(Spacer(1, 0.6 * cm))
    elements.append(Paragraph(f"<b>Tespit Edilen Tehditler ({len(detections)} adet)</b>", heading_style))

    if detections:
        table_data = [["Dosya Adı", "Dosya Konumu", "Zararlı Türü"]]
        for d in detections:
            table_data.append([
                Paragraph(d.get("file_name", "-"), info_style),
                Paragraph(d.get("location", "-"), info_style),
                Paragraph(d.get("threat_label", "-"), info_style),
            ])

        table = Table(table_data, colWidths=[4 * cm, 8 * cm, 5 * cm], repeatRows=1)
        table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), FONT_NAME_BOLD),
            ("FONTNAME", (0, 1), (-1, -1), FONT_NAME),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(COLOR_PRIMARY)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
            ("TOPPADDING", (0, 1), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D4E4E3")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(COLOR_PRIMARY_LIGHT)]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(table)
    else:
        elements.append(Paragraph("Bu aralıkta zararlı dosya tespit edilmedi.", info_style))

    doc.build(elements, canvasmaker=NumberedCanvas)
    return output_path


# ---------------------------------------------------------------------------
# E-posta gonderimi (Gmail SMTP + App Password, port 587/STARTTLS)
# ---------------------------------------------------------------------------
def send_email_with_attachment(pdf_path: Path, subject: str, config: dict) -> bool:
    """
    .env icindeki SMTP_EMAIL / SMTP_APP_PASSWORD ile Gmail uzerinden
    PDF eklentili mail gonderir. Basarili olursa True, HATA DURUMUNDA
    EXCEPTION FIRLATMAZ - False doner (cagiran taraf servisi cokertmeden
    yakalayabilsin diye).
    """
    sender = os.getenv("SMTP_EMAIL")
    app_password = os.getenv("SMTP_APP_PASSWORD")
    recipient = config.get("report_recipient_email") or sender

    if not sender or not app_password:
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(
            "Ekte SentinEL Endpoint Security'nin son bir saatlik guvenlik raporu bulunmaktadir.",
            "plain",
        ))

        with open(pdf_path, "rb") as f:
            part = MIMEApplication(f.read(), _subtype="pdf")
            part.add_header("Content-Disposition", "attachment", filename=pdf_path.name)
            msg.attach(part)

        context = ssl.create_default_context()
        # Port 587 + STARTTLS: bazi kurumsal aglarda 465 (SMTP_SSL) firewall
        # tarafindan engellenebiliyor, 587 daha esnek kabul ediliyor.
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(sender, app_password)
            server.sendmail(sender, recipient, msg.as_string())

        return True

    except Exception:
        return False