import os
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
)

ASSET_FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "fonts")

FONT_DIRS = [
    ASSET_FONT_DIR,
    "/usr/share/fonts/TTF", 
    "/usr/share/fonts/dejavu", 
    "/usr/share/fonts/truetype/dejavu",
    "C:\\Windows\\Fonts", 
    "/Library/Fonts",
    "/System/Library/Fonts"
]

SEVERITY_COLORS = {
    "critical": colors.HexColor("#7b0000"),
    "high": colors.HexColor("#c0392b"),
    "medium": colors.HexColor("#e67e22"),
    "low": colors.HexColor("#2e8b57"),
}

def _register_fonts():
    for d in FONT_DIRS:
        regular = os.path.join(d, "DejaVuSans.ttf")
        bold = os.path.join(d, "DejaVuSans-Bold.ttf")
        if os.path.exists(regular) and os.path.exists(bold):
            pdfmetrics.registerFont(TTFont("DejaVu", regular))
            pdfmetrics.registerFont(TTFont("DejaVu-Bold", bold))
            return "DejaVu", "DejaVu-Bold"

    print("UYARI: DejaVu fontu bulunamadı, Türkçe karakterler PDF'te bozuk görünebilir (assets/fonts/ içine koy).")
    return "Helvetica", "Helvetica-Bold"

def _p(text, style):
    return Paragraph(escape(str(text)), style)

def generate_pdf(parsed, ai_result, timestamp, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"rapor_{timestamp}.pdf")

    font, font_bold = _register_fonts()
    base = getSampleStyleSheet()
    normal = ParagraphStyle("n", parent=base["Normal"], fontName=font, fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=normal, fontSize=8, leading=10)
    sev_white = ParagraphStyle("sw", parent=small, textColor=colors.white, fontName=font_bold)
    h1 = ParagraphStyle("h1", parent=normal, fontName=font_bold, fontSize=18, leading=22, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=normal, fontName=font_bold, fontSize=12, leading=16, spaceBefore=12, spaceAfter=6)

    doc = SimpleDocTemplate(
        path, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm, title="Ağ Güvenlik Raporu",
    )
    story = []

    story.append(_p("Yerel Ağ Güvenlik Analiz Raporu", h1))
    story.append(_p(f"Oluşturma tarihi: {datetime.now().strftime('%d.%m.%Y %H:%M')}", normal))
    story.append(_p("Analiz tamamen yerel çalışan bir dil modeliyle yapılmıştır.", small))

    ai_findings = {}
    for f in (ai_result or {}).get("findings", []):
        ai_findings[f.get("port")] = f

    for host in parsed["hosts"]:
        story.append(_p(f"Hedef: {host['host']}", h2))

        if not host["ports"]:
            story.append(_p("Açık port bulunamadı (firewall filtreliyor olabilir).", normal))
            continue

        rows = [[_p("Port", small), _p("Servis", small), _p("Yazılım / Sürüm", small), _p("Önem", small)]]
        for p in host["ports"]:
            software = f"{p.get('product') or ''} {p.get('version') or ''}".strip()
            sev = str(ai_findings.get(p["port"], {}).get("severity", "-")).lower()
            rows.append([
                _p(f"{p['port']}/{p['protocol']}", small),
                _p(p.get("service") or "", small),
                _p(software, small),
                _p(sev.upper() if sev != "-" else "-", sev_white if sev in SEVERITY_COLORS else small),
            ])
        table = Table(rows, colWidths=[2.2 * cm, 3 * cm, 8 * cm, 2.8 * cm], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dddddd")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for i, p in enumerate(host["ports"], start=1):
            sev = str(ai_findings.get(p["port"], {}).get("severity", "")).lower()
            if sev in SEVERITY_COLORS:
                style.append(("BACKGROUND", (3, i), (3, i), SEVERITY_COLORS[sev]))
        table.setStyle(TableStyle(style))
        story.append(table)

        story.append(_p("Bulgu Ayrıntıları", h2))
        for p in host["ports"]:
            f = ai_findings.get(p["port"])
            rules = p.get("rule_findings", [])
            cves = p.get("cves", [])
            if not (f or rules or cves):
                continue

            story.append(_p(f"Port {p['port']} - {p.get('service') or ''}", ParagraphStyle(
                "ph", parent=normal, fontName=font_bold, spaceBefore=6)))
            for r in rules:
                story.append(_p(f"[KURAL] {r}", normal))
            if cves:
                ids = ", ".join(f"{c['id']} (CVSS {c['cvss']})" for c in cves)
                story.append(_p(f"NVD eşleşmeleri: {ids}", normal))
            if f:
                reason = str(f.get("reason", ""))
                if reason not in rules:
                    story.append(_p(f"Sebep: {reason}", normal))
                story.append(_p(f"Öneri: {f.get('recommendation', '')}", normal))

    story.append(_p("Sınırlamalar", h2))
    for note in [
        "AI yorumları küçük bir yerel modelden gelir; hata içerebilir, kritik kararlardan önce doğrulanmalıdır.",
        "CVE listesi her servis için CVSS'e göre ilk 5 kayıttır ve sürüm eşleşmesi doğrulanmamış olası eşleşmelerdir.",
        "Sürümü belirsiz servisler (örn. aralık olarak bildirilenler) için CVE sorgulanamamıştır.",
        "Zafiyet script'leri çalıştırılmadıysa 'bulgu yok' sonucu 'güvenli' anlamına gelmez.",
        "Bu araç yalnızca sahibi olduğunuz veya izin aldığınız sistemlerde kullanılmalıdır.",
        "Önerilen minimum sürümler model tahminidir, resmi kaynaktan doğrulanmalıdır.",
    ]:
        story.append(_p("• " + note, small))

    doc.build(story)
    return path
