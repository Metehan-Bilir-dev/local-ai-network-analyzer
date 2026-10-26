import json
import os
import argparse
from datetime import datetime
from scanner import NetworkScanner
from parser import parse_scan_result
from ai_client import LocalAI
from cve_lookup import CVELookup
from rules import apply_rules
from reporter import generate_pdf

SCAN_PROFILES = {
    "1": {
        "label": "Hızlı Tarama",
        "description": "Sadece yaygın portlar, hızlı sonuç",
        "options": {"fast": True}
    },
    "2": {
        "label": "Normal Tarama",
        "description": "Standart port aralığı, versiyon tespiti",
        "options": {}
    },
    "3": {
        "label": "Zafiyet Taraması",
        "description": "Bilinen zafiyetleri kontrol eder (--script=vuln), daha yavaş",
        "options": {"vuln_scan": True}
    },
    "4": {
        "label": "Kapsamlı Tarama",
        "description": "OS tespiti + zafiyet taraması, en detaylı ama en yavaş",
        "options": {"os_detect": True, "vuln_scan": True}
    },
    "5": {
        "label": "Tüm Portları Tara",
        "description": "65535 portun tamamı, çok yavaş olabilir",
        "options": {"deep": True}
    },
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Yerel Ağ Zafiyet Analiz ve Raporlama Aracı"
    )
    parser.add_argument("--target", default=None, help="Doğrudan taranacak hedef IP (verilirse keşif atlanır).")
    parser.add_argument("--subnet", default=None, help="Keşif için subnet.")
    parser.add_argument(
        "--format", choices=["json", "txt", "pdf"], default="json",
        help="Çıktı formatı (varsayılan: json)"
    
    )
    parser.add_argument("--ai", action="store_true", help="Tarama sonrası AI analizi yap.")
    return parser.parse_args()


def discover_and_select(scanner, subnet):
    print(f"Ağ taranıyor: {subnet or 'otomatik tespit edilecek'} ...")
    hosts = scanner.discover_hosts(subnet)

    if not hosts:
        print("Hiç canlı host bulunamadı.")
        return None

    print("\nBulunan cihazlar:\n")
    for idx, host in enumerate(hosts, start=1):
        print(f"  {idx}. {host['ip']}  ({host['hostname']})")

    while True:
        choice = input("\nTaramak istediğin cihazın numarasını gir: ")
        if choice.isdigit() and 1 <= int(choice) <= len(hosts):
            return hosts[int(choice) - 1]["ip"]
        print("Geçersiz seçim, tekrar dene.")


def select_scan_profile():
    print("\nTarama tipini seç:\n")
    for key, profile in SCAN_PROFILES.items():
        print(f"  {key}. {profile['label']} — {profile['description']}")

    while True:
        choice = input("\nSeçimin: ")
        if choice in SCAN_PROFILES:
            return SCAN_PROFILES[choice]
        print("Geçersiz seçim, tekrar dene.")

def has_finding(script_output):
    """Script çıktılarında gerçek bir bulgu var mı kontrol eder."""
    clean_phrases = [
        "couldn't find",
        "could not find",
        "no vulnerabilities",
        "not vulnerable",
        "no reply from server",
        "timeout"
    ]
    for output in script_output.values():
        text = output.lower()
        if not any(phrase in text for phrase in clean_phrases):
            return True
    return False

def ask_yes_no(question):
    while True:
        answer = input(f"{question} (e/h): ").strip().lower()
        if answer in ("e", "evet", "y", "yes"):
            return True
        if answer in ("h", "hayır", "hayir", "n", "no"):
            return False
        print("Lütfen 'e' veya 'h' gir.")

def enrich_with_cves(parsed):
    cache_dir = os.path.join(os.path.dirname(__file__), "..", "cve_cache")
    lookup = CVELookup(cache_dir)

    for host in parsed["hosts"]:
        for p in host["ports"]:
            cves = lookup.lookup(p.get("cpe"))
            if cves:
                p["cves"] = cves


def print_cves(parsed):
    found = False
    for host in parsed["hosts"]:
        for p in host["ports"]:
            for cve in p.get("cves", []):
                if not found:
                    print("\n--- CVE Eşleşmeleri (NVD) ---")
                    found = True
                print(f"  [{p['port']}] {cve['id']}  CVSS: {cve['cvss']}")
    if not found:
        print("\nCVE eşleşmesi yok: sürüm bilgisi çıkarılamadığı için sorgulanamayan servisler olabilir.")


def print_summary(parsed):
    for host in parsed["hosts"]:
        print(f"\n=== {host['host']} ===")

        if not host["ports"]:
            print("Açık port bulunamadı.")
            print("(Not: Firewall portları filtreliyor olabilir.)")
            continue

        findings = []
        for p in host["ports"]:
            print(f"  {p['port']}/{p['protocol']}  {p['service']}  {p.get('product') or ''} {p.get('version') or ''}".rstrip())
            for hit in p.get("rule_findings", []):
                print(f"    [KURAL] {hit}")
            scripts = p.get("script_output", {})
            if scripts and has_finding(scripts):
                for name, output in scripts.items():
                    findings.append((p["port"], name, output.strip()))

        if findings:
            print("\nBulgular:")
            for port, name, output in findings:
                print(f"  [{port}] {name}: {output}")
        elif any(p.get("script_output") for p in host["ports"]):
            print("\nScript taraması bulgu üretmedi.")
        else:
            print("\nZafiyet script'leri çalıştırılmadı; bu 'zafiyet yok' anlamına gelmez.")
def write_scan_log(parsed, timestamp):
    log_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "scan_text")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"scan_{timestamp}.txt")

    lines = []
    for host in parsed["hosts"]:
        lines.append(f"=== {host['host']} ===")

        if not host["ports"]:
            lines.append("Açık port bulunamadı.")
            lines.append("(Not: Firewall portları filtreliyor olabilir.)")
            continue

        findings = []
        for p in host["ports"]:
            lines.append(f"  {p['port']}/{p['protocol']}  {p['service']}  {p.get('product') or ''} {p.get('version') or ''}".rstrip())
            for hit in p.get("rule_findings", []):
                lines.append(f"    [KURAL] {hit}")
            scripts = p.get("script_output", {})
            if scripts and has_finding(scripts):
                for name, output in scripts.items():
                    findings.append((p["port"], name, output.strip()))

        if findings:
            lines.append("\nBulgular:")
            for port, name, output in findings:
                lines.append(f"  [{port}] {name}: {output}")
        elif any(p.get("script_output") for p in host["ports"]):
            lines.append("\nScript taraması bulgu üretmedi.")
        else:
            lines.append("\nZafiyet script'leri çalıştırılmadı; bu 'zafiyet yok' anlamına gelmez.")

        lines.append("")

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return log_path


def write_ai_log(ai_result, timestamp):
    log_dir = os.path.join(os.path.dirname(__file__), "..", "logs", "ai_text")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"ai_analysis_{timestamp}.txt")

    lines = [f"Özet: {ai_result.get('summary', '')}", ""]

    findings = ai_result.get("findings", [])
    if not findings:
        lines.append("AI herhangi bir bulgu raporlamadı.")
    else:
        for finding in findings:
            lines.append(f"[{finding.get('severity', '?').upper()}] Port {finding.get('port')} - {finding.get('service')}")
            lines.append(f"  Sebep: {finding.get('reason')}")
            lines.append(f"  Öneri: {finding.get('recommendation')}")
            lines.append("")

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return log_path
def enforce_rule_severity(ai_result, parsed):
    """Kural ve CVSS'e göre önem derecesine alt sınır koyar."""
    order = ["low", "medium", "high", "critical"]
    floors = {}
    for h in parsed["hosts"]:
        for p in h["ports"]:
            floor = None
            top = max((c.get("cvss") or 0 for c in p.get("cves", [])), default=0)
            if p.get("rule_findings") or top >= 9.0:
                floor = "high"
            elif top >= 7.0:
                floor = "medium"
            if floor:
                floors[p["port"]] = floor

    for f in ai_result.get("findings", []):
        floor = floors.get(f.get("port"))
        if floor:
            current = str(f.get("severity", "low")).lower()
            if current not in order or order.index(current) < order.index(floor):
                f["severity"] = floor
def main():
    args = parse_args()
    scanner = NetworkScanner()

    # 1. Hedef seçimi
    target = args.target
    if target is None:
        target = discover_and_select(scanner, args.subnet)
        if target is None:
            return

    # 2. Tarama tipi seçimi
    profile = select_scan_profile()
    nmap_args = scanner.build_arguments(**profile["options"])

    print(f"\n[{profile['label']}] başlıyor: {target} ({nmap_args})")
    if profile["options"].get("vuln_scan") or profile["options"].get("deep"):
        print("(Bu tür taramalar birkaç dakika sürebilir, lütfen bekle)")

    try:
        result = scanner.scan(target, arguments=nmap_args)
    except Exception as e:
        error_msg = str(e)
        if "root privileges" in error_msg or "requires root" in error_msg:
            print("\nUYARI: Bu tarama türü root yetkisi gerektiriyor.")
            print("Programı şu şekilde tekrar çalıştır: sudo -E .venv/bin/python src/main.py")
        else:
            print(f"Tarama hatası: {error_msg}")
        return

    parsed = parse_scan_result(result)
    apply_rules(parsed)
    

    if ask_yes_no("\nNVD'de CVE araması yapılsın mı? (sadece ürün/sürüm gönderilir, IP gönderilmez)"):
        print("CVE'ler sorgulanıyor (her yeni servis için birkaç saniye sürebilir)...")
        enrich_with_cves(parsed)
        print_cves(parsed)


    scans_dir = os.path.join(os.path.dirname(__file__), "..", "scans")
    os.makedirs(scans_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    filename = os.path.join(scans_dir, f"scan_{timestamp}.json")

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=4, ensure_ascii=False)

    print(f"\nSonuç kaydedildi: {filename}")
    print_summary(parsed)

    scan_log_path = write_scan_log(parsed, timestamp)
    print(f"Tarama log dosyası: {scan_log_path}")
    
    ai_result = None
    run_ai = args.ai or ask_yes_no("\nAI ile özetlemek ister misiniz?")

    if run_ai:
        print("\n--- AI Analizi ---")
        print("Model analiz ediyor, lütfen bekle...")

        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
        with open(config_path) as f:
            config = json.load(f)

        ai = LocalAI(config["ai_api_url"], config["ai_model"])
        ai_result = ai.analyze(parsed)

        if "error" not in ai_result:
            enforce_rule_severity(ai_result, parsed)

        if "error" in ai_result:
            print(f"\nAI analiz hatası: {ai_result['error']}")
        else:
            print(f"\nÖzet: {ai_result.get('summary', '')}\n")

            findings = ai_result.get("findings", [])
            if not findings:
                print("AI herhangi bir bulgu raporlamadı.")
            else:
                for finding in findings:
                    print(f"[{finding.get('severity', '?').upper()}] Port {finding.get('port')} - {finding.get('service')}")
                    print(f"  Sebep: {finding.get('reason')}")
                    print(f"  Öneri: {finding.get('recommendation')}\n")

            reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
            os.makedirs(reports_dir, exist_ok=True)

            ai_filename = os.path.join(reports_dir, f"ai_analysis_{timestamp}.json")
            with open(ai_filename, "w", encoding="utf-8") as f:
                json.dump(ai_result, f, indent=4, ensure_ascii=False)
            print(f"AI analizi kaydedildi: {ai_filename}")

            ai_log_path = write_ai_log(ai_result, timestamp)
            print(f"AI log dosyası: {ai_log_path}")
       
        if ask_yes_no("\nPDF rapor oluşturulsun mu?"):
                pdf_dir = os.path.join(os.path.dirname(__file__), "..", "reports", "pdf")
        try:
            pdf_path = generate_pdf(parsed, ai_result, timestamp, pdf_dir)
            print(f"PDF rapor kaydedildi: {pdf_path}")
        except Exception as e:
            print(f"PDF oluşturulamadı: {e}")

if __name__ == "__main__":
    main()