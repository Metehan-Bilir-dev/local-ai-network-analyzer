import json
import os
from datetime import datetime

from scanner import NetworkScanner
from parser import parse_scan_result
from rules import apply_rules
from ai_client import LocalAI
from cve_lookup import CVELookup
from reporter import generate_pdf
from main import (
    BASE_DIR,
    SCAN_PROFILES,
    sanitize_ai_output,
    enforce_rule_severity,
    build_summary,
    write_scan_log,
    write_ai_log,
)


def discover(subnet=None):
    """Canlı hostları döndürür: [{'ip': ..., 'hostname': ...}]"""
    scanner = NetworkScanner()
    return scanner.discover_hosts(subnet or None)


def scan(target, profile_key):
    """Seçilen profille tarar, kuralları uygular, parsed sonucu döndürür."""
    scanner = NetworkScanner()
    profile = SCAN_PROFILES[profile_key]
    nmap_args = scanner.build_arguments(**profile["options"])
    result = scanner.scan(target, arguments=nmap_args)
    parsed = parse_scan_result(result)
    apply_rules(parsed)
    return parsed


def add_cves(parsed):
    lookup = CVELookup(os.path.join(BASE_DIR, "cve_cache"))
    for host in parsed["hosts"]:
        for p in host["ports"]:
            cves = lookup.lookup(p.get("cpe"))
            if cves:
                p["cves"] = cves


def analyze(parsed):
    """(ai_result, silinen_cve_sayisi, hata) döndürür."""
    try:
        config_path = os.path.join(BASE_DIR, "config", "config.json")
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
        ai = LocalAI(config["ai_api_url"], config["ai_model"])
        result = ai.analyze(parsed)
    except Exception as e:
        return None, 0, str(e)

    if "error" in result:
        return None, 0, result["error"]

    removed = sanitize_ai_output(result, parsed)
    enforce_rule_severity(result, parsed)
    result["summary"] = build_summary(result.get("findings", []))
    return result, removed, None


def save(parsed, ai_result=None, make_pdf=False):
    """Çıktıları kaydeder, yolları sözlük olarak döndürür."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    paths = {}

    scans_dir = os.path.join(BASE_DIR, "scans")
    os.makedirs(scans_dir, exist_ok=True)
    paths["scan"] = os.path.join(scans_dir, f"scan_{timestamp}.json")
    with open(paths["scan"], "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=4, ensure_ascii=False)
    paths["scan_log"] = write_scan_log(parsed, timestamp)

    if ai_result:
        reports_dir = os.path.join(BASE_DIR, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        paths["ai"] = os.path.join(reports_dir, f"ai_analysis_{timestamp}.json")
        with open(paths["ai"], "w", encoding="utf-8") as f:
            json.dump(ai_result, f, indent=4, ensure_ascii=False)
        paths["ai_log"] = write_ai_log(ai_result, timestamp)

    if make_pdf:
        pdf_dir = os.path.join(BASE_DIR, "reports", "pdf")
        paths["pdf"] = generate_pdf(parsed, ai_result, timestamp, pdf_dir)

    return paths