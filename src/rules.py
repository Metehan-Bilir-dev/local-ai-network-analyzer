CRITICAL_RULES = {
    1524: "Parolasız root shell (bindshell)",
    6667: "UnrealIRCd: bilinen arka kapılı sürümler var, sürümü doğrula",
    23: "Telnet: şifreler düz metin gider",
}

VERSION_RULES = [
    ("vsftpd", "2.3.4", "vsftpd 2.3.4 içinde bilinen arka kapı var (CVE-2011-2523)"),
]


def apply_rules(parsed):
    """Her porta kural bulgularını 'rule_findings' olarak ekler."""
    for host in parsed["hosts"]:
        for p in host["ports"]:
            hits = []

            if p["port"] in CRITICAL_RULES:
                hits.append(CRITICAL_RULES[p["port"]])

            software = f"{p.get('product') or ''} {p.get('version') or ''}".lower()
            for name, version, message in VERSION_RULES:
                if name in software and version in software:
                    hits.append(message)

            if hits:
                p["rule_findings"] = hits