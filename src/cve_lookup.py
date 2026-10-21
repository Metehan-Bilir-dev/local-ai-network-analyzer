import json
import os
import time

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def cpe22_to_cpe23(cpe):
    """nmap 'cpe:/a:vendor:product:version' verir, NVD 2.3 formatı ister.
    Sürüm yoksa None döner (sürümsüz CPE ile arama anlamsız)."""
    if not cpe or not cpe.startswith("cpe:/"):
        return None
    parts = cpe[5:].split(":")
    if len(parts) < 4 or not parts[3]:
        return None
    parts += ["*"] * (11 - len(parts))
    return "cpe:2.3:" + ":".join(parts[:11])


class CVELookup:

    def __init__(self, cache_dir, delay=6.5):
        self.cache_dir = cache_dir
        self.delay = delay  # API anahtarsız: 30 sn'de 5 istek
        os.makedirs(cache_dir, exist_ok=True)

    def _cache_path(self, cpe23):
        safe = cpe23.replace(":", "_").replace("*", "x").replace("/", "_")
        return os.path.join(self.cache_dir, safe + ".json")

    def lookup(self, cpe, limit=5):
        cpe23 = cpe22_to_cpe23(cpe)
        if cpe23 is None:
            return []

        path = self._cache_path(cpe23)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return json.load(f)[:limit]

        try:
            response = requests.get(
                NVD_URL,
                params={"cpeName": cpe23, "isVulnerable": ""},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
        except (requests.RequestException, ValueError) as e:
            print(f"  [NVD hata] {cpe23}: {e}")
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            description = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "",
            )
            cves.append({
                "id": cve["id"],
                "cvss": self._best_score(cve),
                "description": description[:300],
            })

        cves.sort(key=lambda c: c["cvss"] or 0, reverse=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(cves, f, indent=2, ensure_ascii=False)

        time.sleep(self.delay)
        return cves[:limit]

    @staticmethod
    def _best_score(cve):
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                return metrics[key][0]["cvssData"]["baseScore"]
        return None