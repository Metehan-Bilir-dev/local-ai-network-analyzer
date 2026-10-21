import json
import os
from ai_client import LocalAI

# Script'in kendi konumuna göre config dosyasını bul (çalıştırıldığı yerden bağımsız)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(BASE_DIR, "..", "config", "config.json")

with open(config_path) as f:
    config = json.load(f)

ai = LocalAI(config["ai_api_url"], config["ai_model"])

sample_data = {
    "hosts": [
        {
            "host": "192.168.0.1",
            "state": "up",
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "tcpwrapped",
                    "product": "",
                    "version": "",
                    "script_output": {
                        "http-csrf": "Found the following possible CSRF vulnerabilities: Path: http://192.168.0.1:80/ Form id: logintitle Form action: /goform/login"
                    }
                }
            ]
        }
    ]
}

result = ai.analyze(sample_data)
print(json.dumps(result, indent=4, ensure_ascii=False))