def parse_scan_result(scan_result):
    parsed = {
        "hosts": []
    }

    for host in scan_result.all_hosts():
        host_data = {
            "host": host,
            "state": scan_result[host].state(),
            "ports": []
        }

        for protocol in scan_result[host].all_protocols():
            ports = scan_result[host][protocol].keys()

            for port in sorted(ports):
                service = scan_result[host][protocol][port]

                if service.get("state") != "open":
                    continue

                port_data = {
                    "port": port,
                    "protocol": protocol,
                    "state": service.get("state"),
                    "service": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "cpe": service.get("cpe")
                }
                

                if "script" in service:
                    # "execution failed" / "ERROR" içeren script sonuçlarını ele
                    clean_scripts = {
                        name: output
                        for name, output in service["script"].items()
                        if "ERROR" not in output and "failed" not in output.lower()
                    }
                    if clean_scripts:
                        port_data["script_output"] = clean_scripts

                host_data["ports"].append(port_data)

        parsed["hosts"].append(host_data)

    return parsed