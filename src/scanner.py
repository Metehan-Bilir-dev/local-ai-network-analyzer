import nmap
import socket
import ipaddress


class NetworkScanner:

    def __init__(self):
        self.scanner = nmap.PortScanner()

    def get_local_subnet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()

        network = ipaddress.ip_interface(f"{local_ip}/24").network
        return str(network)

    def discover_hosts(self, subnet=None):
        if subnet is None:
            subnet = self.get_local_subnet()

        self.scanner.scan(hosts=subnet, arguments="-sn")

        hosts = []
        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == "up":
                hostname = self.scanner[host].hostname()
                hosts.append({
                    "ip": host,
                    "hostname": hostname if hostname else "bilinmiyor"
                })

        return hosts

    def build_arguments(self, ports=None, deep=False, os_detect=False, vuln_scan=False, fast=False):
        args = ["-sV"]

        if ports:
            args.append(f"-p {ports}")
        elif deep:
            args.append("-p-") 

        if os_detect:
            args.append("-O")

        if vuln_scan:
            args.append("--script=vuln")

        if fast:
            args.append("-T4")

        return " ".join(args)

    def scan(self, target, arguments="-sV"):
        self.scanner.scan(hosts=target, arguments=arguments)
        return self.scanner