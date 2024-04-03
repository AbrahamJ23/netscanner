import argparse
import nmap
import scapy.all as scapy
import socket
from tabulate import tabulate

def scan(ip, adapter):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, iface=adapter, verbose=False)[0]
    results = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]
    return results

def display_results(results):
    data = [[result["ip"], result["mac"]] for result in results]
    print(tabulate(data, headers=["IP Address", "MAC Address"], tablefmt="fancy_grid"))

def scan_ports(ip, port_range):
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def detect_os(target_ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, arguments='-O')
        os_match = nm[target_ip]['osmatch']
        if os_match:
            detected_os = os_match[0]['osclass'][0]['osfamily']
            return detected_os
        else:
            return "Besturingssysteem niet gedetecteerd"
    except nmap.nmap.PortScannerError:
        return "Er is een fout opgetreden bij het scannen"
    except Exception as e:
        return f"Fout: {str(e)}"

def get_hostname(ip):
    hostname = "-"
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except:
        pass
    return hostname



def display_open_ports(ip, open_ports):
    data = [[ip, port] for port in open_ports]
    print(tabulate(data, headers=["IP Address", "Open Port"], tablefmt="fancy_grid"))

def display_os(ip, detected_os):
    print(f"OS van {ip}: {detected_os}")

def scan_services(ip, ports):
    nm = nmap.PortScanner()
    port_str = ','.join(map(str, ports))
    nm.scan(hosts=ip, arguments=f'-p {port_str} -sV')

    service_results = []
    for port in ports:
        service_info = nm[ip]['tcp'].get(port, {})
        service_name = service_info.get('name', '-')
        service_version = service_info.get('product', '-') + " " + service_info.get('version', '-')
        if service_name != '-' or service_version != '-':  # Filter lege waarden
            service_results.append((service_name, service_version))

    return service_results



def main():
    parser = argparse.ArgumentParser(description="Netwerkscanner met optionele OS-detectie en poortscanning.")
    parser.add_argument("ip", help="Del-IP-adres of IP-bereik (CIDR-notatie)")
    parser.add_argument("adapter", help="Naam van de Ethernet-adapter")
    parser.add_argument("--ports", type=int, nargs=2, help="Poorten om te scannen (bijv. --ports 20 80) poorten 20 t/m 80")
    parser.add_argument("--osdetect", action="store_true", help="Voer OS-detectie uit")
    parser.add_argument("--services", action="store_true", help="Voer servicescan uit")

    args = parser.parse_args()

    scan_results = scan(args.ip, args.adapter)

    combined_results = []

    for result in scan_results:
        row = [result["ip"], result.get("mac", "N/A")]

        if args.ports:
            open_ports = scan_ports(result["ip"], args.ports)
            row.append(open_ports)
        else:
            row.append("No open ports")

        if args.osdetect:
            os_result = detect_os(result["ip"])
            row.append(os_result)

        if args.services:
            service_result = scan_services(result["ip"], args.ports)
            row.append(service_result)

        combined_results.append(row)

    headers = ["IP Address", "MAC Address", "Open Ports", "OS", "Service Name", "Service Version"]

    print(tabulate(combined_results, headers=headers, tablefmt="fancy_grid"))

if __name__ == "__main__":
    main()


