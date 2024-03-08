import argparse
import nmap
import scapy.all as scapy
import socket

def scan(ip, adapter):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, iface=adapter, verbose=False)[0]
    results = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]
    return results

def display_results(results):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for result in results:
        print(result["ip"] + "\t\t" + result["mac"])

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

def scan_services(ip, ports):
    nm = nmap.PortScanner()
    port_str = ','.join(map(str, ports))
    nm.scan(hosts=ip, arguments=f'-p {port_str} -sV')

    for port in ports:
        service_info = nm[ip]['tcp'][port]
        print(f"IP: {ip}, Poort: {port}, Service: {service_info['name']}, Versie: {service_info['version']}")

def display_open_ports(ip, open_ports):
    print(f"Open poorten op {ip}: {open_ports}")

def display_os(ip, open_ports):
    print(f"OS van {ip}: {open_ports}")

def main():
    parser = argparse.ArgumentParser(description="Netwerkscanner met optionele OS-detectie en poortscanning.")
    parser.add_argument("ip", help="Doel-IP-adres of IP-bereik (CIDR-notatie)")
    parser.add_argument("adapter", help="Naam van de Ethernet-adapter")
    parser.add_argument("--ports", type=int, nargs=2, help="Poorten om te scannen (bijv. --ports 20 80) poorten 20 t/m 80")
    parser.add_argument("--osdetect", action="store_true", help="Voer OS-detectie uit")
    parser.add_argument("--services", action="store_true", help="Voer servicescan uit")

    args = parser.parse_args()

    scan_results = scan(args.ip, args.adapter)
    display_results(scan_results)

    if args.osdetect:
        for result in scan_results:
            os_network = detect_os(result["ip"])
            display_os(result["ip"], os_network)
    
    if args.services and args.ports:
        for result in scan_results:
            scan_services(result["ip"], args.ports)

    if args.ports:
        for result in scan_results:
            open_ports = scan_ports(result["ip"], args.ports)
            display_open_ports(result["ip"], open_ports)
            
            # Voeg deze lijn toe om de hostnaam weer te geven
            hostname = get_hostname(result["ip"])
            print(f"Hostname van {result['ip']}: {hostname}")

if __name__ == "__main__":
    main()
