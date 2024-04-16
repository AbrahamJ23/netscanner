import argparse
import nmap
import scapy.all as scapy
import socket
from tabulate import tabulate
import concurrent.futures

def scan(ip, adapter):
    """
    Voert een ARP-scan uit om IP- en MAC-adressen in het netwerk te ontdekken.

    Parameters:
        ip (str): Het IP-adres of IP-bereik dat moet worden gescand.
        adapter (str): Naam van de Ethernet-adapter om te gebruiken voor het scannen.

    Returns:
        list: Een lijst van dictionaries met de gevonden IP- en MAC-adressen.
    """
    # ARP-verzoek maken
    arp_request = scapy.ARP(pdst=ip)
    # Broadcastpakket maken
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # ARP-verzoek en broadcast samenvoegen
    arp_request_broadcast = broadcast / arp_request
    # ARP-verzoek verzenden en antwoorden ontvangen
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, iface=adapter, verbose=False)[0]
    # IP- en MAC-adressen extraheren uit de ontvangen antwoorden
    results = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]
    return results

def scan_ports(ip, port_range):
    """
    Scant opgegeven poorten op een specifiek IP-adres.

    Parameters:
        ip (str): Het IP-adres waarop de poorten moeten worden gescand.
        port_range (tuple): Een tuple met het start- en eindpoortnummer.

    Returns:
        list: Een lijst van open poorten.
    """
    open_ports = []
    # Poorten scannen in het opgegeven bereik
    for port in range(port_range[0], port_range[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        # Poort verbinden en resultaat controleren
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def detect_os(target_ip):
    """
    Detecteert het besturingssysteem van een opgegeven IP-adres.

    Parameters:
        target_ip (str): Het IP-adres waarvan het besturingssysteem moet worden gedetecteerd.

    Returns:
        str: Het gedetecteerde besturingssysteem of een foutmelding.
    """
    try:
        # Nmap-scanner maken en OS-detectie uitvoeren
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
        return f"Onbekede OS: {str(e)}"

def scan_services(ip, ports):
    """
    Voert een servicescan uit op opgegeven poorten van een specifiek IP-adres.

    Parameters:
        ip (str): Het IP-adres waarop de services moeten worden gescand.
        ports (list): Een lijst van poorten om te scannen.

    Returns:
        list: Een lijst van tuples met de naam en versie van de gevonden services.
    """
    # Nmap-scanner maken en servicescan uitvoeren
    nm = nmap.PortScanner()
    port_str = ','.join(map(str, ports))
    nm.scan(hosts=ip, arguments=f'-p {port_str} -sV')

    service_results = []
    # Resultaten van elke gescande poort verwerken
    for port in ports:
        service_info = nm[ip]['tcp'].get(port, {})
        service_name = service_info.get('name', '-')
        service_version = service_info.get('product', '-') + " " + service_info.get('version', 'No version')
        service_results.append((service_name, service_version))

    return service_results

def main():
    """
    Hoofdfunctie voor het uitvoeren van de netwerkscan.

    Leest de opgegeven argumenten, voert de scan uit en drukt de resultaten af.
    """
    parser = argparse.ArgumentParser(description="Netwerkscanner met optionele OS-detectie en poortscanning.")
    parser.add_argument("ip", help="Del-IP-adres of IP-bereik (CIDR-notatie)")
    parser.add_argument("adapter", help="Naam van de Ethernet-adapter")
    parser.add_argument("--ports", type=int, nargs=2, help="Poorten om te scannen (bijv. --ports 20 80) poorten 20 t/m 80")
    parser.add_argument("--osdetect", action="store_true", help="Voer OS-detectie uit")
    parser.add_argument("--services", action="store_true", help="Voer servicescan uit")

    args = parser.parse_args()

    # IP-adressen scannen in het netwerk
    scan_results = scan(args.ip, args.adapter)

    headers = ["IP Address", "MAC Address", "Open Ports", "OS", "Service Name", "Service Version"]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for result in scan_results:
            open_ports = scan_ports(result["ip"], args.ports) if args.ports else []

            os_result = detect_os(result["ip"]) if args.osdetect else "-"
            service_result = scan_services(result["ip"], args.ports) if args.services and open_ports else ["No services"]

            # Lege serviceversie vervangen door "No version"
            for service in service_result:
                if service[1] == '':
                    service[1] = 'No version'

            # Gecombineerde resultaten afdrukken
            combined_result = [result["ip"], result.get("mac", "N/A"), open_ports, os_result, service_result]
            print(tabulate([combined_result], headers=headers, tablefmt="fancy_grid"))

if __name__ == "__main__":
    main()
