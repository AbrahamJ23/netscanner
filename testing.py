import scapy.all as scapy
import socket

# target gegevens
target_ports = [21, 22, 80, 443]

# Vul hier de naam van je Ethernet-adapter in
ethernet_adapter = "en7"
ip = "192.168.1.1/24"
arp_request = scapy.ARP(pdst=ip)
broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
arp_request_broadcast = broadcast / arp_request
networks = []

# Script moet worden uitgevoerd met sudo
def scan():
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, iface=ethernet_adapter, verbose=False)[0]
    results = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]
    return results

def display_results(results):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for result in results:
        print(result["ip"] + "\t\t" + result["mac"])

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout van 1 seconde
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Aanvullende functie om de resultaten weer te geven
def display_open_ports(ip, open_ports):
    print(f"Open poorten op {ip}: {open_ports}")

# Scan uitvoeren en gevonden IP-adressen gebruiken voor poortscan
scan_results = scan()
display_results(scan_results)

for result in scan_results:
    open_ports = scan_ports(result["ip"], target_ports)
    display_open_ports(result["ip"], open_ports)
