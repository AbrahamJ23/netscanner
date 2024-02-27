import scapy.all as scapy
import socket

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
    results = []

    for element in answered_list:
        result = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        results.append(result)
    
    return results

def display_results(results):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for result in results:
        print(result["ip"] + "\t\t" + result["mac"])

def hostname_detection(net_area, net_mask):
    request = scapy.ARP()
    networks.clear()
    request.pdst = f'{net_area}/{net_mask}'
    clients = scapy.srp(arp_request_broadcast, timeout=5, iface=ethernet_adapter)[0]
    for sent_ip, received_ip in clients:
        networks.append({'IP': received_ip.psrc,
                         'MAC': received_ip.hwsrc
                        #  Werkt nog niet
                        #  ,'HOSTNAME': socket.gethostbyaddr(received_ip.psrc)[0]
                        })
        
    return networks

target_ip = "192.168.1.1/24"
ip_target = "192.168.1.1"
target_netmask = "24"
scan_results = scan()
network_results = hostname_detection(ip_target, target_netmask)
print(network_results)
display_results(scan_results)