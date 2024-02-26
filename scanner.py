import scapy.all as scapy
import socket

arp_request = scapy.ARP()
broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
arp_request_broadcast = broadcast / arp_request
networks = []


# scipt moet gerunt worden met sudo 
def scan(ip):
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
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
    networks.clear()
    arp_request.pdst = f'{net_area}/{net_mask}'
    clients = scapy.srp(arp_request_broadcast, timeout=5)[0]
    for sent_ip, received_ip in clients:
        networks.append({'IP': received_ip.psrc,
                         'MAC': received_ip.hwsrc,
                         'HOSTNAME': socket.gethostbyaddr(received_ip.psrc)[0]})
        
    return networks

    


target_ip = "192.168.1.1/24"
ip_target = "192.168.1.1"
target_netmask = "24"
scan_results = scan(target_ip)
network_results = hostname_detection(ip_target, target_netmask)
print(network_results)
display_results(scan_results)