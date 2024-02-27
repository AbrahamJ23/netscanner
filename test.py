import scapy.all as scapy
import socket

request = scapy.ARP()
broadcast = scapy.Ether()
broadcast.dst = 'ff:ff:ff:ff:ff:ff'
available_networks = []


def IP_Scan(net_area, net_mask):
    available_networks.clear()
    request.pdst = f'{net_area}/{net_mask}'
    request_broadcast = broadcast / request
    clients = scapy.srp(request_broadcast, timeout=5)[0]
    for sent_ip, received_ip in clients:
        print(received_ip)

        available_networks.append({'IP': received_ip.psrc, 
                                   'MAC': received_ip.hwsrc, 
                                   'HOSTNAME': socket.gethostbyaddr(received_ip.psrc)[0]})

    return available_networks

info = IP_Scan("192.168.0.1", "24")
print(info)