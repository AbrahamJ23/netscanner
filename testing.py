from scapy.all import ARP, Ether, srp

def get_mac(ip_address):
    # Create ARP packet
    arp_request = ARP(pdst=ip_address)

    # Create Ethernet frame
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine Ethernet frame and ARP packet
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and capture response
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Return the MAC address
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

# IP addresses
laptop_ip = "192.168.1.127"
router_ip = "192.168.1.1"

# Get MAC addresses
laptop_mac = get_mac(laptop_ip)
router_mac = get_mac(router_ip)

# Print results
if laptop_mac:
    print(f"Laptop IP: {laptop_ip} \t Laptop MAC: {laptop_mac}")
else:
    print(f"No response for {laptop_ip}")

if router_mac:
    print(f"Router IP: {router_ip} \t Router MAC: {router_mac}")
else:
    print(f"No response for {router_ip}")