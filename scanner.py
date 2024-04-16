import argparse
import nmap
import scapy.all as scapy
import socket
from tabulate import tabulate
import concurrent.futures

def scan(ip, adapter):
    """
    Performs an ARP scan to discover IP and MAC addresses in the network.

    Parameters:
        ip (str): The IP address or IP range to scan.
        adapter (str): Name of the Ethernet adapter to use for scanning.

    Returns:
        list: A list of dictionaries containing the discovered IP and MAC addresses.
    """
    # Create ARP request
    arp_request = scapy.ARP(pdst=ip)
    # Create broadcast packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine ARP request and broadcast
    arp_request_broadcast = broadcast / arp_request
    # Send ARP request and receive responses
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, iface=adapter, verbose=False)[0]
    # Extract IP and MAC addresses from the received responses
    results = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]
    return results

def scan_ports(ip, port_range):
    """
    Scans specified ports on a specific IP address.

    Parameters:
        ip (str): The IP address on which the ports should be scanned.
        port_range (tuple): A tuple containing the start and end port numbers.

    Returns:
        list: A list of open ports.
    """
    open_ports = []
    # Scan ports in the specified range
    for port in range(port_range[0], port_range[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        # Connect to port and check result
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def detect_os(target_ip):
    """
    Detects the operating system of a specified IP address.

    Parameters:
        target_ip (str): The IP address for which the operating system should be detected.

    Returns:
        str: The detected operating system or an error message.
    """
    try:
        # Create Nmap scanner and perform OS detection
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, arguments='-O')
        os_match = nm[target_ip]['osmatch']
        if os_match:
            detected_os = os_match[0]['osclass'][0]['osfamily']
            return detected_os
        else:
            return "Operating system not detected"
    except nmap.nmap.PortScannerError:
        return "An error occurred while scanning"
    except Exception as e:
        return f"Unknown OS: {str(e)}"

def scan_services(ip, ports):
    """
    Performs a service scan on specified ports of a specific IP address.

    Parameters:
        ip (str): The IP address on which the services should be scanned.
        ports (list): A list of ports to scan.

    Returns:
        list: A list of tuples containing the name and version of the discovered services.
    """
    # Create Nmap scanner and perform service scan
    nm = nmap.PortScanner()
    port_str = ','.join(map(str, ports))
    nm.scan(hosts=ip, arguments=f'-p {port_str} -sV')

    service_results = []
    # Process results of each scanned port
    for port in ports:
        service_info = nm[ip]['tcp'].get(port, {})
        service_name = service_info.get('name', '-')
        service_version = service_info.get('product', '-') + " " + service_info.get('version', 'No version')
        service_results.append((service_name, service_version))

    return service_results

def main():
    """
    Main function for performing the network scan.

    Reads the provided arguments, performs the scan, and prints the results.
    """
    parser = argparse.ArgumentParser(description="Network scanner with optional OS detection and port scanning.")
    parser.add_argument("ip", help="Destination IP address or IP range (CIDR notation)")
    parser.add_argument("adapter", help="Name of the Ethernet adapter")
    parser.add_argument("--ports", type=int, nargs=2, help="Ports to scan (e.g., --ports 20 80) ports 20 through 80")
    parser.add_argument("--osdetect", action="store_true", help="Perform OS detection")
    parser.add_argument("--services", action="store_true", help="Perform service scan")

    args = parser.parse_args()

    # Scan IP addresses in the network
    scan_results = scan(args.ip, args.adapter)

    headers = ["IP Address", "MAC Address", "Open Ports", "OS", "Service Name", "Service Version"]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for result in scan_results:
            open_ports = scan_ports(result["ip"], args.ports) if args.ports else []

            os_result = detect_os(result["ip"]) if args.osdetect else "-"
            service_result = scan_services(result["ip"], args.ports) if args.services and open_ports else ["No services"]

            # Replace empty service version with "No version"
            for service in service_result:
                if service[1] == '':
                    service[1] = 'No version'

            # Print combined results
            combined_result = [result["ip"], result.get("mac", "N/A"), open_ports, os_result, service_result]
            print(tabulate([combined_result], headers=headers, tablefmt="fancy_grid"))

if __name__ == "__main__":
    main()
