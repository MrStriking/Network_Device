import nmap
import socket
from prettytable import PrettyTable

def own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()
        
def scan_host(ip):
    nm = nmap.PortScanner()
    scan_result = nm.scan(ip, arguments='-sS --top-ports 1000 -n')
    open_ports = []
    if ip in scan_result['scan']:
        host_data = scan_result['scan'][ip]
        if 'tcp' in host_data:
            for port, port_data in host_data['tcp'].items():
                if port_data['state'] == 'open':
                    open_ports.append(port)
    return open_ports      

def criticality(ip, os, services, open_ports):
    score = 1
    if ip == own_ip():
        score = 2
    elif "router" in os.lower() or "gateway" in os.lower() or "vmware" in os.lower():
        score = 5
    elif any(s in services for s in ["msrpc", "netbios-ssn", "microsoft-ds", "rdp", "dns", "domain", "smb"]):
        score = 5
    for port in open_ports:
        if port in [21, 22, 23, 69, 161, 162, 389, 445, 1433, 1521, 3306, 3389, 5432]:
            score = 5
    return score

def Role(os, services):
    if "windows" in os.lower() or os == "The scanning host (Linux VM)":
        return "Work PC"
    if "dns" in services or "domain" in services:
        return "DNS/NAT Service"
    if "router" in os.lower() or "gateway" in os.lower():
        return "Virtual Router/Gateway"
    return "General Device"

def Device_Type(os, services):
    os_lower = os.lower()
    services_lower = services.lower()
    if "windows" in os_lower:
        return "Windows PC"
    elif "linux" in os_lower or "unix" in os_lower:
        return "Linux/Unix Device"
    elif "mac" in os_lower:
        return "Mac Device"
    elif "ios" in os_lower:
        return "iPhone/iPad"
    elif "android" in os_lower:
        return "Android Device"
    elif "router" in os_lower or "gateway" in os_lower:
        return "Router/Gateway"
    elif "vmware" in os_lower:
        return "VMware Host"
    return "Unknown Device"

def scan_network(target_subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_subnet, arguments="-sS -sV -O -T4")
    table = PrettyTable(["IP", "Likely OS", "Services", "Device Role", "Device Type", "Criticality"])

    for host in nm.all_hosts():
        if "osmatch" in nm[host] and nm[host]["osmatch"]:
            os = nm[host]["osmatch"][0]["name"]
        else:
            os = "Unknown"

        services = [nm[host][protocol][port]['name'] 
                    for protocol in nm[host].all_protocols() 
                    for port in nm[host][protocol].keys()]
        services_str = ", ".join(services) if services else "None"

        if os == "Unknown":
            if "vmware" in os.lower() and "nat" in os.lower():
                os = "Linux (VMware NAT Appliance)"
            elif "vmware" in os.lower() and "router" in os.lower():
                os = "Linux (VMware Virtual Router)"
            elif host == own_ip():
                os = "The scanning host (Linux VM)"
            else:
                os = "Unknown Device"
                
        role = Role(os, services_str)
        device_type = Device_Type(os, services_str)
        open_ports = scan_host(host)
        score = criticality(host, os, services_str, open_ports)
        table.add_row([host, os, services_str, role, device_type, score])
    print(table)

if __name__ == "__main__":
    target = "192.168.111.128/24"
    scan_network(target)
