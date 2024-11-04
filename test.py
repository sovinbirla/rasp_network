import nmap
import requests
import os

def scan_network(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    
    devices = []
    for host in nm.all_hosts():
        if 'hostnames' in nm[host]:
            hostnames = nm[host]['hostnames']
            if hostnames:
                hostname = hostnames[0]['name']
            else:
                hostname = 'Unknown'
        else:
            hostname = 'Unknown'
        
        devices.append({
            'ip': host,
            'hostname': hostname
        })
    
    return devices

def get_public_ip():
    response = requests.get('https://api.ipify.org?format=json')
    ip_data = response.json()
    return ip_data['ip']

def parse_dhcp_leases(file_path):
    leases = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            for line in file:
                if line.startswith('lease'):
                    parts = line.split()
                    ip = parts[1]
                    leases.append({'ip': ip})
                elif line.strip().startswith('client-hostname'):
                    parts = line.split()
                    hostname = parts[1].strip('";')
                    leases[-1]['hostname'] = hostname
                elif line.strip().startswith('hardware ethernet'):
                    parts = line.split()
                    mac = parts[2].strip(';')
                    leases[-1]['mac'] = mac
    return leases

if __name__ == "__main__":
    network = '10.0.0.0/24'  # Replace with your network range
    devices = scan_network(network)
    
    print("Connected devices:")
    for device in devices:
        print(f"IP: {device['ip']}, Hostname: {device['hostname']}")

    # Print current network
    public_ip = get_public_ip()
    print(f"My public IP address is: {public_ip}")

    # Parse DHCP leases file
    dhcp_leases_file = '/var/lib/dhcp/dhcpd.leases'  # Replace with the path to your DHCP leases file
    dhcp_leases = parse_dhcp_leases(dhcp_leases_file)
    
    print("DHCP Leases:")
    for lease in dhcp_leases:
        print(f"IP: {lease['ip']}, Hostname: {lease.get('hostname', 'Unknown')}, MAC: {lease.get('mac', 'Unknown')}")

