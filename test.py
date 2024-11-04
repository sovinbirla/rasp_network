import nmap

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

if __name__ == "__main__":
    network = '192.168.1.0/24'  # Replace with your network range
    devices = scan_network(network)
    
    print("Connected devices:")
    for device in devices:
        print(f"IP: {device['ip']}, Hostname: {device['hostname']}")