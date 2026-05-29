from flask import Flask, jsonify
from flask_cors import CORS
import scapy.all as scapy
import socket
import concurrent.futures
import dns.resolver

app = Flask(__name__)
# Enable CORS so your frontend (file:// or localhost) can talk to this backend
CORS(app)

def get_local_ip_range():
    # Helper to find your local IP (e.g., 192.168.1.5)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually connect, just calculates the route
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assumes a standard /24 subnet (most home Wi-Fi)
        return ".".join(local_ip.split('.')[:3]) + ".1/24"
    except:
        return "192.168.1.1/24"

@app.route('/scan', methods=['GET'])
def scan_network():
    target_ip = get_local_ip_range()
    print(f"Scanning target: {target_ip}...")
    
    # 1. Create ARP Request
    arp = scapy.ARP(pdst=target_ip)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # 2. Send packet and capture responses (timeout=2s to be quick)
    result = scapy.srp(packet, timeout=2, verbose=0)[0]

    # 3. Parse clients and GET HOSTNAMES
    clients = []
    for sent, received in result:
        ip_addr = received.psrc
        mac_addr = received.hwsrc
        
        # --- 1. Attempt Reverse DNS Lookup ---
        try:
            hostname = socket.gethostbyaddr(ip_addr)[0]
        except socket.herror:
            hostname = "Unknown Hostname"

        # --- 2. CYBER SECURITY LOGIC: Detect MAC Randomization ---
        second_char = mac_addr[1].lower()
        is_randomized = second_char in ['2', '6', 'a', 'e']
        
        if is_randomized:
            device_type = "Hidden (Randomized MAC)"
        elif "Unknown" not in hostname:
            device_type = "Verified Host"
        else:
            device_type = "Standard Device"

        clients.append({
            'ip': ip_addr,
            'mac': mac_addr,
            'hostname': hostname,
            'vendor': device_type 
        })

    return jsonify({
        "status": "success",
        "scan_target": target_ip,
        "devices_found": len(clients),
        "clients": clients
    })

# ==========================================
# 🎯 TACTICAL PORT SCANNER
# ==========================================
@app.route('/scan_ports/<ip>', methods=['GET'])
def scan_ports(ip):
    # Dictionary of most critical ports to check
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
        139: "NetBIOS", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    open_ports = []

    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) # Short timeout so it doesn't hang
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
        return None

    # Multi-threading for rapid scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_port, common_ports.keys())

    for port in results:
        if port:
            open_ports.append({"port": port, "service": common_ports[port]})

    return jsonify({
        "status": "success",
        "ip": ip,
        "open_ports": open_ports
    })

# ==========================================
# 🎯 TARGET DOMAIN RECON (DNS SNIPER)
# ==========================================
@app.route('/dns_recon/<domain>', methods=['GET'])
def dns_recon(domain):
    records = {'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': []}
    try:
        for record_type in records.keys():
            try:
                answers = dns.resolver.resolve(domain, record_type)
                # Sort MX records by preference if they exist
                if record_type == 'MX':
                    records[record_type] = [f"Pref {rdata.preference}: {rdata.exchange.to_text()}" for rdata in answers]
                else:
                    records[record_type] = [rdata.to_text() for rdata in answers]
            except Exception:
                pass # Ignore if a specific record type doesn't exist for the domain
                
        return jsonify({"status": "success", "domain": domain, "records": records})
    except Exception as e:
        return jsonify({"status": "error", "message": "Failed to resolve domain. Check spelling."})

if __name__ == '__main__':
    # Must run as Root/Admin for Scapy to work!
    app.run(debug=True, port=5000)
