import socket
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from scapy.all import sr1, IP, TCP
import nmap
import pandas as pd
import matplotlib.pyplot as plt
import concurrent.futures
import requests  # Untuk GeoIP Lookup dan Threat Intelligence

class MRZeroScanner:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.network = ipaddress.IPv4Network(f"{self.local_ip}/24", strict=False)
        self.all_ips = [str(ip) for ip in self.network.hosts()]
        self.active_hosts = []
        self.scan_results = {}
        self.vuln_db = self.load_vuln_db()

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    # **Ping Scan**
    def ping_scan(self, ip):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                s.settimeout(1)
                s.sendto(b'PING', (ip, 0))
                data, addr = s.recvfrom(1024)
                return True
        except:
            return False

    # **Stealth SYN Scan**
    def stealth_scan(self, ip, port):
        try:
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=1, verbose=0)
            if response and response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    return {"port": port, "status": "Open", "stealth": True}
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return {"port": port, "status": "Closed", "stealth": True}
        except:
            return {"port": port, "status": "Filtered", "stealth": True}

    # **OS Detection**
    def os_detection(self, ip):
        nm = nmap.PortScanner()
        try:
            nm.scan(ip, arguments="-O")
            if nm[ip].get('osmatch'):
                return nm[ip]['osmatch'][0]['name']
            else:
                return "Unknown OS"
        except Exception as e:
            return "Unknown OS"

    # **Service Detection**
    def service_detection(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                banner = s.recv(1024).decode().strip()
                return banner.split('\n')[0]
        except:
            return "Unknown service"

    # **Vulnerability Database**
    def load_vuln_db(self):
        try:
            with open("vulnerabilities.json", "r") as f:
                return json.load(f)
        except:
            return {}

    def check_vulnerabilities(self, service):
        return self.vuln_db.get(service, [])

    # **Generate Report**
    def generate_report(self):
        if not self.scan_results:
            print("[!] Tidak ada data untuk digenerate.")
            return
        
        df = pd.DataFrame.from_dict(self.scan_results, orient='index')
        df.to_html("scan_report.html")
        print(f"\n[+] Laporan lengkap tersimpan di scan_report.html")

    # **Visualize Network Map**
    def visualize_network(self):
        if not self.scan_results:
            print("[!] Tidak ada data untuk divisualisasikan.")
            return
        
        data = {ip: len(info['ports']) for ip, info in self.scan_results.items()}
        df = pd.DataFrame(list(data.items()), columns=['IP Address', 'Open Ports'])
        
        plt.figure(figsize=(10, 6))
        plt.bar(df['IP Address'], df['Open Ports'], color='skyblue')
        plt.xlabel('IP Address')
        plt.ylabel('Number of Open Ports')
        plt.title('Network Map Visualization')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('network_map.png')
        print("[+] Network map visualization saved as network_map.png")

    # --- FITUR BARU ---
    
    # **GeoIP Lookup**
    def geoip_lookup(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon")
                }
            else:
                return {"error": "Location not found"}
        except:
            return {"error": "Failed to fetch GeoIP data"}

    # **Dark Web Exposure Check**
    def dark_web_exposure_check(self, ip):
        try:
            response = requests.get(f"https://api.greynoise.io/v3/community/{ip}", 
                                    headers={"key": "YOUR_GREYNOISE_API_KEY"})
            data = response.json()
            if data.get("seen"):
                return {
                    "dark_web_exposure": True,
                    "classification": data.get("classification"),
                    "last_seen": data.get("last_seen"),
                    "tags": data.get("tags")
                }
            else:
                return {"dark_web_exposure": False}
        except:
            return {"error": "Failed to check Dark Web exposure"}

    # **Real-time Threat Intelligence**
    def real_time_threat_intelligence(self, ip):
        try:
            response = requests.get(f"https://threatfox.abuse.ch/api/v1/host/lookup/{ip}")
            data = response.json()
            if data.get("data"):
                return {
                    "threat_level": data["data"]["threat_level"],
                    "malware": data["data"].get("malware"),
                    "reported_at": data["data"].get("reported_at")
                }
            else:
                return {"threat_level": "Clean", "malware": None, "reported_at": None}
        except:
            return {"error": "Failed to fetch threat intelligence"}

    # **Multi-threaded Parallel Scan Optimization**
    def optimized_scan(self, func, items, max_workers=200):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(tqdm(executor.map(func, items), total=len(items)))
        return results

    # **Run Menu Options**
    def run(self):
        print(r"""
  __  __ ____  _   _    ___  _   _ _____ 
 |  \/  | __ )| | | |  / _ \| | | |_   _|
 | |\/| |  _ \| |_| | | | | | | | | | |  
 | |  | | |_) |  _  | | |_| | |_| | | |  
 |_|  |_|____/|_| |_|  \___/ \___/  |_|  
        """)
        print("[+] MR-zero X-Treme Scanner Activated")
        print("   Mode: AI-Powered Quantum Scan 🤖")
        print(f"   Target network: 118.98.95.195")

        while True:
            print("\n[+] Pilih mode scanning:")
            print("   1. Full Scan (Host Discovery + OS Detection + Port Scan)")
            print("   2. Host Discovery Only")
            print("   3. Port Scan Only")
            print("   4. Visualize Network Map")
            print("   5. GeoIP Lookup")
            print("   6. Dark Web Exposure Check")
            print("   7. Real-time Threat Intelligence")
            print("   8. Exit")

            choice = input("\nMasukkan pilihan (1-8): ")

            if choice == "1":
                self.full_scan()
            elif choice == "2":
                self.host_discovery()
            elif choice == "3":
                self.port_scan_only()
            elif choice == "4":
                self.visualize_network()
            elif choice == "5":
                self.geoip_lookup_menu()
            elif choice == "6":
                self.dark_web_exposure_menu()
            elif choice == "7":
                self.threat_intelligence_menu()
            elif choice == "8":
                print("[+] Exiting MR-zero Scanner...")
                break
            else:
                print("[!] Pilihan tidak valid. Coba lagi.")

    # **Full Scan**
    def full_scan(self):
        print("\n[+] Phase 1: Quantum Host Discovery (ICMP)")
        results = self.optimized_scan(self.ping_scan, self.all_ips)
        self.active_hosts = [ip for ip, status in zip(self.all_ips, results) if status]

        if not self.active_hosts:
            print("[!] Tidak ada host aktif ditemukan.")
            return

        print("\n[+] Phase 2: OS Fingerprinting")
        os_results = {}
        for ip in tqdm(self.active_hosts):
            os_results[ip] = self.os_detection(ip)

        print("\n[+] Phase 3: Covert Port & Service Analysis")
        common_ports = [21, 22, 80, 443, 3389, 8080, 25565]
        for ip in tqdm(self.active_hosts, desc="Scanning Hosts"):
            ports = {}
            for port in common_ports:
                result = self.stealth_scan(ip, port)
                if result['status'] == 'Open':
                    service = self.service_detection(ip, result['port'])
                    vulns = self.check_vulnerabilities(service)
                    ports[result['port']] = {
                        "status": result['status'],
                        "service": service,
                        "vulnerabilities": vulns
                    }
            self.scan_results[ip] = {
                "os": os_results.get(ip, "Unknown"),
                "ports": ports
            }

        self.generate_report()
        print("\n[+] Quantum Scan Complete! ✅")
        print("   Detailed analysis available in scan_report.html")

    # **Host Discovery Only**
    def host_discovery(self):
        print("\n[+] Starting Host Discovery...")
        results = self.optimized_scan(self.ping_scan, self.all_ips)
        self.active_hosts = [ip for ip, status in zip(self.all_ips, results) if status]
        
        if not self.active_hosts:
            print("[!] Tidak ada host aktif ditemukan.")
            return
        
        print("\n[+] Active Hosts:")
        for ip in self.active_hosts:
            print(f"   - {ip}")

    # **Port Scan Only**
    def port_scan_only(self):
        if not self.active_hosts:
            print("[!] No active hosts detected. Run Host Discovery first.")
            return
        
        print("\n[+] Starting Port Scan on Active Hosts...")
        common_ports = [21, 22, 80, 443, 3389, 8080, 25565]
        for ip in tqdm(self.active_hosts, desc="Scanning Hosts"):
            ports = {}
            for port in common_ports:
                result = self.stealth_scan(ip, port)
                if result['status'] == 'Open':
                    service = self.service_detection(ip, result['port'])
                    vulns = self.check_vulnerabilities(service)
                    ports[result['port']] = {
                        "status": result['status'],
                        "service": service,
                        "vulnerabilities": vulns
                    }
            self.scan_results[ip] = {
                "os": "N/A",
                "ports": ports
            }

        self.generate_report()
        print("\n[+] Port Scan Complete! ✅")

    # **GeoIP Lookup Menu**
    def geoip_lookup_menu(self):
        ip = input("\nMasukkan IP target untuk GeoIP Lookup: ")
        location = self.geoip_lookup(ip)
        if "error" in location:
            print("[!] Gagal mendapatkan lokasi geografis.")
        else:
            print(f"\n[+] Lokasi Geografis untuk {ip}:")
            for key, value in location.items():
                print(f"   {key.capitalize()}: {value}")

    # **Dark Web Exposure Menu**
    def dark_web_exposure_menu(self):
        ip = input("\nMasukkan IP target untuk Dark Web Exposure Check: ")
        exposure = self.dark_web_exposure_check(ip)
        if "error" in exposure:
            print("[!] Gagal memeriksa eksposur Dark Web.")
        else:
            print(f"\n[+] Hasil Eksposur Dark Web untuk {ip}:")
            for key, value in exposure.items():
                print(f"   {key.capitalize()}: {value}")

    # **Threat Intelligence Menu**
    def threat_intelligence_menu(self):
        ip = input("\nMasukkan IP target untuk Real-time Threat Intelligence: ")
        threat = self.real_time_threat_intelligence(ip)
        if "error" in threat:
            print("[!] Gagal mendapatkan informasi ancaman.")
        else:
            print(f"\n[+] Informasi Ancaman untuk {ip}:")
            for key, value in threat.items():
                print(f"   {key.capitalize()}: {value}")

if __name__ == "__main__":
    scanner = MRZeroScanner()
    scanner.run()