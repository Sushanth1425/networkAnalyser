import pyshark
import logging
import asyncio
import requests
import os
from datetime import datetime, timedelta

logging.basicConfig(filename="capture_log.txt", level=logging.INFO)
logging.info("Capture script started.")

interface = 'Wi-Fi'  
suspicious_ips = ['203.0.113.10', '192.168.1.100']  
port_scan_threshold = 10
icmp_threshold = 20 
geolocation_api_key = 'f5797ab713e48f6d21dd44b8ecfebec9' 
blacklist_api_key = '43a459c9805a6c2c514e5e8ae2224ebdcd5e3f532556a50e63bcfa48541f5e35eca73c706c2c532a' 
geo_block_countries = ['India']  

port_scan_tracker = {}
icmp_request_tracker = {}  
sus_ips = []  
malicious_packets = {}
failed_logins = {}

def get_geolocation(ip):
    url = f"http://api.ipstack.com/{ip}?access_key={geolocation_api_key}&format=1"
    try:
        response = requests.get(url)
        data = response.json()
        country = data.get('country_name', 'Unknown')
        return country
    except requests.exceptions.RequestException as e:
        logging.error(f"Geolocation API error for IP {ip}: {e}")
        return 'Unknown'

def check_blacklist(ip):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
    headers = {
        'Key': blacklist_api_key,
        'Accept': 'application/json',
    }
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        if data.get('data', {}).get('abuseConfidenceScore', 0) > 80:
            logging.warning(f"IP {ip} is blacklisted with score {data['data']['abuseConfidenceScore']}")
            return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Blacklist API error for IP {ip}: {e}")
    return False

def block_ip_firewall(ip, permanent=False):
    try:
        action = 'block'
        if permanent:
            action = 'permanent block'
        os.system(f'netsh advfirewall firewall add rule name="Block Suspicious IP {ip}" dir=in action={action} protocol=TCP localport=any remoteip={ip}')
        logging.info(f"Blocked IP {ip} on the firewall with action: {action}")
    except Exception as e:
        print(f"Failed to block IP {ip} on the firewall: {e}")
        logging.error(f"Failed to block IP {ip} on the firewall: {e}")

def process_packet(pkt):
    try:
        if 'IP' in pkt:
            src = pkt.ip.src
            dst = pkt.ip.dst
            proto = pkt.transport_layer
            port = None

            if proto == "TCP" and (pkt.ip.dstport == '22' or pkt.ip.dstport == '3389'):
                if src not in failed_logins:
                    failed_logins[src] = {'count': 0, 'last_attempt': datetime.now()}
                failed_logins[src]['count'] += 1
                failed_logins[src]['last_attempt'] = datetime.now()

                if failed_logins[src]['count'] > 5 and (datetime.now() - failed_logins[src]['last_attempt']).seconds < 60:
                    alert = f" Brute Force detected: {src} attempted over 5 logins on port {pkt.ip.dstport}"
                    print(alert)
                    logging.info(alert)
                    malicious_packets.append(alert)
                    block_ip_firewall(src)

            country = get_geolocation(src)
            if country != 'Unknown' and country not in geo_block_countries:
                alert = f" Suspicious IP based on geolocation: {src} -> {dst} (Country: {country})"
                print(alert)
                malicious_packets.append(alert)
                sus_ips.append(src)
                block_ip_firewall(src, permanent=True)

            if check_blacklist(src):
                alert = f" IP {src} is blacklisted."
                print(alert)
                malicious_packets.append(alert)
                sus_ips.append(src)
                block_ip_firewall(src, permanent=True)

            if src not in port_scan_tracker:
                port_scan_tracker[src] = set()
            if proto in ['TCP', 'UDP']:
                port = pkt[pkt.transport_layer].dstport
                port_scan_tracker[src].add(port)

            if len(port_scan_tracker[src]) > port_scan_threshold:
                alert = f" Port scan suspected from {src} ({len(port_scan_tracker[src])} ports)"
                print(alert)
                malicious_packets.append(alert)

            if 'ICMP' in pkt:
                icmp_type = pkt.icmp.type
                if icmp_type == '8': 
                    if src not in icmp_request_tracker:
                        icmp_request_tracker[src] = 0
                    icmp_request_tracker[src] += 1

                    if icmp_request_tracker[src] > icmp_threshold:
                        alert = f" Suspicious ICMP activity detected: {src} sent more than {icmp_threshold} pings"
                        print(alert)
                        malicious_packets.append(alert)

                    alert = f" ICMP Echo Request detected: {src} -> {dst}"
                    print(alert)
                    malicious_packets.append(alert)

                elif icmp_type == '0':
                    alert = f" ICMP Echo Reply detected: {src} -> {dst}"
                    print(alert)
                    malicious_packets.append(alert)

    except AttributeError:
        pass

print(f"Starting live capture on interface: {interface}")
logging.info(f"Starting live capture on interface: {interface}")

capture = pyshark.LiveCapture(interface=interface)

try:
    capture.apply_on_packets(process_packet, timeout=60)  
except asyncio.CancelledError:
    print("Capture was canceled.")
    logging.error("Capture was canceled.")
except TimeoutError:
    print("Timeout occurred while capturing packets.")
    logging.error("Timeout occurred while capturing packets.")
except Exception as e:
    print(f" An error occurred: {e}")
    logging.error(f"An error occurred: {e}")

try:
    with open("live_threat_report.txt", "w") as f:
        f.write("\n".join(malicious_packets))
    print("\n Live capture complete. Report saved to live_threat_report.txt")
    logging.info("Live capture complete. Report saved to live_threat_report.txt")
except Exception as e:
    print(f" Failed to save the report: {e}")
    logging.error(f"Failed to save the report: {e}")

upgrade_firewall = input("\nDo you want to upgrade the firewall by blocking suspicious IPs? (s for yes): ").strip().lower()

if upgrade_firewall == 's':
    for ip in sus_ips:
        block_ip_firewall(ip, permanent=True)
    print("Firewall upgrade complete. Suspicious IPs blocked.")
else:
    print("Firewall upgrade skipped.")
