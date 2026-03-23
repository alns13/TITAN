import time
import requests
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ICMP

API_addr = "http://127.0.0.1:8000/predict"

#map ports to features
port_to_feat = {
    80 : "http",
    443 : "http_443",
    22 : "ssh",
    21 : "ftp",
    25 : "smtp",
    53 : "domain_u",
    23 : "telnet",
    110: "pop_3",
    109 : "pop_2",
    143 : "imap4",
    119 : "nntp",
    3306 : "mysql",
    6667 : "IRC"
}

packet_history = deque()
TIME_WINDOW = 10.0

#translate scapy TCP flags into KDD dataset flags
def get_tcp_flag(tcp_layer):
    flags = str(tcp_layer.flags)
    if flags == "":
        return "OTH"

    if flags == 'S': return "S0"
    if 'R' in flags: return "REJ"
    if 'A' in flags or 'F' in flags: return "SF"

    return "OTH"

#calculate time window
def update_history(dst_ip, dst_port, flag):
    curr_time = time.time()
    packet_history.append((curr_time, dst_ip, dst_port, flag)) 

    while packet_history and curr_time - packet_history[0][0] > TIME_WINDOW:
        packet_history.popleft()

    count = 0
    srv_count = 0
    serror_count = 0

    for pkt_time, p_dst, p_port, p_flag in packet_history:
        if p_dst == dst_ip:
            count += 1                  #packets to the same host
            if p_flag == "S0":
                serror_count += 1       #SYN errors to this host
            
        if p_port == dst_port:
            srv_count += 1              #packets to the same service

    serror_rate = (serror_count/count) if count > 0 else 0.0

    return count, srv_count, serror_rate

#extract features and translate raw scapy packet into JSON format
def extract_features(packet):
    #only want packets with IP, dont need ARP etc.
    if not packet.haslayer(IP):
        return None
    
    #default values
    proto = "other"
    service = "private"
    flag = "SF"
    port = 0
    dst_ip = packet[IP].dst

    #get protocol
    if packet.haslayer(TCP):
        proto = "tcp"
        sport =packet[TCP].sport
        dport = packet[TCP].dport

        if dport in port_to_feat: 
            port = dport
        else:
            port = sport

        flag = get_tcp_flag(packet[TCP])
        service = port_to_feat.get(port, "private")

    elif packet.haslayer(UDP):
        proto = "udp"
        port = packet[UDP].dport
        service = port_to_feat.get(port, "private")

    elif packet.haslayer(ICMP): 
        proto = "icmp"
        if packet[ICMP].type == 8: service="eco_i"
        elif packet[ICMP].type == 0: service="ecr_i"
        else: service = "icmp"

    #get byte count of packet response body
    packet_size = len(packet[IP].payload) 
    count, srv_count, serror_rate = update_history(dst_ip, port, flag)

    return {
        "duration" : 0,
        "protocol_type" : proto,
        "service" : service,
        "flag" : flag,
        "src_bytes" : packet_size,
        "count" : count,
        "srv_count" : srv_count,
        "serror_rate" : serror_rate,
        "_target_port" : port
    }

def handle_packet(packet):
    formatted_pkt = extract_features(packet)
    if not formatted_pkt: return    #if not an IP packet, then ignore
    target_port = formatted_pkt.pop("_target_port", 0)
    payload = {"data": formatted_pkt}

    try:
        response = requests.post(API_addr, json=payload, timeout=0.1)
        if response.status_code == 200:
            attk_prob = response.json()

            if formatted_pkt["protocol_type"] == 'icmp':
                port_str = f"Type: ICMP"
                if attk_prob > 0.96:
                    print(f"Malicious Traffic Detected | {port_str} | Service: ({formatted_pkt['service'].upper()}) | Protocol: {formatted_pkt['protocol_type'].upper()} | Confidence: {attk_prob * 100:.2f}%")
                else:
                    pass

            elif attk_prob > 0.8: 
                port_str = f"Port: {target_port}"
                print(f"Malicious Traffic Detected | {port_str} | Service: ({formatted_pkt['service'].upper()}) | Protocol: {formatted_pkt['protocol_type'].upper()} | Confidence: {attk_prob * 100:.2f}%") 
            else:
                #comment the "pass" and uncomment the print statement if you want to see normal traffic too
                pass
                #print(f"Normal Traffic | Port: {target_port} ({formatted_pkt['service'].upper()}) | {formatted_pkt['protocol_type'].upper()} | Confidence: {attk_prob * 100:.2f}%") 
    except Exception:
        pass

print("TITAN is online and ready")
sniff(iface="lo",
      filter="ip and not port 22 and not port 8000", 
      prn=handle_packet, 
      store=0)