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
    23 : "telnet"
}

packet_history = deque()
TIME_WINDOW = 2.0

#translate scapy TCP flags into KDD dataset flags
def get_tcp_flag(tcp_layer):
    flags = tcp_layer.flags
    if flags == 'S': return "S0"
    if 'R' in flags: return "REJ"
    if 'A' in flags or 'F' in flags: return "SF"
    return "SF"

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
            
        if p_dst == dst_ip and p_port == dst_port:
            srv_count += 1              #packets to the same service

    serror_rate = (serror_count/count) if count > 0 else 0.0

    return count, srv_count, serror_rate

#extract features and translate raw scapy packet into JSON format
def extract_features(packet):
    #only want packets with IP, dont need ARP etc.
    if IP not in packet:
        return None
    
    dst_ip = packet[IP].dst
    port = 0
    flag = "SF"

    #get protocol
    port = 0
    if TCP in packet:
        proto = "tcp"
        port = packet[TCP].dport
        flag = get_tcp_flag(packet[TCP])
    elif UDP in packet:
        proto = "udp"
        port = packet[UDP].dport
    elif ICMP in packet: proto = "icmp"
    else: proto = "other"

    #get byte count of packet response body
    packet_size = len(packet[IP].payload) 
    service = port_to_feat.get(port, "private")
    count, srv_count, serror_rate = update_history(dst_ip, port, flag)

    return {
        "duration" : 0,
        "protocol_type" : proto,
        "service" : service,
        "flag" : flag,
        "src_bytes" : packet_size,
        "count" : count,
        "srv_count" : srv_count,
        "serror_rate" : serror_rate
    }

def handle_packet(packet):
    formatted_pkt = extract_features(packet)
    if not formatted_pkt: return    #if not an IP packet, then ignore
    payload = {"data": formatted_pkt}

    try:
        response = requests.post(API_addr, json=payload, timeout=0.1)
        if response.status_code == 200:
            attk_prob = response.json()
            if attk_prob > 0.8:
                print(f"Malicious Traffic Detected | {formatted_pkt['protocol_type'].upper()} to Port: {formatted_pkt['service']} | Confidence: {attk_prob * 100:.2f}%") 
            else:
                pass
                #you can uncomment this print statement if you want to see normal traffic
                #print(f"normal traffic... | Confidence: {attk_prob}")
    except Exception:
        pass

print("TITAN is online and ready")
sniff(iface="lo",
      filter="ip and not port 22", 
      prn=handle_packet, 
      store=0)