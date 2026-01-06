import pyshark
import matplotlib.pyplot as plt

pcap_file = "pcaps/basic_traffic.pcapng"
cap = pyshark.FileCapture(pcap_file)

# -------------------- Data Structures --------------------
protocol_count = {}
src_ip_count = {}
dst_ip_count = {}
src_port_count = {}
dst_port_count = {}
traffic_rate = {}
malformed_count = 0
PORT_SERVICE_MAP = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S"
}


print("Reading packets...\n")

# -------------------- Packet Processing --------------------
for packet in cap:
    try:
        # Protocol analysis
        proto = packet.highest_layer
        protocol_count[proto] = protocol_count.get(proto, 0) + 1

        # IP analysis
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_ip_count[src_ip] = src_ip_count.get(src_ip, 0) + 1
            dst_ip_count[dst_ip] = dst_ip_count.get(dst_ip, 0) + 1

        # Port analysis
        if 'TCP' in packet:
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            src_port_count[src_port] = src_port_count.get(src_port, 0) + 1
            dst_port_count[dst_port] = dst_port_count.get(dst_port, 0) + 1

        elif 'UDP' in packet:
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            src_port_count[src_port] = src_port_count.get(src_port, 0) + 1
            dst_port_count[dst_port] = dst_port_count.get(dst_port, 0) + 1

        # Malformed packets
        if proto == '_WS.MALFORMED':
            malformed_count += 1

        # Traffic rate (packets per second)
        timestamp = packet.sniff_time.replace(microsecond=0)
        traffic_rate[timestamp] = traffic_rate.get(timestamp, 0) + 1

    except Exception:
        pass

cap.close()

# -------------------- Output: Protocol --------------------
print("Protocol Distribution:")
print("----------------------")
for proto, count in protocol_count.items():
    print(f"{proto}: {count}")

# -------------------- Output: IP Analysis --------------------
print("\nTop Source IPs:")
print("----------------")
for ip, count in sorted(src_ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"{ip}: {count}")

print("\nTop Destination IPs:")
print("--------------------")
for ip, count in sorted(dst_ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"{ip}: {count}")

# -------------------- Output: Port Analysis --------------------
print("\nTop Source Ports:")
print("----------------")
for port, count in sorted(src_port_count.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"{port}: {count}")

print("\nWell-Known Destination Ports (≤ 1023):")
print("-------------------------------------")

for port, count in sorted(dst_port_count.items(), key=lambda x: x[1], reverse=True):
    try:
        port_num = int(port)

        # Filter only well-known ports
        if port_num <= 1023:
            service = PORT_SERVICE_MAP.get(port_num, "Unknown Service")
            print(f"{service} ({port_num}): {count}")

    except ValueError:
        continue

# -------------------- Anomaly Detection --------------------
print("\nTraffic Rate Spikes:")
print("--------------------")
RATE_THRESHOLD = 200
for time, count in traffic_rate.items():
    if count > RATE_THRESHOLD:
        print(f"[SPIKE] {time} → {count} packets/sec")

print("\nHigh-Traffic Source IPs:")
print("-----------------------")
IP_THRESHOLD = 5000
for ip, count in src_ip_count.items():
    if count > IP_THRESHOLD:
        print(f"[ALERT] {ip} sent {count} packets")

print("\nMalformed Packet Summary:")
print("-------------------------")
if malformed_count > 0:
    print(f"[WARNING] Detected {malformed_count} malformed packets")
else:
    print("No malformed packets detected")

# -------------------- Visualization --------------------
# Protocol Distribution
plt.figure()
plt.bar(protocol_count.keys(), protocol_count.values())
plt.title("Protocol Distribution")
plt.xlabel("Protocol")
plt.ylabel("Packet Count")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Traffic Rate Over Time
plt.figure()
plt.plot(traffic_rate.keys(), traffic_rate.values())
plt.title("Traffic Rate Over Time")
plt.xlabel("Time")
plt.ylabel("Packets per Second")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()














