## Network Traffic Analyzer

A Python-based network traffic analysis tool that processes Wireshark PCAP files to extract insights such as protocol distribution, IP and port analysis, traffic rate trends, and basic anomaly detection.

# Features
- Protocol distribution analysis
- Source and destination IP analysis
- TCP/UDP port analysis
- Traffic rate (packets per second) analysis
- Detection of traffic spikes and malformed packets
- Graphical visualization using Matplotlib

# Technologies Used
- Python
- PyShark
- Wireshark (PCAP files)
- Matplotlib

# Project Structure
network-traffic-analyzer/
├── analyzer.py
├── pcaps/
│ └── sample_pcap_here.txt


# How to Run
1. Install dependencies:
   pip install pyshark matplotlib
2. Place a `.pcapng` file inside the `pcaps/` folder.
3. Update the file path in `analyzer.py` if required.
4. Run: python analyzer.py


# Learning Outcomes
- Understanding of network traffic and protocols
- Hands-on experience with PCAP file analysis
- Exposure to anomaly detection techniques
- Data visualization for network monitoring

# Future Improvements
- CSV export of analysis results
- Port-to-service name mapping
- Advanced anomaly detection
- Live traffic capture support


