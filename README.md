🚦 Traffic Network Analyzer

📌 Overview
Traffic Network Analyzer is a powerful Python tool designed for analyzing network traffic from PCAP/PCAPNG files. It helps in traffic monitoring, cybersecurity analysis, and detecting malicious activities like port scanning and ARP spoofing.

✨ Features
✅ Extracts source & destination IPs, protocols, and packet sizes
✅ Detects port scanning & ARP spoofing
✅ Identifies top active hosts and protocols
✅ Analyzes bandwidth usage and DNS queries
✅ Command-line interface (CLI) for easy execution

🛠️ Installation
(In case some error occurs while downloading try using  a Virtual Environment)
python3 -m venv venv
source venv/bin/activate   # For Linux/macOS
venv\Scripts\activate      # For Windows

Install Dependencies
pip install -r requirements.txt


🚀 Usage
Basic Traffic Analysis
Run the script with a PCAP file:
python3 analyze_traffic.py traffic.pcapng (traffic.pcapng can have any name , in case it dosen't woke try using .pcap )

🔬 How It Works
1️⃣ Reads packets from .pcapng files using Scapy.
2️⃣ Extracts and analyzes source/destination IPs, protocols, and packet sizes.
3️⃣ Detects malicious activities like port scanning & ARP spoofing.
4️⃣ Prints network analysis results in a structured format.


📜 License
This project is open-source and available under the MIT License.

