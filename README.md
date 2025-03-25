Traffic Network Analyzer

Traffic Network Analyzer is a powerful Python tool designed for analyzing network traffic from PCAP/PCAPNG files. It helps in traffic monitoring, cybersecurity analysis, and detecting malicious activities like port scanning and ARP spoofing.

✨ Features

✅ Extracts source & destination IPs, protocols, and packet sizes

✅ Detects port scanning & ARP spoofing

✅ Identifies top active hosts and protocols

✅ Analyzes bandwidth usage and DNS queries

✅ Command-line interface (CLI) for easy execution

🛠️ Installation

(If you encounter errors while installing, try using a virtual environment)

Create a Virtual Environment

<img width="350" alt="image" src="https://github.com/user-attachments/assets/31719991-4044-4f93-916e-ec0c095b802f" />

Activate the Virtual Environment

On Linux/macOS:

<img width="346" alt="image" src="https://github.com/user-attachments/assets/b225cfc2-3478-45f5-9879-776deaddfac8" />

On Windows:

<img width="341" alt="image" src="https://github.com/user-attachments/assets/aed92028-9d9f-4af3-96c7-bd53e899cbd1" />

Install Dependencies

<img width="344" alt="image" src="https://github.com/user-attachments/assets/7a963ad3-7afa-45a4-b1e9-b2bc256b70cc" />

🚀 Usage

Basic Traffic Analysis

Run the script with a PCAP file:

<img width="344" alt="image" src="https://github.com/user-attachments/assets/d9cc2bf2-1e84-475c-b5ec-b65d5828fab7" />

(Replace traffic.pcapng with the actual filename. If it does not work, try using a .pcap file instead.)

🔬 How It Works

1️⃣ Reads packets from .pcapng files using Scapy.
2️⃣ Extracts and analyzes source/destination IPs, protocols, and packet sizes.
3️⃣ Detects malicious activities like port scanning & ARP spoofing.
4️⃣ Prints network analysis results in a structured format.

📜 License

This project is open-source and available under the MIT License.






