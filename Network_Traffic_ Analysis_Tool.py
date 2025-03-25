import sys
import logging
from scapy.all import *
import pandas as pd  # type: ignore
from tabulate import tabulate
from tqdm import tqdm
from scapy.error import Scapy_Exception

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

def read_pcap(pcap_file):
    """Read packets from a PCAP file."""
    try:
        return rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        sys.exit(1)

def extract_packet_data(packets):
    """Extract essential packet data."""
    packet_data = [
        {"src_ip": p[IP].src, "dst_ip": p[IP].dst, "protocol": p[IP].proto, "size": len(p)}
        for p in tqdm(packets, desc="Processing packets", unit="packet") if IP in p
    ]
    return pd.DataFrame(packet_data)

def protocol_name(number):
    """Map protocol number to name."""
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    """Analyze network traffic data."""
    if df.empty:
        return 0, pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    
    df["protocol"] = df["protocol"].map(protocol_name)
    total_bandwidth = df["size"].sum() / 10**6  # Convert to MB
    
    protocol_counts = df["protocol"].value_counts(normalize=True) * 100
    protocol_counts_df = protocol_counts.reset_index().rename(columns={"index": "Protocol", "protocol": "Percentage"})
    
    ip_communication = df.groupby(["src_ip", "dst_ip"]).size().reset_index(name="Count")
    ip_communication["Percentage"] = ip_communication["Count"] / ip_communication["Count"].sum() * 100
    
    return total_bandwidth, protocol_counts_df, ip_communication

def extract_packet_data_security(packets):
    """Extract packet data for security analysis."""
    packet_data = [
        {
            "src_ip": p[IP].src,
            "dst_ip": p[IP].dst,
            "protocol": protocol_name(p[IP].proto),
            "size": len(p),
            "dst_port": p[TCP].dport if TCP in p else 0,
        }
        for p in tqdm(packets, desc="Processing packets for security analysis", unit="packet") if IP in p
    ]
    return pd.DataFrame(packet_data)

def detect_port_scanning(df, threshold=100):
    """Detect potential port scanning activities."""
    if df.empty:
        return
    port_scan_df = df.groupby(["src_ip", "dst_port"]).size().reset_index(name="count")
    unique_ports_per_ip = port_scan_df.groupby("src_ip")["dst_port"].nunique().reset_index(name="unique_ports")
    scanners = unique_ports_per_ip[unique_ports_per_ip["unique_ports"] >= threshold]
    if not scanners.empty:
        logger.warning(f"Potential port scanning detected from: {', '.join(scanners['src_ip'])}")

def detect_dns_queries(packets):
    dns_queries = []
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(DNS) and packet[DNS].qr == 0:  # Ensure IP and DNS layers exist
            queried_domain = (
                packet[DNSQR].qname.decode() if packet.haslayer(DNSQR) and packet[DNSQR].qname else "Unknown"
            )
            dns_queries.append({"src_ip": packet[IP].src, "queried_domain": queried_domain})

    if dns_queries:
        df_dns = pd.DataFrame(dns_queries)
        logger.info("\nDNS Queries Detected:\n")
        logger.info(tabulate(df_dns, headers="keys", tablefmt="grid"))


def detect_arp_spoofing(packets):
    """Detect potential ARP spoofing."""
    arp_table = {}
    for p in packets:
        if p.haslayer(ARP) and p[ARP].op == 2:
            src_ip, src_mac = p[ARP].psrc, p[ARP].hwsrc
            if src_ip in arp_table and src_mac not in arp_table[src_ip]:
                logger.warning(f"Potential ARP Spoofing Detected! IP: {src_ip}, MACs: {arp_table[src_ip] | {src_mac}}")
            arp_table.setdefault(src_ip, set()).add(src_mac)

def print_results(total_bandwidth, protocol_counts_df, ip_communication):
    """Print network analysis results."""
    logger.info(f"Total bandwidth used: {total_bandwidth:.2f} MB")
    logger.info("\nProtocol Distribution:\n" + tabulate(protocol_counts_df, headers="keys", tablefmt="grid"))
    logger.info("\nTop IP Address Communications:\n" + tabulate(ip_communication, headers="keys", tablefmt="grid", floatfmt=".2f"))

def main(pcap_file, port_scan_threshold=100):
    """Main function to analyze network traffic and security threats."""
    packets = read_pcap(pcap_file)
    
    # Traffic Analysis
    df = extract_packet_data(packets)
    total_bandwidth, protocol_counts_df, ip_communication = analyze_packet_data(df)
    print_results(total_bandwidth, protocol_counts_df, ip_communication)
    
    # Security Analysis
    df_security = extract_packet_data_security(packets)
    detect_port_scanning(df_security, port_scan_threshold)
    detect_dns_queries(packets)
    detect_arp_spoofing(packets)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("Usage: python script.py <pcap_file> [port_scan_threshold]")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    port_scan_threshold = int(sys.argv[2]) if len(sys.argv) >= 3 and sys.argv[2].isdigit() else 100
    main(pcap_file, port_scan_threshold)
