# network_packet_sniffer.py

from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
import datetime

# Log file to save packet summaries
log_file = f"packet_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

# List to store captured packets
captured_packets = []


def packet_callback(packet):
    summary = ""

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ""

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        summary = f"[+] {protocol} Packet: {src_ip} -> {dst_ip}"
        print(summary)

        # Log to file
        with open(log_file, "a") as log:
            log.write(summary + "\n")

        # Save packet to list
        captured_packets.append(packet)


if __name__ == '__main__':
    print("[INFO] Starting packet capture. Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping capture and saving packets to file...")
        pcap_filename = f"captured_packets_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(pcap_filename, captured_packets)
        print(f"[INFO] Packets saved to {pcap_filename}")
        print(f"[INFO] Packet summary log saved to {log_file}")
