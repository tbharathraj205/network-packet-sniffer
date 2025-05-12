
# Network Packet Sniffer 🕵️‍♂️

## Description

This is a simple Python-based network packet sniffer that captures live network traffic, logs the packet summaries, and saves captured packets for further analysis. It uses **Scapy** for sniffing and logging network traffic, and supports saving captured packets in `.pcap` format, which can be opened in Wireshark for detailed inspection.

## Features

- **Real-time Packet Capture**: Captures live network traffic using Scapy.
- **Protocol Detection**: Detects and displays **protocol types** such as TCP, UDP, and ICMP.
- **Packet Logging**: Logs the **source** and **destination IPs**, as well as the **protocol**.
- **Packet Storage**: Saves captured packets in `.pcap` format for later analysis.
- **Summary Logging**: Saves packet summaries to a `.txt` log file for easy viewing.

## Requirements

- **Python 3.x**
- **Scapy** library (for packet sniffing and analysis)

### Install the required library:

```bash
pip install scapy
````

# Network Packet Sniffer

## Installation Instructions

### Step 1: Install Python and Scapy

Ensure Python 3.x is installed on your machine.

Install Scapy using the following command:

```bash
pip install scapy
```

### Step 2: Run the Script

1. Open a terminal window.
2. Navigate to the directory containing the `network_packet_sniffer.py` file.
3. Run the script with **administrator (root) privileges**:

```bash
sudo python3 network_packet_sniffer.py
```

### Step 3: Stop the Capture

To stop capturing, press `Ctrl + C`.

The script will automatically save:

* Captured packets to a `.pcap` file
* Packet summaries to a `.txt` log file

## Output Files

* **Packet Log**: `packet_log_YYYYMMDD_HHMMSS.txt`
  Contains packet summaries (source IP, destination IP, protocol type)

* **Captured Packets**: `captured_packets_YYYYMMDD_HHMMSS.pcap`
  Can be opened with Wireshark for detailed analysis

## Project Structure

```
network_packet_sniffer/
│
├── network_packet_sniffer.py  # Main packet sniffer script (v1.0.0)
├── README.md                  # Project documentation
└── LICENSE                    # Open-source license (MIT)
```

## Version History

### v1.0.0 - Initial Release

* Basic packet sniffing functionality
* Logs packet details (IP addresses, protocol types)
* Saves output in both .txt and .pcap formats

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

* Scapy community for providing an excellent library for network packet analysis
* Open-source community for their contributions to network traffic analysis tools

## Troubleshooting

| Issue                        | Solution                                            |
| ---------------------------- | --------------------------------------------------- |
| Script not capturing packets | Ensure you have admin/root privileges               |
| No output in log file        | Verify network traffic and active network interface |

## Future Enhancements

* [ ] Packet filtering (specific IPs or protocols)
* [ ] Simple GUI implementation
* [ ] Real-time traffic analysis with pattern alerts


