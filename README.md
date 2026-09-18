# NetVision - Network Packet Analyzer

NetVision is a lightweight, custom GUI-based network packet sniffer developed in Python. Built as a mini-project for the Cryptography and System Security (CSS) course, it bypasses third-party tools like Wireshark to provide a transparent, code-level look at how raw network bytes are captured, filtered, and parsed into OSI layers.

## Features
* **Live Traffic Capturing:** Intercepts real-time network packets directly from the local machine's Network Interface Card (NIC).
* **Protocol Identification:** Specifically filters and identifies HTTP, DNS, TCP, UDP, and ICMP traffic.
* **Layer-Wise Dissection:** Programmatically extracts and displays Ethernet (Layer 2), IP (Layer 3), Transport (Layer 4), and Application (Layer 7) header details in a hierarchical tree format.
* **Data Export:** Save captured sessions as industry-standard `.pcap` binary files or generate human-readable `.txt` forensic reports.
* **Modern GUI:** Built with CustomTkinter and Python threading for a non-blocking, responsive dark-mode interface.

## Prerequisites
* **Python:** Version 3.8 or higher.
* **Npcap (Windows Only):** Scapy requires Npcap to capture raw packets on Windows. Download it from [npcap.com](https://npcap.com/) and ensure you check **"Install Npcap in WinPcap API-compatible Mode"** during installation.

## Installation
1. Clone this repository to your local machine:
   ```bash
   git clone [https://github.com/yourusername/NetVision.git](https://github.com/yourusername/NetVision.git)
   cd NetVision
