Markdown
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
Install the required Python libraries:

Bash
pip install scapy customtkinter
Usage
Important: Packet sniffing requires administrative privileges to access the network interface card.

Open your terminal or command prompt as an Administrator (or use sudo on Linux/Mac).

Navigate to the project directory.

Run the application:

Bash
python modern_sniffer.py
Click ▶ Start Capture to begin listening to network traffic.

Select any packet in the table to view its layer-wise breakdown in the bottom terminal.

Click ⏹ Stop Capture, then use the export buttons to save your data as a .pcap or .txt file.

Project Team
Developed by computer engineering students at Pillai College of Engineering for the Cryptography and System Security course.

Divyanshu Mhatre (426)

Adheesh Nair (537)

Deep Malbari (522)

Muzamil Ahmad Wani (534)

Abhijit Nair (535)

Disclaimer
This tool is built strictly for educational and diagnostic purposes. Do not use it to intercept traffic on networks where you do not have explicit authorization.
