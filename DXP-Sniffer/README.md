# DXP-Sniffer
A low-level network packet analyzer written in C using Raw Sockets (AF_PACKET). Manually parses Ethernet, IP, TCP, and UDP headers without external libraries like libpcap.

# C Raw Socket Sniffer

A lightweight, low-level network packet sniffer developed in **C**.
Unlike standard tools that rely on libraries like `libpcap`, this project interacts directly with the Linux kernel using **Raw Sockets** to capture and analyze network traffic at the data link layer.

## ⚡ Technical Features

* **Raw Socket Implementation:** Uses `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` to bypass the standard network stack handling.
* **Protocol Decoding:** Manually parses headers using C structures and pointer arithmetic for:
    * **Layer 2:** Ethernet (MAC Addresses).
    * **Layer 3:** IPv4 (Source IPs, Protocol ID).
    * **Layer 4:** TCP & UDP (Source/Dest Ports, Header length calculation).
* **Payload Extraction:** Calculates dynamic offsets (Data Offsets) to extract and display ASCII/Hex payloads from packets.
* **Smart Filtering:** Distinguishes between TCP, UDP, and other protocols in real-time.

## 🛠️ Installation & Usage

This tool requires **root privileges** to access the network interface in promiscuous mode.

### 1. Compile
```bash
gcc sniffer.c -o sniffer
