# **🕵️‍♂️ Raw Network Packet Sniffer**

A lightweight, cross-platform network packet sniffer built entirely from scratch using Python's native ```socket``` and ```struct``` libraries.

Unlike many Python sniffers that rely on heavy third-party libraries like ```scapy``` or ```pyshark```, this project interacts directly with the operating system's networking stack to capture and decode raw binary streams. It's a fantastic educational tool for understanding the OSI model, network encapsulation, and bitwise operations.

## **✨ Features**

* **Zero Dependencies:** Built using only Python standard libraries (```socket```, ```struct```, ```textwrap```, ```os```).  
* **Cross-Platform Compatibility:** \* **Linux:** Uses ```AF\_PACKET``` to capture traffic starting at Layer 2 (Ethernet Frames).  
  * **Windows:** Uses ```AF\_INET``` with ```SIO\_RCVALL``` (Promiscuous Mode) to capture traffic starting at Layer 3 (IPv4).  
* **Deep Protocol Decapsulation:** Peels back network layers one by one:  
  * **Layer 2:** Ethernet (MAC addresses, EtherType)  
  * **Layer 3:** IPv4 (TTL, Protocol, Source/Target IPs)  
  * **Layer 4:** TCP, UDP, and ICMP headers (Ports, Sequence numbers, Flags)  
* **Live Payload Extraction:** Currently configured with a **DNS Filter** (UDP Port 53\) that intercepts and decodes raw binary payloads into clean Hex dumps and human-readable text.

## **🚀 Getting Started**

### **Prerequisites**

Because raw sockets bypass the standard operating system networking stack, **this script requires Administrator / Root privileges to run.**

* Python 3.x installed

### **Running on Windows**

1. Open your Command Prompt (cmd) or PowerShell as **Administrator**.  
2. Navigate to the project directory.  
3. Run the script:  
   ```
   python main.py
   ```

### **Running on Linux / macOS**

1. Open your terminal.  
2. Run the script using sudo:  
   ```
   sudo python3 main.py
   ```

*(Note: macOS heavily restricts raw socket capture natively. Windows or Linux environments are highly recommended for the best experience).*

## **🧠 How It Works**

As packets travel across a network, data is encapsulated in layers (like a Russian nesting doll). This sniffer intercepts the raw byte stream as it hits the Network Interface Card (NIC) and reverses the process:

1. **Byte Order:** It reads the raw stream using Network Byte Order (Big-Endian).  
2. **```struct``` Unpacking:** Using Python's ```struct``` module, it slices the continuous byte stream into defined C-style variable lengths (e.g., extracting 6 bytes for a MAC address, or 2 bytes for an unsigned short port number).  
3. **Bitwise Operations:** For tightly packed headers (like the TCP Flags or the IPv4 Version/Header Length), it utilizes bitwise ```\>\>``` (shift) and ```&``` (AND) operations to isolate individual bits.

## **⚠️ Disclaimer**

This tool is designed strictly for **educational purposes and local system debugging**. Intercepting network traffic on networks you do not own or have explicit permission to monitor is illegal. Please use responsibly.
