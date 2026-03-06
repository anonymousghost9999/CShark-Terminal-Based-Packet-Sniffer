# C-Shark 🦈

*A Terminal-Based Packet Sniffer built with libpcap*

C-Shark is a lightweight command-line packet sniffer written in C using the **libpcap** library.
It captures live network packets from a selected network interface and performs **layer-by-layer protocol analysis** (Ethernet → IP → TCP/UDP → Payload).

The tool is inspired by Wireshark but designed as a **terminal-only educational network analyzer** that demonstrates how packet sniffing and protocol decoding work internally.

The program allows users to:

* Capture packets from a selected network interface
* Decode multiple network layers
* Apply protocol filters
* Store packets from a sniffing session
* Perform deep inspection of captured packets

---

# Features

## 1. Network Interface Discovery

At launch, the program scans all available network interfaces using `pcap_findalldevs()` and displays them to the user.

Example:

```
[C-Shark] Searching for available interfaces...

1. wlan0
2. any
3. lo
4. docker0

Select an interface to sniff:
```

The user selects an interface to start monitoring network traffic.

---

# Main Menu

After selecting an interface, the program provides the following menu:

```
Main Menu:
1. Start Sniffing (All Packets)
2. Start Sniffing (With Filters)
3. Deep Inspect of a single packet
4. Exit C-Shark
```

---

# Packet Capture

C-Shark captures packets using **libpcap's live capture API**.

Packets are processed using:

```
pcap_loop()
```

Each packet is decoded and printed with:

* Packet ID
* Timestamp
* Packet length
* Layer-2 information
* Layer-3 information
* Layer-4 information
* Layer-7 payload preview

Captured packets are also stored in memory for later inspection.

The packet structure used for storage:

```
typedef struct
{
    struct pcap_pkthdr header;
    const u_char *data;
} storedpkt;
```



Maximum stored packets:

```
#define MAX 10000
```



---

# Layer-by-Layer Packet Decoding

## Layer 2 — Ethernet

The program decodes Ethernet headers and displays:

* Source MAC address
* Destination MAC address
* EtherType

Supported EtherTypes:

| EtherType | Protocol |
| --------- | -------- |
| 0x0800    | IPv4     |
| 0x86DD    | IPv6     |
| 0x0806    | ARP      |

Example output:

```
L2(Ethernet):
Source MAC: B4:8C:9D:5D:86:A1
Destination MAC: E6:51:4A:2D:B0:F9
Ether Type : IPv4 (0x0800)
```

---

# Layer 3 — Network Layer

## IPv4

Decoded fields:

* Source IP
* Destination IP
* TTL
* Header Length
* Packet ID
* Flags (DF, MF)
* Protocol

Example:

```
L3(IPv4) || Source IP: 34.107.221.82
L3(IPv4) || Destination IP: 10.2.130.118
Protocol : TCP(6)
TTL : 118
Header length : 20 bytes
```

---

## IPv6

Decoded fields:

* Source IP
* Destination IP
* Hop Limit
* Next Header
* Traffic Class
* Flow Label
* Payload Length

Example:

```
L3(IPv6) || Source IP: 2409:40f0:d6:d3c9::5a
L3(IPv6) || Destination IP: 2404:6800:4007:83d::200a
Protocol : TCP(6)
Hop Limit : 64
Payload Length : 548
```

---

## ARP

Decoded fields:

* Operation (Request / Reply)
* Sender MAC
* Sender IP
* Target MAC
* Target IP
* Hardware Type
* Protocol Type

Example:

```
L3(ARP):
Operation: Request (1)
Sender MAC: 00:1D:45:55:2C:3F
Sender IP: 10.2.128.1
Target MAC: 00:00:00:00:00:00
Target IP: 10.2.138.236
```

---

# Layer 4 — Transport Layer

## TCP

Decoded fields:

* Source Port
* Destination Port
* Sequence Number
* Acknowledgment Number
* Flags (SYN, ACK, FIN, etc.)
* Window Size
* Checksum

Example:

```
Source Port : 35554
Destination Port : 443
Seq Num: 4016914192
Ack Num: 0
Flags: SYN
Window Size: 64800
Checksum: 0x804D
```

---

## UDP

Decoded fields:

* Source Port
* Destination Port
* Length
* Checksum

Example:

```
L4(UDP):
Source Port : 53
Destination Port : 45971
Length : 82 bytes
Checksum : 0x1A99
```

---

# Layer 7 — Payload Inspection

C-Shark attempts to identify application protocols based on port numbers.

Supported protocols:

| Port | Protocol |
| ---- | -------- |
| 80   | HTTP     |
| 443  | HTTPS    |
| 53   | DNS      |

The first **64 bytes of payload** are displayed using a **hex + ASCII dump** format.

Example:

```
16 03 03 00 25 10 00 00 21 20 A3 F9 BF D4 D4 6C
CC 8F CC E8 61 9C 93 F0 09 1A DB A7 F0 41 BF 78
```

The hex dump utility is implemented in the program. 

---

# Packet Filtering

Users can capture only specific types of packets using **BPF filters**.

Available filters:

| Option | Filter         |
| ------ | -------------- |
| HTTP   | `tcp port 80`  |
| HTTPS  | `tcp port 443` |
| ARP    | `arp`          |
| TCP    | `tcp`          |
| UDP    | `udp`          |
| DNS    | `udp port 53`  |

The program compiles and applies filters using:

```
pcap_compile()
pcap_setfilter()
```

---

# Packet Storage & Inspection

Captured packets are stored during a sniffing session.

Users can later inspect packets with the **Deep Inspect** feature.

The program displays:

* Packet summary list
* Packet selection by ID
* Full frame hex dump
* Layer-by-layer decoded fields
* Payload preview

Example:

```
[C-Shark] Packet Summary:
Packet #1 | Timestamp: 1757370992.553060 | Length: 66 bytes | IPv4
Packet #2 | Timestamp: 1757370992.568192 | Length: 179 bytes | IPv6
```

Selecting a packet performs a **detailed forensic breakdown**.

---

# Controls

| Key      | Action                           |
| -------- | -------------------------------- |
| Ctrl + C | Stop sniffing and return to menu |
| Ctrl + D | Exit program                     |

Signal handling is implemented to break packet capture safely.

---

# Project Structure

```
.
├── device.c      # Main packet sniffer implementation
├── header.h      # Network headers and libraries
├── Makefile      # Build configuration
└── README.md
```

`header.h` includes required networking and system libraries such as:

```
pcap.h
net/ethernet.h
netinet/ip.h
netinet/tcp.h
netinet/udp.h
net/if_arp.h
arpa/inet.h
```



---

# Compilation

Build the program using:

```
make
```

This compiles the program and generates the executable.

---

# Running the Program

Packet sniffing requires root privileges.

Run using:

```
sudo ./cshark
```

---

# Dependencies

The program requires the following:

* GCC
* libpcap
* Linux networking headers

Install libpcap (Ubuntu/Debian):

```
sudo apt install libpcap-dev
```

---

# Notes

* C-Shark is a **passive packet sniffer** and does not generate or inject network packets.
* Packet storage is limited to the most recent session.
* Memory allocated for stored packets is freed before starting a new capture session.

---

# Educational Purpose

This project demonstrates:

* Low-level packet capture
* Network protocol parsing
* Layered networking model
* BPF filtering
* Memory management in C

It provides a simplified view of how professional tools like **Wireshark** internally analyze network packets.

---
