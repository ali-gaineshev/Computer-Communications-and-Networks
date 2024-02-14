# IP Datagram Analysis Program
Analyses ICMP and UDP packets!

## Goal
The goal of this assignment is to explore the IP protocol by analyzing a trace of IP datagrams. The provided Python program is designed to analyze a trace of IP datagrams sent and received by an execution of the traceroute program in both Linux and Windows.


## Program Overview
The provided Python program leverages the [packet_struct](packet_struct.py) module to parse and analyze a trace file in pcap format. The primary functionalities of the program include:

- Reading and parsing the pcap file
- Analyzing intermediate routers, fragments, and source node details
- Calculating Round-Trip Time (RTT) for relevant packets
- Generating outputs for specific questions (r1 and r2)

## Files:
* a3.py - the main file of the program, which prints out both r1 and r2 parts. To run
* packet_struct.py - Struct of a packet. Classes - global_header, packet, UDP_header, ICMP_header
* .pcap files - provided by Kui Wu

## Usage
To run the program, execute the following command in the terminal:

```bash
python3 a3.py <pcap file> <r2>
```
<file> - pcap file to read. No error catching. 
<r2> - optional command to only print r2 part (relevant only to pcap file)

## Sample output

![alt text](<../readme_images/Screenshot from 2024-02-14 12-48-39.png>)