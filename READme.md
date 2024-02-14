# CSC 361 - Networking Assignments

## Author

The assignments in this repository were written by Ali Gaineshev. Everything was written from scratch. No additional libraries are needed. Only Python's standard library. 
## Course Information

These assignments are part of the coursework for CSC361 at the University of Victoria (UVic).
## Instructor

The instructor for this course is *Kui Wu*, who provided most of the pcap files used in the assignments.

## Overview of files

### Smart Client - HTTP Client for Server Connection, Request, and Response Analysis

The SmartClient Python script is designed to act as an HTTP client. It connects to a server, sends an HTTP request, receives and analyzes the response, and prints information about the response. Additionally, it checks for features such as HTTP2 support, cookies information, and whether the website is password-protected.
### TCP Traffic Analysis

This Python program analyzes TCP connections in a packet capture (.cap) file. It provides insights into various connection details and statistics, including connection information, complete connection analysis, Round-Trip Time (RTT) calculation, and overall statistics.
### IP Datagram Analysis Program

The IP Datagram Analysis Program focuses on analyzing ICMP and UDP packets in a trace of IP datagrams. Specifically, it examines traces sent and received by the traceroute program by both Linux and Windows. 