# TCP Traffic Analysis
This Python program analyzes TCP connections in a packet capture (.cap) file, providing insights into various connection details and statistics. Sample output is provided

Usage:

```
python3 tcp_info.py [].cap
```

Functionality

    Command-Line Arguments
        The program expects a single command-line argument specifying the path to the packet capture file (.cap).

    Packet Analysis
        Reads the specified packet capture file and extracts information about TCP connections.

    Connection Details
        Prints detailed information for each TCP connection, including source/destination addresses, ports, status, and releevant flags.

    Complete Connections
        Identifies and analyzes complete TCP connections, providing details such as start time, end time, duration, number of packets, data bytes sent, and more.

    Round-Trip Time (RTT) Calculation
        Calculates and prints RTT values for packets in complete connections.

    Overall Statistics
        Provides general statistics on the total number of complete TCP connections, reset TCP connections, and open connections at the end of the trace capture.

    Complete Connection Statistics
        Analyzes and prints statistics for complete TCP connections, including minimum/mean/maximum time duration, RTT values, number of packets, and receive window sizes.

How to Read Output

* Connection details are displayed for each identified TCP connection, with a summary at the end.
* The program categorizes connections as either complete or reset based on flags (SYN, FIN, RST).
* General statistics and detailed statistics for complete connections are provided at the end of the output.

Notes

    This program is designed for analyzing packet capture files and extracting TCP connection details for further analysis.

Sample Output 

![alt text](<../readme_images/Screenshot from 2024-02-14 12-26-30.png>)