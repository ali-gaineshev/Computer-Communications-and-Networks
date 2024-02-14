import sys
import packet_struct
import struct
import statistics
from typing import Tuple, List

def main():
    file = parse_argument()
    cons, cons_packets = read_file(file)
    analyze_cons(cons, cons_packets)

def parse_argument()->str:
    """
    Parse the command line arguments to get the input file path.
    
    Returns:
        str: The input file
    """
    if(len(sys.argv) != 2):
        print("Usage: python3 tcp_info filepath/file.cap")
        exit(1)
    return sys.argv[1]

def analyze_cons(cons, cons_packets)->None:
    """
    Analyze the TCP connections and prints connection details, statistics for complete connections.
    
    Args:
        cons (List[Tuple]): List of connection tuples (source IP, destination IP, source port, destination port)
        cons_packets (List[List[packet_struct.packet]]): List of lists of data packets for each corresponding connection
    """
    all_rtt = []
    i = 0
    total_complete = 0
    total_reset = 0
    duration = []
    all_packets = []
    window_sizes = []

    for conn in cons:
        conns_complete = []
        conns_packets_complete = []

        complete = False

        syn = 0
        fin = 0
        rst = ""

        all_flags = []
        start_time = 0
        end_time = 0
        src_to_dest = 0
        bytes_sent = 0
        bytes_received = 0
        local_window_sizes = []
        src_packets = []
        dest_packets = []

        for packet in cons_packets[i]:
            tcp_info = packet.TCP_header.tcp_get_info()

            num_packets = len(cons_packets[i])
            src_ip, dst_ip = packet.IP_header.retrieve_IP()

            window_size = tcp_info[6]
            local_window_sizes.append(window_size)

            ihl = packet.IP_header.retrieve_ihl()
            total_len = packet.IP_header.retrieve_total_len()
            data_offset = packet.TCP_header.data_offset_get()

            #check if it's source to destination
            if(src_ip == conn[0] and dst_ip == conn[1]):
                src_to_dest += 1
                bytes_sent += (total_len - ihl - data_offset)
                src_packets.append(packet)
            else:
                bytes_received += (total_len - ihl - data_offset)
                dest_packets.append(packet)

            #check flags
            flags = tcp_info[5]
            if(flags["SYN"] == 1):
                if(syn == 0):#first syn
                    start_time = packet.get_timestamp()
                syn += 1
            
            if(flags["FIN"] == 1):
                fin += 1

            if(flags["RST"] == 1):
                rst = "/R"

            if(flags["SYN"] == 1 and flags["FIN"] == 1):
                syn += 1

            all_flags.append((syn,fin, rst))
            


        if(all_flags[-1][0] >= 1 and all_flags[-1][1] >= 1):#complete connection: at least 1 syn and 1 fin
            total_complete +=1
            complete = True

            conns_complete.append(cons)
            conns_packets_complete.append(cons_packets[i])#packet data
            window_sizes.extend(local_window_sizes)

        if(all_flags[-1][2] == "/R"):#total reset connections
            total_reset += 1

        one_fin = 0 #checker for one fin, index
        for j in range(len(all_flags)):
            #flags are saved as added, therefore I need to find 
            #first occurence of 2 FINS or 1 FIN
            if(all_flags[j][1] == 1):#fin
                if(one_fin == 0):
                    one_fin = j

                end_time = cons_packets[i][j].get_timestamp()

            if(all_flags[j][1] == 2):#fins founds
                one_fin = -1
                end_time = cons_packets[i][j].get_timestamp()
                break  


        if(one_fin != -1): 
            end_time = cons_packets[i][one_fin].get_timestamp()

        print(f"Connection {i+1}:")
        print(f"Source Address: {conn[0]}")
        print(f"Destination Address: {conn[1]}")
        print(f"Source Port: {conn[2]}")
        print(f"Destination Port: {conn[3]}")
        print(f"Status: S{all_flags[-1][0]}F{all_flags[-1][1]}{all_flags[-1][2]}")

        if(complete):
            print(f"Start time: {round(start_time, 6)} seconds")
            print(f"End Time: {round(end_time,6)} seconds")
            print(f"Duration: {round(end_time-start_time,6)} seconds")
            print(f"Number of packets sent from Source to Destination: {src_to_dest}")
            print(f"Number of packets sent from Destination to Source: {num_packets - src_to_dest}")
            print(f"Total number of packets: {num_packets}")
            print(f"Number of data bytes sent from Source to Destination: {bytes_sent}")
            print(f"Number of data bytes sent from Destination to Source: {bytes_received}")
            print(f"Total number of data bytes: {bytes_sent + bytes_received}")
            print("END")

            rtt = get_rtt(src_packets, dest_packets)
            all_rtt.extend(rtt)

            all_packets.append(num_packets)
            duration.append(end_time-start_time)

        print(f"{'+'*32 if i != len(cons)-1 else '_' * 48}")

        i += 1

    print("\nC) General\n")
    print(f"Total number of complete TCP connections: {total_complete}")
    print(f"Number of reset TCP connections: {total_reset}")
    print(f"Number of TCP connections that were still open when the trace capture ended: {len(cons)-total_complete}")
    print("_"*48 + "\n")

    print("D) Complete TCP connections\n")
    analyze_complete_conns(duration, all_packets, window_sizes, all_rtt)



def get_rtt(src_packets, dest_packets)->List:
    """
    Calculate RTT values for a set of source and destination packets.

    Args:
        src_packets (List[packet_struct.packet]): List of source packets.
        dest_packets (List[packet_struct.packet]): List of destination packets.

    Returns:
        List: A list of RTT values in seconds.
    """
    rtt_vals = []

    for src in src_packets:
        if (src.TCP_header.flags["RST"] != 1 and src.TCP_header.data_offset > 0  ):# Check if it's not a pure ACK
            for dest in dest_packets:
                if (
                    src.TCP_header.ack_num == dest.TCP_header.seq_num and dest.TCP_header.ack_num == src.TCP_header.seq_num + 1):
                    rtt_val = dest.get_timestamp() - src.get_timestamp()
                    rtt_vals.append(rtt_val)

    return rtt_vals             

            


def analyze_complete_conns(duration,all_packets, window_sizes, rtts):
    """
    Analyzes and prints statistics for complete connections.

    Args:
    duration: List of connection durations.
    all_packets : List of the number of packets for each connection
    window_sizes : List of receive window sizes
    rtts : List of Round-Trip Time values.

    Returns:
    None
    """

    print(f"Minimum time duration: {round(min(duration),6)} seconds")
    print(f"Mean time duration: {round(statistics.mean(duration), 6)} seconds")
    print(f"Maximum time duration: {round(max(duration),6)} seconds\n")


    print(f"Minimum RTT value: {round(min(rtts),6)}")
    print(f"Mean RTT value: {round(statistics.mean(rtts),6)}")
    print(f"Maximum RTT value: {round(max(rtts),6)}\n")

    print(f"Minimum number of packets including both send/received: {round(min(all_packets),6)}")
    print(f"Mean number of packets including both send/received: {round(statistics.mean(all_packets),6)}")
    print(f"Maximum number of packets including both send/received: {round(max(all_packets),6)}\n")

    print(f"Minimum receive window size including both send/received: {round(min(window_sizes),6)} bytes")
    print(f"Mean receive window size including both send/received: {round(statistics.mean(window_sizes),6)} bytes")
    print(f"Maximum receive window size including both send/received: {round(max(window_sizes),6)} bytes")
    print("_"*48 + "\n")

def read_file(file)->(List[Tuple], List[List[packet_struct.packet]]):
    """
    Reads a .cap file, saves every packet and connection to analyze it later.

    Args:
    file : The path to the .cap file to be read.

    Returns:
        cur_cons : List of connection tuples, each representing a connection with (source_ip, dest_ip, source_port, dest_port).
        packets_of_cons : List of lists, each representing packets for corresponding connection.
    """
    global_header = packet_struct.global_header()
    LITTLE_ENDIAN = "<"
    BIG_ENDIAN = ">"
    with open(file,"rb") as f:
        header = f.read(24)

        if header[:4] == b"\xa1\xb2\xc3\xd4":
            endianness = BIG_ENDIAN
        elif header[:4] == b"\xd4\xc3\xb2\xa1":
            endianness = LITTLE_ENDIAN
        else:
            print("Couldn't read the magic number")
            exit(1)
        
        gl_header = struct.unpack(endianness + "IHHiIII", header)
        global_header.set_headers(gl_header, endianness)

        connections = 0

        first_packet = 1
        cur_cons = []
        packets_of_cons = []
        while f.readable():
            #read every 16 bytes to get header
            #read data 
            #repeat
            packet = packet_struct.packet()
            header = f.read(16)
            
            if(header is None or len(header) == 0 or len(header) < 16):
                break
        
            header_info = struct.unpack(endianness + "IIII", header)

            if(first_packet == 1):#first packet, set orig time for the rest of them
                orig_time = packet.timestamp_set(header_info[0], header_info[1] , 0)            
                first_packet = 0

            
            packet.timestamp_set(header_info[0], header_info[1] ,orig_time)
            packet.packet_set_headers(header_info)
            incl_len = header_info[2]

            packet_data = f.read(incl_len)#read packet data
            ihl = 14 + packet.IP_header.get_header_len(packet_data[14:15]) #14 to skip ethernet header

            packet.IP_header.get_total_len(packet_data[16:18])
            s_ip, d_ip = packet.IP_header.get_IP(packet_data[26:30], packet_data[30:34])

            src_port = packet.TCP_header.get_src_port(packet_data[ihl:ihl+2])
            dst_port = packet.TCP_header.get_dst_port(packet_data[ihl+2:ihl+4])
            packet.TCP_header.get_seq_num(packet_data[ihl+4:ihl+8])
            packet.TCP_header.get_ack_num(packet_data[ihl+8:ihl+12])
            packet.TCP_header.get_data_offset(packet_data[ihl+12:ihl+13])
            packet.TCP_header.get_flags(packet_data[ihl+13:ihl+14])
            packet.TCP_header.get_window_size(packet_data[ihl+14:ihl+15], packet_data[ihl+15:ihl+16])


            con, con_rev = get_conn_tuple(s_ip, d_ip, src_port, dst_port)

            #check for src->dest and dest->src to make connection tuple
            if(con in cur_cons ):
                packets_of_cons[cur_cons.index(con)].append(packet)

            elif(con_rev in cur_cons):
                packets_of_cons[cur_cons.index(con_rev)].append(packet)

            else:
                connections += 1
                cur_cons.append(con)
                packets_of_cons.append([])
                packets_of_cons[connections-1].append(packet)

    print(f"A) Total number of connections: {connections}")
    print("_"*48 + "\n")
    print("B) Connection's details\n")
    return cur_cons, packets_of_cons

def get_conn_tuple(s_ip, d_ip, src_port, dst_port)-> (Tuple, Tuple):
    """
    Create two connection tuples: one with source and destination, and the other with reversed source and destination.
    
    Args:
        s_ip : Source IP address.
        d_ip : Destination IP address.
        src_port : Source port.
        dst_port : Destination port.
        
    Returns:
        2 Tuples: Two connection tuples (source IP, destination IP, source port, destination port) and reversed.
    """
    return (s_ip, d_ip, src_port, dst_port), (d_ip, s_ip, dst_port, src_port)   

if __name__ == '__main__':
    main()