import sys
from packet_struct import *
import struct
import statistics


GLOBAL_HEADER_BYTES = 24
PACKET_HEADER_BYTES = 16
SIZE_OF_ETHERNET_HEADER = 14
SIZE_OF_ICMP_HEADER = 8
SIZE_OF_UDP_HEADER = 8

def main():
    file = parse_argument()
    intermediate_routers, fragment_output, src_node, protocols = read_file(file)
    intermediate_routers_ips = get_interm_routers_ips(intermediate_routers)
    rtt_output = calc_rtt(intermediate_routers, src_node, "r1")

    if(len(sys.argv) >= 3):#if 3rd argument is "r2" then print only r2 statistics
        if(sys.argv[2] == "r2"):
            r2_output(intermediate_routers, src_node, file)
    else:
        r1_output(intermediate_routers_ips, fragment_output, src_node, protocols, rtt_output)
        r2_output(intermediate_routers, src_node, file)

def parse_argument():
    """
    Parse the command line arguments to get the input file path.
    
    Returns:
        str: The input file
    """
    if(len(sys.argv) < 2):
        print("Usage: python3 tcp_info filepath/file.cap")
        exit(1)
    return sys.argv[1]

def r1_output(intermediate_routers,  fragment_output, src_node, protocols, rtt_output):
    """
    prints out information for answering r1
    Returns:
        None
    """
    dest_node = intermediate_routers.pop(-1)[0]
    TAB = 4*" "
    print("----------------------------------------------")
    print("R1")
    print(f"The IP address of the source node: {src_node}")
    print(f"The IP address of the ultimate destionation node: {dest_node}")
    print(f"The IP addresses of the intermediate nodes:")

    #print routers info
    for info in intermediate_routers:
        print(f"{TAB}router {info[1]}: {info[0]}")

    print(f"\nThe values in protocol field of IP headers:")
    #print protocol info
    for prot in protocols:
        if(prot == 1):
            print(f"{TAB}1 : ICMP")
        elif(prot == 17):
            print(f"{TAB}17 : UDP")
    print()
    #print fragmentation info
    if(len(fragment_output) != 0):
        for fragment_info in fragment_output:
            print(fragment_info, "\n")
    else:
        print("The number of fragments created from the original datagram is: 1") 
        print("The offset of the last fragment is: 0\n")
    #print rtt info
    for rtt in rtt_output:
        print(rtt)


def r2_output(routers, src_node, file):
    """
    Prints out information for answering r2
    Returns:
        None
    """
    debug = False#change to True if needs to be debugged

    ttl_count = {}
    ips = []
    print("R2")
    for key_ip in routers:
        if(key_ip == "No_response"):
            continue

        ips.append(key_ip)
        if(debug):
            print("Router: ", key_ip)
            print("Total matching arrays: ", len(routers[key_ip]))

        for list_packets in routers[key_ip]:
            receiver_packet = list_packets[-1]
            
            for packet in list_packets:
                if(packet != receiver_packet):
                    ttl = packet.IP_header.ttl
                    if(ttl not in ttl_count):
                        ttl_count[ttl] = 1
                    else:
                        ttl_count[ttl] += 1
                        
    ips.pop(-1)#last one is the destinatione node
    
    no_response_packets = routers["No_response"]
    for packet in no_response_packets:

        for ttl in ttl_count:
            if(packet.IP_header.ttl == ttl):
                ttl_count[ttl] += 1
                break
        

    print("File name: ", file)
    print("\nTTL count:")
    for ttl in ttl_count:
      print(f"TTL: {ttl}, Count: {ttl_count[ttl]}") 
    
    print("\nSequence of routers:")
    i = 1
    for ip in ips:
        print(f"Router {i}, ip - {ip}")
        i += 1 
    
    if("group2" in file):#windows file, only relevant for assignment. For any file - implement global os variable
        ttl_rtts = calc_rtt(routers,src_node,"r2")
        sum = 0
        print("\n{:<7}{}".format("TTL", f"Average RTT in {file}"))
        for ttl in ttl_rtts:
            rtt_avg = statistics.mean(ttl_rtts[ttl])
            sum += rtt_avg
            print("{:<7}{:.6f}".format(ttl, rtt_avg))
        sum = sum - rtt_avg #last one is the src node to dest node
        print("\nTotal sum is ", sum)


def calc_rtt(routers, src_node,r_part):
    """
    Calculates rtt of different ip routers
    Params:
        routers - dictionary of ips as keys and array of arrays of packets related to that ip.
        src_node - source node
        r_part - 2 options : "r1" - to calculate for r1 queston and "r2" - ...
    Returns:
        if r1 - rtt_output: array of strings to output
        if r2 - ttl_rtts: dictionary of ttls as keys and array of rtts as values 
    """
    rtt_output = []

    ttl_rtts = {}
    for ip in routers.keys():
        if(ip == "No_response"):
            continue

        packet_lists = routers[ip]
        avg = 0
        rtt = 0
        st_dev = []
        total_conns = 0
        for packets_list in packet_lists:

            receiver_packet = packets_list[-1]

            for packet in packets_list:
                if(packet != receiver_packet):
                    rtt = receiver_packet.timestamp - packet.timestamp
                    avg += rtt
                    total_conns += 1
                    st_dev.append(rtt)
                    
                    if(r_part == "r2"):
                        ttl = packet.IP_header.ttl
                        try:
                            ttl_rtts[ttl].append(rtt)
                        except:
                            ttl_rtts[ttl] = [rtt]
                        
        if(r_part == "r1"):
            avg = round(avg/total_conns, 6)
            st_dev = round(statistics.pstdev(st_dev, mu = None),6)

            output = f"The average RTT between {src_node} and {ip} is: {avg} ms, the s.d. is: {st_dev} ms"
            rtt_output.append(output)

    if(r_part == "r1"):
        return rtt_output

    elif(r_part == "r2"):
        return ttl_rtts
    else:
        print("error with calculating rtt")
        exit()

def get_interm_routers_ips(routers):
    """
    Param routers is stored as dictionary with {ip- string : [array of packets]}. gets each ip and first ttl of array of packets values
    return array of tuples of (ip, ttl)
    """
    ips = []
    for ip in routers.keys():
        if(ip == "No_response"):
            continue
        ips.append((ip, routers[ip][0][0].IP_header.ttl))

    return ips


def read_file(file):
    """
    Reads a .pcap file, sets values to each packet to later analyze it.

    Args:
    file : The path to the .cap file to be read.

    Returns:
         routers - dictionary of ips as keys and array of arrays of packets related to that ip.
        fragment_output - array of strings, for r1 question
        src_node 
        unique protocols - either ICMP or UDP or both
    """
    gl_header = global_header()
    os = "windows"
    source_node = ""
    packets = []

    with open(file,"rb") as f:
        header = f.read(GLOBAL_HEADER_BYTES)
        metric = gl_header.get_global_header_into(header)
        endianness = gl_header.endianness

        packet_num = 1
        fragmented = False
        unique_protocols = set()
        while f.readable():
            #read every 16 bytes to get header
            #read data 
            #repeat
            cur_packet = packet()
            header = f.read(PACKET_HEADER_BYTES)
            
            if(header is None or len(header) == 0 or len(header) < PACKET_HEADER_BYTES):
                break
        
            packet_header_info = struct.unpack(endianness + "IIII", header)
            cur_packet.packet_No_set(packet_num)
            
            cur_packet.packet_set_headers(packet_header_info)
            incl_len = packet_header_info[2]

            packet_data = f.read(incl_len)#read packet data
            ihl = cur_packet.IP_header.fill_ipv_header(packet_data, SIZE_OF_ETHERNET_HEADER)
            ihl = ihl + SIZE_OF_ETHERNET_HEADER

            protocol = cur_packet.IP_header.protocol

            if(packet_num == 1):#first packet, set orig time for the rest of them
                orig_time = cur_packet.timestamp_set(packet_header_info[0], packet_header_info[1] , 0, metric)   
                source_node = cur_packet.IP_header.src_ip

            #we only care if packets are udp or icmp
            if(protocol != 17 and protocol != 1):
                continue

            cur_packet.timestamp_set(packet_header_info[0], packet_header_info[1] ,orig_time, metric)#needed?
            
            if(protocol == 17):#udp only in linux, but it can be a DNS 
                if(cur_packet.IP_header.flags == 1 and fragmented == False):#first one to fragment
                    cur_packet.UDP_header.read_headers(packet_data[ihl:ihl+SIZE_OF_UDP_HEADER])
                    fragmented = True
                    unique_protocols.add(17)
                    os = "linux"

                elif(cur_packet.IP_header.flags == 0 and cur_packet.IP_header.fragment_offset != 0):# last of fragmented
                    fragmented = False

                else: #non fragmented
                    cur_packet.UDP_header.read_headers(packet_data[ihl:ihl+SIZE_OF_UDP_HEADER])

                    #check if within right dst port range so it's not DNS or other packets
                    if(cur_packet.UDP_header.dst_port >= 33434) and (cur_packet.UDP_header.dst_port <= 33529):#have to do it twice, because of DNS which sends udp too
                        unique_protocols.add(17)
                        os = "linux"

            if(protocol == 1):#ICMP
                unique_protocols.add(1)
                cur_packet.ICMP_header.read_headers(packet_data,ihl)

            packets.append(cur_packet)#removed most, but there are still some unncessary
            packet_num += 1


    relevant_packets = remove_irrelevant(packets, os)

    intermediate_routers, fragments_output = analyze_packets(relevant_packets, os)

    return intermediate_routers, fragments_output, source_node, list(unique_protocols)

def remove_irrelevant(packets, os):
    """
    Removes all irrelevant packets! Depending on the os, either all ICMP or (UDP and ICMP), but excludes DNS and other irrelavant ones
    Returns:
        array of relevant packets
    """
    relevant_packets = []
    for cur_packet in packets:
        #print(cur_packet)
        if(os == "linux"):

            if(cur_packet.IP_header.protocol == 17):
                if(cur_packet.IP_header.flags == 1):#fragmented assumed to be in
                    relevant_packets.append(cur_packet)

                elif(cur_packet.IP_header.flags == 0 and cur_packet.IP_header.fragment_offset != 0):#last part of fragmented
                    relevant_packets.append(cur_packet)

                elif(cur_packet.UDP_header.dst_port >= 33434) and (cur_packet.UDP_header.dst_port <= 33529):#non relevant packets are excluded, such as DNS, NTP, etc
                    relevant_packets.append(cur_packet)

            elif(cur_packet.IP_header.protocol == 1):
                if(cur_packet.ICMP_header.type in [0,3,8,11]):
                    relevant_packets.append(cur_packet)

        elif(os == "windows"):
            if(cur_packet.IP_header.protocol == 1):
                if(cur_packet.ICMP_header.type in [0,3,8,11]):
                    relevant_packets.append(cur_packet)

    return relevant_packets

def analyze_packets(relevant_packets, os):   
    if(os == "linux"):
        return match_packets_linux(relevant_packets)
    elif(os == "windows"):
        return match_packets_windows(relevant_packets)

    else:
        print("Error with getting the os")
        exit()

def match_packets_linux(packets):
    """
    Main function to match packets together; only for linux with UDP as sending and ICMP as receiving
    Returns:
        routers - dictionary of ips as keys and array of arrays of packets related to that ip.
        fragment_output - array of strings, for r1 question
    """
    udp_packets = []
    icmp_packets = []

    #separate into icmp and udp packets
    for packet in packets:
        if(packet.IP_header.protocol == 17):
            udp_packets.append(packet)

        elif(packet.IP_header.protocol == 1):
            icmp_packets.append(packet)
    
    #get matching UDPs together, mostly for fragments. 
    matching_packets = match_packets(udp_packets)#based on src port
    
    if(len(matching_packets) == 0):
        print("Error with matching packets!")
        exit()

    fragments_output = find_fragments(matching_packets)
    #match udp with icmp
    for packet in icmp_packets:
        
        for inner_matching_packets in matching_packets:
            protocol = packet.ICMP_header.inner_protocol["inner_UDP"]
            if(protocol.src_port == inner_matching_packets[0].UDP_header.src_port):
                inner_matching_packets.append(packet)
                break
    

    #find ips of routerts and group packets based on ip
    intermediate_routers = {"No_response": []} #dictionary of keys = routers ip with keys as array of all packets sent to the router
    for inner_matching_packets in matching_packets:
        if(len(inner_matching_packets) == 1):#there is no response to this packet, but still add it for R2
            intermediate_routers["No_response"].append(inner_matching_packets[0])
            continue

        for packet in inner_matching_packets:

            if(packet.IP_header.protocol == 1):#ICMP and it exists
                key_ip = packet.IP_header.src_ip
                if(key_ip not in intermediate_routers.keys()):
                    intermediate_routers[key_ip] = [inner_matching_packets]
                
                else:
                    intermediate_routers[key_ip].append(inner_matching_packets)

    return intermediate_routers, fragments_output
    
def match_packets_windows(packets):
    """
    Main function to match packets together; only for windows with ICMP as sending and ICMP as receiving
    Returns:
        routers - dictionary of ips as keys and array of arrays of packets related to that ip.
        fragment_output - array of strings, for r1 question
    """
    sender_packets = []
    receiver_packets = []

    for packet in packets:
        if packet.ICMP_header.type == 8:
            sender_packets.append(packet)

        elif packet.ICMP_header.type in [0,3,11]:
            receiver_packets.append(packet)

    matching_packets = match_packets(sender_packets)

    if(len(matching_packets) == 0):
        print("Error with matching packets!")
        exit()

    fragments_output = find_fragments(matching_packets)

    for packet in receiver_packets:

        for inner_matching_packets in matching_packets:
            if(packet.ICMP_header.type != 0):
                protocol = packet.ICMP_header.inner_protocol["inner_ICMP"]
                if(protocol.seq_num == inner_matching_packets[0].ICMP_header.seq_num):
                    inner_matching_packets.append(packet)
                    break
            else:
                if(packet.ICMP_header.seq_num == inner_matching_packets[0].ICMP_header.seq_num):
                    inner_matching_packets.append(packet)
                    break


    intermediate_routers = {"No_response":[]} #dictionary of keys = routers ip with keys as array of all packets sent to the router


    for inner_matching_packets in matching_packets:
        if(len(inner_matching_packets) == 1):#there is no response to this packet, but still add it for R2
            intermediate_routers["No_response"].append(inner_matching_packets[0])
            continue
        for packet in inner_matching_packets:
            if(packet.ICMP_header.type in [0, 3, 11]):
                key_ip = packet.IP_header.src_ip
                if(key_ip not in intermediate_routers.keys()):
                    intermediate_routers[key_ip] = [inner_matching_packets]
                
                else:
                    intermediate_routers[key_ip].append(inner_matching_packets)



    return intermediate_routers, fragments_output

def match_packets(packets):
    """
    Match fragments together, otherwise put a single packet into array
    Assumption: for each requesting packet there is only 1 response
    Returns:
        list of list of packets
    """
    matching_packets = []
    for packet in packets:

        if(packet.IP_header.flags == 1 or (packet.IP_header.flags == 0 and packet.IP_header.fragment_offset != 0)):#fragmented
            if(len(matching_packets) == 0):#no instances
                matching_packets.append([packet]) 
            else:#some packets in matching packets
                i = 0
                match_found = False
                for inner_matching_packets in matching_packets:
                    if(packet.IP_header.identification == inner_matching_packets[0].IP_header.identification):
                        matching_packets[i].append(packet)
                        match_found = True
                        break
                    i+=1   

                if(not match_found):
                    matching_packets.append([packet])

        else:
            matching_packets.append([packet])
    
    return matching_packets

def find_fragments(matching_packets):#all packets are UDP!
    """
    Finds fragments together and makes an output for r1
    Returns:
        fragment_output - array of strings, for r1 question
    """
    output = []
    for packets in matching_packets:
        if(len(packets) == 1):
            continue
        
        #fragmentation happened
        id = packets[0].IP_header.identification
        num_fragmented = len(packets)
        #print(packets[-1])
        offset = packets[-1].IP_header.fragment_offset
        fragment_output = (f"The number of fragments created from the original datagram with id {id} is: {num_fragmented}\n"
                            +f"The offset of the last fragment is: {offset}")
        
        output.append(fragment_output)

    return output


if __name__ == '__main__':
    main()

