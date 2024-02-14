import struct 

SIZE_OF_ICMP_HEADER = 8
SIZE_OF_UDP_HEADER = 8

class global_header():

    def __init__(self):
        self.magic_number = 0
        self.version_major = 0
        self.version_minor = 0
        self.thiszone = 0
        self.sigfigs = 0
        self.snaplen = 0
        self.network = 0
        self.endianness = None


    def get_global_header_into(self, header):
        LITTLE_ENDIAN = "<"
        BIG_ENDIAN = ">"
        self.magic_number = struct.unpack("<I", header[0:4])[0]
        
        if header[:4] == b"\xa1\xb2\xc3\xd4":
            endianness = BIG_ENDIAN
            metric = "micro_s"
        elif header[:4] == b"\xa1\xb2\x3c\x4d":
            endianness = BIG_ENDIAN
            metric = "nano_s"
        elif header[:4] == b"\xd4\xc3\xb2\xa1":
            endianness = LITTLE_ENDIAN
            metric = "micro_s"
        elif header[:4] == b"\x4d\x3c\xb2\xa1":
            endianness = LITTLE_ENDIAN
            metric = "nano_s"
        else:
            print("Couldn't read the magic number")
            exit(1)

        self.version_major = struct.unpack(endianness + "H", header[4:6])[0]
        self.version_minor = struct.unpack(endianness + "H", header[6:8])[0]
        self.thiszone = struct.unpack(endianness + "i", header[8:12])[0]
        self.sigfigs = struct.unpack(endianness + "I", header[12:16])[0]
        self.snaplen = struct.unpack(endianness + "I", header[16:20])[0]
        self.network = struct.unpack(endianness + "I", header[20:])[0]
        self.endianness = endianness
        return metric

class pcap_ph_info:
    ts_sec = 0
    ts_usec = 0
    incl_len = 0
    orig_len = 0

    def __init__(self):
        self.ts_sec = 0
        self.ts_usec = 0
        self.incl_len = 0
        self.orig_len = 0

    def set_headers(self, pack):
        self.ts_sec = pack[0]
        self.ts_usec = pack[1]
        self.incl_len = pack[2]
        self.orig_len = pack[3]


class packet():
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.UDP_header =  UDP_header()
        self.ICMP_header = ICMP_header()
        self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        
    #todo
    def timestamp_set(self,buffer1,buffer2,orig_time, metric):
        seconds = buffer1
        if(metric == "micro_s"):
            microseconds = buffer2
            nanoseconds = 0
        elif(metric == "nano_s"):
            microseconds = 0
            nanoseconds = buffer2
        
        self.timestamp = round(
            (seconds*1000 + (microseconds * 0.001) + (nanoseconds * 0.000001))- orig_time,6)

        #print(self.timestamp,self.packet_No)
        return self.timestamp

    def packet_No_set(self,number):
        self.packet_No = number

    def packet_set_headers(self, pack):
        self.pcap_hd_info.set_headers(pack)

    def get_timestamp(self):
        return self.timestamp
        
    def __str__(self):
        string = ("----------------------")
        string += f"{self.packet_No}\n{self.IP_header}\n\n{self.UDP_header if self.IP_header.protocol == 17 else self.ICMP_header}"
        return string
    
class IP_Header:

    def __init__(self):

        self.ip_header_len = 0
        self.total_len = 0
        self.identification = None
        self.flags = None
        self.fragment_offset = None
        self.ttl = None 
        self.protocol = None
        self.src_ip = None
        self.dst_ip = None
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP_addr(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        return s_ip, d_ip
    
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)
        return length

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)
        return length
    
    def get_identification(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        self.identification = num1+num2+num3+num4

    def get_flag_and_offset(self, buffer):
        value = struct.unpack("!H", buffer)[0]

        self.flags = (value >> 13) & 0b0000000000000111
        self.fragment_offset = (value & 0b0001111111111111)*8

    def get_ttl_and_protocol(self,buffer1, buffer2):

        ttl = struct.unpack('!B', buffer1)[0]
        prot = struct.unpack('!B', buffer2)[0]
        self.ttl = ttl
        self.protocol =prot


    def fill_ipv_header(self, packet_data, start):

        ihl = self.get_header_len(packet_data[start:start+1]) 

        self.get_total_len(packet_data[start+2:start+4])
        self.get_identification(packet_data[start+4:start+6])
        self.get_flag_and_offset(packet_data[start+6:start+8])
        self.get_ttl_and_protocol(packet_data[start+8:start+9], packet_data[start+9:start+10])
        self.get_IP_addr(packet_data[start+12:start+16], packet_data[start+16:start+20])
        return ihl

    def __str__(self):
        string = (
            f"IP header:\nIHL: {self.ip_header_len}\nTotal Len: {self.total_len}\nIdentification: {self.identification}\nFlags: {self.flags}\nOffset: {self.fragment_offset}\n"
            f"TTL: {self.ttl}\nProtocol: {self.protocol}\nSrc ip {self.src_ip}\nDest ip {self.dst_ip}"
        )
        return string


class UDP_header: 

        def __init__(self):
            self.src_port = None
            self.dst_port = None
            self.length = None

        def read_headers(self, header):

            self.src_port = struct.unpack(">H", header[0:2])[0]
            self.dst_port = struct.unpack(">H", header[2:4])[0]
            self.length = struct.unpack(">H", header[4:6])[0]

        def __str__(self):
            string = f"UDP HEADER:\nSRC port: {self.src_port}\nDST port: {self.dst_port}\nLength: {self.length}"
            return string
       
class ICMP_header:


    def __init__(self):
        self.type = None
        self.code = None

        self.identifier = None
        self.seq_num = None

        self.inner_protocol = {}

    def read_headers(self, header, ihl):
        self.type = struct.unpack("!B", header[ihl:ihl+1])[0]
        self.code = struct.unpack("!B", header[ihl+1:ihl+2])[0]

        if(self.type in [11,3]):
            inner_ip = IP_Header()
            inner_ihl = inner_ip.fill_ipv_header(header, ihl+SIZE_OF_ICMP_HEADER)
            inner_ihl += ihl + SIZE_OF_ICMP_HEADER
            self.inner_protocol["inner_IP"] = inner_ip
            if inner_ip.protocol == 1:#ICMP
                inner_icmp = ICMP_header()
                inner_icmp.read_headers(header, inner_ihl)
                self.inner_protocol["inner_ICMP"] = inner_icmp

            elif inner_ip.protocol == 17:
                inner_udp = UDP_header()
                inner_udp.read_headers(header[inner_ihl: inner_ihl+ SIZE_OF_UDP_HEADER])
                self.inner_protocol["inner_UDP"] = inner_udp

        elif(self.type in [0, 8]):
            self.identifier = struct.unpack("!H", header[ihl+4:ihl+6])[0]
            self.seq_num = struct.unpack("!H", header[ihl+6:ihl+8])[0]

    def __str__(self):
        string = f"ICMP header:\nType: {self.type}\nCode: {self.code}\n"
        TAB = 4*" " + "Inner "
        if(self.type in [11,3]):
            for key in self.inner_protocol.keys():
                string += f"\n{TAB}{self.inner_protocol[key]}\n"
        elif(self.type in [0,8]):
            string += f"Identifier: {self.identifier}\nSequence number: {self.seq_num}"
        return string