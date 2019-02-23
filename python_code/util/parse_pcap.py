from scapy.all import *
import ipaddr
from python_code.blink import packet as packet_lib

TH_FIN = 0b1
TH_SYN = 0b10
TH_RST = 0b100
TH_PUSH = 0b1000
TH_ACK = 0b10000
TH_URG = 0b100000
TH_ECE = 0b1000000
TH_CWR = 0b10000000

def get_timestamp(meta, format="pcap"):
    if format == "pcap":
        return meta.sec + meta.usec/1000000.
    elif format == "pcapng":
        return ((meta.tshigh << 32) | meta.tslow) / float(meta.tsresol)

def ipv6_to_ipv4(ipv6):

    hashed = hash(ipv6) & 0xfffffff
    ip = ipaddr.IPv4Address(hashed)
    return ip.compressed

def pcap_reader(in_file, packets_to_process=0):
    """

    Args:
        in_file:
        packets_to_process:

    Returns:

    """

    #constants
    IP_LEN = 20
    IPv6_LEN = 40
    TCP_LEN = 14

    #variables
    packet_count = 0

    #helper to read PCAP files (or pcapng)
    with RawPcapReader(in_file) as _pcap_reader:

        first_packet = True
        default_packet_offset = 0
        for packet, meta in _pcap_reader:
            try:
                if first_packet:
                    first_packet = False
                    # check if the metadata is for pcap or pcapng
                    if hasattr(meta, 'usec'):
                        pcap_format = "pcap"
                        link_type = _pcap_reader.linktype
                    elif hasattr(meta, 'tshigh'):
                        pcap_format = "pcapng"
                        link_type = meta.linktype

                    # check first layer
                    if link_type == DLT_EN10MB:
                        default_packet_offset += 14
                    elif link_type == DLT_RAW_ALT:
                        default_packet_offset += 0
                    elif link_type == DLT_PPP:
                        default_packet_offset += 2

                #limit the number of packets we process
                if packet_count == packets_to_process and packets_to_process != 0:
                    break
                packet_count +=1

                #remove bytes until IP layer (this depends on the linktype)
                packet = packet[default_packet_offset:]

                #IP LAYER Parsing
                packet_offset = 0
                version = struct.unpack("!B", packet[0])
                ip_version = version[0] >> 4
                if ip_version == 4:
                    # filter if the packet does not even have 20+14 bytes
                    if len(packet) < (IP_LEN + TCP_LEN):
                        continue
                    #get the normal ip fields. If there are options we remove it later
                    ip_header = struct.unpack("!BBHHHBBHBBBBBBBB", packet[:IP_LEN])
                    #increase offset by layer length
                    ip_header_length = (ip_header[0] & 0x0f) * 4

                    packet_offset += ip_header_length

                    ip_length = ip_header[2]

                    protocol = ip_header[6]
                    #filter protocols
                    if protocol != 6:
                        continue
                    #format ips
                    ip_src = '{0:d}.{1:d}.{2:d}.{3:d}'.format(ip_header[8],
                                                           ip_header[9],
                                                           ip_header[10],
                                                           ip_header[11])
                    ip_dst = '{0:d}.{1:d}.{2:d}.{3:d}'.format(ip_header[12],
                                                           ip_header[13],
                                                           ip_header[14],
                                                           ip_header[15])
                #parse ipv6 headers
                elif ip_version == 6:
                    # filter if the packet does not even have 20+14 bytes
                    if len(packet) < (IPv6_LEN + TCP_LEN):
                        #log.debug("Small packet found")
                        continue
                    ip_header = struct.unpack("!LHBBQQQQ", packet[:40])
                    #protocol/next header
                    ip_length = 40 + ip_header[1]
                    ip_header_length = 40
                    protocol = ip_header[2]
                    if protocol != 6:
                        continue
                    ip_src = ipv6_to_ipv4(ip_header[4] << 64 | ip_header[5])
                    ip_dst = ipv6_to_ipv4(ip_header[6] << 64 | ip_header[7])
                    packet_offset +=40

                else:
                    continue

                #parse TCP header
                tcp_header = struct.unpack("!HHLLBB", packet[packet_offset:packet_offset+TCP_LEN])
                sport = tcp_header[0]
                dport = tcp_header[1]
                pkt_seq = tcp_header[2]
                tcp_header_length = ((tcp_header[4] & 0xf0) >> 4) * 4
                flags = tcp_header[5]
                syn_flag = flags & TH_SYN != 0
                fin_flag = flags & TH_FIN != 0

                 #update data structures
                packet_ts = get_timestamp(meta, pcap_format)

                tcp_payload_length = ip_length - ip_header_length - tcp_header_length

                # yield ((packet_ts, ip_src, sport, ip_dst, dport, protocol, pkt_seq, syn_flag, fin_flag, ip_length,
                #         ip_header_length, tcp_header_length, tcp_payload_length))

                yield packet_lib.TCPPacket(packet_ts, ip_src, ip_dst, pkt_seq, sport, dport, \
                ip_length, ip_header_length, tcp_header_length, syn_flag, fin_flag)

            except Exception:
                #if this prints something just ingore it i left it for debugging, but it should happen almost never
                import traceback
                traceback.print_exc()
