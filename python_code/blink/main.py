import sys

try:
    import pyshark
except:
    print 'Pyshark not available, you must read a pcap file using the parameter --pcap'

import yaml
import time
import logging
import logging.handlers
import argparse

from python_code.util import parse_pcap
from packet import TCPPacket
from p4pipeline import P4Pipeline

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', type=int, help='Port of the controller. The controller is always localhost', required=True)
parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Directory used for the log')
parser.add_argument('--log_level', nargs='?', type=int, default=20, help='Log level')
parser.add_argument('--window_size', nargs='?', type=int, default=10, help='Number of 20ms in the window.')
parser.add_argument('--nbflows_prefix', nargs='?', type=int, default=64, help='Number of flows to monitor for each monitored prefixes.')
parser.add_argument('--seed', nargs='?', type=int, default=1, help='Seed used to hash flows.')
parser.add_argument('--nbprefixes', nargs='?', type=int, default=10000, help='Number of prefixes to monitor.')
parser.add_argument('--pkt_offset', nargs='?', type=int, default=0, help='Number of packets to ignore at the beginning of the trace.')
parser.add_argument('--eviction_timeout', nargs='?', type=float, default=2, help='Eviction timeout of the FlowSelector.')
parser.add_argument('--pcap', nargs='?', type=str, default=None, help='Pcap file to read, otherwise read from stdin.')
args = parser.parse_args()
port = args.port
log_dir = args.log_dir
log_level = args.log_level
window_size = args.window_size
nbflows_prefix = args.nbflows_prefix
nbprefixes = args.nbprefixes
eviction_timeout = args.eviction_timeout
pcap_file = args.pcap
seed = args.seed
pkt_offset = args.pkt_offset

p4pipeline = P4Pipeline(port, log_dir, log_level, window_size, \
nbprefixes, nbflows_prefix, eviction_timeout, seed)

time.sleep(1)

# Read packets from stdin
if pcap_file is None:
    print pkt_offset
    i = 0
    for line in sys.stdin:
        i += 1

        linetab = line.rstrip('\n').split('\t')
        if len(linetab) < 10 or linetab[3] == '' or linetab[1] == '' or linetab[2] == '' or linetab[4] == '' or linetab[5] == '' or linetab[9] == '':
            continue

        try:
            ts = float(linetab[0])
            src_ip = str(linetab[1])
            dst_ip = str(linetab[2])
            seq = int(linetab[3])
            src_port = int(linetab[4])
            dst_port = int(linetab[5])
            ip_len = int(linetab[6])
            ip_hdr_len = int(linetab[7])
            tcp_hdr_len = int(linetab[8])
            tcp_flag = int(linetab[9], 16)
            syn_flag = ( tcp_flag & dpkt.tcp.TH_SYN ) != 0
            fin_flag = ( tcp_flag & dpkt.tcp.TH_FIN ) != 0
            ret = True if linetab[10] == '1' else False
        except ValueError:
            print line
            continue

        # Create the packet object
        packet = TCPPacket(ts, src_ip, dst_ip, seq, src_port, dst_port, ip_len, \
        ip_hdr_len, tcp_hdr_len, syn_flag, fin_flag, ret=ret)

        if packet is not None and pkt_offset <= 0:
            # Send that packet through the p4 pipeline
            p4pipeline.process_packet(packet)
        pkt_offset -= 1

# Read pcap from a pcap file
else:
    for packet in parse_pcap.pcap_reader(pcap_file):

        if packet is not None and pkt_offset <= 0:
            p4pipeline.process_packet(packet)
        pkt_offset -= 1

p4pipeline.close()
