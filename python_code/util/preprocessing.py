import sys
import pyshark
import argparse
import radix
import ipaddress
import dpkt

parser = argparse.ArgumentParser()
parser.add_argument('--infile', type=str, default=None, help='List of all the prefixes in the trace')
parser.add_argument('--outfile', type=str, default='outfile.txt', help='Outfile')
parser.add_argument('--stop_ts', nargs='?', type=int, default=7, help='Stop after the x-th second. Default 7s.')

args = parser.parse_args()
infile = args.infile
outfile = args.outfile
stop_ts = args.stop_ts

rtree = radix.Radix()

if infile is not None:
    with open(infile, 'r') as fd:
        for line in fd.readlines():
            linetab = line.split(' ')
            dst_prefix = str(ipaddress.ip_network(unicode(linetab[0]+'/'+linetab[1]), strict=False))

            rnode = rtree.add(dst_prefix)
            rnode.data['pkts'] = 0
            rnode.data['bytes'] = 0

def write_rtree(outfile, rtree):
    with open(outfile, 'w') as fd:
        for rnode in rtree:
            fd.write(str(rnode.prefix)+'\t'+str(rnode.data['pkts'])+'\t'+str(rnode.data['bytes'])+'\n')

i = 0
# Read packets from stdin
for line in sys.stdin:
    i += 1
    if i%100000==0:
        print ts
        write_rtree(outfile, rtree)
    linetab = line.rstrip('\n').split('\t')
    if len(linetab) < 10 or linetab[3] == '' or linetab[1] == '' or linetab[2] == '' or linetab[4] == '' or linetab[5] == '' or linetab[9] == '':
        continue

    ts = float(linetab[0])
    src_ip = str(linetab[1])
    dst_ip = str(linetab[2])
    seq = int(linetab[3])
    src_port = int(linetab[4])
    dst_port = int(linetab[5])
    ip_len = int(linetab[6])
    ip_hdr_len = int(linetab[7]) #*4 # In bytes
    tcp_hdr_len = int(linetab[8])
    tcp_flag = int(linetab[9], 16)
    tcp_payload_len = ip_len - ip_hdr_len - tcp_hdr_len

    syn_flag = ( tcp_flag & dpkt.tcp.TH_SYN ) != 0
    fin_flag = ( tcp_flag & dpkt.tcp.TH_FIN ) != 0

    if ts > stop_ts:
        break

    if not syn_flag and not fin_flag:
        # Send that packet through the p4 pipeline
        rnode = rtree.search_best(dst_ip)
        if rnode == None:
            dst_prefix = str(ipaddress.ip_network(unicode(dst_ip+'/24'), strict=False))
            rnode = rtree.add(dst_prefix)
            rnode.data['pkts'] = 0
            rnode.data['bytes'] = 0

        rnode.data['pkts'] += 1
        rnode.data['bytes'] += tcp_payload_len

write_rtree(outfile, rtree)

# tshark -r tmp.pcap -Y "tcp" -o "tcp.relative_sequence_numbers: false"  -T fields  -e frame.time_epoch  -e ip.src -e ip.dst -e tcp.seq -e tcp.srcport -e tcp.dstport -e ip.len -e ip.hdr_len -e tcp.hdr_len -e tcp.flags | python preprocessing.py
