import math
import logging
from packet import TCPPacket
from python_code.murmur import _murmur3str
from python_code.util import logger
from python_code.util import sorted_sliding_dic

###
# Since the flowselector_ts is only store within few bits (e.g., 12 bits), at some
# point the actual timestamp will be lower than the last packet seen (when
# the reference ts is reset), we could use it to force eviction of the flows and
# avoid attacks.
###

class FlowSelector:
    def __init__(self, log_dir, log_level, registers, key_size, nb_flows=64, \
    timeout=2, seed=1, window_size=10, bin_time=0.08):

        # Logger for the flowselector
        self.log_dir = log_dir
        logger.setup_logger('flowselector', log_dir+'/flowselector.log', level=log_level)
        self.log = logging.getLogger('flowselector')

        # Logger for the sliding window
        logger.setup_logger('sliding_window', log_dir+'/sliding_window.log', level=log_level)
        self.log_sw = logging.getLogger('sliding_window')

        self.registers = registers

        # Number of flows kept track for each prefix
        self.nb_flows = nb_flows
        self.timeout = timeout
        self.seed = seed

        # Parameters for the sliding window
        self.window_size = window_size
        self.bin_time = bin_time

        self.nb_monitored_flows = [0] * 1000000

        # Number of bits used to stored the key of the flow
        self.key_size = key_size
        self.max_prefixid = 0

        self.outfile_dump_prefix = 'flowselector_dump'
        self.dump_last_ts = 0

        # Some variables used for monitoring
        self.ssd_dic = {}
        self.bogus_trace = {}

    def update_window(self, packet):
        prefix_id = packet.metadata['id']

        # If the sliding window is late by 1s or more, then we completely reset it
        # if packet.ts - self.registers['sw_time'][prefix_id] > self.bin_time*self.window_size:
        #     self.registers['sw_time'][prefix_id] = packet.ts
        #     self.registers['sw_index'][prefix_id] = 0
        #     self.registers['sw_sum'][prefix_id] = 0
        #
        #     for i in range(prefix_id*self.window_size, (prefix_id+1)*self.window_size):
        #         self.registers['sw'][i] = 0

        # The first sw_time is the timestamp of the first packet of the trace
        if self.registers['sw_time'][prefix_id] == 0:
            self.registers['sw_time'][prefix_id] = packet.ts
            self.registers['sw_index'][prefix_id] = 0
            self.registers['sw_sum'][prefix_id] = 0

            for i in range(prefix_id*self.window_size, (prefix_id+1)*self.window_size):
                self.registers['sw'][i] = 0

        # If we must move to the next bin
        elif packet.ts - self.registers['sw_time'][prefix_id] > self.bin_time:

            shift = (packet.ts - self.registers['sw_time'][prefix_id]) / self.bin_time

            for i in xrange(0, int(shift)):
                self.log_sw.info(str(prefix_id)+'\t'+str(round(self.registers['sw_time'][prefix_id], 2)) \
                    +'\t'+str(self.registers['sw_sum'][prefix_id])+'\t'+ \
                    str(len(self.ssd_dic[packet.metadata['id']][0].flow_dic))+'\t'+ \
                    str(len(self.ssd_dic[packet.metadata['id']][1].flow_dic))+'\t'+ \
                    str(len(self.ssd_dic[packet.metadata['id']][2].flow_dic))+'\t'+ \
                    str(len(self.ssd_dic[packet.metadata['id']][3].flow_dic))+'\t'+ \
                    str(self.bogus_trace[packet.metadata['id']]))

                self.registers['sw_time'][prefix_id] += self.bin_time
                self.registers['sw_index'][prefix_id] = (self.registers['sw_index'][prefix_id] + 1)%self.window_size
                self.registers['sw_sum'][prefix_id] -= self.registers['sw'][(prefix_id*self.window_size)+self.registers['sw_index'][prefix_id]]
                self.registers['sw'][(prefix_id*self.window_size)+self.registers['sw_index'][prefix_id]] = 0

        assert self.registers['sw_sum'][prefix_id] == sum(self.registers['sw'][(prefix_id*self.window_size):(prefix_id*self.window_size)+self.window_size]), str(packet.metadata['id'])
        self.bogus_trace[packet.metadata['id']] = False

    def process_packet(self, packet):
        self.update_window(packet)

        # Create (if not yet created) the ssd for this prefix, and update it
        # based on the new timestamp
        if packet.metadata['id'] not in self.ssd_dic:
            self.ssd_dic[packet.metadata['id']] = [sorted_sliding_dic.SortedSlidingDic(0.2), sorted_sliding_dic.SortedSlidingDic(0.5), sorted_sliding_dic.SortedSlidingDic(1), sorted_sliding_dic.SortedSlidingDic(2)]
            self.bogus_trace[packet.metadata['id']] = False
        for ssd_dic_time in self.ssd_dic[packet.metadata['id']]:
            ssd_dic_time.update(packet.ts)

        packet.metadata['to_clone'] = False

        if self.dump_last_ts == 0:
            self.dump_last_ts = packet.ts

        # Dump the flowselector if the last was more than 1s ago
        if packet.ts - self.dump_last_ts > 10:
            self.dump_last_ts = int(packet.ts)
            self.dump(self.log_dir+'/'+self.outfile_dump_prefix+'_'+str(packet.ts), None)

        key_fields = str(packet.src_ip)+str(packet.dst_ip)+str(packet.src_port)+str(packet.dst_port)

        # The flow ID is an integer between 2 and 2^key_size, 0 is kept for unsued cells
        newflow_key = packet.flow_hash(self.key_size, self.seed)

        cell_id = _murmur3str.murmur3str(key_fields, len(key_fields), self.seed+1) \
        %self.nb_flows

        packet.metadata['flowselector_cellid'] = cell_id
        packet.metadata['bogus_ret'] = False

        index = (packet.metadata['id']*self.nb_flows)+cell_id
        curflow_key = self.registers['flowselector_key'][index]
        curflow_ts = self.registers['flowselector_ts'][index]
        curflow_next_expected_seq = self.registers['flowselector_nep'][index]

        # Used when printing a dump
        self.max_prefixid = max(self.max_prefixid, packet.metadata['id'])

        # If the packet belongs to the flow that is stored
        if curflow_key == newflow_key:

            if packet.fin_flag:
                # Update the sliding window if that flow has sent a retransmission
                # during the last time window
                last_ret_ts = self.registers['flowselector_last_ret'][index]
                prefix_id = packet.metadata['id']

                if last_ret_ts > 0 and packet.ts - last_ret_ts < self.bin_time * self.window_size:
                    tmp = int((packet.ts - last_ret_ts)/self.bin_time)
                    index_prev = int((self.registers['sw_index'][prefix_id] - tmp)%self.window_size)

                    self.registers['sw'][(prefix_id*self.window_size)+index_prev] -= 1
                    if self.registers['sw'][(prefix_id*self.window_size)+index_prev] < 0:
                        self.log.warning('1\t'+str(packet.metadata['id']))

                    self.registers['sw_sum'][prefix_id] -= 1

                for ssd_dic_time in self.ssd_dic[packet.metadata['id']]:
                    ssd_dic_time.remove(self.registers['flowselector_5tuple'][index])

                # Reset the flowselector at this index
                self.log.info(str(packet.ts)+'\tRemove_flow\t'+self.registers['flowselector_5tuple'][index]+'\tFIN')
                self.registers['flowselector_key'][index] = 0
                self.registers['flowselector_ts'][index] = 0
                self.registers['flowselector_nep'][index] = 0
                self.registers['flowselector_last_ret'][index] = 0
                self.registers['flowselector_5tuple'][index] = ''

                self.nb_monitored_flows[packet.metadata['id']] -= 1

                packet.metadata['nb_flows_monitored'] = self.nb_monitored_flows[packet.metadata['id']]

                return False
            else:

                # Check if this packet is a retransmission and update the next value
                next_expected_seq = packet.seq+packet.tcp_payload_len
                last_ret_ts = self.registers['flowselector_last_ret'][index]
                prefix_id = packet.metadata['id']

                # This packet is a retransmission!!
                if next_expected_seq == self.registers['flowselector_nep'][index]:

                    packet.metadata['to_clone'] = True

                    if last_ret_ts == 0 or packet.ts - last_ret_ts > self.bin_time * self.window_size:
                        self.registers['sw'][(prefix_id*self.window_size)+self.registers['sw_index'][prefix_id]] += 1
                        self.registers['sw_sum'][prefix_id] += 1
                        self.registers['flowselector_last_ret'][index] = self.registers['sw_time'][prefix_id]

                    elif packet.ts - last_ret_ts < self.bin_time * self.window_size:
                        tmp = int((packet.ts - last_ret_ts)/self.bin_time)
                        index_prev = int((self.registers['sw_index'][prefix_id] - tmp)%self.window_size)

                        # Do -1 on the index of the previous detected retransmission for that flow
                        self.registers['sw'][(prefix_id*self.window_size)+index_prev] -= 1
                        if self.registers['sw'][(prefix_id*self.window_size)+index_prev] < 0:
                            self.log.warning('1\t'+str(packet.metadata['id']))

                        # Do +1 on the current index
                        self.registers['sw'][(prefix_id*self.window_size)+self.registers['sw_index'][prefix_id]] += 1

                        self.registers['flowselector_last_ret'][index] = self.registers['sw_time'][prefix_id]

                    # Check if this is a retransmission due to bogus traces
                    if float("%.6f" % self.registers['flowselector_ts'][index]) == float("%.6f" % packet.ts):
                        packet.metadata['bogus_ret'] = True
                        self.bogus_trace[packet.metadata['id']] = True

                # Update the timestamp and the ID of the next expected packet
                self.registers['flowselector_ts'][index] = packet.ts
                self.registers['flowselector_nep'][index] = next_expected_seq

                packet.metadata['nb_flows_monitored'] = self.nb_monitored_flows[packet.metadata['id']]
                for ssd_dic_time in self.ssd_dic[packet.metadata['id']]:
                    ssd_dic_time.add(self.registers['flowselector_5tuple'][index], packet.ts)

                return True

        # If the flow is not monitored
        else:

            # If the cell is empty, or the timeout has expired for the current
            # sorted flow, we store the new one, and it is not a fin packet
            if (curflow_key == 0 or packet.ts - curflow_ts > self.timeout) and not packet.fin_flag:

                if curflow_key > 0:

                    self.log.info(str(packet.ts)+'\tRemove_flow\t'+str(self.registers['flowselector_5tuple'][index])+'\tTIMEOUT')

                    # Update the sliding window if that flow has sent a retransmission
                    # during the last time window
                    last_ret_ts = self.registers['flowselector_last_ret'][index]
                    prefix_id = packet.metadata['id']

                    if last_ret_ts > 0 and packet.ts - last_ret_ts < self.bin_time * self.window_size:
                        tmp = int((packet.ts - last_ret_ts)/self.bin_time)
                        index_prev = int((self.registers['sw_index'][prefix_id] - tmp)%self.window_size)

                        self.registers['sw'][(prefix_id*self.window_size)+index_prev] -= 1
                        if self.registers['sw'][(prefix_id*self.window_size)+index_prev] < 0:
                            self.log.warning('1\t'+str(packet.metadata['id']))

                        self.registers['sw_sum'][prefix_id] -= 1

                    self.nb_monitored_flows[packet.metadata['id']] -= 1

                    for ssd_dic_time in self.ssd_dic[packet.metadata['id']]:
                        ssd_dic_time.remove(self.registers['flowselector_5tuple'][index])

                next_expected_seq = packet.seq+packet.tcp_payload_len

                self.registers['flowselector_key'][index] = newflow_key
                self.registers['flowselector_ts'][index] = packet.ts
                self.registers['flowselector_nep'][index] = next_expected_seq
                self.registers['flowselector_last_ret'][index] = 0
                self.registers['flowselector_5tuple'][index] = str(packet.src_ip)+' '+str(packet.dst_ip)+' '+str(packet.src_port)+' '+str(packet.dst_port)

                self.nb_monitored_flows[packet.metadata['id']] += 1

                self.log.info(str(packet.ts)+'\tAdd_flow\t'+self.registers['flowselector_5tuple'][index])

                packet.metadata['nb_flows_monitored'] = self.nb_monitored_flows[packet.metadata['id']]
                for ssd_dic_time in self.ssd_dic[packet.metadata['id']]:
                    ssd_dic_time.add(self.registers['flowselector_5tuple'][index], packet.ts)

                return True

            # If the timeout for the current stored packet has not expired
            else:
                return False

    # This function computes how many of the monitored flows have sent at least
    # one packet within the last time window
    def compute_nb_active_flows(self, packet):
        tot = 0

        for last_pkt_ts in self.registers['flowselector_ts'][packet.metadata['id']*self.nb_flows:(packet.metadata['id']+1)*self.nb_flows]:
            if packet.ts - last_pkt_ts < \
                self.window_size * self.bin_time:
                tot += 1

        return tot

    def dump(self, outfile, dic_id_to_prefixes=None):
        with open(outfile, 'w') as fd:
            for prefixid in range(0, self.max_prefixid+1):

                if dic_id_to_prefixes is not None:
                    res = str(prefixid)+'\t'+str(dic_id_to_prefixes[prefixid])+'\t'
                else:
                    res = str(prefixid)+'\tprefix\t'

                nb_flows_monitored = 0
                for fid in range(0, self.nb_flows):
                    if len(self.registers['flowselector_5tuple'][(prefixid*self.nb_flows)+fid]) > 0:
                        nb_flows_monitored += 1

                    res += str(self.registers['flowselector_5tuple'][(prefixid*self.nb_flows)+fid]).replace(' ', '-')+','
                res = res[:-1]
                res += '\t'+str(nb_flows_monitored)
                fd.write(res+'\n')


if __name__ == "__main__":

    """import argparse
    import sys
    import dpkt
    import ipaddress
    from util import parse_pcap

    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', type=str, default=None, help='pcap')
    parser.add_argument('--infile', type=str, default=None, help='List of all \
    the prefixes in the trace, with their number of packets and bytes')
    parser.add_argument('--outdir', type=str, default='outdir', help='Outdir')
    parser.add_argument('--timeout', type=float, default=2, help='Timeout to use for the hfs')
    args = parser.parse_args()
    pcap = args.pcap
    infile = args.infile
    outdir = args.outdir
    timeout = args.timeout

    prefixes_list = []

    with open(infile, 'r') as fd:
        for line in fd.readlines():
            linetab = line.rstrip('\n').split(' ')

            prefix = linetab[0]
            nb_packets = int(linetab[1])
            nb_bytes = int(linetab[2])

            prefixes_list.append([prefix, nb_packets, nb_bytes])

    prefixes_list.sort(key=lambda x:x[2], reverse=True)

    dic_prefixes = {}
    dic_id_to_prefixes = {}
    for p in prefixes_list:
        dic_id_to_prefixes[len(dic_prefixes)] = p[0]
        dic_prefixes[p[0]] = len(dic_prefixes)

    registers = {}
    registers['flowselector_key'] = [0] * (len(dic_prefixes)*64)
    registers['flowselector_ts'] = [0] * (len(dic_prefixes)*64)
    registers['flowselector_nep'] = [0] * (len(dic_prefixes)*64)
    registers['flowselector_5tuple'] = [''] * (len(dic_prefixes)*64)
    registers['flowselector_last_ret'] = [0] * (len(dic_prefixes)*64)

    hfs = FlowSelector(outdir, 25, registers, 32, 64, timeout, seed=10)

    i = 0
    for pkt in parse_pcap.pcap_reader(pcap):
        i += 1

        ts = pkt[0]
        src_ip = pkt[1]
        src_port = pkt[2]
        dst_ip = pkt[3]
        dst_port = pkt[4]
        seq = pkt[6]
        syn_flag = pkt[7]
        fin_flag = pkt[8]
        ip_len = pkt[9]
        ip_hdr_len = pkt[10]
        tcp_hdr_len = pkt[11]


        #if i%10000000 == 0: For the eval
        if i%100000 == 0:
            print ts
        #    hfs.dump(outdir+'/hfs_'+str(float(ts))+'.dump', dic_id_to_prefixes)

        dst_prefix = '.'.join(dst_ip.split('.')[:-1])+'.0/24'

        # Create the packet object
        packet = TCPPacket(ts, src_ip, dst_ip, seq, src_port, dst_port, ip_len, \
        ip_hdr_len, tcp_hdr_len, syn_flag, fin_flag)

        if dst_prefix in dic_prefixes:
            packet.metadata['id'] = dic_prefixes[dst_prefix]
            hfs.process_packet(packet)

# tshark -r tmp.pcap -Y "tcp" -o "tcp.relative_sequence_numbers: false"  -T fields  -e frame.time_epoch  -e ip.src -e ip.dst -e tcp.seq -e tcp.srcport -e tcp.dstport -e ip.len -e ip.hdr_len -e tcp.hdr_len -e tcp.flags | python -m python_implem.flowselector
    """
    """
    nb_flows = 1000

    for dst_port in xrange(0, nb_flows):
        p = TCPPacket(1, '1.1.1.1', '2.2.2.2', 1, dst_port, 3, 21, 10, 10, False, False)
        p.metadata['id'] = 0
        hfs.process_packet(p)
    """
    registers = {}
    registers['flowselector_key'] = [0] * 10
    registers['flowselector_ts'] = [0] * 10
    registers['flowselector_nep'] = [0] * 10
    registers['flowselector_5tuple'] = [''] * 10
    registers['flowselector_last_ret'] = [0] * 10

    registers['sw'] = []
    for _ in xrange(0, 10):
        registers['sw'] += [0] * 10
    registers['sw_index'] = [0] * 10
    registers['sw_time'] = [0] * 10
    registers['sw_sum'] = [0] * 10

    hfs = FlowSelector('log', 25, registers, 32, 2, 2, seed=10)

    p1 = TCPPacket(1, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    p1.metadata['id'] = 0
    p2 = TCPPacket(1.1, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    p2.metadata['id'] = 0

    p3 = TCPPacket(1.2, '1.1.1.1', '2.2.2.3', 1, 2, 3, 21, 10, 10, False, False)
    p3.metadata['id'] = 0
    p4 = TCPPacket(1.3, '1.1.1.1', '2.2.2.3', 2, 2, 3, 21, 10, 10, False, False)
    p4.metadata['id'] = 0
    p5 = TCPPacket(1.4, '1.1.1.1', '2.2.2.3', 2, 2, 3, 21, 10, 10, False, False)
    p5.metadata['id'] = 0

    p6 = TCPPacket(1.7, '1.1.1.1', '2.2.2.4', 2, 2, 3, 21, 10, 10, False, False)
    p6.metadata['id'] = 0
    p7 = TCPPacket(1.8, '1.1.1.1', '2.2.2.4', 3, 2, 3, 21, 10, 10, False, False)
    p7.metadata['id'] = 0
    p8 = TCPPacket(1.9, '1.1.1.1', '2.2.2.4', 4, 2, 3, 21, 10, 10, False, False)
    p8.metadata['id'] = 0

    #p6 = TCPPacket(1.5, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, True)
    #p6.metadata['id'] = 0

    p9 = TCPPacket(3.4, '1.1.1.1', '2.2.2.4', 1, 2, 3, 21, 10, 10, False, False)
    p9.metadata['id'] = 0
    p10 = TCPPacket(3.5, '1.1.1.1', '2.2.2.4', 2, 2, 3, 21, 10, 10, False, False)
    p10.metadata['id'] = 0

    p11 = TCPPacket(3.5, '1.1.1.1', '2.2.2.2', 2, 2, 3, 21, 10, 10, False, True)
    p11.metadata['id'] = 0

    p12 = TCPPacket(3.6, '1.1.1.1', '2.2.2.4', 1, 2, 3, 21, 10, 10, False, False)
    p12.metadata['id'] = 0
    p13 = TCPPacket(3.6, '1.1.1.1', '2.2.2.5', 2, 2, 3, 21, 10, 10, False, False)
    p13.metadata['id'] = 0

    p14 = TCPPacket(3.8, '1.1.1.1', '2.2.2.9', 2, 2, 3, 21, 10, 10, False, False)
    p14.metadata['id'] = 0

    def send_packet(p):
        print hfs.process_packet(p)
        print 'FlowSelector'
        print 'key ', registers['flowselector_key'][0:2]
        print 'ts ', registers['flowselector_ts'][0:2]
        print 'nep ', registers['flowselector_nep'][0:2]
        print '5tuple ', registers['flowselector_5tuple'][0:2]
        print 'last_ret_ts ',registers['flowselector_last_ret'][0:2]
        print 'WindowSize'
        print 'sw ', registers['sw'][0:20]
        print 'index ',registers['sw_index'][0:2]
        print 'time ',registers['sw_time'][0:2]
        print 'sum ',registers['sw_sum'][0:2]

        print '---------------------'

    send_packet(p1)
    send_packet(p2)
    send_packet(p3)
    send_packet(p4)
    send_packet(p5)
    send_packet(p6)
    send_packet(p7)
    send_packet(p8)
    send_packet(p9)
    send_packet(p10)
    send_packet(p11)
    send_packet(p12)
    send_packet(p13)
    send_packet(p14)
