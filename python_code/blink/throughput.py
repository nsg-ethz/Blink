import logging
from packet import TCPPacket
from util import logger

class ThroughputMonitor:
    def __init__(self, log_dir, log_level, registers, window_size=10, bin_time=0.05):

        # Logger for the throughput monitor
        self.log_dir = log_dir
        logger.setup_logger('throughput', log_dir+'/throughput.log', level=log_level)
        self.log = logging.getLogger('throughput')

        self.registers = registers
        self.window_size = window_size
        self.bin_time = bin_time

    def process_packet(self, packet):
        prefix_id = packet.metadata['id']

        # The first sw_time is the timestamp of the first packet of the trace
        if self.registers['sw_time_throughput'][prefix_id] == 0:
            self.registers['sw_time_throughput'][prefix_id] = packet.ts
            self.registers['sw_index_throughput'][prefix_id] = 0
            self.registers['sw_sum1_throughput'][prefix_id] = 0
            self.registers['sw_sum2_throughput'][prefix_id] = 0

            for i in range(prefix_id*self.window_size, (prefix_id+1)*self.window_size):
                self.registers['sw_throughput'][i] = 0

        # If we must move to the next bin
        elif packet.ts - self.registers['sw_time_throughput'][prefix_id] > self.bin_time:

            shift = (packet.ts - self.registers['sw_time_throughput'][prefix_id]) / self.bin_time

            for i in xrange(0, int(shift)):
                self.log.info(str(prefix_id)+'\t'+ \
                    str(round(self.registers['sw_time_throughput'][prefix_id], 2)) \
                    +'\t'+str(self.registers['sw_sum1_throughput'][prefix_id]) \
                    +'\t'+str(self.registers['sw_sum2_throughput'][prefix_id]))

                self.registers['sw_time_throughput'][prefix_id] += self.bin_time

                self.registers['sw_index_throughput'][prefix_id] = (self.registers['sw_index_throughput'][prefix_id] + 1)%self.window_size
                index1 = self.registers['sw_index_throughput'][prefix_id]
                index2 = (index1+(self.window_size/2))%self.window_size

                cur_sw_val1 = self.registers['sw_throughput'][(prefix_id*self.window_size)+index1]
                self.registers['sw_throughput'][(prefix_id*self.window_size)+index1] = 0
                self.registers['sw_sum2_throughput'][prefix_id] -= cur_sw_val1

                cur_sw_val2 = self.registers['sw_throughput'][(prefix_id*self.window_size)+index2]
                self.registers['sw_sum2_throughput'][prefix_id] += cur_sw_val2
                self.registers['sw_sum1_throughput'][prefix_id] -= cur_sw_val2

        assert self.registers['sw_sum1_throughput'][prefix_id] + self.registers['sw_sum2_throughput'][prefix_id] \
            == sum(self.registers['sw_throughput'][(prefix_id*self.window_size):(prefix_id*self.window_size)+self.window_size]), \
            str(packet.metadata['id'])

        # Add the number of bytes to the throughput
        self.registers['sw_sum1_throughput'][prefix_id] += packet.ip_len
        self.registers['sw_throughput'][(prefix_id*self.window_size)+self.registers['sw_index_throughput'][prefix_id]] += packet.ip_len


if __name__ == "__main__":
    from python_code.util import parse_pcap

    nbprefixes = 1
    window_size = 10

    # Registers used for the throughput sliding window
    registers = {}
    registers['sw_throughput'] = []
    for _ in xrange(0, nbprefixes):
        registers['sw_throughput'] += [0] * window_size
    registers['sw_index_throughput'] = [0] * nbprefixes
    registers['sw_time_throughput'] = [0] * nbprefixes
    registers['sw_sum1_throughput'] = [0] * nbprefixes
    registers['sw_sum2_throughput'] = [0] * nbprefixes

    t = ThroughputMonitor('log', 20, registers, window_size)
    #
    # p1 = TCPPacket(1, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p2 = TCPPacket(1.05, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p3 = TCPPacket(1.1, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p4 = TCPPacket(1.15, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p5 = TCPPacket(1.20, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p6 = TCPPacket(1.25, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p7 = TCPPacket(1.30, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p8 = TCPPacket(1.35, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p9 = TCPPacket(1.40, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p10 = TCPPacket(1.45, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p11 = TCPPacket(1.50, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p12 = TCPPacket(1.55, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p13 = TCPPacket(1.60, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p14 = TCPPacket(1.65, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p15 = TCPPacket(1.70, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p16 = TCPPacket(1.75, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p17 = TCPPacket(1.80, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p18 = TCPPacket(1.85, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p19 = TCPPacket(1.90, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    # p20 = TCPPacket(1.95, '1.1.1.1', '2.2.2.2', 1, 2, 3, 21, 10, 10, False, False)
    #
    # packet_list = [p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,p16,p17,p18,p19,p20]

    i = 0
    for p in parse_pcap.pcap_reader('python_code/pcap/caida_2018_small.pcap'):
        i += 1

        p.ts += 0.001*i

        print p
        p.metadata["id"] = 0
        t.process_packet(p)

        print 'sw: ', registers['sw_throughput']
        print 'index: ', registers['sw_index_throughput']
        print 'time: ', registers['sw_time_throughput']
        print 'sum1: ', registers['sw_sum1_throughput']
        print 'sum2: ', registers['sw_sum2_throughput']
