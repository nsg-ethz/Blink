import sys
import socket
import fcntl, os
import errno
import time
import logging
from socket import SHUT_RDWR

from fwtable import FWTable
from flowselector import FlowSelector
from throughput import ThroughputMonitor

from util import logger

class P4Pipeline:
    def __init__(self, port, log_dir, log_level, window_size, nbprefixes, \
    nbflows_prefix, eviction_timeout, seed):

        # Logger for the pipeline
        logger.setup_logger('pipeline', log_dir+'/pipeline.log', level=log_level)
        self.log = logging.getLogger('pipeline')

        self.log.log(20, str(port)+'\t'+str(log_dir)+'\t'+str(log_level)+'\t'+ \
        str(window_size)+'\t'+str(nbprefixes)+'\t'+str(nbflows_prefix)+'\t'+ \
        '\t'+str(eviction_timeout)+'\t'+str(seed))

        self.ip_controller = 'localhost'
        self.port_controller = port
        self.seed = seed

        # Dictionnary with all the forwarding table
        self.fwtables = {}
        self.fwtables['meta_fwtable'] = FWTable(log_dir, log_level, 'meta_fwtable.log')

        # Dictionnary with all the registers array
        self.registers = {}

        self.registers['flowselector_key'] = [0] * (nbflows_prefix*nbprefixes) # *100 to make sure there is no overflow
        self.registers['flowselector_ts'] = [0] * (nbflows_prefix*nbprefixes)
        self.registers['flowselector_nep'] = [0] * (nbflows_prefix*nbprefixes) # nep for Next Expected Packet
        self.registers['flowselector_last_ret'] = [0] * (nbflows_prefix*nbprefixes) # Timestamp
        self.registers['flowselector_5tuple'] = [''] * (nbflows_prefix*nbprefixes) # Just used in the python implem

        # Registers used for the sliding window
        self.registers['sw'] = []
        for _ in xrange(0, nbprefixes):
            self.registers['sw'] += [0] * window_size
        self.registers['sw_index'] = [0] * nbprefixes
        self.registers['sw_time'] = [0] * nbprefixes
        self.registers['sw_sum'] = [0] * nbprefixes

        # Registers used for the throughput sliding window
        self.registers['sw_throughput'] = []
        for _ in xrange(0, nbprefixes):
            self.registers['sw_throughput'] += [0] * window_size
        self.registers['sw_index_throughput'] = [0] * nbprefixes
        self.registers['sw_time_throughput'] = [0] * nbprefixes
        self.registers['sw_sum1_throughput'] = [0] * nbprefixes
        self.registers['sw_sum2_throughput'] = [0] * nbprefixes

        self.registers['threshold_registers'] = [50] * nbprefixes

        self.registers['next_hops_index'] = [0] * nbprefixes
        self.registers['next_hops_port'] = [2,3,4] * nbprefixes

        # This is the FlowSelector, use to keep track of a defined number of
        # active flows per prefix
        self.flowselector = FlowSelector(log_dir, 20, self.registers, 32, \
            nbflows_prefix, eviction_timeout, self.seed)

        self.throughput = ThroughputMonitor(log_dir, 20, self.registers)

        # Socket used to communicate with the controller
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (self.ip_controller, self.port_controller)
        while True:
            status = self.sock.connect_ex(server_address)
            if status == 0:
                print 'Connected!'
                break
            else:
                print 'Could not connect, retry in 2 seconds..'
                time.sleep(2)

        fcntl.fcntl(self.sock, fcntl.F_SETFL, os.O_NONBLOCK)

        self.data = ''

        # Read flow table rules from the controller until the table is fully populated
        self.ready = False
        while not self.ready:
            self.read_controller()
            pass


    def process_packet(self, packet):

        self.read_controller()

        # Translate prefix to ID
        matched = self.fwtables['meta_fwtable'].process_packet(packet)

        # All the matched packets are taken into account when computing the
        # thoughput
        if matched:
            self.throughput.process_packet(packet)

        # Filter out SYN packets and ACK-only packets
        if matched and packet.tcp_payload_len > 0 and not packet.syn_flag:

            packet.metadata['threshold'] = self.registers['threshold_registers'][packet.metadata['id']]

            if self.flowselector.process_packet(packet):

                assert self.registers['sw_sum'][packet.metadata['id']] == \
                    sum(self.registers['sw'][packet.metadata['id']*10:(packet.metadata['id']+1)*10])

                if packet.metadata['to_clone']:

                    self.sock.sendall('RET|'+str(packet.ts)+'|'+str(packet.metadata['id'])+ \
                    '|'+str(packet.src_ip)+'-'+str(packet.dst_ip)+'-'+ \
                    str(packet.src_port)+'-'+str(packet.dst_port)+'-'+ \
                    str(packet.seq)+'-'+str(packet.tcp_payload_len)+'\n')

                if self.registers['sw_sum'][packet.metadata['id']] > packet.metadata['threshold']:
                    # Turn on the Fast reroute for this prefix
                    self.registers['next_hops_index'][packet.metadata['id']] = 1

                    #nb_active_flows = self.flowselector.compute_nb_active_flows(packet)
                    bogus_trace = packet.metadata['bogus_ret']

                    # Print all the fast rerouted packets in the log
                    if packet.metadata['to_clone']:
                        self.log.log(25, 'FR\t'+str(packet.ts)+'\t'+ \
                            str(packet.src_ip)+'\t'+str(packet.dst_ip)+'\t'+ \
                            str(packet.src_port)+'\t'+str(packet.dst_port)+'\t'+ \
                            str(self.registers['sw_sum'][packet.metadata['id']])+'\t'+ \
                            str(packet.metadata['threshold'])+'\t'+ \
                            str(packet.metadata['nb_flows_monitored'])+'\t'+ \
                            str(bogus_trace))

    def close(self):
        self.sock.sendall('CLOSING\n')
        self.sock.shutdown(SHUT_RDWR)
        self.log.log(25, 'PIPELINE_CLOSING|')
        self.sock.close()

    def read_controller(self):
        data_tmp = ''
        toreturn = None

        try:
            data_tmp = self.sock.recv(100000000)
        except socket.error, e:
            err = e.args[0]
            if not (err == errno.EAGAIN or err == errno.EWOULDBLOCK):
                print 'p4pipeline: ', e
                self.sock.close()
                self.sock = None

        if len(data_tmp) > 0:
            self.data += data_tmp

            next_data = ''
            while len(self.data) > 0 and self.data[-1] != '\n':
                next_data = self.data[-1]+next_data
                self.data = self.data[:-1]

            toreturn = self.data
            self.data = next_data

        if toreturn is not None:
            for line in toreturn.split('\n'):
                if line.startswith('READY'):
                    self.ready = True

                if line.startswith('table add'):
                    linetab = line.rstrip('\n').split(' ')
                    table_name = linetab[2]
                    action_name = linetab[3]
                    match = linetab[4]

                    l = []
                    for i in range(6, len(linetab)):
                        l.append(linetab[i])

                    self.fwtables[table_name].add_fw_rule(match, l)

                if line.startswith('do_register_write'):
                    linetab = line.rstrip('\n').split(' ')
                    register_name = linetab[1]
                    index = int(linetab[2])
                    value = int(linetab[3])

                    self.registers[register_name][index] = value

        return False
