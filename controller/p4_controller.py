import sys
import os
import socket
import select
import errno
import logging
import logging.handlers
import threading
import argparse
import time
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
import json

from util import logger
from util import sched_timer

class HiddenPrints:
    def __enter__(self):
        self._original_stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout.close()
        sys.stdout = self._original_stdout

class BlinkController:

    def __init__(self, topo_db, sw_name, ip_controller, port_controller, log_dir, \
        monitoring=True, routing_file=None):

        self.topo = Topology(db=topo_db)
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port = self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.controller.reset_state()
        self.log_dir = log_dir

        print 'connecting to ', ip_controller, port_controller
        # Socket used to communicate with the controller
        self.sock_controller = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (ip_controller, port_controller)
        self.sock_controller.connect(server_address)
        print 'Connected!'

        # Send the switch name to the controller
        self.sock_controller.sendall(str(sw_name))

        self.make_logging()

        if monitoring:
            # Monitoring scheduler
            self.t_sched = sched_timer.RepeatingTimer(10, 0.5, self.scheduling)
            self.t_sched.start()

        self.mapping_dic = {}
        tmp = list(self.topo.get_hosts())+list(self.topo.get_p4switches())
        self.mapping_dic = {k: v for v, k in enumerate(tmp)}
        self.log.info(str(self.mapping_dic))

        self.routing_file = routing_file
        print 'routing_file ', routing_file
        if self.routing_file is not None:
            json_data = open(self.routing_file)
            self.topo_routing = json.load(json_data)

    def make_logging(self):
        # Logger for the pipeline
        logger.setup_logger('p4_to_controller', self.log_dir+'/p4_to_controller_'+ \
            str(self.sw_name)+'.log', level=logging.INFO)
        self.log = logging.getLogger('p4_to_controller')

        # Logger for the sliding window
        logger.setup_logger('p4_to_controller_sw', self.log_dir+'/p4_to_controller_'+ \
            str(self.sw_name)+'_sw.log', level=logging.INFO)
        self.log_sw = logging.getLogger('p4_to_controller_sw')

        # Logger for the rerouting
        logger.setup_logger('p4_to_controller_rerouting', self.log_dir+'/p4_to_controller_'+ \
            str(self.sw_name)+'_rerouting.log', level=logging.INFO)
        self.log_rerouting = logging.getLogger('p4_to_controller_rerouting')

        # Logger for the Flow Selector
        logger.setup_logger('p4_to_controller_fs', self.log_dir+'/p4_to_controller_'+ \
            str(self.sw_name)+'_fs.log', level=logging.INFO)
        self.log_fs = logging.getLogger('p4_to_controller_fs')

    def scheduling(self):

        for host in list(self.topo.get_hosts()):
            prefix = self.topo.get_host_ip(host)+'/24'

            # Print log about the sliding window
            for id_prefix in [self.mapping_dic[host]*2, self.mapping_dic[host]*2+1]:

                with HiddenPrints():
                    sw_time = float(self.controller.register_read('sw_time', index=id_prefix))/1000.
                    sw_index = self.controller.register_read('sw_index', index=id_prefix)
                    sw_sum = self.controller.register_read('sw_sum', index=id_prefix)
                self.log_sw.info('sw_time\t'+host+'\t'+prefix+'\t'+str(id_prefix)+'\t'+str(sw_time))
                self.log_sw.info('sw_index\t'+host+'\t'+prefix+'\t'+str(id_prefix)+'\t'+str(sw_index))

                if sw_sum >= 32:
                    self.log_sw.info('sw_sum\t'+host+'\t'+prefix+'\t'+str(id_prefix)+'\t'+str(sw_sum)+'\tREROUTING')
                else:
                    self.log_sw.info('sw_sum\t'+host+'\t'+prefix+'\t'+str(id_prefix)+'\t'+str(sw_sum))


                sw = []
                tmp = 'sw '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 10):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('sw', (id_prefix*10)+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_sw.info(str(tmp))

        # Print log about rerouting
        for host in list(self.topo.get_hosts()):
            prefix = self.topo.get_host_ip(host)+'/24'

            for id_prefix in [self.mapping_dic[host]*2, self.mapping_dic[host]*2+1]:

                with HiddenPrints():
                    nh_avaibility_1 = self.controller.register_read('nh_avaibility_1', index=id_prefix)
                    nh_avaibility_2 = self.controller.register_read('nh_avaibility_2', index=id_prefix)
                    nh_avaibility_3 = self.controller.register_read('nh_avaibility_3', index=id_prefix)
                    nbflows_progressing_2 = self.controller.register_read('nbflows_progressing_2', index=id_prefix)
                    nbflows_progressing_3 = self.controller.register_read('nbflows_progressing_3', index=id_prefix)
                    rerouting_ts = self.controller.register_read('rerouting_ts', index=id_prefix)
                    threshold = self.controller.register_read('threshold_registers', index=id_prefix)

                self.log_rerouting.info('nh_avaibility\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(nh_avaibility_1)+'\t'+ \
                str(nh_avaibility_2)+'\t'+str(nh_avaibility_3))
                self.log_rerouting.info('nblows_progressing\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(nbflows_progressing_2)+'\t'+ \
                str(nbflows_progressing_3))
                self.log_rerouting.info('rerouting_ts\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(rerouting_ts))
                self.log_rerouting.info('threshold\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(threshold))

                nexthop_str = ''
                nha = [nh_avaibility_1, nh_avaibility_2, nh_avaibility_3]
                i = 0
                if self.routing_file is not None:
                    bgp_type = 'customer' if id_prefix%2 == 0 else 'customer_provider_peer'
                    if bgp_type not in self.topo_routing['switches'][self.sw_name]['prefixes'][host]:
                        nexthop_str = 'NoPathAvailable'
                    else:
                        if len(self.topo_routing['switches'][self.sw_name]['prefixes'][host][bgp_type]) == 2:
                            self.topo_routing['switches'][self.sw_name]['prefixes'][host][bgp_type].append(self.topo_routing['switches'][self.sw_name]['prefixes'][host][bgp_type][-1])
                        for nexthop in self.topo_routing['switches'][self.sw_name]['prefixes'][host][bgp_type]:
                            tmp = 'y' if nha[i] == 0 else 'n'
                            nexthop_str = nexthop_str+str(nexthop)+'('+tmp+')\t'
                            i += 1
                        nexthop_str = nexthop_str[:-1]
                self.log_rerouting.info('nexthop\t'+host+'\t'+prefix+'\t'+ \
                str(id_prefix)+'\t'+str(nexthop_str))

        # Print log about the flow selector
        for host in list(self.topo.get_hosts()):
            prefix = self.topo.get_host_ip(host)+'/24'

            for id_prefix in [self.mapping_dic[host]*2, self.mapping_dic[host]*2+1]:

                sw = []
                tmp = 'fs_key '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_key', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_ts', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs_last_ret '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_last_ret', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs_last_ret_bin '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_last_ret_bin', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs_fwloops '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_fwloops', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

                sw = []
                tmp = 'fs_correctness '+host+' '+prefix+' '+str(id_prefix)+'\t'
                for i in range(0, 64):
                    with HiddenPrints():
                        binvalue = int(self.controller.register_read('flowselector_correctness', 64*id_prefix+i))
                    tmp = tmp+str(binvalue)+','
                    sw.append(binvalue)
                tmp = tmp[:-1]
                self.log_fs.info(str(tmp))

    def forwarding(self):
        p4switches = self.topo.get_p4switches()
        interfaces_to_node = p4switches[self.sw_name]['interfaces_to_node']

        for k, v in interfaces_to_node.items():

            try:
                dst_mac =self.topo.get_hosts()[v][self.sw_name]['mac']
            except KeyError:
                dst_mac = self.topo.get_p4switches()[v][self.sw_name]['mac']

            src_mac = p4switches[self.sw_name][v]['mac']
            outport = p4switches[self.sw_name]['interfaces_to_port'][p4switches[self.sw_name][v]['intf']]

            self.log.info('table add send set_nh '+str(self.mapping_dic[v])+' => '+str(outport)+' '+str(src_mac)+' '+str(dst_mac))
            self.controller.table_add('send', 'set_nh', [str(self.mapping_dic[v])], [str(outport), str(src_mac), str(dst_mac)])

    def run(self):

        sock_list = [self.sock_controller]
        controller_data = ''

        while True:
            inready, outready, excepready = select.select (sock_list, [], [])

            for sock in inready:
                if sock == self.sock_controller:
                    data_tmp = ''
                    toreturn = None

                    try:
                        data_tmp = sock.recv(100000000)
                    except socket.error, e:
                        err = e.args[0]
                        if not (err == errno.EAGAIN or err == errno.EWOULDBLOCK):
                            print 'p4_to_controller: ', e
                            sock.close()
                            sock = None

                    if len(data_tmp) > 0:
                        controller_data += data_tmp

                        next_data = ''
                        while len(controller_data) > 0 and controller_data[-1] != '\n':
                            next_data = controller_data[-1]+next_data
                            controller_data = controller_data[:-1]

                        toreturn = controller_data
                        controller_data = next_data

                    if toreturn is not None:
                        for line in toreturn.split('\n'):
                            if line.startswith('table add '):
                                line = line.rstrip('\n').replace('table add ', '')

                                fwtable_name = line.split(' ')[0]
                                action_name = line.split(' ')[1]

                                match_list = line.split(' => ')[0].split(' ')[2:]
                                action_list = line.split(' => ')[1].split(' ')

                                print line
                                print fwtable_name, action_name, match_list, action_list

                                self.log.info(line)
                                self.controller.table_add(fwtable_name, action_name, \
                                    match_list, action_list)

                            if line.startswith('do_register_write'):
                                line = line.rstrip('\n')
                                linetab = line.split(' ')

                                register_name = linetab[1]
                                index = int(linetab[2])
                                value = int(linetab[3])

                                self.log.info(line)
                                self.controller.register_write(register_name, \
                                    index, value)

                            if line.startswith('reset_states'):
                                self.log.info('RESETTING_STATES')

                                # First stop the scheduler to avoid concurrent used
                                # of the Thirft server
                                self.t_sched.cancel()
                                while self.t_sched.running: # Wait the end of the log printing
                                    time.sleep(0.5)

                                time.sleep(1)

                                # Reset the state of the switch
                                self.controller.register_reset('nh_avaibility_1')
                                self.controller.register_reset('nh_avaibility_2')
                                self.controller.register_reset('nh_avaibility_3')
                                self.controller.register_reset('nbflows_progressing_2')
                                self.controller.register_reset('nbflows_progressing_3')
                                self.controller.register_reset('rerouting_ts')
                                self.controller.register_reset('timestamp_reference')
                                self.controller.register_reset('sw_time')
                                self.controller.register_reset('sw_index')
                                self.controller.register_reset('sw_sum')
                                self.controller.register_reset('sw')
                                self.controller.register_reset('flowselector_key')
                                self.controller.register_reset('flowselector_nep')
                                self.controller.register_reset('flowselector_ts')
                                self.controller.register_reset('flowselector_last_ret')
                                self.controller.register_reset('flowselector_last_ret_bin')
                                self.controller.register_reset('flowselector_correctness')
                                self.controller.register_reset('flowselector_fwloops')


                                print self.sw_name, ' RESET.'

                                # Restart the scheduler
                                time.sleep(1)
                                self.t_sched.start()


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--topo_db', nargs='?', type=str, default=None, help='Topology database.')
    parser.add_argument('--sw_name', nargs='?', type=str, default=None, help='Name of the P4 switch.')
    parser.add_argument('--controller_ip', nargs='?', type=str, default='localhost', help='IP of the controller (Default is localhost)')
    parser.add_argument('--controller_port', nargs='?', type=int, default=None, help='Port of the controller')
    parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Directory used for the log')
    parser.add_argument('--routing_file', nargs='?', type=str, default=None, help='File (json) with the routing')

    args = parser.parse_args()
    topo_db = args.topo_db
    sw_name = args.sw_name
    ip_controller = args.controller_ip
    port_controller = args.controller_port
    log_dir = args.log_dir
    routing_file = args.routing_file

    controller = BlinkController(topo_db, sw_name, ip_controller, port_controller, \
    log_dir, routing_file=routing_file)

    controller.forwarding()
    controller.run()
