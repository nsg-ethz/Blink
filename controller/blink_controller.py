import sys
import socket
import select
import logging
import logging.handlers
import argparse
import json
from p4utils.utils.topology import Topology
import re
import struct

from util import logger

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', nargs='?', type=int, default=None, help='Port of the controller', required=True)
parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Directory used for the logs')
parser.add_argument('--log_level', nargs='?', type=int, default=20, help='Log level')
parser.add_argument('--topo_db', nargs='?', type=str, default=None, help='Topology database.', required=True)
parser.add_argument('--routing_file', type=str, help='File with the routing information', required=True)
parser.add_argument('--threshold', type=int, default=31, help='Threshold used to decide when to fast reroute')

args = parser.parse_args()
port = args.port
log_dir = args.log_dir
log_level = args.log_level
topo_db = args.topo_db
routing_file = args.routing_file
threshold = args.threshold

# Logger for the controller
logger.setup_logger('controller', log_dir+'/controller.log', level=log_level)
log = logging.getLogger('controller')

log.info(str(port)+'\t'+str(log_dir)+'\t'+str(log_level)+'\t'+str(routing_file)+ \
'\t'+str(threshold))

# Read the topology
topo = Topology(db=topo_db)

mapping_dic = {}
tmp = list(topo.get_hosts())+list(topo.get_p4switches())
mapping_dic = {k: v for v, k in enumerate(tmp)}
log.info(str(mapping_dic))


"""
    This function adds an entry in a match+action table of the switch
"""
def add_entry_fwtable(connection, fwtable_name, action_name, match_list, args_list):
    args_str = ''
    for a in args_list:
        args_str += str(a)+' '
    args_str = args_str[:-1]

    match_str = ''
    for a in match_list:
        match_str += str(a)+' '
    match_str = match_str[:-1]

    log.log(25, 'table add '+fwtable_name+' '+action_name+' '+match_str+ ' => '+args_str)
    connection.sendall('table add '+fwtable_name+' '+action_name+' '+match_str+ \
    ' => '+args_str+'\n')

def do_register_write(connection, register_name, index, value):
    log.log(25, 'do_register_write '+register_name+' '+str(index)+' '+str(value))
    connection.sendall('do_register_write '+register_name+' '+str(index)+' '+ \
    str(value)+'\n')

def set_bgp_tags(sw_name):
    json_data = open(routing_file)
    routing_info = json.load(json_data)

    p4switches = topo.get_p4switches()
    interfaces_to_node = p4switches[sw_name]['interfaces_to_node']

    for k, v in interfaces_to_node.items():
        if v in routing_info['switches'][sw_name]["bgp"]:
            bgp_peer_type = routing_info['switches'][sw_name]["bgp"][v]
            interface = p4switches[sw_name][v]['intf']
            inport = p4switches[sw_name]['interfaces_to_port'][interface]
            src_mac = p4switches[v][sw_name]['mac']

            if bgp_peer_type == 'customer':
                bgp_type_val = 0
            else:
                bgp_type_val = 1

            add_entry_fwtable(sock, 'bgp_tag', 'set_bgp_tag', \
                [inport, src_mac], [bgp_type_val])


# Socket to communicate with the p4_controller script
sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_server.bind(('', port))
sock_server.listen(5)
print 'Waiting for new connection...'

socket_list = [sock_server, sys.stdin]

while True:
    read_sockets, write_sockets, error_sockets = select.select(socket_list,[],[])

    for sock in read_sockets:
        if sock == sys.stdin:
            line = sys.stdin.readline()
            if line == 'reset_states\n':
                for sock in socket_list:
                    if sock != sock_server and sock != sys.stdin:
                        sock.sendall('reset_states\n')
                print 'resetting states..'
            else:
                print "Unknown command."
            print '> '

        elif sock == sock_server:
            sock, client_address = sock.accept()
            socket_list.append(sock)

            print "Client (%s, %s) connected" % client_address

            sw_name = sock.recv(10000000)
            print 'switch ', sw_name, ' connected'
            print '> '

            # This IP is used to identify each switch.
            # It is used to reply to the traceroutes
            ip_tmp = '200.200.200.'+str(re.search(r'\d+$', sw_name).group())
            ip_num = struct.unpack("!I", socket.inet_aton(ip_tmp))[0]
            do_register_write(sock, 'switch_ip', 0, ip_num)

            json_data = open(routing_file)
            routing_info = json.load(json_data)

            for host in topo.get_hosts():
                threshold_tmp = threshold
                if "threshold" in routing_info['switches'][sw_name]:
                    threshold_tmp = routing_info['switches'][sw_name]['threshold']

                do_register_write(sock, 'threshold_registers', mapping_dic[host]*2, \
                threshold_tmp)
                do_register_write(sock, 'threshold_registers', mapping_dic[host]*2+1, \
                threshold_tmp)

            for host, nh in routing_info['switches'][sw_name]['prefixes'].items():
                host_prefix = topo.get_host_ip(host)+'/24'

                if "customer" in nh and len(nh["customer"]) > 0:
                    # Add the set_meta forwarding rule for the <prefix,customer> tuple
                    add_entry_fwtable(sock, 'meta_fwtable', 'set_meta', \
                        [str(host_prefix), 0], [mapping_dic[host]*2, \
                        0 if len(nh["customer"]) == 1 else 1,\
                        mapping_dic[nh["customer"][0]]])

                    # If only one backup next-hop is avaible, use it two times
                    if len(nh["customer"]) == 2:
                        nh["customer"].append(nh["customer"][-1])

                    i = 0
                    for n in nh["customer"]:
                        do_register_write(sock, 'next_hops_port', mapping_dic[host]*6+i, \
                        mapping_dic[nh["customer"][i]])
                        i += 1

                # Add the set_meta forwarding rule for the <prefix,customer_provider_peer> tuple
                if "customer_provider_peer" in nh and len(nh["customer_provider_peer"]) > 0:
                    add_entry_fwtable(sock, 'meta_fwtable', 'set_meta', \
                        [str(host_prefix), 1], [mapping_dic[host]*2+1, \
                        0 if len(nh["customer_provider_peer"]) == 1 else 1, \
                        mapping_dic[nh["customer_provider_peer"][0]]])

                    # If only one backup next-hop is avaible, use it two times
                    if len(nh["customer_provider_peer"]) == 2:
                        nh["customer_provider_peer"].append(nh["customer_provider_peer"][-1])

                    i = 0
                    for n in nh["customer_provider_peer"]:
                        do_register_write(sock, 'next_hops_port', mapping_dic[host]*6+(3+i), \
                        mapping_dic[nh["customer_provider_peer"][i]])
                        i += 1

            set_bgp_tags(sw_name)

        else:
            try:
                data = sock.recv(10000000)
                if data:
                    print 'Message received ', sock, data
            except:
                print 'Client ', str(sock), ' is disconnected'
                sock.close()
                socket_list.remove(sock)

    for sock in error_sockets:
        print 'Error ', sock
