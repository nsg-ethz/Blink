import sys
import socket
import logging
import logging.handlers
import argparse
import ipaddress

from util import logger

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', nargs='?', type=int, default=None, help='Port of the controller', required=True)
parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Directory used for the log')
parser.add_argument('--log_level', nargs='?', type=int, default=20, help='Log level')
parser.add_argument('--nbprefixes', nargs='?', type=int, default=10000, help='Number of prefixes to monitor')
parser.add_argument('--prefixes_file', type=str, help='File with the list of prefixes to monitor', required=True)
parser.add_argument('--threshold', type=int, default=31, help='Threshold used to decide when to fast reroute')

args = parser.parse_args()
port = args.port
log_dir = args.log_dir
log_level = args.log_level
nbprefixes = args.nbprefixes
prefixes_file = args.prefixes_file
threshold = args.threshold

# Logger for the pipeline
logger.setup_logger('controller', log_dir+'/controller.log', level=log_level)
log = logging.getLogger('controller')

log.info(str(port)+'\t'+str(log_dir)+'\t'+str(log_level)+'\t'+str(nbprefixes)+ \
'\t'+str(threshold))

log.info('Number of monitored prefixes: '+str(nbprefixes))

# Socket to communicate with the p4 pipeline
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('', port))
sock.listen(5)
print 'Waiting for new connection...'

connection, client_address = sock.accept()

print 'Connected to', client_address


"""
    This function push a forwarding entry in a forwarding table of the switch
"""
def add_entry_fwtable(connection, fwtable_name, action_name, prefix, args_list):
    args_str = ''
    for a in args_list:
        args_str += str(a)+' '
    args_str = args_str[:-1]

    log.log(25, 'table add '+fwtable_name+' '+action_name+' '+prefix+ ' => '+args_str)
    connection.sendall('table add '+fwtable_name+' '+action_name+' '+prefix+ \
    ' => '+args_str+'\n')

def do_register_write(connection, register_name, index, value):
    log.log(25, 'do_register_write '+register_name+' '+str(index)+' '+str(value))
    connection.sendall('do_register_write '+register_name+' '+str(index)+' '+ \
    str(value)+'\n')

prefixes_list = []

with open(prefixes_file, 'r') as fd:
    for line in fd.readlines():
        linetab = line.rstrip('\n').split('\t')
        if len(linetab) > 1:
            prefix = linetab[0]
            nb_pkts = int(linetab[1])
            nb_bytes = int(linetab[2])
        else:
            prefix = line.rstrip('\n').split(' ')[0]
            nb_pkts = 0
            nb_bytes = 0

        prefixes_list.append((prefix, nb_pkts, nb_bytes))

# Sort based on the number of bytes
prefixes_list = sorted(prefixes_list, key=lambda x:x[1], reverse=True)

prefix_id_dic = {}
id_prefix_dic = {}

# Populates the metatable in the p4 switch so as to monitor the top prefixes
for prefix, nb_pkts, nb_bytes in prefixes_list[:nbprefixes]:

    add_entry_fwtable(connection, 'meta_fwtable', 'set_meta', str(prefix), \
        [len(prefix_id_dic)])
    do_register_write(connection, 'threshold_registers', len(prefix_id_dic), threshold)
    # do_register_write(connection, 'next_hops_index', len(prefix_id_dic), 0)

    do_register_write(connection, 'next_hops_port', len(prefix_id_dic)*3, 2)
    do_register_write(connection, 'next_hops_port', (len(prefix_id_dic)*3)+1, 3)
    do_register_write(connection, 'next_hops_port', (len(prefix_id_dic)*3)+2, 4)


    id_prefix_dic[len(prefix_id_dic)] = prefix
    prefix_id_dic[prefix] = len(prefix_id_dic)

connection.sendall('READY\n')

data = ''

while True:
    data_tmp = connection.recv(100000000)

    if len(data_tmp) == 0:
        sock.close()
        print 'Connection closed on the controller, exiting..'
        sys.exit(0)

    else:
        data += data_tmp

        next_data = ''
        while len(data) > 0 and data[-1] != '\n':
            next_data = data[-1]+next_data
            data = data[:-1]

        data = data.rstrip('\n')

        for line in data.split('\n'):
            if line.startswith('CLOSING'):
                log.info('CONTROLLER CLOSING')
                connection.close()
                sys.exit(0)

            elif line.startswith('RET'):
                linetab = line.rstrip('\n').split('|')
                ts = float(linetab[1])
                prefix_id = int(linetab[2])
                dst_ip = id_prefix_dic[prefix_id].split('/')[0]

                log.info('RET|'+str(prefix_id)+'\t'+str(dst_ip)+'\t'+str(ts))

        data = next_data
