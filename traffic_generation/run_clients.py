import time
import argparse
import multiprocessing
from traffic_generation.flowlib import sendFlowTCP
import logging
import logging.handlers

from util import logger

parser = argparse.ArgumentParser()
parser.add_argument('--dst_ip', nargs='?', type=str, default=None, help='Destination IP', required=True)
parser.add_argument('--src_ports', nargs='?', type=str, default=None, help='Ports range', required=True)
parser.add_argument('--dst_ports', nargs='?', type=str, default=None, help='Ports range', required=True)
parser.add_argument('--ipd', nargs='?', type=float, default=None, help='Inter packet delay', required=True)
parser.add_argument('--duration', nargs='?', type=int, default=None, help='Duration', required=True)
parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Log Directory', required=False)
args = parser.parse_args()
dst_ip = args.dst_ip
src_ports = args.src_ports
dst_ports = args.dst_ports
ipd = args.ipd
duration = args.duration
log_dir = args.log_dir

process_list = []

logger.setup_logger('traffic_generation', log_dir+'/traffic_generation.log', level=logging.INFO)
log = logging.getLogger('traffic_generation')

for src_port, dst_port in zip(range(int(src_ports.split(',')[0]), int(src_ports.split(',')[1])), \
    range(int(dst_ports.split(',')[0]), int(dst_ports.split(',')[1]))):

    flow_template = {"dst": dst_ip,
                     "dport": dst_port,
                     "sport": src_port,
                     "ipd":ipd,
                     "duration": duration}

    process = multiprocessing.Process(target=sendFlowTCP, kwargs=flow_template)
    process.daemon = True
    process.start()

    time.sleep(0.1)

    log.info('Sender started for sport: '+str(src_port)+' dport: '+str(dst_port)+ \
    ' ipd: '+str(ipd)+' duration: '+str(duration))

    process_list.append(process)

for p in process_list:
    p.join()
