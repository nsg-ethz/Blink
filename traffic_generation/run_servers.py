import argparse
import multiprocessing
import logging
import logging.handlers
from traffic_generation.flowlib import recvFlowTCP

from util import logger

parser = argparse.ArgumentParser()
parser.add_argument('--ports', nargs='?', type=str, default=None, help='Ports range', required=True)
parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Log Directory', required=False)
args = parser.parse_args()
port_range = args.ports
log_dir = args.log_dir

logger.setup_logger('traffic_generation_receiver', log_dir+'/traffic_generation_receiver.log', level=logging.INFO)
log = logging.getLogger('traffic_generation_receiver')

process_list = []

for port in range(int(port_range.split(',')[0]), int(port_range.split(',')[1])):

    flow_template = {"dport":port}

    process = multiprocessing.Process(target=recvFlowTCP, kwargs=flow_template)
    process.daemon = True
    process.start()

    log.info('Receiver started for dport: '+str(port))

    process_list.append(process)

for p in process_list:
    p.join()
