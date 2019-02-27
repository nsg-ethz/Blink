import argparse
from subprocess import Popen
from p4utils.utils.topology import Topology

parser = argparse.ArgumentParser()
parser.add_argument('--topo_db', nargs='?', type=str, default=None, help='Topology database.')
parser.add_argument('--controller_ip', nargs='?', type=str, default='localhost', help='IP of the controller (Default is localhost)')
parser.add_argument('--controller_port', nargs='?', type=int, default=None, help='Port of the controller')
parser.add_argument('--log_dir', nargs='?', type=str, default='log', help='Directory used for the log')
parser.add_argument('--routing_file', nargs='?', type=str, default=None, help='File (json) with the routing')

args = parser.parse_args()
topo_db = args.topo_db
ip_controller = args.controller_ip
port_controller = args.controller_port
log_dir = args.log_dir
routing_file = args.routing_file

routing_file_param = '' if routing_file is None else '--routing_file '+routing_file

# Read the topology
topo = Topology(db=topo_db)

pid_list = []
for s in topo.get_p4switches():
    print "sudo python -m controller.p4_controller --topo_db "+str(topo_db)+" \
    --sw_name "+str(s)+" --controller_ip "+str(ip_controller)+" --controller_port \
    "+str(port_controller)+" --log_dir "+str(log_dir)+" "+routing_file_param

    pid_list.append(Popen("sudo python -m controller.p4_controller --topo_db \
    "+str(topo_db)+" --sw_name "+str(s)+" --controller_ip "+str(ip_controller)+" \
    --controller_port "+str(port_controller)+" --log_dir "+str(log_dir)+" "+ \
    routing_file_param, shell=True)) # call subprocess

for pid in pid_list:
    pid.wait()
