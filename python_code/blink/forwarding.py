import sys
import logging

sys.path.insert(0, 'util/')
from logger import setup_logger


class Forwarding:
    def __init__(self, params):
        self.routed = set()
        self.fast_rerouted = set()

        # Logger for the Frowarding
        setup_logger('forwarding', params['debug_dir']+'/forwarding.log', level=params['debug_level'])
        self.log = logging.getLogger('forwarding')

        self.outfile = params['output']['filename']
        self.fd = open(self.outfile, 'w', 1)

        self.event_fastreroute = False

    def forward_packet(self, packet, to_fastreroute=True):
        field = packet.dst_ip, packet.dst_port

        if field not in self.routed:
            if len(self.fast_rerouted) == 0:
                self.log.info('Routed_Before\t'+str(field))
            else:
                self.log.info('Routed_After\t'+str(field))
        self.routed.add(field)

        if to_fastreroute:
            if field not in self.fast_rerouted:
                self.log.info('FastRerouted\t'+str(field))
            self.fast_rerouted.add(field)

        """if to_fastreroute:
            self.fd.write(str(packet)+'\tFastRerouted\n')
        else:
            self.fd.write(str(packet)+'\tNormallyRouted\n')"""

    def write_event(self, event):
        if event == 'Event: FastReroute\n':
            if not self.event_fastreroute:
                self.fd.write(event)
            self.event_fastreroute = True
