import radix
import logging
import sys

from util import logger

"""
    This class implements a forwarding table which matches on the destination
    prefix using a Longest Prefix Match, and crafts some metadatas to the packet
"""
class FWTable:
    def __init__(self, debug_dir, debug_level, debug_name):
        self.rtree = radix.Radix()

        # Logger for the pipeline
        logger.setup_logger('fwtable', debug_dir+'/'+debug_name, debug_level)
        self.log = logging.getLogger('fwtable')

    """
        Prefix is the match, metadata is the a dictionnary with the metadata to
        craft to the matched packets
    """
    def add_fw_rule(self, prefix, metadata):
        metadata_str = ''
        for v in metadata:
            metadata_str += str(v)+'|'
        metadata_str = metadata_str[:-1]

        self.log.log(22, str(prefix)+'|'+metadata_str)

        rnode = self.rtree.add(prefix)

        rnode.data['id'] = int(metadata[0])

    def process_packet(self, packet):
        rnode = self.rtree.search_best(packet.dst_ip)
        if rnode is not None:
            for k, v in rnode.data.items():
                packet.metadata[k] = v

            return True
        else:
            return False

if __name__ == '__main__':
    from packet import TCPPacket

    fwtable = FWTable('log', 20, 'fr_fwtable.log')

    fwtable.add_fw_rule('2.2.2.0/24', {'meta1':1, 'meta2':'salut'})

    p1 = TCPPacket(1, '1.1.1.1', '2.2.2.2', 1, 2, 3, 10, 10, 10, False, False)
    p2 = TCPPacket(1, '1.1.1.1', '2.2.3.2', 1, 2, 3, 10, 10, 10, False, False)

    fwtable.process_packet(p1)
    print p1
    fwtable.process_packet(p2)
    print p2
