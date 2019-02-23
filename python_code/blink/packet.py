import math
from python_code.murmur import _murmur3str

class TCPPacket:
    def __init__(self, ts, src_ip, dst_ip, seq, src_port, dst_port, ip_len, \
    ip_hdr_len, tcp_hdr_len, syn_flag, fin_flag, ret=None, dmac=None):
        self.ts = ts
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.seq = seq
        self.src_port = src_port
        self.dst_port = dst_port
        self.ip_len = ip_len
        self.ip_hdr_len = ip_hdr_len
        self.tcp_hdr_len = tcp_hdr_len
        self.tcp_payload_len = ip_len - ip_hdr_len - tcp_hdr_len
        self.syn_flag = syn_flag
        self.fin_flag = fin_flag
        self.ret = ret

        # Used when hashing packet based on the 5-tuple
        self.hashkey = self.src_ip+self.dst_ip+str(self.src_port)+str(self.dst_port)

        # Set the payload to 1 if there is the SYN or FIN flag because the
        # sequence number progress by one upon such packets
        if self.syn_flag or self.fin_flag:
            self.tcp_payload_len = 1

        self.tag = None
        self.dmac = None
        self.metadata = {}

    def __str__(self):
        return str(self.ts)+'\t'+str(self.src_ip)+'\t'+str(self.dst_ip)+'\t'+ \
        str(self.src_port)+'\t'+str(self.dst_port)+'\t'+str(self.seq)+'\t'+ \
        str(self.tcp_payload_len)+'\t'+str(self.dmac)+'\t'+str(self.metadata)

    def flow_hash(self, nb_bits, seed):
        # Keep return random number between 1 and 2^nb_bits.
        return _murmur3str.murmur3str(self.hashkey, len(self.hashkey), seed)% \
            (int(math.pow(2,nb_bits))-1)+1
