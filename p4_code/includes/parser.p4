#define ETHERTYPE_IPV4                      16w0x800
#define IP_PROTOCOLS_TCP                    8w6

parser ParserImpl(packet_in pkt_in, out Parsed_packet pp,
    inout custom_metadata_t meta,
    inout standard_metadata_t standard_metadata) {

    state start {
        pkt_in.extract(pp.ethernet);
        transition select(pp.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            // no default rule: all other packets rejected
        }
    }

    state parse_ipv4 {
        pkt_in.extract(pp.ipv4);
        transition select(pp.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt_in.extract(pp.tcp);

        transition accept;
    }
}
