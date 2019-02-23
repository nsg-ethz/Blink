struct controller_metadata_t {
	bit<1> toController;
	bit<32> code;
}

struct custom_metadata_t {
    // Metadata used in the normal pipeline
    bit<32> id;
    // bit<1> matched;
    bit<1> use_blink;


    bit<1> is_retransmission;

    // Metadata used for the next-hops
    bit<32> next_hop_port;
    IPv4Address nhop_ipv4;

    bit<16> tcp_payload_len;

    // Metadata to handle the timestamps for the flowcache
    bit<9> ingress_timestamp_second;
    bit<19> ingress_timestamp_millisecond;

    // Metadata used by the FlowCache
    bit<32> flowselector_cellid;

    bit<1> selected;

    bit<2> bgp_ngh_type;
}
