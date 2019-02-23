// Maximum number of prefixes
#define MAX_NB_PREFIXES 32w100

// Macros for the per flow retransmission detector component
#define RET_DETECTOR_CBF_SIZE 32w1000000

// Macros for the maximum flows selection time
#define MAX_FLOWS_SELECTION_TIME 48w500000000   // Default 500s = 48w500000000

// Macros for the size of Counting Bloom Filter used for the flow filter
#define FLOWSET_BF_SIZE 32w1000000

// Macros for the sliding window
#define SW_NB_BINS 4w10
#define SW_BINS_DURATION ((bit<19>)(48w80000 >> 10))   // 800000 microseconds!!

// Macros for the flowselector
#define FLOWSELECTOR_NBFLOWS 32w64
#define FLOWSELECTOR_TIMEOUT 9w2 // In second
#define TWO_POWER_32 64w4294967296 // 2^32

// Two offsets for obtain to different hash functions from the crc32 hash function
#define HASH1_OFFSET 32w2134
#define HASH2_OFFSET 32w56097

// Number of progressing flows required in order to classify a nexthop as working
#define MIN_NB_PROGRESSING_FLOWS (threshold_tmp >> 1)
#define TIMEOUT_PROGRESSION (48w1000000 >> 10) // approx.  1s
#define FWLOOPS_TRIGGER 2w3

// Macro used to reply to traceroutes
#define IP_ICMP_PROTO 1
#define ICMP_TTL_EXPIRED 11
