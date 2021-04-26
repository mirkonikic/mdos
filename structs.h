#ifndef __STRUCTS_H__
#define __STRUCTS_H__

#pragma pack(push)
#pragma pack(1)
struct ip_header
{
    unsigned char version_ihl;
    unsigned char type_of_service;
    uint16_t length;
    uint32_t scnd_line;
    unsigned char ttl;
    unsigned char protocol;
    uint16_t checksum;
    uint32_t source_addr;
    uint32_t dest_addr;
    uint32_t options;
};

struct tcp_header
{
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t off_res_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
    uint32_t opts_pad;
};
#pragma pack(pop)

typedef struct global_args
{
    uint16_t attack_port;
    struct in_addr attack_ip;
    struct sockaddr_in iface_addr;
    int syn_delay;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    size_t payload_size;
} GlobalArgs;

typedef struct pckt_det
{
    unsigned long syn_sent;
    unsigned long ack_sent;
    unsigned long synack_recv;
    unsigned long ack_recv;
    unsigned long rst_recv;
} PacketDetails;

#endif
