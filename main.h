#ifndef __MAIN_H__
#define __MAIN_H__

/*INCLUDE STANDARD LIBRARIES*/
#include <arpa/inet.h>
#include <fcntl.h> 
//#include <linux/if.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>   
#include <sys/types.h>  
#include <sys/wait.h> 
#include <time.h>
#include <unistd.h>

#define MAX_PAYLOAD_SIZE 1000
#define VERBOSE 0

/*TERMINAL COLOR CODES*/
#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define YELLOW  "\033[32m"      /* Yellow */
#define GREEN   "\033[33m"      /* Green */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLD	"\033[1m"
#define BOLDBLACK    "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED      "\033[1m\033[31m"      /* Bold Red */
#define BOLDYELLOW   "\033[1m\033[32m"      /* Bold Yellow */
#define BOLDGREEN    "\033[1m\033[33m"      /* Bold Green */
#define BOLDBLUE     "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA  "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN     "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE    "\033[1m\033[37m"      /* Bold White */

void intro(int t);
void parseArgs(int argc, char** argv);
void initDetails();
int get_interface_ip(struct sockaddr_in *ip, char *iface);
void *process_incoming(void *arg);
void *print_status(void *arg);
void *send_packet(void* arg);
void send_ack(unsigned char *packet);
void calc_tcp_checksum(unsigned char* packet, unsigned long packet_length, struct in_addr src, struct in_addr dst);
void loadPayload(char *path);

#endif
