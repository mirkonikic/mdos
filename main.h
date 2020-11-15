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

#define DEF_DELAY 10000 //10 * 1000 gde je 1000 1ms u usleep
#define MAX_PAYLOAD_SIZE 1000
#define DEBUGMODE 0

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

#endif
