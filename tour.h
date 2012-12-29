#ifndef A4_TOUR_H
#define A4_TOUR_H
#include "unp.h"
#include "arp.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_systm.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define NUM_VM 10
#define IPPROTO_TOUR 189
#define TOUR_IDENTIFICATION 2881
// multicast ip address
#define MULTICAST_IP "239.255.2.31"
// #define MULTICAST_IP "224.0.0.11"
#define MULTICAST_PORT "2882"

#define TOUR_PATH "tour_path"
// #define ARP_PATH  "arp_path"

#define ROUTE_LEN 256

struct datagram {
	// 20 bytes header
	struct ip header;
	// data
	int len;
	int itr;
	struct in_addr key;
	struct in_addr nodes[ROUTE_LEN];
	char mc_ip[INET_ADDRSTRLEN];
	int mc_port;
};

struct pf_ip_icmp {
	unsigned char dst_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];
	uint16_t type;
	char buf[84];
};

extern int my_vm;
extern int my_if_index;
extern unsigned char my_if_hwaddr[ETH_ALEN];
extern unsigned char my_name[INET_ADDRSTRLEN];
extern unsigned char my_ip[INET_ADDRSTRLEN];
extern struct in_addr my_addr;
extern pid_t child_ping;

// raw sockets for routing and ping
extern int rt_sock;
extern int pg_sock;

// pf packet
extern int pf_sock;

// udp sockets for multicasting
extern socklen_t mc_addr_len;
extern int sock_mc_send;
extern int sock_mc_recv;
extern struct sockaddr *sasend;
extern struct sockaddr *sarecv;

// nodes information
extern unsigned char node_name[NUM_VM][INET_ADDRSTRLEN];
extern unsigned char node_ip[NUM_VM][INET_ADDRSTRLEN];
extern struct in_addr node_addr[NUM_VM];

// unix domain socket
extern int un_sock;
extern struct sockaddr_un un_addr;

//////////////////////////////////////////////////////////////////////////
// Function prototypes
// init functions
void nodes_ip_init();
void rawsock_init();

//////////////////////////////////////////////////////////////////////////
// process route: tour.c
void generate_tour(int argc, char **argv);
void process();
void process_tour(struct datagram *dg);

//////////////////////////////////////////////////////////////////////////
// Multicast: mcast.c
void mc_init();
void mc_join(char *mc_ip, int mc_port);
void mc_send(int sendfd, struct sockaddr *sadest, socklen_t salen, const char *buf, size_t len);
void mc_recv(int recvfd, socklen_t salen);


//////////////////////////////////////////////////////////////////////////
// areq: ping.c
void un_init();
void un_clear();
int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr);

//////////////////////////////////////////////////////////////////////////
// ping: ping.c
void ping(struct in_addr src, struct in_addr me);
void ping_init();
int ping_send(struct in_addr src, uint16_t seq);
void ping_recv(char *ptr, ssize_t len, struct timeval *tvrecv, int vmid);

static void 
sig_alrm(int signo)
{
	return;
}
#endif

