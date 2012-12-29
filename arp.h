#ifndef ARP_H_
#define ARP_H_
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define FRAME_TYPE 0x0806
#define HARD_TYPE 1
#define PROT_TYPE 0x0800
#define HARD_SIZE 6
#define PROT_SIZE 4
#define INET_ADDRSTRLEN 16

#define ARP_REQ 1
#define ARP_REP 2

#define MAX_CACHE 128

#define ARP_PROTOCOL 19351
#define ARP_ID  	 15391
// number of interfaces
#define NIF 16

#define ARP_PATH "arp_path_1332"

struct hwaddr {
		     int             sll_ifindex;	 /* Interface number */
		     unsigned short  sll_hatype;	 /* Hardware type */
		     unsigned char   sll_halen;		 /* Length of address */
		     unsigned char   sll_addr[ETH_ALEN];	 /* Physical layer address */
		     unsigned char	 sll_ip[INET_ADDRSTRLEN]; /* Corresponding IP */
};

struct arp_msg {

	/* Ethernet header */
	unsigned char dst_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];
	uint16_t f_t; //frame type

	/* id field */
	uint16_t id; //identification

	/* ARP request/reply */
	uint16_t hrd; //hard type
	uint16_t pro; //prot type
	unsigned char hln; //hard size
	unsigned char pln; //prot size

	unsigned char op; //1 for ARO request, 2 for ARP reply

	unsigned char sender_mac[ETH_ALEN];
	unsigned char sender_ip[INET_ADDRSTRLEN];
	unsigned char target_mac[ETH_ALEN];
	unsigned char target_ip[INET_ADDRSTRLEN];
};

struct arp_cache_entry {
	unsigned char 	ip[INET_ADDRSTRLEN];
	unsigned char 	mac[ETH_ALEN];
	uint16_t 		sll_ifindex;
	uint16_t		sll_hatype;
	int				connfd;
	int 			isValid;
	int				isComplete;
	int				isLocal;
};
#endif /* ARP_H_ */
