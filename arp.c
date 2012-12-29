#include "unp.h"
#include "hw_addrs.h"
#include "arp.h"

#define NUM_VM 10

int maxfd = 0;
fd_set rset, allset;

unsigned char if_hwaddr[NIF][IF_HADDR];
int if_sock[NIF], if_size;
unsigned char node_ip[NUM_VM][INET_ADDRSTRLEN];
struct sockaddr_ll if_addr[NIF];

unsigned char broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// socket file descriptor for etho0
int if_sockfd;
// hardware address for etho0
struct sockaddr_ll addr;

// Unix domain socket
int un_listenfd;
int un_connfd = -1;
struct sockaddr_un un_addr;
struct sockaddr_un un_cliaddr;

// this vm's number and etho0's hardware index
int my_vm, my_index;
unsigned char my_ip[INET_ADDRSTRLEN];

struct arp_cache_entry cache[MAX_CACHE];

void cache_init();
void arpModel();
void un_init();
void if_init();
void accept_conn(int fd);
int search_cache(char ip[]);
int insert_entry(struct arp_cache_entry entry);
void update_cache(int index, struct arp_msg *msg);
void insert_local_hw_cache(char ip[]);
void delete_cache(int fd);
int isDest(char ip[]);
int recv_arp(int sockfd, struct arp_msg *msg);
void process_un(int sockfd, struct hwaddr *hwaddr_info);
void process_arp_request(int sockfd, struct arp_msg *msg);
void process_arp_reply(int sockfd, struct arp_msg *msg);
int recv_un(int sockfd, struct hwaddr *hwaddr_info);

int
main() {
	FD_ZERO(&allset);
	if_init();
	un_init();
	cache_init();
	arpModel();
	return 0;
}

void
arpModel() {
	int n;
	// puts("----->ARP: Ready for requests...");
	while (1) {
		// rset = allset;
		FD_ZERO(&rset);
		FD_SET(un_listenfd, &rset);
		FD_SET(if_sockfd, &rset);
		maxfd = max(un_listenfd, if_sockfd);
		if (un_connfd != -1){
			printf("Add un_connfd to fs_set %d\n", un_connfd);
			FD_SET(un_connfd, &rset);
			maxfd = (maxfd, un_connfd);
		}
		Select(maxfd + 1, &rset, NULL, NULL, NULL);

		if (FD_ISSET(un_listenfd, &rset)) {
			// puts("----->ARP: Request to establish domain socket connection.");
			accept_conn(un_listenfd);
		}

		if (un_connfd != -1 && FD_ISSET(un_connfd, &rset)) {
			struct hwaddr hwaddr_info;
			bzero(&hwaddr_info, sizeof(struct hwaddr));
			if ((n = recv_un(un_connfd, &hwaddr_info)) > 0) {
				// puts("----->ARP: Incoming un_packet. Handing over...");
				// printf("Requested IP is: %s\n", hwaddr_info.sll_ip);
				process_un(un_connfd, &hwaddr_info);
			} else if(n == 0) {
				puts("----->ARP: Time out.");
				close(un_connfd);
				un_connfd = -1;
			}
		}

		if (FD_ISSET(if_sockfd, &rset)) {
			struct arp_msg msg;
			bzero(&msg, sizeof(struct arp_msg));
			if ((n = recv_arp(if_sockfd, &msg)) == 0) {
				// puts("*********MSG received***********");
				// print_msg(&msg);
				if (msg.op == ARP_REQ) {
					// puts("----->ARP: Incoming PF_PACKET: ARP request. Handing over...");
					process_arp_request(if_sockfd, &msg);
				} else if (msg.op == ARP_REP) {
					// puts("----->ARP: Incoming PF_PACKET: ARP reply. Handing over...");
					process_arp_reply(if_sockfd, &msg);
				}
			}
		}
	}
}

/*********************************************************************
 * Initialization Functions *
 *********************************************************************/

void
cache_init() {
	memset(cache, 0, sizeof(cache));
}

/* Create  Unix Domain Socket */
void
un_init()
{
	un_listenfd = Socket(AF_LOCAL, SOCK_STREAM, 0);

	bzero(&un_addr, sizeof(struct sockaddr_un));
	un_addr.sun_family = AF_LOCAL;
	strcpy(un_addr.sun_path, ARP_PATH);
	unlink(ARP_PATH);
	bind(un_listenfd, (SA *)&un_addr, sizeof(struct sockaddr_un));
	listen(un_listenfd, LISTENQ);
	maxfd = max(maxfd, un_listenfd);
}

void
if_init()
{
	struct hwa_info *hwa, *hwahead;
	struct sockaddr *sa;
	struct hostent *hptr;
	char *ptr;
	char **pptr;
	int i, j, prflag, n;
	struct arp_cache_entry cache_entry;

	memset(if_hwaddr, 0, sizeof(if_hwaddr));
	memset(if_sock, 0, sizeof(if_sock));
	if_size = 0;
	puts("<-- HW INFO -->");
	for (i = 0; i < NUM_VM; i++){
		sprintf(node_ip[i], "vm%d", i+1);
		hptr = gethostbyname(node_ip[i]);
		for (pptr = hptr->h_addr_list; *pptr != NULL; pptr++){
			Inet_ntop(hptr->h_addrtype, *pptr, node_ip[i], INET_ADDRSTRLEN);
		}
	}
	for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {
		printf("interface index = %d\n", (n = hwa->if_index));
		printf("%s :%s", hwa->if_name,
				((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");

		if ((hwa->ip_alias) != IP_ALIAS) {
			if_size++;
		}
		if ((sa = hwa->ip_addr) != NULL) {
			printf("\tIP addr = %s\n", Sock_ntop_host(sa, sizeof(*sa)));

			if (hwa->if_haddr != NULL) {
				if (strcmp(hwa->if_haddr, if_hwaddr[my_index])
						== 0 && (hwa->ip_alias) == IP_ALIAS) {
					insert_local_hw_cache(Sock_ntop_host(sa, sizeof(*sa)));
				}
			}
		}
		// get canonical ip
		if (strcmp(hwa->if_name, "eth0") == 0) {
			sprintf(my_ip, "%s", Sock_ntop_host(sa, sizeof(*sa)));

			my_index = hwa->if_index;
			for (my_vm = 0; my_vm < NUM_VM; my_vm++) {
				if (strcmp(my_ip, node_ip[my_vm]) == 0) {
					my_vm++;
					break;
				}
			}
		}

		prflag = i = 0;
		do {
			if (hwa->if_haddr[i] != '\0') {
				prflag = 1;
				break;
			}
		} while (++i < IF_HADDR);

		if (prflag) {
			printf("\tHW addr = ");
			for (i = 0; i < IF_HADDR; i++) {
				if_hwaddr[n][i] = hwa->if_haddr[i];
				printf("%02x ", (int) if_hwaddr[n][i] & 0xff);
			}
			puts("");
		}
	}
	// printf("***info: number of interfaces -- %d\n***", if_size);
	// Create PF_PACKET socket for etho0
	if_sockfd = Socket(AF_PACKET, SOCK_RAW, htons(ARP_PROTOCOL));

	addr.sll_family = PF_PACKET;
	addr.sll_protocol = htons(ARP_PROTOCOL);
	addr.sll_ifindex = my_index;
	addr.sll_hatype = ARPHRD_ETHER;
	addr.sll_pkttype = PACKET_HOST;
	addr.sll_halen = ETH_ALEN;

	for (j = 0; j < ETH_ALEN; j++){
		addr.sll_addr[j] = if_hwaddr[my_index][j];
	}

	Bind(if_sockfd, (SA *)&addr, sizeof(struct sockaddr_ll));
	maxfd= (maxfd, if_sockfd);
	insert_local_hw_cache(my_ip);
	// puts("if_init done\n");
	puts("");
}

/*********************************************************************
 * Cache manipulation functions *
 *********************************************************************/
/**
 * Search the cache for a given IP.
 * Return the index of IP in the cache if it exists
 * Return -1 if such an entry does not exist.
 */
int
search_cache(char ip[]) {
	int index;
	int i;
	for (index = 0; index < MAX_CACHE; index++){
		if (cache[index].isValid == 0) continue;
		// printf("Compare IP %s with cache IP %s.\n", ip, cache[index].ip);
		if (strcmp(cache[index].ip, ip) == 0)
			return index;
	}
	return -1;
}

int
insert_entry(struct arp_cache_entry entry) {
	int success = -1, i;
	puts("\t***********NEW ENTRY***********");
	printf("Connection fd:%d\n",entry.connfd);
	printf("IP:%s\n",entry.ip);
	printf("Is complete %d\n",entry.isComplete);
	printf("Is valid %d\n",entry.isValid);
	if (entry.isComplete){
		printf("MAC:");
		for (i = 0; i < ETH_ALEN; i ++) {
			printf("%02x ", (int)entry.mac[i] & 0xff);
		}
		printf("\n");
	}
	for (i = 0; i < MAX_CACHE; i ++) {
		if (cache[i].isValid != 1) {
			cache[i] = entry;
			success = 1;
			break;
		}
	}
	puts("\t******END OF NEW ENTRY*********");
	return success;
}

void
insert_local_hw_cache(char ip[]) {
	struct arp_cache_entry cache_entry;
	int i;

	cache_entry.connfd = -1;
	strcpy(cache_entry.ip, ip);
	cache_entry.isComplete = 1;
	cache_entry.isLocal = 1;
	cache_entry.isValid = 1;
	for (i = 0; i < IF_HADDR; i++){
			cache_entry.mac[i] = if_hwaddr[my_index][i];
	}
	cache_entry.sll_hatype = HARD_TYPE;
	cache_entry.sll_ifindex = my_index;

	insert_entry(cache_entry);
}

void
update_cache(int index, struct arp_msg *msg) {
	int i;
	for (i = 0; i < IF_HADDR; i++){
			cache[index].mac[i] = msg->sender_mac[i];
	}
}

void
delete_cache(int fd) {
	int i;
	for (i = 0; i < MAX_CACHE; i ++) {
		if (cache[i].isComplete != 1 && cache[i].connfd == fd) {
			cache[i].isValid = 0;
		}
	}
}

int
isDest(char ip[]) {
	int i;
	int isDest = -1;
	if ((i = search_cache(ip)) != -1) {
		// if (strcmp(cache[i].mac, if_hwaddr[my_index]) == 0) {
		if (memcmp(cache[i].mac, if_hwaddr[my_index], ETH_ALEN) == 0) {
			puts("****DESTINATION******");
			isDest = 1;
		}
	}
	return isDest;
}
/*********************************************************************
 * Receive and send ARP message functions *
 *********************************************************************/
int
recv_arp(int sockfd, struct arp_msg *msg) {
	int n;
	size_t len;
	struct sockaddr_ll sa;
	n = recvfrom(sockfd, msg, sizeof(struct arp_msg), 0,
			(SA *) &sa, &len);
	// printf("Received %d bytes.\n", n);
	if (n < 0) {
		perror("recvfrom error");
		return -1;
	}
	if (msg->f_t != htons(ARP_PROTOCOL) || msg->id != htons(ARP_ID)) {
		return -1;
	}
	return 0;
}

int
send_arp_msg(int sockfd, char destMac[], struct arp_msg *msg) {
	int i, r;
	int j;
	struct sockaddr_ll sa;
	struct ethhdr *eh = (struct ethhdr *)msg;
	for (i = 0; i < IF_HADDR; i++){
				msg->src_mac[i] = if_hwaddr[my_index][i];
				msg->sender_mac[i] = if_hwaddr[my_index][i];
				msg->dst_mac[i] = destMac[i];
	}
	//memcpy((void *)msg + ETH_ALEN, (void *)if_hwaddr[my_index], ETH_ALEN);
	eh->h_proto = htons(ARP_PROTOCOL);

	printf("Sending index is: %d\n", my_index);
	for (i = 0; i < IF_HADDR; i++){
				printf("%02x ", (int)if_hwaddr[my_index][i] & 0xff);
	}
	printf("\n");

	msg->hln = HARD_SIZE;
	msg->hrd = HARD_TYPE;
	msg->pro = PROT_TYPE;
	msg->pln = PROT_SIZE;

	// print_msg(msg);

	bzero(&sa, sizeof(sa));
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ARP_PROTOCOL);
	sa.sll_ifindex = my_index;
	sa.sll_hatype = ARPHRD_ETHER;
	sa.sll_pkttype = PACKET_OTHERHOST;
	sa.sll_halen = ETH_ALEN;

	for (i = 0; i < ETH_ALEN; i++){
		sa.sll_addr[i] = destMac[i];
	}
	r = sendto(sockfd, msg, sizeof(struct arp_msg), 0, (SA *)&sa, sizeof(sa));
	if (r < 0){
		perror("send_pf_packet error");
		return -1;
	}
/////////////////////////////////////
	////output_pf_packet(msg);
	return 0;
}

void
print_msg(struct arp_msg *msg) {
	int i;
	int option;
	printf("#######START#########\n");
	printf("*******Header********\n");
	if (msg->src_mac != NULL) {
		printf("\tSrc MAC: ");
		for (i = 0; i < IF_HADDR; i++){
			printf("%02x ", (int)msg->src_mac[i] & 0xff);
		}
		printf("\n");
	} else puts("No Src MAC.");

	if (msg->dst_mac != NULL) {
		printf("\tDest MAC: ");
		for (i = 0; i < IF_HADDR; i++){
			printf("%02x ", (int)msg->dst_mac[i] & 0xff);
		}
		printf("\n");
	} else puts("No Dest MAC");

	printf("*******ARP Message********\n");
	printf("\tExtra ID: %d\n", msg->id);
	printf("\tHard Type: %d\n", msg->hrd);
	printf("\tProt Type: %d\n", msg->pro);
	printf("\tHard Size: %d\n", (int) msg->hln);
	printf("\tProt Size: %d\n", (int) msg->pln);
	option = (int)msg->op;
	printf("\tOption: %d\n", option);
	if(option == ARP_REP){
		printf("\tTarget MAC:");
		for (i = 0; i < ETH_ALEN; i ++) {
			printf("%02x ", (int)msg->target_mac[i] & 0xff);
		}
		printf("\n");
	}
	printf("\tTarget IP:%s\n", msg->target_ip);
	printf("\tSender MAC:");
	for (i = 0; i < ETH_ALEN; i ++) {
		printf("%02x ", (int)msg->sender_mac[i] & 0xff);
	}
	printf("\n");
	printf("\tSender IP:%s\n", msg->sender_ip);
	printf("#######ENDS#########\n");

}
/*********************************************************************
 * Domain socket functions
 *********************************************************************/
void
accept_conn(int fd) {
	socklen_t clilen;

	bzero(&un_cliaddr, sizeof(un_cliaddr));
	clilen = sizeof(un_cliaddr);
	un_connfd = accept(fd, (SA *) &un_cliaddr, &clilen);

	printf("----->ARP: New domain connection established. Listen fd: %d. Connection fd: %d\n", fd, un_connfd);
}

int
recv_un(int sockfd, struct hwaddr *hwaddr_info) {
	int n;
	char *rec;
	size_t len;
	//n = recvfrom(sockfd, hwaddr_info, sizeof(struct hwaddr), 0, (SA *)&sa, &len);
	printf("----->ARP: !!!Receiving from domain socket.\n");

	n = recv(sockfd, hwaddr_info, sizeof(struct hwaddr), 0);
	//n = Recv(sockfd, rec, 3, 0);
	//printf("Received %d bytes\n", n);
	//printf("Requested IP: %s\n", hwaddr_info->sll_ip);
	//printf("Hard Type: %d\n", (int)hwaddr_info->sll_hatype);
	//puts(rec);

	if (n == 0 ) {
		delete_cache(sockfd);
		close(sockfd);
		puts("----->ARP: Time out occurred, cleaning up cache and close connection...");
	} else if (n < 0){
		puts("recvfrom error");
		return -1;
	}
	return n;
}

int
send_un(int sockfd, struct hwaddr *hwaddr_info) {
	int n;
	//n = sendto(sockfd, hwaddr_info, sizeof(hwaddr_info), 0, (SA *)un_addr, sizeof(un_addr));
	send(sockfd, hwaddr_info, sizeof(struct hwaddr), 0);
	if (n < 0)
		perror("sendto error");
	//OK
	puts("----->ARP: send_un: hwaddr_info sent.");
	return 0;
}

/*********************************************************************
 * Process message Functions *
 *********************************************************************/
void process_arp_request(int sockfd, struct arp_msg *msg) {
	int i;
	struct arp_cache_entry cache_entry;

	bzero(&cache_entry, sizeof(cache_entry));

	cache_entry.connfd = sockfd;
	cache_entry.sll_ifindex = my_index;
	cache_entry.sll_hatype = msg->hrd;
	strcpy(cache_entry.ip, msg->sender_ip);
	for (i = 0; i < IF_HADDR; i++){
				cache_entry.mac[i] = msg->sender_mac[i];
	}

	cache_entry.isComplete = 1;
	cache_entry.isValid = 1;
	cache_entry.isLocal = 0;

	// Pertains to the request, insert new entry
	if (strcmp(my_ip, msg->target_ip) == 0 || isDest(msg->target_ip) ) {
		puts("----->ARP: DESTINATION.");
		if ((i = search_cache(msg->sender_ip) == -1)) {
			puts("----->ARP: I DO pertain to this request. Create new entry for this <senderIP, senderMAC>.\n");
			if (insert_entry(cache_entry) < 0) {
				perror("unable to insert cache entry.");
			}
		} else {
			puts("----->ARP: I DO pertain to this request. Update <senderIP, senderMAC>.\n");
			update_cache(i, msg);
		}
		// Send ARP reply
		msg->op = ARP_REP;
		for (i = 0; i < INET_ADDRSTRLEN; i ++) {
			msg->target_ip[i] = msg->sender_ip[i];
		}
		printf("Target ip:%s\n", msg->target_ip);
		for (i = 0; i < IF_HADDR; i++){
					msg->target_mac[i] = msg->sender_mac[i];
		}
		strcpy(msg->sender_ip, my_ip);
		for (i = 0; i < IF_HADDR; i++){
					msg->sender_mac[i] = if_hwaddr[my_index][i];
		}
		puts("----->ARP: I'm responsible for sending reply...");
		send_arp_msg(sockfd, msg->target_mac, msg);
		puts("----->ARP: Reply sent.\n");

	} else if ((i = search_cache(msg->sender_ip) != -1)) { // There is an existing entry, update
		puts("----->ARP: I'm not pertain to this request, but I have an existing entry, updating...\n");
		update_cache(i, msg);
	}
}
void
process_arp_reply(int sockfd, struct arp_msg *msg) {
	int i, j;
	struct hwaddr *hwaddr_info = malloc(sizeof(struct hwaddr));

	bzero(hwaddr_info, sizeof(struct hwaddr));

	puts("----->ARP: Processing ARP reply...");
	if ((i = search_cache(msg->sender_ip)) == -1) {
		printf("----->ARP: No valid entry for: %s.\n", msg->sender_ip);
	}
	else {
		printf("----->ARP: Complete entry %d.\n", i);
		if (cache[i].isValid == 1) {
			cache[i].connfd = un_connfd;
			for (j = 0; j < IF_HADDR; j++){
				cache[i].mac[j] = msg->sender_mac[j];
				hwaddr_info->sll_addr[j] = cache[i].mac[j];
			}
			hwaddr_info->sll_halen = HARD_SIZE;
			hwaddr_info->sll_hatype = cache[i].sll_hatype;
			hwaddr_info->sll_ifindex = cache[i].sll_ifindex;
			strcpy(hwaddr_info->sll_ip, cache[i].ip);
			if (cache[i].isComplete == 0) {
				cache[i].isComplete = 1;
				puts("----->ARP: Sending back hwadr...");
				send_un(cache[i].connfd, hwaddr_info);
				close(cache[i].connfd);
				un_connfd = -1;
				puts("----->ARP: Reply proceeded, close connection.\n");
			}
		}
	}
}

void
process_un(int sockfd, struct hwaddr *hwaddr_info) {
	int index;
	int i;
	// puts("----->ARP:processing domain sockets...");
	if ((index = search_cache(hwaddr_info->sll_ip)) == -1) {
		puts("----->ARP: domain sockets: no cache entry found...");
		struct arp_cache_entry cache_entry;
		struct arp_msg msg;
		bzero(&msg, sizeof(msg));
		puts("----->ARP: domain sockets: create a new incomplete entry...");
		// Insert a temp entry
		cache_entry.connfd = sockfd;
		cache_entry.sll_ifindex = my_index;
		cache_entry.sll_hatype = hwaddr_info->sll_hatype;
		strcpy(cache_entry.ip, hwaddr_info->sll_ip);
		cache_entry.isComplete = 0;
		cache_entry.isValid = 1;
		cache_entry.isLocal = 0;

		if (insert_entry(cache_entry) < 0) {
			perror("unable to insert cache entry.");
		}

		puts("----->ARP: domain sockets: broadcast ARP_REQ...");
		// Send ARP request
		msg.op = ARP_REQ;
		strcpy(msg.sender_ip, my_ip);
		strcpy(msg.target_ip, hwaddr_info->sll_ip);
		msg.id = htons(ARP_ID);
		send_arp_msg(if_sockfd, broadcast_mac, &msg);
	} else {
		puts("----->ARP: domain sockets: existing entry found...");
		if (cache[index].isComplete == 1){
			cache[index].connfd = sockfd;
			for (i = 0; i < ETH_ALEN; i++){
				hwaddr_info->sll_addr[i] = cache[index].mac[i];
			}
	//		strcpy(hwaddr_info->sll_addr, cache[index].mac);
			hwaddr_info->sll_ifindex = cache[index].sll_ifindex;
			puts("----->ARP: domain sockets: sending reply through domain socket...");
			send_un(cache[index].connfd, hwaddr_info);
			close(cache[index].connfd);
			un_connfd = -1;
			puts("----->ARP: domain sockets: sending OK, connection closed.");
		}
	}
	puts("----->ARP:domain sockets processed...");
}
