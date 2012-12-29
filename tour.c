#include "unp.h"
#include "tour.h"
#include "arp.h"
#include "hw_addrs.h"

int my_vm;
int my_if_index;
unsigned char my_if_hwaddr[ETH_ALEN];
unsigned char my_name[INET_ADDRSTRLEN];
unsigned char my_ip[INET_ADDRSTRLEN];
struct in_addr my_addr;
pid_t child_ping = -1;

// raw sockets for routing and ping
int rt_sock;
int pg_sock;

// pf packet
int pf_sock;

// udp sockets for multicasting
socklen_t mc_addr_len;
int sock_mc_send = -1;
int sock_mc_recv = -1;
struct sockaddr *sasend = NULL;
struct sockaddr *sarecv = NULL;

// nodes information
unsigned char node_name[NUM_VM][INET_ADDRSTRLEN];
unsigned char node_ip[NUM_VM][INET_ADDRSTRLEN];
struct in_addr node_addr[NUM_VM];

// unix domain socket
int un_sock;
struct sockaddr_un un_addr;

int
main(int argc, char **argv)
{
	// printf("%d\n", sizeof(struct pf_ip_icmp));
	nodes_ip_init();
	rawsock_init();
	signal(SIGALRM, sig_alrm);

	if (argc > 1){
		if (argc > ROUTE_LEN){
			printf("Too many arguments\n");
			exit(1);
		}
		generate_tour(argc, argv);
		mc_init();
	}
	process();
	puts("DONE");
	return 0;
}

// get the server ips
void
nodes_ip_init()
{
	int i;
	struct hostent *hptr;
	char **pptr;
	struct hwa_info *hwa, *hwahead;
	struct sockaddr *sa;

	for (i = 0; i < NUM_VM; i++){
		sprintf(node_ip[i], "vm%d", i+1);
		sprintf(node_name[i], "vm%d", i+1);
		hptr = gethostbyname(node_ip[i]);
		printf("%s: ", node_ip[i]);
		for (pptr = hptr->h_addr_list; *pptr != NULL; pptr++){
			printf("%s\n", Inet_ntop(hptr->h_addrtype, *pptr, node_ip[i], INET_ADDRSTRLEN));
			node_addr[i].s_addr = inet_addr(node_ip[i]);
			break;
		}
	}

	bzero(my_ip, sizeof(my_ip));
	for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next){
		if (strcmp(hwa->if_name, "eth0") == 0){
			my_if_index = hwa->if_index;
			for (i = 0; i < ETH_ALEN; i++){
				my_if_hwaddr[i] = hwa->if_haddr[i];
			}
			if ((sa = hwa->ip_addr) != NULL){
				sprintf(my_ip, "%s", Sock_ntop_host(sa, sizeof(*sa)));
			}
			break;
		}
	}
	free_hwa_info(hwahead);

	for (my_vm = 0; my_vm < NUM_VM; my_vm++){
		if (strcmp(my_ip, node_ip[my_vm]) == 0){
			my_addr.s_addr = inet_addr(my_ip);
			memcpy(my_name, node_name[my_vm], sizeof(my_name));
			my_vm++;
			break;
		}
	}
	printf("INFO: my_vm %d\n", my_vm);
	printf("INFO: my_name %s\n", my_name);
	printf("INFO: my_ip %s\n", my_ip);
	printf("INFO: my_if_index %d: ", my_if_index);
	for (i = 0; i < ETH_ALEN; i++){ printf("%02x ", my_if_hwaddr[i]); }
	puts("");
}

void
rawsock_init()
{
	const int on = 1;
	// create rt socket
	if ((rt_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TOUR)) < 0){
		perror("socket error");
		exit(1);
	}
	// header
	if (setsockopt(rt_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
		perror("setsockopt error");
		exit(1);
	}
}

void
generate_tour(int argc, char **argv)
{
	int i, j, r;
	struct datagram packet;
	struct sockaddr_in next;
	unsigned char buf[128];

	// pack ip datagram
	memset(&packet, 0, sizeof(packet));
	packet.key = my_addr;
	packet.len = argc - 1;
	packet.itr = 1;
	for (i = 1; i < argc; i++){
		printf("%s\n", argv[i]);
		if (strcmp(argv[i], my_name) == 0){
			printf("ERROR: the source node should not be part of the tour\n");
			exit(1);
		}
		for (j = 0; j < NUM_VM; j++){
			if (strcmp(argv[i], node_name[j]) == 0){
				break;
			}
		}
		if (j == NUM_VM){
			printf("ERROR: unknown node %s\n", argv[i]);
			exit(1);
		}
		packet.nodes[i-1].s_addr = inet_addr(node_ip[j]);
	}
	// add multicast
	strcpy(packet.mc_ip, MULTICAST_IP);
	packet.mc_port = atoi(MULTICAST_PORT);

	packet.header.ip_v = 4;
	packet.header.ip_hl = 5;
	packet.header.ip_len = (sizeof(struct datagram));
	packet.header.ip_id = htons(TOUR_IDENTIFICATION);
	packet.header.ip_ttl = 1;
	packet.header.ip_p = IPPROTO_TOUR;
	packet.header.ip_src = my_addr;
	packet.header.ip_dst = packet.nodes[0];
	printf("INFO: pack the ip datagram -- len %d\n", sizeof(struct datagram));
	printf("INFO: %s %d\n", packet.mc_ip, packet.mc_port);

	// send datagram

	bzero(&next, sizeof(next));
	next.sin_family = AF_INET;
	next.sin_addr = packet.nodes[0];

	// debug
	// memset(buf, 0x1, sizeof(buf));
	// sendto(rt_sock, buf, sizeof(buf), 0, (SA *)&next, sizeof(next));
	
	if ((r = sendto(rt_sock, &packet, sizeof(packet), 0, (SA *)&next, sizeof(next))) < 0){
		perror("sendto error");
	}
	puts("sendto done");
}

void
process()
{
	int maxfd = 0, i, j, nready, r;
	time_t rawtime;
	struct tm *timeinfo;
	fd_set rset;

	while (1){
		maxfd = 0;
		FD_ZERO(&rset);
		FD_SET(rt_sock, &rset);
		maxfd = max(rt_sock, maxfd);
		maxfd++;
		// puts("selecting");

		nready = select(maxfd, &rset, NULL, NULL, NULL);

		if (FD_ISSET(rt_sock, &rset)){
			struct datagram packet;
			r = recvfrom(rt_sock, &packet, sizeof(packet), 0, NULL, NULL);
			if (r < 0){
				continue;
			}
			printf("INFO: rt_socket receives %d bytpes\n", r);
			time(&rawtime);
			timeinfo = localtime(&rawtime);
			for (i = 0; i < NUM_VM; i++){
				if (packet.nodes[packet.itr - 1].s_addr == node_addr[i].s_addr)
					break;
			}
			printf("%s received source routing packet from vm%d\n", asctime(timeinfo), i + 1);
			// printf("len %d itr %d\n", packet.len, packet.itr);
			process_tour(&packet);
		}
	}
}

void
process_tour(struct datagram *dg)
{
	// join the multicast address
	int i, r;
	struct datagram packet;
	struct sockaddr_in next;
	char buf[256];
	if (sock_mc_recv == -1 && sock_mc_send == -1){
		printf("INFO: vm%d first joins the multicast group\n", my_vm);
		if ((r = fork()) == 0){
			ping(dg->key, my_addr);
			exit(0);
		} else {
			child_ping = r;
			printf("Fork child ping with pid %d\n", child_ping);
		}
		mc_join(dg->mc_ip, dg->mc_port);
	}
	if (dg->itr == dg->len){
		// tell all other nodes
		sleep(5);
		sprintf(buf, "<<<<< This is node vm%d. Tour has ended on vm%d. Groupmembers please identify yourselves. >>>>>", my_vm, my_vm);
		printf("%s\n", buf);
		mc_send(sock_mc_send, sasend, mc_addr_len, buf, strlen(buf));
		printf("KILL PING with pid %d\n", child_ping);
		if (child_ping != -1){
			printf("KILL PING with pid %d\n", child_ping);
			kill(child_ping, SIGKILL);
		}
		return ;
	}

	bzero(&packet, sizeof(packet));
	packet.key = dg->key;
	packet.len = dg->len;
	packet.itr = dg->itr + 1;
	for (i = 0; i < ROUTE_LEN; i++){
		packet.nodes[i] = dg->nodes[i];
	}
	strcpy(packet.mc_ip, dg->mc_ip);
	packet.mc_port = dg->mc_port;

	packet.header.ip_v = 4;
	packet.header.ip_hl = 5;
	packet.header.ip_len = (sizeof(struct datagram));
	packet.header.ip_id = htons(TOUR_IDENTIFICATION);
	packet.header.ip_ttl = 1;
	packet.header.ip_p = IPPROTO_TOUR;
	packet.header.ip_src = my_addr;
	packet.header.ip_dst = packet.nodes[packet.itr-1];
	
	bzero(&next, sizeof(next));
	next.sin_family = AF_INET;
	next.sin_addr = packet.nodes[packet.itr-1];

	if ((r = sendto(rt_sock, &packet, sizeof(packet), 0, (SA *)&next, sizeof(next))) < 0){
		perror("sendto error");
	}
	puts("forward tour");
}


void
mc_init()
{
	const int on = 1;
	socklen_t salen;
	sock_mc_send = Udp_client(MULTICAST_IP, MULTICAST_PORT, (void **)&sasend, &salen);
	sock_mc_recv = socket(sasend->sa_family, SOCK_DGRAM, 0);

	Setsockopt(sock_mc_recv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	sarecv = malloc(salen);
	mc_addr_len = salen;
	memcpy(sarecv, sasend, salen);
	Bind(sock_mc_recv, sarecv, salen);

	Mcast_join(sock_mc_recv, sasend, salen, NULL, 0);
	Mcast_set_loop(sock_mc_send, 0);
	
	if (fork() == 0){
		// mc_recv(int recvfd, socklen_t salen)
		mc_recv(sock_mc_recv, salen);
	}
	puts("mc_init done");
}

void
mc_join(char *mc_ip, int mc_port)
{
	const int on = 1;
	char buff[128];
	socklen_t salen;

	memset(buff, 0, sizeof(buff));
	sprintf(buff, "%d", mc_port);
	sock_mc_send = Udp_client(mc_ip, buff, (void **)&sasend, &salen);
	// puts("In mc_join");

	sock_mc_recv = socket(sasend->sa_family, SOCK_DGRAM, 0);

	Setsockopt(sock_mc_recv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	sarecv = malloc(salen);
	mc_addr_len = salen;
	memcpy(sarecv, sasend, salen);
	Bind(sock_mc_recv, sarecv, salen);

	Mcast_join(sock_mc_recv, sasend, salen, NULL, 0);
	Mcast_set_loop(sock_mc_send, 0);

	if (fork() == 0){
		// mc_recv(int recvfd, socklen_t salen)
		mc_recv(sock_mc_recv, salen);
	}
	// send a message to the group
	// sprintf(buff, "vm%d joins the multicast group", my_vm);
	sprintf(buff, "<<<<< Node vm%d . I am a member of the group. >>>>>", my_vm);
	printf("Node vm%d . sending: %s\n", my_vm, buff);
	mc_send(sock_mc_send, sasend, mc_addr_len, buff, strlen(buff));
	// printf("vm%d joins multicast group", my_vm);
}

void
mc_send(int sendfd, struct sockaddr *sadest, socklen_t salen, const char *buf, size_t len)
{
	int i;
	// printf("mc_send: %s\n", buf);
	// sendto(sendfd, buf, len, 0, sadest, salen);
	sendto(sendfd, buf, len, 0, sadest, salen);
}

void
mc_recv(int recvfd, socklen_t salen)
{
	char buf[256];
	char tmp[128];
	int r;
	socklen_t len;
	struct sockaddr *safrom;
	safrom = malloc(salen);

	while (1){
		r = recvfrom(recvfd, buf, 128, 0, safrom, &len);
		buf[r] = 0;
		printf("Node vm%d. received %d bytes: %s\n", my_vm, r, buf);
		if (r > 80){
			sprintf(tmp, "<<<<< Node vm%d. I am a member of the group >>>>>", my_vm);
			printf("Node vm%d . sending: %s\n", my_vm, tmp);
			mc_send(sock_mc_send, sasend, mc_addr_len, tmp, strlen(tmp));
			// printf("Kill PING with pid %d\n", child_ping);
			if (child_ping != -1){
				printf("Kill PING with pid %d\n", child_ping);
				kill(child_ping, SIGKILL);
				child_ping = -1;
			}
		}
	}
	free(safrom);
}

