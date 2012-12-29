#include "tour.h"
#include "arp.h"
pid_t pid;
struct in_addr start;

//////////////////////////////////////////////////////////////////////////
// areq
void
un_init()
{
	un_sock = Socket(AF_LOCAL, SOCK_STREAM, 0);

	bzero(&un_addr, sizeof(struct sockaddr_un));
	//unlink(ARP_PATH);
	un_addr.sun_family = AF_LOCAL;
	strcpy(un_addr.sun_path, ARP_PATH);
	//Bind(un_sock, (SA *)&un_addr, sizeof(struct sockaddr_un));
	// puts("un_init done\n");
}

void
un_clear()
{
	close(un_sock);
}

int
areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr)
{
	int r;
	un_init();
	// printf("SUN_PATH is: %s\n", un_addr.sun_path);
	Connect(un_sock, (SA *)&un_addr, sizeof(un_addr));

	strcpy(HWaddr->sll_ip, Sock_ntop_host(IPaddr, sizeof(IPaddr)));
	HWaddr->sll_halen = HARD_SIZE;
	HWaddr->sll_hatype = HARD_TYPE;

	// Bug here: sizeof(struct hwaddr)
	r = write(un_sock, HWaddr, sizeof(struct hwaddr));
	if (r < 0){
		perror("write error");
	}

	///////////////Time out////////////////
	// Bug here: sizeof(struct hwaddr)
	// alarm(2);
	r = read(un_sock, HWaddr, sizeof(struct hwaddr));
	// alarm(0);
	///////////////////////////////////////
	un_clear(un_sock);
	return 0;
}


//////////////////////////////////////////////////////////////////////////
// ping: ping.c
uint16_t
in_cksum(uint16_t *addr, int len)
{
	int				nleft = len;
	uint32_t		sum = 0;
	uint16_t		*w = addr;
	uint16_t		answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	/* 4mop up an odd byte, if necessary */
	if (nleft == 1){
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

	/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

void
tv_sub(struct timeval *out, struct timeval *in)
{
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

void
ping_init()
{		
	int i, off = 0;
	struct sockaddr_ll pf_addr;

	pg_sock = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	// setsockopt(pg_sock, IPPROTO_IP, IP_HDRINCL, &off, sizeof(off));

	pf_sock = Socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

	bzero(&pf_addr, sizeof(pf_addr));
	pf_addr.sll_family = PF_PACKET;
	pf_addr.sll_protocol = htons(ETH_P_ALL);
	// pf_addr.sll_ifindex = my_if_index;
	// pf_addr.sll_ifindex = 2;
	pf_addr.sll_ifindex = my_if_index;
	pf_addr.sll_hatype = ARPHRD_ETHER;
	pf_addr.sll_pkttype = PACKET_HOST;
	pf_addr.sll_halen = ETH_ALEN;
	for (i = 0; i < ETH_ALEN; i++){
		pf_addr.sll_addr[i] = my_if_hwaddr[i];
	}
	Bind(pf_sock, (SA *)&pf_addr, sizeof(pf_addr));
}

void
ping(struct in_addr src, struct in_addr me)
{
	int i, j, r, seq = 0;
	char recvbuf[256];
	ssize_t n;
	struct timeval tval;

	pid = getpid() & 0xffff;
	start = me;

	ping_init();
	// for (i = 0; i < ETH_ALEN; i++){ printf("%02x ", my_if_hwaddr[i]); }
	for (i = 0; i < NUM_VM; i++){
		if (src.s_addr == node_addr[i].s_addr)
			break;
	}
	printf("PING vm%d (%s): %d bytes\n", i + 1, inet_ntoa(src), 64);
	while (1){
		// send
		// r = ping_send(src, seq);
		if ((r = ping_send(src, seq)) >= 0){
			alarm(1);
			r = recvfrom(pg_sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
			if (r >= 0){
				// printf("INFO: ping on vm%d receive %d bytes\n", my_vm, r);
				// Gettimeofday(&tval, NULL);
				ping_recv(recvbuf, r, &tval, i+1);
			} else {
				printf("ERROR: icmp timeout\n");
			}
			alarm(0);
		}
		seq++;
		// recv
		sleep(1);
	}
}

int
ping_send(struct in_addr src, uint16_t seq)
{
	int r, i;
	struct sockaddr_in IPaddr;
	struct hwaddr HWaddr;
	struct sockaddr_ll sa;
	struct pf_ip_icmp pa;

	bzero(&IPaddr, sizeof(IPaddr));
	IPaddr.sin_family = AF_INET;
	IPaddr.sin_addr = src;

	////////////////////////////////////////////////////////////////////////////////////
	// AREQ
	if ((r = areq((SA *)&IPaddr, sizeof(IPaddr), &HWaddr)) < 0){
		return r;
	}
	alarm(0);
	printf("Get areq\n");

	// TEST, calculate header checksum
	/*struct icmp tmp;
	bzero(&tmp, sizeof(tmp));
	tmp.icmp_type = ICMP_ECHO;
	tmp.icmp_code = 0;
	tmp.icmp_id = pid;
	tmp.icmp_seq = seq;
	// memset(tmp.icmp_data, 0xa5, sizeof(struct icmp) - 8);
	tmp.icmp_cksum = in_cksum((u_short *)&tmp, sizeof(struct icmp));

	sendto(pg_sock, &tmp, sizeof(tmp), 0, (SA *)&IPaddr, sizeof(IPaddr));
	printf("ping_send done %d bytes %d\n", sizeof(struct icmp), seq);
	return 0;*/

	////////////////////////////////////////////////////////////////////////////////////
	// TEST PING VM3
	
	/*HWaddr.sll_ifindex = 2;
	HWaddr.sll_hatype = ARPHRD_ETHER;
	HWaddr.sll_halen = ETH_ALEN;
	HWaddr.sll_addr[0] = 0x00;
	HWaddr.sll_addr[1] = 0x50;
	HWaddr.sll_addr[2] = 0x56;
	HWaddr.sll_addr[3] = 0x00;
	HWaddr.sll_addr[4] = 0x80;
	HWaddr.sll_addr[5] = 0x06;*/
	// TEST PING VM1


	bzero(&sa, sizeof(sa));
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETH_P_IP);
	sa.sll_ifindex = my_if_index;
	sa.sll_hatype = ARPHRD_ETHER;
	sa.sll_pkttype = PACKET_OTHERHOST;
	sa.sll_halen = ETH_ALEN;
	for (i = 0; i < ETH_ALEN; i++){
		sa.sll_addr[i] = HWaddr.sll_addr[i];
	}

	bzero(&pa, sizeof(pa));
	//////////////////////////////////////////////////////
	// pack ether frame header
	// memcpy(eh, HWaddr.sll_addr, ETH_ALEN);
	// memcpy(eh + ETH_ALEN, my_if_hwaddr, ETH_ALEN);
	// pa.type = htons(ETH_P_IP);
	struct ethhdr *eh = (struct ethhdr *)&pa;
	for (i = 0; i < ETH_ALEN; i++){
		pa.dst_mac[i] = HWaddr.sll_addr[i];
	}
	for (i = 0; i < ETH_ALEN; i++){
		pa.src_mac[i] = my_if_hwaddr[i];
	}
	eh->h_proto = htons(ETH_P_IP);

	//////////////////////////////////////////////////////
	// pack ip datagram header
	struct ip *hdr = (struct ip *)pa.buf;
	hdr->ip_v = 4;
	hdr->ip_hl = 5;
	hdr->ip_tos = 0;
	hdr->ip_len = htons(84);

	hdr->ip_id = htons(0);
	hdr->ip_off = htons(16384);
	hdr->ip_ttl = 64;
	hdr->ip_p = IPPROTO_ICMP;
	hdr->ip_src = start;
	hdr->ip_dst = src;
	hdr->ip_sum = 0;
	hdr->ip_sum = in_cksum((u_short *)hdr, 20);

	/*// ip header
	pa.header.ip_v = 4;
	pa.header.ip_hl = 5;
	// pa.header.ip_len = htons(sizeof(struct pf_ip_icmp) - 14);
	pa.header.ip_len = (sizeof(struct pf_ip_icmp) - 14);
	pa.header.ip_id = 0x2881;
	pa.header.ip_ttl = 1;
	pa.header.ip_p = IPPROTO_ICMP;
	pa.header.ip_src = my_addr;
	pa.header.ip_dst = src;*/

	//////////////////////////////////////////////////////
	// pack icmp data
	struct icmp *ptr = (struct icmp *)(pa.buf + 20);
	ptr->icmp_type = ICMP_ECHO;
	ptr->icmp_code = 0;
	ptr->icmp_id = pid;
	ptr->icmp_seq = seq;
	memset(ptr->icmp_data, 0xa5, 56);
	Gettimeofday((struct timeval *)ptr->icmp_data, NULL);
	ptr->icmp_cksum = 0;
	ptr->icmp_cksum = in_cksum((u_short *)ptr, 64);

	int len = 64;
	// printf("INFO: ping_send done %d len %d\n", seq, len);
	r = sendto(pf_sock, &pa, sizeof(pa), 0, (SA *)&sa, sizeof(sa));
	if (r < 0){
		perror("ERROR: ping_send sendto error");
	}
	return 0;
}

void
ping_recv(char *ptr, ssize_t len, struct timeval *tvrecv, int vmid)
{
	int hlen1, icmplen;
	double rtt;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;

	ip = (struct ip *)ptr;
	hlen1 = ip->ip_hl << 2;
	if (ip->ip_p != IPPROTO_ICMP){
		return;
	}
	icmp = (struct icmp *)(ptr + hlen1);
	icmplen = len - hlen1;
	if (icmp->icmp_type == ICMP_ECHOREPLY) {
		if (icmp->icmp_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			return;			/* not enough data to use */

		tvsend = (struct timeval *) icmp->icmp_data;
		Gettimeofday(tvrecv, NULL);
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		printf("%d bytes from vm%d: seq=%u, ttl=%d, rtt=%.3f ms\n",
				icmplen, vmid, icmp->icmp_seq, ip->ip_ttl, rtt);
	}
}
