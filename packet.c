
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h> /* IPPROTO_RAW def. */
#include <netinet/ip.h>
#else
#include "gettimeofday.h"
#define IPDEFTTL	64
#endif



#include "common.h"
#include "list.h"
#include "client.h"
#include "message.h"
#include "socket.h"
#include "destination.h"
#include "packet.h"

int create_listen_socket()
{
	int listen_sock;

	listen_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (listen_sock < 0)
	{
		printf("Couldn't create privileged icmp socket: %s\n", strerror(errno));
		return 0;
	}

#ifdef WIN32
	unsigned long flags = 1;
	if (ioctlsocket(listen_sock, FIONBIO, &flags) != SOCKET_ERROR)
#else
	if (fcntl(listen_sock, F_SETFL, O_NONBLOCK) == -1)
#endif
	{
		printf("F_SETFL: %s", strerror(errno));
		return 0;
	}

	return listen_sock;
}

int create_icmp_socket()
{
	int icmp_sock;

	icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (icmp_sock < 0)
	{
			printf("Couldn't create privileged raw socket: %s\n", strerror(errno));
			return 0;
	}

	/* set SO_BROADCAST option */
	socket_broadcast(icmp_sock);
	/* set SO_IPHDRINCL option */
	socket_iphdrincl(icmp_sock);

	return icmp_sock;
}

/* Send an ICMP time exceeded packet */
int send_icmp( int icmp_sock, struct sockaddr_in *rsrc,  struct sockaddr_in *dest_addr, struct sockaddr_in *src_addr, int server)
{
	int pkt_len = IPHDR_SIZE + ICMPHDR_SIZE, err = 0;
	struct ip_packet_t* ip_pkt;
	struct ip_packet_t* ip_pkt2;
	struct icmp_packet_t* pkt;
	struct icmp_packet_t* pkt2;
	char *packet;

	if (!server)
		pkt_len *= 2;

	packet = malloc(pkt_len);
	memset(packet, 0, pkt_len);

	ip_pkt = (struct ip_packet_t*)packet;
	ip_pkt->vers_ihl = 0x45;//|(pkt_len>>2);//5;//(IPVERSION << 4) | (IPHDR_SIZE >> 2);
	ip_pkt->tos = 0;
	ip_pkt->pkt_len = pkt_len;
	ip_pkt->id = 1; //kernel sets proper value htons(ip_id_counter);
	ip_pkt->flags_frag_offset = 0;
	ip_pkt->ttl = IPDEFTTL; // default time to live (64)
	ip_pkt->proto = 1; // ICMP
	ip_pkt->checksum = 0; // maybe the kernel helps us out..?
	ip_pkt->src_ip = rsrc->sin_addr.s_addr; // insert source IP address here
	ip_pkt->dst_ip = dest_addr->sin_addr.s_addr;

	pkt = malloc(ICMPHDR_SIZE);
	memset(pkt, 0, ICMPHDR_SIZE);
	pkt->type = server ? 8 : 11; // ICMP echo request or time exceeded
	pkt->code = 0; // Must be zero 
	pkt->identifier = 0;
	pkt->seq = 0;
	pkt->checksum = 0;

	/* Generate "original" packet if client to append to time exceeded */
	if (!server)
	{
		ip_pkt2	= malloc(IPHDR_SIZE);
		memset(ip_pkt2, 0, IPHDR_SIZE);
		ip_pkt2->vers_ihl = 0x45;
		ip_pkt2->tos = 0;
		/* no idea why i need to shift the bits here, but not on ip_pkt->pkt_len... */
		ip_pkt2->pkt_len = (IPHDR_SIZE + ICMPHDR_SIZE) << 8;
		ip_pkt2->id = 1; //kernel sets proper value htons(ip_id_counter);
		ip_pkt2->flags_frag_offset = 0;
		ip_pkt2->ttl = 1; // real TTL would be 1 on a time exceeded packet
		ip_pkt2->proto = 1; // ICMP
		ip_pkt2->checksum = 0; // maybe the kernel helps us out..?
		ip_pkt2->src_ip = dest_addr->sin_addr.s_addr;//htonl(0x7f000001); // localhost..
		ip_pkt2->dst_ip = src_addr->sin_addr.s_addr;//htonl(0x7f000001); // localhost..
	   
		pkt2 = malloc(ICMPHDR_SIZE);
		memset(pkt2, 0, ICMPHDR_SIZE);
		pkt2->type = 8; // ICMP echo request
		pkt2->code = 0; // Must be zero 
		pkt2->identifier = 0;
		pkt2->seq = 0;
		pkt2->checksum = 0;

		pkt2->checksum = htons(calc_icmp_checksum((uint16_t*)pkt2, ICMPHDR_SIZE));
		ip_pkt2->checksum = htons(calc_icmp_checksum((uint16_t*)ip_pkt2, IPHDR_SIZE));
	}

	pkt->checksum = htons(calc_icmp_checksum((uint16_t*)pkt, ICMPHDR_SIZE));
	ip_pkt->checksum = htons(calc_icmp_checksum((uint16_t*)ip_pkt, IPHDR_SIZE));

	memcpy(packet+IPHDR_SIZE, pkt, ICMPHDR_SIZE);
	if (!server)
	{
		memcpy(packet+IPHDR_SIZE+ICMPHDR_SIZE, ip_pkt2, IPHDR_SIZE);
		memcpy(packet+IPHDR_SIZE+ICMPHDR_SIZE+IPHDR_SIZE, pkt2, ICMPHDR_SIZE);
	}

	err = sendto(icmp_sock, packet, pkt_len, 0, (struct sockaddr*)dest_addr, sizeof(struct sockaddr));
	free(packet);
	//err = sendto(icmp_sock, (const void*)ip_pkt, pkt_len, 0, (struct sockaddr*)dest_addr, sizeof(struct sockaddr));
	if (err < 0) {
		printf("Failed to send ICMP packet: %s\n", strerror(errno));
		return -1;
	}
	else if (err != pkt_len)
		printf("WARNING WARNING, didn't send entire packet\n");

	return 0;
}


uint16_t calc_icmp_checksum(uint16_t *data, int bytes)
{
	uint32_t sum;
	int i;

	sum = 0;
	for (i=0;i<bytes/2;i++) {
		sum += data[i];
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = htons(0xFFFF - sum);
	return sum;
}

void socket_broadcast(int sd)
{
	const int one = 1;

	if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST,
		(char *)&one, sizeof(one)) == -1)
	{
		printf("[socket_broadcast] can't set SO_BROADCAST option\n");
		/* non fatal error */
	}
}

void socket_iphdrincl(int sd)
{
	const int one = 1;

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL,
		(char *)&one, sizeof(one)) == -1)
	{
		printf("[socket_iphdrincl] can't set IP_HDRINCL option\n");
		/* non fatal error */
	}
}

