
#ifndef PACKET_T_H 
#define PACKET_T_H 

//	Includes
#ifndef WIN32
  	#include	<sys/unistd.h>
  	#include	<sys/types.h>
  	#include	<sys/socket.h>
  	#include	<netinet/in.h>
	#include 	<limits.h>
  	#include	<arpa/inet.h>
  	#include	<netdb.h>
	#include	<pthread.h>
	#include	<errno.h>
	//#include	<net/ethernet.h>
	#include	<syslog.h>
	#include	<pwd.h>
	#include	<grp.h>
#endif /* !WIN32 */
	#include	<stdarg.h>
	#include	<unistd.h>
  	#include	<stdio.h>
  	#include	<stdlib.h>
  	#include	<string.h>
  	#include	<time.h>
  	#include	<sys/time.h>
  	#include	<signal.h>
  	#include	<stdint.h>

#ifdef WIN32
	#include    <winsock2.h>
	typedef int socklen_t;
	typedef uint32_t in_addr_t;
	#define ETH_ALEN        6               /* Octets in one ethernet addr   */
	struct ether_header
	{
		u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
		u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
		u_int16_t ether_type;                 /* packet type ID field */
	};
#endif /* WIN32 */

//	Constants
#define	false		0
#define	true		1
#define	bool		char

/* packet size (physical header size + ip header + tcp header + 0 data bytes) */
#ifndef IP_MAX_SIZE
#define IP_MAX_SIZE 65535
#endif

#ifndef IPHDR_SIZE
#define IPHDR_SIZE  sizeof(struct ip_packet_t)
#endif
#ifndef ICMPHDR_SIZE
#define ICMPHDR_SIZE  sizeof(struct icmp_packet_t)
#endif


/*	ip_packet_t: This is basically my own definition of the IP packet, which
	of course complies with the official definition ;) See any good book on IP
	(or even the RFC) for info on the contents of this packet.
*/
struct ip_packet_t {
	uint8_t			vers_ihl,
					tos;
	uint16_t		pkt_len,
					id,
					flags_frag_offset;
	uint8_t			ttl,
					proto;	// 1 for ICMP
	uint16_t		checksum;
	uint32_t		src_ip,
					dst_ip;
};


/*	icmp_packet_t: This is the definition of a standard ICMP header. */
struct icmp_packet_t {
	uint8_t			type,
					code;
	uint16_t		checksum,
					identifier,
					seq;
};



//	Prototypes 

int send_icmp(int icmp_sock, struct sockaddr_in *rsrc, struct sockaddr_in *dest_addr, struct sockaddr_in *src_addr, int server);
uint16_t calc_icmp_checksum(uint16_t *data, int bytes);
int create_icmp_socket();
int create_listen_socket();
void socket_broadcast(int sd);
void socket_iphdrincl(int sd);


#endif
