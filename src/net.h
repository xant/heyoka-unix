/* 
 * This file is part of heyoka, and you should have received it
 * with the rest of the heyoka tarball. For the latest release,
 * check http://heyoka.sourceforge.net
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA
 */

#ifndef _NET_H
#define _NET_H

#include "types.h"
#include "tunnel.h"
#ifndef __WIN32__
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define NET_ERROR	-1
#define NET_TIMEOUT	 0
#define NET_SUCCESS	 1

#define NET_MAX_PACKET_SIZE		1024

#pragma pack (1)
typedef struct _net_ip_header_t {
	uint8 hdr_len:4;		// header length
	uint8 version:4;		// version
	uint8 tos;				// type of service
	uint16 tot_len;			// total length
	uint16 id;				// identification
	uint16 flags_offset;	// fragment offset field
	uint8 ttl;				// time to live
	uint8 proto;			// protocol
	uint16 cksum;			// checksum
	ip_addr src_ip;			// source ip address
	ip_addr dst_ip;			// destination ip address
} net_ip_header_t;
#pragma pack ()

#pragma pack (1)
typedef struct _net_udp_header_t {
	uint16 src_port;
	uint16 dst_port;
	uint16 length;
	uint16 cksum;
} net_udp_header_t;
#pragma pack ()

#pragma pack (1)
typedef struct _net_dns_header_t {
	uint16 id;

	uint8 rd:1;
	uint8 tc:1;
	uint8 aa:1;
	uint8 opcode:4;
	uint8 qr:1;

	uint8 rcode:4;
	uint8 cd:1;
	uint8 ad:1;
	uint8 z:1;
	uint8 ra:1;
	
	uint16 question_num;
	uint16 answer_num;
	uint16 authority_num;
	uint16 additional_num;
} net_dns_header_t;
#pragma pack ()

#pragma pack (1)
typedef struct _net_packet_t {
	net_ip_header_t *ip;
	net_udp_header_t	*udp;
	net_dns_header_t *dns;
	struct net_dns_rr_question_t *rr_q;
	struct net_dns_rr_answer_t *rr_a;
} net_packet_t;
#pragma pack ()


#define NET_MAX_QNAME			255// 255
#define NET_MAX_SUB_QNAME		63
#define NET_MAX_TXT				254	// not 255 because we need one byte as length field
#define NET_MAX_ANSWER_RR_DATA	NET_MAX_TXT	

#define NET_DNS_TYPE_TXT		htons(0x10)
#define NET_DNS_TYPE_NULL		htons(0x0a)
#define NET_DNS_CLASS_IN		htons(1)
#define NET_DNS_RCODE_NXDOMAIN	0x03
#define NET_DNS_RCODE_NOERROR	0x0000

#define NET_DEFAULT_DNS_PORT	53
#define NET_DEFAULT_PACKET_RECV_TIMEOUT		5 // in seconds

#define length_of_rr_question(rr)	(rr->qname_length + 4 + 1) // +1 is for the trailing 0
#define length_of_rr_answer(rr)		(ntohs(rr->length) + 12)

#pragma pack (1)
struct net_dns_rr_question_t {
	unsigned int qname_length;
	char qname[NET_MAX_QNAME];
	uint16 type;
	uint16 class;
};
#pragma pack ()

#pragma pack (1)
struct net_dns_rr_answer_t {
	uint16 name;
	uint16 type;
	uint16 class;
	uint32 ttl;		/* time to live */
	uint16 length;	/* length of data */
	uint8 data[NET_MAX_ANSWER_RR_DATA]; //+1 for the length field
};
#pragma pack ()

#define NET_SOCKET_RAW	SOCK_RAW
#define NET_SOCKET_UDP	SOCK_DGRAM
#define NET_SOCKET_TCP	SOCK_STREAM

#define NET_ADDR_ANY		0x00
#define NET_PORT_NONE		0x00
#define NET_DO_LISTEN		0x01
#define NET_DO_NOT_LISTEN	0x00

net_packet_t			     *net_new_packet();
void						  net_destroy_packet(net_packet_t *);
net_ip_header_t 			 *net_craft_ip(const ip_addr src, const ip_addr dst);
net_udp_header_t			 *net_craft_udp(const uint16 src_port, const uint16 dst_port);
net_dns_header_t		 	 *net_craft_dns();
struct net_dns_rr_question_t *net_craft_dns_rr_question(const uint8 *data, const uint16 data_length, const char *domain);
struct net_dns_rr_answer_t	 *net_craft_dns_rr_answer(const uint8 *data, unsigned int data_length, const char *domain);
unsigned char 				  net_encode_flag(const tunnel_header_flag_t *flag);
tunnel_header_flag_t		 *net_decode_flag(const uint8 flag);

int		net_socket(int type, ip_addr listen_addr, uint16 listen_port, int do_listen);
int		net_send_packet(const int sock, const net_packet_t *packet, struct sockaddr_in *addr);
int		net_recv_packet(const int sock, net_packet_t *packet, const unsigned int timeout, struct sockaddr_in *client);
int		net_read(const int sock, unsigned char *buffer, const unsigned int buffer_length, const unsigned int timeout_sec, const unsigned int timeout_usec);
int		net_write(const int sock, unsigned char *buffer, unsigned int buffer_length);
int		net_connect(int s, const ip_addr addr, const uint16 port);
int		net_accept(const int sock);
ip_addr	net_get_local_ip();

unsigned int	net_dns_get_qname(struct net_dns_rr_question_t *rr, char *data, const char *domain);
unsigned int	net_dns_get_txt(struct net_dns_rr_answer_t *rr, char *data);
#define			net_dns_set_rcode(d, rc)	(d->rcode = rc)

#define net_set_ip_src(packet, _ip)		(packet->ip->src_ip = _ip)
#define net_set_ip_dst(packet, _ip)		(packet->ip->dst_ip = _ip)
#define net_set_udp_src(packet, _port)	(packet->udp->src_port = _port)
#define net_set_udp_dst(packet, _port)	(packet->udp->dst_port = _port)
#define net_ip_to_ascii(ip) inet_ntoa(*((struct in_addr *) &ip))

#endif
