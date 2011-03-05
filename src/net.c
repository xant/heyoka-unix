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

#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>
	
#include "net.h"
#include "tunnel.h"
#include "util.h"
 
/*
 * Allocate memory for a packet structure and NULL the 
 * allocated area.
 */
net_packet_t *
net_new_packet()
{
	net_packet_t *packet = 0;

	packet = (net_packet_t *) malloc_or_die(sizeof(net_packet_t));

	memset(packet, 0x00, sizeof(net_packet_t));

	return packet;
}

void
net_destroy_packet(net_packet_t *packet)
{
	if (packet) {
		if (packet->ip) {
			free(packet->ip);
		}
		if (packet->udp) {
			free(packet->udp);
		}
		if (packet->dns) {
			free(packet->dns);
		}
		if (packet->rr_q) {
			free(packet->rr_q);
		}
		if (packet->rr_a) {
			free(packet->rr_a);
		}
		free(packet);
	}
}

/*
 * Allocate memory for the IP header and fill it with 
 * data.
 */
net_ip_header_t *
net_craft_ip(const ip_addr src, const ip_addr dst)
{
	net_ip_header_t *ip = 0;

	ip = (net_ip_header_t *) malloc_or_die(sizeof(net_ip_header_t ));

	memset(ip, 0x00, sizeof(net_ip_header_t ));

	ip->version = 4;		 // IPv4
	ip->hdr_len = 5;		 // 5 four byte words
	ip->ttl = 255;			 // max time to live
	ip->src_ip = src;		 // source ip address
	ip->dst_ip = dst;		 // destination ip address
	ip->proto = IPPROTO_UDP; // udp packet is encapsulated
	//ip->flags_offset = 1 << 7;      // Evil bit (RFC 3514)
	

	// the ip checksum is calculated over the ip header and the wrapped 
	// protocol (the udp and dns headers). Therefore, the checksum will be 
	// calculated when the packet just before it is going to be sent. that 
	// also affects the total length field of the ip header.
	// ip->cksum
	// ip->tot_len

	return ip;
}

/*
 * Allocate memory for the UDP header and fill it with 
 * data.
 */
net_udp_header_t	*
net_craft_udp(const uint16 src_port, const uint16 dst_port)
{
	net_udp_header_t *udp = 0;

	udp = (net_udp_header_t *) malloc_or_die(sizeof(net_udp_header_t));

	memset(udp, 0x00, sizeof(net_udp_header_t));

	udp->dst_port = htons(dst_port);	// source port		
	udp->src_port = htons(src_port);	// destination port
	udp->cksum = 0;						// The checksum will be calculated from the OS

	// The udp length is calculated over the udp and the encapsulated dns 
	// header. This is going to be done just before the packet is sent.
	// udp->length

	return udp;
}

net_dns_header_t *			
net_craft_dns()
{
	net_dns_header_t *dns = 0;

	dns = (net_dns_header_t *) malloc_or_die(sizeof(net_dns_header_t));

	memset(dns, 0x00, sizeof(net_dns_header_t));

	dns->id = (uint16) rand();	// random identifier
	dns->rd = 1;			    // recursion desired
	dns->question_num = htons(1);
	// The response and authoritive answe flag will be set before the packet is sent.
	// If there's a answer RR, then the flag will be set to 1.
	// dns->qr
	// dns->aa

	// all other fields remain 0.

	return dns;
}

/*
 * Allocate Memory for the question RR and fill it with data.
 */
struct net_dns_rr_question_t *
net_craft_dns_rr_question(const uint8 *data, const uint16 data_length, const char *domain)
{
	struct net_dns_rr_question_t *rr = 0;
	uint8 *ptr = 0;
	unsigned int k = 0, i = 0, max_use = 0;
	unsigned int qlength = 0;
	unsigned int sub_dom_length = 0;

	if (!data || !data_length || !domain) {
		error("no domain or data name given for Question RR\n");
		return 0;
	}

	rr = (struct net_dns_rr_question_t *) malloc_or_die(sizeof(struct net_dns_rr_question_t));

	ptr = rr->qname;
	rr->type =  NET_DNS_TYPE_TXT;	// type of the question RR is TXT
	rr->class = NET_DNS_CLASS_IN;


	// -2 means: -1 for the subdomain length field of the actual domain name and -1 for the terminating 0
	// TODO: what is the third -1 needed for?!
	max_use = NET_MAX_QNAME - strlen(domain) - 2 - 1; 	

	// add data to the QNAME
	k = 0;	
	while (k < data_length && qlength < max_use) {
		// calculate length of sub domain (data_length - k) states how many bytes are left in the buffer
		if ((data_length - k) < NET_MAX_SUB_QNAME) {
			sub_dom_length = data_length - k;
		} else {
			sub_dom_length = NET_MAX_SUB_QNAME;
		}

		if (qlength + sub_dom_length >= max_use) {
			sub_dom_length = max_use - qlength;
		}

		// add the subdomain length field
		*ptr++ = sub_dom_length;
		qlength++;

		// add data to subdomain
		for (i = 0; i < sub_dom_length; i++, k++) {
			*ptr++ = *data++;
			qlength++;
		}
	}

	// in this loop ptr always points to where the length of the following subdomain is stored
	(*ptr) = 0;
	for (k = 0, i = 1; k < strlen(domain); k++) {
		if (domain[k] != '.') {
			// add character to data and increase the sub somain length counter byte by one ('ptr' points to it)
			(*ptr)++;
			ptr[i] = domain[k];
			i++;
		} else {
			// set pointer to new sub domain
			ptr += i;
			*ptr = 0;
			i = 1;
		}
	}
	ptr += i;
	*(uint16 *) ptr = 0;
	
	//TODO: verify the +2:
	qlength += strlen(domain) + 1;
	
	rr->qname_length = qlength;

	return rr;
}

/*
 * Allocate Memory for the answer RR and fill it with data.
 * The expected data must be base64 encoded and 
 */
struct net_dns_rr_answer_t *
net_craft_dns_rr_answer(const uint8 *data, unsigned int data_length, const char *domain)
{
	struct net_dns_rr_answer_t *rr;

	if (!data || data_length == 0 || !domain) {
		error("no domain or data name given for Question RR\n");
		return 0;
	}

	if (data_length > NET_MAX_ANSWER_RR_DATA) {
		error("more data for answer RR than allowed: %i\n", data_length);
		return 0;
	}

	rr = (struct net_dns_rr_answer_t *) malloc_or_die(sizeof(struct net_dns_rr_answer_t));

	rr->name = 0x0cc0;
	rr->type = NET_DNS_TYPE_TXT;
	rr->class = htons(1);
	rr->ttl = htonl(0);
	rr->length = htons(data_length + 1);	// +1 for the data_length field which is part of the actual data

	if (data_length > NET_MAX_ANSWER_RR_DATA) {
		data_length = NET_MAX_ANSWER_RR_DATA;
	}
	rr->data[0] = data_length;
	memcpy(rr->data + 1, data, data_length);

	return rr;
}

static uint16
ip_checksum(const uint16 *ptr, unsigned int nbytes)
{
    unsigned long sum = 0;
    unsigned short oddbyte = 0, rs = 0;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;

    }

    if(nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    rs = (unsigned short)(~sum);

    return rs;
}

/*
 * Create a TCP, UDP or RAW socket. Dependant on what parameters there are
 * a TCP, UDP or RAW socket will be created.
 * 
 * NET_SOCKET_RAW									= creates raw socket
 * NET_SOCKET_DGRAM									= UDP socket
 * NET_SOCKET_DGRAM + listen_addr + listen_port		= listening UDP socket
 * NET_SOCKET_STREAM								= TCP socket
 * NET_SOCKET_STREAM + listen_addr + listen_port	= listening TCP socket
 *
 */
int
net_socket(int type, ip_addr ip, uint16 port, int do_listen)
{
	struct sockaddr_in addr;
	int sockfd = -1;
	int flag = 1;
	
	sockfd = socket(AF_INET, type, 0);// ( (type == NET_SOCKET_TCP || type == NET_SOCKET_RAW) ? 0 : IPPROTO_UDP));
	if (sockfd == -1) {
		error("cannot create socket\n");
		return -1;
	}

	if (type == NET_SOCKET_RAW) {
		if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (char *) &flag, sizeof(flag)) == -1) {
			error("setsockopt failed\n");
			return -1;
		}
	} else {
		if (do_listen) {
			addr.sin_addr.s_addr = INADDR_ANY;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);

			if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
				error("bind failed\n");
				return -1;
			}
			listen(sockfd, 10);		

		}
	}

	return sockfd;
}


int
net_send_packet(const int sock, const net_packet_t *packet, struct sockaddr_in *addr)
{
	uint8 raw_packet[NET_MAX_PACKET_SIZE];
	uint8 *ptr = 0;
	unsigned int length = 0;
	uint16 *cksum = 0;

	// build the dns header
	if (!packet->dns || !packet->rr_q) {
		error("missing dns header or question RR in packet\n");
		return NET_ERROR;
	}

	length = sizeof(net_dns_header_t)
			+ length_of_rr_question(packet->rr_q);

	if (packet->rr_a) {
		packet->dns->qr = 1;	// it's a response packet
		packet->dns->ad = 1;	// authoritive answer
		packet->dns->answer_num = htons(1);
		length += length_of_rr_answer(packet->rr_a);
	}

	// build udp header
	if (packet->udp) {
		length += sizeof(net_udp_header_t);
		packet->udp->length = htons(length);

		// build ip header
		if (!packet->ip) {
			error("UDP header without IP header\n");
			return NET_ERROR;
		} else {
			length += sizeof(net_ip_header_t );
			packet->ip->tot_len = htons(length);
		}
	}

	if (length > NET_MAX_PACKET_SIZE) {
		error("packet too big. Length = %i (max packet size = %i)\n", length, NET_MAX_PACKET_SIZE);
		return NET_ERROR;
	}

	ptr = raw_packet;

	// copy data from IP & UDP headers
	if (packet->ip) {
		memcpy(ptr, packet->ip, sizeof(net_ip_header_t ));
		ptr += sizeof(net_ip_header_t );
		if (packet->udp) {
			memcpy(ptr, packet->udp, sizeof(net_udp_header_t));
			ptr += sizeof(net_udp_header_t);
		}
	}
	

	// copy data from DNS & RR headers
	memcpy(ptr, packet->dns, sizeof(net_dns_header_t));
	ptr += sizeof(net_dns_header_t);

	// add qname
	memcpy(ptr, packet->rr_q->qname, packet->rr_q->qname_length);
	ptr += packet->rr_q->qname_length;

	// add the trailing null at end of QNAME
	*ptr = 0;
	ptr++;

	// add class and type
	*(uint16 *) ptr = packet->rr_q->type;
	ptr += sizeof(uint16);
	*(uint16 *) ptr = packet->rr_q->class;
	ptr += sizeof(uint16);
	
	// if there's an answer part for this packet
	if (packet->rr_a) {
		*(uint16 *) ptr = packet->rr_a->name;
		ptr += sizeof(uint16);
		*(uint16 *) ptr = packet->rr_a->type;
		ptr += sizeof(uint16);
		*(uint16 *) ptr = packet->rr_a->class;
		ptr += sizeof(uint16);
		*(uint32 *) ptr = packet->rr_a->ttl;
		ptr += sizeof(uint32);
		*(uint16 *) ptr = packet->rr_a->length;
		ptr += sizeof(uint16);
		memcpy(ptr, packet->rr_a->data, ntohs(packet->rr_a->length));
	}

	// calculate IP checksum
	if (packet->ip) {
		((net_ip_header_t *) raw_packet)->cksum = ip_checksum((uint16 *) raw_packet, length);
	}

	// send off
	if (sendto(sock, (const void *) raw_packet, length, 
								0, (struct sockaddr *) addr, 
										sizeof(struct sockaddr_in)) == -1) {
		error("cannot sendto data\n");
		return NET_ERROR;
	}
	
	return NET_SUCCESS;
}

int	
net_recv_packet(const int sock, net_packet_t *packet, const unsigned int timeout, struct sockaddr_in *client)
{
	uint8 raw_packet[NET_MAX_PACKET_SIZE];
	uint8 *ptr = 0, *pptr = 0;
	int rs, k;
	struct timeval tv;
	fd_set fds;
	int length;
	int client_size;
	unsigned int consumed;

	// if timeout was set to a value greater than zero, we'll return if
	// there was no data to read within that time
	if (timeout != 0) {
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		FD_ZERO(&fds);
		FD_SET(sock, &fds);

		rs = select(sock + 1, &fds, 0, 0, &tv);

		if (rs == -1) {
			error("select on socket does not work\n");
			return NET_ERROR;
		}

		if (rs == 0) {
			debug("Timeout!\n");
			return NET_TIMEOUT;
		}
	}

	if (client) {
		client_size = sizeof(*client);
		length = recvfrom(sock, raw_packet, NET_MAX_PACKET_SIZE, 
								0, (struct sockaddr *) client, &client_size);
	} else {
		length = recvfrom(sock, raw_packet, NET_MAX_PACKET_SIZE, 0, 0, 0);
	}
	if (length == -1) {
		error("cannot recvfrom packet\n");
		return NET_ERROR;
	}

	if (!packet) {
		error("pointer to packet structure is NULL\n");
		return NET_ERROR;
	}

	// we don't receive IP or UDP headers (only the DNS headers)
	packet->ip = 0;
	packet->udp = 0;
	packet->dns = (net_dns_header_t *) malloc_or_die(sizeof(net_dns_header_t));
	
	ptr = (uint8 *) raw_packet;
	consumed = 0;

	// copy the dns header into the packet structure
	memcpy(packet->dns, ptr, sizeof(net_dns_header_t));
	ptr += sizeof(net_dns_header_t);
	consumed += sizeof(net_dns_header_t);

	// extract Question RR from packet
	packet->rr_q = (struct net_dns_rr_question_t *) malloc_or_die(sizeof(struct net_dns_rr_question_t));
	pptr = packet->rr_q->qname;
	packet->rr_q->qname_length = 0;
	// parse qname (ptr points here after the end of the DNS header which is the beginning of the qname
	while (consumed < length && packet->rr_q->qname_length < NET_MAX_QNAME && *ptr) {
		if (*ptr <= NET_MAX_SUB_QNAME) {
			k = ((unsigned char) *ptr) + 1;	// +1 for the length field (the dot)
			packet->rr_q->qname_length += k;
			consumed += k;
			if (consumed < length && packet->rr_q->qname_length < NET_MAX_QNAME) {
				memcpy(pptr, ptr, k);
				ptr += k;
				pptr += k;
			} else {
				error("overly long domain name: %i\n", packet->rr_q->qname_length);
				return NET_ERROR;
			}
		} else {
			error("overly long sub domain name: %i\n", *ptr);
			return NET_ERROR;
		}
	}

	// skip trailing null
	if (*ptr == 0x00 && consumed + 1 < length) {
		ptr += 1;
		consumed += 1;
	} else {
		error("packet truncated: trailing 0 expected\n");
		return NET_ERROR;
	}

	// get class and type
	if ((consumed + 2 * sizeof(uint16)) <= length) {
		packet->rr_q->type = *(uint16 *) ptr;
		ptr += sizeof(uint16);
		packet->rr_q->class = *(uint16 *) ptr;
		ptr += sizeof(uint16);
		consumed += 2 * sizeof(uint16);
	} else {
		error("packet truncated: class and type expected\n");
		return NET_ERROR;
	}

	// extract Answer RR from packet
	if (packet->dns->answer_num > 0) {
		packet->rr_a = (struct net_dns_rr_answer_t *) malloc_or_die(sizeof(struct net_dns_rr_answer_t));

		if ((consumed + 6 * sizeof(uint16)) < length) {
			packet->rr_a->name = *(uint16 *) ptr;
			ptr += sizeof(uint16);
			packet->rr_a->type = *(uint16 *) ptr;
			ptr += sizeof(uint16);
			packet->rr_a->class = *(uint16 *) ptr;
			ptr += sizeof(uint16);
			packet->rr_a->ttl = *(uint32 *) ptr;
			ptr += sizeof(uint32);
			packet->rr_a->length = *(uint16 *) ptr;
			ptr += sizeof(uint16);
			consumed += 6 * sizeof(uint16);
		} else {
			error("packet truncated: answer RR expected\n");
			return NET_ERROR;
		}

		// + 1 is for the additional length field in the answer data part
		if (ntohs(packet->rr_a->length) > NET_MAX_ANSWER_RR_DATA + 1) {
			debug("the answer RR data length was more than allowed %i\n", ntohs(packet->rr_a->length));			
			packet->rr_a->length = htons(NET_MAX_ANSWER_RR_DATA + 1);
		}

		if (consumed + ntohs(packet->rr_a->length) <= (unsigned int) length) {
			memcpy(packet->rr_a->data, ptr, ntohs(packet->rr_a->length));
			consumed += ntohs(packet->rr_a->length);
		} else {
			error("packet truncated: answer RR data expected\n");
			return NET_ERROR;
		}
	} 

	// the number of consumed bytes should be equal to the length of the packet
	// Comment: Bind 9.4.2 adds a OPT record to the query, therefore we'll 
	// ignore everything in the packet after here...

	return NET_SUCCESS;
}

int
net_read(const int sock, unsigned char *buffer, const unsigned int buffer_length, const unsigned int timeout_sec, const unsigned int timeout_usec)
{
	struct timeval tv;
	fd_set fds;
	int rs;

	if ((timeout_sec != 0) || (timeout_usec != 0)) {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_sec = timeout_sec;
		tv.tv_usec = timeout_usec;

		rs = select(sock + 1, &fds, 0, 0, &tv);
		if (rs == -1) {
			error("select on socket does not work\n");
			return NET_ERROR;
		}

		if (rs == 0) {
			return NET_TIMEOUT;
		}
	}

	return recv(sock, buffer, buffer_length, 0);
}

int	
net_write(const int sock, unsigned char *buffer, unsigned int buffer_length)
{
	return send(sock, buffer, buffer_length, 0);
}


int
net_connect(int sock, const ip_addr addr, const uint16 port)
{
	struct sockaddr_in a;
	// convert properly:
	a.sin_addr.s_addr = addr;
	a.sin_port = htons(port);
	a.sin_family = AF_INET;
	
	if (connect(sock, (struct sockaddr *) &a, sizeof(a)) != 0) {
		return NET_ERROR;
	}
	
	return NET_SUCCESS;
}

int
net_accept(const int sock)
{
	return accept(sock, 0, 0);
}


/*
 * The function removes all the sub domain length fields and cuts the 'domain' off the qname
 * 'data' must be allocated with at least NET_MAX_QNAME bytes.
 * The function returns 0, if the domain names do not match.
 */
unsigned int
net_dns_get_qname(struct net_dns_rr_question_t *rr, char *data, const char *domain)
{
	unsigned int consumed = 0;
	unsigned int qname_length = 0;
	unsigned int data_length = 0, i = 0;
	unsigned char *qname = 0;

	qname = rr->qname;
	// remove the domain name and the length field before it from the qname
	// (+1 is for the dot before the domain name)
	if (rr->qname_length < (strlen(domain) + 1)) {
		error("QNAME is truncated\n");
		return 0;
	}
	qname_length = rr->qname_length - ((strlen(domain) + 1));

	// we read each length field, copy the amount of data into the data buffer and then jump to the next length field
	// until we either reach 0 or get to the end of the allowed number of bytes (that would be an error)
	// extract payload data and remove sub domains length fields
	while (*qname
		&& (*qname <= NET_MAX_SUB_QNAME)
			&& (consumed + *qname < qname_length) 
				&& (consumed + *qname < NET_MAX_QNAME)) {
		// copy sub domain into data buffer
		memcpy(data, qname + 1, *qname);
		// jump to next sub domain
		data += *qname;
		data_length += *qname;
		consumed += *qname + 1;
		qname += *qname + 1;	// +1 to skip the dot
	}

	// compare the domain part
	while (*qname
			&& (*qname <= NET_MAX_SUB_QNAME)
				&& (consumed + *qname < rr->qname_length) 
					&& (consumed + *qname < NET_MAX_QNAME)) {
		if (strncmp(qname + 1, domain, *qname) != 0) {
			// domain name mismatch
			return 0;
		}
		domain += *qname + 1;
		consumed += *qname + 1;
		qname += *qname + 1;
	}
	
	return data_length;
}

unsigned int
net_dns_get_txt(struct net_dns_rr_answer_t *rr, char *data)
{
	// the first byte is the length field - we skip it
	memcpy(data, rr->data + 1, (unsigned char) rr->data[0]);
	return rr->data[0];
}

// TODO: move the two functions below somewhere else
unsigned char 
net_encode_flag(const tunnel_header_flag_t *flag)
{
	const char map[] = "abcdefghijklmnopqrstuvwxyz012345";

	if (*(uint8 *) flag >= strlen(map)) {
		error("end of base32 table: flag to encode %.2x\n", *(uint8 *) flag);
		return 0;
	}

	return map[*(uint8 *) flag];
}

tunnel_header_flag_t *
net_decode_flag(const uint8 flag)
{
	const char map[] = "abcdefghijklmnopqrstuvwxyz012345";
	tunnel_header_flag_t *fret;
	uint8 i = 0;

	fret = (tunnel_header_flag_t *) malloc_or_die(sizeof(tunnel_header_flag_t));

	for (i = 0; i < strlen(map); i++) {
		if (map[i] == (char) flag) {
			*fret = *(tunnel_header_flag_t *) &i; 
			return fret;
		}
	}

	error("end of base32 table: flag to decode %.2x\n", flag);
	return 0;
}

/*
 * Get local IP address.
 * This is the easiest but not the best solution. 
 * There's a more efficient way doing it using these functions: 
 *    http://msdn.microsoft.com/en-us/library/aa365949(VS.85).aspx
 * But that would also require an additional library: Iphlpapi.dll.
 */
ip_addr	
net_get_local_ip()
{
	struct in_addr local_ip;
	char hostname[255];
	struct hostent *he;

	if (gethostname(hostname, sizeof(hostname)) != 0) {
		error("cannot retrieve local hostname\n");
		return 0;
	}
	he = gethostbyname(hostname);
	if (!he) {
		error("cannot retrieve local ip address\n");
		return 0;
	}
	local_ip = *(struct in_addr *)*he->h_addr_list;

	return local_ip.S_un.S_addr;
}
