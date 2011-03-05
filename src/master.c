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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __WIN32__
#include <winsock2.h>
#include <windns.h>
#include <windows.h>
#endif

#include "master.h"
#include "buffer.h"
#include "global.h"
#include "net.h"
#include "tunnel.h"
#include "types.h"
#include "util.h"

extern int verbose; 

static master_slave_tracker_t *slaves[MAX_SLAVES];

#ifdef __WIN32__
static DWORD WINAPI 
#else
static void *
#endif
master_wait_for_connection(void *s_ptr)
{
	master_slave_tracker_t *slave;
	int sockfd;

	slave = (master_slave_tracker_t *) s_ptr;

	
	sockfd = net_socket(NET_SOCKET_TCP, 0, slave->tcp_port, NET_DO_LISTEN);
	if (sockfd == NET_ERROR) {
		error("cannot create master data socket\n");
		return 0;
	}

	debug("Waiting for connection on %i/TCP\n", slave->tcp_port);

	slave->buffer->fd_r = net_accept(sockfd);
	if (slave->buffer->fd_r == NET_ERROR) {
		error("connection was not accepted\n");
		return 0;
	}

	slave->buffer->fd_w = slave->buffer->fd_r;
	debug("connection established\n");

	return 0;
}


static int
master_create_slave(char *domain, uint16 port, int do_listen)
{
	uint8 ticket;

	// find an available slave instance
	for (ticket = 1; ticket < 255; ticket++) {
		if (!slaves[ticket]) {

			slaves[ticket] = (master_slave_tracker_t *) malloc_or_die(sizeof(master_slave_tracker_t));
#ifdef __WIN32__
			GetSystemTime(&(slaves[ticket]->last_used));
#else
            gettimeofday(&(slaves[ticket]->last_used), NULL);
#endif
			slaves[ticket]->ticket		 = ticket;
			slaves[ticket]->domain		 = domain;
			slaves[ticket]->tcp_port	= port;
			slaves[ticket]->buffer = buffer_new(MAX_SEQ + 1, -1, -1); // FDs will be passed later

			// create thread to wait asyncronically for a tcp connection to be established
			if (do_listen) {
#ifdef __WIN32__
				CreateThread(0, 0, master_wait_for_connection, slaves[ticket], 0, 0);
#else
                pthread_t new_thread;
                pthread_create(&new_thread, NULL, master_wait_for_connection, slaves[ticket]);
                pthread_detach(new_thread);
#endif
			} else {
				slaves[ticket]->buffer->fd_r = net_socket(NET_SOCKET_TCP, 0, 0, 0); 
				if (slaves[ticket]->buffer->fd_r == NET_ERROR) {
					error("Unable to create socket... exiting\n");
					return 0;
				}
				slaves[ticket]->buffer->fd_w = slaves[ticket]->buffer->fd_r;

				debug("Connecting to 127.0.0.1:%i\n", port);
				if (net_connect(slaves[ticket]->buffer->fd_r, 
										inet_addr("127.0.0.1"), 
											port) == NET_ERROR) {
					error("Unable to connect to: 127.0.0.1:%i\n", port);
					return 0;
				}
	
				debug("Connected to 127.0.0.1:%i\n", port);
			}

			return ticket;
		}
		
		// TODO: find outdated slaves (e.g. slaves[ticket]->last_used > timeout)
	}


	debug("All slave slots are full, sorry\n");

	return -1;
}

static void 
master_destroy_slave(uint8 ticket)
{
	master_slave_tracker_t *slave;

	slave = slaves[ticket];
	
	// TODO: free buffer

	slaves[ticket] = 0;
	free(slave);
}

static struct net_dns_rr_answer_t *
master_handle_hello(tunnel_header_slave_flag_t *slave_flag, 
					unsigned char *dec_data, 
					unsigned int dec_data_length,
					char *domain,
					uint16 port, int do_listen)
{	
	char data[DATA_BUFFER_SIZE];
	char enc_data[DATA_BUFFER_SIZE];
	tunnel_header_master_flag_t master_flag;
	tunnel_header_t hdr, *slave_hdr;
	int ticket;
	unsigned int data_length, enc_data_length, max_out_length;

	if (!slave_flag || !dec_data || !domain || !domain) {
		return 0;
	}

	debug("Slave is attempting a handshake\n");

	slave_hdr = (tunnel_header_t *) dec_data;
	// if this handshake packet does not contain a ticket, we need to assign one
	if (!slave_hdr->ticket) {
		ticket = master_create_slave(domain, port, do_listen);
		if (ticket == -1) {
			return 0;
		}
		debug("created new slave instance with ticket %i\n", ticket);
	} else {
		// otherwise we just reply to the packet using the ticket in the request
		ticket = slave_hdr->ticket;
		debug("the slave is already using ticket %i\n", ticket);
	}

	// construct hello response
	ZERO_FLAG(&master_flag);
	master_flag.hello_reply = 1;
	master_flag.binary_txt = slave_flag->expect_binary;
	*((uint8 *)enc_data) = net_encode_flag((tunnel_header_flag_t *) &master_flag);

	hdr.last_received = 0;
	hdr.sequence = 0;
	hdr.ticket = ticket;

	memcpy(data, dec_data, dec_data_length);
	memcpy(data, &hdr, sizeof(tunnel_header_t));
	data_length = dec_data_length;

	max_out_length = NET_MAX_TXT - strlen(domain) - 1;

	// re-encode received test data for the handshake
	codec_encode(master_flag.binary_txt ? CODEC_BINARY : CODEC_BASE64, 
						data, data_length, enc_data + 1, &enc_data_length, max_out_length);

	debug("sending HELLO response\n");

	return net_craft_dns_rr_answer(enc_data, enc_data_length + 1, domain);
}

static struct net_dns_rr_answer_t *
master_handle_data(tunnel_header_slave_flag_t *slave_flag,	// flag from the slave's packet
						unsigned char *dec_data,			// already decoded data
							unsigned int dec_data_length)	// length of decoded data
{
	tunnel_header_t *slave_hdr;		// pointer to the header in the slave's packet
	tunnel_header_t *master_hdr;		// pointer to the header in the response packet
	master_slave_tracker_t *slave;
	uint8 *payload;				// pointer to the received payload
	unsigned int payload_length;	// length of the payload
	int written_bytes;				// number of bytes written to the buffer
	tunnel_header_master_flag_t master_flag;	// flag in the master's response
	unsigned int max_data_length;			// how much data can be put in the response
	unsigned char master_data[DATA_BUFFER_SIZE];
	unsigned char *master_payload;
	unsigned int master_data_length;
	unsigned char master_enc_data[DATA_BUFFER_SIZE];
	unsigned int master_enc_data_length;
	unsigned int max_out_length;

	// retrieve the header and the ticket
	slave_hdr = (tunnel_header_t *) dec_data;
	slave = slaves[slave_hdr->ticket];

	// verify that this slave does exist
	if (!slave) {
		debug("received packet for non-existing slave (%u)\n", slave_hdr->ticket);
		return 0;
	}

	if (verbose > 0) {
		debug("received (seq=%.5i ack=%.5i size=%i flag=0x%.2x ticket=%i)\n", slave_hdr->sequence , slave_hdr->last_received, dec_data_length, *(uint8 *)slave_flag, slave_hdr->ticket);
	}

	// set the payload pointer and length
	if (slave_flag->spoofed) {
		payload = dec_data + sizeof(tunnel_header_t);
		payload_length = (unsigned int) (dec_data_length - sizeof(tunnel_header_t));
	} else {
		payload = NULL;
		payload_length = 0;
	}

	written_bytes = buffer_write(
			slave->buffer,
				payload,
					payload_length,
						slave_hdr->sequence,
							slave_hdr->last_received);

	if (verbose > 1) {
		printf("master.c: wrote %i bytes (now: seq=%i ack=%i)\n", written_bytes, get_seqn(slave->buffer), get_ackn(slave->buffer));
	}

	// update slave's last used timestamp
#ifdef __WIN32__
    GetSystemTime(&(slave->last_used));
#else
    gettimeofday(&(slave->last_used), NULL);
#endif

	// spoofed packets will be answered with an NXDOMAIN packet
	if (slave_flag->spoofed) {
		// debug("[DEBUG] Spoofed packet... sending a NXDOMAIN\n");
		return 0;
	}

	// now we'll take care of the answer and construct the reply packet
	ZERO_FLAG(&master_flag);

	// calculate how much data we can read from the tcp socket
	max_data_length = 0;

	// check if the client is expecting a binary answer
	if (slave_flag->expect_binary) {
		max_data_length = NET_MAX_TXT 
								- sizeof(tunnel_header_t) 
									- sizeof(tunnel_header_master_flag_t);
		master_flag.binary_txt = 1;
	} else {
		// TODO calculate max data length for Base64
		// max_data_length = NET_MAX_TXT ...
		master_flag.binary_txt = 0;
		error("sending back BASE64 enc -- not implemented yet\n");
	}

	master_hdr = (tunnel_header_t *) master_data;
	master_payload = master_data + sizeof(tunnel_header_t);
	// we now how much data we can consume at max, so go and get that data from the buffer
	master_data_length = buffer_read(
							slave->buffer,
								master_payload,
									max_data_length,
										&(master_hdr->sequence),
											&(master_hdr->last_received), 0);
	// if the data we read from the buffer is exactly the maximum we could have
	// read, we assume that there's more data waiting and signalize that to the
	// slave
	if (master_data_length == max_data_length) {
		master_flag.more_data = 1;
	} else {
		master_flag.more_data = 0;
	}
	master_data_length += sizeof(tunnel_header_t);

	master_hdr->ticket = slave->ticket;

	// we have the data, now encode it...	
	max_out_length = NET_MAX_TXT - 1;

	codec_encode(slave_flag->expect_binary ? CODEC_BINARY : CODEC_BASE64, 
							master_data, 
								master_data_length, 
									master_enc_data + sizeof(tunnel_header_master_flag_t), 
										&master_enc_data_length, 
											max_out_length);

	
	*(uint8 *) master_enc_data = net_encode_flag((tunnel_header_flag_t *) &master_flag);
	master_enc_data_length += sizeof(tunnel_header_flag_t);

	if (verbose > 0) {
		debug("sending (seq=%u ack=%u size=%u)\n",master_hdr->sequence, master_hdr->last_received, master_enc_data_length);
	}

	return net_craft_dns_rr_answer(
								master_enc_data, 
									master_enc_data_length, 
										slave->domain);
}


int 
master_run(int listen_port, char *domain, uint16 port, int do_listen) 
{
	int sock, rs;
	char * qname;  // name to decode (no dots)
	net_dns_header_t *dns;
	struct net_dns_rr_question_t *rr_q;
	net_packet_t *packet, *out_packet;
	struct sockaddr_in slave_addr;
	tunnel_header_slave_flag_t *slave_flag; // client's decoded flag
	tunnel_header_t *hdr;
	char dec_data[DATA_BUFFER_SIZE];	//TODO: make 1024 defined
	unsigned int dec_data_length = 0, enc_data_length = 0, qname_length;
	unsigned int in_buf_size = 0;

	// Checking we have at least one domain
	if (!domain || strlen(domain) == 0) {
		debug("You need to specify at least one domain\n");
		return 0;
	}

	debug("Master starting for (%s) listening on %i/UDP\n", domain, listen_port);

	qname = malloc_or_die(NET_MAX_QNAME);

	sock = net_socket(NET_SOCKET_UDP, 0, listen_port, 1);
	if (sock == -1) {
		error("cannot create server udp socket\n");
		return 0;
	}

	memset(slaves, 0x00, sizeof(master_slave_tracker_t *) * MAX_SLAVES);

	// allocate memory for the packet to receive and send
	packet = net_new_packet(); 

	// server main loop
	do {
		// receive thenext dns request packet
		rs = net_recv_packet(sock, packet, 0, &slave_addr);
		if (rs == NET_ERROR) {
			error("could not receive packet\n");
			break;	
		}

		// Extract the DNS header
		dns = packet->dns; 
		rr_q = packet->rr_q; 

		// a return value of 0 indicates that the domain name did not match
		// we'll skip the packet if that is the case
		qname_length = net_dns_get_qname(rr_q, qname, domain);
		if (qname_length == 0) {
			continue;
		}

		// get the flag that indicates the nature of the message
		// and the encoding
		slave_flag = (tunnel_header_slave_flag_t *) net_decode_flag(*(uint8 *) qname);

		// decode the data in the packet. There must be data in a packet (at least the header). 
		// If there's no data, then that is an error.
		dec_data_length = codec_decode(slave_flag->codec, 
									qname + sizeof(tunnel_header_slave_flag_t), 
										qname_length - sizeof(tunnel_header_slave_flag_t), dec_data);
		if (!dec_data_length) {
			error("decoding of data failed (%.1x); skip packet.\n", slave_flag->codec);
			continue;
		}

		hdr = (tunnel_header_t *) dec_data;

		out_packet = net_new_packet();
		out_packet->dns = packet->dns;
		out_packet->rr_q = packet->rr_q;
		
		if (slave_flag->hello) {
			out_packet->rr_a = master_handle_hello(slave_flag,
												dec_data, 
												dec_data_length,
												domain,
												port, do_listen);
		} else {
			if (slave_flag->control) {
				//TODO: control message from slave. What to do? Ignore as there's nothing that the slave has to tell the master...
				
			} else {
				// out_packet will be 0, if the incoming packed was spoofed and does
				// not have to be answered
				out_packet->rr_a = master_handle_data(slave_flag, 
												dec_data,
													dec_data_length); // ice: why not domain?
			}
		}

		if (!out_packet->rr_a) {
			net_dns_set_rcode(out_packet->dns, NET_DNS_RCODE_NXDOMAIN);
			// UNCOMMENT THE FOLLOWING TO PRINT A TRACE OF EACH PACKET
	        //	debug("sending nxdomain\n");
		}

		packet->dns->qr = 1; // It's a response packet
		packet->dns->ad = 1; // Authoritative answer
		
		if ( (net_send_packet(sock, out_packet, &slave_addr) == NET_ERROR) ) {
			error("cannot send packet\n");
			break;
		}

	} while (rs != NET_ERROR);

	debug("server error\n");

	return -1;
}
