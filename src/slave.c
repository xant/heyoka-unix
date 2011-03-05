. H/* 
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

#include <time.h>
#include <winsock2.h>
#include <windns.h>
#include <windows.h>

#include "slave.h"
#include "buffer.h"
#include "global.h"
#include "net.h"
#include "tunnel.h"
#include "types.h"
#include "util.h"

#define SAMPLE_DATA	"\x00\x01\x02\x03\x04\x05\x06\x07" \
					"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" \
					"\x50\x51\x52\x53\x54\x55\x56\x57" \
					"\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f" \
					"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7" \
					"\xa8\xa9\xaa\xab\xac\xad\xae\xaf" \
					"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7" \
					"\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

extern int verbose;

static uint32 *
slave_get_server_list()
{
	uint32 server_list[DNS_MAX_SERVER_LIST_SIZE];
	uint32 *ns_list;
	unsigned int list_size, server_count, i;

	list_size = DNS_MAX_SERVER_LIST_SIZE - 1;

	debug("retrieving name server list\n");

	DnsQueryConfig(DnsConfigDnsServerList, 0, 0, 0, server_list, &list_size);

	server_count = (unsigned int) server_list[0];

	ns_list = (uint32 *) malloc_or_die((server_count + 1) * sizeof(uint32));
	for (i = 1; i <= server_count; i++) {
		debug("NS #%i: %s (%x)\n", i, net_ip_to_ascii(server_list[i]), server_list[i]);
		ns_list[i - 1] = server_list[i];
	}
	// null terminate the list
	ns_list[i - 1] = 0x00;

	debug("using %i nameserver%s\n", server_count, server_count > 1 ? "s" : "");

	return ns_list;
}

static tunnel_ns_list_t **
slave_handshake(slave_instance_t * slave, char *domain, uint32 *ns_list)
{
	net_packet_t *req_packet;			// request packet
	net_packet_t *res_packet;			// response packet
	struct sockaddr_in req_addr;		// request address structure
	struct sockaddr_in res_addr;		// response address structure
	uint8 *req_sample_data;				// unencoded request sample data 
	uint8 res_sample_data[NET_MAX_TXT + 1];				// unencoded request sample data 
	uint8 *sample_payload;				// pointer to the sample data payload
	uint8 req_enc_data[NET_MAX_QNAME + 1];	// encoded sample data for request
	unsigned int req_enc_data_length;
	uint8 res_enc_data[NET_MAX_TXT + 1];	// encoded sample data in response
	unsigned int res_enc_data_length;
	tunnel_header_t *header;		// pointer to header in request/response
	tunnel_ns_list_t **working_ns_list = 0;	// list of working name servers
	unsigned int ns = 0;				// number of working name servers
	char *ns_addr = 0;					// nameserver address presented as string
	int codec, expect_binary, success;
	tunnel_header_slave_flag_t req_flag;	// slave flag for request
	tunnel_header_master_flag_t *res_flag;	// master flag in response
	int req_sample_length;
	int res_sample_length;
	int res_code, c;

	// DNS request packet
	req_packet = net_new_packet();
	if (!req_packet) {
		error("cannot create new packet\n");
		return 0;
	}

	// DNS response packet
	res_packet = net_new_packet();
	if (!res_packet) {
		error("cannot create new packet\n");
		return 0;
	}

	// Create the packet to send out
	// this is a dummy ip header with dst_ip = 0, it'll be replaced later
	req_packet->ip = net_craft_ip(net_get_local_ip(), 0);	
	req_packet->udp = net_craft_udp(slave->udp_listen_port, NET_DEFAULT_DNS_PORT);	
	req_packet->dns = net_craft_dns();
	req_packet->rr_a = 0;

	req_addr.sin_family = AF_INET;
	req_addr.sin_port = htons(NET_DEFAULT_DNS_PORT); //TODO: the dns port might be optional as well

	// create sample data
	req_sample_data = (uint8 *) malloc_or_die(sizeof(SAMPLE_DATA) + sizeof(tunnel_header_t));
	header = (tunnel_header_t *) req_sample_data;
	memset(header, 0x00, sizeof(tunnel_header_t));
	sample_payload = req_sample_data + sizeof(tunnel_header_t);
	memcpy(sample_payload, SAMPLE_DATA, sizeof(SAMPLE_DATA));

	// iterate through list of nameservers
	for (ns = 0; *ns_list != 0; ns_list++) {
		// set nameserver as target	
		req_addr.sin_addr.s_addr = *ns_list;
		net_set_ip_dst(req_packet, *ns_list);
		ns_addr = net_ip_to_ascii(*ns_list);

		// try all possible codec information
		for (codec = CODEC_BINARY, success = 0; codec >= 0x00 && !success; codec--) {
			for (expect_binary = 1; expect_binary >= 0 && !success; expect_binary--) {
				debug(
					"testing %s codec for sending %s codec for incoming %i (1=Binary)\n", 
						ns_addr, 
							codec_name(codec), 
								expect_binary);
				//TODO: build payload header
				ZERO_FLAG(&req_flag);
				req_flag.codec = codec;
				req_flag.hello = 1;
				req_flag.expect_binary = expect_binary;
				req_enc_data[0] = net_encode_flag((tunnel_header_flag_t *) &req_flag);

				// encode test payload data
				req_sample_length = codec_encode(
										codec, 
											req_sample_data, 
												sizeof(SAMPLE_DATA) + sizeof(tunnel_header_t), 
													req_enc_data + 1, 
														&req_enc_data_length, 
															NET_MAX_QNAME - 1);
				
				// put data into request packet
				req_packet->rr_q = net_craft_dns_rr_question(
									req_enc_data, 
										req_enc_data_length + 1, 
											domain);
	
				// send request off
				if (net_send_packet(slave->udp_send_sock, 
										req_packet, 
											&req_addr) == NET_ERROR) {
					error("cannot send packet\n");
					continue;
				}

				// receive response
				res_code = net_recv_packet(slave->udp_recv_sock, 
										res_packet, 
											NET_DEFAULT_PACKET_RECV_TIMEOUT, 
												&res_addr);
				if (!res_packet->rr_a) {
					error("response had no answer RR\n");
					res_code = NET_ERROR;
				}
				switch (res_code) {
					case NET_ERROR:
						error("receiving response has failed for %s\n", ns_addr);
						break;
					case NET_TIMEOUT:
						error("receiving response has timed out for %s\n", ns_addr);
						break;
					default:
						// get TXT record from response
						res_enc_data_length = net_dns_get_txt(
														res_packet->rr_a, 
															res_enc_data);

						// get flag from header
						res_flag = (tunnel_header_master_flag_t *) 
												net_decode_flag(res_enc_data[0]);

						// decode data with cipher that has been specified in the flag
						res_sample_length = codec_decode(
												res_flag->binary_txt ? CODEC_BINARY : CODEC_BASE64, 
													res_enc_data + 1, 
														res_enc_data_length - 1, 
															res_sample_data);

						header = (tunnel_header_t *) res_sample_data;
						
						// the length of the sample data in the response has 
						// to match the length of the request sample data
						if (req_sample_length == res_sample_length) {
							// the length matches, good, now compare byte by
							// byte but skip the headers that are still in the
							// decoded data buffers
							for (c = req_sample_length - 1; c > sizeof(tunnel_header_t); c--) {
								if (req_sample_data[c] != res_sample_data[c]) {
									break;
								}
							}
							if (c == sizeof(tunnel_header_t)) {
								debug("Data was correctly tranferred :D\n\n");
								// get the tiket from the response
								slave->ticket = header->ticket;
								debug("We've been assigned a ticket: %u\n", slave->ticket);
							
								// increase number of positiv tested nameservers
								ns++;
								// remember name server and codec
								// we always allocate memory for one more structure so that we can null terminate the list later
								if (!working_ns_list) {
									working_ns_list = (tunnel_ns_list_t **) malloc_or_die(2 * sizeof(tunnel_ns_list_t *));
								} else {
									working_ns_list = (tunnel_ns_list_t **) realloc(working_ns_list, (ns + 1)* sizeof(tunnel_ns_list_t *));
								}
								working_ns_list[ns - 1] = (tunnel_ns_list_t *) malloc_or_die(sizeof(tunnel_ns_list_t)); 
								working_ns_list[ns - 1]->address = *ns_list;
								working_ns_list[ns - 1]->codec = codec;	
								working_ns_list[ns - 1]->binary_txt = expect_binary;
								success = 1;
							} else {
								debug("Data has been modified in byte %i\n", c);
								hexdump("Request Sample Data", req_sample_data, req_sample_length);
								hexdump("Response Sample Data", res_sample_data, res_sample_length);
							}	
						} else {
							debug("Data length differs :( %i %i\n", req_sample_length, res_sample_length);
						}
				}
			}
		}
	}
	// we're done now with testing encodings and server

	if (ns > 0) {
		// null terminate the list
		working_ns_list[ns] = 0x00;
		debug("%i nameserver %s found to be working:\n", ns, (ns > 1 ? "s were" : "was"));
		for (ns = 0; working_ns_list[ns] != 0; ns++) {
			debug("  %-16s  (codec: req=%s res=%s)\n", 
				net_ip_to_ascii(working_ns_list[ns]->address), 
					codec_name(working_ns_list[ns]->codec), 
						codec_name((working_ns_list[ns]->binary_txt ? CODEC_BINARY : CODEC_BASE64)));
		}
	} else {
		error("none of the nameservers was found to be working\n");
	}

	return working_ns_list;
}

static DWORD WINAPI 
slave_wait_for_connection(void *s_ptr)
{
	slave_instance_t *slave;
	int sockfd;

	slave = (slave_instance_t *) s_ptr;
	
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


static void 
slave_listen(void *p) 
{
	slave_instance_t *slave;			// pointer to slave instance
	net_packet_t *packet;				// pointer to packet structure
	unsigned int txt_encoded_length;
	unsigned int txt_decoded_length;
	unsigned int payload_length;
	unsigned char txt_encoded[DATA_BUFFER_SIZE];
	unsigned char txt_decoded[DATA_BUFFER_SIZE];
	unsigned char *payload;
	tunnel_header_master_flag_t *flag = 0;
	tunnel_header_t *header = 0;
	unsigned int nbytes = 0;

	debug("listening thread running\n");

	slave = (slave_instance_t *) p;

	// create a new packet structure
	packet = net_new_packet();

	// slave main listening loop
	while (1) {

		// receive next packet
		if (net_recv_packet(slave->udp_recv_sock, packet, 0, 0) == NET_ERROR) {
			error("could not receive next packet\n");
			return;
		}

		if (!packet->rr_a) {
			// there's no answer RR in the packet (e.g. NXDOMAIN responses won't have an answer RR part)
			continue;
		}

		// Extract the encoded data in the TXT record
		txt_encoded_length = net_dns_get_txt(packet->rr_a, txt_encoded);

		// Extract and decode the flag which is the first byte of the encoded data
		// and, independed to the data, is always base32 encoded
		flag = (tunnel_header_master_flag_t *) net_decode_flag(*(uint8 *) txt_encoded);

		// check if more data is waiting to be sent and signalize the sending thread to decrease the 
		// timeout when reading new data in
		if (flag->more_data) {
			if (verbose > 1) {
				debug("Set heartbeat frequence to fast: %i ms\n", HEARTBEAT_FREQ_FAST);
			}
			slave->heartbeat_freq = HEARTBEAT_FREQ_FAST;
		} else {
			if (verbose > 1) {
				debug("Set heartbeat frequence to slow: %i ms\n", HEARTBEAT_FREQ_SLOW);
			}
			slave->heartbeat_freq = HEARTBEAT_FREQ_SLOW;
		}

		// Decode the header + payload which is everything after the first byte
		txt_decoded_length = codec_decode(
								flag->binary_txt ? CODEC_BINARY : CODEC_BASE64, 
									txt_encoded + 1, 
										txt_encoded_length - 1, 
											txt_decoded);

			// Split header and payload
			header = (tunnel_header_t *) txt_decoded;
			payload = txt_decoded + sizeof(tunnel_header_t);
			payload_length = txt_decoded_length - sizeof(tunnel_header_t);

			if (verbose > 1) {
				debug("received (seq=%.5i ack=%.5i BHMC=%i%i%i%i ticket=%i size=%i)\n", 
					header->sequence, header->last_received, flag->binary_txt, 
					flag->hello_reply, flag->more_data, flag->control, header->ticket, payload_length);
			}

	//	if (flag->control) {
			// this is not a data message but a control message
			// dunno what to do with this
	//	} else {
			// write data to the buffer
		buffer_write(slave->buffer,	payload, payload_length,
										header->sequence, header->last_received);
	//	}

	}
	
	// will never reach this part... fingers crossed ;)
	net_destroy_packet(packet);
}

/*
 * Slave sending function
 */
static DWORD WINAPI 
slave_send(void *p) 
{
	slave_instance_t *slave;			// slave instance
	struct sockaddr_in to_addr;			// socket address structure of ns
	SYSTEMTIME now, then;				// to calculate the timeout for heartbeats
	uint8 out_data[NET_MAX_QNAME + 1];	// complete data buffer (flag, encoded header and payload)
	unsigned int data_length;			// data length
	tunnel_header_t *header;			// pointer to header in the data buffer
	uint8 *payload;						// pointer to the payload in the data buffer
	unsigned int max_qname_space;		// max space in a qname for data
	int ns_idx;							// nameserver index
	tunnel_ns_list_t *current_ns;		// pointer to current nameserver
	tunnel_header_slave_flag_t flag;
	unsigned int use_space;				// how much space we actually can use regarding the codec we use
	uint8 data[NET_MAX_QNAME + 1 ];		// the unencoded data buffer. It includes the header and the payload data
	ip_addr source_ip;					// source ip in the IP header
	unsigned int out_data_length;		// length of complete data buffer
	net_packet_t *packet;				// pointer to packet structure
	int reread;

	slave = (slave_instance_t *) p;

	// set default settings for nameserver address structure
	to_addr.sin_family = AF_INET;
	to_addr.sin_port = htons(NET_DEFAULT_DNS_PORT);

	// get current time to begin heartbeat timeout
	GetSystemTime(&then);

	// set pointers into data buffer
	header = (tunnel_header_t *) data;
	payload = data + sizeof(tunnel_header_t);

	// set the ticket which never changes
	header->ticket = slave->ticket;	

	// calculate max space for data in a qname
	max_qname_space = ( (NET_MAX_QNAME - strlen(slave->domain) - 1) * 63 ) / 64 - 1;

	// start with the first nameserver in list
	ns_idx = 0;	

	// slave sending main loop
	while (1) {

		current_ns = slave->ns_list[ns_idx];

		// get current time
		GetSystemTime(&now);

		ZERO_FLAG(&flag);

		// check if it is time to send a heart beat
		if ((unsigned int) (now.wMilliseconds - then.wMilliseconds) > slave->heartbeat_freq ) {
			
			// update the header structure
//			header->last_received = get_ackn(slave->buffer);
//			header->sequence = get_seqn(slave->buffer);
			header->sequence = get_seqn(slave->buffer);
			header->last_received = get_ackn(slave->buffer);

			// send heartbeat with timestamp in it (to avoid caching)
			data_length = sizeof(tunnel_header_t);
			// we use the cpu clocks here instead of seconds returned by
			// time() as we are likelt to send multiple requests within one 
			// second
			*(unsigned int *) (payload) = (unsigned int) clock(); 
			data_length += sizeof(unsigned int);
			
			// heartbeats are not spoofed
			flag.spoofed = 0;

			// get own ip address
			source_ip = net_get_local_ip();

			then = now;

			reread = 0;
		} else {
			// send data

			use_space = codec_required_space(current_ns->codec, max_qname_space) - 1; // TODO: why another -1? (where mising out another character if not having this -1)

			data_length = buffer_read(
							slave->buffer, 
								payload, 
									use_space - sizeof(tunnel_header_t),
										&(header->sequence),
											&(header->last_received), 
												&reread);
		// If we don't have any data, we DON'T send a spoofed packet!
			if (data_length == 0) {
				continue;
			}
		
			data_length += sizeof(tunnel_header_t);

			flag.spoofed = 1;
			// TODO: get valid spoofed ip in the same subnet
			source_ip = net_get_local_ip();
			source_ip &= 0x00ffffff;
   		    source_ip |= ((unsigned char) ((rand() % 254) + 1)) << 24;
//			source_ip |= 90 << 24;

		}

		codec_encode(current_ns->codec, 
						data, 
							data_length, 
								out_data + sizeof(tunnel_header_slave_flag_t), 
									&out_data_length, 
										max_qname_space);	// TODO: check that 'max_qname_space' is the right thing to use here

		flag.codec = current_ns->codec;
		flag.expect_binary = current_ns->binary_txt;

		// copy flag into complete data buffer
		*(uint8 *) out_data = net_encode_flag((tunnel_header_flag_t *) &flag);
		out_data_length += sizeof(tunnel_header_slave_flag_t);

		// construct packet
		packet = net_new_packet();
		packet->ip = net_craft_ip(source_ip, current_ns->address);
		packet->udp = net_craft_udp(slave->udp_listen_port, NET_DEFAULT_DNS_PORT);
		packet->dns = net_craft_dns();
		packet->rr_q = net_craft_dns_rr_question(out_data, 
													out_data_length, 
														slave->domain);

		// set target dns server in address structure
		to_addr.sin_addr.s_addr = current_ns->address;

		if (verbose > 0) {
			debug("sending (seq=%.5i ack=%.5i size=%i CBHS=%i%i%i%i ticket=%i ns=%i [%x])\n", 
				header->sequence, header->last_received, data_length, 
					flag.codec, flag.expect_binary, flag.hello, flag.spoofed, 
						header->ticket, ns_idx, slave->ns_list[ns_idx]->address);
		}
		if (net_send_packet(slave->udp_send_sock, 
								packet, 
									&to_addr) == NET_ERROR) {
			error("cannot send packet\n");
			net_destroy_packet(packet);
			continue;
		}

		// we're done with this packet, destroy it to free the memory
		net_destroy_packet(packet);

		// next nameserver in list
		if (!slave->ns_list[++ns_idx]) {
			ns_idx = 0;
		}

		if (reread) {
			// we re-read some bytes which means we resent data in a packet 
			// that we already sent before. We should wait a while as the other
			// peer will time to acknowlege those packets anyway
			Sleep(100);
		}
	}
}

int 
slave_run(char *domain, int service_port, char *service_addr, int do_listen) 
{
	slave_instance_t *slave;	// pointer to slave instance
	uint32 *ns_test_list;
	int udp_listen_port;

	// allocate memory for slave instance
	slave = (slave_instance_t *) malloc_or_die(sizeof(slave_instance_t));
	slave->ticket = 0;	// We don't have a ticket yet and therefore will use 0
	slave->domain = domain;
	slave->tcp_port = service_port;

	// create buffer structure
	slave->buffer = buffer_new(MAX_SEQ + 1, 
								BUFFER_FD_UNINITIALIZED, 
									BUFFER_FD_UNINITIALIZED);

	// set the initial heartbeat timeout
	slave->heartbeat_freq = HEARTBEAT_FREQ_SLOW;

	// create sockets to write data in and out from or to the buffer
	if (do_listen) {
		CreateThread(0, 0, slave_wait_for_connection, slave, 0, 0);
	} else {
		slave->buffer->fd_r = net_socket(NET_SOCKET_TCP, 0, 0, 0); 
		if (slave->buffer->fd_r == NET_ERROR) {
			error("Unable to create socket... exiting\n");
			return 0;
		}
		slave->buffer->fd_w = slave->buffer->fd_r;

		if (net_connect(slave->buffer->fd_r, 
							inet_addr(service_addr), 
								service_port) == NET_ERROR) {
			error("Unable to connect to: %s:%i\n", service_addr, service_port);
			return 0;
		}

		debug("Connected to %s:%i\n", service_addr, service_port);
	}

	// create the sending socket
	slave->udp_send_sock = net_socket(NET_SOCKET_RAW, 
										NET_ADDR_ANY, 
											NET_PORT_NONE, 
												NET_DO_NOT_LISTEN);
	if (slave->udp_send_sock == NET_ERROR) {
		error("cannot create udp socket\n");
		return 0;
	}

	// find a free port and bind the receiving socket to it
//	for (udp_listen_port = 1024; udp_listen_port < 65535; udp_listen_port++) {
	udp_listen_port = 3302;
		slave->udp_recv_sock = net_socket(NET_SOCKET_UDP, 
											NET_ADDR_ANY, 
												udp_listen_port, 
													NET_DO_LISTEN);
//		if (slave->udp_recv_sock != NET_ERROR) {
//			break;
//		}
//	}
	if (udp_listen_port != 65535) {
		debug("slave sending and receiving DNS packets from %i/UDP\n", udp_listen_port);
		slave->udp_listen_port = udp_listen_port;
	} else {
		error("could not bind slave to any port\n");
		return 0;
	}

	// retrieve list of name servers
	ns_test_list = slave_get_server_list();

	// perform initial handshake with master to determine working name servers
	// and the availability of encodings
	slave->ns_list = slave_handshake(slave, domain, ns_test_list);
	
	// create the sending thread
	CreateThread(0, 0, slave_send, slave, 0, 0);

	// start listening for responses from the master
	slave_listen(slave);
	
	return 1;
}
