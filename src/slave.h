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

#ifndef _SLAVE_H
#define _SLAVE_H

#include "tunnel.h"
#include "buffer.h"

// heartbeat frequency in milliseconds
#define HEARTBEAT_FREQ_SLOW		300 
#define HEARTBEAT_FREQ_FAST		10 

typedef struct _slave_instance_t {
	char *domain;
	uint8 ticket;
	tunnel_ns_list_t **ns_list;
	int udp_send_sock;
	int udp_recv_sock;
	int udp_listen_port;
	unsigned int heartbeat_freq;
	buffer_t * buffer;
	int tcp_port;
} slave_instance_t;

int slave_run(char *domain, int service_port, char *service_addr, int do_listen);


#endif
