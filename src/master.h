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

#ifndef _SERVER_H
#define _SERVER_H

#include "types.h"
#include "buffer.h"

typedef struct _master_slave_tracker_t {
#ifdef __WIN32__
	SYSTEMTIME last_used;
#else
        struct timeval last_used;
#endif
	uint8 ticket;
	char *domain;
	buffer_t *buffer;
	int tcp_port;

} master_slave_tracker_t;

int master_run(int listen_port, char *domain, uint16 port, int do_listen);

#endif
