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

#ifndef _BUFFER_H
#define _BUFFER_H

#ifdef __WIN32__
#include <windows.h>
#else
#include <pthread.h>
#define CRITICAL_SECTION pthread_mutex_t
#endif

#include "types.h"

#define MAX_EQ_ACKS			3

#define BUFFER_ERROR		-1
#define BUFFER_NO_DATA		-2

#define BUFFER_FD_UNINITIALIZED		-1

#define get_seqn(buffer) buffer->seqn_s
#define get_ackn(buffer) buffer->ackn_s


typedef struct _buffer_t {
	unsigned int size;

	// buffer_write() area 
	uint16 ackn_r; // ackn received
	uint16 ack_r_counter; // This counts how many equal acks we can receive before retransmitting 
	uint8 *data_write; // buffer of data to write into fd
	uint8 *map_write;  // map of data received in the buffer
	int fd_w; // file descriptor to write to

	// buffer_read() area
	uint16 seqn_s; // seqn to send
	uint16 ackn_s; // ackn to send 
	unsigned int endbuf; // position in the read buffer where to add data from fd_r 
	uint8 *data_read; // buffer of data to read from fd
	int fd_r; // file descriptor to read from

	CRITICAL_SECTION lock;
} buffer_t;

/* allocate and initialize a new buffer structure */
buffer_t	*buffer_new(unsigned int size, int fd_r, int fd_w);

/* write data to buffer and flush data to file when possible 
   returns the number of bytes actually written to the file descriptor */
int			 buffer_write(buffer_t *buffer, uint8 *data, unsigned int length, uint16 seqn, uint16 ackn);

/* read data from buffer and refill buffer from file if necessary 
   returns the number of bytes read. data, seqn and ackn are all output variables */
int			 buffer_read(buffer_t *buffer, uint8 *data, unsigned int length, uint16 * seqn, uint16 * ackn, int *reread);

void	buffer_get_status(buffer_t *buffer, uint16 *ackn, uint16 *seqn);
#endif

