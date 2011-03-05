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

#ifndef ALT_BUFFER_H
#define ALT_BUFFER_H

#include "types.h"

#define BUFFER_ERROR		-1

#define is_inbetween_with_rollover(start,val,end,mod) (end % mod > start % mod ?							\
											((val % mod >= start % mod && val % mod <= end % mod) ? 1 : 0)	\
										 :																	\
										    ((val % mod >= start % mod || val % mod <= end % mod) ? 1 : 0))

#define delta_with_rollover(start,end,mod)		( (end % mod >= start % mod) ? (end % mod - start % mod) : (mod - start % mod + end % mod) )

#define increment_with_rollover(lval,rval,max)	(lval = (lval + rval) % max)

typedef struct _alt_buffer_t {
	unsigned int ackn;
	unsigned int seqn;

	uint8 *read_data;
	uint8 *write_data;
	uint8 *write_map;

	unsigned int size;					// total size of buffer	
	
	unsigned int read_window_size;		// size of window
	unsigned int read_window_start;		// start position of read window
	unsigned int read_window_end;		// end position of read window
	
	/*
	 * although the read window is set, it does not mean that it is actually 
	 * filled with data waiting to be read. Hence read_start and read_end which
	 * indicate to what extend the window is filled with data (e.g. read_end
	 * is the last byte in the window that contains data
	 */
	unsigned int read_start;			// position of first byte in read buffer
	unsigned int read_end;				// position of last byte in read buffer
	unsigned int read_pos;				// position in read buffer (= seqn for sending)
	
	unsigned int write_window_size;		// size of window
	unsigned int write_window_start;	// start position of current window (= ackn in sent packet)
	unsigned int write_window_end;		// end position of current window
	
	int write_fd;
	int read_fd;

	unsigned int same_ack_counter;
	unsigned int max_same_ack;
} alt_buffer_t;


#define alt_get_seqn(buffer) buffer->read_pos
#define alt_get_ackn(buffer) buffer->write_window_start

alt_buffer_t*alt_buffer_new(unsigned int size, int fd_r, int fd_w);

/* write data to buffer and flush data to file when possible 
   returns the number of bytes actually written to the file descriptor */
int			 alt_buffer_write(alt_buffer_t *buffer, uint8 *data, int length, unsigned int seqn, unsigned int ackn);

/* read data from buffer and refill buffer from file if necessary 
   returns the number of bytes read. data, seqn and ackn are all output variables */
int			 alt_buffer_read(alt_buffer_t *buffer, uint8 *data, unsigned int length, unsigned int *seqn, unsigned int *ackn);

#endif