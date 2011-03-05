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

#include <windows.h>

#include "buffer.h"
#include "util.h"
#include "global.h"
#include "net.h"

extern int verbose;

static int 
is_inbetween(int start, int val, int end, int mod)
{
	start %= mod;
	end %= mod;
	val %= mod;

/*	if (end > start) {
		if (val >= start && val <= end) {
			return 1;
		}
	} else {
		if (val >= start || val <= end) {
			return 1;
		}
	}*/

	return ((end > start) ^ (val >= start) ^ (val <= end));
}

static unsigned int 
delta(int start, int end, int mod)
{
	start %= mod;
	end %= mod;

	if (end >= start) {
		return end - start;
	}
	
	return mod - start + end;
}

buffer_t *
buffer_new(unsigned int size, int fd_r, int fd_w)
{
	buffer_t *buffer;

	buffer = (buffer_t *) malloc_or_die(sizeof(buffer_t));
	buffer->size = size;

	// buffer_write() area  
	buffer->ackn_r = MAX_SEQ; 
	buffer->ack_r_counter = 0;
	buffer->data_write = (uint8 *) malloc_or_die(size);
	buffer->map_write = (uint8 *) malloc_or_die(size);
	memset(buffer->map_write, 0, size);
	buffer->fd_w = fd_w; 

	// buffer_read() area
	buffer->seqn_s = 0; 
	buffer->ackn_s = MAX_SEQ; 
	buffer->endbuf = 0; // Where to write from fd to read buffer 
	buffer->data_read = (uint8 *) malloc_or_die(size);
	buffer->fd_r = fd_r; // file descriptor to read from

	InitializeCriticalSection(&(buffer->lock));

	return buffer;
}

/*
 * This function is called whenever a packet is received. 
 *	N.B.: all operations are done modulo MAX_SEQ+1, because all counters go from 0 to MAX_SEQ, assuming therefore MAX_SEQ+1 values
*/
int
buffer_write(buffer_t *buffer, uint8 *data, unsigned int length, uint16 seqn, uint16 ackn)
{
	unsigned int i;
	unsigned int pos = 0; // data position in the buffer
	unsigned int pos_start; // initial position from where to write to fd-w
	unsigned int nbytes = 0; // number of bites written to fd-w
	uint16 ackn_s;

	if (!buffer) {
		printf("buffer error\n");
		return BUFFER_ERROR;
	}

	EnterCriticalSection(&(buffer->lock));
	// Some data has been acknowledged since last packet?
	if ( (buffer->ackn_r == ackn) 	
			// is there actually data waiting to be ack'd?
			&&  (buffer->seqn_s != ((buffer->ackn_r + 1) % (MAX_SEQ + 1)))) {	
		// still the same data to acknowledge. We might need to retransmit
		buffer->ack_r_counter++; 
	} else {
		// some data has been ackowledged.... update ackn_r
		buffer->ackn_r = ackn; 
		// and reset the counter. No need to retransmit here
		buffer->ack_r_counter = 0; 
	}
	ackn_s = buffer->ackn_s;
	LeaveCriticalSection(&(buffer->lock));

	// If the packet had no data, we could return...
	if (length > 0) {

		// Check that at least 1 of the received bytes is inside the interval and set pos accordingly to start copying bytes from there
		// The check assumes that RECV_BUFFER_SIZE > length (which is obviously true, unless one fucks up with constants)
		if (is_inbetween(ackn_s + 1, seqn, (uint16)(ackn_s + RECV_BUFFER_SIZE), buffer->size)) {
			pos = seqn % buffer->size;	// we start to write from where `seqn' is
		} else {
			if (is_inbetween(ackn_s + 1, seqn + length, ackn_s + RECV_BUFFER_SIZE, buffer->size)) {
				pos_start = (ackn_s + 1) % buffer->size;
				if (seqn > pos_start) {
					length -= seqn - pos_start;
				} else {
					length -= pos_start - seqn;
				}	
				pos = pos_start;
				// as the bytes will be copied at the beginning of the window, 
				// we'll not copy so much data that we're in danger to overwrite the end of the window
			} else {
				return 0;
			}
		}

		for (i = 0; (i < length) && ((pos + i) != (ackn_s + RECV_BUFFER_SIZE)); i++) {
			buffer->data_write[(pos + i) % buffer->size] = data[i];
			buffer->map_write[(pos + i) % buffer->size] = 1;
		}
	}
	
	if (buffer->fd_w == -1) {
		if (verbose > 0) {
			debug("writing FD not ready yet\n");
		}
		return 0;
	}


	// find how many bytes we're going to write to the file descriptor
	pos_start = (ackn_s + 1) % buffer->size;
	pos = pos_start;
	for (nbytes = 0; nbytes < buffer->size; nbytes++) {
		if (!(buffer->map_write[pos])) {
			break;
		}
		pos = (pos + 1) % buffer->size;
	}


	// write the data out (this has to be done in two steps if the section of 
	// data is split over the 'edge' of the buffer)
	if ((pos_start + nbytes) > buffer->size) {
		// it's split into two parts. We'll write to the end of the buffer and 
		// then reset the position pointer in order to continue writing from
		// the beginning of the buffer
		send(buffer->fd_w, buffer->data_write + pos_start, buffer->size - pos_start, 0);
		memset(buffer->map_write + pos_start, 0x00, buffer->size - pos_start);
		nbytes -= buffer->size - pos_start;
		pos_start = 0;
		//buffer->ackn_s = MAX_SEQ;	// replaced with vvv
		ackn_s = MAX_SEQ;
	}

	// can simply be written out
	send(buffer->fd_w, buffer->data_write + pos_start , nbytes, 0);
	memset(buffer->map_write + pos_start, 0x00, nbytes);

	// update the ack#
	EnterCriticalSection(&(buffer->lock));
	buffer->ackn_s = (ackn_s + nbytes) % (MAX_SEQ + 1); //buffer->size
	if (verbose > 2) {
		printf("buffer.c: wrote %i bytes (ackn was %i is now: %i)\n", nbytes, ackn_s, buffer->ackn_s);
	}
	LeaveCriticalSection(&(buffer->lock));
	
	return nbytes;
}

int	
buffer_read(buffer_t *buffer, uint8 *data, unsigned int length, uint16 *seqn, uint16 *ackn, int *reread)
{
	unsigned int pos; 
	unsigned int nbytes; //bytes returned
	unsigned int i;
	uint16 ackn_r;
	uint16 ackn_s;
	unsigned int ack_r_counter;

	if (!buffer) {
		return BUFFER_ERROR;
	}

	EnterCriticalSection(&(buffer->lock));
	ackn_r = buffer->ackn_r;
	ackn_s = buffer->ackn_s; 
	ack_r_counter = buffer->ack_r_counter;
	LeaveCriticalSection(&(buffer->lock));

	if (reread) {
		*reread = 0;
	}
	
	if (verbose > 1) {
		printf("buffer.c: buffer->ackn_r:%u buffer->seqn_s:%u\n",buffer->ackn_r,buffer->seqn_s);
	}
	if ((delta(ackn_r, buffer->seqn_s, buffer->size) > SEND_BUFFER_SIZE) || // if window is full...
		(ack_r_counter >= MAX_EQ_ACKS)) {		// ...or we received MAX_EQ_ACKS equal acks
		// we retransmit the first unacknowledged byte
		// find the first byte to copy
		pos = (ackn_r + 1) % buffer->size;
		for (nbytes = 0; nbytes < length 
							// && nbytes < SEND_BUFFER_SIZE // Oh, come on.... useless!
							//	&& (((pos + nbytes) % buffer->size) < buffer->endbuf); nbytes++) { //// WRONG!!!!!!!!!!!!
								&& (nbytes < delta(pos, buffer->endbuf, buffer->size)); nbytes++) { // Correct when rolling over
			data[nbytes] = buffer->data_read[(pos + nbytes) % buffer->size];
		}
		*seqn = (ackn_r + 1) % buffer->size;
		*ackn = (ackn_s);
		if (reread) {
			*reread = 1;
		}
	//	printf("we retransmit %i bytes starting from %i\n",nbytes,pos);
		return nbytes;

	} else {
		// if we can't get enough data from the buffer, we'll fill it up again
		if (verbose > 2) {
			printf("buffer.c: I REQUIRE %i bytes there are %i\n", length, delta((ackn_r % buffer->size), buffer->endbuf, buffer->size));
		}
		if (delta(ackn_r, buffer->endbuf, buffer->size) < length) {
			// read from fd and copy to data, up to the end of the buffer
			/*
			NIL:
				Is here a flaw?
					Assumption: 
						buffer->size = 65535
						buffer->endbuf = 65500
						buffer->size - buffer->endbuf = 35

						=> It'll write 35 bytes into the buffer and endbuf == size
						=> buffer->endbuf = (buffer->endbuf + i) % buffer->size = 0;
			*/

			if (buffer->fd_r > 0) {
				i = net_read(buffer->fd_r, buffer->data_read + buffer->endbuf, buffer->size - buffer->endbuf, 0, 100); // 10 milliseconds, TODO: tune this!
			} else {
				*seqn = buffer->seqn_s;
				*ackn = ackn_s;
				return 0; // the socket hasn't been created yet
			}
			if (i > 0) {
				buffer->endbuf = (buffer->endbuf + i) % buffer->size; // it could wrap exactly to 0
				//TODO: what's this for? vvvvv
				// Again, if we wrapped around but still need data
	//			if ((buffer->endbuf == 0) 
	//					&& (delta((ackn_r % buffer->size), 0, buffer->size) < length)) {
	//				// read from fd and copy to data, up to the beginning of unacknowledged data
	//				i = net_read(buffer->fd_r, buffer->data_read, (ackn_r % buffer->size) - 1, 0, 10); // 10 milliseconds, TODO: tune this!
	//				if (i > 0) {
	//					buffer->endbuf += i; // no risk of wrapping around here
	//				}
	//			}
			}
		}	

		// Now we finally copy into the buffer
		i = delta(buffer->seqn_s, buffer->endbuf, buffer->size);
		*seqn = buffer->seqn_s;
		for (nbytes = 0; nbytes < length && nbytes < i; nbytes++) {
			data[nbytes] = buffer->data_read[(buffer->seqn_s + nbytes) % buffer->size];
		}
		buffer->seqn_s = (buffer->seqn_s + nbytes) % (MAX_SEQ + 1);

		*ackn =ackn_s;
		
		return nbytes;
	}
}
