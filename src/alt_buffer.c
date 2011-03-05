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

#include <stdlib.h>
#include <string.h>
#ifdef __WIN32__
#include <windows.h>
#endif

#include "alt_buffer.h"
#include "util.h"
#include "global.h"
#include "net.h"


alt_buffer_t *
alt_buffer_new(unsigned int size, int fd_r, int fd_w)
{
	alt_buffer_t *buffer;

	buffer = (alt_buffer_t *) malloc_or_die(sizeof(alt_buffer_t));
	buffer->size = size;

	buffer->read_data = (uint8 *) malloc_or_die(size);
	buffer->write_data = (uint8 *) malloc_or_die(size);
	buffer->write_map = (uint8 *) malloc_or_die(size);
	memset(buffer->write_map, 0x00, size);
	
	buffer->read_window_size = RECV_BUFFER_SIZE;
	buffer->read_window_start = 0;
	buffer->read_window_end = RECV_BUFFER_SIZE;
	buffer->read_pos = 0;
	buffer->read_start = 0;
	buffer->read_end = 0;

	buffer->write_window_size = SEND_BUFFER_SIZE;
	buffer->write_window_start = 0;
	buffer->write_window_end = SEND_BUFFER_SIZE;

	buffer->write_fd = fd_w;
	buffer->read_fd = fd_r;

	buffer->ackn = MAX_SEQ;
	buffer->seqn = 0;

	buffer->same_ack_counter = 0;
	buffer->max_same_ack = 16; // TODO: define

	return buffer;
}

/*
BUFFER_WRITE: 

	Map the sequence number to find where in the buffer the data goes to

	If ack is in reading window and (writing position is in writing window or writing position + length is in window) 
		Update the reading window and the ackn

		While MAP says there's space at `pos' and there's more space in window
			add data to buffer
			update map
		Done
		
		Empty buffer and update writing window
	Done
*/
int
alt_buffer_write(alt_buffer_t *buffer, uint8 *data, int length, unsigned int seqn, unsigned int ackn)
{
	unsigned int pos;
	int consumed_bytes = -1;
	unsigned int w, flushed_bytes;
	uint8 *temp;
	
	if (!buffer || !data) {
		return BUFFER_ERROR;
	}

	// if ackn is the same as the last already received then increase the counter of same ack numbers
	if (ackn == buffer->ackn) {
		buffer->same_ack_counter++;
	} else {
		// update ack number

		// reset same ack counter
		buffer->same_ack_counter = 0;
	}

	// return if there's no data to write
	if (!length) {
		return 0;
	}
	
	// Check that at least 1 of the received bytes is inside the interval (return if not)
	if (!is_inbetween_with_rollover(buffer->read_window_start, seqn, buffer->read_window_end, buffer->size) 
			&& !is_inbetween_with_rollover(buffer->read_window_start, seqn + length, buffer->read_window_end, buffer->size) ) {
		return 0;
	}

	// Update the reading window and the ack# (TODO: add a lock as it is used in the buffer_read function?!)
	increment_with_rollover(
						buffer->read_window_end, 
							delta_with_rollover(buffer->read_window_start, ackn, buffer->size), 
								buffer->size);
	buffer->read_window_start = ackn;
	increment_with_rollover(
						buffer->read_window_start, 
							1, 
								buffer->size);
	buffer->ackn = ackn;

	// Map the sequence number to find where in the buffer the data goes to
	pos = seqn % buffer->size;

	/*
	 * the first byte of our data is not necessarily in the window. We'll have
	 * to find the first byte that goes in our window. The cases are the following:
     *
	 *  a) pos is outside of the window before write_window_start, which means
	 *     write_window_start is the first byte to write
	 *		We can easily verify that by swapping start and end of the window
	 *      in an inbetween macro call: inbetween(end, value, start)
	 *  b) pos is between write_window_start and write_window_end, which means
	 *     we can write from pos
	 *
	 */
	
	// Case a) pos outside, before window start
	if (is_inbetween_with_rollover(buffer->read_window_end, seqn, buffer->read_window_start, buffer->size)) {
		pos = buffer->read_window_start;
	}
	// Case b) (has not to be done as pos stays the same

	// While MAP says there's space at `pos' and there's more space in window
	for (consumed_bytes = 0; 
			consumed_bytes < length 
				&& pos != buffer->write_window_end
					&& !buffer->write_map[pos]; 
				consumed_bytes++) {
		buffer->write_data[pos] = data[consumed_bytes];
		buffer->write_map[pos] = 0x01;
		increment_with_rollover(pos, 1, buffer->size);
	}

	
	temp = (uint8*) malloc_or_die(buffer->write_window_size);
	flushed_bytes = 0;
	// Empty buffer where possible
	for (w = buffer->write_window_start, flushed_bytes = 0; 
			w != buffer->write_window_end && buffer->write_map[w] && flushed_bytes < buffer->write_window_size; 
				increment_with_rollover(w, 1, buffer->size), flushed_bytes++) {
		temp[flushed_bytes] = buffer->write_data[w];
		buffer->write_map[w] = 0x00;			
	}
	// update write window
	increment_with_rollover(buffer->write_window_start, flushed_bytes, buffer->size);
	increment_with_rollover(buffer->write_window_end, flushed_bytes, buffer->size);

	// write data out
	net_write(buffer->write_fd, temp, flushed_bytes);
	
	free(temp);
	
	return consumed_bytes;
}

/*
BUFFER_READ:

TODO:
	out:ackn, seqn

1:	If there's enough data left in the read buffer to satisfy `length'
		If we still can read more data from the window
			read data to the end of window or until `length' is satisfied
		Else
			Go back to beginning of window and return data from there (== resend)
		Done
	Else
		Read more data in and go back to 1
	End

*/
int	
alt_buffer_read(alt_buffer_t *buffer, uint8 *data, unsigned int length, unsigned int *seqn, unsigned int *ackn)
{	
	int consumed_bytes;
	unsigned int *pos, temp_pos;
	unsigned int read_more_bytes;
	unsigned int read_bytes, r;
	uint8 *temp;
	
printf("A\n");
	if (!buffer || !data) {
		return BUFFER_ERROR;
	}

printf("B\n");
	do {
		printf("C: %i %i %i %i %i\n", buffer->read_pos, buffer->read_window_end, buffer->size, length, delta_with_rollover(buffer->read_pos, buffer->read_end, buffer->size));
		// check if there's enough data left in the read buffer to satisfy `length'
		if (delta_with_rollover(buffer->read_pos, buffer->read_end, buffer->size) >= length) {
			printf("C.2\n");
			// check if we still can read more data from the window and that the ack in the last received packets was not the same
			if (delta_with_rollover(buffer->read_pos, buffer->read_window_end, buffer->size) >= length
					&& buffer->same_ack_counter != buffer->max_same_ack) {
				// read data to the end of window or until `length' is satisfied
				pos = &(buffer->read_pos);
			} else {
				// Go back to beginning of window and return data from there (== resend)
				temp_pos = buffer->read_window_start;
				pos = &temp_pos;
			}
			// copy data into data buffer
			printf("C.3\n");
			for (consumed_bytes = 0; consumed_bytes < length && *pos != buffer->read_window_end; consumed_bytes++) {
				data[consumed_bytes] = buffer->read_data[*pos + consumed_bytes];
				increment_with_rollover(*pos, 1, buffer->size);
			}
			printf("C.4\n");
		} else {
			printf("D\n");
			// Fill buffer up with data from `fd' and then try to read again
			read_more_bytes = buffer->size - delta_with_rollover(buffer->read_start, buffer->read_end, buffer->size);
			temp = (uint8 *) malloc_or_die(read_more_bytes);
			read_bytes = net_read(buffer->read_fd, temp, read_more_bytes, 0, 10);
			printf("D.2: %i\n", read_bytes);
			// if there's no data, then we don't need to bother and try to read again: Hence, break out of the loop
			if (!read_bytes) {
				consumed_bytes = 0;
			} else {
				printf("READ SOME BYTES: %i\n", read_bytes);
				system("pause");
				for (r = 0; r < read_bytes; r++) {
					buffer->read_data[buffer->read_end] = temp[r];
					increment_with_rollover(buffer->read_end, 1, buffer->size);
				}
				// go back up
				consumed_bytes = -1;
			}
			free(temp);
		}
	} while (consumed_bytes == -1);
printf("E\n");
//	Sleep(200);
	printf("CONSUMED BYTES: %i\n", consumed_bytes);
	return consumed_bytes;
}
