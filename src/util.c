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
#include <stdarg.h>
#include <stdio.h>
#include <windows.h>
#include <malloc.h>

#include "util.h"


void
debug(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	printf("[DEBUG]: ");
	vfprintf(stderr, format, args);
	va_end(args);
}

void
error(const char *format, ...)
{
	char buffer[256];
	va_list args;

	va_start(args, format);
	printf("[ERROR]: ");
	vfprintf(stderr, format, args);
	if (WSAGetLastError() != 0) {
		FormatMessage(
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				0, WSAGetLastError(), 0, buffer, 255, 0);
		printf("[ERROR]: %s (%i)\n", buffer, WSAGetLastError());
	}
	va_end(args);
}

void
warning(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	printf("[WARNING]: ");
	vfprintf(stderr, format, args);
	va_end(args);
}

void
out(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
}


void 
hexdump(const char *label, const unsigned char *data,
												const unsigned int length)
{
        unsigned int i = 0;
        char line[16 * 3 + 1];
        char hrline[16 * 3 + 1];
        char hex[4];
        
        out("%s (%i bytes):\n", label, length);
        
        line[0] = '\0';
        hrline[0] = '\0';
        for (i = 1; i <= length; i++) {
                sprintf(hex, "%.2X ", data[i - 1]);
                strcat(line, hex);
                if (data[i - 1] >= 33 && data[i - 1] <= 126) {
                    strncat(hrline, data + (i - 1), 1);
                } else {
                    strcat(hrline, ".");
                }
                if (i % 16 == 0) {
                        out("%s   %s\n", line, hrline);
                        line[0] = '\0';
                        hrline[0] = '\0';
                }
        }
        out("%s   %s\n", line, hrline);
}

void *
malloc_or_die(size_t size)
{
	void *ptr;

	ptr = (void *) malloc (size);

	if (!ptr) {
		error("out of memory; could not allocate %u bytes\n", size);
		exit(-1);
	}

	memset(ptr, 0x00, size);

	return ptr;
}

// http://msdn.microsoft.com/en-us/library/h0c183dk(VS.71).aspx
void heapdump( void )
{
   _HEAPINFO hinfo;
   int heapstatus;

   hinfo._pentry = NULL;

   do {
	   heapstatus = _heapwalk( &hinfo );
	   switch( heapstatus ) {
		   case _HEAPBADPTR:
			  printf( "ERROR - bad pointer to heap\n" );
  			  printf( "%6s block at %Fp of size %4.4X\n",
					( hinfo._useflag == _USEDENTRY ? "USED" : "FREE" ),
					hinfo._pentry, hinfo._size );
			  break;
		   case _HEAPBADBEGIN:
			  printf( "ERROR - bad start of heap\n" );
  			  printf( "%6s block at %Fp of size %4.4X\n",
					( hinfo._useflag == _USEDENTRY ? "USED" : "FREE" ),
					hinfo._pentry, hinfo._size );
			  break;
		   case _HEAPBADNODE:
			  printf( "ERROR - bad node in heap\n" );
  			  printf( "%6s block at %Fp of size %4.4X\n",
					( hinfo._useflag == _USEDENTRY ? "USED" : "FREE" ),
					hinfo._pentry, hinfo._size );
			  break;
		}  
   } while (heapstatus == _HEAPOK);

}