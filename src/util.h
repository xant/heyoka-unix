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

#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdarg.h>

void	debug(const char *format, ...);
void	error(const char *format, ...);
void	warning(const char *format, ...);
void	out(const char *format, ...);
void	hexdump(const char *label, const unsigned char *data, const unsigned int length);
void heapdump( void );

void    *malloc_or_die(size_t size);

#ifndef __WIN32__
#define Sleep sleep
#endif

#endif
