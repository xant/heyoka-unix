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

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "net.h"
#include "master.h"
#include "slave.h"
#include "util.h"

#define MODE_MASTER 0
#define MODE_SLAVE 1

int verbose = 0;
char release[20] = "0.1.2-alpha";

void 
usage(char *path)
{
	out("\n%s %s\n(c) 2009 icesurfer & nico - Published under GNU GPL\n\n", path, release);
	out(" Options:\n");
	out("  -m           : run as master (default)\n");
	out("  -s           : run as slave\n");
	out("  -d domain    : domain name for dns requests (required)\n");
	out("  -p port      : TCP port to use\n");
	out("  -l           : listen on local port, instead of connecting\n");
	out("  -v			: verbose output (-v -v -v = debug)\n");
}

int main(int argc, char **argv)
{

	int retval;
	int o;
	int mode = MODE_MASTER;
	char domain[NET_MAX_QNAME];
	WSADATA wsaData;
	uint16 port;
	int do_listen;

	if ((retval = WSAStartup(0x202, &wsaData)) != 0) {
        error("Server: WSAStartup() failed with error %d\n", retval);
        WSACleanup();
        return -1;
    }
	
	*domain = 0;
	do_listen = 0;
	port = 0;

	for (o = 1; o < argc; o++) {
      if (*argv[o] == '-') {
          switch(argv[o][1]) {
				case 'h':
                      usage(*argv);
                      return 0;
				case 'd':
                      if (o + 1 < argc) {
						  strncpy(domain, argv[++o], NET_MAX_QNAME - 1);
                      }
                      break;
				case 'p':
					port = (uint16)atoi(argv[++o]);
					if ((port<1) || (port>65535)) {
						  port = 3389;
					}
					break;
				case 'l':
					do_listen = 1;
					break;
				case 'm':
					mode= MODE_MASTER;
					break;
				case 's':
					mode = MODE_SLAVE;
					break;
				case 'v':
					verbose++;
					break;
				default:
                      printf("ignoring unrecognized option -%c\n", o);
			}
		}
    } 

	if (mode == MODE_SLAVE) {
		printf("[DEBUG] Starting client mode...\n");
		slave_run(domain, port, "127.0.0.1", do_listen);
	} else {
		printf("[DEBUG] Starting server mode...\n");
		master_run(NET_DEFAULT_DNS_PORT, domain, port, do_listen);
	}

	return 0;
}