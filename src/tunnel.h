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

#ifndef _TUNNEL_H
#define _TUNNEL_H

#include <windns.h>
#include <string.h>

#include "types.h"
#include "codec.h"

/*
 * The list of flags used either by client sending to the server
 * or the server sending to the client. The flags inidcate the packet
 * type and the encoding used for the payload.
 */
#define	FLAG_PAYLOAD				0x01	
#define	FLAG_NO_PAYLOAD				0x00

#define	FLAG_DATA_PACKET			0x02	
#define	FLAG_HELLO_PACKET			0x00

/* client to server only */
#define	FLAG_BASE32					CODEC_BASE32
//#define	FLAG_UTF8					(CODEC_UTF8	  << 2)
#define	FLAG_BINARY					CODEC_BINARY
// BASE64 encoding is not used not used by client
//#define	FLAG_BASE64				(CODEC_BASE64 << 2)	

#define	FLAG_SPOOFED				0x10
#define	FLAG_NOT_SPOOFED			0x00

/* server to client only */
#define	FLAG_MORE_DATA_COMING		0x00
#define	FLAG_NO_MORE_DATA_COMING	0x10

#pragma pack (1)
typedef struct _tunnel_header_slave_flag_t {
	unsigned char spoofed:1;		// spoofed (1) packet or non-spoofed (0)
	unsigned char codec:1;			// base32 (CODEC_BASE32) or binary (CODEC_BINARY) encoding
	unsigned char hello:1;			// data (0) or hello/communication (1) packet
	unsigned char expect_binary:1;	// server must send binary data in answer
	unsigned char control:1;		// 1 = this is a control packet
	unsigned char zero:3;			// bits that are not going to be used!
} tunnel_header_slave_flag_t;
#pragma pack ()

#pragma pack (1)
typedef struct _tunnel_header_master_flag_t {
	unsigned char more_data:1;		// there's more data coming from the server
	unsigned char hello_reply:1;	// reply to a hello message, of course
	unsigned char binary_txt:1;		// The TXT response is binary (1) or base64 (0)
	unsigned char control:1;		// 1 = this is a control packet
	unsigned char zero:3;			// bits that are not going to be used!
} tunnel_header_master_flag_t;
#pragma pack ()

#pragma pack (1)
typedef struct _tunnel_header_flag_t {
	union {
		tunnel_header_slave_flag_t slave;
		tunnel_header_master_flag_t master;
	} un;
} tunnel_header_flag_t;
#pragma pack ()

#define ZERO_FLAG(flag) memset(flag, 0x00, sizeof(tunnel_header_flag_t))

#pragma pack (1)
typedef struct _tunnel_header_t {
	uint8 ticket; 
	uint16 sequence;
	uint16 last_received;
} tunnel_header_t;
#pragma pack ()

typedef struct _tunnel_ns_list_t {
	uint32 address;
	uint8 codec;
	uint8 binary_txt;
	uint8 resource; // 1: TXT 2: NULL 3: BOTH
	uint8 nullsize; // Bytes per NULL response
} tunnel_ns_list_t;




#define TEST_DATA	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"	\
					"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"	\
					"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"	\
					"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
#define TEST_DATA_SIZE		(4 * 16)
#define TEST_DATA_RESPONSE TEST_DATA_REQUEST
#define DNS_MAX_SERVER_LIST_SIZE	(8 * sizeof(IP4_ADDRESS))

uint32				*tunnel_get_server_list();
tunnel_ns_list_t	**tunnel_test_server_list(uint32 *ns_list, uint8 *ticket, char *domain);

#endif
