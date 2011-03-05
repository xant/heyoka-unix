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
#include <string.h>

#include "codec.h"
#include "util.h"

static const char b32table[] = "abcdefghijklmnopqrstuvwxyz012345";
static const char base32_pad_char = '7';
static signed char base32_dmap[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, 
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
};

static const char base64_charset[] = 
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64_pad_char = '=';
static signed char base64_dmap[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};


unsigned int 
codec_encode(unsigned char codec, unsigned char *input, 
					unsigned int in_len, unsigned char *output, 
							unsigned int *out_len, unsigned int max_out_len)
{
	unsigned int consumed = 0;

	switch(codec) {
		case CODEC_BASE32:
				consumed = codec_base32_encode(input, in_len, 
														output, max_out_len);
				*out_len = strlen(output);
				break;
		case CODEC_BASE64:
				consumed = codec_base64_encode(input, in_len, 
														output, max_out_len);
				*out_len = strlen(output);
				break;
		case CODEC_BINARY:
				consumed = codec_binary_encode(input, in_len, 
												output, out_len, max_out_len);
				break;
//		case CODEC_UTF8:
//				consumed = codec_utf8_encode(input, in_len, output, 
//														out_len, max_out_len);
//				break;
		default:
			error("unknown codec: %.2x\n", codec);
	}

	return consumed;
}

unsigned int 
codec_decode(unsigned char codec, unsigned char *input, 
								unsigned int in_len, unsigned char *output)
{
	unsigned int ret = 0;

	switch(codec) {
		case CODEC_BASE32:
				ret = codec_base32_decode(input, output);
				break;
		case CODEC_BASE64:
				ret = codec_base64_decode(input, output);
				break;
		case CODEC_BINARY:
				ret = codec_binary_decode(input, in_len, output);
				break;
//		case CODEC_UTF8:
//				ret = codec_utf8_decode(input, in_len, output);
//				break;
		default:
			error("unknown codec: %.2x\n", codec);
	}

	return ret;
}



/* 
 * We need the length because the input is binary
 */
unsigned int 
codec_base32_encode(unsigned char *input, unsigned int in_len, 
							unsigned char *output, unsigned int max_out_len)
{
	unsigned char *p = 0;
    unsigned int i = 0, j = 0, mod = 0;
	unsigned int len = 0;

    // calculcate how much space of the available we will use:
	len = max_out_len * 5 / 8;
	// if we don't have enough characters in the input buffer, we will use,
	// what we have
	if (in_len < len) {
		len = in_len;
	}
    p = output;
    mod = len % 5;
    i = 0;
   
    while (i < len - mod) {
        *p++ = b32table[input[i] >> 3];
        *p++ = b32table[(input[i] << 2 | input[i + 1] >> 6) & 0x1f];
        *p++ = b32table[(input[i + 1] >> 1) & 0x1f];
        *p++ = b32table[(input[i + 1] << 4 | input[i + 2] >> 4) & 0x1f];
        *p++ = b32table[(input[i + 2] << 1 | input[i + 3] >> 7) & 0x1f];
        *p++ = b32table[(input[i + 3] >> 2) & 0x1f];
        *p++ = b32table[(input[i + 3] << 3 | input[i + 4] >> 5) & 0x1f];
        *p++ = b32table[input[i + 4] & 0x1f];
        i += 5;
    }

    if (mod == 0) {
        *p = 0;
        return len;
    }
    *p++ = b32table[input[i] >> 3];
    if (mod == 1) {
       *p++ = b32table[(input[i] << 2) & 0x1f];
 		for (j=0;j<6;j++) {
			*p++ = 55;
		}
        *p = 0;
        return len;
    }
    *p++ = b32table[(input[i] << 2 | input[i+1] >> 6) & 0x1f];
    *p++ = b32table[(input[i+1] >> 1) & 0x1f];

    if (mod == 2) {
        *p++ = b32table[(input[i+1] << 4) & 0x1f];
        for (j=0;j<4;j++) {
			*p++ = 55;
        }
        *p = 0;
        return len;
    }
    *p++ = b32table[(input[i+1] << 4 | input[i+2] >> 4) & 0x1f];
    if (mod == 3) {
        *p++ = b32table[(input[i+2] << 1) & 0x1f];
        for (j=0;j<3;j++) {
			*p++ = 55;
		}
        *p = 0;
        return len;
    } 

    *p++ = b32table[(input[i + 2] << 1 | input[i + 3] >> 7) & 0x1f];
    *p++ = b32table[(input[i + 3] >> 2) & 0x1f];
    *p++ = b32table[(input[i + 3] << 3) & 0x1f];
    *p++ = 55;
    *p = 0;   
    return len;
}

unsigned int 
codec_base64_encode(unsigned char *input, unsigned int in_len, 
							unsigned char *output, unsigned int max_out_len) 
{
	unsigned char fragment = 0;
	unsigned int len, consumed;

	// Some more magic 3rd grade math foo: 
	// calculate how much space of the available we will use:
	len = max_out_len * 6 / 8;
	// if we don't have enough characters in the input buffer, we will use,
	// what we have
	if (in_len < len) {
		len = in_len;
	}

	consumed = len;

	for (; len >= 3; len -= 3) {
		*output++ = base64_charset[input[0] >> 2];
		*output++ = base64_charset[((input[0] << 4) & 0x30) | (input[1] >> 4)];
		*output++ = base64_charset[((input[1] << 2) & 0x3c) | (input[2] >> 6)];
		*output++ = base64_charset[input[2] & 0x3f];
		input += 3;
    }

    if (len > 0) {
		*output++ = base64_charset[input[0] >> 2];
		fragment = (input[0] << 4) & 0x30;
		if (len > 1) {
		    fragment |= input[1] >> 4;
		}
		*output++ = base64_charset[fragment];
		*output++ = (len < 2) ? '=' : base64_charset[(input[1] << 2) & 0x3c];
		*output++ = '=';
    }
    *output = '\0';

	return consumed;
}

unsigned int 
codec_base32_decode(unsigned char *input, unsigned char *output)
{
    unsigned int i = 0, j = 0;
    unsigned char c = 0;
    char dbytes[5], ebytes[8];
    unsigned int len = 0;

    for (i = 0; i < strlen(input); i += 8) {
    	for (j = 0; j < 8; j++) {
    	    c = (unsigned char) input[i + j];
	        ebytes[j] = ((c == base32_pad_char) ? 0 : base32_dmap[c]);
	    }

	    // decode bytes
    	dbytes[0] = ((ebytes[0] << 3) & 0xf8) | ((ebytes[1] >> 2) & 0x07);
    	dbytes[1] = ((ebytes[1] & 0x03) << 6) 
						| ((ebytes[2] & 0x1f) << 1) | ((ebytes[3] >> 4) & 1);
	    dbytes[2] = ((ebytes[3] & 0x0f) << 4) | ((ebytes[4] >> 1) & 0x0f);
	    dbytes[3] = ((ebytes[4] & 1) << 7) 
					  | ((ebytes[5] & 0x1f) << 2) | ((ebytes[6] >> 3) & 0x03);
    	dbytes[4] = ((ebytes[6] & 0x07) << 5) | (ebytes[7] & 0x1f);

	    // copy bytes over into destination buffer
    	for (j = 0; j < sizeof(dbytes); j++) {
    	    *output++ = (unsigned char) dbytes[j];
	        len++;
	    }
    }
    return len;
}

unsigned int 
codec_base64_decode(unsigned char *input, unsigned char *output)
{
   unsigned int chunk = 0, chars = 0, len = 0;
   unsigned char *org = 0;

   org = output;
   chunk = 0;
   chars = 0;

   while (*input) {
       if (*input == base64_pad_char) {
           break;
       }
	   chars++;
       if (*input > 0 && base64_dmap[*input] != -1) {
           chunk |= base64_dmap[*input];
           if (chars == 4) {
               *output++ = chunk >> 16;
               *output++ = (chunk >> 8) & 0x00ff;
			   *output++ = chunk & 0x00ff;
			   chunk = 0;
               chars = 0;
			   len += 3;
           } else {
               chunk <<= 6;
			   
           }
       }
       input++;
   }

   switch(chars) {
       case 2:
           *output++ = chunk >> 10;
		   len++;
           break;
       case 3:
           *output++ = chunk >> 16;
           *output++ = (chunk >> 8) & 0x0ff;
		   len += 2;          
           break;
   }
   return len;
}

unsigned int 
codec_binary_encode(unsigned char *input, unsigned int in_len, 
							unsigned char *output, unsigned int *out_len, 
													unsigned int max_out_len)
{
	
	if (max_out_len > in_len) {
		memcpy(output, input, in_len);
		*out_len = in_len;
		return in_len;
	} else {
		memcpy(output, input, max_out_len);
		*out_len = max_out_len;
		return max_out_len;
	}
}

unsigned int 
codec_binary_decode(unsigned char *input, unsigned int in_len, 
													unsigned char *output)
{
	memcpy(output, input, in_len);

	return in_len;
}

unsigned int 
codec_required_space(int codec, int length)
{
	int ret = 0;

	switch (codec) {
		case CODEC_BASE32:
				ret = (unsigned int)((length * 5) / 8);
				break;
		case CODEC_BINARY:
				ret = length;
				break;
		case CODEC_BASE64:
				ret = (unsigned int)((length * 6) / 8);
				break;
		default:
				error("unknown codec: %.2x\n", codec);
	
	}

	return ret;
}

/*
unsigned int 
codec_utf8_encode(unsigned char *input, unsigned int in_len, 
							unsigned char *output, unsigned int *out_len, 
													unsigned int max_out_len)
{
	unsigned int consumed = 0;

	*out_len = 0;

	for (consumed = 0; (consumed < in_len) 
									&& (consumed < max_out_len); consumed++) {
		if(*input < 128) {
			*output++ = *input;				
			(*out_len)++;
		} else {
			if (consumed < max_out_len - 1) {
				*output++ = (*input >> 6) | 0xc0;
				*output++ = (*input & 0x3F) | 0x80;
				(*out_len) += 2;
			} else {
				break;
			}
		}
		input++;
	}

	return consumed;
}

unsigned int 
codec_utf8_decode(unsigned char *input, unsigned int in_len, 
														unsigned char *output)
{
	unsigned int l = 0;
	unsigned int len;

	len = 0;

	for (l = 0; l < in_len; l++) {
		if (*input >= 0xc0) {
			*output = ((*input - 0xc0) << 6) | (*(input + 1) - 0x80);
			*input++;
		} else {
			*output = *input++;
		}

		len++;
	}

	return len;
}
*/
