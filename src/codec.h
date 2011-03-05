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

#ifndef _CODEC_H
#define _CODEC_H

#define CODEC_BASE32	0x0
//#define CODEC_UTF8	0x1		// we don't use utf8 anymore
#define CODEC_BINARY	0x1
#define CODEC_BASE64	0x2

/* 
 * Each codec comes with a encoding and a decoding function.
 * The encoding function (wrapped by 'codec_encode') expects the input and 
 * output buffer plus parameters that indicate eithers length and an 
 * additional parameter that states how much space is left in the output 
 * buffer. The function returns the number of bytes that were actually 
 * consumed from the input buffer.
 *
 * As for the decoding fuction, it only expects input and output buffer plus 
 * the length of the input buffer. The return value is the length of the 
 * decoded data.
 */
unsigned int codec_encode(unsigned char codec, unsigned char *input, 
							unsigned int in_len, unsigned char *output, 
							 unsigned int *out_len, unsigned int max_out_len);

unsigned int codec_decode(unsigned char codec, unsigned char *input, 
								unsigned int in_len, unsigned char *output);


unsigned int codec_base32_encode(unsigned char *input, unsigned int in_len, 
												unsigned char *output, 
													unsigned int max_out_len);
unsigned int codec_base32_decode(unsigned char *input, unsigned char *output);

unsigned int codec_base64_encode(unsigned char *input, unsigned int in_len, 
												unsigned char *output, 
													unsigned int max_out_len);
unsigned int codec_base64_decode(unsigned char *input, unsigned char *output);

//unsigned int codec_utf8_encode(unsigned char *input, unsigned int in_len, 
//											unsigned char *output, 
//												unsigned int *out_len, 
//													unsigned int max_out_len);
//unsigned int codec_utf8_decode(unsigned char *input, 
//											unsigned int in_len, 
//												   unsigned char *output);

unsigned int codec_binary_encode(unsigned char *input, unsigned int in_len, 
											unsigned char *output, 
												unsigned int *out_len, 
													unsigned int max_out_len);
unsigned int codec_binary_decode(unsigned char *input, 
											unsigned int in_len, 
														unsigned char *output);

#define codec_name(idx)	(idx == CODEC_BASE32 ? "BASE32" : \
							(idx == CODEC_BINARY ? "BINARY" : \
								(idx == CODEC_BASE64 ? "BASE64" : \
									"{invalid codec}" \
								) \
							) \
						)

unsigned int codec_required_space(int codec, int length);


#endif

