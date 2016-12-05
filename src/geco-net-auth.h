///* $Id$
// *
// * MD5 hash calculation
// * Copyright (C) 1991-1992 RSA Data Security, Inc.
// *
// * This library is free software: you can redistribute it and/or modify it
// * under the terms of the GNU Lesser General Public License as published by
// * the Free Software Foundation, either version 2.1 of the License, or
// * (at your option) any later version.
// *
// * This library is distributed in the hope that it will be useful,
// * but WITHOUT ANY WARRANTY; without even the implied warranty of
// * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// * GNU General Public License for more details.
// *
// * You should have received a copy of the GNU Lesser General Public License
// * along with this program.  If not, see <http://www.gnu.org/licenses/>.
// */
//
///******************************************************************
// License to copy and use this software is granted provided that it
// is identified as the "RSA Data Security, Inc. MD5 Message-Digest
// Algorithm" in all material mentioning or referencing this software
// or this function.
//
// License is also granted to make and use derivative works provided
// that such works are identified as "derived from the RSA Data
// Security, Inc. MD5 Message-Digest Algorithm" in all material
// mentioning or referencing the derived work.
//
// RSA Data Security, Inc. makes no representations concerning either
// the merchantability of this software or the suitability of this
// software for any particular purpose. It is provided "as is"
// without express or implied warranty of any kind.
//
// These notices must be retained in any copies of any part of this
// documentation and/or software.
// *******************************************************************/
//
#ifndef MY_MD5_H_
#define MY_MD5_H_

#include <string>
#include <iostream>
#include "geco-common.h"

/**
* CRC32Ϊ32bit�ļ�hash��MD5Ϊ128bit�ϸ��ӵ�hash�㷨��
* ֱ����ò��CRC32�ļ����ٶ�Ҫ��MD5��ġ�
* ������FlexHEX������ļ���hashʱ����CRC32���MD5��û���������ơ�
* ʵ�鷢�֣�Linux����ϵͳ����md5sum��cksumȡ�ļ���ϣ��MD5������CRC32ʱ���72%���ҡ�
* MD5�����ٶ�Ҫ��������CRC32��
* SHAϵ���㷨��ժҪ���ȷֱ�Ϊ��
* SHAΪ20�ֽڣ�160λ����SHA256Ϊ32�ֽڣ�256λ, SHA384Ϊ48�ֽڣ�384λ����SHA512Ϊ64�ֽڣ�512λ����
* ����������������ժҪ�ĳ��ȸ�������˸����Է�����ײ�����Ҳ��Ϊ��ȫ������δ������ժҪ�㷨�ķ�չ����
* ����SHAϵ���㷨������ժҪ���Ƚϳ�������������ٶ���MD5��ȣ�Ҳ��Խ�����
* ĿǰSHA1��Ӧ�ý�Ϊ�㷺����ҪӦ����CA������֤���У�
* ������Ŀǰ�����������е�BT����У�Ҳ��ʹ��SHA1�������ļ�У��ġ�
*/
#define  MD5_HMAC
#undef   SHA20_HMAC
#undef   SHA32_HMAC
#undef   SHA48_HMAC
#undef   SHA64_HMAC

#if defined(MD5_HMAC)
#define  HMAC_LEN   16 /* 16 bytes == 128 Bits == 4 doublewords */
#elif defined(SHA20_HMAC)
#define  HMAC_LEN   20 /* 20 bytes == 160 Bits == 5 doublewords */
#elif defined(SHA32_HMAC)
#define  HMAC_LEN   32
#elif defined(SHA48_HMAC)
#define  HMAC_LEN   48
#elif defined(SHA64_HMAC)
#define  HMAC_LEN   64
#endif

#define SECRET_KEYSIZE  4096
#define KEY_INIT     0
#ifndef KEY_READ
#define KEY_READ     1
#endif
#define MAX_DEST    16

extern void (*gset_checksum)(char *buffer, int length);
extern int (*gvalidate_checksum)(char *buffer, int length);

extern int validate_md5_checksum(char *buffer, int length);
extern void set_md5_checksum(char *buffer, int length);

extern void set_crc32_checksum(char *buffer, int length);
extern int validate_crc32_checksum(char* buffer, int len);

extern uint generate_random_uint32();
extern const char* hexdigest(uchar data[], int lenbytes);
extern uchar* get_secre_key(int operation_code);

/* PROTOTYPES should be set to one if and only if the compiler supports
function argument prototyping.
The following makes PROTOTYPES default to 0 if it has not already
been defined with C compiler flags.
*/
/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;
/* UINT2 defines a two byte word */
typedef unsigned short UINT2;
/* UINT4 defines a four byte word */
typedef unsigned int UINT4;
/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
returns an empty list.
*/
/* MD5 context. */
typedef struct
{
    UINT4 state[4]; /* state (ABCD) */
    UINT4 count[2]; /* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64]; /* input buffer */
} MD5_CTX;
extern void MD5Init(MD5_CTX *);
extern void MD5Update(MD5_CTX *, unsigned char * src, unsigned int len);
extern void MD5Final(unsigned char dest_digest[16], MD5_CTX * ctx);
extern unsigned int generate_md5_checksum(const void *data, int length);
#endif

