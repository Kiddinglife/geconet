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
///* PROTOTYPES should be set to one if and only if the compiler supports
// function argument prototyping.
// The following makes PROTOTYPES default to 0 if it has not already
// been defined with C compiler flags.
// */
#ifndef MY_MD5_H_
#define MY_MD5_H_

#include <string>
#include <iostream>
#include "basic-type.h"

/**
* CRC32为32bit的简单hash，MD5为128bit较复杂的hash算法。
* 直觉上貌似CRC32的计算速度要比MD5快的。
* 今天用FlexHEX计算大文件的hash时发现CRC32相对MD5并没有明显优势。
* 实验发现：Linux操作系统下用md5sum和cksum取文件哈希：MD5仅花费CRC32时间的72%左右。
* MD5计算速度要明显优于CRC32！
* SHA系列算法的摘要长度分别为：
* SHA为20字节（160位）、SHA256为32字节（256位, SHA384为48字节（384位）、SHA512为64字节（512位），
* 由于它产生的数据摘要的长度更长，因此更难以发生碰撞，因此也更为安全，它是未来数据摘要算法的发展方向。
* 由于SHA系列算法的数据摘要长度较长，因此其运算速度与MD5相比，也相对较慢。
* 目前SHA1的应用较为广泛，主要应用于CA和数字证书中，
* 另外在目前互联网中流行的BT软件中，也是使用SHA1来进行文件校验的。
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


extern int set_crc32_checksum(char *buffer, int length);
extern uchar* key_operation(int operation_code);
extern int validate_crc32_checksum(char* buffer, int len);
extern uint generate_random_uint32();


// a small class for calculating MD5 hashes of strings or byte arrays
// it is not meant to be fast or secure
//
// usage: 
//      1) MD5 obj; 
//      2) obj.update()
//      2) obj.finalize()
//      3) obj.hexdigest() 
//      or
//      MD5(std::string).hexdigest()
//
// assumes that char is 8 bit and int is 32 bit
class MD5
{
    public:
    typedef unsigned int size_type; // must be 32bit

    MD5();
    MD5(const std::string& text);
    void init();
    void update(const unsigned char *buf, size_type length);
    void update(const char *buf, size_type length);
    MD5& finalize();
    std::string hexdigest() const;
    friend std::ostream& operator<<(std::ostream&, MD5 md5);

    unsigned char* Digest() const { return (unsigned char*)digest; }

    private:
    typedef unsigned char uint1; //  8bit
    typedef unsigned int uint4;  // 32bit
    enum { blocksize = 64 }; // VC6 won't eat a const static int here

    void transform(const uint1 block[blocksize]);
    static void decode(uint4 output[], const uint1 input[], size_type len);
    static void encode(uint1 output[], const uint4 input[], size_type len);

    bool finalized;
    uint1 buffer[blocksize]; // bytes that didn't fit in last 64 byte chunk
    uint4 count[2];   // 64bit counter for number of bits (lo, hi)
    uint4 state[4];   // digest so far
    uint1 digest[16]; // the result

    // low level logic operations
    static inline uint4 F(uint4 x, uint4 y, uint4 z);
    static inline uint4 G(uint4 x, uint4 y, uint4 z);
    static inline uint4 H(uint4 x, uint4 y, uint4 z);
    static inline uint4 I(uint4 x, uint4 y, uint4 z);
    static inline uint4 rotate_left(uint4 x, int n);
    static inline void FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
    static inline void GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
    static inline void HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
    static inline void II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
};
std::string md5(const std::string str);
#endif

