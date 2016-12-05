/*
 converted to C++ class by Frank Thilo (thilo@unix-ag.org)
 for bzflag (http://www.bzflag.org)

 based on:
 md5.h and md5.c
 reference implemantion of RFC 1321

 Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 rights reserved.

 License to copy and use this software is granted provided that it
 is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 Algorithm" in all material mentioning or referencing this software
 or this function.

 License is also granted to make and use derivative works provided
 that such works are identified as "derived from the RSA Data
 Security, Inc. MD5 Message-Digest Algorithm" in all material
 mentioning or referencing the derived work.

 RSA Data Security, Inc. makes no representations concerning either
 the merchantability of this software or the suitability of this
 software for any particular purpose. It is provided "as is"
 without express or implied warranty of any kind.

 These notices must be retained in any copies of any part of this
 documentation and/or software.

 */

 /* system implementation headers */
#include <stdio.h>
#include "geco-net-auth.h"
#include "geco-net-common.h"

void(*gset_checksum)( char*, int ) = &set_md5_checksum;
int(*gvalidate_checksum)( char*, int ) = &validate_md5_checksum;

/* Constants for MD5Transform routine.
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21
static void MD5Transform(UINT4[4], unsigned char[64]);
static void Encode(unsigned char *, UINT4 *, unsigned int);
static void Decode(UINT4 *, unsigned char *, unsigned int);
static unsigned char PADDING[64] =
{ 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
 /* ROTATE_LEFT rotates x left n bits.
  */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
  /* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
   Rotation is separate from addition to prevent recomputation.
   */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
   /* MD5 initialization. Begins an MD5 operation, writing a new context.
    */
void MD5Init(MD5_CTX *context)
{
    context->count[0] = context->count[1] = 0;
    /* Load magic initialization constants.
     */
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}
/* MD5 block update operation. Continues an MD5 message-digest
 operation, processing another message block, and updating the
 context.
 */
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputLen)
{
    unsigned int i, index, partLen;
    /* Compute number of bytes mod 64 */
    index = (unsigned int) ( ( context->count[0] >> 3 ) & 0x3F );
    /* Update number of bits */
    if( ( context->count[0] += ( (UINT4) inputLen << 3 ) )
        < ( (UINT4) inputLen << 3 ) ) context->count[1]++;
    context->count[1] += ( (UINT4) inputLen >> 29 );
    partLen = 64 - index;
    /* Transform as many times as possible.  */
    if( inputLen >= partLen )
    {
        memcpy((POINTER) &context->buffer[index], (POINTER) input, partLen);
        MD5Transform(context->state, context->buffer);

        for( i = partLen; i + 63 < inputLen; i += 64 )
            MD5Transform(context->state, &input[i]);

        index = 0;
    } else
        i = 0;
    /* Buffer remaining input */
    memcpy((POINTER) &context->buffer[index], (POINTER) &input[i],
        inputLen - i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
 the message digest and zeroizing the context.
 */
void MD5Final(unsigned char digest[16], MD5_CTX *context)
{
    unsigned char bits[8];
    unsigned int index, padLen;
    /* Save number of bits */
    Encode(bits, context->count, 8);
    /* Pad out to 56 mod 64.
     */
    index = (unsigned int) ( ( context->count[0] >> 3 ) & 0x3f );
    padLen = ( index < 56 ) ? ( 56 - index ) : ( 120 - index );
    MD5Update(context, PADDING, padLen);
    /* Append length (before padding) */
    MD5Update(context, bits, 8);
    /* Store state in digest */
    Encode(digest, context->state, 16);
    /* Zeroize sensitive information.
     */
    memset((POINTER) context, 0, sizeof(*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform(UINT4 state[4], unsigned char block[64])
{
    UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    Decode(x, block, 64);
    /* Round 1 */
    FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
    FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */
    /* Round 2 */
    GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */
    /* Round 3 */
    HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
    HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */
    /* Round 4 */
    II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
    II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    /* Zeroize sensitive information.  */
    memset((POINTER) x, 0, sizeof(x));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
 a multiple of 4.
 */
static void Encode(unsigned char *output, UINT4 *input, unsigned int len)
{
    unsigned int i, j;
    for( i = 0, j = 0; j < len; i++, j += 4 )
    {
        output[j] = (unsigned char) ( input[i] & 0xff );
        output[j + 1] = (unsigned char) ( ( input[i] >> 8 ) & 0xff );
        output[j + 2] = (unsigned char) ( ( input[i] >> 16 ) & 0xff );
        output[j + 3] = (unsigned char) ( ( input[i] >> 24 ) & 0xff );
    }
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
 a multiple of 4.
 */
static void Decode(UINT4 *output, unsigned char *input, unsigned int len)
{
    unsigned int i, j;
    for( i = 0, j = 0; j < len; i++, j += 4 )
        output[i] = ( (UINT4) input[j] ) | ( ( (UINT4) input[j + 1] ) << 8 )
        | ( ( (UINT4) input[j + 2] ) << 16 )
        | ( ( (UINT4) input[j + 3] ) << 24 );
}

// return hex representation of digest as string
const char* hexdigest(uchar data[ ], int lenbytes)
{
    static char buf[1024];
	memset(buf, 0, 1024);
    for( int i = 0; i < lenbytes; i++ )
        sprintf(buf + i * 2, "%02x", data[i]);
    buf[lenbytes * 2] = 0;
    return buf;
}

//std::ostream& operator<<(std::ostream& out, MD5 md5)
//{
//    return out << md5.hexdigest();
//}

#define BASE 65521L             /* largest prime smaller than 65536 */

/* Example of the crc table file */
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])
static uint crc_c[256] =
{ 0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F, 0x35F1141C,
        0x26A1E7E8, 0xD4CA64EB, 0x8AD958CF, 0x78B2DBCC, 0x6BE22838,
        0x9989AB3B, 0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
        0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B, 0xD7C45070,
        0x25AFD373, 0x36FF2087, 0xC494A384, 0x9A879FA0, 0x68EC1CA3,
        0x7BBCEF57, 0x89D76C54, 0x5D1D08BF, 0xAF768BBC, 0xBC267848,
        0x4E4DFB4B, 0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
        0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35, 0xAA64D611,
        0x580F5512, 0x4B5FA6E6, 0xB93425E5, 0x6DFE410E, 0x9F95C20D,
        0x8CC531F9, 0x7EAEB2FA, 0x30E349B1, 0xC288CAB2, 0xD1D83946,
        0x23B3BA45, 0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
        0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A, 0x7DA08661,
        0x8FCB0562, 0x9C9BF696, 0x6EF07595, 0x417B1DBC, 0xB3109EBF,
        0xA0406D4B, 0x522BEE48, 0x86E18AA3, 0x748A09A0, 0x67DAFA54,
        0x95B17957, 0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
        0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198, 0x5125DAD3,
        0xA34E59D0, 0xB01EAA24, 0x42752927, 0x96BF4DCC, 0x64D4CECF,
        0x77843D3B, 0x85EFBE38, 0xDBFC821C, 0x2997011F, 0x3AC7F2EB,
        0xC8AC71E8, 0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
        0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096, 0xA65C047D,
        0x5437877E, 0x4767748A, 0xB50CF789, 0xEB1FCBAD, 0x197448AE,
        0x0A24BB5A, 0xF84F3859, 0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45,
        0x3FD5AF46, 0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
        0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6, 0xFB410CC2,
        0x092A8FC1, 0x1A7A7C35, 0xE811FF36, 0x3CDB9BDD, 0xCEB018DE,
        0xDDE0EB2A, 0x2F8B6829, 0x82F63B78, 0x709DB87B, 0x63CD4B8F,
        0x91A6C88C, 0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
        0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043, 0xCFB5F4A8,
        0x3DDE77AB, 0x2E8E845F, 0xDCE5075C, 0x92A8FC17, 0x60C37F14,
        0x73938CE0, 0x81F80FE3, 0x55326B08, 0xA759E80B, 0xB4091BFF,
        0x466298FC, 0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
        0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033, 0xA24BB5A6,
        0x502036A5, 0x4370C551, 0xB11B4652, 0x65D122B9, 0x97BAA1BA,
        0x84EA524E, 0x7681D14D, 0x2892ED69, 0xDAF96E6A, 0xC9A99D9E,
        0x3BC21E9D, 0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
        0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D, 0x758FE5D6,
        0x87E466D5, 0x94B49521, 0x66DF1622, 0x38CC2A06, 0xCAA7A905,
        0xD9F75AF1, 0x2B9CD9F2, 0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE,
        0xEC064EED, 0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
        0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F, 0x49547E0B,
        0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF, 0x8ECEE914, 0x7CA56A17,
        0x6FF599E3, 0x9D9E1AE0, 0xD3D3E1AB, 0x21B862A8, 0x32E8915C,
        0xC083125F, 0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
        0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90, 0x9E902E7B,
        0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F, 0xE330A81A, 0x115B2B19,
        0x020BD8ED, 0xF0605BEE, 0x24AA3F05, 0xD6C1BC06, 0xC5914FF2,
        0x37FACCF1, 0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
        0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E, 0xF36E6F75,
        0x0105EC76, 0x12551F82, 0xE03E9C81, 0x34F4F86A, 0xC69F7B69,
        0xD5CF889D, 0x27A40B9E, 0x79B737BA, 0x8BDCB4B9, 0x988C474D,
        0x6AE7C44E, 0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351, };
static uint generate_crc32c(char *buffer, int length)
{
    unsigned char byte0, byte1, byte2, byte3, swap;
    uint crc32 = ~0L;
    int i;

    for( i = 0; i < length; i++ )
    {
        CRC32C(crc32, buffer[i]);
    }
    crc32 = ~crc32;
    /* do the swap */
    byte0 = (unsigned char) crc32 & 0xff;
    byte1 = (unsigned char) ( crc32 >> 8 ) & 0xff;
    byte2 = (unsigned char) ( crc32 >> 16 ) & 0xff;
    byte3 = (unsigned char) ( crc32 >> 24 ) & 0xff;
    swap = byte0;
    byte0 = byte3;
    byte3 = swap;
    swap = byte1;
    byte1 = byte2;
    byte2 = swap;
    crc32 = ( ( byte3 << 24 ) | ( byte2 << 16 ) | ( byte1 << 8 ) | byte0 );

    return crc32;

}
unsigned int generate_md5_checksum(const void *data, int length)
{
    unsigned int digest[4];
    unsigned int val;
    MD5_CTX ctx;
    MD5Init(&ctx);
    MD5Update(&ctx, (unsigned char *) data, length);
    MD5Final((unsigned char *) digest, &ctx);
    val = digest[0] ^ digest[1] ^ digest[2] ^ digest[3];
    return val;
}

int validate_md5_checksum(char *buffer, int length)
{
    /* save and zero checksum */
    geco_packet_t *message = (geco_packet_t *) buffer;
    uint original_md5 = ntohl(message->pk_comm_hdr.checksum);
    EVENTLOG1(VERBOSE, "DEBUG Validation : original_md5 == %x", original_md5);
    message->pk_comm_hdr.checksum = 0;
    uint md5checksum = generate_md5_checksum(buffer, length);
    EVENTLOG1(VERBOSE, "DEBUG Validation : md5checksum == %x", md5checksum);
    return ( ( original_md5 == md5checksum ) ? 1 : 0 );
}
void set_md5_checksum(char *buffer, int length)
{
    /* check packet length */
    geco_packet_t *message = (geco_packet_t *) buffer;
    message->pk_comm_hdr.checksum = 0L;
    uint md5checksum = generate_md5_checksum(buffer, length);
    message->pk_comm_hdr.checksum = htonl(md5checksum);
}
int validate_crc32_checksum(char *buffer, int length)
{
    geco_packet_t *message;
    uint original_crc32;
    uint crc32 = ~0;

    /* save and zero checksum */
    message = (geco_packet_t *) buffer;
    original_crc32 = ntohl(message->pk_comm_hdr.checksum);
    message->pk_comm_hdr.checksum = 0;
    crc32 = generate_crc32c(buffer, length);
    return ( ( original_crc32 == crc32 ) ? 1 : 0 );
}
void set_crc32_checksum(char *buffer, int length)
{
    geco_packet_t *message;
    uint crc32c;
    message = (geco_packet_t *) buffer;
    message->pk_comm_hdr.checksum = 0L;
    crc32c = generate_crc32c(buffer, length);
    message->pk_comm_hdr.checksum = htonl(crc32c);
}
uchar* get_secre_key(int operation_code)
{
    static bool init = false;
	static uchar secret_key[SECRET_KEYSIZE] = {0};
    if( !init )
    {
        uint count = 0, tmp;
        while( count < SECRET_KEYSIZE )
        {
            /* if you care for security, you need to use a cryptographically secure PRNG */
            tmp = generate_random_uint32();
            memcpy(&secret_key[count], &tmp, sizeof(uint));
            count += sizeof(uint);
        }
		assert(count == SECRET_KEYSIZE);
        init = true;
    }
    return secret_key;

    //static uchar *secret_key = NULL;
    //if( secret_key == NULL )
    //{
    //    uint tmp = generate_random_uint32();
    //    uint count = 0, tmp;
    //    secret_key = (unsigned char*) malloc(SECRET_KEYSIZE);
    //    while( count < 1 )
    //    {
    //        /* if you care for security, you need to use a cryptographically secure PRNG */
    //        tmp = generate_random_uint32();
    //        memcpy((char*)&secret_key[count], (char*)&tmp, sizeof(uint));
    //        count += sizeof(uint);
    //    }
    //} else
    //{
    //    return secret_key;
    //}
}

uint generate_random_uint32()
{
    //// create default engine as source of randomness
    //std::default_random_engine dre;
    //// use engine to generate integral numbers between 10 and 20 (both included)
    //const  int maxx = std::numeric_limits<int>::max();
    //std::uniform_int_distribution<int> di(10, 20);
    //return 0;
    return (unsigned int) rand();
}
