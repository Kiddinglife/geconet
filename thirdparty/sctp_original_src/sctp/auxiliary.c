/* $Id: auxiliary.c 2771 2013-05-30 09:09:07Z dreibh $
 * --------------------------------------------------------------------------
 *
 *           //=====   //===== ===//=== //===//  //       //   //===//
 *          //        //         //    //    // //       //   //    //
 *         //====//  //         //    //===//  //       //   //===<<
 *              //  //         //    //       //       //   //    //
 *       ======//  //=====    //    //       //=====  //   //===//
 *
 * -------------- An SCTP implementation according to RFC 4960 --------------
 *
 * Copyright (C) 2000 by Siemens AG, Munich, Germany.
 * Copyright (C) 2001-2004 Andreas Jungmaier
 * Copyright (C) 2004-2013 Thomas Dreibholz
 *
 * Acknowledgements:
 * Realized in co-operation between Siemens AG and the University of
 * Duisburg-Essen, Institute for Experimental Mathematics, Computer
 * Networking Technology group.
 * This work was partially funded by the Bundesministerium fuer Bildung und
 * Forschung (BMBF) of the Federal Republic of Germany
 * (Förderkennzeichen 01AK045).
 * The authors alone are responsible for the contents.
 *
 * This library is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contact: sctp-discussion@sctp.de
 *          dreibh@iem.uni-due.de
 *          tuexen@fh-muenster.de
 *          andreas.jungmaier@web.de
 */

#include "auxiliary.h"
#include "globals.h"
#include "sctp.h"
#include "adaptation.h"

#include <stdio.h>

#define BASE 65521L             /* largest prime smaller than 65536 */
#define NMAX 5552
#define NMIN 16

/* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */

#define DO1(buf,i)  {s1 += buf[i]; s2 += s1;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

/* Example of the crc table file */

#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])

uint32_t crc_c[256] =
{
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
    0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
    0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
    0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
    0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
    0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
    0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
    0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
    0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
    0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
    0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
    0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
    0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
    0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
    0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
    0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
    0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
    0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
    0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
    0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
    0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
    0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
    0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
    0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
    0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
    0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
    0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
    0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
    0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
    0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
    0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
    0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
    0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
};

static int insert_adler32(unsigned char *buffer, int length);
static int insert_crc32(unsigned char *buffer, int length);
static int validate_adler32(unsigned char *header_start, int length);
static int validate_crc32(unsigned char *buffer, int length);


static int (*insert_checksum) (unsigned char* buffer, int length) = insert_crc32;
static int (*validate_checksum) (unsigned char* buffer, int length) = validate_crc32;


static uint32_t sctp_adler32(uint32_t adler, const unsigned char *buf, unsigned int len);


int set_checksum_algorithm(int algorithm){
    if (algorithm == SCTP_CHECKSUM_ALGORITHM_CRC32C) {
        insert_checksum =  &insert_crc32;
        validate_checksum =  &validate_crc32;
        return SCTP_SUCCESS;
    } else if (algorithm == SCTP_CHECKSUM_ALGORITHM_ADLER32) {
        insert_checksum =  &insert_adler32;
        validate_checksum =  &validate_adler32;
        return SCTP_SUCCESS;
    } else
        return -1;
}


unsigned char* key_operation(int operation_code)
{
    static unsigned char *secret_key = NULL;
    uint32_t              count = 0, tmp;

    if (operation_code == KEY_READ) return secret_key;
    else if (operation_code == KEY_INIT) {
        if (secret_key != NULL) {
            error_log(ERROR_MAJOR, "tried to init secret key, but key already created !");
            return secret_key;
        }
        secret_key = (unsigned char*)malloc(SECRET_KEYSIZE);
        while (count < SECRET_KEYSIZE){
            /* if you care for security, you need to use a cryptographically secure PRNG */
            tmp = adl_random();
            memcpy(&secret_key[count], &tmp, sizeof(uint32_t));
            count += sizeof(uint32_t);
        }
    } else {
        error_log(ERROR_MAJOR, "unknown key operation code !");
        return NULL;
    }
    return secret_key;
}

int aux_insert_checksum(unsigned char *buffer, int length)
{
    return ((*insert_checksum)(buffer,length));
}


static int insert_adler32(unsigned char *buffer, int length)
{
    SCTP_message *message;
    uint32_t      a32;
    /* save crc value from PDU */
    if (length > NMAX || length < NMIN)
        return -1;
    message = (SCTP_message *) buffer;
    message->common_header.checksum = htonl(0L);

    /* now compute the thingie */
    /* FIXME : sanity checks for size etc. */
    a32 = sctp_adler32(1, buffer, length);

    /* and insert it into the message */
    message->common_header.checksum = htonl(a32);

    event_logi(VERBOSE, "DEBUG Validation : Inserting adler32 == %x", a32);

    return 1;
}

static uint32_t generate_crc32c(unsigned char *buffer, int length)
{
    unsigned char byte0, byte1, byte2, byte3, swap;
    uint32_t      crc32 = ~0L;
    int           i;

    for (i = 0; i < length; i++)
    {
      CRC32C(crc32, buffer[i]);
    }
    crc32 =~ crc32;
    /* do the swap */
    byte0 = (unsigned char) crc32 & 0xff;
    byte1 = (unsigned char) (crc32>>8) & 0xff;
    byte2 = (unsigned char) (crc32>>16) & 0xff;
    byte3 = (unsigned char) (crc32>>24) & 0xff;
    swap = byte0; byte0 = byte3; byte3 = swap;
    swap = byte1; byte1 = byte2; byte2 = swap;
    crc32 = ((byte3 << 24)|(byte2 << 16)|(byte1 << 8)| byte0);

    return crc32;

}

static int insert_crc32(unsigned char *buffer, int length)
{
    SCTP_message *message;
    uint32_t      crc32c;

    /* check packet length */
    if (length > NMAX  || length < NMIN)
      return -1;

    message = (SCTP_message *) buffer;
    message->common_header.checksum = 0L;
    crc32c =  generate_crc32c(buffer, length);
    /* and insert it into the message */
    message->common_header.checksum = htonl(crc32c);

   return 1;
}


int validate_size(unsigned char *header_start, int length)
{
    if ((length % 4) != 0L)
        return 0;
    if (length > NMAX  || length < NMIN)
        return 0;
    return 1;
}



static int validate_adler32(unsigned char *header_start, int length)
{
    SCTP_message *message;
    uint32_t      old_crc32;
    uint32_t      a32;

    /* save crc value from PDU */
    message = (SCTP_message *) header_start;
    old_crc32 = ntohl(message->common_header.checksum);

    event_logi(VVERBOSE, "DEBUG Validation : old adler == %x", old_crc32);

    message->common_header.checksum = htonl(0L);

    /* now compute the thingie */
    a32 = sctp_adler32(1, header_start, length);

    event_logi(VVERBOSE, "DEBUG Validation : my adler32 == %x", a32);
    if (a32 == old_crc32)  return 1;
    return 0;
}

static int validate_crc32(unsigned char *buffer, int length)
{
    SCTP_message *message;
    uint32_t      original_crc32;
    uint32_t      crc32 = ~0;

    /* check packet length */

    /* save and zero checksum */
    message = (SCTP_message *) buffer;
    original_crc32 = ntohl(message->common_header.checksum);
    event_logi(VVERBOSE, "DEBUG Validation : old crc32c == %x", original_crc32);
    message->common_header.checksum = 0;
    crc32 = generate_crc32c(buffer, length);
    event_logi(VVERBOSE, "DEBUG Validation : my crc32c == %x", crc32);

    return ((original_crc32 == crc32)? 1 : 0);
}



int validate_datagram(unsigned char *buffer, int length)
{
    /* sanity check for size (min,max, multiple of 32 bits) */
    if (!validate_size(buffer, length))
        return 0;
    if (!(*validate_checksum)(buffer, length))
        return 0;
    /* FIXME :  validation is not yet complete */
    return 1;
}

/**
 * adler32.c -- compute the Adler-32 checksum of a data stream
 * Copyright (C) 1995-1996 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 * available, e.g. from  http://www.cdrom.com/pub/infozip/zlib/
 */
static uint32_t sctp_adler32(uint32_t adler, const unsigned char *buf, unsigned int len)
{
    uint32_t s1 = adler & 0xffff;
    uint32_t s2 = (adler >> 16) & 0xffff;
    int      k;

    if (buf == NULL)
        return 1L;

    while (len > 0) {
        k = len < NMAX ? len : NMAX;
        len -= k;
        while (k >= 16) {
            DO16(buf);
            buf += 16;
            k -= 16;
        }
        if (k != 0)
            do {
                s1 += *buf++;
                s2 += s1;
            }
            while (--k);
        s1 %= BASE;
        s2 %= BASE;
    }
    return (s2 << 16) | s1;
}
