/* $Id: messages.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef MESSAGES_H
#define MESSAGES_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#ifdef  STDC_HEADERS
    #include <sys/types.h>
    #include <sys/socket.h>
#endif

#include <glib.h>


#define  MD5_HMAC   1
#define  HMAC_LEN   16          /* 16 bytes == 128 Bits == 4 doublewords */
#undef   SHA_HMAC


/**************************** SCTP common message definitions *********************************/

#ifdef SCTP_OVER_UDP
/* #define SCTP_OVER_UDP_UDPPORT 9899 */
/* #warning Using SCTP over UDP! */
typedef struct UDP_HEADER {
   gushort src_port;
   gushort dest_port;
   gushort length;
   gushort checksum;
} udp_header;
#endif


#define MAX_MTU_SIZE              1500
#define IP_HEADERLENGTH             20

/**
 * the common header, maybe we need to check for sizes of types on 64 bit machines
 * for now assume that "unsigned short" has 16 bits ! (Bft: short is always 16 Bit
 *                                                     32: int and long are 32
 *                                                     64: int is 32, long is 64)
 */
typedef struct SCTP_COMMON_HEADER
{
    gushort src_port;
    gushort dest_port;
    guint32 verification_tag;
    guint32 checksum;
}
SCTP_common_header;

/*
 * max. SCTP-datagram length without common header
 */
#define MAX_SCTP_PDU   (MAX_MTU_SIZE - IP_HEADERLENGTH - sizeof(SCTP_common_header))


/*
 * A general struct for an SCTP-message
 */
typedef struct SCTP_MESSAGE
{
    SCTP_common_header common_header;
    guchar sctp_pdu[MAX_SCTP_PDU];
}
SCTP_message;


/**************************** SCTP chunk definitions ******************************************/

/*--------------------------- chunk types ----------------------------------------------------*/
/*      See section 3.2                                                                       */
/*--------------------------------------------------------------------------------------------*/

#define CHUNK_DATA              0x00
#define CHUNK_INIT              0x01
#define CHUNK_INIT_ACK          0x02
#define CHUNK_SACK              0x03
#define CHUNK_HBREQ             0x04
#define CHUNK_HBACK             0x05
#define CHUNK_ABORT             0x06
#define CHUNK_SHUTDOWN          0x07
#define CHUNK_SHUTDOWN_ACK      0x08
#define CHUNK_ERROR             0x09
#define CHUNK_COOKIE_ECHO       0x0A
#define CHUNK_COOKIE_ACK        0x0B
#define CHUNK_ECNE              0x0C
#define CHUNK_CWR               0x0D
#define CHUNK_SHUTDOWN_COMPLETE 0x0E

#define CHUNK_FORWARD_TSN       0xC0
#define CHUNK_ASCONF            0xC1
#define CHUNK_ASCONF_ACK        0x80

#define STOP_PROCESSING(chunk_id)               (((guint8)chunk_id & 0xC0)==0x00))
#define STOP_PROCESSING_WITH_ERROR(chunk_id)    (((guint8)chunk_id & 0xC0)==0x40))
#define SKIP_CHUNK(chunk_id)                    (((guint8)chunk_id & 0xC0)==0x80))
#define SKIP_CHUNK_WITH_ERROR(chunk_id)         (((guint8)chunk_id & 0xC0)==0xC0))

/*--------------------------- common chunk header -------------------------------------------*/

typedef struct SCTP_CHUNK_HEADER
{
    guint8 chunk_id;            /* e.g. CHUNK_DATA etc. */
    guint8 chunk_flags;         /* usually 0    */
    guint16 chunk_length;       /* sizeof(SCTP_chunk_header)+ number of bytes in the chunk */
}
SCTP_chunk_header;


#define FLAG_NONE                 0x00
#define FLAG_DESTROYED_TCB        0x00
#define FLAG_NO_TCB               0x01




/*--------------------------- data chunk ----------------------------------------------------*/
/* when chunk_id == CHUNK_DATA */
typedef struct SCTP_DATA_CHUNK_HEADER
{
    guint32 tsn;
    guint16 stream_id;
    guint16 stream_sn;
    guint32 protocolId;
}
SCTP_data_chunk_header;

#define  FIXED_DATA_CHUNK_SIZE      (sizeof(SCTP_chunk_header) + sizeof(SCTP_data_chunk_header))

#define SCTP_DATA_BEGIN_SEGMENT	     0x02
#define SCTP_DATA_MIDDLE_SEGMENT     0x00
#define SCTP_DATA_END_SEGMENT        0x01
#define SCTP_DATA_UNORDERED          0x04

#define MAX_DATACHUNK_PDU_LENGTH  (MAX_SCTP_PDU-sizeof(SCTP_chunk_header)-sizeof(SCTP_data_chunk_header))


typedef struct SCTP_DATA_CHUNK
{
    guint8 chunk_id;
    guint8 chunk_flags;
    guint16 chunk_length;
    guint32 tsn;
    guint16 stream_id;
    guint16 stream_sn;
    guint32 protocolId;
    guchar data[MAX_DATACHUNK_PDU_LENGTH];
}
SCTP_data_chunk;


/*--------------------------- variable length parameter definitions ------------------------*/
/*                                                                                          */
/*                               See section 3.2.1                                          */
/*                                                                                          */
/*------------------------------------------------------------------------------------------*/

#define STOP_PARAM_PROCESSING(param_type)               (((guint16)param_type & 0xC000)==0x0000)
#define STOP_PARAM_PROCESSING_WITH_ERROR(param_type)    (((guint16)param_type & 0xC000)==0x4000)
#define SKIP_PARAM(param_type)                          (((guint16)param_type & 0xC000)==0x8000)
#define SKIP_PARAM_WITH_ERROR(param_type)               (((guint16)param_type & 0xC000)==0xC000)


/* optional and variable length parameter types */
#define VLPARAM_HB_INFO                 0x0001
#define VLPARAM_IPV4_ADDRESS            0x0005
#define VLPARAM_IPV6_ADDRESS            0x0006
#define VLPARAM_COOKIE                  0x0007
#define VLPARAM_UNRECOGNIZED_PARAM      0x0008
#define VLPARAM_COOKIE_PRESERV          0x0009
#define VLPARAM_ECN_CAPABLE             0x8000
#define VLPARAM_HOST_NAME_ADDR          0x000B
#define VLPARAM_SUPPORTED_ADDR_TYPES    0x000C

#define VLPARAM_PRSCTP                  0xC000
#define VLPARAM_ADDIP                   0xC001
#define VLPARAM_DELIP                   0xC002
#define VLPARAM_ERROR_CAUSE_INDICATION  0xC003
#define VLPARAM_SET_PRIMARY             0xC004
#define VLPARAM_SUCCESS_REPORT          0xC005
#define VLPARAM_ADAPTATION_LAYER_IND    0xC006

/* Header of variable length parameters */
typedef struct SCTP_VLPARAM_HEADER
{
    guint16 param_type;
    guint16 param_length;
}
SCTP_vlparam_header;

typedef struct SCTP_IP_ADDRESS
{
    SCTP_vlparam_header vlparam_header;
    union __dest_addr
    {
        guint32 sctp_ipv4;
        guint32 sctp_ipv6[4];
    }
    dest_addr;
}
SCTP_ip_address;

#define IS_IPV4_ADDRESS_NBO(a)  ((a.vlparam_header.param_type==htons(VLPARAM_IPV4_ADDRESS))&&\
                             (a.vlparam_header.param_length==htons(8)))

#define IS_IPV6_ADDRESS_NBO(a)  ((a.vlparam_header.param_type==htons(VLPARAM_IPV6_ADDRESS))&&\
                             (a.vlparam_header.param_length==htons(20)))

#define IS_IPV4_ADDRESS_PTR_NBO(p)  ((p->vlparam_header.param_type==htons(VLPARAM_IPV4_ADDRESS))&&\
                                 (p->vlparam_header.param_length==htons(8)))

#define IS_IPV6_ADDRESS_PTR_NBO(p)  ((p->vlparam_header.param_type==htons(VLPARAM_IPV6_ADDRESS))&&\
                                 (p->vlparam_header.param_length==htons(20)))

#define IS_IPV4_ADDRESS_HBO(a)  ((a.vlparam_header.param_type==VLPARAM_IPV4_ADDRESS)&&\
                             (a.vlparam_header.param_length==8))

#define IS_IPV6_ADDRESS_HBO(a)  ((a.vlparam_header.param_type== VLPARAM_IPV6_ADDRESS)&&\
                             (a.vlparam_header.param_length==20))

#define IS_IPV4_ADDRESS_PTR_HBO(p)  ((p->vlparam_header.param_type==VLPARAM_IPV4_ADDRESS)&&\
                                 (p->vlparam_header.param_length==8))

#define IS_IPV6_ADDRESS_PTR_HBO(p)  ((p->vlparam_header.param_type==VLPARAM_IPV6_ADDRESS)&&\
                                 (p->vlparam_header.param_length==20))

/* Supported Addresstypes */
typedef struct SCTP_SUPPORTED_ADDRESSTYPES
{
    SCTP_vlparam_header vlparam_header;
    guint16 address_type[4];
}
SCTP_supported_addresstypes;


/* Cookie Preservative */
typedef struct SCTP_COOKIE_PRESERVATIVE
{
    SCTP_vlparam_header vlparam_header;
    guint32 cookieLifetimeInc;
}
SCTP_cookie_preservative;



/*--------------------------- init chunk ----------------------------------------------------*/
/**
 * this is the INIT specific part of the sctp_chunk, which is ALWAYS sent
 * it MAY take some additional variable length params.....
 * and MAY also be used for INIT_ACK chunks.
 */
typedef struct SCTP_INIT_FIXED
{
    guint32 init_tag;
    guint32 rwnd;
    guint16 outbound_streams;
    guint16 inbound_streams;
    guint32 initial_tsn;
}
SCTP_init_fixed;

/* max. length of optional parameters */
#define MAX_INIT_OPTIONS_LENGTH  (MAX_SCTP_PDU - sizeof(SCTP_init_fixed))

/* init chunk structure, also used for initAck */
typedef struct SCTP_INIT
{
    SCTP_chunk_header chunk_header;
    SCTP_init_fixed   init_fixed;
    guchar            variableParams[MAX_INIT_OPTIONS_LENGTH];
}
SCTP_init;


/*--------------------------- selective acknowledgements defs --------------------------------*/
#define MAX_VARIABLE_SACK_SIZE  (MAX_SCTP_PDU - 16)
/* see section 2.3.3 */
typedef struct SCTP_SACK_CHUNK
{
    SCTP_chunk_header chunk_header;
    guint32 cumulative_tsn_ack;
    guint32 a_rwnd;
    guint16 num_of_fragments;
    guint16 num_of_duplicates;
    guchar fragments_and_dups[MAX_VARIABLE_SACK_SIZE];
}
SCTP_sack_chunk;

typedef struct _fragment32
{
    guint32 start_tsn;
    guint32 stop_tsn;
}
fragment32;

typedef struct _fragment
{
    guint16 start;
    guint16 stop;
}
fragment;

typedef struct _duplicate
{
    guint32 duplicate_tsn;
}
duplicate;

/*--------------------------- heartbeat chunk defs --------------------------------*/

/* our heartbeat chunk structure */
typedef struct SCTP_HEARTBEAT
{
    SCTP_chunk_header chunk_header;
    SCTP_vlparam_header HB_Info;
    guint32 sendingTime;
    guint32 pathID;
#ifdef MD5_HMAC
    guint8 hmac[16];
#elif SHA_HMAC
    guint32 hmac[5];
#endif
}
SCTP_heartbeat;


/*--------------------------- simple chunk --------------------------------------------------*/
/* Simple chunks for chunks without or with bytestrings as chunk data.
   Can be used for the following chunk types:
   CHUNK_ABORT
   CHUNK_SHUTDOWN_ACK
   CHUNK_COOKIE_ACK
   ? CHUNK_COOKIE_ECHO ?

   simple chunk can also be used for transfering chunks to/from bundling, since bundling
   looks only on the chunk header.
*/
#define MAX_SIMPLE_CHUNKDATA_LENGTH   (MAX_SCTP_PDU - sizeof(SCTP_chunk_header))

typedef struct SCTP_SIMPLE_CHUNK
{
    SCTP_chunk_header chunk_header;
    unsigned char simple_chunk_data[MAX_SIMPLE_CHUNKDATA_LENGTH];
} SCTP_simple_chunk;

typedef struct __pr_stream_data
{
    guint16 stream_id;
    guint16 stream_sn;
}
pr_stream_data;

typedef struct SCTP_FORWARD_TSN_CHUNK
{
    SCTP_chunk_header   chunk_header;
    guint32             forward_tsn;
    guchar              variableParams[MAX_SCTP_PDU];
}
SCTP_forward_tsn_chunk;

/*--------------------------- parameter definitions ------------------------------------------*/

/**
 * The cookie definition as used by this implementation
 *  We include all parameters that where sent with the initAck to the a-side.
 *  In detail, the cookie contains the follwing params in the given order:
 *  - fixed part of initAck.
 *  - fixed part of init.
 *  - variable part of initAck (address list).
 *  - variable part of init (address list).
 *  Only the fixed part is defined here.
 */
typedef struct SCTP_OUR_COOKIE
{
    SCTP_init_fixed z_side_initAck;
    SCTP_init_fixed a_side_init;
    guint16 src_port;
    guint16 dest_port;
    guint32 local_tie_tag;
    guint32 peer_tie_tag;
    guint32 sendingTime;
    guint32 cookieLifetime;
#ifdef MD5_HMAC
    guint8 hmac[16];
#elif SHA_HMAC
    guint32 hmac[5];
#endif
    guint16 no_local_ipv4_addresses;
    guint16 no_remote_ipv4_addresses;
    guint16 no_local_ipv6_addresses;
    guint16 no_remote_ipv6_addresses;
    guint16 no_local_dns_addresses;
    guint16 no_remote_dns_addresses;
}
SCTP_our_cookie;
/* the variable parameters should be appended in that
   same order to the cookie
 */


typedef struct SCTP_COOKIE_PARAM
{
    SCTP_vlparam_header vlparam_header;
    SCTP_our_cookie ck;
}
SCTP_cookie_param;

/* cookie chunks fixed params length including chunk header */
#define COOKIE_FIXED_LENGTH     (sizeof(SCTP_our_cookie))
/* max. length of cookie variable length params parameters */
#define MAX_COOKIE_VLP_LENGTH   (MAX_SCTP_PDU -  COOKIE_FIXED_LENGTH)

/* cookie echo chunk structure */
typedef struct SCTP_COOKIE_ECHO
{
    SCTP_chunk_header chunk_header;
    SCTP_our_cookie cookie;
    guchar vlparams[MAX_COOKIE_VLP_LENGTH];
}
SCTP_cookie_echo;


/*--------------------------- Errorchunk definitions -----------------------------------------*/

/**
 * Errorchunks: for error-chunks the SCTP_simple_chunk can be used since it contains
 * only varible length params.
 */
typedef struct SCTP_ERROR_CHUNK
{
    SCTP_chunk_header chunk_header;
    unsigned char data[MAX_DATACHUNK_PDU_LENGTH];
} SCTP_error_chunk;

typedef struct SCTP_ERROR_CAUSE
{
    unsigned short cause_code;
    unsigned short cause_length;
    guchar cause_information[MAX_SCTP_PDU];
}SCTP_error_cause;


/*--------------------------- Error causes definitions ---------------------------------------*/
/* Error cause codes */
#define ECC_INVALID_STREAM_ID                   1
#define ECC_MISSING_MANDATORY_PARAM             2
#define ECC_STALE_COOKIE_ERROR                  3
#define ECC_OUT_OF_RESOURCE_ERROR               4
#define ECC_UNRESOLVABLE_ADDRESS                5
#define ECC_UNRECOGNIZED_CHUNKTYPE              6
#define ECC_INVALID_MANDATORY_PARAM             7
#define ECC_UNRECOGNIZED_PARAMS                 8
#define ECC_NO_USER_DATA                        9
#define ECC_COOKIE_RECEIVED_DURING_SHUTDWN      10
#define ECC_RESTART_WITH_NEW_ADDRESSES          11

#define ECC_USER_INITIATED_ABORT                12
#define ECC_PROTOCOL_VIOLATION                  13


#define ECC_DELETE_LAST_IP_FAILED       0xC
#define ECC_OP_REFUSED_NO_RESOURCES     0xD
#define ECC_DELETE_SOURCE_ADDRESS       0xE


/*--------------------------- Error causes param defs ----------------------------------------*/

typedef struct SCTP_STALECOOKIEERROR
{
    SCTP_vlparam_header vlparam_header;
    guint32 staleness;
}
SCTP_staleCookieError;


typedef struct SCTP_INVALID_STREAMID_ERROR
{
    guint16 stream_id;
    guint16 reserved;
}
SCTP_InvalidStreamIdError;


typedef struct SCTP_UNRESOLVABLE_ADDRESS_ERROR
{
    SCTP_vlparam_header vlparam_header;
    guchar the_address[MAX_SCTP_PDU];
}
SCTP_UnresolvableAddress;

typedef struct SCTP_UNRECOGNIZED_PARAMS_ERROR
{
    SCTP_vlparam_header vlparam_header;
    guchar the_params[MAX_SCTP_PDU];
}
SCTP_UnrecognizedParams;

typedef struct SCTP_MISSING_PARAMS_ERROR
{
    unsigned int numberOfParams;
    unsigned short params[20];
}
SCTP_MissingParams;

/*--------------------------- ASCONF Chunk and Parameter Types ---------------------------------*/

typedef struct SCTP_ASCONF_FIXED
{
    guint32     serial_number;
    guint16     reserved16;
    guint8      reserved8;
    guint8      address_type;
    guint32     sctp_address[4];
    guchar      variableParams[MAX_SCTP_PDU];
}
SCTP_asconf_fixed;

typedef struct SCTP_ASCONF_ACK
{
    guint32     serial_number;
    guchar      variableParams[MAX_SCTP_PDU];
}
SCTP_asconf_ack;


typedef struct SCTP_ASCONF
{
    SCTP_chunk_header  chunk_header;
    SCTP_asconf_fixed  asc_fixed;
    guchar             variableParams[MAX_INIT_OPTIONS_LENGTH];
}
SCTP_asconf;

typedef struct SCTP_ASCONF_ACK_CHUNK
{
    SCTP_chunk_header  chunk_header;
    SCTP_asconf_ack    asc_ack;
    guchar             variableParams[MAX_INIT_OPTIONS_LENGTH];
}
SCTP_asconf_ack_chunk;


/*--------------------------- and some useful (?) macros ----------------------------------------*/

#define CHUNKP_LENGTH(chunk)		(ntohs((chunk)->chunk_length))

/* Chunk classes for distribution and any other modules which might need it */
#define isInitControlChunk(chunk) ((chunk)->chunk_header.chunk_id == CHUNK_INIT       || \
                                   (chunk)->chunk_header.chunk_id == CHUNK_INIT_ACK   || \
                                   (chunk)->chunk_header.chunk_id == CHUNK_COOKIE_ECHO || \
                                   (chunk)->chunk_header.chunk_id == CHUNK_COOKIE_ACK)

#define isInitCookieChunk(chunk)  ((chunk)->chunk_header.chunk_id == CHUNK_INIT       || \
                                   (chunk)->chunk_header.chunk_id == CHUNK_COOKIE_ECHO)

#define isInitAckChunk(chunk)     ((chunk)->chunk_header.chunk_id == CHUNK_INIT_ACK)

#define isShutDownAckChunk(chunk) ((chunk)->chunk_header.chunk_id == CHUNK_SHUTDOWN_ACK)

#define isShutDownCompleteChunk(chunk) ((chunk)->chunk_header.chunk_id == CHUNK_SHUTDOWN_COMPLETE)


#endif
