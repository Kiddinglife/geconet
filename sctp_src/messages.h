/* $Id$
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
 * Copyright (C) 2004-2016 Thomas Dreibholz
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
} geco_packet_fixed_t;
#endif


#define MAX_MTU_SIZE              1500
#define DEFAULT_MTU_CEILING     1500
#define IP_HEADERLENGTH             20

/**
 * the common header, maybe we need to check for sizes of types on 64 bit machines
 * for now assume that "unsigned short" has 16 bits ! (Bft: short is always 16 Bit
 *                                                     32: int and long are 32
 *                                                     64: int is 32, long is 64)
 */
typedef struct
{
    gushort src_port;
    gushort dest_port;
    uint verification_tag;
    uint checksum;
}
geco_packet_fixed_t;

/*
 * max. SCTP-datagram length without common header
 */
#define MAX_NETWORK_PACKET_VALUE_SIZE  \
(MAX_MTU_SIZE - IP_HEADERLENGTH - sizeof(geco_packet_fixed_t))


/*
 * A general struct for an SCTP-message
 */
typedef struct SCTP_MESSAGE
{
    geco_packet_fixed_t common_header;
    uchar sctp_pdu[MAX_NETWORK_PACKET_VALUE_SIZE];
}
dctp_packet_t;


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

#define STOP_PROCESS_CHUNK(chunk_id)               (((uint8)chunk_id & 0xC0)==0x00))
#define STOP_PROCESS_CHUNK_REPORT_EREASONROR(chunk_id)    (((uint8)chunk_id & 0xC0)==0x40))
#define SKIP_CHUNK(chunk_id)                    (((uint8)chunk_id & 0xC0)==0x80))
#define SKIP_CHUNK_REPORT_EREASONROR(chunk_id)         (((uint8)chunk_id & 0xC0)==0xC0))

/*--------------------------- common chunk header -------------------------------------------*/

typedef struct
{
    uint8 chunk_id;            /* e.g. CHUNK_DATA etc. */
    uint8 chunk_flags;         /* usually 0    */
    ushort chunk_length;       /* sizeof(chunk_fixed_t)+ number of bytes in the chunk */
}chunk_fixed_t;


#define FLAG_NONE                 0x00
#define FLAG_DESTROYED_TCB        0x00
#define FLAG_NO_TCB               0x01




/*--------------------------- data chunk ----------------------------------------------------*/
/* when chunk_id == CHUNK_DATA */
typedef struct
{
    uint tsn;
    ushort stream_id;
    ushort stream_sn;
    uint protocolId;
}data_chunk_fixed_t;

#define  DATA_CHUNK_FIXED_SIZES (sizeof(chunk_fixed_t) + sizeof(data_chunk_fixed_t))

#define DCHUNK_FLAG_FIRST_FRAG	     0x02
#define DCHUNK_FLAG_MIDDLE_FRAG     0x00
#define DCHUNK_FLAG_LAST_FRG        0x01
#define DCHUNK_FLAG_UNORDER          0x04 //unordered chunk

#define MAX_DATA_CHUNK_VALUE_SIZE  (MAX_NETWORK_PACKET_VALUE_SIZE-sizeof(chunk_fixed_t)-sizeof(data_chunk_fixed_t))


typedef struct
{
    uint8 chunk_id;
    uint8 chunk_flags;
    ushort chunk_length;
    uint tsn;
    ushort stream_id;
    ushort stream_sn;
    uint protocolId;
    uchar data[MAX_DATA_CHUNK_VALUE_SIZE];
}data_chunk_t;


/*--------------------------- variable length parameter definitions ------------------------*/
/*                                                                                          */
/*                               See section 3.2.1                                          */
/*                                                                                          */
/*------------------------------------------------------------------------------------------*/

#define STOP_PROCESS_PARAM(param_type)               (((ushort)param_type & 0xC000)==0x0000)
#define STOP_PROCES_PARAM_REPORT_EREASON(param_type)    (((ushort)param_type & 0xC000)==0x4000)
#define SKIP_PARAM(param_type)                          (((ushort)param_type & 0xC000)==0x8000)
#define SKIP_PARAM_REPORT_EREASON(param_type)               (((ushort)param_type & 0xC000)==0xC000)


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
typedef struct
{
    ushort param_type;
    ushort param_length;
}vlparam_fixed_t;

typedef struct
{
    vlparam_fixed_t vlparam_header;
    union __dest_addr
    {
        uint sctp_ipv4;
        uint sctp_ipv6[4];
    }
    dest_addr;
}ip_address_t;

#define IS_IPV4_ADDRESS_NBO(a)  \
((a.vlparam_header.param_type==htons(VLPARAM_IPV4_ADDRESS))&&\
                             (a.vlparam_header.param_length==htons(8)))

#define IS_IPV6_ADDRESS_NBO(a) \
((a.vlparam_header.param_type==htons(VLPARAM_IPV6_ADDRESS))&&\
                             (a.vlparam_header.param_length==htons(20)))

#define IS_IPV4_ADDRESS_PTR_NBO(p)  \
((p->vlparam_header.param_type==htons(VLPARAM_IPV4_ADDRESS))&&\
                                 (p->vlparam_header.param_length==htons(8)))

#define IS_IPV6_ADDRESS_PTR_NBO(p)  \
((p->vlparam_header.param_type==htons(VLPARAM_IPV6_ADDRESS))&&\
                                 (p->vlparam_header.param_length==htons(20)))

#define IS_IPV4_ADDRESS_HBO(a) \
((a.vlparam_header.param_type==VLPARAM_IPV4_ADDRESS)&&\
                             (a.vlparam_header.param_length==8))

#define IS_IPV6_ADDRESS_HBO(a)  \
((a.vlparam_header.param_type== VLPARAM_IPV6_ADDRESS)&&\
                             (a.vlparam_header.param_length==20))

#define IS_IPV4_ADDRESS_PTR_HBO(p)  \
((p->vlparam_header.param_type==VLPARAM_IPV4_ADDRESS)&&\
                                 (p->vlparam_header.param_length==8))

#define IS_IPV6_ADDRESS_PTR_HBO(p) \
((p->vlparam_header.param_type==VLPARAM_IPV6_ADDRESS)&&\
                                 (p->vlparam_header.param_length==20))

/* Supported Addresstypes */
typedef struct
{
    vlparam_fixed_t vlparam_header;
    ushort address_type[4];
}supported_address_types_t;


/* Cookie Preservative */
typedef struct
{
    vlparam_fixed_t vlparam_header;
    uint cookieLifetimeInc;
}cookie_preservative_t;



/*--------------------------- init chunk ----------------------------------*/
/**
 * this is the INIT specific part of the sctp_chunk, which is ALWAYS sent
 * it MAY take some additional variable length params.....
 * and MAY also be used for INIT_ACK chunks.
 */
typedef struct
{
    uint init_tag;
    uint rwnd;
    ushort outbound_streams;
    ushort inbound_streams;
    uint initial_tsn;
}init_chunk_fixed_t;

/* max. length of optional parameters */
#define MAX_INIT_CHUNK_OPTIONS_SIZE  (MAX_NETWORK_PACKET_VALUE_SIZE - sizeof(init_chunk_fixed_t))

/* init chunk structure, also used for initAck */
typedef struct
{
    chunk_fixed_t chunk_header;
    init_chunk_fixed_t   init_fixed;
    uchar            variableParams[MAX_INIT_CHUNK_OPTIONS_SIZE];
}init_chunk_t;


/*--------------------------- selective acknowledgements defs --------------------------------*/
#define MAX_VARIABLE_SACK_SIZE  (MAX_NETWORK_PACKET_VALUE_SIZE - 16)
/* see section 2.3.3 */
typedef struct
{
    chunk_fixed_t chunk_header;
    uint cumulative_tsn_ack;
    uint a_rwnd;
    ushort num_of_fragments;
    ushort num_of_duplicates;
    uchar fragments_and_dups[MAX_VARIABLE_SACK_SIZE];
}sack_chunk_t;

typedef struct
{
    uint start_tsn;
    uint stop_tsn;
}segment32_t;

typedef struct
{
    ushort start;
    ushort stop;
}segment16_t;

typedef struct _duplicate
{
    uint duplicate_tsn;
}duplicate_tsn_t;

/*--------------------------- heartbeat chunk defs --------------------------------*/

/* our heartbeat chunk structure */
typedef struct
{
    chunk_fixed_t chunk_header;
    vlparam_fixed_t HB_Info;
    uint sendingTime;
    uint pathID;
#ifdef MD5_HMAC
    uint8 hmac[16];
#elif SHA_HMAC
    uint hmac[5];
#endif
}
heartbeat_chunk_t;


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
#define MAX_SIMPLE_CHUNK_VALUE_SIZE   (MAX_NETWORK_PACKET_VALUE_SIZE - sizeof(chunk_fixed_t))

typedef struct SCTP_SIMPLE_CHUNK
{
    chunk_fixed_t chunk_header;
    unsigned char simple_chunk_data[MAX_SIMPLE_CHUNK_VALUE_SIZE];
} simple_chunk_t;

typedef struct __pr_stream_data
{
    ushort stream_id;
    ushort stream_sn;
}
pr_stream_data;

typedef struct SCTP_FORWARD_TSN_CHUNK
{
    chunk_fixed_t   chunk_header;
    uint             forward_tsn;
    uchar              variableParams[MAX_NETWORK_PACKET_VALUE_SIZE];
}
forward_tsn_chunk_t;

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
    init_chunk_fixed_t z_side_initAck;
    init_chunk_fixed_t a_side_init;
    ushort src_port;
    ushort dest_port;
    uint local_tie_tag;
    uint peer_tie_tag;
    uint sendingTime;
    uint cookieLifetime;
#ifdef MD5_HMAC
    uint8 hmac[16];
#elif SHA_HMAC
    uint hmac[5];
#endif
    ushort no_local_ipv4_addresses;
    ushort no_remote_ipv4_addresses;
    ushort no_local_ipv6_addresses;
    ushort no_remote_ipv6_addresses;
    ushort no_local_dns_addresses;
    ushort no_remote_dns_addresses;
}
cookie_fixed_t;
/* the variable parameters should be appended in that
   same order to the cookie
   */


typedef struct SCTP_COOKIE_PARAM
{
    vlparam_fixed_t vlparam_header;
    cookie_fixed_t ck;
}
cookie_param_t;

/* cookie chunks fixed params length including chunk header */
#define COOKIE_FIXED_LENGTH     (sizeof(cookie_fixed_t))
/* max. length of cookie variable length params parameters */
#define MAX_COOKIE_VLP_LENGTH   (MAX_NETWORK_PACKET_VALUE_SIZE -  COOKIE_FIXED_LENGTH)

/* cookie echo chunk structure */
typedef struct SCTP_COOKIE_ECHO
{
    chunk_fixed_t chunk_header;
    cookie_fixed_t cookie;
    uchar vlparams[MAX_COOKIE_VLP_LENGTH];
}
cookie_echo_chunk_t;


/*--------------------------- Errorchunk definitions -----------------------------------------*/

/**
 * Errorchunks: for error-chunks the simple_chunk_t can be used since it contains
 * only varible length params.
 */
typedef struct SCTP_ERROR_CHUNK
{
    chunk_fixed_t chunk_header;
    unsigned char data[MAX_DATA_CHUNK_VALUE_SIZE];
} error_chunk_t;

typedef struct SCTP_ERROR_CAUSE
{
    unsigned short cause_code;
    unsigned short cause_length;
    uchar cause_information[MAX_NETWORK_PACKET_VALUE_SIZE];
}error_cause_t;


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
    vlparam_fixed_t vlparam_header;
    uint staleness;
}
stale_cookie_err_t;


typedef struct SCTP_INVALID_STREAMID_ERROR
{
    ushort stream_id;
    ushort reserved;
}
invalid_stream_id_err_t;


typedef struct SCTP_UNRESOLVABLE_ADDRESS_ERROR
{
    vlparam_fixed_t vlparam_header;
    uchar the_address[MAX_NETWORK_PACKET_VALUE_SIZE];
}
unresolved_addr_err_t;

typedef struct SCTP_UNRECOGNIZED_PARAMS_ERROR
{
    vlparam_fixed_t vlparam_header;
    uchar the_params[MAX_NETWORK_PACKET_VALUE_SIZE];
}
unrecognized_params_err_t;

typedef struct SCTP_MISSING_PARAMS_ERROR
{
    unsigned int numberOfParams;
    unsigned short params[20];
}
missing_mandaory_params_err_t;

/*--------------------------- ASCONF Chunk and Parameter Types ---------------------------------*/

typedef struct SCTP_ASCONF_FIXED
{
    uint     serial_number;
    ushort     reserved16;
    uint8      reserved8;
    uint8      address_type;
    uint     sctp_address[4];
    uchar      variableParams[MAX_NETWORK_PACKET_VALUE_SIZE];
}
asconfig_chunk_fixed_t;

typedef struct SCTP_ASCONF_ACK
{
    uint     serial_number;
    uchar      variableParams[MAX_NETWORK_PACKET_VALUE_SIZE];
}
asconfig_ack_chunk_fixed_t;


typedef struct SCTP_ASCONF
{
    chunk_fixed_t  chunk_header;
    asconfig_chunk_fixed_t  asc_fixed;
    uchar             variableParams[MAX_INIT_CHUNK_OPTIONS_SIZE];
}
asconfig_chunk_t;

typedef struct SCTP_ASCONF_ACK_CHUNK
{
    chunk_fixed_t  chunk_header;
    asconfig_ack_chunk_fixed_t    asc_ack;
    uchar             variableParams[MAX_INIT_CHUNK_OPTIONS_SIZE];
}
asconf_ack_chunk_t;


/*--------------------------- and some useful (?) macros ----------------------------------------*/

#define get_chunk_length(chunk)		(ntohs((chunk)->chunk_length))

/* Chunk classes for distribution and any other modules which might need it */
#define is_init_control_chunk(chunk) ((chunk)->chunk_header.chunk_id == CHUNK_INIT       || \
                                   (chunk)->chunk_header.chunk_id == CHUNK_INIT_ACK   || \
                                   (chunk)->chunk_header.chunk_id == CHUNK_COOKIE_ECHO || \
                                   (chunk)->chunk_header.chunk_id == CHUNK_COOKIE_ACK)

#define is_init_cookie_chunk(chunk)  ((chunk)->chunk_header.chunk_id == CHUNK_INIT       || \
                                   (chunk)->chunk_header.chunk_id == CHUNK_COOKIE_ECHO)

#define is_init_ack_chunk(chunk)     ((chunk)->chunk_header.chunk_id == CHUNK_INIT_ACK)

#define is_shutdown_ack_chunk(chunk) ((chunk)->chunk_header.chunk_id == CHUNK_SHUTDOWN_ACK)

#define is_shutdown_complete_chunk(chunk) ((chunk)->chunk_header.chunk_id == CHUNK_SHUTDOWN_COMPLETE)


#endif
