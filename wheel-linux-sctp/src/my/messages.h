/*
 * messages.h
 *
 *  Created on: 13 Apr 2016
 *      Author: jakez
 */

#ifndef MY_MESSAGES_H_
#define MY_MESSAGES_H_

#include "config.h"
#include "basic-type.h"

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#endif

#define  MD5_HMAC   1
#undef   SHA_HMAC
#define  HMAC_LEN   16 /* 16 bytes == 128 Bits == 4 doublewords */

/**************************** SCTP common message definitions *********************************/
#define MAX_MTU_SIZE 1500
#define IP_HDR_SIZE 20

#ifdef SCTP_OVER_UDP
#define PACKET_COMM_HDR_SIZE  4*sizeof(UInt16)
#define MAX_PACKET_VALUE_SIZE \
(MAX_MTU_SIZE - IP_HDR_SIZE - PACKET_COMM_HDR_SIZE)
/* #define SCTP_OVER_UDP_UDPPORT 9899 */
/* #warning Using SCTP over UDP! */
struct packet_comm_hdr_t
{
    UInt16 src_port;
    UInt16 dest_port;
    UInt16 length;
    UInt16 checksum;
};
#else
#define PACKET_COMM_HDR_SIZE  2 * (sizeof(UInt16) + sizeof(UInt32))
#define MAX_PACKET_VALUE_SIZE \
MAX_MTU_SIZE - IP_HDR_SIZE- PACKET_COMM_HDR_SIZE
struct packet_comm_hdr_t
{
    UInt16 src_port;
    UInt16 dest_port;
    UInt32 verification_tag;
    UInt32 checksum;
};
#endif
// A general struct for an SCTP-message
struct packet_t
{
    packet_comm_hdr_t pk_comm_hdr;
    UInt8 chunk[MAX_PACKET_VALUE_SIZE];
};

/**************************** SCTP chunk definitions ******************************************/
/*--------------------------- chunk types -------------------------------------------*/
// See RFC4060 section 3.2 Chunk Field Descriptions Page17
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

#define STOP_PROCESS_CHUNK(chunk_id)\
(((UInt8)chunk_id & 0xC0)==0x00))
#define STOP_PROCESS_CHUNK_REPORT_ERROR(chunk_id)\
(((UInt8)chunk_id & 0xC0)==0x40))
#define SKIP_CHUNK(chunk_id)\
(((UInt8)chunk_id & 0xC0)==0x80))
#define SKIP_CHUNK_REPORT_ERROR(chunk_id)\
(((UInt8)chunk_id & 0xC0)==0xC0))

/*--------------------------- common chunk header -------------------------------------------*/
#define CHUNK_FIXED_SIZE (2*sizeof(UInt8)+sizeof(UInt16))
struct chunk_fixed_t
{
    UInt8 chunk_type; /* e.g. CHUNK_DATA etc. */
    UInt8 chunk_flag; /* usually 0    */
    UInt16 chunk_length; /* sizeof(SCTP_chunk_header)+ number of bytes in the chunk */
};
#define FLAG_NONE                 0x00
#define FLAG_DESTROYED_TCB        0x00
#define FLAG_NO_TCB               0x01

/*--------------------------- data chunk ----------------------------------------------------*/
#define DATA_CHUNK_FIRST_SEGMENT      0x02 //BEGIN
#define DATA_CHUNK_MIDDLE_SEGMENT     0x00 //MIDDLE
#define DATA_CHUNK_LAST_SEGMENT        0x01 //END
#define UNORDER_DATA_CHUNK          0x04
#define DATA_CHUNK_FIXED_HDR_SIZE (sizeof(UInt32)+3*sizeof(UInt16))
#define DATA_CHUNK_FIXED_SIZE   \
(CHUNK_FIXED_SIZE+DATA_CHUNK_FIXED_HDR_SIZE)
#define MAX_DATA_CHUNK_VALUE_SIZE  \
(MAX_PACKET_VALUE_SIZE-DATA_CHUNK_FIXED_SIZE)

/* when chunk_id == CHUNK_DATA */
struct data_chunk_fixed_hdr_t
{
    UInt32 trans_seq_num;
    UInt16 stream_identity;
    UInt16 stream_seq_num;
    UInt16 protocol_id;
};
struct data_chunk_t
{
    chunk_fixed_t comm_chunk_hdr;
    data_chunk_fixed_hdr_t data_chunk_hdr;
    UInt8 data[MAX_DATA_CHUNK_VALUE_SIZE];
};

/*--------------------------- variable length parameter definitions ------------------------*/
// See RFC4960 Section 3.2.1 Optional/Variable-Length Parameter Format From Page 19
// vl params only appear in control chunks
#define STOP_PROCESS_PARAM(param_type)   \
(((UInt16)param_type & 0xC000)==0x0000)
#define STOP_PROCES_PARAM_REPORT_ERROR(param_type)    \
(((UInt16)param_type & 0xC000)==0x4000)
#define SKIP_PARAM(param_type)       \
(((UInt16)param_type & 0xC000)==0x8000)
#define SKIP_PARAM_REPORT_ERROR(param_type)    \
(((UInt16)param_type & 0xC000)==0xC000)

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
struct vlparam_fixed_t
{
    UInt16 param_type;
    UInt16 param_length;
};

struct ip_address
{
    vlparam_fixed_t vlparam_header;
    union
    {
        UInt32 sctp_ipv4;
        UInt32 sctp_ipv6[4];
    } dest_addr_un;
};

/* Supported Addresstypes */
struct vlparam_supported_address_types_t
{
    vlparam_fixed_t vlparam_header;
    UInt16 address_type[4];
};

/* Cookie Preservative */
struct vlparam_cookie_preservative
{
    vlparam_fixed_t vlparam_header;
    UInt32 cookieLifetimeInc;
};

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

/*--------------------------- init chunk ----------------------------------------------------*/
// See RFC4960 Section 3.3.2.Initiation (INIT) From Page 24
/**
 * this is the INIT specific part of the sctp_chunk, which is ALWAYS sent
 * it MAY take some additional variable length params.....
 * and MAY also be used for INIT_ACK chunks.
 */
struct init_chunk_fixed_t
{
    UInt32 init_tag;
    UInt32 rwnd;
    UInt16 outbound_streams;
    UInt16 inbound_streams;
    UInt32 initial_tsn;
};
/* max. length of optional parameters */
#define INIT_CHUNK_FIXED_SIZE (3*sizeof(UInt32)+2*sizeof(UInt16))
#define MAX_INIT_CHUNK_VALUE_SIZE  \
(MAX_PACKET_VALUE_SIZE - CHUNK_FIXED_SIZE -INIT_CHUNK_FIXED_SIZE)
/* init chunk structure, also used for initAck */
struct init_chunk_t
{
    chunk_fixed_t chunk_header;
    init_chunk_fixed_t   init_fixed;
    UInt8                               variableParams[MAX_INIT_CHUNK_VALUE_SIZE];
};

/*--------------------------- selective acknowledgements defs --------------------------------*/
//  see RFC4960 Section 2.3.3 
#define SACK_CHUNK_FIXED_SIZE (2*sizeof(UInt32)+2*sizeof(UInt16))
#define MAX_SACK_CHUNK_VALUE_SIZE  \
(MAX_PACKET_VALUE_SIZE - CHUNK_FIXED_SIZE - SACK_CHUNK_FIXED_SIZE )
struct sack_chunk_fixed_t
{
    UInt32 cumulative_tsn_ack;
    UInt32 a_rwnd;
    UInt16 num_of_fragments;
    UInt16 num_of_duplicates;
};
struct sack_chunk_t
{
    chunk_fixed_t chunk_header;
    sack_chunk_fixed_t sack_fixed;
    UInt8 fragments_and_dups[MAX_SACK_CHUNK_VALUE_SIZE];
};
struct segment32_t
{
    UInt32 start_tsn;
    UInt32 stop_tsn;
};
struct segment_t
{
    UInt32 start;
    UInt32 stop;
};
typedef  UInt32 duplicate_tsn_t;

/*--------------------------- heartbeat chunk defs --------------------------------*/
/* our heartbeat chunk structure */
struct heartbeat_chunk_t
{
    chunk_fixed_t chunk_header;
    vlparam_fixed_t HB_Info;
    UInt32 sendingTime;
    UInt32 pathID;
#ifdef MD5_HMAC
    UInt8 hmac[16];
#elif SHA_HMAC
    UInt32 hmac[5];
#endif
};

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
#define MAX_SIMPLE_CHUNK_VALUE_SIZE  (MAX_PACKET_VALUE_SIZE - CHUNK_FIXED_SIZE)
struct simple_chunk_t
{
    chunk_fixed_t chunk_header;
    UInt8 data[MAX_SIMPLE_CHUNK_VALUE_SIZE];
};
struct pr_stream_data_t
{
    UInt16 stream_id;
    UInt16 stream_sn;
};
struct forward_tsn_chunk_t
{
    chunk_fixed_t   chunk_header;
    UInt32              forward_tsn;
    UInt8                variableParams[MAX_PACKET_VALUE_SIZE];
};
#endif /* MY_MESSAGES_H_ */
