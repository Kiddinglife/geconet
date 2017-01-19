/*
 * messages.h
 *
 *  Created on: 13 Apr 2016
 *  Finish on: 14 April 2016
 *      Author: jakez
 *
 */

#ifndef MY_MESSAGES_H_
#define MY_MESSAGES_H_

#include <sys/types.h>
#ifndef _WIN32 //all unix-like compilers should have this header
#include <sys/socket.h>
#endif

#include "geco-net-config.h"
#include "geco-common.h"

#define DEFAULT_COOKIE_LIFE_SPAN 30000 //ms

typedef short chunk_id_t;
#define MAX_CHUNKS_SIZE 32
#define MAX_CHUNKS_SIZE_MASK 31

/**************************** packet definitions ***************************/
extern uint PMTU_LOWEST;
#define PMTU_HIGHEST 1500
#define IP_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define MAX_UDP_PACKET_SIZE  (PMTU_HIGHEST - IP_HDR_SIZE - UDP_HDR_SIZE)
#define MAX_GECO_PACKET_SIZE  (PMTU_HIGHEST - IP_HDR_SIZE)
/* src port + dest port + ver tag + checksum + chunk type + chunk flag + chunk length = 16 bytes*/
#define MIN_GECO_PACKET_SIZE (GECO_PACKET_FIXED_SIZE+CHUNK_FIXED_SIZE)
#define MIN_UDP_PACKET_SIZE (sizeof(uint)+CHUNK_FIXED_SIZE)

#define GECO_PACKET_FIXED_SIZE  (2 * (sizeof(ushort) + sizeof(uint)))
#define GECO_PACKET_FIXED_SIZE_USE_UDP  (sizeof(uint))
// constant nomatter udp or war socket, paylods without any headers
#define MAX_PACKET_PDU  (PMTU_HIGHEST - IP_HDR_SIZE - GECO_PACKET_FIXED_SIZE)
struct geco_packet_fixed_t
{
	uint verification_tag;
	uint checksum;
	ushort src_port;
	ushort dest_port;
};

#define MAX_NETWORK_PACKET_VALUE_SIZE (MAX_GECO_PACKET_SIZE - GECO_PACKET_FIXED_SIZE)
// A general struct for an SCTP-message
struct geco_packet_t
{
	geco_packet_fixed_t pk_comm_hdr;
	uchar chunk[MAX_NETWORK_PACKET_VALUE_SIZE];
};

/**************************** SCTP chunk definitions ******************************************/
/*--------------------------- chunk types --------------------------------*/
// See RFC4060 section 3.2 Chunk Field Descriptions Page17
#define CHUNK_DATA              0x00 //0
#define CHUNK_INIT              0x01 //1
#define CHUNK_INIT_ACK          0x02 //2
#define CHUNK_SACK              0x03 //3
#define CHUNK_HBREQ             0x04 //4
#define CHUNK_HBACK             0x05 //5
#define CHUNK_ABORT             0x06 //6
#define CHUNK_SHUTDOWN          0x07 //7
#define CHUNK_SHUTDOWN_ACK      0x08 //8
#define CHUNK_ERROR             0x09 //9
#define CHUNK_COOKIE_ECHO       0x0A //10
#define CHUNK_COOKIE_ACK        0x0B //11
#define CHUNK_ECNE              0x0C //12
#define CHUNK_CWR               0x0D //13
#define CHUNK_SHUTDOWN_COMPLETE 0x0E //14

#define CHUNK_FORWARD_TSN       0xC0 //192
#define CHUNK_ASCONF            0xC1//193
#define CHUNK_ASCONF_ACK        0x80//128
#define CHUNK_PADDING        0x84//128

// 0xc0 = 192 = 11000000
// 0x40 = 64   = 01000000
// 0x80 = 128 = 10000000
#define STOP_PROCESS_CHUNK(chunk_id)\
(((uchar)chunk_id & 0xC0)==0x00))
#define STOP_PROCESS_CHUNK_REPORT_EREASONROR(chunk_id)\
(((uchar)chunk_id & 0xC0)==0x40))
#define SKIP_CHUNK(chunk_id)\
(((uchar)chunk_id & 0xC0)==0x80))
#define SKIP_CHUNK_REPORT_EREASONROR(chunk_id)\
(((uchar)chunk_id & 0xC0)==0xC0))

/*************** common chunk header ******************/
#define CHUNK_FIXED_SIZE (2*sizeof(uchar)+sizeof(ushort))
struct chunk_fixed_t
{
	uchar chunk_id; /* e.g. CHUNK_DATA etc. */
	uchar chunk_flags; /* usually 0    */
	ushort chunk_length; /* sizeof(SCTP_chunk_header)+ number of bytes in the chunk */
};
#define FLAG_TBIT_UNSET       0x00 // perr has our itag setup
#define FLAG_DELETED_CHANNEL  0x00 
#define FLAG_TBIT_SET         0x01 // peer has no our itag setup

/**************** chunk_value chunk *******************/
#define DCHUNK_FLAG_FIRST_FRAG  0x02 //BEGIN    10base: 10  2base : 10
#define DCHUNK_FLAG_MIDDLE_FRAG 0x00 //MIDDLE   10base: 0   2base : 00
#define DCHUNK_FLAG_LAST_FRG    0x01 //END      10base: 1   2base : 01
#define DCHUNK_FLAG_FL_FRG      0x01 //Unfrag   10base: 11  2base : 11

#define DCHUNK_FLAG_RO          20
#define DCHUNK_FLAG_RS          24
#define DCHUNK_FLAG_URO         4
#define DCHUNK_FLAG_URS         8

#define DCHUNK_FLAG_ROS_MASK     28 //                       10base: 12   2base : 11100
#define DCHUNK_FLAG_OS_MASK      12 //                       10base: 12   2base : 01100
#define DCHUNK_FLAG_O_MASK       4 //                        10base: 12   2base : 0100
#define DCHUNK_FLAG_S_MASK       8 //                        10base: 12   2base : 1000

#define DCHUNK_FLAG_ORDER       4 //ordered data chunk       10base: 4    2base : 0100
#define DCHUNK_FLAG_UNORDER     0 //unordered data chunk     10base: 0    2base : 0000

#define DCHUNK_FLAG_SEQ       8 //sequence data chunk        10base: 4    2base : 1000
#define DCHUNK_FLAG_UNSEQ     0 //unsequence data chunk      10base: 0    2base : 0000

#define DCHUNK_FLAG_RELIABLE_MASK     16 //                  10base: 12   2base : 10000
#define DCHUNK_FLAG_RELIABLE    16 //reliable data chunk     10base: 8    2base : 10000
#define DCHUNK_FLAG_UNRELIABLE  0 //unreliable data chunk    10base: 8    2base : 00000

/* when chunk_id == CHUNK_DATA */
#define DATA_CHUNK_FIXED_SIZE (sizeof(uint)+2*sizeof(ushort))
//4+8 = 12 bytes
#define DATA_CHUNK_FIXED_SIZES \
(CHUNK_FIXED_SIZE+DATA_CHUNK_FIXED_SIZE)
#define MAX_DATA_CHUNK_VALUE_SIZE  \
(MAX_NETWORK_PACKET_VALUE_SIZE-DATA_CHUNK_FIXED_SIZES)
struct data_chunk_fixed_t
{
	ushort stream_identity;
	ushort stream_seq_num;  // unordered msg has NO this field
	uint trans_seq_num;  // unrealiable msg has NO this field
};

struct data_chunk_t
{
	chunk_fixed_t comm_chunk_hdr;
	data_chunk_fixed_t data_chunk_hdr;
	uchar chunk_value[MAX_DATA_CHUNK_VALUE_SIZE];
};

#define DATA_CHUNK_FIXED_NOTSN_SIZE (sizeof(uint)+sizeof(ushort))
#define DATA_CHUNK_FIXED_NOTSN_SIZES (CHUNK_FIXED_SIZE+DATA_CHUNK_FIXED_NOTSN_SIZE)
#define MAX_DATA_CHUNK_VALUE_NOTSN_SIZE  \
(MAX_NETWORK_PACKET_VALUE_SIZE-DATA_CHUNK_FIXED_NOTSN_SIZES)
struct dchunk_uros_fixed_t
{
	//uint trans_seq_num; // unrealiable msg has NO this field
	ushort stream_identity;
	ushort stream_seq_num;  // unordered msg has NO this field
};
struct dchunk_uros_t
{
	chunk_fixed_t comm_chunk_hdr;
	dchunk_uros_fixed_t data_chunk_hdr;
	uchar chunk_value[MAX_DATA_CHUNK_VALUE_NOTSN_SIZE];
};

#define DCHUNK_R_FIXED_SIZE (sizeof(uint))
#define DCHUNK_R_FIXED_SIZES (CHUNK_FIXED_SIZE+DCHUNK_R_FIXED_SIZE)
#define MAX_DATA_CHUNK_VALUE_NOSSN_SIZE  \
(MAX_NETWORK_PACKET_VALUE_SIZE-DCHUNK_R_FIXED_SIZE)
struct dchunk_r_fixed_t
{
	uint trans_seq_num;  // unrealiable msg has NO this field
	// ushort stream_identity;
	//ushort stream_seq_num; // unordered msg has NO this field
};
struct dchunk_r_t
{
	chunk_fixed_t comm_chunk_hdr;
	dchunk_r_fixed_t data_chunk_hdr;
	uchar chunk_value[MAX_DATA_CHUNK_VALUE_NOSSN_SIZE];
};

#define DCHUNK_UR_FIXED_SIZES CHUNK_FIXED_SIZE
#define MAX_DCHUNK_UR_VALUE_SIZE  \
MAX_NETWORK_PACKET_VALUE_SIZE
struct dchunk_ur_t
{
	chunk_fixed_t comm_chunk_hdr;
	uchar chunk_value[MAX_DCHUNK_UR_VALUE_SIZE];
};

/*************************** variable length parameter definitions ***************************/
// See RFC4960 Section 3.2.1 Optional/Variable-Length Parameter Format From Page 19
// vl params only appear in control chunks
enum ActionWhenUnknownVlpOrChunkType
	: int
{
	STOP_PROCESS_CHUNK_FOR_FOUND_NEW_ADDR = 1,
	STOP_PROCESS_CHUNK_FOR_INVALID_MANDORY_INIT_PARAMS,
	STOP_PROCESS_CHUNK_FOR_WRONG_CHUNK_TYPE,
	STOP_PROCESS_CHUNK_FOR_NULL_CHANNEL,
	STOP_PROCESS_CHUNK_FOR_NULL_SRC_ADDR,

	SKIP_CHUNK,
	SKIP_CHUNK_REPORT_EREASON,
	STOP_PROCESS_PARAM,
	STOP_PROCES_PARAM_REPORT_EREASON,
	SKIP_PARAM,
	SKIP_PARAM_REPORT_EREASON
};
#define STOP_PROCESS_PARAM(param_type)   \
(((ushort)param_type & 0xC000)==0x0000)
#define STOP_PROCES_PARAM_REPORT_EREASON(param_type)    \
(((ushort)param_type & 0xC000)==0x4000)
#define SKIP_PARAM(param_type)       \
(((ushort)param_type & 0xC000)==0x8000)
#define SKIP_PARAM_REPORT_EREASON(param_type)    \
(((ushort)param_type & 0xC000)==0xC000)

/* optional and variable length parameter types */
#define VLPARAM_HB_INFO                 0x0001
#define VLPARAM_IPV4_ADDRESS            0x0005
#define VLPARAM_IPV6_ADDRESS            0x0006
#define VLPARAM_COOKIE                  0x0007
#define VLPARAM_UNRECOGNIZED_PARAM      0x0008
#define VLPARAM_COOKIE_PRESEREASONV          0x0009
#define VLPARAM_ECN_CAPABLE             0x8000
#define VLPARAM_HOST_NAME_ADDR          0x000B
#define VLPARAM_SUPPORTED_ADDR_TYPES    0x000C

#define VLPARAM_UNRELIABILITY                  0xC000
#define VLPARAM_ADDIP                   0xC001
#define VLPARAM_DELIP                   0xC002
#define VLPARAM_EREASONROR_CAUSE_INDICATION  0xC003
#define VLPARAM_SET_PRIMARY             0xC004
#define VLPARAM_SUCCESS_REPORT          0xC005
#define VLPARAM_ADAPTATION_LAYER_IND    0xC006
#define VLPARAM_PADDING   0x8005

#define VLPARAM_FIXED_SIZE  (2 * sizeof(ushort))
/* Header of variable length parameters */
struct vlparam_fixed_t
{
	ushort param_type;
	ushort param_length;
};
struct ipaddr_vlp_t
{
	vlparam_fixed_t vlparam_header;
	union
	{
		uint ipv4_addr;
		in6_addr ipv6_addr;
	} dest_addr_un;
};
/* Supported Addresstypes */
struct supported_addr_types_vlp_t
{
	vlparam_fixed_t vlparam_header;
	ushort address_type[4];
};
/* Cookie Preservative */
struct cookie_preservative_vlp_t
{
	vlparam_fixed_t vlparam_header;
	uint cookieLifetimeInc;
};
struct padding_vlp_t
{
	vlparam_fixed_t vlparam_header;
	uchar paddings[1];
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

/*************************** init chunk ***************************/
// See RFC4960 Section 3.3.2.Initiation (INIT) From Page 24
/**
 * this is the INIT specific part of the sctp_chunk, which is ALWAYS sent
 * it MAY take some additional variable length params.....
 * and MAY also be used for INIT_ACK chunks.
 */
struct init_chunk_fixed_t
{
	uint init_tag;
	uint rwnd;
	ushort outbound_streams;
	ushort inbound_streams;
	uint initial_tsn;
};
/* max. length of optional parameters */
#define INIT_CHUNK_TOTAL_SIZE MAX_NETWORK_PACKET_VALUE_SIZE
#define INIT_CHUNK_FIXED_SIZE (3*sizeof(uint)+2*sizeof(ushort))
#define INIT_CHUNK_FIXED_SIZES \
(INIT_CHUNK_FIXED_SIZE+CHUNK_FIXED_SIZE)
#define MAX_INIT_CHUNK_OPTIONS_SIZE  \
(MAX_NETWORK_PACKET_VALUE_SIZE - CHUNK_FIXED_SIZE -INIT_CHUNK_FIXED_SIZE)
/* init chunk structure, also used for initAck */
struct init_chunk_t
{
	chunk_fixed_t chunk_header;
	init_chunk_fixed_t init_fixed;
	uchar variableParams[MAX_INIT_CHUNK_OPTIONS_SIZE];
};

/*************************** selective acknowledgements defs ***************************/
//  see RFC4960 Section 2.3.3 
#define SACK_CHUNK_FIXED_SIZE (2*sizeof(uint)+2*sizeof(ushort))
#define MAX_SACK_CHUNK_VALUE_SIZE  \
(MAX_NETWORK_PACKET_VALUE_SIZE - CHUNK_FIXED_SIZE - SACK_CHUNK_FIXED_SIZE )
struct sack_chunk_fixed_t
{
	uint cumulative_tsn_ack;
	uint a_rwnd;
	ushort num_of_fragments;
	ushort num_of_duplicates;
};
struct sack_chunk_t
{
	chunk_fixed_t chunk_header;
	sack_chunk_fixed_t sack_fixed;
	uchar fragments_and_dups[MAX_SACK_CHUNK_VALUE_SIZE];
};
struct segment32_t
{
	uint start_tsn;
	uint stop_tsn;
};
struct segment16_t
{
	ushort start;
	ushort stop;
};
typedef uint duplicate_tsn_t;

/************************** heartbeat chunk defs ***************************/
#define HB_VLPARAM_SIZES (sizeof(heartbeat_chunk_t) - sizeof(chunk_fixed_t))
#define PMTU_CHANGE_RATE 20 //20 BYTES
/* our heartbeat chunk structure */
struct heartbeat_chunk_t
{
	chunk_fixed_t chunk_header;
	vlparam_fixed_t HB_Info;
	uint pathID;
	uint sendingTime;
	ushort mtu;
	ushort hmaclen;
#ifdef MD5_HMAC
	uchar hmac[16];
#elif SHA_HMAC
	uint hmac[5];
#endif
};

/*************************** simple chunk ***************************/
/* Simple chunks for chunks without or with bytestrings as chunk chunk_value.
 Can be used for the following chunk types:
 CHUNK_ABORT
 CHUNK_SHUTDOWN_ACK
 CHUNK_COOKIE_ACK
 ? CHUNK_COOKIE_ECHO ?

 simple chunk can also be used for transfering chunks to/from bundling, since bundling
 looks only on the chunk header.
 */
#define SIMPLE_CHUNK_SIZE MAX_NETWORK_PACKET_VALUE_SIZE
#define MAX_SIMPLE_CHUNK_VALUE_SIZE  (MAX_NETWORK_PACKET_VALUE_SIZE - CHUNK_FIXED_SIZE)
struct simple_chunk_t
{
	chunk_fixed_t chunk_header;
	uchar chunk_value[MAX_SIMPLE_CHUNK_VALUE_SIZE];
};
struct forward_tsn_chunk_t
{
	chunk_fixed_t chunk_header;
	uint forward_tsn;
	uchar variableParams[MAX_NETWORK_PACKET_VALUE_SIZE];
};

/***************************- parameter definitions***************************/
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
#include "geco-net-auth.h"
 /* cookie chunks fixed params length including chunk header */
#ifdef MD5_HMAC
#define HMAC_SIZE (16*sizeof(uchar))
#define COOKIE_FIXED_SIZE  \
(16*sizeof(uchar)+8*sizeof(ushort)+4*sizeof(uint) +2*INIT_CHUNK_FIXED_SIZE)
#elif SHA_HMAC
#define HMAC_SIZE (5*sizeof(uint))
#define COOKIE_FIXED_SIZE  \
(5*sizeof(uint)+8*sizeof(ushort)+4*sizeof(uint) +2*INIT_CHUNK_FIXED_SIZE)
#endif
struct cookie_fixed_t
{
	init_chunk_fixed_t local_initack;
	init_chunk_fixed_t peer_init;
	ushort src_port;
	ushort dest_port;
	uint local_tie_tag;
	uint peer_tie_tag;
	uint sendingTime;
	uint cookieLifetime;
#ifdef MD5_HMAC
	uchar hmac[HMAC_SIZE];
#elif SHA_HMAC
	uint hmac[HMAC_SIZE];
#endif
	ushort no_local_ipv4_addresses;
	ushort no_remote_ipv4_addresses;
	ushort no_local_ipv6_addresses;
	ushort no_remote_ipv6_addresses;
	ushort no_local_dns_addresses;
	ushort no_remote_dns_addresses;
};
/* max. length of cookie variable length params parameters */
#define MAX_COOKIE_VLPARAMS_SIZE \
(MAX_NETWORK_PACKET_VALUE_SIZE -  COOKIE_FIXED_SIZE)
/* cookie echo chunk structure */
struct cookie_echo_chunk_t
{
	chunk_fixed_t chunk_header;
	cookie_fixed_t cookie;
	uchar vlparams[MAX_COOKIE_VLPARAMS_SIZE];
};
#define COOKIE_PARAM_SIZE \
(COOKIE_FIXED_SIZE+VLPARAM_FIXED_SIZE)
/* the variable parameters should be appended in thatsame order to the cookie*/
struct cookie_param_t
{
	vlparam_fixed_t vlparam_header;
	cookie_fixed_t ck;
};

/*************************** Error definitions ***************************/
/**
 * Errorchunks: for error-chunks the SCTP_simple_chunk can be used since it contains
 * only varible length params.
 */
#define ERROR_CHUNK_TOTAL_SIZE \
(CHUNK_FIXED_SIZE+MAX_DATA_CHUNK_VALUE_SIZE)
struct error_chunk_t
{
	chunk_fixed_t chunk_header;
	uchar chunk_value[MAX_DATA_CHUNK_VALUE_SIZE];
};
#define ERR_CAUSE_FIXED_SIZE (2*sizeof(ushort))
struct error_cause_t
{
	ushort error_reason_code;
	ushort error_reason_length;
	uchar error_reason[MAX_NETWORK_PACKET_VALUE_SIZE];
};

const static char* ECCSTRS[32] =
{ "ECC_INVALID_STREAM_ID", "ECC_MISSING_MANDATORY_PARAM", "ECC_STALE_COOKIE_ERROR", "ECC_OUT_OF_RESOURCE_ERROR",
	"ECC_UNRESOLVABLE_ADDRESS", "ECC_UNRECOGNIZED_CHUNKTYPE", "ECC_INVALID_MANDATORY_PARAM",
	"ECC_UNRECOGNIZED_PARAMS", "ECC_NO_USER_DATA", "ECC_COOKIE_RECEIVED_DURING_SHUTDWN",
	"ECC_RESTART_WITH_NEW_ADDRESSES", "ECC_USER_INITIATED_ABORT", "ECC_PROTOCOL_VIOLATION",
	"ECC_PEER_INSTANCE_NOT_FOUND", "ECC_PEER_NOT_LISTENNING_PORT" };

// Error reson codes
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
#define ECC_PEER_INSTANCE_NOT_FOUND        14
#define ECC_PEER_NOT_LISTENNING_PORT        15

#define ECC_DELETE_LAST_IP_FAILED       16
#define ECC_OP_REFUSED_NO_RESOURCES     17
#define ECC_DELETE_SOURCE_ADDRESS       18
#define ECC_UNMATCHED_DEST_ADDR_FAMILY       19
#define ECC_PEER_NOT_LISTENNING_ADDR        20
#define ECC_PEER_NOT_SUPPORT_ADDR_TYPES        21

// Error REASON param defs
struct stale_cookie_err_t
{
	vlparam_fixed_t vlparam_header;
	uint staleness;
};
struct invalid_stream_id_err_t
{
	ushort stream_id;
	ushort reserved;
};
struct unresolved_addr_err_t
{
	vlparam_fixed_t vlparam_header;
	uchar addrs[MAX_NETWORK_PACKET_VALUE_SIZE];
};
struct unrecognized_params_err_t
{
	vlparam_fixed_t vlparam_header;
	uchar params[MAX_NETWORK_PACKET_VALUE_SIZE];
};
struct missing_mandaory_params_err_t
{
	unsigned int numberOfParams;
	unsigned short params[20];
};

/************* ASCONF Chunk and Parameter Types *************/
struct asconfig_chunk_fixed_t
{
	uint serial_number;
	ushort reserved16;
	uchar reserved8;
	uchar address_type;
	uint sctp_address[4];
	uchar variableParams[MAX_NETWORK_PACKET_VALUE_SIZE];
};
struct asconfig_ack_chunk_fixed_t
{
	uint serial_number;
	uchar variableParams[MAX_NETWORK_PACKET_VALUE_SIZE];
};
struct asconfig_chunk_t
{
	chunk_fixed_t chunk_header;
	asconfig_chunk_fixed_t asc_fixed;
	uchar variableParams[MAX_INIT_CHUNK_OPTIONS_SIZE];
};
struct asconf_ack_chunk_t
{
	chunk_fixed_t chunk_header;
	asconfig_ack_chunk_fixed_t asc_ack;
	uchar variableParams[MAX_INIT_CHUNK_OPTIONS_SIZE];
};
struct padding_chunk_t
{
	chunk_fixed_t chunk_header;
	uchar variableParams[1];
};

struct packet_params_t
{
	// used for free this packet_params_t
	uint total_packet_bytes;//received length from mtra
	uint released_bytes;//curr release bytes
	char data[PMTU_HIGHEST];
};

/******************** some useful macros ************************/
#define get_chunk_length(chunk)        (ntohs((chunk)->chunk_length))
// Chunk classes for distribution and any other modules which might need it
#define is_init_control_chunk(chunk) \
((chunk)->chunk_header.chunk_id == CHUNK_INIT       || \
(chunk)->chunk_header.chunk_id == CHUNK_INIT_ACK   || \
(chunk)->chunk_header.chunk_id == CHUNK_COOKIE_ECHO || \
(chunk)->chunk_header.chunk_id == CHUNK_COOKIE_ACK)
#define is_init_cookie_chunk(chunk)\
((chunk)->chunk_header.chunk_id == CHUNK_INIT || \
(chunk)->chunk_header.chunk_id == CHUNK_COOKIE_ECHO)
#define is_init_ack_chunk(chunk)   \
((chunk)->chunk_header.chunk_id == CHUNK_INIT_ACK)
#define is_shutdown_ack_chunk(chunk) \
((chunk)->chunk_header.chunk_id == CHUNK_SHUTDOWN_ACK)
#define is_shutdown_complete_chunk(chunk) \
((chunk)->chunk_header.chunk_id == CHUNK_SHUTDOWN_COMPLETE)
#endif /* MY_MESSAGES_H_ */
