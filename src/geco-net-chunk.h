/*
 *
 * Copyright (c) 1994
 * Hewlett-Packard Company SGI_STL
 *
 * Permission to use, copy, modify, distribute and sell this software
 * and its documentation for SGI_STL purpose is hereby granted without fee,
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation.  Hewlett-Packard Comp SGI_STL makes no
 * representations about the suitability of this software for SGI_STL
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * Copyright (c) 1997
 * Silicon Graphics
 *
 * Permission to use, copy, modify, distribute and sell this software
 * and its documentation for SGI_STL purpose is hereby granted without fee,
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation.  Silicon Graphics makes no
 * representations about the suitability of this software for SGI_STL
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * Copyright (c) 2016
 * Geco Gaming Company
 *
 * Permission to use, copy, modify, distribute and sell this software
 * and its documentation for GECO purpose is hereby granted without fee,
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation.  GECO makes no representations about
 * the suitability of this software for GECO purpose.
 * It is provided "as is" without express or implied warranty.
 *
 */

 /*
  * geco-ds-type-traitor-ext.h
  *  Created on: 17 Aug 2016 Author: jakez
  *
  * all build_* functions will allocate memory for a chunk
  * may call add2chunklist() followed this function in callee's context
  *  to add this chunk to list for further processing
  *
  *  all put_* functions handle fills up particular field of a chunk or packet,
  *  chunk length value will NOT be transfomed into network order for future use
  *  they will return the written length that has been 4 bytes aligned for calee
  *  to update its current write position
  */

# ifndef __INCLUDE_CHUNK_BUILDER_H
# define __INCLUDE_CHUNK_BUILDER_H

#include "geco-net-common.h"

  /**
   *  check if this is a good cookie, i.e. verify HMAC signature
   *  @return TRUE when signature is correct, else false
   */
bool mch_verify_hmac(cookie_echo_chunk_t* cookie_chunk);
int mch_validate_init_vlps(uint src_cid, uint dest_cid);



/**
* @brief returns a pointer to the beginning of a simple chunk,
* internally fillup chunk length.
*/
extern simple_chunk_t *mch_complete_simple_chunk(uint chunkID);
/**
* mch_free_simple_chunk removes the chunk from the array of simple_chunks_ and frees the
* memory allocated for that chunk*/
extern void mch_free_simple_chunk(uint chunkID);
/**
removes the chunk from the array of simple_chunks_ without freeing the
memory allocated for that chunk.
Used in the following 2 cases:
1) the caller wants to keep the chunk for retransmissions.
2) the chunk was created with uchar mch_make_simple_chunk(simple_chunk_t* chunk)
and the pointer to the chunk points into an geco packet from recv_geco_packet(),
which was allocated as a whole. In this case the chunk can not be freed here.*/
extern void mch_remove_simple_chunk(uchar chunkID);
extern chunk_id_t add2chunklist(simple_chunk_t * chunk, const char *log_text = NULL);


simple_chunk_t *mch_read_simple_chunk(uint chunkID);
// ch_receiverWindow reads the remote receiver window from an init or initAck 
uint mch_read_rwnd(uint initcid);
// ch_receiverWindow reads the remote receiver window from an init or initAck 
uint mch_read_itsn(uint initcid);
init_chunk_fixed_t* mch_read_init_fixed(uint initcid);
/* reads the simple_chunks_ type of a chunk.*/
uchar mch_read_chunkid(uchar chunkID);
/*reads the number of output streams from an init or initAck */
ushort mch_read_ostreams(uchar init_chunk_id);
/*reads the number of input streams from an init or initAck */
ushort mch_read_instreams(uchar init_chunk_id);
uint mch_read_itag(uchar init_chunk_id);
/**
*  @brief returns the suggested cookie lifespan increment if a cookie
*  preservative is present in a init chunk.
*/
uint mch_read_cookie_preserve(uint chunkID, bool ignore_cookie_life_spn_from_init_chunk_, uint defaultcookielife);
/**
* @brief scans for a parameter of a certain type in a message string.
* The message string must point to a parameter header.
* The function can also be used to find parameters within a parameter
* (e.g. addresses within a cookie).
* @param [in] vlp_type type of paramter to scan for,
* @param [in]
* vlp_fixed pointer to the first parameter header, from which we start scanning
* @param [in] len    maximum length of parameter field, that may be scanned.
* @return
* position of first parameter occurence
* i.e.  NULL returned  if not found !!!!!!!
* supports all vlp type EXCEPT of
* VLPARAM_ECN_CAPABLE andVLPARAM_HOST_NAME_ADDR)
*/
uchar* mch_read_vlparam(uint vlp_type, uchar* vlp_fixed, uint len);
/**
* only used for finding some vlparam in init or init ack chunks
* NULL no geco_instance_params, otherwise have geco_instance_params, return vlp fixed*/
uchar* mch_read_vlparam_init_chunk(uchar * setup_chunk, uint chunk_len, ushort param_type);



void mch_write_vlp_supportedaddrtypes(chunk_id_t chunkID, bool with_ipv4, bool with_ipv6, bool with_dns);
void mch_write_vlp_of_init_chunk(chunk_id_t initChunkID, ushort pCode, uchar* data = 0, ushort dataLength = 0);
int mch_write_vlp_setprimarypath(uint initAckCID, uint initCID); //TODO
int mch_write_vlp_unreliability(uint initAckCID, uint initCID);
int mch_write_vlp_addrlist(uint chunkid, sockaddrunion local_addreslist[MAX_NUM_ADDRESSES], uint local_addreslist_size);
int mch_write_vlp_ecn(uint initAckID, uint initCID);//TODO
void mch_write_error_cause(chunk_id_t chunkID, ushort errcode, uchar* errdata = 0, uint errdatalen = 0);
void mch_write_error_cause_unrecognized_chunk(chunk_id_t cid, error_cause_t*ecause, uchar* errdata, uint errdatalen);
int mch_write_hmac(cookie_param_t* cookieString);
void mch_write_cookie(uint initCID, uint initAckID, init_chunk_fixed_t* peer_init,
	init_chunk_fixed_t* local_initack, uint cookieLifetime, uint local_tie_tag,
	uint peer_tie_tag, ushort last_dest_port, ushort last_src_port,
	sockaddrunion local_Addresses[], uint num_local_Addresses,
	bool local_support_unre,
	bool local_support_addip,
	sockaddrunion peer_Addresses[],
	uint num_peer_Addresses);



/*
* swaps length INSIDE the packet and enters chunk into the current list call  mch_remove_simple_chunk() to free
*/
uchar mch_make_simple_chunk(simple_chunk_t* chunk);
/**
* creates a simple chunk except of DATA chunk. It can be used for parameterless
* chunks like abort, cookieAck and shutdownAck. It can also be used for chunks
* that have only variable length parameters like the error chunks
*/
uint mch_make_simple_chunk(uint chunk_type, uchar flag);
/* makes an initAck and initializes the the fixed part of initAck */
chunk_id_t mch_make_init_ack_chunk(uint initTag, uint rwnd, ushort noOutStreams, ushort noInStreams, uint initialTSN);
/* makes an initAck and initializes the the fixed part of initAck */
chunk_id_t mch_make_init_chunk(uint initTag, uint rwnd, ushort noOutStreams, ushort noInStreams, uint initialTSN);
chunk_id_t mch_make_cookie_echo(cookie_param_t * cookieParam);
error_chunk_t* mch_make_error_chunk();
chunk_id_t mch_make_init_chunk_from_cookie(cookie_echo_chunk_t* cookie_echo_chunk);
chunk_id_t mch_make_init_ack_chunk_from_cookie(cookie_echo_chunk_t* cookie_echo_chunk);

#endif
