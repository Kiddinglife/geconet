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
#include "globals.h"


extern error_chunk_t* build_error_chunk();
extern uint put_error_cause_unrecognized_chunk(error_cause_t*ecause,
        uchar* errdata, uint errdatalen);
extern uint put_error_cause(error_cause_t*ecause,
        ushort errcode, uchar* errdata,ushort errdatalen);

/*
 makes an init and initializes the the fixed part of init
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |   Type = 1    |  Chunk Flags  |      Chunk Length             |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         Initiate Tag                          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Advertised Receiver Window Credit (a_rwnd)          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Number of Outbound Streams   |  Number of Inbound Streams    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                          Initial TSN                          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 /              Optional/Variable-Length Parameters              /
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 refer to 3.3.2.  Initiation (INIT) (1)
 */
extern init_chunk_t* build_init_chunk(
        unsigned int initTag,
        unsigned int arwnd,
        unsigned short noOutStreams,
        unsigned short noInStreams,
        unsigned int initialTSN);


extern init_chunk_t* build_init_ack_chunk(
        unsigned int initTag,
        unsigned int arwnd,
        unsigned short noOutStreams,
        unsigned short noInStreams,
        unsigned int initialTSN);


/*
 function to add supported address types variable parameter to init (ack) chunk
 @ret the toal length of param including param type, param len and pram value

 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Type = 12            |          Length               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |        Address Type #1        |        Address Type #2        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                            ......                             |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+
 Address Type: 16 bits (unsigned integer)
 This is filled with the type value of the corresponding address
 TLV (e.g., IPv4 = 5, IPv6 = 6, Host name = 11).
 */
extern uint put_vlp_supported_addr_types(supported_address_types_t* initchunk, bool with_ipv4,
        bool with_ipv6, bool with_dns);


/*
 *  function to add user supported addresses to init (ack) chunk
 @ret the toal length of param including param type, param len and pram value

 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |        Type = 5               |      Length = 8               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        IPv4 Address                           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |            Type = 6           |          Length = 20          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 |                         IPv6 Address                          |
 |                                                               |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 Combined with the Source Port Number in the SCTP common header,
 the value passed in an IPv4 or IPv6 Address parameter indicates a
 transport address the sender of the INIT will support for the
 association being initiated.  That is, during the life time of
 this association, this IP address can appear in the source address
 field of an IP datagram sent from the sender of the INIT, and can
 be used as a destination address of an IP datagram sent from the
 receiver of the INIT.

 More than one IP Address parameter can be included in an INIT
 chunk when the INIT sender is multi-homed.  Moreover, a multi-
 homed endpoint may have access to different types of network;
 thus, more than one address type can be present in one INIT chunk,
 i.e., IPv4 and IPv6 addresses are allowed in the same INIT chunk.

 If the INIT contains at least one IP Address parameter, then the
 source address of the IP datagram containing the INIT chunk and
 any additional address(es) provided within the INIT can be used as
 destinations by the endpoint receiving the INIT.  If the INIT does
 not contain any IP Address parameters, the endpoint receiving the
 INIT MUST use the source address associated with the received IP
 datagram as its sole destination address for the association.

 Note that not using any IP Address parameters in the INIT and INIT
 ACK is an alternative to make an association more likely to work
 across a NAT box.
 */
extern uint put_vlp_addrlist(ip_address_t* ip_addr,
        sockaddrunion local_addreslist[MAX_NUM_ADDRESSES],
        uint local_addreslist_size);
#endif
