/*
* Copyright (c) 2016
* Geco Gaming Company
*
* Permission to use, copy, modify, distribute and sell this software
* and its documentation for GECO purpose is hereby granted without fee,
* provided that the above copyright notice appear in all copies and
* that both that copyright notice and this permission notice appear
* in supporting documentation. Geco Gaming makes no
* representations about the suitability of this software for GECO
* purpose.  It is provided "as is" without express or implied warranty.
*
*/

/**
* Created on 22 April 2016 by Jake Zhang
* Reviewed on 07 May 2016 by Jakze Zhang
*/

#ifndef __INCLUDE_DISPATCH_LAYER_H
#define __INCLUDE_DISPATCH_LAYER_H

#include "globals.h"

/*------------------- Functions called by the ULP -----------------------*/
/* This functions are defined in a seperate header file sctp.h in order to seperate the interface to
the ULP and the interface to other modules within SCTP.*/
/*------------------------------------------------------------------*/


/**
 * This struct stores data of dispatcher_t.
 * Each dispatcher_t is related to one port and to
 * one poller. This may change soon !
 */
struct dispatcher_t
{
    /*The name of this SCTP-instance, used as key*/
    ushort dispatcher_name;

    /*The local port of this instance, or zero for don't cares.
    Once assigned this should not be changed !*/
    ushort local_port;
    ushort local_addres_size;
    sockaddrunion* local_addres_list;
    char* local_addres_str_list;
    bool is_inaddr_any;
    bool is_in6addr_any;
    bool is_ip4;
    bool is_ip6;

    applicaton_layer_cbs_t applicaton_layer_cbs; /*setup by app layer*/
    /*maximum number of incoming streams that this instance will take */
    ushort noOfInStreams;
    /*maximum number of outgoingng streams that this instance will take */
    ushort noOfOutStreams;

    /*default params for dispatcher initialization*/
    uint default_rtoInitial;
    uint default_validCookieLife;
    uint default_assocMaxRetransmits;
    uint default_pathMaxRetransmits;
    uint default_maxInitRetransmits;
    uint default_myRwnd;
    uint default_delay;
    uint default_rtoMin;
    uint default_rtoMax;
    uint default_maxSendQueue;
    uint default_maxRecvQueue;
    uint default_maxBurst;
    uint supportedAddressTypes;
    uchar default_ipTos;
    bool    supportsPRSCTP;
    bool    supportsADDIP;
};

struct dispatch_layer_t
{
    bool sctpLibraryInitialized;

    /*Keyed list of associations with the association - ID as key*/

    /**
     * Whenever an external event (ULP-call, socket-event or timer-event) this variable must
     * contain the addressed sctp instance.
     * This pointer must be reset to null after the event  has been handled.
     */
    dispatcher_t *dispatcher_;

    /**
    initAck is sent to this address
    In this case, dctp-control reads this address on reception of the cookie echo
    (which consequently also does not contain an addresslist) to initialize the new association.
    */
    sockaddrunion *last_source_addr_;
    sockaddrunion *last_dest_addr_;
    short last_src_path_;
    ushort last_src_port_;
    ushort last_dest_port_;
    uint last_init_tag_;;


    dispatch_layer_t()
    {
        sctpLibraryInitialized = false;

    }
    /*------------------- Functions called by the Unix-Interface --------------*/
    /**
    * \fn recv_dctp_packet
    *  recv_dctp_packet is the callback function of the DCTP-message dispatch_layer.
    *  It is called by the Unix-interface module when a new ip packet is received.
    *  This function also performs OOTB handling, tag verification etc.
    *  (see also RFC 4960, section 8.5.1.B)  and sends data to the bundling module of
    *  the right association
    *
    *  @param socket_fd          the socket file discriptor
    *  @param buffer             pointer to arrived datagram
    *  @param bufferlength       length of datagramm
    *  @param fromAddress        source address of DG
    *  @param portnum            bogus port number
    */
    void recv_dctp_packet(int socket_fd, char *buffer,
        int bufferLength, union sockaddrunion * source_addr,
    union sockaddrunion * dest_addr);

};
#endif