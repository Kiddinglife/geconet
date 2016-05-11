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
#include <unordered_map>
#include <vector>

/*------------------- Functions called by the ULP -----------------------*/
/* This functions are defined in a seperate header file dctp.h
 * in order to seperate the interface to the ULP and the interface
 * to other modules within DCTP.*/
/*------------------------------------------------------------------*/

/**
 * This struct stores data of dispatcher_t.
 * Each dispatcher_t is related to one port and to one poller.
 * This may change soon !
 *  SCTP_INSTANCE
 * a dispather could have many endpoints
 * this is similar to TCP listenning socket opens a new socket for new conenctions
 * with binding a new socket pair as indentifier.
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

    bool supportsPRSCTP;
    bool supportsADDIP;
};

/**
 * This struct contains all data of an endpoint. As far as other modules must know
 * elements of this struct, read functions are provided. No other module has write
 * access to this structure
 * ASSCIATION
 * 偶联（AssociATION） 偶联就是两个 SCTP 端点通过SCTP 协议规定的4 步握手机制建立起来
 * 的进行数据 传递的逻辑联系或者通道。 SCTP 协议规定在任何时刻两个端点之间能且仅能建立
 * 一个偶联。由于偶联由两个 端点的传送地址来定义，所以通过数据配置本地IP 地址、
 * 本地SCTP 端口号、对端 IP 地址、对端SCTP 端口号等四个参数，可以唯一标识一个SCTP 偶联
 */
struct endpoint_t
{
    /*The current ID of this endpoint,
     it is used as a key to find a endpoint in the list,
     and never changes in the  live of the endpoint */
    uint ep_id;

    uint local_tag; /*The local tag of this endpoint*/
    uint remote_tag; /*The tag of remote side of this endpoint*/

    /*Pointer to the SCTP-instance this association
     belongs to. It is equal to the wellknown port
     number of the ULP that uses this instance*/
    dispatcher_t* dispatcher;

    /* a single same port  plus multi different ip addresses consist of a uniqe endpoint*/
    ushort local_port;
    sockaddrunion *local_addres;
    uint local_addres_size;

    unsigned short remote_port;
    sockaddrunion *remote_addres;
    uint remote_addres_size;

    uchar ipTos;
    uint locally_supported_addr_types;
    uint maxSendQueue;
    uint maxRecvQueue;
    bool is_INADDR_ANY;
    bool is_IN6ADDR_ANY;

    void *flow_control;
    void *reliable_transfer_control;
    void *receive_control;
    void *stream_control;
    void *path_control;
    void *bundle_control;
    void *dctp_control;

    /* do I support the DCTP extensions ? */
    bool locally_supported_PRDCTP;
    bool locally_supported_ADDIP;
    /* and these values for our peer */
    bool remotely_supported_PRSCTP;
    bool remotely_supported_ADDIP;

    /** marks an association for deletion */
    bool deleted;
    /** transparent pointer to some upper layer data */
    void * application_layer_dataptr;
};

class dispatch_layer_t
{
public:
    bool sctpLibraryInitialized;

    /*Keyed list of end_points_ with ep_id as key*/
    //typedef uint endpoint_id;
    //typedef ushort endpoint_local_port;
    //std::unordered_map<endpoint_id, endpoint_t*> end_points_;
    //std::unordered_map<endpoint_local_port, endpoint_t*> end_points_;
    std::vector<endpoint_t*> endpoints_list_;

    /*Keyed list of dispatchers with dispatcher name as key*/
    std::vector<dispatcher_t*> dispathers_list_;

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
    uint last_init_tag_;

    /**
     * Whenever an external event (ULP-call, socket-event or timer-event) this variable must
     * contain the addressed association.
     * Read functions for 'global data' read data from the association pointed to by this pointer.
     * This pointer must be reset to null after the event  has been handled.
     */
    endpoint_t *curr_endpoint_;
    endpoint_t tmp_endpoint_;
    sockaddrunion tmp_addr_;
    dispatcher_t tmp_dispather_;

    dispatch_layer_t();

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
    void recv_dctp_packet(int socket_fd, char *buffer, int bufferLength,
            sockaddrunion * source_addr, sockaddrunion * dest_addr);

private:
    /**
     *   retrieveAssociation retrieves a association from the list using the transport address as key.
     *   Returns NULL also if the association is marked "deleted" !
     *   CHECKME : Must return NULL, if no Address-Port combination does not occur in ANY existing assoc.
     *  If it occurs in one of these -> return it

     * two associations are equal if their remote and local ports are equal and at least
     one of their remote addresses are equal. This is like in TCP, where a connection
     is identified by the transport address, i.e. the IP-address and port of the peer.

     *   @param  src_addr address from which data arrived
     *   @param  src_port SCTP port from which data arrived
     *   @return pointer to the retrieved association, or NULL
     *   TODO hash(src_addr, src_port, dest_port) as key for endpoint to improve the performaces
     */
    endpoint_t *find_endpoint_by_transport_addr(sockaddrunion * src_addr,
            ushort src_port, ushort dest_port);
    bool cmp_endpoint(const endpoint_t& a, const endpoint_t& b);

    /**
     *   @return pointer to the retrieved association, or NULL
     */
    dispatcher_t* find_dispatcher_by_transport_addr(sockaddrunion* dest_addr,
            uint address_type);
    bool cmp_dispatcher(const dispatcher_t& a, const dispatcher_t& b);

    /**
     * after dispatcher and  endpoint have been found for an
     * incoming packet, this function will return, if a packet may be processed
     * or if it is not destined for this instance
     */
    bool validate_dest_addr(sockaddrunion * dest_addr);

    /**returns a value indicating which chunks are in the packet.*/
    uint get_chunk_types(char* packet_value, int len);
};
#endif
