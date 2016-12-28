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

#include <vector>
#include <list>
#include <array>
#ifdef _WIN32
#include <unordered_map>
#else
#include <tr1/unordered_map>
#endif

#include "geco-net-common.h"
#include "geco-malloc.h"
#include "geco-net.h"
#include "geco-net-auth.h"
#include "geco-net-chunk.h"

struct timeout;

/**
 * This struct stores data of geco_instance_t.
 * Each geco_instance_t is related to one port and to one poller.
 * This may change soon !
 *  SCTP_INSTANCE
 * a dispather could have many endpoints
 * this is similar to TCP listenning socket opens a new socket for new conenctions
 * with binding a new socket pair as indentifier.
 */
struct geco_instance_t
{
    /*The name of this SCTP-instance, used as key*/
    ushort dispatcher_name;

    /*The local port of this instance, or zero for don't cares.
     Once assigned this should not be changed !*/
    ushort local_port;
    ushort local_addres_size;
    sockaddrunion* local_addres_list; /* when init, set port to local_port*/
    char* local_addres_str_list;
    bool is_inaddr_any;
    bool is_in6addr_any;
    bool use_ip4;
    bool use_ip6;

    ulp_cbs_t ulp_callbacks; /*setup by app layer*/

    /*maximum number of incoming streams that this instance will take */
    ushort noOfInStreams;
    /*maximum number of outgoingng streams that this instance will take */
    ushort noOfOutStreams;

    /*default params for geco_inst initialization*/
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
 * this struct contains all data belonging to a bundling module
 * Refers to RFC 4960, the sender should always try to bundle ctrl or/and sack
 * chunks in an outgoing packet
 * when sack chunk presents,
 * we use sack_buf to bundle ctrl or/and data chunks
 * when ctrl chunk presents AND NO sack chunk,
 * we use ctrl_buf to bundle data chunks
 * when data chunk presents AND NO sack AND ctrl chunks,
 * we use data_buf and nothing to bundle.
 */
struct bundle_controller_t
{
    /** buffer for control chunks */
    char ctrl_buf[MAX_GECO_PACKET_SIZE];
    /** buffer for sack chunks */
    char sack_buf[MAX_GECO_PACKET_SIZE];
    /** buffer for data chunks */
    char data_buf[MAX_GECO_PACKET_SIZE];

    /* Leave some space for the SCTP common header */
    /**  current position in the buffer for control chunks */
    uint ctrl_position;
    /**  current position in the buffer for sack chunks */
    uint sack_position;
    /**  current position in the buffer for data chunks */
    uint data_position;

    /** is there data to be sent in the buffer ? */
    bool data_in_buffer;
    /**  is there a control chunk  to be sent in the buffer ? */
    bool ctrl_chunk_in_buffer;
    /**  is there a sack chunk  to be sent in the buffer ? */
    bool sack_in_buffer;

    /** status flag for correct sequence of actions */
    bool got_send_request;
    bool got_send_address;
    bool locked;
    /** did we receive a shutdown, either by ULP or peer ? */
    bool got_shutdown;
    // this is stored in mbu if so, geco packet fixed sies are 4 bytes veri tag,
    // othwewise 12 bytes (2 srcport + 2 destport + 4 veritag + 4 checksum)
    // this variable is for each channel
    uint requested_destination;
	uint geco_packet_fixed_size;

    bundle_controller_t()
    {
      reset();
    }
    void reset()
    {
      requested_destination = 0;
	  geco_packet_fixed_size = GECO_PACKET_FIXED_SIZE;
      ctrl_position = data_position = sack_position = geco_packet_fixed_size;
      got_shutdown = locked = got_send_address = got_send_request = data_in_buffer = ctrl_chunk_in_buffer =
          sack_in_buffer = false;
    }
};

/**
 * this struct contains all necessary data for
 * creating SACKs from received data chunks
 * both are closely Connected
 * as sack is created based on form recv data chunks
 */
struct recv_controller_t  //recv_ctrl
{
    sack_chunk_t* sack_chunk;
    uint cumulative_tsn;
    /*stores highest tsn received so far, taking care of wraps
     * i.e. highest < lowest indicates a wrap */
    uint lowest_duplicated_tsn;
    uint highest_duplicated_tsn;
    bool contains_valid_sack;
    bool timer_running;
    bool new_chunk_received; /*indicates whether a received chunk is truly new */
    timeout* sack_timer; /* timer for delayed sacks */
    int datagrams_received;
    uint sack_flag; /* 1 (sack each data chunk) or 2 (sack every second chunk)*/
    uint last_address;
    uint channel_id;
    uint my_rwnd;
    uint delay; /* delay for delayed ACK in msecs */
    uint numofdestaddrlist; /* number of dest addresses */
    std::list<internal_data_chunk_t*> fragmented_data_chunks_list;
    std::list<internal_data_chunk_t*> duplicated_data_chunks_list;
};

/**
 * this struct contains the necessary data per (destination or) path.
 * There may be more than one within an channel
 */
struct path_params_t
{
    //id of path
    uint path_id;
    // operational state of path ctrl for one path
    short state;
    //true if hb is enabled
    bool hb_enabled;
    //true as long as RTO calc has been done
    bool firstRTO;
    //only once per hb-interval
    bool timer_backoff;
    //set to true when data chunks are acked
    bool data_chunk_acked;
    // true if chunks have been senr over this path within last RTO
    bool data_chunks_sent_in_last_rto;
    //set to true when a hb is sent
    bool hb_sent;
    /*set to true when a hearbeat is acknowledged and to false when a
     heartbeat is sent when the heartbeat timer expires. */
    bool heartbeatAcked;
    // conuter for retrans on a single path
    uint retrans_count;
    // rto
    uint rto;
    //smoothed rounf trip tine
    uint srtt;
    //round trip time variation
    uint rttvar;
    //defines the rate at which hb is sent
    uint hb_interval;
    //current mtu of this path
    uint pmtu;
    // id of hb timer
    timeout* hb_timer_id;
    //time of last RTO update
    uint64 last_rto_update_time;
};

/**
 * this struct contains all necessary data for one instance of the path management
 * module. There is one such module per existing channel.
 */
struct geco_channel_t;
struct path_controller_t
{
    //channel id
    uint channel_id;
    geco_channel_t* channel_ptr;

    // store the current primary path
    int primary_path;
    int destaddr_in_init_sentbyme;

    //the number of paths used by this channel
    int path_num;
    //counter for all retransmittions over all paths
    uint total_retrans_count;
    //pointer to path-secific prams maybe more than one
    path_params_t* path_params;
    //max retrans per path
    uint max_retrans_per_path;
    // initial RTO, a configurable parameter
    uint rto_initial;
    /** minimum RTO, a configurable parameter */
    uint rto_min;
    /** maximum RTO, a configurable parameter */
    uint rto_max;
};

/**state controller structure. Stores the current state of the channel.*/
struct smctrl_t
{
    /*@{ */
    /** the state of this state machine */
    ChannelState channel_state;
    /** stores timer-ID of init/cookie-timer, used to stop this timer */
    timeout* init_timer_id;
    /** */
    uint init_timer_interval;
    /**  stores the channel id (==tag) of this association */
    uint channel_id;
    /** Counter for init and cookie retransmissions */
    uint init_retrans_count;
    /** pointer to the init chunk data structure (for retransmissions) */
    init_chunk_t *my_init_chunk;  //!< init chunk sent by me MUST NOT free it as this is from mtra
    int addr_my_init_chunk_sent_to;

    /** pointer to the cookie chunk data structure (for retransmissions) */
    cookie_echo_chunk_t *peer_cookie_chunk; //MUST NOT free it as this is from mtra
    /** my tie tag for cross initialization and other sick cases */
    uint local_tie_tag;
    /** peer's tie tag for cross initialization and other sick cases */
    uint peer_tie_tag;
    /** todo we store these here, too. Maybe better be stored with StreamEngine ? */
    ushort outbound_stream;
    /** todo we store these here, too. Maybe better be stored with StreamEngine ? */
    ushort inbound_stream;
    /** value for maximum retransmissions per association */
    uint max_assoc_retrans_count;
    /** value for maximum initial retransmissions per association */
    uint max_init_retrans_count;
    /** value for the current cookie lifetime */
    uint cookie_lifetime;
    /** the geco instance */
    geco_instance_t* instance;
    geco_channel_t* channel;
    /*@} */
};

/**
 * this struct contains all necessary data for retransmissions
 * and processing of received SACKs,
 * both are closely Connected as retrans is determined based on recv sacks
 */
struct reltransfer_controller_t
{
    uint lowest_tsn; /*storing the lowest tsn that is in the list */
    uint highest_tsn;/*storing the highest tsn that is in the list */
    uint num_of_chunks;
    uint highest_acked;
    /** a list that is ordered by ascending tsn values */
    std::list<internal_data_chunk_t*> chunk_list_tsn_ascended;  //@fixme what is the type used ?

    struct timeval sack_arrival_time;
    struct timeval saved_send_time;
    /*this val stores 0 if retransmitted chunks have been acked, else 1 */
    uint save_num_of_txm;
    uint newly_acked_bytes;
    uint numofdestaddrlist;
    uint channel_id;
    uint peer_arwnd;
    bool all_chunks_are_unacked;
    bool shutdown_received;
    bool fast_recovery_active;
    /** the exit point is only valid, if we are in fast recovery */
    uint fr_exit_point;
    uint advancedPeerAckPoint;
    uint lastSentForwardTSN;
    uint lastReceivedCTSNA;
    std::vector<internal_data_chunk_t*> prChunks;
};

/**
 * this struct contains all relevant congestion control parameters for
 * one PATH to the destination/association peer endpoint
 */
struct congestion_parameters_t
{
    unsigned int cwnd;
    unsigned int cwnd2;
    unsigned int partial_bytes_acked;
    unsigned int ssthresh;
    unsigned int mtu;
    uint64 time_of_cwnd_adjustment;
    uint64 last_send_time;
};

struct flow_controller_t
{
    uint outstanding_bytes;
    uint peerarwnd;
    uint numofdestaddrlist;
    congestion_parameters_t* cparams;
    uint current_tsn;
    std::list<internal_data_chunk_t*> chunk_list;  //todo not really sure GList *chunk_list;
    uint list_length;
    /** one timer may be running per destination address */
    timeout** T3_timer;
    /** for passing as parameter in callback functions */
    uint *addresses;
    uint channel_id;
    /** */
    bool shutdown_received;
    bool waiting_for_sack;
    bool t3_retransmission_sent;
    bool one_packet_inflight;
    bool doing_retransmission;
    uint maxQueueLen;
};

/*this stores all the data need to be delivered to the user*/
struct delivery_data_t
{
    uchar chunk_flags;
    uint data_length;
    uint tsn;
    ushort stream_id;
    ushort stream_sn;
    uint protocolId;
    uint fromAddressIndex;
    uchar data[MAX_DATA_CHUNK_VALUE_SIZE];
};

/*stores several chunks that can be delivered to the user as one message*/
struct delivery_pdu_t
{
    uint number_of_chunks;
    uint read_position;
    uint read_chunk;
    uint chunk_position;
    uint total_length;
    /* one chunk pointer or an array of these */
    delivery_data_t** ddata;
};

struct recv_stream_t  //ReceiveStream
{
    /* list of PDUs waiting for pickup (after notification has been called) */
    std::list<delivery_pdu_t*> pduList;
    /* list of PDUs waiting for transfer to pduList and doing mdi arrive notification */
    std::list<delivery_pdu_t*> prePduList;
    /* used to detect Protocol violations in se_searchReadyPdu */
    ushort highestSSN;
    ushort nextSSN;
    bool highestSSNused;
    int index;
};

struct send_stream_t  //SendStream
{
    unsigned int nextSSN;
};

struct deliverman_controller_t
{
    uint numSendStreams;
    uint numReceiveStreams;
    recv_stream_t* recv_streams;
    send_stream_t* send_streams;
    bool* recvStreamActivated;
    uint queuedBytes;
    bool unreliable;
    //fixme is delivery_data_t* used?
    std::list<delivery_data_t*> packets;  //!< list for all packets
};

/**
 * This struct contains all data of an channel. As far as other modules must know
 * elements of this struct, read functions are provided. No other module has write
 * access to this structure
 * ASSCIATION
 * 偶联（AssociATION） 偶联就是两个 SCTP 端点通过SCTP 协议规定的4 步握手机制建立起来
 * 的进行数据 传递的逻辑联系或者通道。 SCTP 协议规定在任何时刻两个端点之间能且仅能建立
 * 一个偶联。由于偶联由两个 端点的传送地址来定义，所以通过数据配置本地IP 地址、
 * 本地SCTP 端口号、对端 IP 地址、对端SCTP 端口号等四个参数，可以唯一标识一个SCTP 偶联
 */
struct geco_channel_t
{
    /*The current ID of this channel,
     it is used as a key to find a channel in the list,
     and never changes in the  live of the channel */
    uint channel_id;

    uint local_tag; /*The local tag of this channel*/
    uint remote_tag; /*The tag of remote side of this channel*/

    /*Pointer to the geco-instance this association belongs to.
     It is equal to the assignated port number of the ULP that uses this instance*/
    geco_instance_t* geco_inst;

    /* a single same port  plus multi different ip addresses consist of a uniqe channel*/
    ushort local_port;
    sockaddrunion *local_addres;
    uint local_addres_size;

    ushort remote_port;

    // it uses geco_malloc_ext() to alloc remeber to use geco_free_ext() to free mempey
    sockaddrunion *remote_addres;
    uint remote_addres_size;

    uchar ipTos;
    uint locally_supported_addr_types;
    uint maxSendQueue;
    uint maxRecvQueue;
    bool is_INADDR_ANY;
    bool is_IN6ADDR_ANY;

    flow_controller_t *flow_control;
    reltransfer_controller_t *reliable_transfer_control;
    recv_controller_t *receive_control;
    deliverman_controller_t *deliverman_control;
    path_controller_t *path_control;
    bundle_controller_t *bundle_control;
    smctrl_t *state_machine_control;

    /* do I support the DCTP extensions ? */
    bool locally_supported_PRDCTP;
    bool locally_supported_ADDIP;
    /* and these values for our peer */
    bool remotely_supported_PRSCTP;
    bool remotely_supported_ADDIP;

    bool deleted; /** marks an association for deletion */
    void * ulp_dataptr; /* transparent pointer to some upper layer data */
};

/**
 *  recv_geco_packet
 *  recv_geco_packet is the callback function of the DCTP-message dispatch_layer.
 *  It is called by the transport layer module when a new ip packet is received.
 *  This function amainly performs verfying tag, checksum, src and dest
 *  addres and filtering and pre-processing
 *  src and dest  address and port number, non-oob and oob chunks
 *  illegal chunks will be discarded and/or send ABORT to peer
 *  legal chunks will be sent to the bundling module of
 *  the right association for further processing eg, disassemble
 *  @param socket_fd          the socket file discriptor
 *  @param buffer             pointer to arrived datagram
 *  @param bufferlength       length of datagramm
 *  @param fromAddress        source address of DG
 *  @param portnum            bogus port number
 */
extern int mdi_recv_geco_packet(int socket_fd, char *dctp_packet, uint dctp_packet_len, sockaddrunion * source_addr,
    sockaddrunion * dest_addr);

#endif
