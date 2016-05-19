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
#include "geco-ds-malloc.h"
#include "gecotimer.h"
#include <unordered_map>
#include <vector>
#include <list>
#include <array>

/*------------------- Functions called by the ULP -----------------------*/
/* This functions are defined in a seperate header file dctp.h
 * in order to seperate the interface to the ULP and the interface
 * to other modules within DCTP.*/
/*------------------------------------------------------------------*/

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
    /** */
    uint requested_destination;
};

/**
 * this struct contains all necessary data for
 * creating SACKs from received data chunks
 * both are closely connected
 * as sack is created based on form recv data chunks
 */
struct recv_controller_t //recv_ctrl
{
    void* sack_chunk;
    uint cumulative_tsn;
    /*stores highest tsn received so far, taking care of wraps
     * i.e. highest < lowest indicates a wrap */
    uint lowest_duplicated_tsn;
    uint highest_duplicated_tsn;
    bool contains_valid_sack;
    bool is_timer_running;
    bool is_newly_recv_chunk; /*indicates whether a received chunk is truly new */
    timer_id_t sack_timer_id; /* timer for delayed sacks */
    int recv_packet_size;
    uint sack_flag; /* 1 (sack each data chunk) or 2 (sack every second chunk)*/
    uint last_address;
    uint channel_id;
    uint rwnd;
    uint delay; /* delay for delayed ACK in msecs */
    uint num_of_addresses; /* number of dest addresses */
    std::list<data_chunk_t*> fragmented_data_chunks_list;
    std::list<data_chunk_t*> duplicated_data_chunks_list;
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
    // id of hb timer
    timer_id_t hb_timer_id;
    //time of last RTO update
    struct timeval last_rto_update_time;
};

/**
* this struct contains all necessary data for one instance of the path management
* module. There is one such module per existing channel.
*/
struct path_controller_t
{
    //channel id
    uint channel_id;
    // store the current primary path
    uint primary_path;
    //the number of paths used by this channel
    uint path_num;
    //counter for all retransmittions over all paths
    uint retrans_count;
    //pointer to path-secific prams maybe more than one
    path_params_t* path_params;
    //max retrans per path 
    uint max_retrans_count;
    // initial RTO, a configurable parameter 
    uint rto_initial;
    /** minimum RTO, a configurable parameter */
    uint rto_min;
    /** maximum RTO, a configurable parameter */
    uint rto_max;
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
struct channel_t
{
    /*The current ID of this channel,
     it is used as a key to find a channel in the list,
     and never changes in the  live of the channel */
    uint channel_id;

    uint local_tag; /*The local tag of this channel*/
    uint remote_tag; /*The tag of remote side of this channel*/

    /*Pointer to the geco-instance this association belongs to.
     It is equal to the assignated port number of the ULP that uses this instance*/
    geco_instance_t* dispatcher;

    /* a single same port  plus multi different ip addresses consist of a uniqe channel*/
    ushort local_port;
    sockaddrunion *local_addres;
    uint local_addres_size;

    ushort remote_port;
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
    recv_controller_t *receive_control;
    void *stream_control;
    path_controller_t *path_control;
    bundle_controller_t *bundle_control;
    void *dctp_control;

    /* do I support the DCTP extensions ? */
    bool locally_supported_PRDCTP;
    bool locally_supported_ADDIP;
    /* and these values for our peer */
    bool remotely_supported_PRSCTP;
    bool remotely_supported_ADDIP;

    bool deleted; /** marks an association for deletion */
    void * application_layer_dataptr; /* transparent pointer to some upper layer data */
};


/**
 * this struct contains all necessary data for retransmissions
 * and processing of received SACKs,
 * both are closely connected as retrans is determined based on recv sacks
 */
struct retransmit_controller_t
{
    uint lowest_tsn; /*storing the lowest tsn that is in the list */
    uint highest_tsn;/*storing the highest tsn that is in the list */
    uint num_of_chunks;
    uint highest_acked;
    /** a list that is ordered by ascending tsn values */
    std::list<sack_chunk_t*> ordered_list; //fixme what is the type used ?

    struct timeval sack_arrival_time;
    struct timeval saved_send_time;
    /*this val stores 0 if retransmitted chunks have been acked, else 1 */
    uint save_num_of_txm;
    uint newly_acked_bytes;
    uint num_of_addresses;
    uint my_channel;
    uint peer_arwnd;
    bool all_chunks_are_unacked;
    bool shutdown_received;
    bool fast_recovery_active;
    /** the exit point is only valid, if we are in fast recovery */
    uint fr_exit_point;
    uint advancedPeerAckPoint;
    uint lastSentForwardTSN;
    uint lastReceivedCTSNA;
    std::vector<data_chunk_t*> prChunks;  //fixme what is the type used ?
};

struct transport_layer_t;
class dispatch_layer_t
{
    public:
    bool sctpLibraryInitialized;

    /*Keyed list of end_points_ with ep_id as key*/
    //typedef uint endpoint_id;
    //typedef ushort endpoint_local_port;
    //std::unordered_map<endpoint_id, channel_t*> end_points_;
    //std::unordered_map<endpoint_local_port, channel_t*> end_points_;
    std::vector<channel_t*> endpoints_list_;

    /*Keyed list of dispatchers with dispatcher name as key*/
    std::vector<geco_instance_t*> dispathers_list_;

    /**
     * Whenever an external event (ULP-call, socket-event or timer-event) this variable must
     * contain the addressed sctp instance.
     * This pointer must be reset to null after the event  has been handled.
     */
    geco_instance_t *curr_geco_instance_;

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
    uint last_veri_tag_;

    /**
     * Whenever an external event (ULP-call, socket-event or timer-event) this variable must
     * contain the addressed association.
     * Read functions for 'global data' read data from the association pointed to by this pointer.
     * This pointer must be reset to null after the event  has been handled.
     */
    channel_t *curr_channel_;
    channel_t tmp_endpoint_;
    sockaddrunion tmp_addr_;
    geco_instance_t tmp_dispather_;
    sockaddrunion found_addres_[MAX_NUM_ADDRESSES];

    /* related to chunk handler and builder */
    uchar write_cursors_[MAX_CHUNKS_SIZE];
    simple_chunk_t* simple_chunks_[MAX_CHUNKS_SIZE];
    bool completed_chunks_[MAX_CHUNKS_SIZE];
    uchar free_chunk_id_;
    simple_chunk_t* curr_simple_chunk_ptr_;

    /* a buffer that is used if no channel bundling controller
     * has been allocated and initialized yet */
    bundle_controller_t default_bundle_ctrl_;
    bool send_abort_for_oob_packet_;

    timer_mgr timer_mgr_;
    transport_layer_t* transport_layer_;

    char hoststr_[MAX_IPADDR_STR_LEN];
    dispatch_layer_t();

    /*------------------- Functions called by the Unix-Interface --------------*/
    /**
     * \fn recv_geco_packet
     *  recv_geco_packet is the callback function of the DCTP-message dispatch_layer.
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
    void recv_geco_packet(int socket_fd, char *buffer, uint bufferLength,
        sockaddrunion * source_addr, sockaddrunion * dest_addr);

    /*------------------- Functions called by the SCTP bundling --------------------------------------*/

    /**
    * Used by bundling to send a geco packet.
    *
    * Bundling passes a static pointer and leaves space for udp hdr and geco hdr , so
    * we can fill that header in up front !
    * Before calling send_message at the adaption-layer, this function does:
    * \begin{itemize}
    * \item add the SCTP common header to the message
    * \item convert the SCTP message to a byte string
    * \item retrieve the socket-file descriptor of the SCTP-instance
    * \item retrieve the destination address
    * \item retrieve destination port ???
    * \end{itemize}
    *
    *  @param geco_packet     geco_packet (i.e.geco_packet_fixed_t and chunks)
    *  @param length          
        length of complete geco_packet (including legth of udp hdr(if has), geco hdr,and chunks)
    *  @param destAddresIndex  Index of address in the destination address list.
    *  @return                 Errorcode (0 for good case: length bytes sent; 1 or -1 for error)
    */
    int send_geco_packet(char* geco_packet, uint length, short destAddressIndex);

    private:
    int get_primary_path()
    {
        path_controller_t* path_ctrl = get_path_controller();
        if (path_ctrl == NULL)
        {
            error_log(loglvl_major_error_abort,
                "set_path_chunk_sent_on: GOT path_ctrl NULL");
            return -1;
        }
        return path_ctrl->primary_path;
    }
    /**
    * function to return a pointer to the path management module of this association
    * @return  pointer to the pathmanagement data structure, null in case of error.
    */
    path_controller_t* get_path_controller(void)
    {
        if (curr_channel_ == NULL)
        {
            error_log(loglvl_minor_error, "get_path_controller: curr_channel_ is NULL");
            return NULL;
        }
        else
        {
            return curr_channel_->path_control;
        }
    }
    /**
    * helper function, that simply sets the chunksSent flag of this path management instance to true
    * @param path_param_id  index of the address, where flag is set
    */
    inline void set_data_chunk_sent_flag(short path_param_id)
    {
        path_controller_t* path_ctrl = get_path_controller();
        if (path_ctrl == NULL)
        {
            error_log(loglvl_major_error_abort,
                "set_path_chunk_sent_on: GOT path_ctrl NULL");
            return;
        }
        if (path_ctrl->path_params == NULL)
        {
            error_logi(loglvl_major_error_abort,
                "set_path_chunk_sent_on(%d): path_params NULL !", path_param_id);
            return;
        }
        if (!(path_param_id >= 0 && path_param_id < path_ctrl->path_num))
        {
            error_logi(loglvl_major_error_abort, 
                "set_path_chunk_sent_on: invalid path ID: %d", path_param_id);
            return;
        }
        event_logi(verbose, "Calling set_path_chunk_sent_on(%d)", path_param_id);
        path_ctrl->path_params[path_param_id].data_chunks_sent_in_last_rto = true;
    }

    void free_internal_data_chunk(internal_data_chunk_t* item)
    {
        /* this is common item we allocated by allocator*/
        if (item == NULL)
            return;

        if (item->ct == ctrl_type::flow_ctrl)
        {
            if (item->num_of_transmissions == 0)
            {
                //TODO delete from list
            }
            return;
        }

        if (item->ct == ctrl_type::reliable_transfer_ctrl)
        {
            if (item->num_of_transmissions != 0)
            {
                //TODO delete from list
            }
            return;
        }

    }
    /**
     * function called by bundling when a SACK is actually sent, to stop
     * a possibly running  timer
     */
    inline void stop_sack_timer(void)
    {
        recv_controller_t* rctrl = get_recv_controller(curr_channel_);
        if (rctrl == NULL)
        {
            error_log(loglvl_minor_error,
                "stop_sack_timer()::recv_controller_t instance not set !");
            return;
        }
        /*also make sure free all received duplicated data chunks */
        rctrl->duplicated_data_chunks_list.clear();
        /* stop running sack timer*/
        if (rctrl->is_timer_running)
        {
            timer_mgr_.delete_timer(rctrl->sack_timer_id);
            rctrl->is_timer_running = false;
            event_log(loglvl_intevent, "stop_sack_timer()::Stopped Timer");
        }
    }

    /**
     * Disassembles chunks from a received datagram
     *
     * FIXME : data chunks may only be parsed after control chunks.....
     *
     * All chunks within the datagram are dispatched and sent to the appropriate
     * module, i.e.: control chunks are sent to sctp_control/pathmanagement,
     * SACK chunks to reliable_transfer, and data_chunks to RX_control.
     * Those modules must get a pointer to the start of a chunk and
     * information about its size (without padding).
     * @param  address_index  index of address on which this data arrived
     * @param  datagram     pointer to first chunk of the newly received data
     * @param  len          length of payload (i.e. len of the concatenation of chunks)
     */
    int handle_chunks_from_geco_packet(uint address_index, uchar * datagram,
        int len);

    void clear()
    {
        last_source_addr_ = NULL;
        last_dest_addr_ = NULL;
        last_src_port_ = 0;
        last_dest_port_ = 0;
        curr_channel_ = NULL;
        curr_geco_instance_ = NULL;
    }

    /**
     * looks for Error chunk_type in a newly received datagram
     * that contains a special error cause code
     *
     * All chunks within the datagram are lookes at, until one is found
     * that equals the parameter chunk_type.
     * @param  packet_value     pointer to the newly received data
     * @param  len          stop after this many bytes
     * @param  error_cause  error cause code to look for
     * @return true is chunk_type exists in SCTP datagram, false if it is not in there
     */
    bool contains_error_chunk(uchar * packet_value, uint packet_val_len,
        ushort error_cause);

    uint get_bundle_total_size(bundle_controller_t* buf)
    {
        assert(GECO_PACKET_FIXED_SIZE == sizeof(geco_packet_fixed_t));
        return ((buf)->ctrl_position + (buf)->sack_position
            + (buf)->data_position - 2 * UDP_GECO_PACKET_FIXED_SIZES);
    }

    // fixme 
    // should return (buf)->sack_position - GECO_PACKET_FIXED_SIZE?
    // this needsbe fixedup soon
    uint get_bundle_sack_size(bundle_controller_t* buf)
    {
        assert(GECO_PACKET_FIXED_SIZE == sizeof(geco_packet_fixed_t));
        return ((buf)->ctrl_position + (buf)->data_position
            - UDP_GECO_PACKET_FIXED_SIZES);
    }

    /**
     * Trigger sending of all chunks previously entered with put_Chunk functions
     *  Chunks sent are deleted afterwards.
     *
     * FIXME : special treatment for GLOBAL BUFFER, as this is not associated with
     *         any association.
     *
     *
     *  @return                 Errorcode (0 for good case: length bytes sent; 1 or -1 for error)
     *  @param   ad_idx     pointer to address index or NULL if data is to be sent to default address
     */
    int send_bundled_chunks(uint * ad_idx = NULL);

    /**
     * creates a simple chunk except of DATA chunk. It can be used for parameterless
     * chunks like abort, cookieAck and shutdownAck. It can also be used for chunks
     * that have only variable length parameters like the error chunks
     */
    uchar alloc_simple_chunk(uchar chunk_type, uchar flag)
    {
        assert(sizeof(simple_chunk_t) == MAX_SIMPLE_CHUNK_VALUE_SIZE);
        //create smple chunk used for ABORT, SHUTDOWN-ACK, COOKIE-ACK
        simple_chunk_t* simple_chunk_ptr =
            (simple_chunk_t*)geco::ds::single_client_alloc::allocate(
            SIMPLE_CHUNK_SIZE);
        simple_chunk_ptr->chunk_header.chunk_id = chunk_type;
        simple_chunk_ptr->chunk_header.chunk_flags = flag;
        simple_chunk_ptr->chunk_header.chunk_length = 0x0004;
        debug_simple_chunk(simple_chunk_ptr, "create simple chunk %u");
        return free_chunk_id_;
    }

    /**
     * free_simple_chunk removes the chunk from the array of simple_chunks_ and frees the
     * memory allocated for that chunk
     */
    void free_simple_chunk(uchar chunkID)
    {
        uint cid = chunkID;
        if (simple_chunks_[chunkID] != NULL)
        {
            event_logi(loglvl_intevent, "freed simple chunk %u", cid);
            geco::ds::single_client_alloc::deallocate(simple_chunks_[chunkID],
                SIMPLE_CHUNK_SIZE);
            simple_chunks_[chunkID] = NULL;
        }
        else
        {
            error_log(loglvl_major_error_abort, "chunk already freed\n");
        }
    }

    void debug_simple_chunk(simple_chunk_t * chunk, const char *log_text = NULL)
    {
        uint cid;
        free_chunk_id_ = (free_chunk_id_ + 1) % MAX_CHUNKS_SIZE;
        cid = free_chunk_id_;
        event_logi(loglvl_intevent, log_text, cid);
        simple_chunks_[free_chunk_id_] = chunk;
        write_cursors_[free_chunk_id_] = 0;
        completed_chunks_[free_chunk_id_] = false;
    }

    /** returns a pointer to the beginning of a simple chunk.*/
    simple_chunk_t *get_simple_chunk(uchar chunkID);

    /**
     * this function used for bundling of control chunks
     * Used by geco-control and path management
     * @param chunk pointer to chunk, that is to be put in the bundling buffer
     * @return TODO : error value, 0 on success
     */
    int bundle_simple_chunk(simple_chunk_t * chunk, uint * dest_index = NULL);

    /**
     * function to return a pointer to the bundling module of this association
     * @return   pointer to the bundling data structure, null in case of error.
     */
    inline bundle_controller_t* get_bundle_controller(channel_t* channel = NULL)
    {
        if (channel == NULL)
        {
            error_log(verbose, "get_bundle_control: association not set");
            return NULL;
        }
        else
        {
            return channel->bundle_control;
        }
    }

    /**
     * function to return a pointer to the receiver module of this association
     * @return pointer to the RX-control data structure, null in case of error.
     */
    inline recv_controller_t* get_recv_controller(channel_t* channel = NULL)
    {
        if (channel == NULL)
        {
            error_log(verbose, "get_recv_controller: association not set");
            return NULL;
        }
        else
        {
            return channel->receive_control;
        }
    }

    /**
     * Enable sending again - wait after received chunks have been diassembled completely.
     */
    inline void unlock_bundle_ctrl(uint* ad_idx = NULL)
    {
        bundle_controller_t* bundle_ctrl =
            (bundle_controller_t*)get_bundle_controller(curr_channel_);

        /*1) no channel exists, it is NULL, so we take the global bundling buffer */
        if (bundle_ctrl == NULL)
        {
            event_log(verbose,
                "unlock_bundle_ctrl()::Setting global bundling buffer ");
            bundle_ctrl = &default_bundle_ctrl_;
        }

        bundle_ctrl->locked = false;
        if (bundle_ctrl->got_send_request)
            send_bundled_chunks(ad_idx);

        event_logi(verbose,
            "unlock_bundle_ctrl() was called..and got %s send request -> processing",
            (bundle_ctrl->got_send_request == true) ? "A" : "NO");
    }

    /**
     * Keep sender from sending data right away - wait after received chunks have
     * been diassembled completely.
     */
    inline void lock_bundle_ctrl()
    {
        bundle_controller_t* bundle_ctrl =
            (bundle_controller_t*)get_bundle_controller(curr_channel_);

        /*1) no channel exists, it is NULL, so we take the global bundling buffer */
        if (bundle_ctrl == NULL)
        {
            event_log(verbose,
                "lock_bundle_ctrl()::Setting global bundling buffer ");
            bundle_ctrl = &default_bundle_ctrl_;
        }

        bundle_ctrl->locked = true;
        bundle_ctrl->got_send_request = false;
    }

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
     *   TODO hash(src_addr, src_port, dest_port) as key for channel to improve the performaces
     */
    channel_t *find_channel_by_transport_addr(sockaddrunion * src_addr,
        ushort src_port, ushort dest_port);
    bool cmp_channel(const channel_t& a, const channel_t& b);

    /**
     *   @return pointer to the retrieved association, or NULL
     */
    geco_instance_t* find_geco_instance_by_transport_addr(
        sockaddrunion* dest_addr, uint address_type);
    bool cmp_geco_instance(const geco_instance_t& a, const geco_instance_t& b);

    /**
     * after dispatcher and  channel have been found for an
     * incoming packet, this function will return, if a packet may be processed
     * or if it is not destined for this instance
     */
    bool validate_dest_addr(sockaddrunion * dest_addr);

    /**returns a value indicating which chunks are in the packet.*/
    uint find_chunk_types(uchar* packet_value, uint len);

    /**
     * contains_chunk: looks for chunk_type in a newly received geco packet
     * Should be called after find_chunk_types().
     * The chunkArray parameter is inspected. This only really checks for chunks
     * with an ID <= 30. For all other chunks, it just guesses...
     * @return 0 NOT contains, 1 contains and only one, 2 contains and NOT only one
     * @pre: need call find_chunk_types() first
     */
    inline int contains_chunk(uchar chunk_type, uint chunk_types)
    {
        // 0000 0000 ret = 0 at beginning
        // 0000 0001 1
        // 1                chunktype init
        // 0000 0010 ret
        // 2                chunktype init ack
        // 0000 0110 ret
        // 7                chunktype shutdown
        // 1000 0110 ret
        // 192            chunktype shutdown
        // 1000 0000-byte0-byte0-1000 0110 ret

        uint val = 0;
        chunk_type > 30 ? val = (1 << 31) : val = (1 << chunk_type);

        if ((val & chunk_types) == 0)
        {
            // not contains
            return 0;
        }
        else
        {
            // 1 only have this chunk type,  2 Not only this chunk type
            return val == chunk_types ? 1 : 2;
        }
        return 0;
    }

    /**
     * find_first_chunk: looks for chunk_type in a newly received datagram
     * All chunks within the datagram are looked at, until one is found
     * that equals the parameter chunk_type.
     * @param  datagram     pointer to the newly received data
     * @param  len          stop after this many bytes
     * @param  chunk_type   chunk type to look for
     * @return pointer to first chunk of chunk_type in SCTP datagram, else NULL
     */
    uchar* find_first_chunk(uchar * packet_value, uint packet_val_len,
        uchar chunk_type);

    /**
     * find_sockaddr: looks for address type parameters in INIT or INIT-ACKs
     * All parameters within the chunk are looked at, and the n-th supported address is
     * copied into the provided buffer pointed to by the foundAddress parameter.
     * If there are less than n addresses, an appropriate error is
     * returned. n should be at least 1, of course.
     * @param  chunk            pointer to an INIT or INIT ACK chunk
     * @param  n                get the n-th address
     * @param  foundAddress
     * pointer to a buffer where an address, if found, will be copied
     * @return -1  for parameter problem, 0 for success (i.e. address found), 1 if there are not
     *             that many addresses in the chunk.
     */
    int find_sockaddres(uchar * init_chunk, uint chunk_len, uint n,
        sockaddrunion* foundAddress, int supportedAddressTypes);
    /**
     * @return -1 prama error, >=0 number of the found addresses
     * */
    int find_sockaddres(uchar * init_chunk, uint chunk_len,
        int supportedAddressTypes);

    /** NULL no params, otherwise have params*/
    uchar* find_vlparam_fixed_from_setup_chunk(uchar * setup_chunk,
        uint chunk_len, ushort param_type);
};
#endif
