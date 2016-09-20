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

#include "globals.h"
#include "geco-malloc.h"
#include "gecotimer.h"
#include "protoco-stack.h"
#include "auth.h"
#include "chunk_factory.h"

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
	bool is_ip4;
	bool is_ip6;

	applicaton_layer_cbs_t applicaton_layer_cbs; /*setup by app layer*/

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
	/** */
	uint requested_destination;

	bundle_controller_t()
	{
		reset();
	}
	void reset()
	{
		requested_destination = 0;
		ctrl_position = data_position = sack_position =
			UDP_GECO_PACKET_FIXED_SIZES;
		got_shutdown = locked = got_send_address = got_send_request = data_in_buffer =
			ctrl_chunk_in_buffer = sack_in_buffer = false;
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
	timer_id_t sack_timer; /* timer for delayed sacks */
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
	int primary_path;
	//the number of paths used by this channel
	int path_num;
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

/**state controller structure. Stores the current state of the channel.*/
struct state_machine_controller_t
{
	void reset()
	{
		channel_state = Closed;
		instance = 0;
	}

	state_machine_controller_t()
	{
		reset();
	}

	/*@{ */
	/** the state of this state machine */
	ChannelState channel_state;
	/** stores timer-ID of init/cookie-timer, used to stop this timer */
	timer_id_t init_timer_id;
	/** */
	uint init_timer_interval;
	/**  stores the channel id (==tag) of this association */
	uint channel_id;
	/** Counter for init and cookie retransmissions */
	uint init_retrans_count;
	/** pointer to the init chunk data structure (for retransmissions) */
	init_chunk_t *my_init_chunk;  //!< init chunk sent by me
	int addr_my_init_chunk_sent_to;

	/** pointer to the cookie chunk data structure (for retransmissions) */
	cookie_echo_chunk_t *cookieChunk;
	/** my tie tag for cross initialization and other sick cases */
	uint local_tie_tag;
	/** peer's tie tag for cross initialization and other sick cases */
	uint peer_tie_tag;
	/** todo we store these here, too. Maybe better be stored with StreamEngine ? */
	ushort out_stream_count;
	/** todo we store these here, too. Maybe better be stored with StreamEngine ? */
	ushort in_stream_count;
	/** value for maximum retransmissions per association */
	uint max_retrans_count;
	/** value for maximum initial retransmissions per association */
	uint max_init_retrans_count;
	/** value for the current cookie lifetime */
	uint cookie_lifetime;
	/** the geco instance */
	geco_instance_t* instance;
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
	struct timeval time_of_cwnd_adjustment;
	struct timeval last_send_time;
};

struct flow_controller_t
{
	uint outstanding_bytes;
	uint peerarwnd;
	uint numofdestaddrlist;
	congestion_parameters_t* cparams;
	uint current_tsn;
	std::list<internal_data_chunk_t*> chunk_list; //todo not really sure GList *chunk_list;
	uint list_length;
	/** one timer may be running per destination address */
	timer_id_t* T3_timer;
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
	geco_instance_t* geco_inst;

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

	flow_controller_t *flow_control;
	reltransfer_controller_t *reliable_transfer_control;
	recv_controller_t *receive_control;
	deliverman_controller_t *deliverman_control;
	path_controller_t *path_control;
	bundle_controller_t *bundle_control;
	state_machine_controller_t *state_machine_control;

	/* do I support the DCTP extensions ? */
	bool locally_supported_PRDCTP;
	bool locally_supported_ADDIP;
	/* and these values for our peer */
	bool remotely_supported_PRSCTP;
	bool remotely_supported_ADDIP;

	bool deleted; /** marks an association for deletion */
	void * application_layer_dataptr; /* transparent pointer to some upper layer data */
};

struct transportaddr_hash_functor  //hash 函数
{
	size_t operator()(transport_addr_t &addr) const
	{
		return transportaddr2hashcode(&(addr.local_saddr), &(addr.peer_saddr));
	}
};

struct transportaddr_cmp_functor  //比较函数 ==
{
	bool operator()(transport_addr_t &addr1, transport_addr_t &addr2) const
	{
		return saddr_equals(&(addr1.local_saddr), &(addr2.local_saddr))
			&& saddr_equals(&(addr1.peer_saddr), &(addr2.peer_saddr));
	}
};
struct sockaddr_hash_functor  //hash 函数
{
	size_t operator()(sockaddrunion &addr) const
	{
		return sockaddr2hashcode(&addr);
	}
};

struct sockaddr_cmp_functor  //比较函数 ==
{
	bool operator()(sockaddrunion &a, sockaddrunion &b) const
	{
		return saddr_equals(&a, &b);
	}
};
struct network_interface_t;
class dispatch_layer_t
{
public:
	bool enable_test_;
	bool dispatch_layer_initialized;
	bool ignore_cookie_life_spn_from_init_chunk_;
	bool send_abort_for_oob_packet_;

#ifdef _WIN32
	std::unordered_map<transport_addr_t, channel_t*,
		transportaddr_hash_functor, transportaddr_cmp_functor>
		channel_map_;
	std::unordered_map<sockaddrunion, geco_instance_t*,
		sockaddr_hash_functor, sockaddr_cmp_functor>
		instance_map_;
#else
	std::tr1::unordered_map<transport_addr_t, channel_t*, transportaddr_hash_functor,
		transportaddr_cmp_functor> channel_map_;
	std::tr1::unordered_map<sockaddrunion, geco_instance_t*, sockaddr_hash_functor,
		sockaddr_cmp_functor> instance_map_;
#endif

	/* many diferent channels belongs to a same geco instance*/
	std::vector<channel_t*> channels_; /*store all channels, channel id as key*/
	std::vector<geco_instance_t*> geco_instances_; /* store all instances, instance name as key*/

	/* whenever an external event (ULP-call, socket-event or timer-event) this variable must
	 * contain the addressed geco instance. This pointer must be reset to null after the event
	 * has been handled.*/
	geco_instance_t *curr_geco_instance_;

	/* whenever an external event (ULP-call, socket-event or timer-event) this variable must
	 * contain the addressed channel. This pointer must be reset to null after the event
	 * has been handled.*/
	channel_t *curr_channel_;

	/* inits along with library inits*/
	uint defaultlocaladdrlistsize_;
	sockaddrunion* defaultlocaladdrlist_;

	/* these one-shot state variables are so frequently used in recv_gco_packet()
	 * to improve performances */
	geco_packet_fixed_t* curr_geco_packet_fixed_;
	geco_packet_t* curr_geco_packet_;
	uint curr_geco_packet_value_len_;
	uchar* curr_uchar_init_chunk_;
	sockaddrunion *last_source_addr_;
	sockaddrunion *last_dest_addr_;
	sockaddrunion addr_from_init_or_ack_chunk_;
	// cmp_channel() will set last_src_path_ to the one found src's
	// index in channel's remote addr list
	int last_src_path_;
	ushort last_src_port_;
	ushort last_dest_port_;
	uint last_init_tag_;
	uint last_veri_tag_;
	bool do_dns_query_for_host_name_;
	char src_addr_str_[MAX_IPADDR_STR_LEN];
	char dest_addr_str_[MAX_IPADDR_STR_LEN];
	bool is_found_init_chunk_;
	bool is_found_cookie_echo_;
	bool is_found_abort_chunk_;
	bool should_discard_curr_geco_packet_;
	int dest_addr_type_;
	uint ip4_saddr_;
	in6_addr* ip6_saddr_;
	uint total_chunks_count_;
	uint chunk_types_arr_;
	int init_chunk_num_;
	bool send_abort_;
	bool found_init_chunk_;
	bool is_there_at_least_one_equal_dest_port_;
	init_chunk_fixed_t* init_chunk_fixed_;
	vlparam_fixed_t* vlparam_fixed_;

	/* tmp variables used for looking up channel and geco instance*/
	channel_t tmp_channel_;
	sockaddrunion tmp_addr_;
	geco_instance_t tmp_geco_instance_;
	sockaddrunion tmp_local_addreslist_[MAX_NUM_ADDRESSES];
	int tmp_local_addreslist_size_;
	uint my_supported_addr_types_;
	sockaddrunion tmp_peer_addreslist_[MAX_NUM_ADDRESSES];
	int tmp_peer_addreslist_size_;
	uint tmp_peer_supported_types_;

	/*related to simple chunk send */
	uint curr_write_pos_[MAX_CHUNKS_SIZE]; /* where is the next write starts */
	simple_chunk_t* simple_chunks_[MAX_CHUNKS_SIZE]; /* simple ctrl chunks to send*/
	//simple_chunk_t simple_chunks_pods_[MAX_CHUNKS_SIZE]; /* simple ctrl chunks to send*/
	bool completed_chunks_[MAX_CHUNKS_SIZE];/*if a chunk is completely constructed*/
	uint simple_chunk_index_; /* current simple chunk index */
	simple_chunk_t* simple_chunk_t_ptr_; /* current simple chunk ptr */

	/* used if no bundlecontroller has been allocated and initialized yet */
	bundle_controller_t default_bundle_ctrl_;
	//bool send_abort_for_oob_packet_;
	// uncomment as we never send abort to a unconnected peer

	/* related to error cause */
	ushort curr_ecc_code_;
	ushort curr_ecc_len_;
	uchar* curr_ecc_reason_;

	timer_mgr timer_mgr_;
	network_interface_t* transport_layer_;
	char hoststr_[MAX_IPADDR_STR_LEN];
	bool library_support_unreliability_;
	char chunkflag2use_;

#if ENABLE_UNIT_TEST
	/* unit test extra variables*/
	bool enable_mock_dispatcher_disassemle_curr_geco_packet_;
	bool enable_mock_dispatch_send_geco_packet_;
	bool enable_mock_dispatcher_process_init_chunk_;
#endif

	dispatch_layer_t();

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
	int recv_geco_packet(int socket_fd, char *buffer, uint bufferLength,
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

public:
	/**
	 * @todo use safe random generator
	 * generates a random tag value for a new association, but not 0
	 * @return   generates a random tag value for a new association, but not 0
	 */
	uint generate_init_tag(void)
	{
		unsigned int tag;
		while ((tag = generate_random_uint32()) == 0)
			;
		return tag;
	}

	geco_instance_t* find_geco_instance_by_id(uint geco_inst_id)
	{
		for (auto& inst : geco_instances_)
		{
			if (inst->dispatcher_name == geco_inst_id)
			{
				return inst;
			}
		}
		return NULL;
	}

	/**
	 * @brief
	 * returns the number of incoming streams that this instance is willing to handle !
	 * @return maximum number of in-streams or 0 error
	 * @pre this only works when curr channel presens, curr geco instance presents or
	 * it will search grco instance by instance name
	 */
	ushort get_local_inbound_stream(uint* geco_inst_id = NULL);
	ushort get_local_outbound_stream(uint* geco_inst_id = NULL);

	/* ch_receiverWindow reads the remote receiver window from an init or initAck */
	uint get_rwnd(uint chunkID)
	{
		if (simple_chunks_[chunkID] == NULL)
		{
			ERRLOG(MAJOR_ERROR, "Invalid chunk ID");
			return 0;
		}

		if (simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK
			|| simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT)
		{
			return ntohl(((init_chunk_t*)simple_chunks_[chunkID])->init_fixed.rwnd);
		}
		else
		{
			ERRLOG(MAJOR_ERROR, "get_rwnd: chunk type not init or initAck");
			return 0;
		}
		return 0;
	}
	/* ch_receiverWindow reads the remote receiver window from an init or initAck */
	uint get_init_tsn(uint chunkID)
	{
		if (simple_chunks_[chunkID] == NULL)
		{
			ERRLOG(MAJOR_ERROR, "Invalid chunk ID");
			return 0;
		}

		if (simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK
			|| simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT)
		{
			return ntohl(((init_chunk_t*)simple_chunks_[chunkID])->init_fixed.initial_tsn);
		}
		else
		{
			ERRLOG(MAJOR_ERROR, "get_init_tsn: chunk type not init or initAck");
			return 0;
		}
		return 0;
	}

	/**
	 * This is the second function needed to fully create and initialize an association (after
	 * mdi_newAssociation()) THe association is created in two steps because data become available
	 * at the a-side in two steps
	 * \begin{enumerate}
	 * \item associate
	 * \item init acknowledgement
	 * \end{enumerate}
	 * At the z-side, with the cookie message all data is available at once. So mdi_newAssociation
	 * and mdi_initAssociation must be called when the initAck with valid Cookie is received.
	 *
	 * @param  remoteSideReceiverWindow  rwnd size that the peer allowed in this association
	 * @param  noOfInStreams  number of incoming (receive) streams after negotiation
	 * @param  noOfOutStreams number of outgoing (send) streams after negotiation
	 * @param  remoteInitialTSN     initial  TSN of the peer
	 * @param  tagRemote            tag of the peer
	 * @param  localInitialTSN      my initial TSN, needed for initializing my flow control
	 * @return 0 for success, else 1 for error
	 */
	unsigned short set_channel(unsigned int remoteSideReceiverWindow,
		unsigned short noOfInStreams, unsigned short noOfOutStreams,
		unsigned int remoteInitialTSN, unsigned int tagRemote,
		unsigned int localInitialTSN, bool assocSupportsPRSCTP,
		bool assocSupportsADDIP)
	{
		EVENTLOG(DEBUG, "- - - Enter set_channel()");
		assert(curr_channel_ == NULL);

		if (curr_channel_->remote_tag != 0)
		{
			/* channel init was already completed */
			EVENTLOG(INFO, "set_channel()::reset channel members!");
			free_flow_control(curr_channel_->flow_control);
			free_reliable_transfer(curr_channel_->reliable_transfer_control);
			free_recvctrl(curr_channel_->receive_control);
			free_deliverman(curr_channel_->deliverman_control);
		}
		curr_channel_->remote_tag = tagRemote;
		bool with_pr = assocSupportsPRSCTP && curr_channel_->locally_supported_PRDCTP;
		curr_channel_->locally_supported_PRDCTP = curr_channel_->remotely_supported_PRSCTP =
			with_pr;
		curr_channel_->flow_control = alloc_flowcontrol(remoteSideReceiverWindow,
			localInitialTSN, curr_channel_->remote_addres_size,
			curr_channel_->maxSendQueue);
		curr_channel_->reliable_transfer_control = alloc_reliable_transfer(
			curr_channel_->remote_addres_size, localInitialTSN);
		curr_channel_->receive_control = alloc_recvctrl(remoteInitialTSN,
			curr_channel_->remote_addres_size, curr_channel_->geco_inst);
		curr_channel_->deliverman_control = alloc_deliverman(
			noOfInStreams, noOfOutStreams, with_pr);

		EVENTLOG2(DEBUG, "channel id %d, local tag %d", curr_channel_->channel_id,
			curr_channel_->local_tag);
		return 0;
	}

	/**
	* after submitting results from a SACK to flowcontrol, the counters in
	* reliable transfer must be reset
	* @param rtx   pointer to a retransmit_controller_t, where acked bytes per address will be reset to 0
	*/
	void reset_rtx_bytecounters(reltransfer_controller_t * rtx)
	{
		EVENTLOG(VERBOSE, "- - - Enter reset_rtx_bytecounters()");
		rtx->newly_acked_bytes = 0L;
		EVENTLOG(VERBOSE, "- - - Leave reset_rtx_bytecounters()");
	}

	/**
	 * function creates and allocs new retransmit_controller_t structure.
	 * There is one such structure per established association
	 * @param number_of_destination_addresses
	 * @param number of paths to the peer of the association
	 * @return pointer to the newly created structure
	 */
	reltransfer_controller_t* alloc_reliable_transfer(uint numofdestaddrlist, uint iTSN)
	{
		EVENTLOG(VERBOSE, "- - - Enter alloc_reliable_transfer()");

		reltransfer_controller_t* tmp = (reltransfer_controller_t*)geco_malloc_ext(sizeof(reltransfer_controller_t), __FILE__, __LINE__);
		if (tmp == NULL)
			ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
		tmp->lowest_tsn = iTSN - 1;
		tmp->highest_tsn = iTSN - 1;
		tmp->lastSentForwardTSN = iTSN - 1;
		tmp->highest_acked = iTSN - 1;
		tmp->lastReceivedCTSNA = iTSN - 1;
		tmp->newly_acked_bytes = 0L;
		tmp->num_of_chunks = 0L;
		tmp->save_num_of_txm = 0L;
		tmp->peer_arwnd = 0L;
		tmp->shutdown_received = false;
		tmp->fast_recovery_active = false;
		tmp->all_chunks_are_unacked = true;
		tmp->fr_exit_point = 0L;
		tmp->numofdestaddrlist = numofdestaddrlist;
		tmp->advancedPeerAckPoint = iTSN - 1;   /* a save bet */
		if ((tmp->channel_id = get_curr_channel_id()) == 0)
			ERRLOG(FALTAL_ERROR_EXIT, "channel_id is zero !");
		else
			EVENTLOG2(DEBUG, "channel id %d, local tag %d", curr_channel_->channel_id,
				curr_channel_->local_tag);
		reset_rtx_bytecounters(tmp);

		EVENTLOG(VERBOSE, "- - - Leave alloc_reliable_transfer()");
		return tmp;
	}
	/**
	* function deletes a retransmit_controller_t structure (when it is not needed anymore)
	* @param rtx_instance pointer to a retransmit_controller_t, that was previously created
	with rtx_new_reltransfer()
	*/
	void free_reliable_transfer(reltransfer_controller_t* rtx_inst)
	{
		EVENTLOG(VERBOSE, "- - - Enter free_reliable_transfer()");

		if (rtx_inst->chunk_list_tsn_ascended.size() > 0)
		{
			EVENTLOG(NOTICE, "free_flow_control() : rtx_inst is deleted but chunk_list has size > 0, still queued ...");
			for (auto it = rtx_inst->chunk_list_tsn_ascended.begin(); it != rtx_inst->chunk_list_tsn_ascended.end();)
			{
				free_reltransfer_data_chunk((*it));
				rtx_inst->chunk_list_tsn_ascended.erase(it++);
			}
		}
		//@FIXME  need also free rtx_inst->prChunks     g_array_free(rtx->prChunks, TRUE);
		// see https://developer.gnome.org/glib/stable/glib-Arrays.html#g-array-free
		for (auto& it : rtx_inst->prChunks)
		{
			free_data_chunk(it);
		}
		geco_free_ext(rtx_inst, __FILE__, __LINE__);

		EVENTLOG(VERBOSE, "- - - Leave free_reliable_transfer()");
	}

	/**
	 * Creates new instance of flowcontrol module and returns pointer to it
	 * @TODO : get and update MTU (guessed values ?) per destination address
	 * @param  peer_rwnd receiver window that peer allowed us when setting up the association
	 * @param  my_iTSN my initial TSN value
	 * @param  numofdestaddres the number of paths to the association peer
	 * @return  pointer to the new fc_data instance
	 */
	flow_controller_t* alloc_flowcontrol(uint peer_rwnd,
		uint my_iTSN,
		uint numofdestaddres,
		uint maxQueueLen)
	{
		EVENTLOG4(VERBOSE,
			"- - - Enter alloc_flowcontrol(peer_rwnd=%d,numofdestaddres=%d,my_iTSN=%d,maxQueueLen=%d)",
			peer_rwnd, numofdestaddres, my_iTSN, maxQueueLen);

		flow_controller_t* tmp = (flow_controller_t*)geco_malloc_ext(sizeof(flow_controller_t), __FILE__, __LINE__);
		if (tmp == NULL)
		{
			geco_free_ext(tmp, __FILE__, __LINE__);
			ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
		}

		tmp->current_tsn = my_iTSN;
		if ((tmp->cparams =
			(congestion_parameters_t*)geco_malloc_ext(numofdestaddres * sizeof(congestion_parameters_t), __FILE__, __LINE__)) == NULL)
		{
			geco_free_ext(tmp, __FILE__, __LINE__);
			ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
		}
		if ((tmp->T3_timer =
			(timer_id_t*)geco_malloc_ext(numofdestaddres * sizeof(timer_id_t), __FILE__, __LINE__)) == NULL)
		{
			geco_free_ext(tmp->cparams, __FILE__, __LINE__);
			geco_free_ext(tmp, __FILE__, __LINE__);
			ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
		}
		if ((tmp->addresses =
			(uint*)geco_malloc_ext(numofdestaddres * sizeof(uint), __FILE__, __LINE__)) == NULL)
		{
			geco_free_ext(tmp->T3_timer, __FILE__, __LINE__);
			geco_free_ext(tmp->cparams, __FILE__, __LINE__);
			geco_free_ext(tmp, __FILE__, __LINE__);
			ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
		}

		for (uint count = 0; count < numofdestaddres; count++)
		{
			tmp->T3_timer[count] = timer_mgr_.timers.end(); /* i.e. timer not running */
			tmp->addresses[count] = count;
			(tmp->cparams[count]).cwnd = 2 * MAX_MTU_SIZE;
			(tmp->cparams[count]).cwnd2 = 0L;
			(tmp->cparams[count]).partial_bytes_acked = 0L;
			(tmp->cparams[count]).ssthresh = peer_rwnd;
			(tmp->cparams[count]).mtu = MAX_NETWORK_PACKET_VALUE_SIZE;
			gettimenow(&(tmp->cparams[count].time_of_cwnd_adjustment));
			timerclear(&(tmp->cparams[count].last_send_time));
		}

		tmp->outstanding_bytes = 0;
		tmp->peerarwnd = peer_rwnd;
		tmp->numofdestaddrlist = numofdestaddres;
		tmp->waiting_for_sack = false;
		tmp->shutdown_received = false;
		tmp->t3_retransmission_sent = false;
		tmp->one_packet_inflight = false;
		tmp->doing_retransmission = false;
		tmp->maxQueueLen = maxQueueLen;
		tmp->list_length = 0;
		if ((tmp->channel_id = get_curr_channel_id()) == 0)
		{
			free_flow_control(tmp);
			ERRLOG(FALTAL_ERROR_EXIT, "channel_id is zero !");
		}
		rtx_set_peer_arwnd(peer_rwnd);

		EVENTLOG1(VERBOSE, "- - - Leave alloc_flowcontrol(channel id=%d)", tmp->channel_id);
		return 0;
	}
	/**
	* Deletes data occupied by a flow_control data structure
	* @param fc_instance pointer to the flow_control data structure
	*/
	void free_flow_control(flow_controller_t* fctrl_inst)
	{
		EVENTLOG(VERBOSE, "- - - Enter free_flow_control()");
		fc_stop_timers();
		geco_free_ext(fctrl_inst->cparams, __FILE__, __LINE__);
		geco_free_ext(fctrl_inst->T3_timer, __FILE__, __LINE__);
		geco_free_ext(fctrl_inst->addresses, __FILE__, __LINE__);
		if (fctrl_inst->chunk_list.size() > 0)
		{
			EVENTLOG(NOTICE, "free_flow_control() : fctrl_inst is deleted but chunk_list has size > 0 ...");
			for (auto it = fctrl_inst->chunk_list.begin(); it != fctrl_inst->chunk_list.end();)
			{
				free_flowctrl_data_chunk((*it));
				fctrl_inst->chunk_list.erase(it++);
			}
		}
		geco_free_ext(fctrl_inst, __FILE__, __LINE__);
		EVENTLOG(VERBOSE, "- - - Leave free_flow_control()");
	}
	/**
	* this function stops all currently running timers of the flowcontrol module
	* and may be called when the shutdown is imminent
	*/
	void fc_stop_timers(void)
	{
		EVENTLOG(VERBOSE, "- - - Enter fc_stop_timers()");
		flow_controller_t* fc;
		if ((fc = get_flowctrl()) == NULL)
		{
			ERRLOG(FALTAL_ERROR_EXIT, "flow controller is NULL !");
			return;
		}
		timer_id_t& nulltimer = timer_mgr_.timers.end();
		for (uint count = 0; count < fc->numofdestaddrlist; count++)
		{
			if (fc->T3_timer[count] != nulltimer)
			{
				timer_mgr_.delete_timer(fc->T3_timer[count]);
				fc->T3_timer[count] = nulltimer;
#ifdef _DEBUG
				EVENTLOG1(VERBOSE, "Stopping T3-Timer(id=%d, timer_type=%d) ", fc->T3_timer[count]->timer_id, fc->T3_timer[count]->timer_type);
#endif
			}
		}
		EVENTLOG(VERBOSE, "- - - Leave fc_stop_timers()");
	}

	int get_my_default_rwnd()
	{
		return  (curr_geco_instance_ == NULL) ? -1 : curr_geco_instance_->default_myRwnd;
	}
	int get_default_delay(geco_instance_t* geco_instance)
	{
		return  (geco_instance == NULL) ? -1 : geco_instance->default_delay;
	}
	/**
	 * function creates and allocs new rxc_buffer structure.
	 * There is one such structure per established association
	 * @param  remote_initial_TSN initial tsn of the peer
	 * @return pointer to the newly created structure
	 */
	recv_controller_t* alloc_recvctrl(unsigned int remote_initial_TSN,
		unsigned int number_of_destination_addresses, geco_instance_t* geco_instance)
	{
		EVENTLOG(VERBOSE, "- - - Enter alloc_recvctrl()");
		recv_controller_t* tmp = (recv_controller_t*)geco_malloc_ext(sizeof(recv_controller_t), __FILE__, __LINE__);
		if (tmp == NULL)
			ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");

		tmp->numofdestaddrlist = number_of_destination_addresses;
		tmp->sack_chunk = (sack_chunk_t*)geco_malloc_ext(MAX_NETWORK_PACKET_VALUE_SIZE, __FILE__, __LINE__);
		tmp->cumulative_tsn = remote_initial_TSN - 1; /* as per section 4.1 */
		tmp->lowest_duplicated_tsn = remote_initial_TSN - 1;
		tmp->highest_duplicated_tsn = remote_initial_TSN - 1;
		tmp->contains_valid_sack = false;
		tmp->timer_running = false;
		tmp->datagrams_received = -1;
		tmp->sack_flag = 2;
		tmp->last_address = 0;
		tmp->my_rwnd = get_my_default_rwnd();
		tmp->delay = get_default_delay(geco_instance);
		if ((tmp->channel_id = get_curr_channel_id()) == 0)
		{
			free_recvctrl(tmp);
			ERRLOG(FALTAL_ERROR_EXIT, "channel_id is zero !");
		}
		else
			EVENTLOG2(DEBUG, "channel id %d, local tag %d", curr_channel_->channel_id,
				curr_channel_->local_tag);
		return tmp;
		EVENTLOG(VERBOSE, "- - - Leave alloc_recvctrl()");
	}
	/**
	* function deletes a rxc_buffer structure (when it is not needed anymore)
	* @param rxc_instance pointer to a rxc_buffer, that was previously created
	*/
	void free_recvctrl(recv_controller_t* rxc_inst)
	{
		EVENTLOG(VERBOSE, "- - - Enter free_recvctrl()");
		geco_free_ext(rxc_inst->sack_chunk, __FILE__, __LINE__);
		if (rxc_inst->timer_running)
		{
			timer_mgr_.delete_timer(rxc_inst->sack_timer);
			rxc_inst->timer_running = FALSE;
		}
		for (auto it = rxc_inst->fragmented_data_chunks_list.begin(); it != rxc_inst->fragmented_data_chunks_list.end();)
		{
			free_data_chunk((*it));
			rxc_inst->fragmented_data_chunks_list.erase(it++);
		}
		for (auto it = rxc_inst->duplicated_data_chunks_list.begin(); it != rxc_inst->duplicated_data_chunks_list.end();)
		{
			free_data_chunk((*it));
			rxc_inst->duplicated_data_chunks_list.erase(it++);
		}
		geco_free_ext(rxc_inst, __FILE__, __LINE__);

		EVENTLOG(VERBOSE, "- - - Leave free_recvctrl()");
	}

	/**
	 This function is called to instanciate one deliverman for an association.
	 It creates and initializes the Lists for Sending and Receiving Data.
	 It is called by dispatcher layer. returns: the pointer to the Stream Engine
	 */
	deliverman_controller_t* alloc_deliverman(unsigned int numberReceiveStreams, /* max of streams to receive */
		unsigned int numberSendStreams, /* max of streams to send */
		bool assocSupportsPRSCTP)
	{
		EVENTLOG(VERBOSE,
			"- - - Enter alloc_deliverman(new_stream_engine: #inStreams=%d, #outStreams=%d, unreliable == %s)",
			numberReceiveStreams, numberSendStreams, (assocSupportsPRSCTP == TRUE) ? "TRUE" : "FALSE");

		deliverman_controller_t* tmp = (deliverman_controller_t*)geco_malloc_ext(sizeof(deliverman_controller_t), __FILE__, __LINE__);
		if (tmp == NULL)
			ERRLOG(FALTAL_ERROR_EXIT, "deliverman_controller_t Malloc failed");

		if ((tmp->recv_streams =
			(recv_stream_t*)geco_malloc_ext(numberReceiveStreams * sizeof(recv_stream_t), __FILE__, __LINE__)) == NULL)
		{
			geco_free_ext(tmp, __FILE__, __LINE__);
			ERRLOG(FALTAL_ERROR_EXIT, "recv_streams Malloc failed");
		}
		if ((tmp->recvStreamActivated =
			(bool*)geco_malloc_ext(numberReceiveStreams * sizeof(bool), __FILE__, __LINE__)) == NULL)
		{
			geco_free_ext(tmp->recv_streams, __FILE__, __LINE__);
			geco_free_ext(tmp, __FILE__, __LINE__);
			ERRLOG(FALTAL_ERROR_EXIT, "recvStreamActivated Malloc failed");
		}
		int i;
		for (i = 0; i < numberReceiveStreams; i++) tmp->recvStreamActivated[i] = FALSE;

		if ((tmp->send_streams =
			(send_stream_t*)geco_malloc_ext(numberSendStreams * sizeof(send_stream_t), __FILE__, __LINE__)) == NULL)
		{
			geco_free_ext(tmp->recvStreamActivated, __FILE__, __LINE__);
			geco_free_ext(tmp->recv_streams, __FILE__, __LINE__);
			geco_free_ext(tmp, __FILE__, __LINE__);
			ERRLOG(FALTAL_ERROR_EXIT, "send_streams Malloc failed");
		}

		tmp->numSendStreams = numberSendStreams;
		tmp->numReceiveStreams = numberReceiveStreams;
		tmp->unreliable = assocSupportsPRSCTP;
		tmp->queuedBytes = 0;
		for (i = 0; i < numberReceiveStreams; i++)
		{
			(tmp->recv_streams)[i].nextSSN = 0;
			//(tmp->recv_streams)[i].pduList = NULL;
			//(tmp->recv_streams)[i].prePduList = NULL;
			(tmp->recv_streams)[i].index = 0; /* for ordered chunks, next ssn */
		}
		for (i = 0; i < numberSendStreams; i++)
		{
			(tmp->send_streams[i]).nextSSN = 0;
		}
		return (tmp);

		EVENTLOG(VERBOSE, "- - - Leave alloc_deliverman()");
	}
	/** Deletes the instance pointed to by streamengine.*/
	void free_deliverman(deliverman_controller_t* se)
	{
		EVENTLOG(VERBOSE, "- - - Enter free_deliverman()");
		geco_free_ext(se->send_streams, __FILE__, __LINE__);
		for (int i = 0; i < se->numReceiveStreams; i++)
		{
			EVENTLOG(VERBOSE, "delete free_deliverman(): freeing data for receive stream %d", i);
			/* whatever is still in these lists, delete it before freeing the lists */
			auto& pdulist = se->recv_streams[i].pduList;
			for (auto it = pdulist.begin(); it != pdulist.end();)
			{
				free_delivery_pdu((*it));
				delivery_pdu_t*  d_pdu = (*it);
				pdulist.erase(it++);
			}
			auto& predulist = se->recv_streams[i].prePduList;
			for (auto it = predulist.begin(); it != predulist.end();)
			{
				free_delivery_pdu((*it));
				predulist.erase(it++);
			}
		}
		geco_free_ext(se->recvStreamActivated, __FILE__, __LINE__);
		geco_free_ext(se->recv_streams, __FILE__, __LINE__);
		geco_free_ext(se, __FILE__, __LINE__);
		EVENTLOG(VERBOSE, "- - - Leave free_deliverman()");
	}

	reltransfer_controller_t* get_reltranferctrl(void)
	{
		return curr_channel_ == NULL ? NULL : curr_channel_->reliable_transfer_control;
	}
	flow_controller_t* get_flowctrl(void)
	{
		return curr_channel_ == NULL ? NULL : curr_channel_->flow_control;
	}

	/**
	* function to set the a_rwnd value when we got it from our peer
	* @param  new_arwnd      peers newly advertised receiver window
	* @return  0 for success, -1 for error
	*/
	int rtx_set_peer_arwnd(unsigned int new_arwnd)
	{
		EVENTLOG(VERBOSE, "- - - Enter rtx_set_his_receiver_window(%u)", new_arwnd);

		int ret = 0;
		reltransfer_controller_t *rtx;
		if ((rtx = (reltransfer_controller_t *)get_reltranferctrl()) == NULL)
		{
			ERRLOG(MAJOR_ERROR, "retransmit_controller_t instance not set !");
			ret = -1;
			goto leave;
		}
		else
			rtx->peer_arwnd = new_arwnd;

	leave:
		EVENTLOG(VERBOSE, "Leave rtx_set_peer_rwnd(%u)", new_arwnd);
		return ret;
	}

	/**
	 * @brief Copies local addresses of this instance into the array passed as parameter.
	 * @param [out] local_addrlist
	 * array that will hold the local host's addresses after returning.
	 * @return numlocalAddres
	 * number of addresses that local host/current channel has.
	 * @pre either of current channel and current geco instance MUST present.
	 */
	int get_local_addreslist(sockaddrunion* local_addrlist, sockaddrunion *peerAddress,
		uint numPeerAddresses, uint addressTypes, bool receivedFromPeer);

	/**
	* function to read the association id of the current association
	* @return   association-ID of the current association;
	* 0 means the association is not set (an error).
	*/
	uint get_curr_channel_id(void)
	{
		return  curr_channel_ == NULL ? 0 : curr_channel_->channel_id;
	}

	/**
	 * function to return a pointer to the state machine controller of this association
	 * @return pointer to the SCTP-control data structure, null in case of error.
	 */
	state_machine_controller_t* get_state_machine_controller()
	{
		return  curr_channel_ == NULL ? NULL : curr_channel_->state_machine_control;
	}

	/**
	 sci_getState is called by distribution to get the state of the current SCTP-control instance.
	 This function also logs the state with log-level VERBOSE.
	 @return state value (0=CLOSED, 3=ESTABLISHED)
	 */
	uint get_curr_channel_state()
	{
		state_machine_controller_t* smctrl =
			(state_machine_controller_t*)get_state_machine_controller();
		if (smctrl == NULL)
		{
			/* error log */
			ERRLOG(MAJOR_ERROR, "get_curr_channel_state: NULL");
			return ChannelState::Closed;
		}
#ifdef _DEBUG
		switch (smctrl->channel_state)
		{
		case ChannelState::Closed:
			EVENTLOG(VERBOSE, "Current channel state : CLOSED");
			break;
		case ChannelState::CookieWait:
			EVENTLOG(VERBOSE, "Current channel state :COOKIE_WAIT ");
			break;
		case ChannelState::CookieEchoed:
			EVENTLOG(VERBOSE, "Current channel state : COOKIE_ECHOED");
			break;
		case ChannelState::Connected:
			EVENTLOG(VERBOSE, "Current channel state : ESTABLISHED");
			break;
		case ChannelState::ShutdownPending:
			EVENTLOG(VERBOSE, "Current channel state : SHUTDOWNPENDING");
			break;
		case ChannelState::ShutdownReceived:
			EVENTLOG(VERBOSE, "Current channel state : SHUTDOWNRECEIVED");
			break;
		case ChannelState::ShutdownSent:
			EVENTLOG(VERBOSE, "Current channel state : SHUTDOWNSENT");
			break;
		case ChannelState::ShutdownAckSent:
			EVENTLOG(VERBOSE, "Current channel state : SHUTDOWNACKSENT");
			break;
		default:
			EVENTLOG(VERBOSE, "Unknown channel state : return Closed");
			return ChannelState::Closed;
			break;
		}
#endif
		return smctrl->channel_state;
	}

	int get_primary_path()
	{
		path_controller_t* path_ctrl = get_path_controller();
		if (path_ctrl == NULL)
		{
			ERRLOG(MAJOR_ERROR, "set_path_chunk_sent_on: GOT path_ctrl NULL");
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
			ERRLOG(MINOR_ERROR, "get_path_controller: curr_channel_ is NULL");
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
	inline void set_data_chunk_sent_flag(int path_param_id)
	{
		path_controller_t* path_ctrl = get_path_controller();
		if (path_ctrl == NULL)
		{
			ERRLOG(MAJOR_ERROR, "set_path_chunk_sent_on: GOT path_ctrl NULL");
			return;
		}
		if (path_ctrl->path_params == NULL)
		{
			ERRLOG1(MAJOR_ERROR, "set_path_chunk_sent_on(%d): path_params NULL !",
				path_param_id);
			return;
		}
		if (!(path_param_id >= 0 && path_param_id < path_ctrl->path_num))
		{
			ERRLOG1(MAJOR_ERROR, "set_path_chunk_sent_on: invalid path ID: %d", path_param_id);
			return;
		}
		EVENTLOG1(VERBOSE, "Calling set_path_chunk_sent_on(%d)", path_param_id);
		path_ctrl->path_params[path_param_id].data_chunks_sent_in_last_rto = true;
	}

	void free_internal_data_chunk(internal_data_chunk_t* item)
	{
		/* this is common item we allocated by allocator*/
		if (item == NULL) return;

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
		if (curr_channel_ != NULL && curr_channel_->receive_control != NULL)
		{
			/*also make sure free all received duplicated data chunks */
			curr_channel_->receive_control->duplicated_data_chunks_list.clear();
			/* stop running sack timer*/
			if (curr_channel_->receive_control->timer_running)
			{
				timer_mgr_.delete_timer(curr_channel_->receive_control->sack_timer);
				curr_channel_->receive_control->sack_timer = timer_mgr_.timers.end();
				curr_channel_->receive_control->timer_running = false;
				EVENTLOG(DEBUG, "stop_sack_timer()::Stopped Timer");
			}
		}
		else
		{
			ERRLOG(MAJOR_ERROR, "stop_sack_timer()::recv_controller_t instance not set !");
		}
	}

	/**
	 * Disassembles chunks from a received datagram
	 * data chunks may only be parsed after control chunks.....
	 *
	 * sctp common header header has been verified
	 * tag (if association is established) and CRC is okay
	 * get first chunk-id and length, pass pointers & len on to the relevant module in below :
	 - CHUNK_INIT, CHUNK_INIT_ACK,CHUNK_ABORT, CHUNK_SHUTDOWN,CHUNK_SHUTDOWN_ACK
	 CHUNK_COOKIE_ECHO,CHUNK_COOKIE_ACK go to SCTP_CONTROL
	 (change of association state)
	 - CHUNK_HBREQ, CHUNK_HBACK go to PATH_MAN instance
	 - CHUNK_SACK goes to RELIABLE_TRANSFER
	 - CHUNK_ERROR probably to SCTP_CONTROL as well  (at least there !)
	 - CHUNK_DATA goes to RX_CONTROL
	 *
	 * Those modules must get a pointer to the start of a chunk and
	 * information about its size (without padding).
	 *
	 * @param  curr_source_path_  index of address on which this data arrived
	 * @param  curr_geco_packet_->chunk  pointer to first chunk of the newly received data
	 * @param  curr_geco_packet_value_len_
	 * length of payload (i.e. len of the concatenation of chunks)
	 */
	int disassemle_curr_geco_packet(void);

	/**
	 * For now this function treats only one incoming data chunk' tsn
	 * @param chunk the data chunk that was received by the bundling
	 */
	int process_data_chunk(data_chunk_t * data_chunk, uint ad_idx);

	/**
	 * sctlr_init is called by bundling when a init message is received from the peer.
	 * an InitAck may be returned, alongside with a cookie chunk variable parameter.
	 * The following data are created and included in the init acknowledgement:
	 * a COOKIE parameter.
	 * @param init_chunk_t  pointer to the received init-chunk (including optional parameters)
	 * 0 all good,
	 * 	ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_CHUNK: stop process the chunk and delete channel
	 *
	 */
	int process_init_chunk(init_chunk_t * init);

	/**
	 *  deletes the current chanel.
	 *  The chanel will not be deleted at once, but is only marked for deletion. This is done in
	 *  this way to allow other modules to finish their current activities. To prevent them to start
	 *  new activities, the currentAssociation pointer is set to NULL.
	 */
	void delete_curr_channel(void);

	/**
	 * indicates that communication was lost to peer (chapter 10.2.E).
	 * Calls the respective ULP callback function.
	 * @param  status  type of event, that has caused the association to be terminated
	 */
	void on_connection_lost(uint status);
	/**
	* indicates that an association is established (chapter 10.2.D).
	* @param status     type of event that caused association to come up;
	* either COMM_UP_RECEIVED_VALID_COOKIE, COMM_UP_RECEIVED_COOKIE_ACK
	* or COMM_UP_RECEIVED_COOKIE_RESTART
	*/
	void on_connection_up(uint status);
	/**
	* indicates that a restart has occured(chapter 10.2.G).
	* Calls the respective ULP callback function.
	*/
	void on_peer_restart(void);

	/**
	 * Clear the global association data.
	 *  This function must be called after the association retrieved from the list
	 *  with setAssociationData is no longer needed. This is the case after a time
	 *  event has been handled.
	 */
	void clear_current_channel(void)
	{
		curr_channel_ = NULL;
		curr_geco_instance_ = NULL;
	}

	/**
	 * this function aborts and clear this association and send abort to peer.
	 * And optionally adds an error parameter to the ABORT chunk that is sent out.
	 * this is for A-side to send abort  as it has channel presented
	 */
	void abort_channel(short error_type, uchar* errordata, ushort errordattalen);

	/**
	 pm_disableHB is called to disable heartbeat for one specific path id.
	 @param  pathID index of  address, where HBs should not be sent anymore
	 @return error code: 0 for success, 1 for error (i.e. pathID too large)
	 */
	int stop_heart_beat_timer(short pathID)
	{
		path_controller_t* pathctrl = get_path_controller();
		if (pathctrl == NULL)
		{
			ERRLOG(MAJOR_ERROR, "pm_disableHB: get_path_controller() failed");
			return -1;
		}
		if (pathctrl->path_params == NULL)
		{
			ERRLOG1(MAJOR_ERROR, "pm_disableHB(%d): no paths set", pathID);
			return -1;
		}
		if (!(pathID >= 0 && pathID < pathctrl->path_num))
		{
			ERRLOG1(MAJOR_ERROR, "pm_disableHB: invalid path ID %d", pathID);
			return -1;
		}
		if (pathctrl->path_params[pathID].hb_enabled)
		{
			timer_mgr_.delete_timer(pathctrl->path_params[pathID].hb_timer_id);
			pathctrl->path_params[pathID].hb_timer_id = timer_mgr_.timers.end();
			pathctrl->path_params[pathID].hb_enabled = false;
			EVENTLOG1(INTERNAL_TRACE, "stop_heart_beat_timer: path %d disabled", pathID);
		}
		return 0;
	}

	/*
	 @what
	 sctlr_initAck is called by bundling when a init acknowledgement was received from the peer.
	 @how
	 @why
	 @note
	 The following data are retrieved from the init-data and saved for this association:
	 - remote tag from the initiate tag field
	 - receiver window credit of the peer
	 - # of send streams of the peer, must be lower or equal the # of receive streams this host
	 has 'announced' with the init-chunk.
	 - # of receive streams the peer allows the receiver of this initAck to use.
	 @caution
	 The initAck must contain a cookie which is returned to the peer with the cookie acknowledgement.
	 Params: initAck: data of initAck-chunk including optional parameters without chunk header
	 */
	ChunkProcessResult process_init_ack_chunk(init_chunk_t * initAck);
	void set_channel_remote_addrlist(sockaddrunion destaddrlist[MAX_NUM_ADDRESSES],
		int noOfAddresses)
	{
		if (curr_channel_ == NULL)
		{
			ERRLOG(MINOR_ERROR, "set_channel_destaddrlist(): current cannel is NULL!");
			return;
		}
		memcpy(curr_channel_->remote_addres, destaddrlist,
			noOfAddresses * sizeof(sockaddrunion));
		curr_channel_->remote_addres_size = noOfAddresses;
	}
	bool peer_supports_particial_reliability(init_chunk_t* initack)
	{
		assert(initack != 0);
		uchar* foundvlp = find_first_vlparam_of(VLPARAM_UNRELIABILITY,
			&initack->variableParams[0],
			initack->chunk_header.chunk_length - INIT_CHUNK_FIXED_SIZES);
		if (foundvlp != NULL)
		{
			if (ntohs(((vlparam_fixed_t*)foundvlp)->param_length) >= VLPARAM_FIXED_SIZE)
			{
				return true;
			}
			else
			{
				EVENTLOG(VERBOSE, " pr vlp too short < 4 bytes");
				return false;
			}
		}
		return false;
	}
	cookie_param_t* get_state_cookie_from_init_ack(init_chunk_t* initack)
	{
		assert(initack != 0);
		if (initack->chunk_header.chunk_id == CHUNK_INIT_ACK)
		{
			return (cookie_param_t*)find_first_vlparam_of(VLPARAM_UNRELIABILITY,
				&initack->variableParams[0],
				initack->chunk_header.chunk_length - INIT_CHUNK_FIXED_SIZES);
		}
		else
		{
			return 0;
		}
	}
	chunk_id_t alloc_cookie_echo(cookie_param_t * cookieParam)
	{
		if (cookieParam == 0) return -1;

		cookie_echo_chunk_t* cookieChunk =
			(cookie_echo_chunk_t*)geco_malloc_ext(sizeof(cookie_echo_chunk_t), __FILE__,
				__LINE__);
		memset(cookieChunk, 0, sizeof(cookie_echo_chunk_t));
		cookieChunk->chunk_header.chunk_id = CHUNK_COOKIE_ECHO;
		cookieChunk->chunk_header.chunk_flags = 0x00;
		cookieChunk->chunk_header.chunk_length = ntohs(
			cookieParam->vlparam_header.param_length);
		add2chunklist((simple_chunk_t*)cookieChunk, "created cookie echo chunk %u ");
		/*  copy cookie parameter EXcluding param-header into chunk            */
		memcpy(&(cookieChunk->cookie), cookieParam,
			ntohs(cookieParam->vlparam_header.param_length) - VLPARAM_FIXED_SIZE);
		while (curr_write_pos_[simple_chunk_index_] & 3)
			curr_write_pos_[simple_chunk_index_]++;
		return simple_chunk_index_;
	}
	/**
	 * this is called by bundling, when a SACK needs to be processed.This is a LONG function !
	 * FIXME : check correct update of rtx->lowest_tsn !
	 * FIXME : handling of out - of - order SACKs
	 * CHECK : did SACK ack lowest outstanding tsn, restart t3 timer(section 7.2.4.4) )
	 * @param  adr_index   index of the address where we got that sack
	 * @param  sack_chunk  pointer to the sack chunk
	 * @return -1 on error, 0 if okay.
	 */
	int process_sack_chunk(uint adr_index, void *sack_chunk, uint totalLen);

	chunk_id_t build_init_chunk_from_cookie(cookie_echo_chunk_t* cookie_echo_chunk)
	{
		assert(cookie_echo_chunk != NULL);
		init_chunk_t* initChunk = (init_chunk_t*)geco_malloc_ext(INIT_CHUNK_TOTAL_SIZE, __FILE__, __LINE__);
		if (initChunk == NULL) ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
		memset(initChunk, 0, INIT_CHUNK_TOTAL_SIZE);
		initChunk->chunk_header.chunk_id = CHUNK_INIT;
		initChunk->chunk_header.chunk_flags = 0x00;
		initChunk->chunk_header.chunk_length = INIT_CHUNK_FIXED_SIZES;
		initChunk->init_fixed = cookie_echo_chunk->cookie.peer_init;
		return add2chunklist((simple_chunk_t*)initChunk, "add2chunklist()::created initChunk  from cookie %u");
	}

	chunk_id_t build_init_ack_chunk_from_cookie(cookie_echo_chunk_t* cookie_echo_chunk)
	{
		assert(cookie_echo_chunk != NULL);
		init_chunk_t* initChunk = (init_chunk_t*)geco_malloc_ext(INIT_CHUNK_TOTAL_SIZE, __FILE__, __LINE__);
		if (initChunk == NULL) ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
		memset(initChunk, 0, INIT_CHUNK_TOTAL_SIZE);
		initChunk->chunk_header.chunk_id = CHUNK_INIT_ACK;
		initChunk->chunk_header.chunk_flags = 0x00;
		initChunk->chunk_header.chunk_length = INIT_CHUNK_FIXED_SIZES;
		initChunk->init_fixed = cookie_echo_chunk->cookie.local_initack;
		return add2chunklist((simple_chunk_t*)initChunk, "add2chunklist()::created init ack chunk  from cookie %u");
	}

	uint get_local_tag()
	{
		return curr_channel_ == NULL ? 0 : curr_channel_->local_tag;
	}

	uint get_remote_tag()
	{
		return curr_channel_ == NULL ? 0 : curr_channel_->remote_tag;
	}
	/**
	*  This function allocates memory for a new association.
	*  For the active side of an association, this function is called when ULP calls Associate
	*  For the passive side this function is called when a valid cookie message is received.
	*  It also creates all the modules path management, bundling and SCTP-control.
	*  The rest of the modules are created with mdi_initAssociation.
	*  The created association is put into the list of associations.
	*
	*  @param SCTP_InstanceName    identifier for an SCTP instance (if there are more)
	*  @param  local_port          src port (which this association listens to)
	*  @param  remote_port         destination port (peers source port)
	*  @param   tagLocal           randomly generated tag belonging to this association
	*  @param  primaryDestinitionAddress   index of the primary address
	*  @param  noOfDestinationAddresses    number of addresses the peer has
	*  @param  destinationAddressList      pointer to the array of peer's addresses
	*  @return true for success, else for failure
	*/
	bool alloc_new_channel(geco_instance_t* sInstance,
		ushort local_port,
		ushort remote_port,
		uint tagLocal,
		short primaryDestinitionAddress,
		ushort noOfDestinationAddresses,
		sockaddrunion *destinationAddressList);

	/**
	sctlr_cookie_echo is called by bundling when a cookie echo chunk was received from  the peer.
	The following data is retrieved from the cookie and saved for this association:
	\begin{itemize}
	\item  from the init chunk:
	\begin{itemize}
	\item peers tag
	\item peers receiver window credit
	\item peers initial TSN
	\item peers network address list if multihoming is used
	\end{itemize}
	\item local tag generated before the initAck was sent
	\item my initial TSN generated before the initAck was sent
	\item number of send streams I use, must be lower or equal to peers number of receive streams from init chunk
	\item number of receive streams I use (can be lower than number of send streams the peer requested in
	the init chunk
	\end{itemiz}
	@param  cookie_echo pointer to the received cookie echo chunk
	*/
	void process_cookie_echo_chunk(cookie_echo_chunk_t * cookie_echo);

	void clear()
	{
		last_source_addr_ = NULL;
		last_dest_addr_ = NULL;
		last_src_port_ = 0;
		last_dest_port_ = 0;
		curr_channel_ = NULL;
		curr_geco_instance_ = NULL;
		curr_ecc_code_ = 0;
		chunkflag2use_ = -1;
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
	bool contains_error_chunk(uchar * packet_value, uint packet_val_len, ushort error_cause);

	uint get_bundle_total_size(bundle_controller_t* buf)
	{
		assert(GECO_PACKET_FIXED_SIZE == sizeof(geco_packet_fixed_t));
		return ((buf)->ctrl_position + (buf)->sack_position + (buf)->data_position
			- 2 * UDP_GECO_PACKET_FIXED_SIZES);
	}

	uint get_bundle_sack_size(bundle_controller_t* buf)
	{
		assert(GECO_PACKET_FIXED_SIZE == sizeof(geco_packet_fixed_t));
		return ((buf)->ctrl_position + (buf)->data_position - UDP_GECO_PACKET_FIXED_SIZES);
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
	int send_bundled_chunks(int * ad_idx = NULL);

	/**
	 * creates a simple chunk except of DATA chunk. It can be used for parameterless
	 * chunks like abort, cookieAck and shutdownAck. It can also be used for chunks
	 * that have only variable length parameters like the error chunks
	 */
	uint alloc_simple_chunk(uint chunk_type, uchar flag)
	{
		//create smple chunk used for ABORT, SHUTDOWN-ACK, COOKIE-ACK
		simple_chunk_t* simple_chunk_ptr = (simple_chunk_t*)geco_malloc_ext(SIMPLE_CHUNK_SIZE,
			__FILE__, __LINE__);

		simple_chunk_ptr->chunk_header.chunk_id = chunk_type;
		simple_chunk_ptr->chunk_header.chunk_flags = flag;
		simple_chunk_ptr->chunk_header.chunk_length = CHUNK_FIXED_SIZE;

		add2chunklist(simple_chunk_ptr, "create simple chunk %u");
		return simple_chunk_index_;
	}
	/* makes an initAck and initializes the the fixed part of initAck */
	uchar alloc_init_ack_chunk(uint initTag, uint rwnd, ushort noOutStreams, ushort noInStreams,
		uint initialTSN)
	{
		assert(sizeof(init_chunk_t) == INIT_CHUNK_TOTAL_SIZE);
		add2chunklist(
			(simple_chunk_t*)build_init_chunk(initTag, rwnd, noOutStreams, noInStreams,
				initialTSN, CHUNK_INIT_ACK), "create init ack chunk %u");
		return simple_chunk_index_;
	}
	void enter_error_cause_unrecognized_chunk(chunk_id_t cid, error_cause_t*ecause,
		uchar* errdata, uint errdatalen)
	{
		//error chunk is paramsless chunk so no need simple_chunks[cid] check
		curr_write_pos_[cid] += put_ec_unrecognized_chunk(ecause, errdata, errdatalen);
	}

	/**
	 * function to put an error_chunk with type UNKNOWN PARAMETER
	 * @return error value, 0 on success, -1 on error
	 */
	int send_error_chunk_unrecognized_chunk_type(uchar* errdata, ushort length)
	{
		// build chunk  and add it to chunklist
		add2chunklist((simple_chunk_t*)build_error_chunk(), "add error chunk %u\n");
		// add error cause
		enter_error_cause(simple_chunk_index_, ECC_UNRECOGNIZED_CHUNKTYPE, errdata, length);
		// send it
		simple_chunk_t* simple_chunk_t_ptr_ = complete_simple_chunk(simple_chunk_index_);
		lock_bundle_ctrl();
		bundle_ctrl_chunk(simple_chunk_t_ptr_);
		unlock_bundle_ctrl();
		free_simple_chunk(simple_chunk_index_);
		return send_bundled_chunks();
	}
	void enter_error_cause(chunk_id_t chunkID, ushort errcode, uchar* errdata = 0,
		uint errdatalen = 0)
	{
		assert(simple_chunks_[chunkID] != NULL);
		assert(completed_chunks_[chunkID] == false);
		assert(simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_ERROR);
		assert(simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_ABORT);
		assert(simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK);
		curr_write_pos_[chunkID] +=
			put_error_cause((error_cause_t*)&simple_chunks_[chunkID]->chunk_value[curr_write_pos_[chunkID]],
				errcode, errdata, errdatalen);
	}

	void enter_supported_addr_types(chunk_id_t chunkID, bool with_ipv4, bool with_ipv6,
		bool with_dns)
	{
		//if( simple_chunks_[chunkID] == NULL )
		//{
		//    ERRLOG(MAJOR_ERROR, "enter_suppeorted_addr_types()::Invalid chunk ID\n");
		//    return;
		//}
		//if( completed_chunks_[chunkID] )
		//{
		//    ERRLOG(MAJOR_ERROR, " enter_supported_addr_types()::chunk already completed!\n");
		//    return;
		//}
		//if( simple_chunks_[chunkID]->chunk_header.chunk_id != CHUNK_INIT
		//    && simple_chunks_[chunkID]->chunk_header.chunk_id != CHUNK_INIT_ACK )
		//{
		//    ERRLOG(MAJOR_ERROR, " enter_supported_addr_types()::chunk type not init !\n");
		//    return;
		//}

		assert(simple_chunks_[chunkID] != NULL);
		assert(completed_chunks_[chunkID] == false);
		assert(simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT);
		assert(simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK);
		uchar* param =
			&((init_chunk_t*)(simple_chunks_[chunkID]))->variableParams[curr_write_pos_[chunkID]];
		curr_write_pos_[chunkID] += put_vlp_supported_addr_types(param, with_ipv4, with_ipv6,
			with_dns);
	}

	void enter_vlp_cookie_life_span(chunk_id_t chunkID, uint lifespan)
	{
		assert(simple_chunks_[chunkID] != NULL);
		assert(completed_chunks_[chunkID] == false);
		assert(simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT);

		cookie_preservative_t* preserv;
		init_chunk_t* init = ((init_chunk_t*)simple_chunks_[chunkID]);

		/* check if init chunk already contains a cookie preserv. */
		uchar* start = find_first_vlparam_of(VLPARAM_COOKIE_PRESEREASONV, init->variableParams,
			init->chunk_header.chunk_length - INIT_CHUNK_FIXED_SIZES);
		if (start != 0)
		{
			/* simply overwrite this cookie preserv. */
			preserv = (cookie_preservative_t*)start;
			put_vlp_cookie_life_span(preserv, lifespan);
		}
		else
		{
			/* append the new parameter */
			preserv = (cookie_preservative_t*)&init->variableParams[curr_write_pos_[chunkID]];
			curr_write_pos_[chunkID] += put_vlp_cookie_life_span(preserv, lifespan);
		}
	}

	/*
	 * swaps length INSIDE the packet and enters chunk into the current list
	 * DO NOT need call  free_simple_chunk() !
	 */
	uchar alloc_simple_chunk(simple_chunk_t* chunk)
	{
		chunk->chunk_header.chunk_length = ntohs(chunk->chunk_header.chunk_length);
		add2chunklist(chunk, "created chunk from string %u ");
		return simple_chunk_index_;
	}

	/* reads the simple_chunks_ type of a chunk.*/
	uchar get_simple_chunk_id(uchar chunkID)
	{
		if (simple_chunks_[chunkID] == NULL)
		{
			ERRLOG(WARNNING_ERROR, "Invalid chunk ID\n");
			return 0;
		}
		return simple_chunks_[chunkID]->chunk_header.chunk_id;
	}

	/*reads the number of output streams from an init or initAck */
	ushort read_outbound_stream(uchar init_chunk_id)
	{
		if (simple_chunks_[init_chunk_id] == NULL)
		{
			ERRLOG(MAJOR_ERROR, "Invalid chunk ID\n");
			return 0;
		}

		simple_chunk_t* scptr = simple_chunks_[init_chunk_id];
		uint chunkid = scptr->chunk_header.chunk_id;
		if (chunkid == CHUNK_INIT || chunkid == CHUNK_INIT_ACK)
		{
			ushort osnum = ntohs(((init_chunk_t*)scptr)->init_fixed.outbound_streams);
			return osnum;
		}
		else
		{
			ERRLOG(MAJOR_ERROR, "read_outbound_stream(): chunk type not init or initAck");
			return 0;
		}
	}

	/*reads the number of input streams from an init or initAck */
	ushort read_inbound_stream(uchar init_chunk_id)
	{
		if (simple_chunks_[init_chunk_id] == NULL)
		{
			ERRLOG(MAJOR_ERROR, "Invalid chunk ID\n");
			return -1;
		}

		simple_chunk_t* scptr = simple_chunks_[init_chunk_id];
		uint chunkid = scptr->chunk_header.chunk_id;
		if (chunkid == CHUNK_INIT || chunkid == CHUNK_INIT_ACK)
		{
			ushort isnum = ntohs(((init_chunk_t*)scptr)->init_fixed.inbound_streams);
			return isnum;
		}
		else
		{
			ERRLOG(MAJOR_ERROR, "read_inbound_stream(): chunk type not init or initAck");
			return -1;
		}
	}

	uint read_init_tag(uchar init_chunk_id)
	{
		if (simple_chunks_[init_chunk_id] == NULL)
		{
			ERRLOG(MAJOR_ERROR, "Invalid chunk ID\n");
			return -1;
		}

		simple_chunk_t* scptr = simple_chunks_[init_chunk_id];
		uint chunkid = scptr->chunk_header.chunk_id;
		if (chunkid == CHUNK_INIT || chunkid == CHUNK_INIT_ACK)
		{
			uint initag = ntohl(((init_chunk_t*)scptr)->init_fixed.init_tag);
			return initag;
		}
		else
		{
			ERRLOG(MAJOR_ERROR, "read_init_tag(): chunk type not init or initAck");
			return -1;
		}
	}

	/**
	 * free_simple_chunk removes the chunk from the array of simple_chunks_ and frees the
	 * memory allocated for that chunk
	 */
	void free_simple_chunk(uint chunkID)
	{
		if (simple_chunks_[chunkID] != NULL)
		{
			EVENTLOG1(INFO, "free_simple_chunk():: free simple chunk %u", chunkID);
			geco_free_ext(simple_chunks_[chunkID], __FILE__, __LINE__);
			simple_chunks_[chunkID] = NULL;
		}
		else
		{
			ERRLOG(FALTAL_ERROR_EXIT, "chunk already freed\n");
		}
	}

	/**
	 removes the chunk from the array of simple_chunks_ without freeing the
	 memory allocated for that chunk.
	 Used in the following 2 cases:
	 1) the caller wants to keep the chunk for retransmissions.
	 2) the chunk was created with uchar alloc_simple_chunk(simple_chunk_t* chunk)
	 and the pointer to the chunk points into an geco packet from recv_geco_packet(),
	 which was allocated as a whole. In this case the chunk can not be freed here.
	 */
	void remove_simple_chunk(uchar chunkID)
	{
		uchar cid = chunkID;
		if (simple_chunks_[chunkID] != NULL)
		{
			simple_chunks_[chunkID] = NULL;
			EVENTLOG1(DEBUG, "remove_simple_chunk():: REMOVE chunk %u", cid);
		}
		else
		{
			ERRLOG(WARNNING_ERROR, "chunk already forgotten");
		}
	}

	chunk_id_t add2chunklist(simple_chunk_t * chunk, const char *log_text = NULL)
	{
		simple_chunk_index_ = ((simple_chunk_index_ + 1) % MAX_CHUNKS_SIZE_MASK);
		EVENTLOG1(DEBUG, log_text, simple_chunk_index_);
		simple_chunks_[simple_chunk_index_] = chunk;
		curr_write_pos_[simple_chunk_index_] = 0;
		completed_chunks_[simple_chunk_index_] = false;
		return simple_chunk_index_;
	}

	/**
	 * @brief returns a pointer to the beginning of a simple chunk,
	 * internally fillup chunk length.
	 */
	simple_chunk_t *complete_simple_chunk(uint chunkID)
	{
		if (simple_chunks_[chunkID] == NULL)
		{
			ERRLOG(MAJOR_ERROR, "Invalid chunk ID\n");
			return NULL;
		}
		simple_chunks_[chunkID]->chunk_header.chunk_length =
			htons(
			(simple_chunks_[chunkID]->chunk_header.chunk_length
				+ curr_write_pos_[chunkID]));
		completed_chunks_[chunkID] = true;
		return simple_chunks_[chunkID];
	}

	/**
	 * this function used for bundling of control chunks
	 * Used by geco-control and path management
	 * @param chunk pointer to chunk, that is to be put in the bundling buffer
	 */
	void bundle_ctrl_chunk(simple_chunk_t * chunk, int * dest_index = NULL);

	/**
	 * function to return a pointer to the bundling module of this association
	 * @return   pointer to the bundling data structure, null in case of error.
	 */
	inline bundle_controller_t* get_bundle_controller(channel_t* channel =
		NULL)
	{
		if (channel == NULL)
		{
			ERRLOG(VERBOSE, "get_bundle_control: association not set");
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
			ERRLOG(MINOR_ERROR, "get_recv_controller: association not set");
			return NULL;
		}
		else
		{
			return channel->receive_control;
		}
	}

	/**
	 * Allow sender to send data right away
	 * when all received chunks have been diassembled completely.
	 * @example
	 * firstly, lock_bundle_ctrl() when disassembling received chunks;
	 * then, generate and bundle outging chunks like sack, data or ctrl chunks;
	 * the bundle() will interally force sending all chunks if the bundle are full.
	 * then, excitely call send all bundled chunks;
	 * finally, unlock_bundle_ctrl(dest addr);
	 * will send all bundled chunks automatically to the specified dest addr
	 */
	inline void unlock_bundle_ctrl(int* ad_idx = NULL)
	{
		bundle_controller_t* bundle_ctrl = (bundle_controller_t*)get_bundle_controller(
			curr_channel_);

		/*1) no channel exists, it is NULL, so we take the global bundling buffer */
		if (bundle_ctrl == NULL)
		{
			EVENTLOG(VERBOSE, "unlock_bundle_ctrl()::Setting global bundling buffer");
			bundle_ctrl = &default_bundle_ctrl_;
		}

		bundle_ctrl->locked = false;
		if (bundle_ctrl->got_send_request) send_bundled_chunks(ad_idx);

		EVENTLOG1(VERBOSE, "unlock_bundle_ctrl()::got %s send request",
			(bundle_ctrl->got_send_request == true) ? "A" : "NO");
	}
	/**
	 * disallow sender to send data right away when newly received chunks have
	 * NOT been diassembled completely.
	 */
	inline void lock_bundle_ctrl()
	{
		bundle_controller_t* bundle_ctrl = (bundle_controller_t*)get_bundle_controller(
			curr_channel_);

		/*1) no channel exists, it is NULL, so we take the global bundling buffer */
		if (bundle_ctrl == NULL)
		{
			EVENTLOG(VERBOSE, "lock_bundle_ctrl()::Setting global bundling buffer");
			bundle_ctrl = &default_bundle_ctrl_;
		}

		bundle_ctrl->locked = true;
		bundle_ctrl->got_send_request = false;
	}

	/**
	 * @brief
	 * retrieves a association from the list using the transport address as key.
	 * Returns NULL also if the association is marked "deleted" !
	 * CHECKME : Must return NULL, if no Address-Port combination does not
	 * occur in ANY existing assoc.
	 *  If it occurs in one of these -> return it
	 *
	 * two associations are equal if their remote and local ports are equal and
	 * at least one of their remote addresses are equal. This is like in TCP, where
	 * a connection is identified by the transport address,
	 *  i.e. the IP-address and port of the peer.
	 *
	 * @param  src_addr address from which data arrived
	 * @param  src_port SCTP port from which data arrived
	 * @return pointer to the retrieved association, or NULL
	 * TODO hash(src_addr, src_port, dest_port) as key for channel to
	 * improve the performaces. */
	channel_t *find_channel_by_transport_addr(sockaddrunion * src_addr, ushort src_port,
		ushort dest_port);

	// cmp_channel() this mothod will set last_src_path_ to the one found src's
	// index in channel's remote addr list
	bool cmp_channel(const channel_t& a, const channel_t& b);

	/**
	 *   @return pointer to the retrieved association, or NULL
	 */
	geco_instance_t* find_geco_instance_by_transport_addr(sockaddrunion* dest_addr,
		ushort dest_port);
	bool cmp_geco_instance(const geco_instance_t& a, const geco_instance_t& b);

	/**
	 * after geco_inst and  channel have been found for an
	 * incoming packet, this function will return, if a packet may be processed
	 * or if it is not destined for this instance
	 * if channel presents, packet is discarded, otherwise, send ABORT+UNRESOLVED ADDR
	 * to peer
	 */
	bool validate_dest_addr(sockaddrunion * dest_addr);

	/**returns a value indicating which chunks are in the packet.*/
	uint find_chunk_types(uchar* packet_value, uint len, uint* total_chunk_count = NULL);

	/**check if local addr is found, return  ip4or6 loopback if found,
	 *  otherwise return  the ones same to stored in inst localaddrlist*/
	bool contain_local_addr(sockaddrunion* addr_list, uint addr_list_num);

	/**
	 * contains_chunk: looks for chunk_type in a newly received geco packet
	 * Should be called after find_chunk_types().
	 * The chunkArray parameter is inspected. This only really checks for chunks
	 * with an ID <= 30. For all other chunks, it just guesses...
	 * @return 0 NOT contains, 1 contains and only one,
	 * 2 contains this one and also other type chunks, NOT means two of this
	 * @pre: need call find_chunk_types() first
	 */
	inline int contains_chunk(uint chunk_type, uint chunk_types)
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
	 * find_first_chunk_of: looks for chunk_type in a newly received datagram
	 * All chunks within the datagram are looked at, until one is found
	 * that equals the parameter chunk_type.
	 * @param  datagram     pointer to the newly received data
	 * @param  vlparams_len          stop after this many bytes
	 * @param  chunk_type   chunk type to look for
	 * @return pointer to first chunk of chunk_type in SCTP datagram, else NULL
	 */
	uchar* find_first_chunk_of(uchar * packet_value, uint packet_val_len, uint chunk_type);

	/**
	 * @breif looks for address type parameters in INIT or INIT-ACKs.
	 * All parameters within the chunk are looked at, and the n-th supported address is
	 * copied into the provided buffer pointed to by the foundAddress parameter.
	 * If there are less than n addresses, an appropriate error is
	 * returned. n should be at least 1, of course.
	 * @param  chunk            pointer to an INIT or INIT ACK chunk
	 * @param  n                get the n-th address
	 * @param  foundAddress
	 * pointer to a buffer where an address, if found, will be copied
	 * @return -1  for parameter problem, 0 for success (i.e. address found),
	 * 1 if there are not that many addresses in the chunk.
	 */
	int read_peer_addr(uchar * init_chunk, uint chunk_len, uint n, sockaddrunion* foundAddress,
		int supportedAddressTypes);

	/**
	 * @return -1 prama error, >=0 number of the found addresses
	 * rbu_scanInitChunkForParameter() rbundling.c
	 * if ignore_last_src_addr == false, this fuction will always record this address
	 * even through receiver supportedAddressTypes does not supports it
	 */
	int read_peer_addreslist(sockaddrunion peer_addreslist[MAX_NUM_ADDRESSES],
		uchar * init_chunk, uint chunk_len, uint supportedAddressTypes,
		uint* peer_supported_type = NULL, bool ignore_dups = true,
		bool ignore_last_src_addr = false);

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
	uchar* find_first_vlparam_of(uint vlp_type, uchar* vlp_fixed, uint len)
	{
		ushort vlp_len;
		uint padding_len;
		uint read_len = 0;
		uint vlptype;
		vlparam_fixed_t* vlp;

		while (read_len < len)
		{
			/*1) validate reset of space of packet*/
			if (len - read_len < VLPARAM_FIXED_SIZE)
			{
				EVENTLOG(WARNNING_ERROR,
					"remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
				return NULL;
			}

			vlp = (vlparam_fixed_t*)vlp_fixed;
			vlptype = ntohs(vlp->param_type);
			vlp_len = ntohs(vlp->param_length);
			if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len) return NULL;

			if (vlptype == vlp_type)
			{
				return vlp_fixed;
			}

			read_len += vlp_len;
			padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
			read_len += padding_len;
			vlp_fixed += read_len;
		}
		return NULL;
	}

	/**
	 * @brief appends local IP addresses to a chunk, usually an init, initAck or asconf.
	 * @param [out] chunkid addres wrriten to this chunk
	 * @param [in] local_addreslist  the addres that will be written to chunk
	 */
	int enter_vlp_addrlist(uint chunkid, sockaddrunion local_addreslist[MAX_NUM_ADDRESSES],
		uint local_addreslist_size);

	/** check if endpoint is ADD-IP capable, store result, and put HIS chunk in cookie */
	int write_add_ip_chunk(uint initAckCID, uint initCID)
	{  //todo
		return 0;
	}
	/** check for set primary chunk ? Maybe add this only after Cookie Chunk ! */
	int write_set_primary_chunk(uint initAckCID, uint initCID)
	{  //todo
		return 0;
	}
	int write_vlp_unreliability(uint initAckCID, uint initCID)
	{
		EVENTLOG(VERBOSE, " - - - Enter write_vlp_unreliability()");

		init_chunk_t* init = (init_chunk_t*)(simple_chunks_[initCID]);
		init_chunk_t* initack = (init_chunk_t*)(simple_chunks_[initAckCID]);
		if (init == NULL || initack == NULL)
		{
			ERRLOG(FALTAL_ERROR_EXIT, "Invalid init or initAck chunk ID");
			return -1;
		}
		int ret;
		uchar* foundvlp = find_first_vlparam_of(VLPARAM_UNRELIABILITY, &init->variableParams[0],
			init->chunk_header.chunk_length - INIT_CHUNK_FIXED_SIZES);
		if (foundvlp != NULL)
		{
			ushort vlp_len = ntohs(((vlparam_fixed_t*)foundvlp)->param_length);
			if (vlp_len < VLPARAM_FIXED_SIZE)
			{
				EVENTLOG(VERBOSE, "vlp length less than 4 bytes -> return -1");
				ret = -1;
				return ret;
			}
			if (vlp_len == VLPARAM_FIXED_SIZE)
			{
				/* peer supports it, but doesn't send anything unreliably  */ret = 0;
			}
			else
			{
				/* peer supports it, and does send some */ret = 1;
			}
			memcpy(&initack->variableParams[curr_write_pos_[initAckCID]], foundvlp, vlp_len);
			curr_write_pos_[initAckCID] += vlp_len;
			while (curr_write_pos_[initAckCID] & 3)
				curr_write_pos_[initAckCID]++;
			EVENTLOG1(VERBOSE, "Found pr vlp (len %d ), copied to init ack cookie", vlp_len);
		}
		else
		{
			ret = -1;
			EVENTLOG(VERBOSE, "Not found pr vlp");
		}

		EVENTLOG(VERBOSE, " - - - Leave write_vlp_unreliability()");
		return ret;
	}
	bool support_unreliability(void)
	{
		if (curr_channel_ != NULL)
		{
			return (curr_channel_->remotely_supported_PRSCTP
				&& curr_channel_->locally_supported_PRDCTP);
		}
		if (curr_geco_instance_ != NULL)
		{
			return curr_geco_instance_->supportsPRSCTP;
		}
		return (library_support_unreliability_);
	}

	/**
	 * @brief enters unrecognized params from Init into initAck chunk
	 * that is returned then. Returns -1 if unrecognized chunk forces termination of chunk parsing
	 * without any further action, 1 for an error that stops chunk parsing, but returns error to
	 * the peer and 0 for normal continuation */
	int process_unrecognized_vlparams(uint initCID, uint AckCID);

	/*
	 * ch_enterUnrecognizedErrors enters unrecognized params from InitAck into an Error chunk
	 * that will be appended to an CookieEcho. Iff an error chunk was created, error not will be
	 * zero, else will be a new chunk id.
	 * Returns -1 if unrecognized chunk forces termination of chunk parsing
	 * without any further action, 1 for an error that stops chunk parsing, but returns error to
	 * the peer and 0 for normal continuation
	 */
	int process_unrecognized_params_errs_from_initack(chunk_id_t initAckID,
		uint supportedTypes,
		chunk_id_t *errorchunk, sockaddrunion* preferredDest, bool* destSet,
		bool* peerSupportsIPV4, bool* peerSupportsIPV6,
		bool* peerSupportsPRSCTP, bool* peerSupportsADDIP);

	/**
	 return the current system time converted to a value of  milliseconds.
	 to make representation in millisecs possible. This done by taking the remainder of
	 a division by OVERFLOW_SECS = 15x24x60x60, restarting millisecs count every 15 days.
	 @return unsigned 32 bit value representing system time in milliseconds.
	 span of time id 15 days
	 */
	uint get_safe_time_ms(void)
	{
		struct timeval cur_tval;
		gettimenow(&cur_tval);
		/* modulo overflows every every 15 days*/
		return ((cur_tval.tv_sec % OVERFLOW_SECS) * 1000 + cur_tval.tv_usec);
	}
	/** computes a cookie signature.
	 * TODO: replace this by something safer than MD5 */
	int write_hmac(cookie_param_t* cookieString)
	{
		if (cookieString == NULL) return -1;

		uint cookieLength = ntohs(
			cookieString->vlparam_header.param_length) - VLPARAM_FIXED_SIZE;
		if (cookieLength == 0) return -1;

		uchar* key = get_secre_key(KEY_READ);
		if (key == NULL) return -1;

		unsigned char digest[HMAC_LEN];
		MD5_CTX ctx;
		MD5Init(&ctx);
		MD5Update(&ctx, (uchar*)cookieString, cookieLength);
		MD5Update(&ctx, (uchar*)key, SECRET_KEYSIZE);
		MD5Final(digest, &ctx);
		memcpy(cookieString->ck.hmac, digest, sizeof(cookieString->ck.hmac));
		EVENTLOG1(VERBOSE, "Computed MD5 signature : %s", hexdigest(digest, HMAC_LEN));

		return 0;
	}
	int put_ecn(uint initAckID, uint initCID)
	{
		//TODO
		return 0;
	}
	void write_vlp_to_init_chunk(uint initChunkID, uint pCode, uint len, uchar* data)
	{
		if (simple_chunks_[initChunkID] == NULL)
		{
			ERRLOG(MAJOR_ERROR, "Invalid chunk ID");
			return;
		}
		if (completed_chunks_[initChunkID])
		{
			ERRLOG(MAJOR_ERROR, " write_vlp_to_init_chunk : chunk already completed");
			return;
		}
		/* chunk_value is the start of init chunk,
		 * curr_write_pos_[initChunkID] is offset to the vlp_fixed_t,
		 * so we need pass by INIT_CHUNK_FIXED_SIZE + curr_write_pos_[initChunkID]
		 * to get the correct writable pos*/
		uchar *vlPtr = (simple_chunks_[initChunkID]->chunk_value + INIT_CHUNK_FIXED_SIZE
			+ curr_write_pos_[initChunkID]);
		*((ushort*)vlPtr) = htons(pCode);
		vlPtr += sizeof(ushort);  // pass by param type
		*((ushort*)vlPtr) = htons(len + VLPARAM_FIXED_SIZE);
		vlPtr += sizeof(ushort);  // pass by param length field
		if (len > 0 && data != NULL) memcpy(vlPtr, data, len);
		curr_write_pos_[initChunkID] += (len + VLPARAM_FIXED_SIZE);
		while (curr_write_pos_[initChunkID] & 3)
			curr_write_pos_[initChunkID]++;
	}
	/* @brief append the variable length cookie param to an initAck. */
	/* ch_initFixed reads the fixed part of an init or initAck as complete structure */
	void write_cookie(uint initCID, uint initAckID, init_chunk_fixed_t* init_fixed,
		init_chunk_fixed_t* initAck_fixed, uint cookieLifetime, uint local_tie_tag,
		uint peer_tie_tag, ushort last_dest_port, ushort last_src_port,
		sockaddrunion local_Addresses[], uint num_local_Addresses,
		sockaddrunion peer_Addresses[], uint num_peer_Addresses);

	init_chunk_fixed_t* get_init_fixed(uint chunkID)
	{
		if (simple_chunks_[chunkID] == NULL)
		{
			ERRLOG(MAJOR_ERROR, "get_init_fixed()::Invalid chunk ID");
			return NULL;
		}

		if (simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK
			|| simple_chunks_[chunkID]->chunk_header.chunk_id == CHUNK_INIT)
		{
			return &((init_chunk_t *)simple_chunks_[chunkID])->init_fixed;
		}
		else
		{
			ERRLOG(MAJOR_ERROR, "get_init_fixed()::chunk type not init or initAck");
			return NULL;
		}
	}

	void write_unknown_param_error(uchar* pos, uint cid, ushort length, uchar* data)
	{
		error_cause_t* ec;
		if (pos == NULL)
		{
			ERRLOG(FALTAL_ERROR_EXIT, "write_unknown_param()::pos gets NULL !");
		}
		ec = (error_cause_t*)pos;
		ec->error_reason_code = htons(VLPARAM_UNRECOGNIZED_PARAM);
		ec->error_reason_length = htons(length + ERR_CAUSE_FIXED_SIZE);
		if (length > 0) memcpy(&ec->error_reason, data, length);
		curr_write_pos_[cid] += length + ERR_CAUSE_FIXED_SIZE;
		while ((curr_write_pos_[cid] % 4) != 0)
			curr_write_pos_[cid]++;
	}
	/**
	 *  @brief returns the suggested cookie lifespan increment if a cookie
	 *  preservative is present in a init chunk.
	 */
	uint get_cookie_lifespan(uint chunkID)
	{
		if (simple_chunks_[chunkID] == NULL)
		{
			ERRLOG(MAJOR_ERROR, "Invalid chunk ID");
			return 0;
		}

		if (simple_chunks_[chunkID]->chunk_header.chunk_id != CHUNK_INIT)
		{
			ERRLOG(MAJOR_ERROR, "get_cookie_lifespan()::chunk type not init");
			return 0;
		}

		init_chunk_t* init = ((init_chunk_t*)simple_chunks_[chunkID]);
		uint vlparams_len = ntohs(init->chunk_header.chunk_length) - INIT_CHUNK_FIXED_SIZES;
		uchar* curr_pos = find_first_vlparam_of(VLPARAM_COOKIE_PRESEREASONV,
			init->variableParams, vlparams_len);
		if (curr_pos != NULL && !ignore_cookie_life_spn_from_init_chunk_)
		{
			/* found cookie preservative */
			return ntohl(((cookie_preservative_t*)curr_pos)->cookieLifetimeInc)
				+ get_cookielifespan_from_statectrl();
		}
		else
		{
			/* return default cookie life span*/
			return get_cookielifespan_from_statectrl();
		}
		return 0;
	}

	/**
	 * get current parameter value for cookieLifeTime
	 * @return current value, -1 on error
	 */
	int get_cookielifespan_from_statectrl(void)
	{
		state_machine_controller_t* old_data = get_state_machine_controller();
		if (old_data == NULL)
		{
			EVENTLOG(DEBUG,
				"get_cookielifespan_from_statectrl():  get state machine ctrl is NULL -> use default timespan 10000ms !");
			return DEFAULT_COOKIE_LIFE_SPAN;
		}
		return old_data->cookie_lifetime;
	}

	/**
	 * only used for finding some vlparam in init or init ack chunks
	 * NULL no params, otherwise have params, return vlp fixed*/
	uchar* find_vlparam_from_setup_chunk(uchar * setup_chunk, uint chunk_len,
		ushort param_type);
};
#endif
