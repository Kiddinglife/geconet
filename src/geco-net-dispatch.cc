#include "geco-net-dispatch.h"
#include "geco-net-transport.h"
#include "geco-net-chunk.h"
#include "geco-net-auth.h"
#include "geco-ds-malloc.h"
#include "geco-net.h"
#include <algorithm>

#define EXIT_CHECK_LIBRARY           if(library_initiaized == false) {ERRLOG(FALTAL_ERROR_EXIT, "library not initialized!!!");}

static void print_addrlist(sockaddrunion* list, uint nAddresses)
{
	static char addrstr[MAX_IPADDR_STR_LEN];
	static ushort port;
	for (uint i = 0; i < nAddresses; i++)
	{
		saddr2str(&list[i], addrstr, MAX_IPADDR_STR_LEN, &port);
		EVENTLOG2(DEBUG, "+++ ip addr=%s:%d", addrstr, port);
	}
}

struct transportaddr_hash_functor
{
	size_t operator()(const transport_addr_t &addr) const
	{
		EVENTLOG1(DEBUG, "hashcode=%u", transportaddr2hashcode(addr.local_saddr, addr.peer_saddr) % 1000);
		return transportaddr2hashcode(addr.local_saddr, addr.peer_saddr);
	}
};

struct transportaddr_cmp_functor
{
	bool operator()(const transport_addr_t& addr1, const transport_addr_t &addr2) const
	{
		return saddr_equals(addr1.local_saddr, addr2.local_saddr) && saddr_equals(addr1.peer_saddr, addr2.peer_saddr);
	}
};
struct sockaddr_hash_functor
{
	size_t operator()(const sockaddrunion& addr) const
	{
		return sockaddr2hashcode(&addr);
	}
};

struct sockaddr_cmp_functor
{
	bool operator()(const sockaddrunion& a, const sockaddrunion& b) const
	{
		return saddr_equals(&a, &b, true);
	}
};

////////////////////// default lib geco_instance_params ///////////////////
uint PMTU_LOWEST = 576;
int myRWND = 32767; // maybe changed to other values after calling mtra_init()
bool library_initiaized = false;
bool library_support_unreliability_;
int checksum_algorithm_ = MULP_CHECKSUM_ALGORITHM_MD5;
bool support_pr_ = true;
bool support_addip_ = true;
uint delayed_ack_interval_ = SACK_DELAY;  //ms
bool send_abort_for_oob_packet_ = true;
uint ipv4_sockets_geco_instance_users = 0;
uint ipv6_sockets_geco_instance_users = 0;
bool mdi_connect_udp_sfd_ = false;
// inits along with library inits
uint defaultlocaladdrlistsize_;
sockaddrunion* defaultlocaladdrlist_;
/////////////////////////////////////////////////////////////////////////////

bool enable_test_;
bool ignore_cookie_life_spn_from_init_chunk_;

// --- add channel
// channel_.transport_addrslist = new transport_addr[size] // size is determined when channel is created
// for transport_addr in channel_.transport_addrslist: 
//		channel_map_.insert(transport_addr, channels_.size());
// channels_.push_back(channel_)
// ----delete channel
// for transport_addr in channel_.transport_addrslist: 
//		channel_map_.remove(transport_addr)
// channels_.fastdelete(channel_);
// transport_addr [------channel_map_--->] channel_id [-----channels_ vector---->] channel pointer
#ifdef _WIN32
std::unordered_map<transport_addr_t, uint, transportaddr_hash_functor, transportaddr_cmp_functor> channel_map_;
#else
std::tr1::unordered_map<transport_addr_t, uint, transportaddr_hash_functor, transportaddr_cmp_functor> channel_map_;
#endif

#ifdef _WIN32
std::unordered_map<sockaddrunion, short, sockaddr_hash_functor, sockaddr_cmp_functor> path_map;
#else
std::tr1::unordered_map<sockaddrunion, short, sockaddr_hash_functor, sockaddr_cmp_functor> path_map;
#endif

geco_channel_t** channels_; /// store all channels, channel id as key
uint channels_size_;
uint* available_channel_ids_; /// store all frred channel ids, can be reused when creatng a new channel
uint available_channel_ids_size_;
std::vector<geco_instance_t*> geco_instances_; /// store all instances, instance name as key
uchar* chunk;

/// whenever an external event (ULP-call, socket-event or timer-event), 
/// this pointer is setup a value and will be reset to null after the event has been handled.
geco_instance_t *curr_geco_instance_;
/// whenever an external event (ULP-call, socket-event or timer-event) this variable must contain the addressed channel. 
/// This pointer must be reset to null after the event has been handled.*/
geco_channel_t *curr_channel_;
static int mdi_send_sfd_;
packet_params_t* g_packet_params;
uint current_rwnd = 0;

/// these one-shot state variables are so frequently used in recv_gco_packet()  to improve performances 
int* curr_bundle_chunks_send_addr_ = 0;
geco_packet_fixed_t* curr_geco_packet_fixed_;
geco_packet_t* curr_geco_packet_;
uint curr_geco_packet_value_len_;
uchar* curr_uchar_init_chunk_;
sockaddrunion *last_source_addr_;
sockaddrunion *last_dest_addr_;
sockaddrunion addr_from_init_or_ack_chunk_;
// cmp_channel() will set last_src_path_ to the one found src's index in channel's remote addr list
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
bool mdi_udp_tunneled_;
bool should_discard_curr_geco_packet_;
int dest_addr_type_;
uint ip4_saddr_;
in6_addr* ip6_saddr_;
uint total_chunks_count_;
uint chunk_types_arr_;
int init_chunk_num_;
bool send_abort_;
bool found_init_chunk_;
bool cookie_echo_found_;
bool is_there_at_least_one_equal_dest_port_;
init_chunk_fixed_t* init_chunk_fixed_;
vlparam_fixed_t* vlparam_fixed_;

/// tmp variables used for looking up channel and geco instance
geco_channel_t tmp_channel_;
sockaddrunion tmp_addr_;
geco_instance_t tmp_geco_instance_;
sockaddrunion tmp_local_addreslist_[MAX_NUM_ADDRESSES];
int tmp_local_addreslist_size_;
uint my_supported_addr_types_;
sockaddrunion tmp_peer_addreslist_[MAX_NUM_ADDRESSES];
int tmp_peer_addreslist_size_;
uint tmp_peer_supported_types_;
transport_addr_t curr_trans_addr_;

/// used if no bundle module instance has been allocated and initialized yet 
bundle_controller_t* default_bundle_ctrl_;

/// related to error cause 
ushort curr_ecc_code_;
ushort curr_ecc_len_;
uchar* curr_ecc_reason_;

char hoststr_[MAX_IPADDR_STR_LEN];
char chunkflag2use_;

// tmp variables used in process_cookie_echo() 
chunk_id_t cookie_ack_cid_;
uint cookie_local_tie_tag_;
uint cookie_remote_tie_tag_;
uint cookiesendtime_;
uint currtime_;
uint cookielifetime_;

#if ENABLE_UNIT_TEST
/* unit test extra variables*/
bool enable_mock_dispatcher_disassemle_curr_geco_packet_;
bool enable_mock_dispatch_send_geco_packet_;
bool enable_mock_dispatcher_process_init_chunk_;
#endif

static recv_controller_t* mrecv;
static deliverman_controller_t* mdlm;
static reltransfer_controller_t* mreltx;
static smctrl_t* msm;
static path_controller_t* mpath;
static flow_controller_t* mfc;
static bundle_controller_t* mbu;

bundle_controller_t* mdi_read_mbu(geco_channel_t* channel = NULL);
reltransfer_controller_t* mdi_read_mreltsf(void);
deliverman_controller_t* mdi_read_mdlm(void);
path_controller_t* mdi_read_mpath();
flow_controller_t* mdi_read_mfc(void);
recv_controller_t* mdi_read_mrecv(void);
smctrl_t* mdi_read_smctrl();

/// this function aborts this association. And optionally adds an error parameter to the ABORT chunk that is sent out. */
void msm_abort_channel(short error_type = 0, uchar* errordata = 0, ushort errordattalen = 0);
/// get current parameter value for cookieLifeTime @return current value, -1 on erro
int msm_get_cookielife(void);
uint msm_read_max_assoc_retrans_count();
/// bundle when a init acknowledgement was received from the peer.
/// @note
/// The following data are retrieved from the init-data and saved for this association:
/// - remote tag from the initiate tag field
/// - receiver window credit of the peer
/// - # of send streams of the peer, must be lower or equal the # of receive streams this host
/// has 'announced' with the init-chunk.
/// - # of receive streams the peer allows the receiver of this initAck to use.
/// @caution
/// The initAck must contain a cookie which is returned to the peer with the cookie acknowledgement.
/// Params: initAck: data of initAck-chunk including optional parameters without chunk header
ChunkProcessResult msm_process_init_ack_chunk(init_chunk_t * initAck);
/// For now this function treats only one incoming data chunk' tsn
/// @param chunk the data chunk that was received by the bundling
int mrecv_process_data_chunk(data_chunk_t * data_chunk, uint ad_idx);
/// This function is called to initiate the setup an association.
/// The local tag and the initial TSN are randomly generated.
/// Together with the parameters of the function, they are used to create the init-message.
/// This data are also stored in a newly created association-record.
/// @param noOfOutStreams        number of send streams.
/// @param noOfInStreams         number of receive streams.
void msm_connect(ushort noOfOutStreams, ushort noOfInStreams, sockaddrunion *destinationList, uint numDestAddresses);
/// function initiates the shutdown of this association.
void msm_shutdown();
/// called when a shutdown chunk was received from the peer.
/// This function initiates a graceful shutdown of the association.
/// @param  shutdown_chunk pointer to the received shutdown chunk
int msm_process_shutdown_chunk(simple_chunk_t* simple_chunk);
/// called by bundling when a shutdownAck chunk was received from the peer.
/// Depending on the current state of the association, COMMUNICATION LOST is signaled to the
/// Upper Layer Protocol, and the association marked for removal.
int msm_process_shutdown_ack_chunk();
/// called by bundling when a SHUTDOWN COMPLETE chunk was received from the peer.
/// COMMUNICATION LOST is signaled to the ULP, timers stopped, and the association is marked for removal.
int msm_process_shutdown_complete_chunk();

/// Function returns the outstanding byte count value of this association.
/// @return current outstanding_bytes value, else -1
int mfc_get_outstanding_bytes(void);
uint mfc_get_queued_chunks_count(void);
/// this function stops all currently running timers of the flowcontrol moduleand may be called when the shutdown is imminent
void mfc_stop_timers(void);
/// this function stops all currently running timers, and may be called when the shutdown is imminent
/// @param  new_rwnd new receiver window of the association peer
void mfc_restart(uint new_rwnd, uint iTSN, uint maxQueueLen);

/// function to return the last a_rwnd value we got from our peer
/// @return  peers advertised receiver window
uint mreltx_get_peer_rwnd();
/// function to set the a_rwnd value when we got it from our peer
/// @param  new_arwnd      peers newly advertised receiver window
/// @return  0 for success, -1 for error*/
int mreltx_set_peer_arwnd(uint new_arwnd);
/// Function returns the number of chunks that are waiting in the queue to be acked
/// @return size of the retransmission queue
uint mreltx_get_unacked_chunks_count();
/// called, when a Cookie, that indicates the peer's restart, is received in the ESTABLISHED stat-> we need to restart too
static reltransfer_controller_t* mreltx_restart(reltransfer_controller_t* mreltx, uint numOfPaths, uint iTSN);

/// function to return the number of chunks that can be retrievedby the ULP - this function may need to be refined !!!!!!
int mdlm_read_queued_chunks();
ushort mdlm_read_istreams(void);
ushort mdlm_read_ostreams(void);
void mdlm_read_streams(ushort* inStreams, ushort* outStreams);
uint mdlm_read_queued_bytes();

/// function called by bundling when a SACK is actually sent, to stop a possibly running  timer
void mrecv_stop_sack_timer();
uint mrecv_read_cummulative_tsn_acked();
void mrecv_restart(int my_rwnd, uint newRemoteInitialTSN);
/// do the correct update of mrecv->lowest_duplicated_tsn
/// @param mrecv	instance of recv_controller_t
/// @param chunk_tsn	tsn we just received
/// @return boolean indicating whether lowest_duplicated_tsn was updated or not
bool mrecv_before_lowest_duptsn(recv_controller_t* mrecv, uint chunk_tsn);
static bool mrecv_sort_duplicates_cmp(duplicate_tsn_t one, duplicate_tsn_t two)
{
	return ubefore(one, two);
}
/// 1.called by bundling, after new data has been processed (so we may start building a sack chunk)
/// 2.by streamengine, when ULP has read some data, and we want to update the RWND.
void mrecv_on_packet_processed(bool new_data_received);

/// mpath_new creates a new instance of path management. There is one path management instance per association.
/// WATCH IT : this needs to be fixed ! path_params is NULL, but may accidentally be referenced !
/// @param numberOfPaths    number of paths of the association
/// @param primaryPath      initial primary path
/// @param  gecoInstance pointer to the geco instance
/// @return pointer to the newly created path management instance !
path_controller_t* mpath_new(short numberOfPaths, short primaryPath);
/// Deletes the instance pointed to by pathmanPtr.
/// @param   pathmanPtr pointer to the instance that is to be deleted
void mpath_free(path_controller_t *pathmanPtr);
/// pm_readState returns the current state of the path.
/// @param pathID  index of the questioned address
/// @return state of path (active/inactive)
int mpath_read_path_status(short pathid);
int mpath_get_rto_initial(void);
int mpath_get_rto_min(void);
uint mpath_get_rto_max(void);
int mpath_get_max_retrans_per_path(void);
/// pm_readRTO returns the currently set RTO value in msecs for a certain path.
/// @param pathID    index of the address/path
/// @return  path's current RTO
int mpath_read_rto(short pathID);
int mpath_read_primary_path();
/// simple function that sends a heartbeat chunk to the indicated address
/// @param  pathID index to the address, where HB is to be sent to
int mpath_do_hb(int pathID);
void mpath_start_hb_probe(uint remote_addres_size, ushort primaryPath);
/// pm_heartbeat is called when a heartbeat was received from the peer.
/// This function just takes that chunk, and sends it back.
/// @param heartbeatChunk pointer to the heartbeat chunk
/// @param source_address address we received the HB chunk from (and where it is echoed)
void mpath_process_heartbeat_chunk(heartbeat_chunk_t* heartbeatChunk, int source_address);
/// Function is used to update RTT, SRTT, RTO values after chunks have been acked.
/// CHECKME : this function is called too often with RTO == 0;
/// Is there one update per RTT ?
/// @param  pathID index of the path where data was acked
/// @param  newRTT new RTT measured, when data was acked, or zero if it was retransmitted
void mpath_handle_chunks_acked(short pathID, int roundtripTime);
/// pm_chunksAcked is called by reliable transfer whenever chunks have been acknowledged.
/// @param pathID   last path-ID where chunks were sent to (and thus probably acked from)
/// @param newRTT   the newly determined RTT in milliseconds, and 0 if retransmitted chunks had been acked
void mpath_chunks_acked(short pathID, int newRTT);
/// mpath_handle_chunks_retx is called whenever datachunks are retransmitted or a hearbeat-request
/// has not been acknowledged within the current heartbeat-intervall. It increases path- and peer-
/// retransmission counters and compares these counters to the corresonding thresholds.
/// @param  pathID index to the path that CAUSED retransmission
/// @return true if association was deleted, false if not
bool mpath_handle_chunks_retx(short pathid);
/// pm_chunksRetransmitted is called by reliable transfer whenever chunks have been retransmitted.
/// @param  pathID  address index, where timeout has occurred (i.e. which caused retransmission)
bool mpath_chunks_retx(short pathID);
/// spm_heartbeatTimer is called by the adaption-layer when the heartbeat timer expires.
/// It may set the path to inactive, or restart timer, or even cause COMM LOST
/// As all timer callbacks, it takes three arguments  (two pointers to necessary data)
/// @param timerID  ID of the HB timer that expired.
///  @param associationIDvoid  pointer to the association-ID
/// @param pathIDvoid         pointer to the path-ID
int mpath_heartbeat_timer_expired(timeout* timerID);
/// pm_heartbeatAck is called when a heartbeat acknowledgement was received from the peer.
/// checks RTTs, normally resets error counters, may set path back to ACTIVE state
/// @param heartbeatChunk pointer to the received heartbeat ack chunk
void mpath_process_heartbeat_ack_chunk(heartbeat_chunk_t* heartbeatChunk);
/// helper function, that simply sets the data_chunks_sent_in_last_rto flag of this path management instance to true
/// @param pathID  index of the address, where flag is set
void mpath_data_chunk_sent(short pathID);
/// pm_setPrimaryPath sets the primary path.
/// @param pathID     index of the address that is to become primary path
/// @return 0 if okay, else 1 if there was some error
short mpath_set_primary_path(short pathID);
/// pm_disableHB is called to disable heartbeat for one specific path id.
/// @param  pathID index of  address, where HBs should not be sent anymore
/// @return error code: 0 for success, 1 for error (i.e. pathID too large)
int mpath_disable_hb(short pathID);
int mpath_disable_all_hb();
/// pm_enableHB is called when ULP wants to enable heartbeat.
/// @param  pathID index of address, where we sent the HBs to
/// @param  hearbeatIntervall time in msecs, that is to be added to the RTT, before sending HB
/// @return error code, 0 for success, 1 for error (i.e. address index too large)
int mpath_enable_hb(short pathID, unsigned int hearbeatIntervall);

/// generates a random tag value for a new association, but not 0
/// @return   generates a random tag value for a new association, but not 0
inline uint mdi_generate_itag(void);
/// @brief Copies local addresses of this instance into the array passed as parameter.
/// @param [out] local_addrlist
/// array that will hold the local host's addresses after returning.
/// @return numlocalAddres number of addresses that local host/current channel has.
/// @pre either of current channel and current geco instance MUST present.
int mdi_validate_localaddrs_before_write_to_init(sockaddrunion* local_addrlist, sockaddrunion *peerAddress,
	uint numPeerAddresses, uint supported_types, bool receivedFromPeer);
/// check if local addr is found, return  ip4or6 loopback if found, otherwise return  the ones same to stored in inst localaddrlist
bool mdi_contains_localhost(sockaddrunion* addr_list, uint addr_list_num);
uint mdi_read_local_tag();
uint mdi_read_remote_tag();
unsigned int mdi_read_supported_addr_types(void);
int mdi_read_rwnd();
int mdi_read_default_delay(geco_instance_t* geco_instance);
// NULL means use last src addr , NOT_NULL means use primary addr or specified addr 
// @CAUTION  the 3 functions below MUST be used together to send bundled chunks
void mdi_set_bundle_dest_addr(int * ad_idx = NULL)
{
	curr_bundle_chunks_send_addr_ = ad_idx;
}

int mdi_send_bundled_chunks(int* ad_idx = NULL);
void mdi_bundle_ctrl_chunk(simple_chunk_t * chunk, int * dest_index = NULL);
/// deletes the current chanel.
/// The chanel will not be deleted at once, but is only marked for deletion. This is done in
/// this way to allow other modules to finish their current activities. To prevent them to start
/// new activities, the currentAssociation pointer is set to NULL.
void mdi_delete_curr_channel();
/// Clear the global association data. This function must be called after the association retrieved from the list
/// with setAssociationData is no longer needed. This is the case after a time event has been handled.
void mdi_clear_current_channel();
/// Allow sender to send data right away
/// when all received chunks have been diassembled completely.
/// @example
/// firstly, mdi_lock_bundle_ctrl() when disassembling received chunks;
/// then, generate and bundle outging chunks like sack, data or ctrl chunks;
/// the bundle() will interally force sending all chunks if the bundle are full.
/// then, excitely call send all bundled chunks;
/// finally, mdi_unlock_bundle_ctrl(dest addr);
/// will send all bundled chunks automatically to the specified dest addr
/// ad_idx = -1, send to last_source_addr
/// ad_idx = -2, send to primary path
/// ad_idx >0, send to the specified path as dest addr
void mdi_unlock_bundle_ctrl(int* ad_idx = NULL);
geco_channel_t* mdi_find_channel();
inline uint mdi_read_default_max_burst()
{
	if (curr_geco_instance_ == NULL)
		return DEFAULT_MAX_BURST;
	if (curr_channel_ == NULL)
		return DEFAULT_MAX_BURST;
	return curr_channel_->geco_inst->default_maxBurst;
}
/// Each module within SCTP that has timers implements its own timer call back
///  functions. These are registered at the adaption layer when a timer is started
///  and called directly at the module when the timer expires.
///  setAssociationData allows SCTP-modules with timers to retrieve the data of the
///  addressed association from the list of associations.
///  For this purpose the association-ID must be included in one of the
///  parameters of the start_timer function of the adaption-layer.
///  @param  associationID    the ID of the association
///  @return 0 if successful, 1 if the association does not exist in the list
bool mdi_set_curr_channel_inst(uint channelid);
/// copies destination addresses from the array passed as parameter to  the current association
/// @param addresses array that will hold the destination addresses after returning
/// @param noOfAddresses number of addresses that the peer has (and sends along in init/initAck)
void mdi_set_channel_remoteaddrlist(sockaddrunion addresses[MAX_NUM_ADDRESSES], int noOfAddresses);
void mdi_on_peer_connected(uint status);
/// indicates that communication was lost to peer (chapter 10.2.E).
/// Calls the respective ULP callback function.
/// @param  status  type of event, that has caused the association to be terminated
void mdi_on_disconnected(uint status);
/// indicates a change of network status (chapter 10.2.C). Calls the respective ULP callback function.
/// @param  destinationAddress   index to address that has changed
/// @param  newState             state to which indicated address has changed (PM_ACTIVE/PM_INACTIVE)
void mdi_on_path_status_changed(short destaddr_id, int newState);
/// indicates that a restart has occured(chapter 10.2.G). Calls the respective ULP callback function.
void mdi_on_peer_restarted();
/// indicates that association has been gracefully shut down (chapter 10.2.H). Calls the respective ULP callback function.
void mdi_on_shutdown_completed();
/// indicates gracefully shut down (chapter 10.2.H).Calls the respective ULP callback function.
void mdi_on_peer_shutdown_received();

//\\ IMPLEMENTATIONS \\//
inline uint mfc_get_queued_chunks_count(void)
{
	flow_controller_t* fc = mdi_read_mfc();
	if (fc == NULL)
	{
		ERRLOG(MAJOR_ERROR, "mfc_readNumberOfQueuedChunks()::flow control instance not set !");
		return 0;
	}
#ifdef _DEBUG
	EVENTLOG1(VERBOSE, "mfc_readNumberOfQueuedChunks() returns %u", (uint)fc->chunk_list.size());
#endif
	return (uint)fc->chunk_list.size();
}
inline int mfc_get_outstanding_bytes(void)
{
	flow_controller_t* fc = mdi_read_mfc();
	if (fc == NULL)
	{
		ERRLOG(MAJOR_ERROR, "mfc_get_outstanding_bytes()::flow control instance not set !");
		return -1;
	}
	return (int)fc->outstanding_bytes;
}

inline uint mreltx_get_peer_rwnd()
{
	reltransfer_controller_t *rtx;
	if ((rtx = mdi_read_mreltsf()) == NULL)
	{
		ERRLOG(MAJOR_ERROR, "mreltx_get_peer_rwnd()::reltransfer_controller_t instance not set !");
		return 0;
	}
	EVENTLOG1(VERBOSE, "mreltx_get_peer_rwnd() returns %u", rtx->peer_arwnd);
	return rtx->peer_arwnd;
}
inline int mreltx_set_peer_arwnd(uint new_arwnd)
{
	reltransfer_controller_t *rtx;
	if ((rtx = (reltransfer_controller_t *)mdi_read_mreltsf()) == NULL)
	{
		ERRLOG(MAJOR_ERROR, "retransmit_controller_t instance not set !");
		return -1;
	}
	else
		rtx->peer_arwnd = new_arwnd;
	EVENTLOG1(VERBOSE, "mreltx_set_peer_arwnd to %u", rtx->peer_arwnd);
	return 0;
}
inline uint mreltx_get_unacked_chunks_count()
{
	reltransfer_controller_t *rtx;
	if ((rtx = (reltransfer_controller_t *)mdi_read_mreltsf()) == NULL)
	{
		ERRLOG(MAJOR_ERROR, "reltransfer_controller_t instance not set !");
		return -1;
	}
	EVENTLOG1(VERBOSE, "mreltx_get_unacked_chunks_count() returns %u", rtx->chunk_list_tsn_ascended.size());
	return rtx->chunk_list_tsn_ascended.size();
}

inline int mdlm_read_queued_chunks()
{
	int i, num_of_chunks = 0;
	deliverman_controller_t* se = (deliverman_controller_t *)mdi_read_mdlm();
	if (se == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Could not read deliverman_controller_t Instance !");
		return -1;
	}
	for (i = 0; i < (int)se->numSequencedStreams; i++)
	{
		/* Add number of all chunks (i.e. lengths of all pduList lists of all streams */
		num_of_chunks += se->recv_seq_streams[i].pduList.size();
	}
	for (i = 0; i < (int)se->numOrderedStreams; i++)
	{
		/* Add number of all chunks (i.e. lengths of all pduList lists of all streams */
		num_of_chunks += se->recv_order_streams[i].pduList.size();
	}
	return num_of_chunks;
}
inline ushort mdlm_read_istreams(void)
{
	deliverman_controller_t* se = (deliverman_controller_t *)mdi_read_mdlm();
	if (se == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Could not read deliverman_controller_t Instance !");
		return 0;
	}
	return se->numOrderedStreams + se->numSequencedStreams;
}
inline ushort mdlm_read_ostreams(void)
{
	deliverman_controller_t* se = (deliverman_controller_t *)mdi_read_mdlm();
	if (se == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Could not read deliverman_controller_t Instance !");
		return 0;
	}
	return se->numOrderedStreams + se->numSequencedStreams;
}

//-------------------------- mpath
int mpath_enable_hb(short pathID, unsigned int hearbeatIntervall)
{
	path_controller_t* pmData = mdi_read_mpath();
	assert(pmData != NULL && "mpath_do_hb: GOT path_ctrl NULL");
	assert(pmData->path_params != NULL && "mpath_do_hb: path_params is NULL");

	pmData->path_params[pathID].hb_interval = hearbeatIntervall;
	EVENTLOG2(VERBOSE, "mpath_enable_hb: chose interval %u msecs for path %d", hearbeatIntervall, pathID);

	if (pathID >= 0 && pathID < pmData->path_num)
	{
		if (pmData->path_params[pathID].hb_enabled)
		{
			if (pmData->path_params[pathID].hb_timer_id != NULL)
			{
				mtra_timeouts_del(pmData->path_params[pathID].hb_timer_id);
				pmData->path_params[pathID].hb_timer_id = NULL;
			}
			pmData->path_params[pathID].hb_enabled = false;
			EVENTLOG1(INFO, "mpath_disable_hb: path %d is primary", pathID);
		}
		return GECONET_ERRNO::SUCESS;
	}
	EVENTLOG1(VERBOSE, "mpath_do_hb: invalid path ID %d", pathID);
	return GECONET_ERRNO::ILLEGAL_FUNC_PARAM;
}
int mpath_disable_hb(short pathID)
{
	path_controller_t* pmData = mdi_read_mpath();
	assert(pmData != NULL && "mpath_do_hb: GOT path_ctrl NULL");
	assert(pmData->path_params != NULL && "mpath_do_hb: path_params is NULL");

	if (pathID >= 0 && pathID < pmData->path_num)
	{
		if (pmData->path_params[pathID].hb_enabled)
		{
			if (pmData->path_params[pathID].hb_timer_id != NULL)
			{
				mtra_timeouts_del(pmData->path_params[pathID].hb_timer_id);
				pmData->path_params[pathID].hb_timer_id = NULL;
			}
			pmData->path_params[pathID].hb_enabled = false;
			EVENTLOG1(INFO, "mpath_disable_hb: path %d is primary", pathID);
		}
		return GECONET_ERRNO::SUCESS;
	}
	EVENTLOG1(VERBOSE, "mpath_do_hb: invalid path ID %d", pathID);
	return GECONET_ERRNO::ILLEGAL_FUNC_PARAM;
}
int mpath_disable_all_hb()
{
	path_controller_t* pmData = mdi_read_mpath();
	assert(pmData != NULL && "mpath_do_hb: GOT path_ctrl NULL");
	assert(pmData->path_params != NULL && "mpath_do_hb: path_params is NULL");

	for (int pathID = 0; pathID < pmData->path_num; pathID++)
	{
		if (pmData->path_params[pathID].hb_enabled)
		{
			if (pmData->path_params[pathID].hb_timer_id != NULL)
			{
				mtra_timeouts_del(pmData->path_params[pathID].hb_timer_id);
				pmData->path_params[pathID].hb_timer_id = NULL;
			}
			pmData->path_params[pathID].hb_enabled = false;
			EVENTLOG1(INFO, "mpath_disable_hb: path %d hb is disabled", pathID);
		}
	}
	return GECONET_ERRNO::SUCESS;
}
short mpath_set_primary_path(short pathID)
{
	path_controller_t* pmData = mdi_read_mpath();
	assert(pmData != NULL && "mpath_do_hb: GOT path_ctrl NULL");
	assert(pmData->path_params != NULL && "mpath_do_hb: path_params is NULL");

	if (pathID >= 0 && pathID < pmData->path_num)
	{
		if (pmData->path_params[pathID].state == PM_ACTIVE)
		{
			pmData->primary_path = pathID;
			pmData->path_params[pathID].data_chunks_sent_in_last_rto = false;
			EVENTLOG1(INFO, "pm_setPrimaryPath: path %d is primary", pathID);
			return GECONET_ERRNO::SUCESS;
		}
		return GECONET_ERRNO::INACTIVE_PATH;
	}

	EVENTLOG1(VERBOSE, "mpath_do_hb: invalid path ID %d", pathID);
	return GECONET_ERRNO::ILLEGAL_FUNC_PARAM;
}
void mpath_data_chunk_sent(short pathID)
{
	path_controller_t* pmData = mdi_read_mpath();
	assert(pmData != NULL && "mpath_do_hb: GOT path_ctrl NULL");
	assert(pmData->path_params != NULL && "mpath_do_hb: path_params is NULL");
	assert(pathID >= 0 && pathID < pmData->path_num && "mpath_do_hb: invalid path ID");
	EVENTLOG1(VERBOSE, "mpath_data_chunk_sent(%d)", pathID);
	pmData->path_params[pathID].data_chunks_sent_in_last_rto = true;
}
int mpath_read_path_status(short pathID)
{
	path_controller_t* pmData = mdi_read_mpath();
	assert(pmData != NULL && "mpath_read_path_status: GOT path_ctrl NULL");
	assert(pmData->path_params != NULL && "mpath_read_path_status: path_params is NULL");
	assert(pathID >= 0 && pathID < pmData->path_num && "mpath_read_path_status: invalid path ID");

	if (pmData->path_params == NULL)
		return PM_INACTIVE;
	else
		return pmData->path_params[pathID].state;

}
inline int mpath_get_rto_initial(void)
{
	path_controller_t* pmData = mdi_read_mpath();
	if (pmData == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Could not read deliverman_controller_t Instance !");
		return -1;
	}
	return pmData->rto_initial;
}
inline int mpath_get_rto_min(void)
{
	path_controller_t* pmData = mdi_read_mpath();
	if (pmData == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Could not read deliverman_controller_t Instance !");
		return -1;
	}
	return pmData->rto_min;
}
inline uint mpath_get_rto_max(void)
{
	path_controller_t* pmData = mdi_read_mpath();
	if (pmData == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Could not read deliverman_controller_t Instance !");
		return -1;
	}
	return pmData->rto_max;
}
inline int mpath_get_max_retrans_per_path(void)
{
	path_controller_t* pmData = mdi_read_mpath();
	if (pmData == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Could not read deliverman_controller_t Instance !");
		return -1;
	}
	return pmData->max_retrans_per_path;
}
inline int mpath_read_rto(short pathID)
{
	path_controller_t* pmData = mdi_read_mpath();
	if (pmData == NULL)
	{
		ERRLOG(MAJOR_ERROR, "Could not get path_controller_t Instance !");
		return -1;
	}

	if (pathID >= 0 && pathID < pmData->path_num)
	{
		if (pmData->path_params == NULL)
			return pmData->rto_initial;
		else
			return pmData->path_params[pathID].rto;
	}
	else
	{
		ERRLOG1(MAJOR_ERROR, "mpath_read_rto(%d): invalid path ID", pathID);
	}
	return -1;
}
inline int mpath_read_primary_path()
{
	path_controller_t* path_ctrl = mdi_read_mpath();
	if (path_ctrl == NULL)
	{
		ERRLOG(MAJOR_ERROR, "set_path_chunk_sent_on: GOT path_ctrl NULL");
		return -1;
	}
	return path_ctrl->primary_path;
}
int mpath_do_hb(int pathID)
{
	path_controller_t* path_ctrl = mdi_read_mpath();
	assert(path_ctrl != NULL && "mpath_do_hb: GOT path_ctrl NULL");
	assert(path_ctrl->path_params != NULL && "mpath_do_hb: path_params is NULL");
	assert(pathID >= 0 && pathID < path_ctrl->path_num && "mpath_do_hb: invalid path ID");

	chunk_id_t heartbeatCID = mch_make_hb_chunk(get_safe_time_ms(), (uint)pathID);
	mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(heartbeatCID), &pathID);
	int ret = mdi_send_bundled_chunks(&pathID);
	mch_free_simple_chunk(heartbeatCID);
	path_ctrl->path_params[pathID].hb_sent = ret > -1 ? true : false;
	return ret;
}
void mpath_start_hb_probe(uint noOfPaths, ushort primaryPathID)
{
	path_controller_t* pmData = mdi_read_mpath();
	assert(pmData != NULL && "mpath_start_hb_probe: GOT path_ctrl NULL");

	pmData->path_params = (path_params_t *)geco_malloc_ext(noOfPaths * sizeof(path_params_t), __FILE__, __LINE__);
	if (pmData->path_params == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "mpath_start_hb_probe: out of memory");

	uint timeout_ms, j = 0;
	int i;
	//uint maxburst = mdi_read_default_max_burst();

	if (primaryPathID >= 0 && primaryPathID < noOfPaths)
	{
		pmData->primary_path = primaryPathID;
		pmData->path_num = noOfPaths;
		pmData->total_retrans_count = 0;

		for (i = 0; i < (int)noOfPaths; i++)
		{
			if (i == primaryPathID)
			{
				pmData->path_params[i].state = PM_ACTIVE;
				timeout_ms = 0; // send pmtu HB imediately on primary path
			}
			else
			{
				pmData->path_params[i].state = PM_PATH_UNCONFIRMED;
				j++;
				timeout_ms = j * GRANULARITY; // send pmtu HB very quickly on unconfirmed paths every other GRANULARITY ms
			}

			pmData->path_params[i].hb_enabled = true;
			pmData->path_params[i].firstRTO = true;
			pmData->path_params[i].retrans_count = 0;
			pmData->path_params[i].rto = pmData->rto_initial;
			pmData->path_params[i].srtt = pmData->rto_initial;
			pmData->path_params[i].rttvar = 0;
			pmData->path_params[i].hb_sent = false;
			pmData->path_params[i].heartbeatAcked = false;
			pmData->path_params[i].timer_backoff = false;
			pmData->path_params[i].data_chunk_acked = false;
			pmData->path_params[i].data_chunks_sent_in_last_rto = false;
			pmData->path_params[i].hb_interval = PM_INITIAL_HB_INTERVAL;
			pmData->path_params[i].hb_timer_id = 0;
			pmData->path_params[i].path_id = i;
			pmData->path_params[i].eff_pmtu = PMTU_LOWEST;
			pmData->path_params[i].probing_pmtu = PMTU_HIGHEST;

			EVENTLOG1(0, "timeout = %d", timeout_ms);
			assert(pmData->path_params[i].hb_timer_id == NULL);
			pmData->path_params[i].hb_timer_id = mtra_timeouts_add(TIMER_TYPE_HEARTBEAT, timeout_ms,
				&mpath_heartbeat_timer_expired, &pmData->channel_id, &pmData->path_params[i].path_id,
				&pmData->path_params[i].probing_pmtu);
			/* after RTO we can do next RTO update */
			pmData->path_params[i].last_rto_update_time = get_safe_time_ms();
		}
	}
}
void mpath_handle_chunks_acked(short pathID, int newRTT)
{
	path_controller_t* pmData = mdi_read_mpath();
	assert(pmData != NULL && "mpath_do_hb: GOT path_ctrl NULL");
	assert(pmData->path_params != NULL && "mpath_do_hb: path_params is NULL");
	assert(pathID >= 0 && pathID < pmData->path_num && "mpath_do_hb: invalid path ID");

	EVENTLOG2(NOTICE, "mpath_handle_chunks_acked: pathID: %u, new RTT: %u msecs", pathID, newRTT);

	if (newRTT > 0) // newRTT = 0 if last send is retransmit.
	{
		if (pmData->path_params[pathID].firstRTO == true)
		{
			pmData->path_params[pathID].srtt = newRTT;
			pmData->path_params[pathID].rttvar = std::max(newRTT >> 1, GRANULARITY);
			pmData->path_params[pathID].rto = std::max(std::min((uint)newRTT * 3, pmData->rto_max), pmData->rto_min);
			pmData->path_params[pathID].firstRTO = false;
		}
		else
		{
			pmData->path_params[pathID].rttvar = (uint)((1.f - RTO_BETA) * pmData->path_params[pathID].rttvar
				+ RTO_BETA * abs((int)(pmData->path_params[pathID].srtt - newRTT)));
			pmData->path_params[pathID].rttvar = std::max(pmData->path_params[pathID].rttvar, (uint)GRANULARITY);
			pmData->path_params[pathID].srtt = (uint)((1.f - RTO_ALPHA) * pmData->path_params[pathID].srtt
				+ RTO_ALPHA * newRTT);
			pmData->path_params[pathID].rto = pmData->path_params[pathID].srtt + 4 * pmData->path_params[pathID].rttvar;
			pmData->path_params[pathID].rto = std::max(std::min(pmData->path_params[pathID].rto, pmData->rto_max),
				pmData->rto_min);
		}
		EVENTLOG3(NOTICE, "mpath_handle_chunks_acked: RTO update done: RTTVAR: %u msecs, SRTT: %u msecs, RTO: %u msecs",
			pmData->path_params[pathID].rttvar, pmData->path_params[pathID].srtt, pmData->path_params[pathID].rto);
	}
	else
	{
		EVENTLOG(DEBUG, "mpath_handle_chunks_acked: chunks acked without RTO-update");
	}

	// reset counters for endpoint and this path
	pmData->path_params[pathID].retrans_count = 0;
	pmData->total_retrans_count = 0;
}
void mpath_chunks_acked(short pathID, int newRTT)
{
	path_controller_t* pmData = mdi_read_mpath();

	assert(pmData != NULL && "mpath_do_hb: GOT path_ctrl NULL");
	assert(pmData->path_params != NULL && "mpath_do_hb: path_params is NULL");

	if (pathID >= 0 && pathID < pmData->path_num)
	{
		ERRLOG1(MINOR_ERROR, "pm_chunksAcked: invalid path ID: %d", pathID);
		return;
	}
	if (newRTT < 0)
	{
		ERRLOG(MINOR_ERROR, "pm_chunksAcked: Warning: newRTT < 0");
		return;
	}
	if (newRTT > (int) pmData->rto_max)
	{
		ERRLOG1(MINOR_ERROR, "pm_chunksAcked: Warning: RTO > RTO_MAX: %d", newRTT);
		return;
	}

	newRTT = std::min((uint)newRTT, pmData->rto_max);

	if (pmData->path_params[pathID].state == PM_ACTIVE)
	{
		// Update RTO only if is the first data chunk acknowldged in this RTT intervall.
		// rtt is mesured by a pair of send and ack.
		// But we may have more than send at diffrent time and more than one ack received at different time.
		// we must use right matched send and ack to caculate the rtt. otherwise, do not update rto.
		// when t3-rtx timer expired, we set resend to true to show there are two sends happening
		// when the time receiving ack is earlier than gussed rto_update_time, we believe
		// this is ack for the older send not the recent send and not update rtt
		uint64 now = gettimestamp();
		if (now < pmData->path_params[pathID].last_rto_update_time)
		{
			EVENTLOG2(NOTICE, "pm_chunksAcked: now %llu stamp - no update before %lu stamp", now,
				pmData->path_params[pathID].last_rto_update_time);
			newRTT = 0;
		}
		else
		{
			if (newRTT != 0)
			{
				// only if actually new valid RTT measurement is taking place, do update the time
				pmData->path_params[pathID].last_rto_update_time = now;
				pmData->path_params[pathID].last_rto_update_time += pmData->path_params[pathID].srtt * stamps_per_ms();
			}
		}
		mpath_handle_chunks_acked(pathID, newRTT);
		pmData->path_params[pathID].data_chunk_acked = true;
	}
	else
	{
		/* FIX :::::::
		 we got an ACK possibly from on an inactive path */
		 /* immediately send out a Heartbeat on that path, then when we get */
		 /* a HB-ACK, we can set the path back to ACTIVE */
		 /* when original newRTT is 0 then we got a RTX-SACK, else if we are */
		 /* inactive, get ACTIVE */
		 /* Nay, nay nay !   stale acknowledgement, silently discard */
		return;
	}

}
bool mpath_handle_chunks_retx(short pathID)
{
	path_controller_t* pmData = mdi_read_mpath();
	assert(pmData != NULL && "mpath_do_hb: GOT path_ctrl NULL");
	assert(pmData->path_params != NULL && "mpath_do_hb: path_params is NULL");
	assert(pathID >= 0 && pathID < pmData->path_num && "mpath_do_hb: invalid path ID");
	EVENTLOG3(DEBUG, "mpath_handle_chunks_retx(%d) : path-rtx-count==%u, peer-rtx-count==%u", pathID,
		pmData->path_params[pathID].retrans_count, pmData->total_retrans_count);

	// update error counters for endpoint and path
	if (pmData->path_params[pathID].state == PM_PATH_UNCONFIRMED)
	{
		pmData->path_params[pathID].retrans_count++;
	}
	else if (pmData->path_params[pathID].state == PM_ACTIVE)
	{
		pmData->path_params[pathID].retrans_count++;
		pmData->total_retrans_count++;
	}
	else
	{
		EVENTLOG(DEBUG, "mpath_handle_chunks_retx: ignored, because already inactive");
		return false;
	}

	if (pmData->total_retrans_count >= msm_read_max_assoc_retrans_count())
	{
		mdi_on_disconnected(ConnectionLostReason::ExceedMaxRetransCount);
		mdi_delete_curr_channel();
		mdi_clear_current_channel();
		EVENTLOG(DEBUG, "mpath_handle_chunks_retx: communication lost");
		return true;
	}

	bool allPathsInactive = true;
	if (pmData->path_params[pathID].retrans_count >= pmData->max_retrans_per_path)
	{
		// Set state of this path to inactive and notify change of state to ULP
		pmData->path_params[pathID].state = PM_INACTIVE;
		EVENTLOG1(DEBUG, "mpath_handle_chunks_retx: path %d to INACTIVE ", pathID);

		// check if an active path is left
		int pID;
		for (pID = 0; pID < pmData->path_num; pID++)
		{
			if (pmData->path_params[pID].state == PM_ACTIVE)
			{
				allPathsInactive = false;
				break;
			}
		}

		if (allPathsInactive)
		{
			/* No active parts are left, communication lost to ULP */
			mdi_on_disconnected(ConnectionLostReason::PeerUnreachable);
			mdi_delete_curr_channel();
			// currchannel will be used later anyway ! so not clear
			// mdi_clear_current_channel();
			EVENTLOG(DEBUG, "mpath_handle_chunks_retx: communication lost (all paths are INACTIVE)");
			return true;
		}

		if (pathID == pmData->primary_path)
		{
			//reset alternative path data acked and sent to false and they will be chaged to true very quickly when send data chunks on it.
			pmData->path_params[pID].data_chunks_sent_in_last_rto = false;
			pmData->path_params[pID].data_chunk_acked = false;
			pmData->primary_path = pID;

			//reset primary path data acked and sent to false so that we can do hb for it again by seting hb timer in hb_timer_expired()
			pmData->path_params[pathID].data_chunks_sent_in_last_rto = false;
			pmData->path_params[pathID].data_chunk_acked = false;
			EVENTLOG2(INFO, "mpath_handle_chunks_retx():: primary path %d becomes inactive, change path %d to primary",
				pathID, pID);
		}

		mdi_on_path_status_changed(pathID, PM_INACTIVE);
	}
	return false;
}
bool mpath_chunks_retx(short pathID)
{
	path_controller_t* pmData = (path_controller_t *)mdi_read_mpath();
	assert(pmData != NULL && "mpath_chunks_retx():: mdi_read_mpath() failed");
	assert(pathID >= 0 && pathID < pmData->path_num && "mpath_chunks_retx: invalid path ID");

	if (pmData->path_params[pathID].state == PM_INACTIVE)
	{
		/* stale acknowledgement, silently discard */
		ERRLOG1(MINOR_ERROR, "mpath_chunks_retx: retransmissions over inactive path %d", pathID);
		return false;
	}
	return mpath_handle_chunks_retx(pathID);
}
int mpath_heartbeat_timer_expired(timeout* timerID)
{
	uint associationID = *(uint*)timerID->callback.arg1;
	int pathID = *(int *)timerID->callback.arg2;
	int mtu = timerID->callback.arg3 == NULL ? 0 : *(int*)timerID->callback.arg3;

	if (!mdi_set_curr_channel_inst(associationID))
	{ /* error log: expired timer refers to a non existent association. */
		ERRLOG1(WARNNING_ERROR, "mpath_heartbeat_timer_expired()::init timer expired association %08u does not exist",
			associationID);
		return -1;
	}

	geco_channel_t* channel = channels_[associationID];
	path_controller_t* pmData = channel->path_control;
	assert(pmData != NULL && "mpath_process_heartbeat_ack_chunk():: mdi_read_mpath() failed");
	assert(pathID >= 0 && pathID < pmData->path_num && "mpath_heartbeat_timer_expired: invalid path ID");

	EVENTLOG2(0, "Heartbeat timer expired for path %u at time ms %u", pathID, get_safe_time_ms());
	chunk_id_t heartbeatCID = 0;
	bool removed_association = false;
	int ret = 0;
	uint newtimeout = pmData->path_params[pathID].hb_interval + pmData->path_params[pathID].rto;

	/* Heartbeat has been sent and not acknowledged: handle as retransmission */
	if (pmData->path_params[pathID].hb_sent && !pmData->path_params[pathID].heartbeatAcked)
	{
		switch (pmData->path_params[pathID].state)
		{
		case PM_ACTIVE:
		case PM_PATH_UNCONFIRMED:
			/*
			 * Handling of unacked heartbeats is the same as that of unacked data chunks.
			 * The state after calling pm_chunksRetransmitted may have changed to inactive.
			 * If commLost is detected in mpath_handle_chunks_retx(), the current association
			 * is marked for deletetion. Doing so, all timers are stop. The HB-timers are
			 * stopped by calling pm_disableHB in mdi_deleteCurrentAssociation().
			 * heartBeatEnabled  is also set to false */
			removed_association = mpath_handle_chunks_retx((short)pathID);
			break;
		case PM_INACTIVE:
			/* path already inactive, dont increase counter etc. */
			EVENTLOG1(VERBOSE, "path %d already inactive, dont increase counter etc", pathID);
			break;
		default:
			ERRLOG1(WARNNING_ERROR, "no such pm state %d", pmData->path_params[pathID].state);
			return false;
			break;
		}

		if (!removed_association)
		{
			if (!pmData->path_params[pathID].timer_backoff)
			{
				pmData->path_params[pathID].rto = std::min(2 * pmData->path_params[pathID].rto, pmData->rto_max);
				EVENTLOG2(INFO, "Backing off timer : Path %d, RTO= %u", pathID, pmData->path_params[pathID].rto);
			}

			if (mtu > 0)
			{
				if (
					/*probe packet is lost but recent path network (last rto) are in good condition, treat as pmtu issue,*/
					(pmData->path_params[pathID].data_chunks_sent_in_last_rto && pmData->path_params[pathID].data_chunk_acked) ||
					/*idle path, isolated probe packet lost, treat as pmtu issue*/
					(!pmData->path_params[pathID].data_chunks_sent_in_last_rto && !pmData->path_params[pathID].data_chunk_acked))
				{
					//send smaller hb&&pmtu probe again
					if (mtu < PMTU_HIGHEST)
						mtu -= PMTU_CHANGE_RATE;
					if (mtu > (int) PMTU_LOWEST && mtu != pmData->path_params[pathID].eff_pmtu)
					{	//if == eff pmtu, which means we  last test upwards not acked, we still use the cached eff not sending probe again
						pmData->path_params[pathID].probing_pmtu = mtu;
						timerID->callback.arg3 = &pmData->path_params[pathID].probing_pmtu;
						heartbeatCID = mch_make_hb_chunk(get_safe_time_ms(), (uint)pathID, mtu);
					}
				}
				else
				{
					/*7.6.2 after a probe failure event and suppressed congestion
					 control, PLPMTUD MUST NOT probe again until an interval that is
					 larger than the expected interval between congestion control events.
					 here we do not send hb we ecpect t3-rtx timer timeouts to detect connection lost
					 also we reset the timeout to rto, when it timeouts, data chunks should be acked */
					newtimeout = pmData->path_params[pathID].rto;
				}
			}
		}
	}
	else
	{
		// send heartbeat if no chunks have been acked in the last HB-intervall (path is idle).
		if (mtu == 0)
		{
			timerID->callback.arg3 = 0;
			mtu = 0;
			if (generate_random_uint32() % 10 == 6)
			{
				// hit ratio for pmtu hb probe is 1/10 which is lamostly hbintervel*10 = 300000ms = 300s = 5 minutes
				// so eff pmtu will be cached at most 5 minutes
				if (pmData->path_params[pathID].eff_pmtu + PMTU_CHANGE_RATE <= PMTU_HIGHEST)
				{
					mtu = pmData->path_params[pathID].probing_pmtu = pmData->path_params[pathID].eff_pmtu + PMTU_CHANGE_RATE;
					timerID->callback.arg3 = &pmData->path_params[pathID].probing_pmtu;
				}
			}
			heartbeatCID = mch_make_hb_chunk(get_safe_time_ms(), (uint)pathID, mtu);
		}
		else
		{
			pmData->path_params[pathID].probing_pmtu = mtu;
			timerID->callback.arg3 = &pmData->path_params[pathID].probing_pmtu;
			heartbeatCID = mch_make_hb_chunk(get_safe_time_ms(), (uint)pathID, mtu);
		}
	}

	if (!removed_association)
	{
		pmData->path_params[pathID].hb_sent = false;
		if (heartbeatCID != 0)
		{
			EVENTLOG2(DEBUG, "--------------> timeout Send HB PROBE WITH BYTES OF %d on path %d", mtu, pathID);
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(heartbeatCID));
			pmData->path_params[pathID].hb_sent = mdi_send_bundled_chunks(&pathID) > -1 ? true : false;
			mch_free_simple_chunk(heartbeatCID);
		}

		if (pmData->path_params[pathID].hb_enabled)
		{
			// heartbeat could have been disabled when the association went down after commLost detected in mpath_handle_chunks_retx()
			// just readd this timer back with different timeouts
			mtra_timeouts_readd(timerID, newtimeout);
			/* reset this flag, so we can check, whether the path was idle */
			pmData->path_params[pathID].data_chunks_sent_in_last_rto = false;
		}

		//reset states
		pmData->path_params[pathID].heartbeatAcked = false;
		pmData->path_params[pathID].timer_backoff = false;
		pmData->path_params[pathID].data_chunk_acked = false;
	}

	/* Heartbeat has been sent and not acknowledged: handle as retransmission */
	//if (pmData->path_params[pathID].hb_sent && !pmData->path_params[pathID].heartbeatAcked)
	//{
	//	switch (pmData->path_params[pathID].state)
	//	{
	//	case PM_ACTIVE:
	//	case PM_PATH_UNCONFIRMED:
	//		/*
	//		* Handling of unacked heartbeats is the same as that of unacked data chunks.
	//		* The state after calling pm_chunksRetransmitted may have changed to inactive.
	//		* If commLost is detected in mpath_handle_chunks_retx(), the current association
	//		* is marked for deletetion. Doing so, all timers are stop. The HB-timers are
	//		* stopped by calling pm_disableHB in mdi_deleteCurrentAssociation().
	//		* heartBeatEnabled  is also set to false */
	//		removed_association = mpath_handle_chunks_retx((short)pathID);
	//		break;
	//	case PM_INACTIVE:
	//		/* path already inactive, dont increase counter etc. */
	//		EVENTLOG1(VERBOSE, "path %d already inactive, dont increase counter etc", pathID);
	//		break;
	//	default:
	//		ERRLOG1(WARNNING_ERROR, "no such pm state %d", pmData->path_params[pathID].state);
	//		return false;
	//		break;
	//	}
	//	if (!removed_association)
	//	{
	//		if (!pmData->path_params[pathID].timer_backoff)
	//		{
	//			pmData->path_params[pathID].rto = std::min(2 * pmData->path_params[pathID].rto, pmData->rto_max);
	//			EVENTLOG2(INFO, "Backing off timer : Path %d, RTO= %u", pathID, pmData->path_params[pathID].rto);
	//		}
	//	}
	//}
	//if (!removed_association && !pmData->path_params[pathID].data_chunk_acked && pmData->path_params[pathID].hb_enabled
	//	&& !pmData->path_params[pathID].data_chunks_sent_in_last_rto)
	//{
	//	// send heartbeat if no chunks have been acked in the last HB-intervall (path is idle).
	//	EVENTLOG(VERBOSE, "--------------> Sending HB");
	//	heartbeatCID = mch_make_hb_chunk(get_safe_time_ms(), (uint)pathID);
	//	mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(heartbeatCID), &pathID);
	//	ret = mdi_send_bundled_chunks(&pathID);
	//	pmData->path_params[pathID].hb_sent = ret > -1 ? true : false;
	//	mch_free_simple_chunk(heartbeatCID);
	//	// heartbeat could have been disabled when the association went down after commLost detected in mpath_handle_chunks_retx()
	//	// just readd this timer back with different timeouts
	//	mtra_timeouts_readd(timerID, pmData->path_params[pathID].hb_interval + pmData->path_params[pathID].rto);
	//	/* reset this flag, so we can check, whether the path was idle */
	//	pmData->path_params[pathID].data_chunks_sent_in_last_rto = false;
	//	EVENTLOG3(DEBUG, "Heartbeat timer started again with %u msecs for path %u, RTO=%u msecs",
	//		pmData->path_params[pathID].hb_interval + pmData->path_params[pathID].rto, pathID,
	//		pmData->path_params[pathID].rto);
	//}
	//else if (!removed_association)
	//{
	//	pmData->path_params[pathID].hb_sent = false;
	//}
	//if (!removed_association)
	//{
	//	pmData->path_params[pathID].heartbeatAcked = false;
	//	pmData->path_params[pathID].timer_backoff = false;
	//	pmData->path_params[pathID].data_chunk_acked = false;
	//}
	mdi_clear_current_channel();
	return ret;
}
void mpath_process_heartbeat_chunk(heartbeat_chunk_t* heartbeatChunk, int source_address)
{
	EVENTLOG1(INFO, "mpath_process_heartbeat_chunk()::source_address (%d)", source_address);
	//return;
	assert(curr_channel_ != NULL);
	if (curr_channel_->state_machine_control->channel_state == CookieEchoed
		|| curr_channel_->state_machine_control->channel_state == Connected)
	{
		heartbeatChunk->chunk_header.chunk_id = CHUNK_HBACK;
		heartbeatChunk->chunk_header.chunk_length = htons(20 + ntohs(heartbeatChunk->hmaclen));
		mdi_bundle_ctrl_chunk((simple_chunk_t*)heartbeatChunk);
		mdi_send_bundled_chunks();
	}
}
void mpath_process_heartbeat_ack_chunk(heartbeat_chunk_t* heartbeatChunk)
{
	path_controller_t* pmData = (path_controller_t *)mdi_read_mpath();
	if (pmData == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mpath_process_heartbeat_ack_chunk():: mdi_read_mpath() failed");
	}
	if (pmData->path_params == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mpath_process_heartbeat_ack_chunk():: path_params is NULL !");
	}

	chunk_id_t heartbeatCID = mch_make_simple_chunk((simple_chunk_t*)heartbeatChunk);
	bool hbSignatureOkay = mch_verify_heartbeat(heartbeatCID);
	if (!hbSignatureOkay)
	{
		EVENTLOG(DEBUG, "unmathced HB Signature ---> return");
		mch_remove_simple_chunk(heartbeatCID);
		return;
	}

	short pathID = mch_read_path_idx_from_heartbeat(heartbeatCID);
	if (!(pathID >= 0 && pathID < pmData->path_num))
	{
		EVENTLOG1(INFO, "pm_heartbeatAck: invalid path ID %d", pathID);
		return;
	}

	uint sendingTime = mch_read_sendtime_from_heartbeat(heartbeatCID);
	ushort newpmtu = mch_read_pmtu_from_heartbeat(heartbeatCID);
	mch_remove_simple_chunk(heartbeatCID);

	int roundtripTime = get_safe_time_ms() - sendingTime;
	EVENTLOG2(DEBUG, " HBAck for path %u, RTT = %d msecs", pathID, roundtripTime);
	//exit(-1);

	// reset error counters if received hback or sack
	mpath_handle_chunks_acked(pathID, roundtripTime);

	// Handling of acked heartbeats is the simular that that of acked data chunks.
	short state = pmData->path_params[pathID].state;
	if (state == PM_INACTIVE || state == PM_PATH_UNCONFIRMED)
	{
		// change to the active state
		pmData->path_params[pathID].state = PM_ACTIVE;
		EVENTLOG1(INFO, "pathID %d changed to ACTIVE", pathID);
		mdi_on_path_status_changed(pathID, (int)PM_ACTIVE);

		// restart timer with new RTO
		assert(pmData->path_params[pathID].hb_timer_id != NULL);
		assert(pmData->path_params[pathID].hb_timer_id->callback.arg1 == (void *)&pmData->channel_id);
		assert(pmData->path_params[pathID].hb_timer_id->callback.arg2 == (void *)&pmData->path_params[pathID].path_id);
		assert(pmData->path_params[pathID].hb_timer_id->callback.action == &mpath_heartbeat_timer_expired);
		assert(pmData->path_params[pathID].hb_timer_id->callback.type == TIMER_TYPE_HEARTBEAT);
		assert(pmData->path_params[pathID].hb_timer_id->flags == 0);
		mtra_timeouts_readd(pmData->path_params[pathID].hb_timer_id,
			pmData->path_params[pathID].hb_interval + pmData->path_params[pathID].rto);
	}

	// update this path's pmtu
	if (newpmtu > 0)
	{
		pmData->path_params[pathID].eff_pmtu = newpmtu;
		bool smallest = true;
		// update smallest channel pmtu pmtu is zero this is pure hb probe
		for (int i = 0; i < pmData->path_num; i++)
		{
			if (pmData->path_params[i].eff_pmtu < newpmtu)
			{
				smallest = false;
				break;
			}
		}
		if (smallest)
		{
			pmData->min_pmtu = newpmtu;
			curr_channel_->bundle_control->geco_packet_fixed_size == sizeof(uint) ?
				curr_channel_->bundle_control->curr_max_pdu = newpmtu - IP_HDR_SIZE - UDP_HDR_SIZE :
				curr_channel_->bundle_control->curr_max_pdu = newpmtu - IP_HDR_SIZE;
			curr_channel_->flow_control->cparams->mtu = newpmtu - IP_HDR_SIZE - 12;
		}
	}

	EVENTLOG2(DEBUG, "-------------->Receive HB PROBE WITH BYTES OF %d on path %d", newpmtu, pathID);
	//exit(-1);
	// stop pmtu probe on this path as we already get the best max eff pmtu
	pmData->path_params[pathID].hb_timer_id->callback.arg3 = 0;
	pmData->path_params[pathID].heartbeatAcked = true;
	pmData->path_params[pathID].timer_backoff = false;
}

inline int msm_get_cookielife(void)
{
	smctrl_t* smctrl_ = mdi_read_smctrl();
	if (smctrl_ == NULL)
	{
		EVENTLOG(DEBUG, "msm_get_cookielife():  get state machine ctrl is NULL -> use default timespan 10000ms !");
		return DEFAULT_COOKIE_LIFE_SPAN;
	}
	return smctrl_->cookie_lifetime;
}
inline uint msm_read_max_assoc_retrans_count()
{
	smctrl_t* smctrl_ = mdi_read_smctrl();
	assert(smctrl_ != NULL);
	return smctrl_->max_assoc_retrans_count;
}
// we firstly try raw socket if it fails we switch to udp-tunneld by setting to upd socks in on_connection_failed_cb()
static int msm_timer_expired(timeout* timerID)
{
	int ttype = timerID->callback.type;
	void* associationID = timerID->callback.arg1;

	// retrieve association from list
	curr_channel_ = channels_[*(int*)associationID];
	if (curr_channel_ == NULL)
	{
		ERRLOG(MAJOR_ERROR, "init timer expired but association %u does not exist -> return");
		return false;
	}
	curr_geco_instance_ = curr_channel_->geco_inst;

	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		ERRLOG(WARNNING_ERROR, "no smctrl with channel presents -> return");
		return false;
	}
	assert(smctrl->init_timer_id == timerID);

	int primary_path = mpath_read_primary_path();
	EVENTLOG3(VERBOSE, "msm_timer_expired(AssocID=%u,  state=%u, PrimaryPath=%u", (*(unsigned int *)associationID),
		smctrl->channel_state, primary_path);

	switch (smctrl->channel_state)
	{
	case ChannelState::CookieWait:
		EVENTLOG(NOTICE, "init timer expired in state COOKIE_WAIT");
		if (ttype != TIMER_TYPE_INIT)
		{
			ERRLOG(WARNNING_ERROR, "timer type (TIMER_TYPE_INIT) not matched channel_state  COOKIE_WAIT");
			return false;
		}

		if (smctrl->init_retrans_count < smctrl->max_assoc_retrans_count)
		{
			// resend init
			mdi_bundle_ctrl_chunk((simple_chunk_t*)smctrl->my_init_chunk);
			mdi_send_bundled_chunks();

			// restart init timer after timer backoff
			smctrl->init_retrans_count++;
			smctrl->init_timer_interval = std::min(smctrl->init_timer_interval * 2, mpath_get_rto_max());
			EVENTLOG1(NOTICE, "init timer backedoff %d msecs", smctrl->init_timer_interval);
			mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = mtra_timeouts_add(TIMER_TYPE_INIT, smctrl->init_timer_interval, &msm_timer_expired,
				&smctrl->channel_id);
		}
		else
		{
			EVENTLOG(WARNNING_ERROR, "init retransmission counter exeeded threshold in state COOKIE_WAIT");

			// del timer and call lost first because we need channel ptr but mdi_delete_curr_channel will zero it
			geco_free_ext(smctrl->my_init_chunk, __FILE__, __LINE__);
			smctrl->my_init_chunk = NULL;
			mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = NULL;
			mdi_on_disconnected(ConnectionLostReason::ExceedMaxRetransCount); //report error to ULP

			mdi_delete_curr_channel();
			mdi_clear_current_channel();
		}
		break;

	case ChannelState::CookieEchoed:
		EVENTLOG(NOTICE, "init timer expired in state CookieEchoed");
		if (ttype != TIMER_TYPE_INIT)
		{
			ERRLOG(WARNNING_ERROR, "timer type (TIMER_TYPE_INIT) not matched channel_state  CookieEchoed");
			return false;
		}

		if (smctrl->init_retrans_count < smctrl->max_assoc_retrans_count)
		{
			// resend init
			mdi_bundle_ctrl_chunk((simple_chunk_t*)smctrl->my_init_chunk);
			mdi_send_bundled_chunks();

			// restart init timer after timer backoff
			smctrl->init_retrans_count++;
			smctrl->init_timer_interval = std::min(smctrl->init_timer_interval * 2, mpath_get_rto_max());
			EVENTLOG1(NOTICE, "init timer backedoff %d msecs", smctrl->init_timer_interval);
			mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = mtra_timeouts_add(TIMER_TYPE_INIT, smctrl->init_timer_interval, &msm_timer_expired,
				&smctrl->channel_id);
		}
		else
		{
			EVENTLOG(NOTICE, "init retransmission counter exeeded threshold in state CookieEchoed");

			// del timer and call lost first because we need channel ptr but mdi_delete_curr_channel will zero it
			geco_free_ext(smctrl->peer_cookie_chunk, __FILE__, __LINE__);
			smctrl->peer_cookie_chunk = NULL;
			mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = NULL;
			mdi_on_disconnected(ConnectionLostReason::ExceedMaxRetransCount); //report error to ULP

			mdi_delete_curr_channel();
			mdi_clear_current_channel();
		}
		break;

	case ChannelState::ShutdownSent:
		EVENTLOG(NOTICE, "init timer expired in state ShutdownSent");
		if (ttype != TIMER_TYPE_SHUTDOWN)
		{
			ERRLOG(FALTAL_ERROR_EXIT, "timer type (TIMER_TYPE_SHUTDOWN) not matched channel_state  ShutdownSent");
			return false;
		}

		if (smctrl->init_retrans_count < smctrl->max_assoc_retrans_count)
		{
			// make and send shutdown again, with updated TSN (section 9.2)
			chunk_id_t shutdownCID = mch_make_shutdown_chunk(mrecv_read_cummulative_tsn_acked());
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shutdownCID));
			mdi_send_bundled_chunks(&primary_path);
			mch_free_simple_chunk(shutdownCID);

			// backoff timer and restart it
			smctrl->init_retrans_count++;
			smctrl->init_timer_interval = std::min(smctrl->init_timer_interval * 2, mpath_get_rto_max());
			EVENTLOG1(NOTICE, "init timer backedoff %d msecs", smctrl->init_timer_interval);
			mtra_timeouts_readd(smctrl->init_timer_id, smctrl->init_timer_interval);
		}
		else
		{
			EVENTLOG(NOTICE, "init retransmission counter exeeded threshold in state ShutdownSent");

			// del timer and call lost first because we need channel ptr but mdi_delete_curr_channel will zero it
			mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = NULL;
			mdi_on_disconnected(ConnectionLostReason::ExceedMaxRetransCount); //report error to ULP

			mdi_delete_curr_channel();
			mdi_clear_current_channel();
		}
		break;

	case ChannelState::ShutdownAckSent:
		EVENTLOG(NOTICE, "init timer expired in state ShutdownAckSent");
		if (ttype != TIMER_TYPE_SHUTDOWN)
		{
			ERRLOG(WARNNING_ERROR, "timer type (TIMER_TYPE_SHUTDOWN) not matched channel_state  ShutdownAckSent");
			return false;
		}
		if (smctrl->init_retrans_count < smctrl->max_assoc_retrans_count)
		{
			// resend ShutdownAck
			chunk_id_t shutdownAckCID = mch_make_simple_chunk(CHUNK_SHUTDOWN_ACK, FLAG_TBIT_UNSET);
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shutdownAckCID));
			mdi_send_bundled_chunks(&primary_path);
			mch_free_simple_chunk(shutdownAckCID);

			/* COMMENTED OUT BECAUSE PROBABLY VERY WRONG............. */
			/* make and send shutdown_complete again */
			/* shutdown_complete_CID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_COMPLETE, FLAG_NONE); */
			/* bu_put_Ctrl_Chunk(ch_chunkString(shutdown_complete_CID)); */
			/* bu_sendAllChunks(&primary); */
			/* ch_deleteChunk(shutdown_complete_CID); */

			// restart init timer after timer backoff
			smctrl->init_retrans_count++;
			smctrl->init_timer_interval = std::min(smctrl->init_timer_interval * 2, mpath_get_rto_max());
			EVENTLOG1(NOTICE, "init timer backedoff %d msecs", smctrl->init_timer_interval);
			mtra_timeouts_readd(smctrl->init_timer_id, smctrl->init_timer_interval);
		}
		else
		{
			EVENTLOG(NOTICE, "init retransmission counter exeeded threshold in state ShutdownAckSent");
			// del timer and call lost first because we need channel ptr but mdi_delete_curr_channel will zero it
			geco_free_ext(smctrl->peer_cookie_chunk, __FILE__, __LINE__);
			smctrl->peer_cookie_chunk = NULL;
			mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = NULL;
			mdi_on_disconnected(ConnectionLostReason::ExceedMaxRetransCount); //report error to ULP
			mdi_delete_curr_channel();
			mdi_clear_current_channel();
		}
		break;

	default:
		ERRLOG1(WARNNING_ERROR, "unexpected event: timer expired in state %02d", smctrl->channel_state);
		mtra_timeouts_del(smctrl->init_timer_id);
		smctrl->init_timer_id = NULL;
		return false;
		break;
	}
	return true;
}
void msm_connect(ushort noOfOrderStreams, ushort noOfSeqStreams, sockaddrunion *destinationList, uint numDestAddresses)
{
	smctrl_t* smctrl;
	if ((smctrl = mdi_read_smctrl()) == NULL)
	{
		ERRLOG(MAJOR_ERROR, "read smctrl_ failed");
		return;
	}
	if (smctrl->channel_state == ChannelState::Closed)
	{
		EVENTLOG(DEBUG, "msm_connect():: init connection in state CLOSED");
		uint itag = mdi_read_local_tag();
		uint rwand = mdi_read_rwnd();
		uint itsn = mdi_generate_itag();
		chunk_id_t initCID = mch_make_init_chunk(itag, rwand, noOfOrderStreams, noOfSeqStreams, itsn);
		EVENTLOG4(DEBUG, "msm_connect()::INIT CHUNK (CID=%d) [itag=%d,rwnd=%d,itsn=%d]", initCID, itag, rwand, itsn);

		/* store the number of streams */
		smctrl->ordered_streams = noOfOrderStreams;
		smctrl->sequenced_streams = noOfSeqStreams;

		if (support_pr_)
		{
			mch_write_vlp_of_init_chunk(initCID, VLPARAM_UNRELIABILITY);
			EVENTLOG(DEBUG, "msm_connect():: we support_pr_, write to INIT CHUNK");
		}

		if (support_addip_)
		{
			mch_write_vlp_of_init_chunk(initCID, VLPARAM_ADDIP);
			EVENTLOG(DEBUG, "msm_connect()::we support_addip_, write to  INIT CHUNK");
		}

		my_supported_addr_types_ = mdi_read_supported_addr_types();
		EVENTLOG1(DEBUG, "msm_connect()::my_supported_addr_types_(%d), write to INIT CHUNK", my_supported_addr_types_);

		mch_write_vlp_supportedaddrtypes(initCID, my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV4,
			my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV6, false);

		union sockaddrunion lAddresses[MAX_NUM_ADDRESSES];
		ushort nlAddresses = mdi_validate_localaddrs_before_write_to_init(lAddresses, destinationList, numDestAddresses,
			my_supported_addr_types_, false);
		mch_write_vlp_addrlist(initCID, lAddresses, nlAddresses);
		EVENTLOG1(DEBUG, "msm_connect()::local addr size (%d), write them to INIT CHUNK", nlAddresses);

		simple_chunk_t* myinit = mch_complete_simple_chunk(initCID);
		smctrl->my_init_chunk = (init_chunk_t*)myinit;
		mch_remove_simple_chunk(initCID);

		/* send init chunk */
		for (int count = 0; count < (int)numDestAddresses; count++)
		{
			// we firstly try raw socket if it fails we switch to udp-tunneld by setting to upd socks in on_connection_failed_cb()
			if (mdi_connect_udp_sfd_)
			{
				destinationList[count].sa.sa_family == AF_INET ? mdi_send_sfd_ = mtra_read_ip4udpsock() : mdi_send_sfd_ =
					mtra_read_ip6udpsock();
			}
			else
			{
				destinationList[count].sa.sa_family == AF_INET ? mdi_send_sfd_ = mtra_read_ip4rawsock() : mdi_send_sfd_ =
					mtra_read_ip6rawsock();
			}
			mdi_bundle_ctrl_chunk(myinit, &count);
			mdi_send_bundled_chunks(&count);
		}
		EVENTLOG1(DEBUG, "msm_connect()::addr_my_init_chunk_sent_to (%d)", numDestAddresses - 1);

		// init smctrl
		EVENTLOG(DEBUG, "msm_connect()::init smctrl");
		smctrl->addr_my_init_chunk_sent_to = numDestAddresses - 1;
		smctrl->peer_cookie_chunk = NULL;
		smctrl->local_tie_tag = 0;
		smctrl->peer_tie_tag = 0;
		smctrl->init_timer_interval = mpath_read_rto(mpath_read_primary_path());
		if (smctrl->init_timer_id != NULL)
		{  // stop t1-init timer
			EVENTLOG(DEBUG, "msm_connect()::stop t1-init timer");
			mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = NULL;
		}
		// start T1 init timer
		EVENTLOG(DEBUG, "msm_connect()::start t1-init timer");
		smctrl->init_timer_id = mtra_timeouts_add(TIMER_TYPE_INIT, smctrl->init_timer_interval, &msm_timer_expired,
			(void*)smctrl->channel);
		EVENTLOG(DEBUG, "********************** ENTER CookieWait State ***********************");
		smctrl->channel_state = ChannelState::CookieWait;
	}
	else
	{
		ERRLOG(MAJOR_ERROR, "msm_connect()::ChannelState::Closed !");
		return;
	}
}
void msm_abort_channel(short error_type, uchar* errordata, ushort errordattalen)
{
	// @TODO remember me free all queued chunks
	// send queues or recv queues in mdlm
	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "msm_abort_channel()::smctrl is NULL!");
		return;
	}

	if (smctrl->channel_state == ChannelState::Closed)
	{
		EVENTLOG(DEBUG, "event: abort in state CLOSED");
		mdi_delete_curr_channel();
		mdi_clear_current_channel();
		return;
	}

	chunk_id_t abortcid = mch_make_simple_chunk(CHUNK_ABORT, FLAG_TBIT_UNSET);
	if (error_type > 0)
		mch_write_error_cause(abortcid, error_type, errordata, errordattalen);
	mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abortcid));
	mch_free_simple_chunk(abortcid);
	mdi_unlock_bundle_ctrl();
	mdi_send_bundled_chunks();
	if (smctrl->init_timer_id != NULL)
	{  //stop init timer
		mtra_timeouts_del(smctrl->init_timer_id);
		//mtra_timer_mgr_.delete_timer(smctrl->init_timer_id);
		smctrl->init_timer_id = NULL;
	}

	mdi_on_disconnected(ConnectionLostReason::PeerAbortConnection);

	// delete all data of channel
	mdi_delete_curr_channel();
	mdi_clear_current_channel();
}
void msm_shutdown()
{
	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "msm_shutdown()::smctrl is NULL!");
		return;
	}
	bool readyForShutdown;
	switch (smctrl->channel_state)
	{
	case ChannelState::Connected:
		EVENTLOG1(INFO, "event: msm_shutdown in state %02d --> aborting", smctrl->channel_state);
		mpath_disable_all_hb();
		/* stop reliable transfer and read its state */
		readyForShutdown = (mreltx_get_unacked_chunks_count() == 0) && (mfc_get_queued_chunks_count() == 0);
		if (readyForShutdown)
		{
			// make and send shutdown
			chunk_id_t shutdownCID = mch_make_shutdown_chunk(mrecv_read_cummulative_tsn_acked());
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shutdownCID));
			mch_remove_simple_chunk(shutdownCID);
			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();

			// start shutdown timer
			smctrl->init_timer_interval = mpath_read_rto(mpath_read_primary_path());
			if (smctrl->init_timer_id != NULL)
				mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = mtra_timeouts_add(TIMER_TYPE_SHUTDOWN, smctrl->init_timer_interval, &msm_timer_expired,
				&smctrl->channel_id);
			smctrl->init_retrans_count = 0;

			// mrecv must acknoweledge every data chunk immediately after the shutdown was sent.
			curr_channel_->receive_control->sack_flag = 1;
			smctrl->channel_state = ChannelState::ShutdownSent;
		}
		else
		{
			// accepts no new data from its upper layer,
			// but retransmits data to the far end if necessary to fill gaps
			curr_channel_->flow_control->shutdown_received = true;
			curr_channel_->reliable_transfer_control->shutdown_received = true;
			// wait for msm_all_chunks_acked() from mreltx
			smctrl->channel_state = ChannelState::ShutdownPending;
		}
		break;
	case ChannelState::Closed:
	case ChannelState::CookieWait:
	case ChannelState::CookieEchoed:
		/* Siemens convention: ULP can not send datachunks until it has received the communication up. */
		EVENTLOG1(NOTICE, "event: msm_shutdown in state %02d --> aborting", smctrl->channel_state);
		msm_abort_channel(ECC_USER_INITIATED_ABORT);
		break;
	case ChannelState::ShutdownSent:
	case ChannelState::ShutdownReceived:
	case ChannelState::ShutdownPending:
	case ChannelState::ShutdownAckSent:
		/* ignore, keep on waiting for completion of the running shutdown */
		EVENTLOG1(NOTICE, "event: msm_shutdown in state %", smctrl->channel_state);
		break;
	default:
		ERRLOG(WARNNING_ERROR, "unexpected event: msm_shutdown");
		break;
	}
}

inline recv_controller_t* mdi_read_mrecv(void)
{
	return curr_channel_ == NULL ? NULL : curr_channel_->receive_control;
}
inline reltransfer_controller_t* mdi_read_mreltsf(void)
{
	return curr_channel_ == NULL ?
		NULL :
		curr_channel_->reliable_transfer_control;
}
inline deliverman_controller_t* mdi_read_mdlm(void)
{
	return curr_channel_ == NULL ? NULL : curr_channel_->deliverman_control;
}
inline path_controller_t* mdi_read_mpath()
{
	return curr_channel_ == NULL ? NULL : curr_channel_->path_control;
}
inline flow_controller_t* mdi_read_mfc(void)
{
	return curr_channel_ == NULL ? NULL : curr_channel_->flow_control;
}
inline smctrl_t* mdi_read_smctrl()
{
	return curr_channel_ == NULL ? NULL : curr_channel_->state_machine_control;
}
inline int mdi_read_rwnd()
{
	return (curr_geco_instance_ == NULL) ? -1 : curr_geco_instance_->default_myRwnd;
}
inline int mdi_read_default_delay(geco_instance_t* geco_instance)
{
	return (geco_instance == NULL) ? -1 : geco_instance->default_delay;
}
inline uint mdi_read_local_tag()
{
	return curr_channel_ == NULL ? 0 : curr_channel_->local_tag;
}
inline uint mdi_read_remote_tag()
{
	return curr_channel_ == NULL ? 0 : curr_channel_->remote_tag;
}
inline unsigned int mdi_read_supported_addr_types(void)
{
	return curr_geco_instance_ == NULL ? 0 : curr_geco_instance_->supportedAddressTypes;
}
int mdi_read_peer_addreslist(sockaddrunion peer_addreslist[MAX_NUM_ADDRESSES], uchar * chunk, uint len,
	uint my_supported_addr_types, uint* peer_supported_addr_types, bool ignore_dups, bool ignore_last_src_addr)
{
	EVENTLOG(DEBUG, "- - - Enter mdi_read_peer_addreslist()");
	assert(chunk != NULL && peer_addreslist != NULL && len > 0);

	/*1) validate method input geco_instance_params*/
	uint read_len;
	int found_addr_number;
	found_addr_number = 0;

	/*2) validate chunk id inside this chunk*/
	simple_chunk_t* init_chunk = (simple_chunk_t*)chunk;
	if (init_chunk->chunk_header.chunk_id == CHUNK_INIT || init_chunk->chunk_header.chunk_id == CHUNK_INIT_ACK)
	{
		read_len = INIT_CHUNK_FIXED_SIZES;
	}
	else if (init_chunk->chunk_header.chunk_id == CHUNK_COOKIE_ECHO)
	{
		read_len = CHUNK_FIXED_SIZE + COOKIE_FIXED_SIZE;
	}
	else
	{
		found_addr_number = -1;
		EVENTLOG(DEBUG, "- - - Leave mdi_read_peer_addreslist()");
		return found_addr_number;
	}

	uchar* curr_pos;
	curr_pos = chunk + read_len;

	uint vlp_len;
	vlparam_fixed_t* vlp;
	ipaddr_vlp_t* addres;
	bool is_new_addr;
	int idx;
	IPAddrType flags;

	/*3) parse all vlparams in this chunk*/
	while (read_len < len)
	{
		if (len - read_len < VLPARAM_FIXED_SIZE)
		{
			EVENTLOG(WARNNING_ERROR, "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !");
			found_addr_number = -1;
			EVENTLOG(DEBUG, "- - - Leave mdi_read_peer_addreslist()");
			return found_addr_number;
		}

		vlp = (vlparam_fixed_t*)curr_pos;
		vlp_len = ntohs(vlp->param_length);
		// vlp length too short or patial vlp problem
		if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len)
		{
			found_addr_number = -1;
			EVENTLOG(DEBUG, "- - - Leave mdi_read_peer_addreslist()");
			return found_addr_number;
		}

		ushort paratype = ntohs(vlp->param_type);
		/* determine the falgs from last source addr
		 * then this falg will be used to validate other found addres*/
		if (paratype == VLPARAM_IPV4_ADDRESS || paratype == VLPARAM_IPV6_ADDRESS)
		{
			bool b1 = false, b2 = false, b3 = false;
			if (!(b1 = mdi_contains_localhost(last_source_addr_, 1)))
			{
				/* this is from a normal address,
				 * furtherly filter out except loopbacks */
				if ((b2 = typeofaddr(last_source_addr_, LinkLocalAddrType)))  //
				{
					flags = (IPAddrType)(AllCastAddrTypes | LoopBackAddrType);
					EVENTLOG(DEBUG,
						"last_source_addr_ from LinkLocalAddrType use default flag AllCastAddrTypes | LoopBackAddrType");
				}
				else if ((b3 = typeofaddr(last_source_addr_, SiteLocalAddrType))) // filtered
				{
					flags = (IPAddrType)(AllCastAddrTypes | LoopBackAddrType | LinkLocalAddrType);
					EVENTLOG(DEBUG,
						"last_source_addr_ from SiteLocalAddrType use default flag AllCastAddrTypes | LoopBackAddrType | LinkLocalAddrType");
				}
				else
				{
					flags = (IPAddrType)(AllCastAddrTypes | AllLocalAddrTypes);
					EVENTLOG(DEBUG,
						"last_source_addr_ from normal address use default flag AllCastAddrTypes | AllLocalAddrTypes");
				}
			}
			else
			{
				/* this is from a loopback, use default flag*/
				flags = AllCastAddrTypes;
				EVENTLOG(DEBUG, "last_source_addr_ is from a loopback, use default flag AllCastAddrTypes");
			}
		}

		/*4) validate received addresses in this chunk*/
		switch (paratype)
		{
		case VLPARAM_IPV4_ADDRESS:
			if ((my_supported_addr_types & SUPPORT_ADDRESS_TYPE_IPV4))
			{ // use peer addrlist that we can support, ignoring unsupported addres
			  // validate if exceed max num addres allowed
				if (found_addr_number < MAX_NUM_ADDRESSES)
				{
					addres = (ipaddr_vlp_t*)curr_pos;
					// validate vlp type and length
					if (IS_IPV4_ADDRESS_PTR_NBO(addres))
					{
						uint ip4_saddr = ntohl(addres->dest_addr_un.ipv4_addr);
						// validate addr itself
						if (!IN_CLASSD(ip4_saddr) && !IN_EXPERIMENTAL(ip4_saddr) && !IN_BADCLASS(ip4_saddr)
							&& INADDR_ANY != ip4_saddr && INADDR_BROADCAST != ip4_saddr)
						{
							peer_addreslist[found_addr_number].sa.sa_family =
								AF_INET;
							peer_addreslist[found_addr_number].sin.sin_port = htons(last_src_port_);
							peer_addreslist[found_addr_number].sin.sin_addr.s_addr = addres->dest_addr_un.ipv4_addr;

							if (!typeofaddr(&peer_addreslist[found_addr_number], flags)) // NOT contains the addr type of [flags]
							{
								//current addr duplicated with a previous found addr?
								is_new_addr = true;  // default as new addr
								if (ignore_dups)
								{
									for (idx = 0; idx < found_addr_number; idx++)
									{
										if (saddr_equals(&peer_addreslist[found_addr_number], &peer_addreslist[idx], true))
										{
											is_new_addr = false;
										}
									}
								}

								if (is_new_addr)
								{
									found_addr_number++;
									if (peer_supported_addr_types != NULL)
										(*peer_supported_addr_types) |=
										SUPPORT_ADDRESS_TYPE_IPV4;
#ifdef _DEBUG
									saddr2str(&peer_addreslist[found_addr_number - 1], hoststr_, sizeof(hoststr_), 0);
									EVENTLOG1(VERBOSE, "Found NEW IPv4 Address = %s", hoststr_);
#endif
								}
								else
								{
									EVENTLOG(DEBUG, "IPv4 was in the INIT or INIT ACK chunk more than once");
								}
							}
						}
					}
					else  // IS_IPV4_ADDRESS_PTR_HBO(addres) == false
					{
						EVENTLOG(DEBUG, "ip4 vlp has problem, stop read addresses");
						break;
					}
				}
			}
			break;
		case VLPARAM_IPV6_ADDRESS:
			if ((my_supported_addr_types & SUPPORT_ADDRESS_TYPE_IPV6))
			{ // use peer addrlist that we can support, ignoring unsupported addres
			  /*6) pass by other validates*/
				if (found_addr_number < MAX_NUM_ADDRESSES)
				{
					addres = (ipaddr_vlp_t*)curr_pos;
					if (IS_IPV6_ADDRESS_PTR_NBO(addres))
					{
#ifdef WIN32
						if (!IN6_IS_ADDR_UNSPECIFIED(
							&addres->dest_addr_un.ipv6_addr) && !IN6_IS_ADDR_MULTICAST(&addres->dest_addr_un.ipv6_addr)
							&& !IN6_IS_ADDR_V4COMPAT(&addres->dest_addr_un.ipv6_addr))
#else
						if (!IN6_IS_ADDR_UNSPECIFIED(
							addres->dest_addr_un.ipv6_addr.s6_addr) && !IN6_IS_ADDR_MULTICAST(addres->dest_addr_un.ipv6_addr.s6_addr)
							&& !IN6_IS_ADDR_V4COMPAT(addres->dest_addr_un.ipv6_addr.s6_addr))
#endif
						{

							// fillup addrr
							peer_addreslist[found_addr_number].sa.sa_family =
								AF_INET6;
							peer_addreslist[found_addr_number].sin6.sin6_port = htons(last_src_port_);
							peer_addreslist[found_addr_number].sin6.sin6_flowinfo = 0;
							peer_addreslist[found_addr_number].sin6.sin6_scope_id = 0;
							memcpy_fast(peer_addreslist[found_addr_number].sin6.sin6_addr.s6_addr,
								addres->dest_addr_un.ipv6_addr.s6_addr, sizeof(struct in6_addr));
							if (!typeofaddr(&peer_addreslist[found_addr_number], flags)) // NOT contains the addr type of [flags]
							{
								// current addr duplicated with a previous found addr?
								is_new_addr = true;  // default as new addr
								if (ignore_dups)
								{
									for (idx = 0; idx < found_addr_number; idx++)
									{
										if (saddr_equals(&peer_addreslist[found_addr_number], &peer_addreslist[idx], true))
										{
											is_new_addr = false;
										}
									}
								}

								if (is_new_addr)
								{
									found_addr_number++;
									if (peer_supported_addr_types != NULL)
										(*peer_supported_addr_types) |=
										SUPPORT_ADDRESS_TYPE_IPV6;
#ifdef _DEBUG
									saddr2str(&peer_addreslist[found_addr_number - 1], hoststr_, sizeof(hoststr_), 0);
									EVENTLOG1(VERBOSE, "Found NEW IPv6 Address = %s", hoststr_);
#endif
								}
								else
								{
									EVENTLOG(DEBUG, "IPv6 was in the INIT or INIT ACK chunk more than once");
								}
							}
						}
					}
				}
				else
				{
					EVENTLOG(DEBUG, "Too many addresses found during IPv4 reading");
				}
			}
			break;
		case VLPARAM_SUPPORTED_ADDR_TYPES:
			if (peer_supported_addr_types != NULL)
			{
				supported_addr_types_vlp_t* sat = (supported_addr_types_vlp_t*)curr_pos;
				int size = ((vlp_len - VLPARAM_FIXED_SIZE) / sizeof(ushort)) - 1;
				while (size >= 0)
				{
					*peer_supported_addr_types |=
						ntohs(sat->address_type[size]) == VLPARAM_IPV4_ADDRESS ?
						SUPPORT_ADDRESS_TYPE_IPV4 :
						SUPPORT_ADDRESS_TYPE_IPV6;
					size--;
				}
				EVENTLOG1(DEBUG, "Found VLPARAM_SUPPORTED_ADDR_TYPES, update peer_supported_addr_types now it is (%d)",
					*peer_supported_addr_types);
			}
			break;
		}
		read_len += vlp_len;
		while (read_len & 3)
			++read_len;
		curr_pos = chunk + read_len;
	}  // while

	// we do not to validate last_source_assr here as we have done that in recv_geco_pacjet()
	if (!ignore_last_src_addr)
	{
		is_new_addr = true;
		for (idx = 0; idx < found_addr_number; idx++)
		{
			if (saddr_equals(last_source_addr_, &peer_addreslist[idx], true))
			{
				is_new_addr = false;
			}
		}

		if (is_new_addr)
		{
			// always add last_source_addr as it is from received packet
			// which means the path is active on that address
			// if exceed MAX_NUM_ADDRESSES, we rewrite the last addr by last_source_addr
			if (found_addr_number >= MAX_NUM_ADDRESSES)
			{
				found_addr_number = MAX_NUM_ADDRESSES - 1;

			}
			if (peer_supported_addr_types != NULL)
			{
				switch (saddr_family(last_source_addr_))
				{
				case AF_INET:
					(*peer_supported_addr_types) |=
						SUPPORT_ADDRESS_TYPE_IPV4;
					break;
				case AF_INET6:
					(*peer_supported_addr_types) |=
						SUPPORT_ADDRESS_TYPE_IPV6;
					break;
				default:
					ERRLOG(FALTAL_ERROR_EXIT, "no such addr family!");
					break;
				}
			}
			if ((last_source_addr_->sa.sa_family == AF_INET ?
				SUPPORT_ADDRESS_TYPE_IPV4 :
				SUPPORT_ADDRESS_TYPE_IPV6) & my_supported_addr_types)
			{
				//memcpy(&peer_addreslist[found_addr_number], last_source_addr_, sizeof(sockaddrunion));
				memcpy_fast(&peer_addreslist[found_addr_number], last_source_addr_, sizeof(sockaddrunion));
				found_addr_number++;
#ifdef _DEBUG
				saddr2str(last_source_addr_, hoststr_, sizeof(hoststr_), 0);
#endif
				EVENTLOG3(VERBOSE, "Added also last_source_addr_ (%s )to the addresslist at index %u,found_addr_number = %u!",
					hoststr_, found_addr_number, found_addr_number + 1);
			}
		}
	}

	EVENTLOG(DEBUG, "- - - Leave mdi_read_peer_addreslist()");
	return found_addr_number;
}
inline uint mdi_generate_itag(void)
{
	uint tag;
	do
	{
		tag = generate_random_uint32();
	} while (tag == 0);
	return tag;
}

bool mdi_contains_localhost(sockaddrunion * addr_list, uint addr_list_num)
{
	bool ret = false;
	uint ii;
	uint idx;
	for (ii = 0; ii < addr_list_num; ii++)
	{
		/*1) check loopback addr first*/
		switch (saddr_family(addr_list + ii))
		{
		case AF_INET:
			if (ntohl(s4addr(&(addr_list[ii]))) == INADDR_LOOPBACK)
			{
				EVENTLOG1(VERBOSE, "contains_local_host_addr():Found IPv4 loopback address ! Num: %u", addr_list_num);
				ret = true;
			}
			break;
		case AF_INET6:
#ifdef __linux__
			if (IN6_IS_ADDR_LOOPBACK(s6addr(&(addr_list[ii]))))
			{
#else
			if (IN6_IS_ADDR_LOOPBACK(&sin6addr(&(addr_list[ii]))))
			{
#endif
				EVENTLOG1(VERBOSE, "contains_local_host_addr():Found IPv6 loopback address ! Num: %u", addr_list_num);
				ret = true;
			}
			break;
		default:
			ERRLOG(MAJOR_ERROR, "contains_local_host_addr():no such addr family!");
			ret = false;
		}
	}
	/*2) otherwise try to find from local addr list stored in curr geco instance*/
	if (curr_geco_instance_ != NULL)
	{
		if (curr_geco_instance_->local_addres_size > 0)
		{
			for (idx = 0; idx < curr_geco_instance_->local_addres_size; ++idx)
			{
				for (ii = 0; ii < addr_list_num; ++ii)
				{
					if (saddr_equals(addr_list + ii, curr_geco_instance_->local_addres_list + idx))
					{
						ret = true;
						EVENTLOG(VERBOSE, "contains_local_host_addr():Found same address from curr_geco_instance_");
					}
				}
			}
		}
		else
		{ /*3 otherwise try to find from global local host addres list if geco instace local_addres_size is 0*/
			for (idx = 0; idx < defaultlocaladdrlistsize_; idx++)
			{
				for (ii = 0; ii < addr_list_num; ++ii)
				{
					if (saddr_equals(addr_list + ii, defaultlocaladdrlist_ + idx))
					{
						ret = true;
						EVENTLOG(VERBOSE, "contains_local_host_addr():Found same address from defaultlocaladdrlist_");
					}
				}
			}
		}
	}
	/*4 find from global local host addres list if geco instance NULL*/
	else
	{
		for (idx = 0; idx < defaultlocaladdrlistsize_; idx++)
		{
			for (ii = 0; ii < addr_list_num; ++ii)
			{
				if (saddr_equals(addr_list + ii, defaultlocaladdrlist_ + idx))
				{
					ret = true;
					EVENTLOG(VERBOSE, "contains_local_host_addr():Found same address from defaultlocaladdrlist_");
				}
			}
		}
	}
	return ret;
}
int mdi_validate_localaddrs_before_write_to_init(sockaddrunion* local_addrlist, sockaddrunion *peerAddress,
	uint numPeerAddresses, uint supported_types, bool receivedFromPeer)
{
	/*1) make sure either curr channel or curr geco instance presents */
	if (curr_channel_ == NULL && curr_geco_instance_ == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT,
			"dispatch_layer_t::mdi_validate_localaddrs_before_write_to_init()::neither assoc nor instance set - error !");
		return -1;
	}

	if (curr_geco_instance_ == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT,
			"mdi_validate_localaddrs_before_write_to_init():: curr_geco_instance_ not set - program error");
		return -1;
	}

	/* 2) Determine address type of peer addres
	 * localHostFound == false:
	 * localhost not found means we are NOT sending msg to ourselves
	 * this is from a normal address, so we need filter out except loopback and cast addres
	 * localHostFound == true:
	 * localhost Found means we are sending msg to ourselves
	 * peer addr is actually our local address, so we need filter out
	 * all illegal addres */
	uint count, tmp;
	IPAddrType filterFlags = (IPAddrType)0;
	bool localHostFound = false, linkLocalFound = false, siteLocalFound = false;
	for (count = 0; count < numPeerAddresses; count++)
	{
		localHostFound = mdi_contains_localhost(peerAddress + count, 1);
		linkLocalFound = ::typeofaddr(peerAddress + count, LinkLocalAddrType);
		siteLocalFound = ::typeofaddr(peerAddress + count, SiteLocalAddrType);
	}

	/* 3) Should we add @param peerAddress to @param local_addrlist ?
	 * receivedFromPeer == false: I send an INIT with my addresses to the peer
	 * receivedFromPeer == true: I got an INIT with addresses from the peer */
	if (receivedFromPeer == false && localHostFound == true)
	{
		/* 3.1) this means:
		 * dest allist has my local addr and I am sending an INIT  to myself.
		 * so should add my loopback addr into init chunk
		 * need filter out all illgal-formate addres
		 */
		filterFlags = AllCastAddrTypes;
#ifdef _DEBUG
		EVENTLOG(DEBUG,
			"mdi_validate_localaddrs_before_write_to_init():: 3.1) I sent an INIT with my addresses to myself ->  filterFlags = AllCastAddrTypes;");
#endif
	}
	else if (receivedFromPeer == false && localHostFound == false)
	{
		/* 3.2) this means:
		 * I sent an INIT  to peer hosts other than myself
		 * so should filter out all my loopback addres
		 *(only refers to addres that can be used as dest addr from peer end( like lan ip 192.168.1.168 or wan ip 220.123.22.21)
		 * 127.0.0.1 and ::1 cannot be put into init chunk because metwork routing must use visiable addr like  lan ip 192.168.1.168 or wan ip 220.123.22.21
		 */
		filterFlags = (IPAddrType)(AllCastAddrTypes | LoopBackAddrType);
#ifdef _DEBUG
		EVENTLOG(DEBUG,
			"mdi_validate_localaddrs_before_write_to_init()::  3.2) I sent an INIT with my addresses to peer hosts other than myself - >  filterFlags = (IPAddrType) ( AllCastAddrTypes | LoopBackAddrType )");
#endif
	}
	else if (receivedFromPeer == true && localHostFound == false)
	{
		/* 3.3) this means:
		 * I received an INIT with addresses from others which is a normal case.
		 * should filter out all illegal-formate addres and loopback addres from my  local addr list
		 * and only use the rest ones (only refers to addres like lan ip 192.168.1.168 or wan ip 220.123.22.21) that can found in the network */
		if (linkLocalFound)
		{
			filterFlags = (IPAddrType)(AllCastAddrTypes | LoopBackAddrType);
		}
		else if (siteLocalFound)
		{
			filterFlags = (IPAddrType)(AllCastAddrTypes | LinkLocalAddrType | LoopBackAddrType);
		}
		else
		{
			filterFlags = (IPAddrType)(AllCastAddrTypes | AllLocalAddrTypes);
		}
#ifdef _DEBUG
		EVENTLOG(DEBUG,
			"mdi_validate_localaddrs_before_write_to_init():: 3.3) I received an INIT with addresses from others which is a normal case. -> unknwn");
#endif
	}
	else  // (receivedFromPeer == true && localHostFound == true)
	{
		/* 3.4) this means:
		 * I received an INIT with addresses from myself
		 * should filter out all  illegal-formate addres from geco instance's local addr list
		 * and use the rest ones. It is ok if the rest addres include my loopback addr
		 * as i am sending init ack to myself i should use all my local addres */
		filterFlags = AllCastAddrTypes;
#ifdef _DEBUG
		EVENTLOG(DEBUG,
			"mdi_validate_localaddrs_before_write_to_init():: 3.4) I received an INIT with addresses from myself -> filterFlags = AllCastAddrTypes");
#endif
	}
#ifdef _DEBUG
	uint ip4count = 0;
#endif
	count = 0;
	bool anyaddr = false;
	/* 4.1) if geco instance has any addr 4 setup, we use default local addr list_*/
	if (curr_geco_instance_->is_inaddr_any)
	{
		anyaddr = true;
		for (tmp = 0; tmp < defaultlocaladdrlistsize_; tmp++)
		{
			if (saddr_family(&(defaultlocaladdrlist_[tmp])) == AF_INET)
			{
				if (supported_types & SUPPORT_ADDRESS_TYPE_IPV4)
				{
					// filter out unwanted local addres and copy the rest ones
					if (!::typeofaddr(&(defaultlocaladdrlist_[tmp]), filterFlags))
					{
						// addr looks good, copy it
						//memcpy(&(local_addrlist[count]), &(defaultlocaladdrlist_[tmp]), sizeof(sockaddrunion));
						memcpy_fast(&(local_addrlist[count]), &(defaultlocaladdrlist_[tmp]), sizeof(sockaddrunion));
						count++;
					}
				}
			}
		}
#ifdef _DEBUG
		ip4count = count;
		EVENTLOG2(DEBUG,
			"mdi_validate_localaddrs_before_write_to_init(): picked up and copied %u local ip4 addresses from INADDR_ANY (defaultlocaladdrlistsize_ %u)",
			ip4count, defaultlocaladdrlistsize_);
#endif
	}

	/* 4.2) if geco instance has any addr 6 setup, we use @param defaultlocaladdrlist_*/
	if (curr_geco_instance_->is_in6addr_any)
	{
		anyaddr = true;
		for (tmp = 0; tmp < defaultlocaladdrlistsize_; tmp++)
		{
			if (saddr_family(&(defaultlocaladdrlist_[tmp])) == AF_INET6)
			{
				if (supported_types & SUPPORT_ADDRESS_TYPE_IPV6)
				{
					// filter out unwanted local addres and copy the rest ones
					if (!::typeofaddr(&(defaultlocaladdrlist_[tmp]), filterFlags))
					{
						// addr looks good copy it
						//memcpy(&(local_addrlist[count]), &(defaultlocaladdrlist_[tmp]), sizeof(sockaddrunion));
						memcpy_fast(&(local_addrlist[count]), &(defaultlocaladdrlist_[tmp]), sizeof(sockaddrunion));
						count++;
					}
				}
			}
		}
#ifdef _DEBUG
		EVENTLOG2(DEBUG,
			"mdi_validate_localaddrs_before_write_to_init(): picked up and copied %u local ip6 addresses from INADDR6_ANY (defaultlocaladdrlistsize_ %u)",
			count - ip4count, defaultlocaladdrlistsize_);
#endif
	}

	if (anyaddr == false)
	{
		/* 4.3) geco instance has NO any addr (6) setup,
		 * search from local addr list of geco instance*/
		for (tmp = 0; tmp < curr_geco_instance_->local_addres_size; tmp++)
		{
			ushort af = saddr_family(&(curr_geco_instance_->local_addres_list[tmp]));
			if (af == AF_INET)
			{
				if (supported_types & SUPPORT_ADDRESS_TYPE_IPV4)
				{
					if (!typeofaddr(&(curr_geco_instance_->local_addres_list[tmp]), filterFlags))
					{
						// addr looks good copy it
						//memcpy(&(local_addrlist[count]), &(curr_geco_instance_->local_addres_list[tmp]), sizeof(sockaddrunion));
						memcpy_fast(&(local_addrlist[count]), &(curr_geco_instance_->local_addres_list[tmp]),
							sizeof(sockaddrunion));
						count++;
					}
				}
			}
			else if (af == AF_INET6)
			{
				if (supported_types & SUPPORT_ADDRESS_TYPE_IPV6)
				{
					if (!typeofaddr(&(curr_geco_instance_->local_addres_list[tmp]), filterFlags))
					{
						// addr looks good copy it
						//memcpy(&(local_addrlist[count]), &(curr_geco_instance_->local_addres_list[tmp]), sizeof(sockaddrunion));
						memcpy_fast(&(local_addrlist[count]), &(curr_geco_instance_->local_addres_list[tmp]),
							sizeof(sockaddrunion));
						count++;
					}
				}
			}
			else
			{
				ERRLOG(FALTAL_ERROR_EXIT, "mdi_validate_localaddrs_before_write_to_init(): no such af !");
			}
		}
#ifdef _DEBUG
		EVENTLOG2(DEBUG,
			"mdi_validate_localaddrs_before_write_to_init(): found %u local addresses from inst local addr list (from %u)",
			count, curr_geco_instance_->local_addres_size);
#endif
	}

	if (count == 0)
		ERRLOG(FALTAL_ERROR_EXIT, "mdi_validate_localaddrs_before_write_to_init(): found no addres!");

	return count;
}
int mdi_send_geco_packet(char* geco_packet, uint length, short destAddressIndex, uint geco_packet_fixed_size)
{
#ifdef _DEBUG
	EVENTLOG(VERBOSE, "- - - - Enter mdi_send_geco_packet()");
#endif

#if enable_mock_dispatch_send_geco_packet
	EVENTLOG(DEBUG, "Mock::dispatch_layer_t::mdi_send_geco_packet() is called");
	return 0;
#endif

	assert(geco_packet != NULL);
	assert(length != 0);

	int len = 0;
	geco_packet_t* geco_packet_ptr = (geco_packet_t*)geco_packet;
	simple_chunk_t* chunk = ((simple_chunk_t*)(geco_packet_ptr->chunk - GECO_PACKET_FIXED_SIZE + geco_packet_fixed_size));

	/*1)when sending OOB chunk without channel found, we use last_source_addr_
	 * carried in OOB packet as the sending dest addr see recv_geco_packet() for details*/
	sockaddrunion* dest_addr_ptr;
	uchar tos;
	int primary_path;

	if (curr_channel_ == NULL)
	{  // no need to test path activeness
		assert(last_source_addr_ != NULL);
		assert(last_init_tag_ != 0);
		assert(last_dest_port_ != 0);
		assert(last_src_port_ != 0);

		//memcpy(&dest_addr, last_source_addr_, sizeof(sockaddrunion));
		dest_addr_ptr = last_source_addr_;
		geco_packet_ptr->pk_comm_hdr.verification_tag = htonl(last_init_tag_ != 0 ? last_init_tag_ : last_veri_tag_);
		last_init_tag_ = 0;  //reset it

		// swap port number
		if (!mdi_udp_tunneled_)
		{
			geco_packet_ptr->pk_comm_hdr.src_port = htons(last_dest_port_);
			geco_packet_ptr->pk_comm_hdr.dest_port = htons(last_src_port_);
			gset_checksum(geco_packet, length);	// calc checksum and insert it MD5
		}
		curr_geco_instance_ == NULL ? tos = (uchar)IPTOS_DEFAULT : tos = curr_geco_instance_->default_ipTos;
		EVENTLOG4(VERBOSE,
			"mdi_send_geco_packet() : currchannel is null, use last src addr as dest addr, tos = %u, tag = %x, src_port = %u , dest_port = %u",
			tos, last_init_tag_, last_dest_port_, last_src_port_);
	}
	else  // curr_channel_ != NULL
	{
		ChannelState channelstate;
		//2) normal send with channel found
		if (destAddressIndex < -1 || destAddressIndex >= (int)curr_channel_->remote_addres_size)
		{
			EVENTLOG1(NOTICE, "dispatch_layer::mdi_send_geco_packet(): invalid destAddressIndex (%d)!!!", destAddressIndex);
			len = -1;
			goto leave;
		}
		//3) Use given destination address from current association
		if (destAddressIndex != -1)
		{  // 0<=destAddressIndex<remote_addres_size
			channelstate = curr_channel_->state_machine_control->channel_state;
			if ((channelstate == CookieEchoed || channelstate == Connected)
				&& curr_channel_->path_control->path_params[destAddressIndex].state == PM_INACTIVE)
			{ // when CookieEchoed || Connected, connection pharse is finished followed which we will send either ctrl or data chunks. at this moment, primary must be available for transfer
				destAddressIndex = curr_channel_->path_control->primary_path; //primary path is always active
			}
			dest_addr_ptr = curr_channel_->remote_addres + destAddressIndex;
		}
		else
		{
			dest_addr_ptr = last_source_addr_;
			if (last_source_addr_ == NULL)
			{
				//5) last src addr is NUll, we use primary path
				primary_path = curr_channel_->path_control->primary_path; //primary path is always active
				dest_addr_ptr = curr_channel_->remote_addres + primary_path;
				EVENTLOG2(VERBOSE,
					"dispatch_layer::mdi_send_geco_packet()::last_source_addr_ is NULL ---> use to primary with index %u (with %u paths)",
					primary_path, curr_channel_->remote_addres_size);
				assert(curr_channel_->path_control->path_params[primary_path].state == PM_ACTIVE);
			}
			else
			{
				//6) use last src addr
				EVENTLOG(VERBOSE, "dispatch_layer::mdi_send_geco_packet(): : use last_source_addr_");
				channelstate = curr_channel_->state_machine_control->channel_state;
				if (!path_map.empty())
				{
					// path map is filled in mdi_on_peer_connected() and so we know that
					// connection pharse is finished followed which we will send either ctrl or data chunks and primary must be active
					const short& pid = path_map[*last_source_addr_];
					if (curr_channel_->path_control->path_params[pid].state != PM_ACTIVE)
					{
						primary_path = curr_channel_->path_control->primary_path;					//primary path is always active
						dest_addr_ptr = curr_channel_->remote_addres + primary_path;
						EVENTLOG2(VERBOSE,
							"dispatch_layer::mdi_send_geco_packet()::but last_source_addr_ inactive ---> use primary with index %u (with %u paths)",
							primary_path, curr_channel_->remote_addres_size);
						assert(curr_channel_->path_control->path_params[primary_path].state == PM_ACTIVE);
					}
				}
			}
		}

		/*7) for INIT received when channel presents,
		 * we need send INIT-ACK with init tag from INIT of peer*/
		if (is_init_ack_chunk(chunk))
		{
			assert(last_init_tag_ != 0);
			geco_packet_ptr->pk_comm_hdr.verification_tag = htonl(last_init_tag_);
		}
		else
			/*8) use normal tag stored in curr channel*/
			geco_packet_ptr->pk_comm_hdr.verification_tag = htonl(curr_channel_->remote_tag);

		tos = curr_channel_->ipTos;
		assert(curr_channel_->bundle_control->geco_packet_fixed_size != 0);
		if (!mdi_udp_tunneled_ && !mdi_connect_udp_sfd_)
		{
			geco_packet_ptr->pk_comm_hdr.src_port = htons(curr_channel_->local_port);
			geco_packet_ptr->pk_comm_hdr.dest_port = htons(curr_channel_->remote_port);
			gset_checksum(geco_packet, length);	// calc checksum and insert it MD5
		}
		EVENTLOG4(VERBOSE, "dispatch_layer_t::mdi_send_geco_packet() : tos = %u, tag = %x, src_port = %u , dest_port = %u",
			tos, curr_channel_->remote_tag, curr_channel_->local_port, curr_channel_->remote_port);
	}  // curr_channel_ != NULL

	mdi_send_sfd_ = (
		mdi_udp_tunneled_ || mdi_connect_udp_sfd_ ?
		(dest_addr_ptr->sa.sa_family == AF_INET ? mtra_read_ip4udpsock() : mtra_read_ip6udpsock()) :
		(dest_addr_ptr->sa.sa_family == AF_INET ? mtra_read_ip4rawsock() : mtra_read_ip6rawsock()));
	len = mtra_send(mdi_send_sfd_, geco_packet, length, dest_addr_ptr, tos);

#ifdef _DEBUG
	ushort port;
	saddr2str(dest_addr_ptr, hoststr_, MAX_IPADDR_STR_LEN, &port);
	EVENTLOG4(DEBUG, "mdi_send_geco_packet()::sent geco packet of %d bytes to %s:%u, sent bytes %d", length, hoststr_,
		port, len);
#endif

leave:
#ifdef _DEBUG
	EVENTLOG1(VERBOSE, "- - - - Leave mdi_send_geco_packet(ret = %d)", len);
#endif

	return (len == (int)length) ? 0 : -1;
}
void mdi_on_path_status_changed(short destaddr_id, int newState)
{
	assert(curr_channel_ != NULL);
	EVENTLOG3(INFO, "mdi_networkStatusChangeNotif(assoc %u, path-id %d, state %s)", curr_channel_->channel_id,
		destaddr_id, newState == PM_ACTIVE ? "PM_ACTIVE" : "PM_INACTIVE");
	if (curr_geco_instance_->ulp_callbacks.networkStatusChangeNotif != NULL)
	{
		curr_geco_instance_->ulp_callbacks.networkStatusChangeNotif(curr_channel_->channel_id, destaddr_id, newState,
			curr_channel_->ulp_dataptr);
	}
}
int mdi_send_bundled_chunks(int* ad_idx)
{
#ifdef _DEBUG
	if (ad_idx == NULL)
		EVENTLOG(VERBOSE, "- -  - Enter send_bundled_chunks (ad_idx=Null)");
	else
		EVENTLOG1(VERBOSE, "- -  - Enter send_bundled_chunks (ad_idx=%d)", *ad_idx);
#endif

	int ret = 0;
	bundle_controller_t* bundle_ctrl = (bundle_controller_t*)mdi_read_mbu(curr_channel_);

	// no channel exists, so we take the global bundling buffer
	if (bundle_ctrl == NULL)
	{
		EVENTLOG(VERBOSE, "use global bundling buffer");
		bundle_ctrl = default_bundle_ctrl_;
	}

	if (bundle_ctrl->locked)
	{
		bundle_ctrl->got_send_request = true;
		if (ad_idx != NULL)
		{
			bundle_ctrl->got_send_address = true;
			bundle_ctrl->requested_destination = *ad_idx;
		}
		EVENTLOG(VERBOSE, "sender is LOCKED ---> return");
		ret = 1;
		goto leave;
	}

	/* determine  path_param_id to use as dest addr
	 * should take into account  eg. check path inactive or active */
	int path_param_id;
	if (ad_idx != NULL)
	{
		if (*ad_idx > 0xFFFF)
		{
			ERRLOG(FALTAL_ERROR_EXIT, "address_index too big !");
			ret = -1;
			goto leave;
		}
		else
		{
			path_param_id = *ad_idx;
		}
	}
	else
	{
		if (bundle_ctrl->got_send_address)
		{
			path_param_id = bundle_ctrl->requested_destination;
		}
		else
		{
			path_param_id = -1;  // use last src path OR primary path
		}
	}

	EVENTLOG1(VERBOSE, "send to path %d ", path_param_id);

	/* try to bundle ctrl or/and sack chunks with data chunks in an packet*/
	char* send_buffer;
	int send_len;
	if (bundle_ctrl->sack_in_buffer)
	{
		mrecv_stop_sack_timer();
		/* send sacks, by default they go to the last active address,from which data arrived */
		send_buffer = bundle_ctrl->sack_buf;

		/*
		 * at least sizeof(geco_packet_fixed_t)
		 * at most pointing to the end of SACK chunk */
		send_len = bundle_ctrl->sack_position;
		EVENTLOG1(VERBOSE, "send_bundled_chunks(sack) : send_len == %d ", send_len);

		if (bundle_ctrl->ctrl_chunk_in_buffer)
		{
			ret = bundle_ctrl->ctrl_position - bundle_ctrl->geco_packet_fixed_size;
			memcpy_fast(&(send_buffer[send_len]), &(bundle_ctrl->ctrl_buf[bundle_ctrl->geco_packet_fixed_size]), ret);
			send_len += ret;
			EVENTLOG1(VERBOSE, "send_bundled_chunks(sack+ctrl) : send_len == %d ", send_len);
		}
		if (bundle_ctrl->data_in_buffer)
		{
			ret = bundle_ctrl->data_position - bundle_ctrl->geco_packet_fixed_size;
			memcpy_fast(&(send_buffer[send_len]), &(bundle_ctrl->data_buf[bundle_ctrl->geco_packet_fixed_size]), ret);
			send_len += ret;
			EVENTLOG1(VERBOSE,
				ret == 0 ?
				"send_bundled_chunks(sack+data) : send_len == %d " :
				"send_bundled_chunks(sack+ctrl+data) : send_len == %d ", send_len);
		}
	}
	else if (bundle_ctrl->ctrl_chunk_in_buffer)
	{
		send_buffer = bundle_ctrl->ctrl_buf;
		send_len = bundle_ctrl->ctrl_position;
		EVENTLOG1(VERBOSE, "send_bundled_chunks(ctrl) : send_len == %d ", send_len);
		if (bundle_ctrl->data_in_buffer)
		{
			ret = bundle_ctrl->data_position - bundle_ctrl->geco_packet_fixed_size;
			//memcpy(&send_buffer[send_len], &(bundle_ctrl->data_buf[GECO_PACKET_FIXED_SIZE]), ret);
			memcpy_fast(&send_buffer[send_len], &(bundle_ctrl->data_buf[bundle_ctrl->geco_packet_fixed_size]), ret);
			send_len += ret;
			EVENTLOG1(VERBOSE, "send_bundled_chunks(ctrl+data) : send_len == %d ", send_len);
		}
	}
	else if (bundle_ctrl->data_in_buffer)
	{
		send_buffer = bundle_ctrl->data_buf;
		send_len = bundle_ctrl->data_position;
		EVENTLOG1(VERBOSE, "send_bundled_chunks(data) : send_len == %d ", send_len);
	}
	else
	{
		EVENTLOG(VERBOSE, "Nothing to send");
		ret = 1;
		goto leave;
	}
	EVENTLOG1(VERBOSE, "send_len == %d ", send_len);

	// this should not happen as bundle_xxx_chunk() internally detectsif exceeds MAX_GECO_PACKET_SIZE, if so, it will call
	if (send_len > MAX_GECO_PACKET_SIZE)
	{
		EVENTLOG5(FALTAL_ERROR_EXIT,
			"send len (%u)  exceeded (%u) - aborting\nsack_position: %u, ctrl_position: %u, data_position: %u", send_len,
			MAX_GECO_PACKET_SIZE, bundle_ctrl->sack_position, bundle_ctrl->ctrl_position, bundle_ctrl->data_position);
		ret = -1;
		goto leave;
	}

	if (bundle_ctrl->data_in_buffer && path_param_id > -1)
		mpath_data_chunk_sent(path_param_id);

	EVENTLOG2(VERBOSE, "sending message len==%u to adress idx=%d", send_len, path_param_id);

	// send_len = geco hdr + chunks
	ret = mdi_send_geco_packet(send_buffer, send_len, path_param_id, bundle_ctrl->geco_packet_fixed_size);

	// reset all positions
	bundle_ctrl->sack_in_buffer = bundle_ctrl->ctrl_chunk_in_buffer = bundle_ctrl->data_in_buffer =
		bundle_ctrl->got_send_request = bundle_ctrl->got_send_address = false;
	bundle_ctrl->data_position = bundle_ctrl->ctrl_position = bundle_ctrl->sack_position =
		bundle_ctrl->geco_packet_fixed_size;

#ifdef _DEBUG
	EVENTLOG(VERBOSE, "- - - Leave send_bundled_chunks()");
#endif

leave: return ret;
}
void mdi_init(void)
{
	assert(MAX_NETWORK_PACKET_VALUE_SIZE == sizeof(simple_chunk_t));
	found_init_chunk_ = false;
	is_found_abort_chunk_ = false;
	is_found_cookie_echo_ = false;
	is_found_init_chunk_ = false;
	is_there_at_least_one_equal_dest_port_ = false;
	should_discard_curr_geco_packet_ = false;
	do_dns_query_for_host_name_ = false;
	// uncomment as we never send abort to a unconnected peer
	send_abort_ = false;
	enable_test_ = false;
	ignore_cookie_life_spn_from_init_chunk_ = false;

	curr_channel_ = NULL;
	curr_geco_instance_ = NULL;
	curr_geco_packet_ = NULL;
	curr_uchar_init_chunk_ = NULL;
	curr_channel_ = NULL;
	curr_geco_instance_ = NULL;
	vlparam_fixed_ = NULL;
	ip6_saddr_ = NULL;
	curr_ecc_reason_ = NULL;
	curr_geco_packet_fixed_ = NULL;
	init_chunk_fixed_ = NULL;
	defaultlocaladdrlist_ = NULL;

	total_chunks_count_ = 0;
	defaultlocaladdrlistsize_ = 0;
	tmp_peer_supported_types_ = 0;
	my_supported_addr_types_ = 0;
	curr_ecc_len_ = 0;
	curr_ecc_code_ = 0;
	curr_geco_packet_value_len_ = 0;
	chunk_types_arr_ = 0;
	tmp_local_addreslist_size_ = 0;
	tmp_peer_addreslist_size_ = 0;
	init_chunk_num_ = 0;
	last_source_addr_ = last_dest_addr_ = 0;
	last_src_port_ = last_dest_port_ = 0;
	last_init_tag_ = 0;
	last_src_path_ = 0;
	last_veri_tag_ = 0;
	ip4_saddr_ = 0;
	curr_ecc_code_ = 0;
	dest_addr_type_ = -1;
	chunkflag2use_ = -1;
	cookie_ack_cid_ = 0;
	cookie_local_tie_tag_ = 0;
	cookie_remote_tie_tag_ = 0;

	geco_instances_.resize(DEFAULT_ENDPOINT_SIZE / 2, NULL); // resize as we use fixed nuber of geco instances, overflow is fatal error exit
	channels_ = new geco_channel_t*[DEFAULT_ENDPOINT_SIZE];
	available_channel_ids_ = new uint[DEFAULT_ENDPOINT_SIZE];
	memset(channels_, 0, sizeof(geco_channel_t*) * DEFAULT_ENDPOINT_SIZE);
	memset(available_channel_ids_, 0, sizeof(uint) * DEFAULT_ENDPOINT_SIZE);
	available_channel_ids_size_ = channels_size_ = 0;

	memset(tmp_local_addreslist_, 0,
		MAX_NUM_ADDRESSES * sizeof(sockaddrunion));
	memset(tmp_peer_addreslist_, 0,
		MAX_NUM_ADDRESSES * sizeof(sockaddrunion));

#if ENABLE_UNIT_TEST
	enable_mock_dispatcher_disassemle_curr_geco_packet_ = false;
	enable_mock_dispatch_send_geco_packet_ = false;
	enable_mock_dispatcher_process_init_chunk_ = false;
#endif
}
void mdi_delete_curr_channel(void)
{
	uint path_id;
	if (curr_channel_ != NULL)
	{
		mpath_disable_all_hb();
		mfc_stop_timers();
		mrecv_stop_sack_timer();

		/* mark channel as deleted, it will be deleted when get_channel(..) encounters a "deleted" channel*/
		channels_[curr_channel_->channel_id] = NULL;
		available_channel_ids_[available_channel_ids_size_] = curr_channel_->channel_id;
		available_channel_ids_size_++;
		curr_channel_->deleted = true;
		EVENTLOG1(DEBUG, "mdi_delete_curr_channel()::channel ID %u marked for deletion", curr_channel_->channel_id);
	}
}
void mdi_on_disconnected(uint status)
{
	assert(curr_channel_ != NULL);
	assert(curr_geco_instance_->ulp_callbacks.communicationLostNotif != NULL);
	char str[128];
	ushort port;
	for (uint i = 0; i < curr_channel_->remote_addres_size; i++)
	{
		saddr2str(&curr_channel_->remote_addres[i], str, 128, &port);
		EVENTLOG2(DEBUG, "mdi_on_disconnected()::remote_addres %s:%d", str, port);
	}
	for (uint i = 0; i < curr_channel_->local_addres_size; i++)
	{
		saddr2str(&curr_channel_->local_addres[i], str, 128, &port);
		EVENTLOG2(DEBUG, "mdi_on_disconnected()::local_addres %s:%d", str, port);
	}
	EVENTLOG2(INFO, "mdi_on_disconnected(assoc %u, status %u)", curr_channel_->channel_id, status);
	if (curr_geco_instance_->ulp_callbacks.communicationLostNotif != NULL)
		curr_geco_instance_->ulp_callbacks.communicationLostNotif(curr_channel_->channel_id, status,
			curr_channel_->ulp_dataptr);
}
inline bundle_controller_t* mdi_read_mbu(geco_channel_t* channel)
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
void mdi_unlock_bundle_ctrl(int* ad_idx)
{
	bundle_controller_t* bundle_ctrl = (bundle_controller_t*)mdi_read_mbu(curr_channel_);

	/*1) no channel exists, it is NULL, so we take the global bundling buffer */
	if (bundle_ctrl == NULL)
	{
		EVENTLOG(DEBUG, "mdi_unlock_bundle_ctrl()::Setting global bundling buffer");
		bundle_ctrl = default_bundle_ctrl_;
	}

	bundle_ctrl->locked = false;
	if (bundle_ctrl->got_send_request)
		mdi_send_bundled_chunks(ad_idx);

	EVENTLOG1(DEBUG, "mdi_unlock_bundle_ctrl()::got %s send request",
		(bundle_ctrl->got_send_request == true) ? "A" : "NO");
}

void mdi_lock_bundle_ctrl()
{
	bundle_controller_t* bundle_ctrl = (bundle_controller_t*)mdi_read_mbu(curr_channel_);

	/*1) no channel exists, it is NULL, so we take the global bundling buffer */
	if (bundle_ctrl == NULL)
	{
		EVENTLOG(VERBOSE, "mdi_lock_bundle_ctrl()::Setting global bundling buffer");
		bundle_ctrl = default_bundle_ctrl_;
	}

	bundle_ctrl->locked = true;
	bundle_ctrl->got_send_request = false;
}
uint mdi_read_curr_channel_id(void)
{
	return curr_channel_ == NULL ? 0 : curr_channel_->channel_id;
}
uint get_curr_channel_state()
{
	smctrl_t* smctrl = (smctrl_t*)mdi_read_smctrl();
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
bool contains_error_chunk(uchar * packet_value, uint packet_val_len, ushort error_cause)
{
	uint chunk_len = 0;
	uint read_len = 0;
	chunk_fixed_t* chunk;
	uchar* curr_pos = packet_value;
	vlparam_fixed_t* err_chunk;

	while (read_len < packet_val_len)
	{
		EVENTLOG3(VVERBOSE, "contains_error_chunk(error_cause %u)::packet_val_len=%d, read_len=%d", error_cause,
			packet_val_len, read_len);

		if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
		{
			EVENTLOG(MINOR_ERROR, "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !");
			return false;
		}

		chunk = (chunk_fixed_t*)curr_pos;
		chunk_len = get_chunk_length(chunk);
		if (chunk_len < CHUNK_FIXED_SIZE || chunk_len + read_len > packet_val_len)
			return false;

		if (chunk->chunk_id == CHUNK_ERROR)
		{
			EVENTLOG(VERBOSE, "contains_error_chunk()::Error Chunk Found");
			uint err_param_len = 0;
			uchar* simple_chunk;
			uint param_len = 0;
			// search for target error param
			while (err_param_len < chunk_len - CHUNK_FIXED_SIZE)
			{
				if (chunk_len - CHUNK_FIXED_SIZE - err_param_len < VLPARAM_FIXED_SIZE)
				{
					EVENTLOG(MINOR_ERROR, "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !");
					return false;
				}

				simple_chunk = &((simple_chunk_t*)chunk)->chunk_value[err_param_len];
				err_chunk = (vlparam_fixed_t*)simple_chunk;
				if (ntohs(err_chunk->param_type) == error_cause)
				{
					EVENTLOG1(VERBOSE, "contains_error_chunk()::Error Cause %u found -> Returning true", error_cause);
					return true;
				}
				param_len = ntohs(err_chunk->param_length);
				err_param_len += param_len;
				param_len = ((param_len % 4) == 0) ? 0 : (4 - param_len % 4);
				err_param_len += param_len;
			}
		}

		read_len += chunk_len;
		while (read_len & 3)
			++read_len;
		curr_pos = packet_value + read_len;
	}
	return false;
}
inline uint get_bundle_total_size(bundle_controller_t* buf)
{
	assert(GECO_PACKET_FIXED_SIZE == sizeof(geco_packet_fixed_t));
	return ((buf)->ctrl_position + (buf)->sack_position + (buf)->data_position - 2 * buf->geco_packet_fixed_size);
}
inline uint get_bundle_sack_size(bundle_controller_t* buf)
{
	assert(GECO_PACKET_FIXED_SIZE == sizeof(geco_packet_fixed_t));
	return ((buf)->ctrl_position + (buf)->data_position - buf->geco_packet_fixed_size);
}
void mdi_bundle_ctrl_chunk(simple_chunk_t * chunk, int * dest_index)
{
	EVENTLOG(VERBOSE, "- -  Enter mdi_bundle_ctrl_chunk()");
	bundle_controller_t* bundle_ctrl = (bundle_controller_t*)mdi_read_mbu(curr_channel_);

	/*1) no channel exists, so we take the global bundling buffer */
	if (bundle_ctrl == NULL)
	{
		EVENTLOG(VERBOSE, "mdi_bundle_ctrl_chunk()::use global bundle_ctrl");
		bundle_ctrl = default_bundle_ctrl_;
	}

	ushort chunk_len = get_chunk_length((chunk_fixed_t*)chunk);
	uint bundle_size = get_bundle_total_size(bundle_ctrl);

	if ((bundle_size + chunk_len) > bundle_ctrl->curr_max_pdu)
	{
		/*2) an packet CANNOT hold all data, we send chunks and get bundle empty*/
		EVENTLOG5(VERBOSE, "mdi_bundle_ctrl_chunk()::Chunk Length(bundlesize %u+chunk_len %u = %u),"
			"exceeded MAX_NETWORK_PACKET_VALUE_SIZE(%u) : sending chunk to address %u !", bundle_size, chunk_len,
			bundle_size + chunk_len, MAX_GECO_PACKET_SIZE, (dest_index == NULL) ? 0 : *dest_index);
		bundle_ctrl->locked = false;/* unlock to allow send bundle*/
		mdi_send_bundled_chunks(dest_index);
		// we do not unlock because when is is hb packet that must exceed the curr_max_pdu, we want to send hb anyway so do not unlock here anyway
	}

	/*3) an packet CAN hold all data*/
	if (dest_index != NULL)
	{
		bundle_ctrl->got_send_address = true;
		bundle_ctrl->requested_destination = *dest_index;
	}
	else
	{
		bundle_ctrl->got_send_address = false;
		bundle_ctrl->requested_destination = 0;
	}

	/*3) copy new chunk to bundle and insert padding, if necessary*/
	memcpy_fast(&bundle_ctrl->ctrl_buf[bundle_ctrl->ctrl_position], chunk, chunk_len);
	bundle_ctrl->ctrl_position += chunk_len;
	bundle_ctrl->ctrl_chunk_in_buffer = true;
	while (bundle_ctrl->ctrl_position & 3)
	{
		bundle_ctrl->ctrl_buf[bundle_ctrl->ctrl_position] = 0;
		bundle_ctrl->ctrl_position++;
	}

	EVENTLOG3(VERBOSE,
		"mdi_bundle_ctrl_chunk():chunklen %u + GECO_PACKET_FIXED_SIZE(%u) = Total buffer size now (includes pad): %u",
		get_chunk_length((chunk_fixed_t *)chunk), GECO_PACKET_FIXED_SIZE, get_bundle_total_size(bundle_ctrl));

	EVENTLOG(VERBOSE, "- -  Leave mdi_bundle_ctrl_chunk()");
}
bool mdi_set_curr_channel_inst(uint channelid)
{
	curr_channel_ = channels_[channelid];
	if (curr_channel_)
	{
		curr_geco_instance_ = curr_channel_->geco_inst;
		return true;
	}
	return false;
}
static void mdi_print_channel()
{
	EVENTLOG8(INFO, "\ncurr_channel_->channel_id=%d\n"
		"curr_channel_->deleted=%d\n"
		"curr_channel_->local_port=%d\n"
		"curr_channel_->remote_port=%d\n"
		"curr_channel_->local_tag=%d\n"
		"curr_channel_->remote_tag=%d\n"
		"curr_channel_->local_tie_tag=%d\n"
		"curr_channel_->peer_tie_tag=%d\n", curr_channel_->channel_id, curr_channel_->deleted, curr_channel_->local_port,
		curr_channel_->remote_port, curr_channel_->local_tag, curr_channel_->remote_tag,
		curr_channel_->state_machine_control->local_tie_tag, curr_channel_->state_machine_control->peer_tie_tag);
	EVENTLOG1(DEBUG, "curr_channel_->local_addres(%d):", curr_channel_->local_addres_size);
	print_addrlist(curr_channel_->local_addres, curr_channel_->local_addres_size);
	EVENTLOG1(DEBUG, "curr_channel_->remote_addres(%d):", curr_channel_->remote_addres_size);
	print_addrlist(curr_channel_->remote_addres, curr_channel_->remote_addres_size);
}

void mdlm_read_streams(ushort* inStreams, ushort* outStreams)
{
	deliverman_controller_t* se = mdi_read_mdlm();
	assert(se != NULL && "Called mdlm_read_streams, but no Streamengine is there !");
	*inStreams = se->numOrderedStreams;
	*outStreams = se->numSequencedStreams;
	assert(*inStreams != 0 && *outStreams != 0);
}

void mdi_on_peer_connected(uint status)
{
	EVENTLOG1(INFO, "mdi_on_peer_connected %d", status);
	//mdi_print_channel();

	assert(curr_channel_ != NULL);
	assert(curr_geco_instance_ != NULL);
	assert(last_source_addr_ != NULL);

	// reset mbu geco packet size
	if (default_bundle_ctrl_->geco_packet_fixed_size != 0 && curr_channel_->bundle_control->geco_packet_fixed_size == 0)
	{
		curr_channel_->bundle_control->geco_packet_fixed_size = default_bundle_ctrl_->geco_packet_fixed_size;
		curr_channel_->bundle_control->data_position = curr_channel_->bundle_control->sack_position =
			curr_channel_->bundle_control->ctrl_position = default_bundle_ctrl_->geco_packet_fixed_size;
		curr_channel_->bundle_control->curr_max_pdu = default_bundle_ctrl_->curr_max_pdu;
	}

	// find primary path
	//short primaryPath;
	//if (last_source_addr_ != NULL)
	//{
	//	for (primaryPath = 0;primaryPath < curr_channel_->remote_addres_size;primaryPath++)
	//	{
	//		if (saddr_equals(&(curr_channel_->remote_addres[primaryPath]), last_source_addr_, true))
	//		{
	//			break;
	//		}
	//	}
	//	// if not found use zero
	//	if (primaryPath >= curr_channel_->remote_addres_size)
	//		primaryPath = 0;
	//}
	//else
	//{
	//	// if NULL use zero
	//	primaryPath = 0;
	//}

	ushort primaryPath;
	for (primaryPath = 0; primaryPath < curr_channel_->remote_addres_size; primaryPath++)
	{
		if (saddr_equals(&(curr_channel_->remote_addres[primaryPath]), last_source_addr_, true))
		{
			break;
		}
	}

	assert(last_source_addr_ != NULL);
	assert(primaryPath < curr_channel_->remote_addres_size);

	// set number of paths and primary path at pathmanegement and start heartbeat
	mpath_start_hb_probe(curr_channel_->remote_addres_size, primaryPath);

#ifdef _DEBUG
	unsigned short noOfInStreams;
	unsigned short noOfOutStreams;
	mdlm_read_streams(&noOfInStreams, &noOfOutStreams);
	EVENTLOG5(DEBUG,
		"Distribution: COMM-UP, assocId: %u, status: %s, noOfNetworks: %u, noOfInStreams: %u,noOfOutStreams  %u",
		curr_channel_->channel_id, status == PM_ACTIVE ? "PM_ACTIVE" : "PM_INACTIVE", curr_channel_->remote_addres_size,
		noOfInStreams, noOfOutStreams);
#endif

	/* Forward mdi_communicationup Notification to the ULP */
	if (curr_geco_instance_->ulp_callbacks.communicationUpNotif != NULL)
	{
		curr_channel_->ulp_dataptr = curr_geco_instance_->ulp_callbacks.communicationUpNotif(curr_channel_->channel_id,
			status, curr_channel_->remote_addres_size, noOfInStreams, noOfOutStreams,
			curr_channel_->locally_supported_PRDCTP, curr_channel_->remotely_supported_PRSCTP,
			curr_channel_->locally_supported_ADDIP, curr_channel_->remotely_supported_ADDIP, curr_channel_->ulp_dataptr);
	}
	else
	{
		curr_channel_->ulp_dataptr = NULL;
	}

	for (primaryPath = 0; primaryPath < curr_channel_->remote_addres_size; primaryPath++)
	{
		//hash all remote addrs to path ids
		path_map.insert(std::make_pair(curr_channel_->remote_addres[primaryPath], primaryPath));

		if (mpath_read_path_status(primaryPath) == PM_ACTIVE)
		{
			mdi_on_path_status_changed(primaryPath, (int)PM_ACTIVE);
		}
	}
}

void mdi_on_peer_restarted(void)
{
	assert(curr_channel_ != NULL);
	assert(curr_geco_instance_->ulp_callbacks.restartNotif != NULL);
	EVENTLOG1(INFO, "mdi_on_peer_restarted(channel_id=%u)", curr_channel_->channel_id);
	curr_geco_instance_->ulp_callbacks.restartNotif(curr_channel_->channel_id, curr_channel_->ulp_dataptr);
}

inline void mdi_clear_current_channel(void)
{
	curr_channel_ = NULL;
	curr_geco_instance_ = NULL;
}
inline geco_instance_t* find_geco_instance_by_id(uint geco_inst_id)
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
inline ushort get_local_ordered_streams(uint * geco_inst_id = NULL)
{
	if (curr_channel_ != NULL)
	{
		return curr_channel_->geco_inst->ordered_streams;
	}
	else if (curr_geco_instance_ != NULL)
	{
		return curr_geco_instance_->ordered_streams;
	}
	else
	{
		if (geco_inst_id != NULL)
		{
			curr_geco_instance_ = find_geco_instance_by_id(*geco_inst_id);
			if (curr_geco_instance_ != NULL)
			{
				uint ins = curr_geco_instance_->ordered_streams;
				curr_geco_instance_ = NULL;
				return ins;
			}
		}

	}
	return 0;
}

inline ushort get_local_sequenced_streams(uint * geco_inst_id = NULL)
{
	if (curr_channel_ != NULL)
	{
		return curr_channel_->geco_inst->sequenced_streams;
	}
	else if (curr_geco_instance_ != NULL)
	{
		return curr_geco_instance_->sequenced_streams;
	}
	else
	{
		if (geco_inst_id != NULL)
		{
			curr_geco_instance_ = find_geco_instance_by_id(*geco_inst_id);
			if (curr_geco_instance_ != NULL)
			{
				uint ins = curr_geco_instance_->sequenced_streams;
				curr_geco_instance_ = NULL;
				return ins;
			}
		}

	}
	return 0;
}

bool do_we_support_unreliability(void)
{
	if (curr_geco_instance_ != NULL)
	{
		return curr_geco_instance_->supportsPRSCTP;
	}
	else if (curr_channel_ != NULL)
	{
		return curr_channel_->locally_supported_PRDCTP;
	}
	else
		return (support_pr_);
}
bool do_we_support_addip(void)
{
	if (curr_geco_instance_ != NULL)
	{
		return curr_geco_instance_->supportsADDIP;
	}
	else if (curr_channel_ != NULL)
	{
		return curr_channel_->locally_supported_ADDIP;
	}
	else
		return (support_addip_);
}

uint mdlm_read_queued_bytes()
{
	deliverman_controller_t* mdlm = mdi_read_mdlm();
	return mdlm != NULL ? mdlm->queuedBytes : 0;
}

bool mrecv_after_highest_tsn(recv_controller_t* mrecv, uint chunk_tsn)
{
	// every time we received a reliable chunk, it first goes here to update highest tsn if possible
	if (uafter(chunk_tsn, mrecv->highest_tsn))
	{
		mrecv->highest_tsn = chunk_tsn;
		return true;
	}
	// it is possibly dup chunk or new chunk
	return false;
}
bool mrecv_before_lowest_duptsn(recv_controller_t* mrecv, uint chunk_tsn)
{
	if (ubefore(chunk_tsn, mrecv->lowest_duplicated_tsn))
	{
		mrecv->lowest_duplicated_tsn = chunk_tsn;
		return true;
	}
	return false;
}
/// insert chunk_tsn in the list of duplicates from small to big if it is not in list
/// @param chunk_tsn	tsn we just received
void mrecv_update_duplicates(recv_controller_t* mrecv, uint chunk_tsn)
{
	/*
	 // 10 10 10 20 20 20 30 30
	 low=std::lower_bound (v.begin(), v.end(), 20); //
	 up= std::upper_bound (v.begin(), v.end(), 20); //
	 std::cout << "lower_bound at position " << (low- v.begin()) << '\n';
	 std::cout << "upper_bound at position " << (up - v.begin()) << '\n';
	 lower_bound at position 3
	 upper_bound at position 6
	 */
	assert(!mrecv->duplicated_data_chunks_list.empty());
	auto end = mrecv->duplicated_data_chunks_list.end();
	auto insert_pos = lower_bound(mrecv->duplicated_data_chunks_list.begin(), end, chunk_tsn, mrecv_sort_duplicates_cmp);
	if (*insert_pos != chunk_tsn)
		mrecv->duplicated_data_chunks_list.insert(insert_pos, chunk_tsn);
}
bool mrecv_update_fragments(recv_controller_t* mrecv, uint chunk_tsn)
{
	static uint lo, hi, gapsize;
	static segment32_t newseg;
	static std::list<segment32_t>::iterator tmp;

	// printf("test %u\n", (unsigned int)(UINT32_MAX + 1)); => test 0
	// if cumulative_tsn == UINT32_MAX, UINT32_MAX + 1 will wrap round to 0 agin
	// why use 4 bytes tsn is that sender must NOT send chunks with tsn wrapper at one time sending.
	// otherwise, the tsn will not be working correctly for retrans, reordering and acking functions.
	// eg. assume tsn is beteen [0,2], sender  sents chunk 0,1,2,0,1,2,
	// 1.when sender send all chunks in one packet,  this will confuses receiver's reliableing function.
	// 2.when send send all chunks one after another, it is likely that receiver will buffer all or some of received chunks,
	// which also confuses receiver's reliableing function.
	// the tricky using uint is it is so big that receiver will never receive wrapped tsn.
	// also sender will stop sending chunks when congestion ocurres.
	// key point: receiver is always catching up with sender's tsn, and most of time receiver is as fast as sender,
	// so there is no chance for sender to run fast enough to wrap around (tsn wrapping).
	lo = (uint)(mrecv->cumulative_tsn + 1);

	for (auto itr = mrecv->fragmented_data_chunks_list.begin(); itr != mrecv->fragmented_data_chunks_list.end();)
	{
		hi = itr->start_tsn - 1;
		if (ubetween(lo, chunk_tsn, hi))
		{
			gapsize = hi - lo + 1;    //the number of missing tsn in current gap
			if (gapsize > 1)
			{
				if (chunk_tsn == hi)
				{
					/* Given 1-45..., cstna=1
					 * Assume ctsn=3
					 *
					 * loop1:
					 * lo=cstna+1=1+1=2, hi=4-1=3 =>
					 * (ubetween(2,3,3)) =>
					 * gapsize=hi-lo+1=3-2+1=2 >1 =>
					 * (3= ctsn==hi =3) =>
					 * update frag start tsn = ctsn = 3, makr as new chunk
					 *
					 * now sequence sre 1-3.4.5...
					 */
					itr->start_tsn = chunk_tsn;
					mrecv->new_chunk_received = true;
					return true;
				}
				else if (chunk_tsn == lo)
				{
					if (chunk_tsn == mrecv->cumulative_tsn + 1)
					{
						/* Given 1-4.5..., cstna=1
						 * Assume ctsn=2
						 *
						 * loop1:
						 * lo=cstna+1=1+1=2, hi=4-1=3 =>
						 * (ubetween(2,2,3)) =>
						 * gapsize=hi-lo+1=3-2+1=2 >1 =>
						 * (2= ctsn==cstna+1 =1+1=2 true) =>
						 * update cstna = ctsn, makr as new chunk
						 *
						 * now sequence sre 12-4.5...
						 */
						mrecv->cumulative_tsn++;
						mrecv->new_chunk_received = true;
						return true;
					}

					/* Given 1-4.5-8.9..., cstna=1
					 * Assume ctsn=6
					 *
					 * loop1:
					 * lo=cstna+1=1+1=2, hi=4-1=3 =>
					 * (ubetween(2,6,3) = false) =>
					 * update lo = stoptsn+1 = 5+1 = 6 =>
					 *
					 * loop2:
					 * hi=8-1=7 =>
					 * (ubetween(2,6,7) = true) =>
					 * gapsize=hi-lo+1=7-2+1=6 >1 =>
					 * (6= ctsn==lo =6 true ) =>
					 * (6= ctsn!=cstna+1 =1+1=2 true ) =>
					 * update cstna = ctsn, makr as new chunk
					 *
					 * now sequence sre 1-4.5.6-8.9...
					 */
					--itr;
					assert(itr != mrecv->fragmented_data_chunks_list.end());
					itr->stop_tsn = chunk_tsn;
					mrecv->new_chunk_received = true;
					return true;
				}
				else
				{
					/* Given 1-4.5-9.10..., cstna=1
					 * Assume ctsn=7
					 *
					 * loop1:
					 * lo=cstna+1=1+1=2, hi=4-1=3 =>
					 * (ubetween(2,6,3) = false) =>
					 * update lo = stoptsn+1 = 5+1 = 6 =>
					 *
					 * loop2:
					 * hi=9-1=8 =>
					 * (ubetween(2,6,8) = true) =>
					 * gapsize=hi-lo+1=8-2+1=7 >1 =>
					 * (7= ctsn!=hi =8 ) =>
					 * (7= ctsn!=lo =6 ) =>
					 * allocate and init new frag with ctsn7 ,insert to list, makr as new chunk
					 *
					 * now sequence sre 1-4.5-7-8.9...
					 */
					 //@TODO g_list_insert_sorted but I think we do not need loop again
					newseg.start_tsn = newseg.stop_tsn = chunk_tsn;
					mrecv->fragmented_data_chunks_list.insert(itr, newseg);
					mrecv->new_chunk_received = true;
				}
			}
			else //gapsize == 1
			{
				if (lo == mrecv->cumulative_tsn + 1)
				{
					/* Given 1-3.4..., cstna=1
					 * Assume chunk_tsn=2
					 *
					 * loop1:
					 * lo=cstna+1=1+1=2, hi=3-1=2 =>
					 * (ubetween(2,2,2)) =>
					 * gapsize=hi-lo+1=2-2+1=1 =>
					 * (2=lo==cstna+1=1+1=2) =>
					 * update cstna=4,remove frag, makr as new chunk
					 *
					 * now sequence sre 1.2.3.4...
					 */
					mrecv->cumulative_tsn = itr->stop_tsn;
					mrecv->fragmented_data_chunks_list.erase(itr);
					mrecv->new_chunk_received = true;
					return true;
				}
				else
				{
					/* Given 0-4.5-7..., cstna=1
					 * Assume chunk_tsn=6
					 *
					 * loop1:
					 * lo=cstna+1=0+1=1, hi=4-1=3 =>
					 * (ubetween(1,6,3)=false) =>
					 * update lo=5=1=6 =>
					 *
					 * loop2:
					 * hi=7-1=6 =>
					 * (ubetween(6,6,6)=true) =>
					 * (gapsize=hi-lo+1=6-6+1=1 ==1) =>
					 * (6=lo != cstna+1=1+1=2) =>
					 * insert chunk before frag, makr as new chunk
					 *
					 * now sequence are 0-4.5.6.7...
					 */
					mrecv->new_chunk_received = true;
					tmp = itr;
					--itr;
					assert(itr != mrecv->fragmented_data_chunks_list.end());
					tmp->start_tsn = itr->start_tsn;
					mrecv->fragmented_data_chunks_list.erase(itr++);
					return true;
				}
			}
		}
		else
		{
			// ch_tsn is not in the gap between these two fragments
			lo = itr->stop_tsn + 1;
		}
		itr++;
	}
	return false;
}

bool mrecv_chunk_is_duplicate(recv_controller_t* mrecv, uint chunk_tsn)
{
	// Assume lowest_duplicated_tsn and highest_duplicated_tsn have already been updated if they should be

	// Given cstna=2, chunk_tsn=2, received sequence 2-4.5-7...,  dups sequence 0,2 =>
	// ubetween(0, 2, 2)  =>return true
	if (ubetween(mrecv->lowest_duplicated_tsn, chunk_tsn, mrecv->cumulative_tsn))
		return true;

	// Given cstna=2, chunk_tsn=6, current received sequence 0 1 2 45 7...,  dups sequence lowest 2, highest 7 =>
	// !ubetween(2, 6, 7)  =>return false => it is new chunk frag passing to mrecv_update_framents() for further processing
	if (!ubetween(mrecv->cumulative_tsn, chunk_tsn, mrecv->highest_tsn))
		return false;

	// frag list is empty which means this is first time received new chunk
	if (mrecv->fragmented_data_chunks_list.empty())
		return false;

	// now chunk_tsn between any fragment start and end boundary must be dup, otherwise must be new
	for (segment32_t& seg : mrecv->fragmented_data_chunks_list)
	{
		if (ubetween(seg.start_tsn, chunk_tsn, seg.stop_tsn))
		{
			// Given cstna=2, chunk_tsn=5, received sequence 2-4.5-7...,  dups sequence lowest 0, highest 5 =>
			// ubetween(0, 5, 2) false =>
			// ubetween(2, 5, 5)  true =>
			//loop1:
			// ubetween(seg.start-4, 5, seg.stop-5) true => it is dup ,return true
			return true;
		}
		if (uafter(seg.stop_tsn, chunk_tsn))
		{
			// Given cstna=2, chunk_tsn=6, received sequence 2-4.5-7...,  dups sequence lowest 0, highest 7 =>
			// ubetween(0, 6, 2) false =>
			// ubetween(2, 6, 7)  true =>
			// loop1:
			// ubetween(start4, 6, stop5) false =>
			// uafter(stop5,6) false =>
			// loop2:
			// ubetween(start7, 6, stop7) false =>
			// uafter(stop7,6) true =>
			// it is new chunk, return false
			return false;
		}
	}

	// you should never reach here
	return false;
}
void mrecv_bubbleup_ctsna(recv_controller_t* mrecv)
{
	if (mrecv->fragmented_data_chunks_list.size() == 0)
		return;

	for (auto itr = mrecv->fragmented_data_chunks_list.begin(); itr != mrecv->fragmented_data_chunks_list.end();)
	{
		if (mrecv->cumulative_tsn + 1 != itr->start_tsn)
		{
			// if the first frag not cotimus, no need to test other frags as frag tsn is ordered small to big
			// say frag567 and frag89, sequence 23-567-89 => 3+1=4!=5 => return
			EVENTLOG(VVERBOSE, "mrecv_bubbleup_ctsna():: NOT update rxc->cumulative_tsn");
			return;
		}
		// say frag567,newly received data chunks sequence is 234-67
		// assume after calling mrecv_update_fragments(),
		// frag567 is completed and store into mrecv->fragmented_data_chunks_list
		// => current stsna is bubbleup from 4 to 7
		mrecv->cumulative_tsn = itr->stop_tsn;
		mrecv->fragmented_data_chunks_list.erase(itr++);
	}
	EVENTLOG1(VVERBOSE, "mrecv_bubbleup_ctsna()::after update,rxc->cumulative_tsn is now %u", mrecv->cumulative_tsn);
}

bool mdlm_sort_tsn_delivery_data_cmp(delivery_data_t* one, delivery_data_t* two)
{
	return ubefore(one->tsn, two->tsn);
}
bool mdlm_sort_ssn_delivery_data_cmp(delivery_data_t* one, delivery_data_t* two)
{
	return ubefore(one->stream_sn, two->stream_sn);
}
/// called from mrecv to forward received ro and rs chunks to mdlm.
/// returns an error chunk to the peer, when the maximum stream id is exceeded !
int mdlm_process_data_chunk(deliverman_controller_t* mdlm, data_chunk_t* dataChunk, uint dchunk_pdu_len,
	ushort address_index)
{
	static delivery_data_t* dchunk;
	if ((dchunk = (delivery_data_t*)geco_malloc_ext(sizeof(delivery_data_t), __FILE__, __LINE__)))
		return MULP_OUT_OF_RESOURCES;

	// return error, when numReceiveStreams is exceeded
	uint numReceiveStreams =
		dataChunk->comm_chunk_hdr.chunk_flags & DCHUNK_FLAG_ORDER ? mdlm->numOrderedStreams : mdlm->numSequencedStreams;
	dchunk->stream_id = ntohs(dataChunk->data_chunk_hdr.stream_identity);
	if (dchunk->stream_id > numReceiveStreams)
	{
		geco_free_ext(dchunk, __FILE__, __LINE__);
		invalid_stream_id_err_t error_info;
		error_info.stream_id = dataChunk->data_chunk_hdr.stream_identity;
		error_info.reserved = 0;
		msm_abort_channel(ECC_INVALID_STREAM_ID, (uchar*)&error_info, sizeof(invalid_stream_id_err_t));
		return MULP_INVALID_STREAM_ID;
	}

	// return error, when no user data
	dchunk->tsn = ntohl(dataChunk->data_chunk_hdr.trans_seq_num);
	dchunk_pdu_len -= DATA_CHUNK_FIXED_SIZES;
	if (dchunk_pdu_len == 0)
	{
		geco_free_ext(dchunk, __FILE__, __LINE__);
		msm_abort_channel(ECC_NO_USER_DATA, (uchar*)&dchunk->tsn, sizeof(uint));
		return MULP_NO_USER_DATA;
	}

	dchunk->data = dataChunk->chunk_value;
	dchunk->data_length = dchunk_pdu_len;
	dchunk->chunk_flags = dataChunk->comm_chunk_hdr.chunk_flags;
	dchunk->stream_sn = ntohs(dataChunk->data_chunk_hdr.stream_seq_num);
	dchunk->fromAddressIndex = address_index;
	dchunk->packet_params_t = g_packet_params;

	mdlm->queuedBytes += dchunk_pdu_len;
	mdlm->recv_order_streams_actived[dchunk->stream_id] = true;

	if (dchunk->chunk_flags & DCHUNK_FLAG_ORDER)
	{
		const auto& upper = std::upper_bound(mdlm->ro.begin(), mdlm->ro.end(), dchunk, mdlm_sort_tsn_delivery_data_cmp);
		mdlm->ro.insert(upper, dchunk);
	}
	else
	{
		const auto& upper = std::upper_bound(mdlm->rs.begin(), mdlm->rs.end(), dchunk, mdlm_sort_tsn_delivery_data_cmp);
		mdlm->rs.insert(upper, dchunk);
	}
	return MULP_SUCCESS;
}

/// called from mrecv to forward received rchunks (no sid and ssn) to mdlm.
/// returns an error chunk to the peer, when the maximum stream id is exceeded !
int mdlm_process_data_chunk(deliverman_controller_t* mdlm, dchunk_r_t* dataChunk, uint dchunk_len, ushort address_index)
{
	static delivery_data_t* dchunk;
	if ((dchunk = (delivery_data_t*)geco_malloc_ext(sizeof(delivery_data_t), __FILE__, __LINE__)))
		return MULP_OUT_OF_RESOURCES;

	// return error, when no user data
	dchunk_len -= DCHUNK_R_FIXED_SIZES;
	if (dchunk_len == 0)
	{
		geco_free_ext(dchunk, __FILE__, __LINE__);
		msm_abort_channel(ECC_NO_USER_DATA);
		return MULP_NO_USER_DATA;
	}

	dchunk->tsn = ntohl(dataChunk->data_chunk_hdr.trans_seq_num);
	dchunk->data = dataChunk->chunk_value;
	dchunk->data_length = dchunk_len;
	dchunk->chunk_flags = dataChunk->comm_chunk_hdr.chunk_flags;
	dchunk->fromAddressIndex = address_index;
	dchunk->packet_params_t = g_packet_params;
	mdlm->queuedBytes += dchunk_len;

	const auto& upper = std::upper_bound(mdlm->r.begin(), mdlm->r.end(), dchunk, mdlm_sort_tsn_delivery_data_cmp);
	mdlm->r.insert(upper, dchunk);

	return MULP_SUCCESS;
}

/// called from mrecv to forward received uro and urs chunks to mdlm.
/// returns an error chunk to the peer, when the maximum stream id is exceeded !
int mdlm_process_data_chunk(deliverman_controller_t* mdlm, dchunk_urs_t* dataChunk, uint dchunk_len,
	ushort address_index)
{
	static delivery_data_t* dchunk;
	static delivery_pdu_t* d_pdu;
	static ushort sid;
	static ushort ssn;
	static recv_stream_t* recvsm;

	ssn = ntohs(dataChunk->data_chunk_hdr.stream_seq_num);
	recvsm = &mdlm->recv_seq_streams[sid];

	//  increment tsn by one for each data chunk in the packet  and use it to fill tsn field
	// also increment some stream's ssn by one for each data chunk in packet and ure it to fill ssn field
	// thus, all tsns and ssns in this packet MUST be in ascend order. if not, peer's stack impl is not compatiable with with us
	// recvsm->highestSSN == ssn because ur chunk is always segmented as r chunk with ordering type and same sid and ssn
	if (recvsm->highestSSNused && (safter(recvsm->highestSSN, ssn) || recvsm->highestSSN == ssn))
	{
		EVENTLOG(NOTICE, "mdlm_assemble_ulp_data()::wrong ssn");
		msm_abort_channel(ECC_PROTOCOL_VIOLATION);
		return MULP_PROTOCOL_VIOLATION;
	}

	if (sbefore(ssn, recvsm->nextSSN))
	{
		free_packet_params(dchunk_len);
		return MULP_SUCCESS;
	}

	recvsm->nextSSN = ssn + 1;
	recvsm->highestSSN = ssn;
	recvsm->highestSSNused = true;

	sid = ntohs(dataChunk->data_chunk_hdr.stream_identity);
	if ((dchunk = (delivery_data_t*)geco_malloc_ext(sizeof(delivery_data_t), __FILE__, __LINE__)))
		return MULP_OUT_OF_RESOURCES;

	// return error, when numReceiveStreams is exceeded
	dchunk->stream_id = sid;
	if (dchunk->stream_id > mdlm->numSequencedStreams)
	{
		geco_free_ext(dchunk, __FILE__, __LINE__);
		invalid_stream_id_err_t error_info;
		error_info.stream_id = dataChunk->data_chunk_hdr.stream_identity;
		error_info.reserved = 0;
		msm_abort_channel(ECC_INVALID_STREAM_ID, (uchar*)&error_info, sizeof(invalid_stream_id_err_t));
		return MULP_INVALID_STREAM_ID;
	}

	// return error, when no user data
	dchunk_len -= DCHUNK_URS_FIXED_SIZE;
	if (dchunk_len == 0)
	{
		geco_free_ext(dchunk, __FILE__, __LINE__);
		msm_abort_channel(ECC_NO_USER_DATA);
		return MULP_NO_USER_DATA;
	}

	dchunk->data = dataChunk->chunk_value;
	dchunk->data_length = dchunk_len;
	dchunk->chunk_flags = dataChunk->comm_chunk_hdr.chunk_flags;
	dchunk->stream_sn = ssn;
	dchunk->fromAddressIndex = address_index;
	dchunk->packet_params_t = g_packet_params;

	mdlm->queuedBytes += dchunk_len;
	mdlm->recv_seq_streams_activated[dchunk->stream_id] = true;

	if ((dchunk->chunk_flags & DCHUNK_FLAG_FIRST_FRAG) && (dchunk->chunk_flags & DCHUNK_FLAG_LAST_FRG))
	{
		EVENTLOG(VVERBOSE, "mdlm_assemble_ulp_data()::found begin segment");
		if ((d_pdu = (delivery_pdu_t*)geco_malloc_ext(sizeof(delivery_pdu_t), __FILE__, __LINE__)) == NULL)
		{
			return MULP_OUT_OF_RESOURCES;
		}
		d_pdu->number_of_chunks = 1;
		d_pdu->read_position = 0;
		d_pdu->read_chunk = 0;
		d_pdu->chunk_position = 0;
		d_pdu->total_length = dchunk->data_length;
		// ur chunk must not be segmented and so we can force cast it to delivery_data_t**
		d_pdu->ddata = (delivery_data_t**)dchunk;
	}
	else
	{
		EVENTLOG(NOTICE, "mdlm_assemble_ulp_data()::found segmented unreliable chunk");
		geco_free_ext(dchunk, __FILE__, __LINE__);
		geco_free_ext(d_pdu, __FILE__, __LINE__);
		msm_abort_channel(ECC_PROTOCOL_VIOLATION);
		return MULP_PROTOCOL_VIOLATION;
	}

	//auto& prelist = mdlm->recv_seq_streams[dchunk->stream_id].prePduList;
	//const auto& upper = std::upper_bound(prelist.begin(), prelist.end(), d_pdu,
	//	[](delivery_pdu_t* l, delivery_pdu_t* r)->bool
	//{
	//	return sbefore(((delivery_data_t*)l->ddata)->stream_sn, ((delivery_data_t*)r->ddata)->stream_sn);
	//});
	//prelist.insert(upper, d_pdu);

	// thish chunk has ssn >= nexssn, it is already ordered with sequence
	auto& prelist = mdlm->recv_seq_streams[dchunk->stream_id].prePduList;
	prelist.push_back(d_pdu);

	return MULP_SUCCESS;
}

/// called from mrecv to forward received urchunks to mdlm.
/// returns an error chunk to the peer, when the maximum stream id is exceeded !
int mdlm_process_data_chunk(deliverman_controller_t* mdlm, dchunk_ur_t* dataChunk, uint dchunk_len,
	ushort address_index)
{
	static delivery_data_t* dchunk;
	if ((dchunk = (delivery_data_t*)geco_malloc_ext(sizeof(delivery_data_t), __FILE__, __LINE__)))
		return MULP_OUT_OF_RESOURCES;

	// return error, when no user data
	dchunk_len -= DCHUNK_UR_FIXED_SIZES;
	if (dchunk_len == 0)
	{
		geco_free_ext(dchunk, __FILE__, __LINE__);
		msm_abort_channel(ECC_NO_USER_DATA);
		return MULP_NO_USER_DATA;
	}

	dchunk->data = dataChunk->chunk_value;
	dchunk->data_length = dchunk_len;
	dchunk->chunk_flags = dataChunk->comm_chunk_hdr.chunk_flags;
	dchunk->fromAddressIndex = address_index;
	dchunk->packet_params_t = g_packet_params;
	mdlm->queuedBytes += dchunk_len;

	delivery_pdu_t* d_pdu;
	if ((dchunk->chunk_flags & DCHUNK_FLAG_FIRST_FRAG) && (dchunk->chunk_flags & DCHUNK_FLAG_LAST_FRG))
	{
		EVENTLOG(VVERBOSE, "mdlm_assemble_ulp_data()::found begin segment");
		if ((d_pdu = (delivery_pdu_t*)geco_malloc_ext(sizeof(delivery_pdu_t), __FILE__, __LINE__)) == NULL)
			return MULP_OUT_OF_RESOURCES;
		d_pdu->number_of_chunks = 1;
		d_pdu->read_position = 0;
		d_pdu->read_chunk = 0;
		d_pdu->chunk_position = 0;
		d_pdu->total_length = dchunk->data_length;
		// ur chunk must not be segmented and so we can force cast it to delivery_data_t**
		d_pdu->ddata = (delivery_data_t**)dchunk;
		mdlm->ur_pduList.push_back(d_pdu);
	}
	else
	{
		EVENTLOG(NOTICE, "mdlm_assemble_ulp_data()::found segmented unreliable chunk");
		geco_free_ext(dchunk, __FILE__, __LINE__);
		geco_free_ext(d_pdu, __FILE__, __LINE__);
		msm_abort_channel(ECC_PROTOCOL_VIOLATION);
		return MULP_PROTOCOL_VIOLATION;
	}
	return MULP_SUCCESS;
}

/**
 *  indicates new data has arrived from peer (chapter 10.2.) destined for the ULP
 *
 *  @param streamID  received data belongs to this stream
 *  @param  length   so many bytes have arrived (may be used to reserve space)
 *  @param  protoID  the protocol ID of the arrived payload
 *  @param  unordered  unordered flag (true==1==unordered, false==0==normal,numbered chunk)
 */
void mdi_on_peer_data_arrive(int64 tsn, int streamID, int streamSN, uint length)
{
	if (curr_channel_ != NULL)
	{
		EVENTLOG4(VERBOSE, "mdi_dataArriveNotif(assoc %u, streamID %u, length %u, tsn %u)", curr_channel_->channel_id,
			streamID, length, streamSN);
		if (curr_geco_instance_->ulp_callbacks.dataArriveNotif != NULL)
		{
			curr_geco_instance_->ulp_callbacks.dataArriveNotif(curr_channel_->channel_id, streamID, length, streamSN, tsn,
				tsn < 0 ? 1 : 0, streamID < 0 ? 1 : 0, curr_channel_->ulp_dataptr);
		}
	}
}

void mdlm_deliver_ready_pdu(deliverman_controller_t* mdlm)
{
	// deliver ordered chunks
	for (uint i = 0; i < mdlm->numOrderedStreams; i++)
	{
		mdlm->recv_seq_streams[i].highestSSN = 0;
		mdlm->recv_seq_streams[i].highestSSNused = false;

		auto& prePduList = mdlm->recv_order_streams[i].prePduList;
		if (!prePduList.empty())
		{
			auto& pduList = mdlm->recv_order_streams[i].pduList;
			for (auto dpdu : prePduList)
			{
				pduList.push_back(dpdu);
				mdlm->queuedBytes -= dpdu->total_length;
				mdi_on_peer_data_arrive((dpdu->ddata[0]->chunk_flags & DCHUNK_FLAG_RELIABLE) ? dpdu->ddata[0]->tsn : -1, i,
					dpdu->ddata[0]->stream_sn, dpdu->total_length);
			}
			prePduList.clear();
		}
	}

	// deliver sequenced chunks
	for (uint i = 0; i < mdlm->numSequencedStreams; i++)
	{
		mdlm->recv_order_streams[i].highestSSN = 0;
		mdlm->recv_order_streams[i].highestSSNused = false;

		auto& prePduList = mdlm->recv_seq_streams[i].prePduList;
		if (!prePduList.empty())
		{
			auto& pduList = mdlm->recv_seq_streams[i].pduList;
			for (auto dpdu : prePduList)
			{
				pduList.push_back(dpdu);
				mdlm->queuedBytes -= dpdu->total_length;
				mdi_on_peer_data_arrive((dpdu->ddata[0]->chunk_flags & DCHUNK_FLAG_RELIABLE) ? dpdu->ddata[0]->tsn : -1, i,
					dpdu->ddata[0]->stream_sn, dpdu->total_length);
			}
			prePduList.clear();
		}
	}

	// deliver unsequenced and unordered chunks
	for (auto dpdu : mdlm->ur_pduList)
	{
		mdlm->queuedBytes -= dpdu->total_length;
		mdi_on_peer_data_arrive(-1, -1, -1, dpdu->total_length);
	}
	for (auto dpdu : mdlm->r_pduList)
	{
		mdlm->queuedBytes -= dpdu->total_length;
		mdi_on_peer_data_arrive(((delivery_data_t*)(dpdu->ddata))->tsn, -1, -1, dpdu->total_length);
	}

	recv_controller_t* mrecv = mdi_read_mrecv();
	assert(mrecv != NULL);
	// update curr rwnd
	current_rwnd = mdlm->queuedBytes >= mrecv->my_rwnd ? 0 : mrecv->my_rwnd - mdlm->queuedBytes;
	// MAX_PACKET_PDU is constant no matter it is udp-tunneled or not
	// advertising rwnd to sender for avoiding silly window syndrome (SWS),
	if (current_rwnd > 0 && current_rwnd <= 2 * MAX_PACKET_PDU)
		current_rwnd = 1;
	// update arwnd tp prepare for creation of sack chunk in mrecv_create_sack()
	mrecv->sack_chunk->sack_fixed.a_rwnd = htonl(current_rwnd);
}

/*
 * All packets of the same ordering type are ordered relative to each other.
 * stream-id is used for relative ordering of packets in relation to other packets on the same stream
 * Packets in sequence drop older packets.
 *
 * Lets say you send data 1,2,3,4,5,6.
 * Here's the order and substance of what you might get back:
 *
 * UNRELIABLE - 5, 1, 6
 * RELIABLE - 5, 1, 4, 6, 2, 3
 *
 * UNRELIABLE_SEQUENCED - 5 (6 was lost in transit, 1,2,3,4 arrived later than 5)
 * RELIABLE_ORDERED - 1, 2, 3, 4, 5, 6
 * RELIABLE_SEQUENCED - 1,2,3,4 arrived later than 5, first receive 5, 6, then received 1,2,3,4)
 *
 * tsn: 0  12 345 6  89
 *      ro rs ro  ur rs
 * sid: 1  0  1   -  0
 * ssn: 1  3  0   -  2
 *
 * recv_order_streams[sid].preList.insert(dpdu,upper);
 * recv_sequenced_streams[sid].preList.insert(dpdu,upper);
 *
 * ro sid 1 = 0,1
 * rs sid 0 = 2,3
 *
 * done !
 *
 * there are two more streams for ur and r chunks in default
 * so total number of streams = sequenced_streams+order_streams+2
 *
 * 	@note ur and urs chunk are processed in mdlm_process_data_chunk() by delivering to ulp directly
 */
int mdlm_search_ready_pdu(deliverman_controller_t* mdlm)
{
	static delivery_pdu_t* d_pdu;
	static delivery_data_t* d_chunk;
	static uint firstTSN;
	static ushort currentSID;
	static ushort currentSSN;
	static ushort currentTSN;
	static ushort nrOfChunks;
	static bool unordered;
	static bool complete;
	static uint i;
	static uint itemPosition;
	static std::list<delivery_data_t*>::iterator firstItemItr;
	static recv_stream_t* recv_streams;

	i = firstTSN = itemPosition = 0;
	complete = false;
	currentSID = currentSSN = nrOfChunks = 0;

	// search complete pdu from ro chunk list
	for (auto itr = mdlm->ro.begin(); itr != mdlm->ro.end();)
	{
		d_chunk = *itr;
		currentSID = d_chunk->stream_id;
		recv_streams = &mdlm->recv_order_streams[currentSID];
		EVENTLOG3(VERBOSE, "Handling ro chunk with tsn: %u, ssn: %u, sid: %u", currentTSN, currentSSN, currentSID);

		//  increment tsn by one for each data chunk in the packet  and use it to fill tsn field
		// also increment some stream's ssn by one for each data chunk in packet and ure it to fill ssn field
		// thus, all tsns and ssns in this packet MUST be in ascend order. if not, peer's stack impl is not compatiable with with us
		if (recv_streams->highestSSNused && safter(recv_streams->highestSSN, currentSSN))
		{
			EVENTLOG(NOTICE, "mdlm_assemble_ulp_data()::wrong ssn");
			msm_abort_channel(ECC_PROTOCOL_VIOLATION);
			return MULP_PROTOCOL_VIOLATION;
		}
		recv_streams->highestSSN = currentSSN;
		recv_streams->highestSSNused = true;

		currentTSN = d_chunk->tsn;
		currentSSN = d_chunk->stream_sn;

		// start assemble fragmented ulp msg
		if (d_chunk->chunk_flags & DCHUNK_FLAG_FIRST_FRAG)
		{
			EVENTLOG(VVERBOSE, "mdlm_assemble_ulp_data()::found begin segment from mdlm->ro");

			nrOfChunks = 1;
			firstItemItr = itr;
			firstTSN = d_chunk->tsn;

			if ((sbefore(currentSSN, recv_streams->nextSSN) || currentSSN == recv_streams->nextSSN))
			{
				if (d_chunk->chunk_flags & DCHUNK_FLAG_LAST_FRG)
				{
					// frg 4567
					// 32678 0 1 2
					// tsn 1 2 457
					// ssn 0 1 666 2 0
					// sid  0 0 000
					// nextSSN is initially set to 0, currentSSN = 0
					// sbefore(0,0) false || 0==0 true =>true
					// DCHUNK_FLAG_LAST_FRG true =>
					EVENTLOG(VVERBOSE, "Complete PDU found");
					complete = true;
				}

				// find and reassemble segmented chunks
				while (!complete)
				{
					++itr;
					if (itr == mdlm->ro.end())
						break;

					d_chunk = *itr;
					nrOfChunks++;

					if (d_chunk->stream_id == currentSID && d_chunk->stream_sn == currentSSN
						&& d_chunk->tsn == firstTSN + nrOfChunks - 1)
					{
						// tsn 1 2 34
						// ssn 2 1 00
						// sid  0 1 00
						// nextSSN is initially set to 0, currentSSN = 0
						// loop1: sbefore(2,0) false || 2==0 false =>false
						// loop2: sbefore(1,0) false || 1==0 false =>false
						// loop3: sbefore(0,0) false || 0==0 true =>true
						// !completed =>
						// currentTSN = 3,    currentSID = 0,                currentSSN = 0
						// d_chunk->tsn = 4,d_chunk->stream_id=0,  d_chunk->stream_sn=0
						// firstTSn3 + nrOfChunks2 -1 == d_chunk->tsn = 4 => true
						//
						if (d_chunk->chunk_flags & DCHUNK_FLAG_FIRST_FRAG)
						{
							EVENTLOG1(NOTICE, "Multiple Begin segment chunk found with SSN: %u", d_chunk->stream_sn);
							msm_abort_channel(ECC_PROTOCOL_VIOLATION);
							return MULP_PROTOCOL_VIOLATION;
						}
						if (!(d_chunk->chunk_flags & DCHUNK_FLAG_ORDER))
						{
							EVENTLOG1(NOTICE, "Mix Ordered and unordered Segments found with SSN: %u", d_chunk->stream_sn);
							msm_abort_channel(ECC_PROTOCOL_VIOLATION);
							return MULP_PROTOCOL_VIOLATION;
						}
						if (d_chunk->chunk_flags & DCHUNK_FLAG_LAST_FRG)
						{
							EVENTLOG(VVERBOSE, "Complete segmented PDU found");
							complete = true;
						}
					}
					else
					{
						if (d_chunk->tsn == firstTSN + nrOfChunks - 1)
						{
							// tsn-cotinueus segments must have same ssn and sid. if not, send abort
							EVENTLOG1(NOTICE, "tsn-cotinueus segment found but with different ssn or sid", d_chunk->stream_sn);
							msm_abort_channel(ECC_PROTOCOL_VIOLATION);
							return MULP_PROTOCOL_VIOLATION;
						}

						// segments tsn not continueus, wait for the missing segment coming later
						EVENTLOG(VERBOSE, "have to wait for more segements to reassemble  segments");
						break;
					}
				}

				// found an completed pdu
				if (complete)
				{
					if ((d_pdu = (delivery_pdu_t*)geco_malloc_ext(sizeof(delivery_pdu_t), __FILE__, __LINE__)) == NULL)
						return MULP_OUT_OF_RESOURCES;

					d_pdu->number_of_chunks = nrOfChunks;
					d_pdu->read_position = 0;
					d_pdu->read_chunk = 0;
					d_pdu->chunk_position = 0;
					d_pdu->total_length = 0;

					if ((d_pdu->ddata = (delivery_data_t**)geco_malloc_ext(nrOfChunks * sizeof(delivery_data_t*), __FILE__,
						__LINE__)) == NULL)
					{
						geco_free_ext(d_pdu, __FILE__, __LINE__);
						return MULP_OUT_OF_RESOURCES;
					}

					// remove complete chunk(s) from rchunks list and append them to this pdu's ddata
					for (i = 0, itr = firstItemItr; i < nrOfChunks; i++)
					{
						d_pdu->ddata[i] = *itr;
						d_pdu->total_length += d_pdu->ddata[i]->data_length;
						mdlm->ro.erase(itr++);
					}
					assert(std::distance(firstItemItr, itr) == nrOfChunks - 1);

					// insert this pdu to prepdu list and update ssn if possible
					// ddata stored all segmented chunks that have same sid
					// so we use ddata[0]->stream_id to locate the stream
					// all pdus in prePduList are continueous and ordered by ssn
					recv_streams->prePduList.push_back(d_pdu);

					// nextSSN++ is the value of expected ordered dchunks's ssn
					if (recv_streams->nextSSN == currentSSN)
						recv_streams->nextSSN++;
					complete = false;
				}

				// this chunk is not completed, wait more segements coming to us
			}
			// buff this chunk in the ro list for furture ordering
		}
		else
		{
			// if we are here,  middle or last segmented chunk found,
			// should wait for more segs coming to us
			// cotinue to process next chunk
			++itr;
		}
	}
	// search complete pdu from rs  list
	for (auto itr = mdlm->rs.begin(); itr != mdlm->rs.end();)
	{
		d_chunk = *itr;
		currentSID = d_chunk->stream_id;
		recv_streams = &mdlm->recv_order_streams[currentSID];
		EVENTLOG3(VERBOSE, "Handling rs chunk with tsn: %u, ssn: %u, sid: %u", currentTSN, currentSSN, currentSID);

		if (recv_streams->highestSSNused && safter(recv_streams->highestSSN, currentSSN))
		{
			EVENTLOG(NOTICE, "mdlm_assemble_ulp_data()::wrong ssn");
			msm_abort_channel(ECC_PROTOCOL_VIOLATION);
			return MULP_PROTOCOL_VIOLATION;
		}
		recv_streams->highestSSN = currentSSN;
		recv_streams->highestSSNused = true;

		currentTSN = d_chunk->tsn;
		currentSSN = d_chunk->stream_sn;

		// start assemble fragmented ulp msg
		if (d_chunk->chunk_flags & DCHUNK_FLAG_FIRST_FRAG)
		{
			EVENTLOG(VVERBOSE, "mdlm_assemble_ulp_data()::found begin segment from mdlm->ro");

			nrOfChunks = 1;
			firstItemItr = itr;
			firstTSN = d_chunk->tsn;

			if (safter(currentSSN, recv_streams->nextSSN) || currentSSN == recv_streams->nextSSN)
			{
				if (d_chunk->chunk_flags & DCHUNK_FLAG_LAST_FRG)
				{
					EVENTLOG(VVERBOSE, "Complete PDU found");
					complete = true;
				}

				// find and reassemble segmented chunks
				while (!complete)
				{
					++itr;
					if (itr == mdlm->ro.end())
						break;

					d_chunk = *itr;
					nrOfChunks++;

					if (d_chunk->stream_id == currentSID && d_chunk->stream_sn == currentSSN
						&& d_chunk->tsn == firstTSN + nrOfChunks - 1)
					{
						if (d_chunk->chunk_flags & DCHUNK_FLAG_FIRST_FRAG)
						{
							EVENTLOG1(NOTICE, "Multiple Begin segment chunk found with SSN: %u", d_chunk->stream_sn);
							msm_abort_channel(ECC_PROTOCOL_VIOLATION);
							return MULP_PROTOCOL_VIOLATION;
						}
						if (!(d_chunk->chunk_flags & DCHUNK_FLAG_ORDER))
						{
							EVENTLOG1(NOTICE, "Mix Ordered and unordered Segments found with SSN: %u", d_chunk->stream_sn);
							msm_abort_channel(ECC_PROTOCOL_VIOLATION);
							return MULP_PROTOCOL_VIOLATION;
						}
						if (d_chunk->chunk_flags & DCHUNK_FLAG_LAST_FRG)
						{
							EVENTLOG(VVERBOSE, "Complete segmented PDU found");
							complete = true;
						}
					}
					else
					{
						if (d_chunk->tsn == firstTSN + nrOfChunks - 1)
						{
							// tsn-cotinueus segments must have same ssn and sid. if not, send abort
							EVENTLOG1(NOTICE, "tsn-cotinueus segment found but with different ssn or sid", d_chunk->stream_sn);
							msm_abort_channel(ECC_PROTOCOL_VIOLATION);
							return MULP_PROTOCOL_VIOLATION;
						}

						// segments tsn not continueus, wait for the missing segment coming later
						EVENTLOG(VERBOSE, "have to wait for more segements to reassemble  segments");
						break;
					}
				}

				// found an completed pdu
				if (complete)
				{
					if ((d_pdu = (delivery_pdu_t*)geco_malloc_ext(sizeof(delivery_pdu_t), __FILE__, __LINE__)) == NULL)
						return MULP_OUT_OF_RESOURCES;

					d_pdu->number_of_chunks = nrOfChunks;
					d_pdu->read_position = 0;
					d_pdu->read_chunk = 0;
					d_pdu->chunk_position = 0;
					d_pdu->total_length = 0;

					if ((d_pdu->ddata = (delivery_data_t**)geco_malloc_ext(nrOfChunks * sizeof(delivery_data_t*), __FILE__,
						__LINE__)) == NULL)
					{
						geco_free_ext(d_pdu, __FILE__, __LINE__);
						return MULP_OUT_OF_RESOURCES;
					}

					// remove complete chunk(s) from rchunks list and append them to this pdu's ddata
					for (i = 0, itr = firstItemItr; i < nrOfChunks; i++)
					{
						d_pdu->ddata[i] = *itr;
						d_pdu->total_length += d_pdu->ddata[i]->data_length;
						mdlm->ro.erase(itr++);
					}
					assert(std::distance(firstItemItr, itr) == nrOfChunks - 1);

					recv_streams->prePduList.push_back(d_pdu);
					// nextSSN+1 is the value of expected ordered dchunks's ssn
					recv_streams->nextSSN = currentSSN + 1;
					complete = false;
				}
			}
			else
			{
				// always drop earlier sequenced chunk
				// we first drop the first seg then others behind it if existing
				mdlm->rs.erase(itr++);
				while (itr != mdlm->ro.end())
				{
					d_chunk = *itr;
					if (d_chunk->stream_id == currentSID && d_chunk->stream_sn == currentSSN)
					{
						if (d_chunk->chunk_flags & DCHUNK_FLAG_FIRST_FRAG)
						{
							EVENTLOG1(NOTICE, "Multiple Begin segment chunk found with SSN: %u", d_chunk->stream_sn);
							msm_abort_channel(ECC_PROTOCOL_VIOLATION);
							return MULP_PROTOCOL_VIOLATION;
						}
						if (!(d_chunk->chunk_flags & DCHUNK_FLAG_ORDER))
						{
							EVENTLOG1(NOTICE, "Mix Ordered and unordered Segments found with SSN: %u", d_chunk->stream_sn);
							msm_abort_channel(ECC_PROTOCOL_VIOLATION);
							return MULP_PROTOCOL_VIOLATION;
						}
						mdlm->rs.erase(itr++);
					}
					else
					{
						// we have drop all segs for this earlier chunk
						// so we break while loop and cotinue to process next chunk
						++itr;
						break;
					}
				}
			}
		}
		else
		{
			// if we are here,  middle or last segmented chunk found,
			// should wait for more segs coming to us
			// cotinue to process next chunk
			++itr;
		}
	}
	// search complete pdu from r  list
	for (auto itr = mdlm->r.begin(); itr != mdlm->r.end();)
	{
		d_chunk = *itr;
		EVENTLOG3(VERBOSE, "Handling r chunk with tsn: %u, ssn: %u, sid: %u", currentTSN, currentSSN, currentSID);

		// start assemble fragmented ulp msg
		if (d_chunk->chunk_flags & DCHUNK_FLAG_FIRST_FRAG)
		{
			EVENTLOG(VVERBOSE, "mdlm_assemble_ulp_data()::found begin segment from mdlm->ro");

			nrOfChunks = 1;
			firstItemItr = itr;
			firstTSN = d_chunk->tsn;

			if (d_chunk->chunk_flags & DCHUNK_FLAG_LAST_FRG)
			{
				EVENTLOG(VVERBOSE, "Complete PDU found");
				complete = true;
			}

			// find and reassemble segmented chunks
			while (!complete)
			{
				++itr;
				if (itr == mdlm->ro.end())
					break;

				d_chunk = *itr;
				nrOfChunks++;

				if (d_chunk->stream_id == currentSID && d_chunk->stream_sn == currentSSN)
				{
					if (d_chunk->chunk_flags & DCHUNK_FLAG_FIRST_FRAG)
					{
						EVENTLOG1(NOTICE, "Multiple Begin segment chunk found with SSN: %u", d_chunk->stream_sn);
						msm_abort_channel(ECC_PROTOCOL_VIOLATION);
						return MULP_PROTOCOL_VIOLATION;
					}
					if (!(d_chunk->chunk_flags & DCHUNK_FLAG_ORDER))
					{
						EVENTLOG1(NOTICE, "Mix Ordered and unordered Segments found with SSN: %u", d_chunk->stream_sn);
						msm_abort_channel(ECC_PROTOCOL_VIOLATION);
						return MULP_PROTOCOL_VIOLATION;
					}
					if (d_chunk->chunk_flags & DCHUNK_FLAG_LAST_FRG)
					{
						EVENTLOG(VVERBOSE, "Complete segmented PDU found");
						complete = true;
					}
				}
				else
				{
					if (d_chunk->tsn == firstTSN + nrOfChunks - 1)
					{
						// tsn-cotinueus segments must have same ssn and sid. if not, send abort
						EVENTLOG1(NOTICE, "tsn-cotinueus segment found but with different ssn or sid", d_chunk->stream_sn);
						msm_abort_channel(ECC_PROTOCOL_VIOLATION);
						return MULP_PROTOCOL_VIOLATION;
					}
					// segments tsn not continueus, wait for the missing segment coming later
					EVENTLOG(VERBOSE, "have to wait for more segements to reassemble  segments");
					break;
				}
			}

			// found an completed pdu
			if (complete)
			{
				if ((d_pdu = (delivery_pdu_t*)geco_malloc_ext(sizeof(delivery_pdu_t), __FILE__, __LINE__)) == NULL)
					return MULP_OUT_OF_RESOURCES;

				d_pdu->number_of_chunks = nrOfChunks;
				d_pdu->read_position = 0;
				d_pdu->read_chunk = 0;
				d_pdu->chunk_position = 0;
				d_pdu->total_length = 0;

				if ((d_pdu->ddata = (delivery_data_t**)geco_malloc_ext(nrOfChunks * sizeof(delivery_data_t*), __FILE__,
					__LINE__)) == NULL)
				{
					geco_free_ext(d_pdu, __FILE__, __LINE__);
					return MULP_OUT_OF_RESOURCES;
				}

				// remove complete chunk(s) from rchunks list and append them to this pdu's ddata
				for (i = 0, itr = firstItemItr; i < nrOfChunks; i++)
				{
					d_pdu->ddata[i] = *itr;
					d_pdu->total_length += d_pdu->ddata[i]->data_length;
					mdlm->ro.erase(itr++);
				}
				assert(std::distance(firstItemItr, itr) == nrOfChunks - 1);

				// insert this pdu to prepdu list and update ssn if possible
				// ddata stored all segmented chunks that have same sid
				// so we use ddata[0]->stream_id to locate the stream
				// all pdus in prePduList are continueous and ordered by ssn
				recv_streams->prePduList.push_back(d_pdu);
				complete = false;
			}

			// this chunk is not completed, wait more segements coming to us
		}
		else
		{
			// if we are here,  middle or last segmented chunk found,
			// should wait for more segs coming to us
			// cotinue to process next chunk
			++itr;
		}
	}

	return 1;
}

/*
 * function that gets chunks from the Lists, transforms them to PDUs, puts them
 * to the pduList, and calls DataArrive-Notification
 */
int mdlm_notify_data_arrive()
{
	deliverman_controller_t* mdlm = mdi_read_mdlm();
	assert(mdlm != NULL);
	int retval = mdlm_search_ready_pdu(mdlm);
	if (retval == MULP_SUCCESS)
		mdlm_deliver_ready_pdu(mdlm);
	return retval;
}

int mrecv_process_data_chunk(data_chunk_t * data_chunk, uint ad_idx)
{
	static uint chunk_tsn;
	static uint chunk_len;
	static uint assoc_state;
	static bool bubbleup_ctsna;
	static uint bytes_queued;
	static recv_controller_t* mrecv;
	static smctrl_t* msm;
	static uchar chunk_flag;
	static deliverman_controller_t* mdlm;

	mdlm = mdi_read_mdlm();
	assert(mdlm != NULL);

	//resettings
	bubbleup_ctsna = false;
	msm = mdi_read_smctrl();
	assert(msm != NULL);
	assoc_state = msm->channel_state;
	mrecv = mdi_read_mrecv();
	assert(mrecv != NULL);
	mrecv->new_chunk_received = false;
	mrecv->last_address = ad_idx;

	// update curr rwnd
	bytes_queued = mdlm_read_queued_bytes();
	current_rwnd = bytes_queued >= mrecv->my_rwnd ? 0 : mrecv->my_rwnd - bytes_queued;

	// MAX_PACKET_PDU is constant no matter it is udp-tunneled or not
	// advertising rwnd to sender for avoiding silly window syndrome (SWS),
	if (current_rwnd > 0 && current_rwnd <= 2 * MAX_PACKET_PDU)
		current_rwnd = 1;

	// if any received data chunks have not been acked, create a SACK and bundle it with the outbound data
	mrecv->sack_updated = false;

	chunk_flag = ((chunk_fixed_t*)data_chunk)->chunk_flags;
	chunk_len = ntohs(data_chunk->comm_chunk_hdr.chunk_length);

	if (chunk_flag & DCHUNK_FLAG_RELIABLE)
	{
		chunk_tsn = ntohl(data_chunk->data_chunk_hdr.trans_seq_num);
		if ((current_rwnd == 0 && uafter(chunk_tsn, mrecv->highest_tsn)) || assoc_state == ChannelState::ShutdownReceived
			|| assoc_state == ChannelState::ShutdownAckSent)
		{
			// drop data chunk when:
			// 1.our rwnd is 0 and chunk_tsn is higher than current highest_duplicated_tsn
			// if chunk_tsn is lower, we should drop the buffered highest and buffer this chunk_tsn
			// 2.we are ShutdownAckSent state: we have acked all queued data chunks that peer has sent to us.
			// should have no chunks in flight and in peer's queue
			// 3.we are in ShutdownReceived state: we have received and processed all peer's queued chunks, shoul nt receive any more chunks
			mrecv->new_chunk_received = false;
			return 1;
		}

		EVENTLOG2(VERBOSE, "mrecv_process_data_chunk()::chunk_tsn %u, chunk_len %u", chunk_tsn, chunk_len);
		if (mrecv_before_lowest_duptsn(mrecv, chunk_tsn))
			// lower than the lowest_duplicated_tsn one received so far,it must be dup
			mrecv_update_duplicates(mrecv, chunk_tsn);
		else if (mrecv_after_highest_tsn(mrecv, chunk_tsn))
		{
			// higher than the highest_tsn received so far,it must be new chunk
			bubbleup_ctsna = mrecv_update_fragments(mrecv, chunk_tsn);
			assert(mrecv->new_chunk_received == true);
			assert(bubbleup_ctsna == true);
		}
		else if (mrecv_chunk_is_duplicate(mrecv, chunk_tsn))
			mrecv_update_duplicates(mrecv, chunk_tsn);
		else
			bubbleup_ctsna = mrecv_update_fragments(mrecv, chunk_tsn);

		if (bubbleup_ctsna)
			mrecv_bubbleup_ctsna(mrecv);

		if (mrecv->new_chunk_received)
		{
			if ((chunk_flag & DCHUNK_FLAG_OS_MASK) == (DCHUNK_FLAG_UNORDER | DCHUNK_FLAG_UNSEQ))
			{
				if (mdlm_process_data_chunk(mdlm, (dchunk_r_t*)data_chunk, chunk_len, ad_idx) == MULP_SUCCESS)
					mrecv->new_chunk_received = false;
			}
			else
			{
				if (mdlm_process_data_chunk(mdlm, (data_chunk_t*)data_chunk, chunk_len, ad_idx) == MULP_SUCCESS)
					mrecv->new_chunk_received = false;
			}
		}
		else
		{
			/* TODO :  Duplicates : see Note in section 6.2 :
			 Note: When a datagram arrives with duplicate DATA chunk(s) and no new
			 DATA chunk(s), the receiver MUST immediately send a SACK with no
			 delay. Normally this will occur when the original SACK was lost, and
			 the peers RTO has expired. The duplicate TSN number(s) SHOULD be
			 reported in the SACK as duplicate. */
		}
	}
	else
	{
		// there is no retx for unreliable chunk, so any chunks received are treated as "new chunk"
		mrecv->new_chunk_received = true;

		// deliver to reordering function for further processing
		if (current_rwnd == 0 || assoc_state == ChannelState::ShutdownReceived
			|| assoc_state == ChannelState::ShutdownAckSent)
		{
			// drop data chunk when:
			// 1.our rwnd is 0 and chunk_tsn is higher than current highest_duplicated_tsn
			// if chunk_tsn is lower, we should drop the buffered highest and buffer this chunk_tsn
			// 2.we are ShutdownAckSent state: we have acked all queued data chunks that peer has sent to us.
			// should have no chunks in flight and in peer's queue
			// 3.we are in ShutdownReceived state: we have received and processed all peer's queued chunks,
			// shoul nt receive any more chunks
			mrecv->new_chunk_received = false;
			return 1;
		}

		// if unreliable mesg  is framented in sender, the fragmented chunks are sent as reliable
		// and (ordered or unordered same to original msg).
		// so right here, we can safely bypass assembling and reliabling function
		if (mrecv->new_chunk_received)
		{
			if (chunk_flag & DCHUNK_FLAG_UNSEQ)
			{ // unsequenced & unreliable chunk
				if (mdlm_process_data_chunk(mdlm, (dchunk_ur_t*)data_chunk, chunk_len, ad_idx) == MULP_SUCCESS)
					mrecv->new_chunk_received = false;
			}
			else
			{ // sequenced & unreliable chunk
				if (mdlm_process_data_chunk(mdlm, (dchunk_urs_t*)data_chunk, chunk_len, ad_idx) == MULP_SUCCESS)
					mrecv->new_chunk_received = false;
			}
		}
	}

	return 1;
}

int msm_process_init_chunk(init_chunk_t * init)
{
#if defined(_DEBUG)
	EVENTLOG(VERBOSE, "- - - - Enter msm_process_init_chunk() - - -");
#endif

	/*1) put init chunk into chunk  array */
	int ret = 0;
	uchar init_cid = mch_make_simple_chunk((simple_chunk_t*)init);
	if (mch_read_chunkid(init_cid) != CHUNK_INIT)
	{
		ERRLOG(MAJOR_ERROR, "1) put init chunk into chunk  array : [wrong chunk type]");
		mch_remove_simple_chunk(init_cid);
		return STOP_PROCESS_CHUNK_FOR_WRONG_CHUNK_TYPE;
	}

	/*2) validate init geco_instance_params*/
	uchar abortcid;
	smctrl_t* smctrl = mdi_read_smctrl();
	if (!mch_read_ordered_streams(init_cid) || !mch_read_sequenced_streams(init_cid) || !mch_read_itag(init_cid))
	{
		EVENTLOG(DEBUG, "2) validate init geco_instance_params [zero streams  or zero init TAG] -> send abort ");

		/*2.1) make and send ABORT with ecc*/
		abortcid = mch_make_simple_chunk(CHUNK_ABORT, FLAG_TBIT_UNSET);
		mch_write_error_cause(abortcid, ECC_INVALID_MANDATORY_PARAM);

		mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abortcid));
		mch_free_simple_chunk(abortcid);

		mdi_unlock_bundle_ctrl();
		mdi_send_bundled_chunks();

		/*2.2) delete all data of this channel,
		 * smctrl != NULL means current channel MUST exist at this moment */
		if (smctrl != NULL)
		{
			mdi_delete_curr_channel();
			mdi_on_disconnected(ConnectionLostReason::InvalidParam);
			mdi_clear_current_channel();
		}
		return STOP_PROCESS_CHUNK_FOR_INVALID_MANDORY_INIT_PARAMS;
	}

	/*3) validate source addr */
	if (last_source_addr_ == NULL)
	{
		/* 3.1) delete all data of this channel,
		 * smctrl != NULL means current channel MUST exist at this moment */
		if (smctrl == NULL)
		{
			mdi_clear_current_channel();
			return STOP_PROCESS_CHUNK_FOR_NULL_CHANNEL;
		}
		else
		{
			if (smctrl->init_timer_id != NULL)
			{
				mtra_timeouts_del(smctrl->init_timer_id);
			}
			mdi_unlock_bundle_ctrl();
			mdi_delete_curr_channel();
			mdi_on_disconnected(ConnectionLostReason::InvalidParam);
			mdi_clear_current_channel();
			return STOP_PROCESS_CHUNK_FOR_NULL_SRC_ADDR;
		}
	}

	ushort ordered_streams;
	ushort sequenced_streams;
	uchar init_ack_cid;
	uint init_tag;

	/* 4) RFC 4960 - 5.1.Normal Establishment of an Association - (B)
	 * "Z" shall respond immediately with an INIT ACK chunk.*/
	if (smctrl == NULL)
	{
		EVENTLOG(INFO, "event: received normal init chunk from peer");

		/*4.1) get in stream number*/
		ordered_streams = mch_read_ordered_streams(init_cid);
		sequenced_streams = mch_read_sequenced_streams(init_cid);

		/* 4.2) alloc init ack chunk, init tag used as init tsn */
		init_tag = mdi_generate_itag();
		init_ack_cid = mch_make_init_ack_chunk(init_tag, curr_geco_instance_->default_myRwnd, ordered_streams,
			sequenced_streams, init_tag);

		/*4.3) read and validate peer addrlist carried in the received init chunk*/
		assert(my_supported_addr_types_ != 0);
		assert(curr_geco_packet_value_len_ == init->chunk_header.chunk_length);
		tmp_peer_addreslist_size_ = mdi_read_peer_addreslist(tmp_peer_addreslist_, (uchar*)init,
			curr_geco_packet_value_len_, my_supported_addr_types_, &tmp_peer_supported_types_, true, false);
		if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
		{
			EVENTLOG(NOTICE, "msm_process_init_chunk():: UNSUPPOTED ADDR TYPES -> send abort with tbit unset !");
			chunk_id_t abort_cid = mch_make_simple_chunk(CHUNK_ABORT,
				FLAG_TBIT_UNSET);
			const char* errstr = "peer does not supports your adress types !";
			mch_write_error_cause(abort_cid, ECC_PEER_NOT_SUPPORT_ADDR_TYPES, (uchar*)errstr, strlen(errstr) + 1);

			mdi_lock_bundle_ctrl();
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abort_cid));
			mch_free_simple_chunk(abort_cid);
			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();
			return discard;
		}

		/*4.4) get local addr list and append them to INIT ACK*/
		tmp_local_addreslist_size_ = mdi_validate_localaddrs_before_write_to_init(tmp_local_addreslist_, last_source_addr_,
			1, tmp_peer_supported_types_, true);
		if (tmp_local_addreslist_size_ > 1)
		{
			// if ==1 mus be last dest addr, as we will put it as src addr in outgoing ip header
			// so do not copy it to avoid repeated addr
			mch_write_vlp_addrlist(init_ack_cid, tmp_local_addreslist_, tmp_local_addreslist_size_);
		}

		// 4.5) generate and append cookie to INIT ACK
		mch_write_cookie(init_cid, init_ack_cid, mch_read_init_fixed(init_cid), mch_read_init_fixed(init_ack_cid),
			mch_read_cookie_preserve(init_cid, ignore_cookie_life_spn_from_init_chunk_, msm_get_cookielife()),
			/* normal case: no existing channel, set both zero*/
			0, /*local tie tag*/
			0,/*local tie tag*/
			last_dest_port_, last_src_port_, tmp_local_addreslist_, tmp_local_addreslist_size_,
			do_we_support_unreliability(), do_we_support_addip(), tmp_peer_addreslist_, tmp_peer_addreslist_size_);

		/* 4.6) check unrecognized geco_instance_params*/
		int ret = mch_validate_init_vlps(init_cid, init_ack_cid);
		// rfc 4960 p21 in 4 cases init ack and cookie echo is sent
		if (ret < 0)
		{
			// peer's init chunk has icorrect chunk length -> discard
			mch_free_simple_chunk(init_ack_cid);
		}
		else
		{
			// send all bundled chunks to ensure init ack is the only chunk sent in the whole geco packet
#ifdef  _DEBUG
			EVENTLOG(DEBUG,
				"process_init_acke():: call send_bundled_chunks to ensure init ack is the only chunk sent in the whole geco packet ");
#endif
			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();

			/* bundle INIT ACK if full will send, may empty bundle and copy init ack*/
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(init_ack_cid));
			mdi_send_bundled_chunks();  // send init ack
			mch_free_simple_chunk(init_ack_cid);
			EVENTLOG(INFO, "event: sent normal init ack chunk peer");
		}
	}
	else  // existing channel found
	{
		/* the below codes handle the following cases:
		 5.2.1.  INIT Received in COOKIE-WAIT or COOKIE-ECHOED State
		 5.2.2. Unexpected INIT in States Other than CLOSED,COOKIE-ECHOED COOKIE-WAIT, and SHUTDOWN-ACK-SENT
		 5.2.4. Handle a COOKIE ECHO when a TCB Exists */

		ChannelState channel_state = smctrl->channel_state;
		ushort primary_path = mpath_read_primary_path();
		uint init_i_sent_cid;

		/* 5)
		 5.2.1.INIT Received in COOKIE-WAIT or COOKIE-ECHOED State  (Item B)
		 When responding in either state (COOKIE-WAIT or COOKIE-ECHOED) with
		 an INIT ACK, the original parameters are combined with those from the newly received INIT chunk.
		 The endpoint shall also generate a State Cookie with the INIT ACK.
		 The endpoint uses the parameters sent in its INIT to calculate the State Cookie.
		 After that, the endpoint MUST NOT change its state, the T1-init timer
		 shall be left running, and the corresponding TCB MUST NOT be
		 destroyed.  The normal procedures for handling State Cookies when a
		 TCB exists will resolve the duplicate INITs to a single association. */
		if (channel_state == ChannelState::CookieWait)
		{
			/* section 5.2.1 - paragrah 2
			 Upon receipt of an INIT in the COOKIE-WAIT state, an endpoint MUST
			 respond with an INIT ACK using the same parameters it sent in its
			 original INIT chunk (including its Initiate Tag, unchanged).  When
			 responding, the endpoint MUST send the INIT ACK back to the same
			 address that the original INIT (sent by this endpoint) was sent.*/
#ifdef  _DEBUG
			EVENTLOG(DEBUG,
				"******************************* RECEIVE OOTB INIT CHUNK AT Cookie Wait *******************************");
#endif

			// both tie tags of zero value indicates that connection procedures are not done completely.
			// in other words, we are not connected to Z side although channel is not null
			assert(smctrl->local_tie_tag == 0);
			assert(smctrl->peer_tie_tag == 0);
			assert(curr_channel_->local_tag != 0);
			assert(curr_channel_->remote_tag == 0);

			// make init ack with geco_instance_params from init chunk I sent
			uint itag = ntohl(smctrl->my_init_chunk->init_fixed.init_tag);
			uint rwnd = ntohl(smctrl->my_init_chunk->init_fixed.rwnd);
			ushort ordered_streams = ntohs(smctrl->my_init_chunk->init_fixed.ordered_streams);
			ushort sequenced_streams = ntohs(smctrl->my_init_chunk->init_fixed.sequenced_streams);
			uint itsn = ntohl(smctrl->my_init_chunk->init_fixed.initial_tsn);
			init_ack_cid = mch_make_init_ack_chunk(itag, rwnd, ordered_streams, sequenced_streams, itsn);

#ifdef  _DEBUG
			EVENTLOG5(DEBUG, "INIT ACK CHUNK [itag=%d,rwnd=%d,itsn=%d,ordered_streams=%d,sequenced_streams=%d]", itag, rwnd,
				itsn, ordered_streams, sequenced_streams);
#endif

			tmp_peer_addreslist_size_ = mdi_read_peer_addreslist(tmp_peer_addreslist_, (uchar*)init,
				curr_geco_packet_value_len_, my_supported_addr_types_, &tmp_peer_supported_types_, true, false);

			// append localaddrlist to INIT_ACK
			tmp_local_addreslist_size_ = mdi_validate_localaddrs_before_write_to_init(tmp_local_addreslist_,
				tmp_peer_addreslist_, tmp_peer_addreslist_size_, tmp_peer_supported_types_, true /*receivedfrompeer*/);
			mch_write_vlp_addrlist(init_ack_cid, tmp_local_addreslist_, tmp_local_addreslist_size_);

			// generate cookie and append it to INIT ACK
			init_chunk_fixed_t* init_chunk_fixed = mch_read_init_fixed(init_cid);
			init_chunk_fixed_t* init_ack_chunk_fixed = mch_read_init_fixed(init_ack_cid);
			int cokkielife = msm_get_cookielife();
			int newcookielife = mch_read_cookie_preserve(init_cid, ignore_cookie_life_spn_from_init_chunk_, cokkielife);
			bool spre = do_we_support_unreliability();
			bool saddip = do_we_support_addip();
			mch_write_cookie(init_cid, init_ack_cid, init_chunk_fixed, init_ack_chunk_fixed, newcookielife, 0, 0,
				last_dest_port_, last_src_port_, tmp_local_addreslist_, tmp_local_addreslist_size_, spre, saddip,
				tmp_peer_addreslist_, tmp_peer_addreslist_size_);

			/* 6.8) check unrecognized geco_instance_params*/
			ret = mch_validate_init_vlps(init_cid, init_ack_cid);
			if (ret < 0 || ret == ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM)
			{
				/* 6.9) peer's init chunk has icorrect chunk length or
				 stop prcess when meeting unrecognized chunk type
				 both cases should not send init ack-> discard*/
				mch_free_simple_chunk(init_ack_cid);
			}
			else
			{
				/* 6.10) MUST send INIT ACK caried unknown geco_instance_params to the peer
				 * if he has unknown geco_instance_params in its init chunk
				 * as we SHOULD let peer's imple to finish the
				 * unnormal connection handling precedures*/

				 // send all bundled chunks to ensure init ack is the only chunk sent in the whole geco packet
				mdi_unlock_bundle_ctrl();
				mdi_send_bundled_chunks();

				// bundle INIT ACK if full will send and empty bundle then copy init ack
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(init_ack_cid));
				mdi_send_bundled_chunks(&smctrl->addr_my_init_chunk_sent_to);
				mch_free_simple_chunk(init_ack_cid);
				EVENTLOG(DEBUG, "****************** INIT ACK CHUNK  SENT AT COOKIE WAIT *********************");
			}
		}
		else if (channel_state == ChannelState::CookieEchoed)
		{
			/* section 5.2.1 - paragrah 3 and 6
			 - Upon receipt of an INIT in the COOKIE-ECHOED state, an endpoint MUST
			 respond with an INIT ACK using the same parameters it sent in its
			 original INIT chunk (including its Initiate Tag, unchanged), provided
			 that no NEW address has been added to the forming association.  If
			 the INIT message indicates that a new address has been added to the
			 association, then the entire INIT MUST be discarded, and NO changes
			 should be made to the existing association.  An ABORT SHOULD be sent
			 in response that MAY include the error 'Restart of an association
			 with new addresses'.  The error SHOULD list the addresses that were
			 added to the restarting association.
			 - For an endpoint that is in the COOKIE-ECHOED state, it MUST populate
			 its Tie-Tags within both the association TCB and inside the State
			 Cookie (see Section 5.2.2 for a description of the Tie-Tags).*/

#ifdef  _DEBUG
			EVENTLOG(DEBUG,
				"******************************* RECEIVE OOTB INIT CHUNK AT CookieEchoed %u *******************************");
#endif
			// because we have set up tie tags in process_init_ack() where :
			// smctrl->local_tie_tag is channel's local tag
			// smctrl->peer_tie_tag is the init tag carried in init ack
			assert(smctrl->local_tie_tag != 0);
			assert(smctrl->peer_tie_tag != 0);
			assert(curr_channel_->local_tag != 0);
			assert(curr_channel_->remote_tag != 0);
			assert(curr_channel_->local_tag == smctrl->local_tie_tag);
			assert(curr_channel_->remote_tag == smctrl->peer_tie_tag);

			// 5.2) validate no new addr aaded from the newly received INIT
			// read and validate peer addrlist carried in the received init chunk
			assert(my_supported_addr_types_ != 0);
			assert(curr_geco_packet_value_len_ == init->chunk_header.chunk_length);
			tmp_peer_addreslist_size_ = mdi_read_peer_addreslist(tmp_peer_addreslist_, (uchar*)init,
				curr_geco_packet_value_len_, my_supported_addr_types_, &tmp_peer_supported_types_, true, false);
			if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
			{
				EVENTLOG(NOTICE, "msm_process_init_chunk():: UNSUPPOTED ADDR TYPES -> send abort with tbit unset !");
				chunk_id_t abort_cid = mch_make_simple_chunk(CHUNK_ABORT,
					FLAG_TBIT_UNSET);
				const char* errstr = "peer does not supports your adress types !";
				mch_write_error_cause(abort_cid,
					ECC_PEER_NOT_SUPPORT_ADDR_TYPES, (uchar*)errstr, strlen(errstr) + 1);
				mdi_lock_bundle_ctrl();
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abort_cid));
				mch_free_simple_chunk(abort_cid);
				mdi_unlock_bundle_ctrl();
				mdi_send_bundled_chunks();
				return discard;
			}

			/*compare if there is new addr presenting*/
			for (uint idx = 0; idx < curr_channel_->remote_addres_size; idx++)
			{
				for (int inner = 0; inner < tmp_peer_addreslist_size_; inner++)
				{
					if (!saddr_equals(curr_channel_->remote_addres + idx, tmp_peer_addreslist_ + inner))
					{
						EVENTLOG(NOTICE,
							"new addr found in received INIT at CookieEchoed state -> send ABORT with ECC_RESTART_WITH_NEW_ADDRESSES  !");
						chunk_id_t abort_cid = mch_make_simple_chunk(
							CHUNK_ABORT, FLAG_TBIT_UNSET);
						mch_write_error_cause(abort_cid,
							ECC_RESTART_WITH_NEW_ADDRESSES, (uchar*)tmp_peer_addreslist_ + inner, sizeof(sockaddrunion));
						mdi_lock_bundle_ctrl();
						mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abort_cid));
						mdi_unlock_bundle_ctrl();
						mdi_send_bundled_chunks();
						mch_free_simple_chunk(abort_cid);
						/* remove NOT free INIT CHUNK before return */
						mch_remove_simple_chunk(init_cid);
						return STOP_PROCESS_CHUNK_FOR_FOUND_NEW_ADDR;
					}
				}
			}

			/* 5.3)
			 * For an endpoint that is in the COOKIE-ECHOED state it MUST populate
			 * its Tie-Tags with random values so that possible attackers cannot guess
			 * real tag values of the association (see Implementer's Guide > version 10)*/
			smctrl->local_tie_tag = mdi_generate_itag();
			smctrl->peer_tie_tag = mdi_generate_itag();

			/*5.4) get in stream number*/
			ordered_streams = mch_read_ordered_streams(init_cid);
			sequenced_streams = mch_read_sequenced_streams(init_cid);

			/*5.5) an INIT ACK using the same parameters it sent in its
			 original INIT chunk (including its Initiate Tag, unchanged) */
			assert(smctrl->my_init_chunk != NULL);

			/* make and fills init ack*/
			init_ack_cid = mch_make_init_ack_chunk(smctrl->my_init_chunk->init_fixed.init_tag,
				smctrl->my_init_chunk->init_fixed.rwnd, smctrl->my_init_chunk->init_fixed.ordered_streams,
				smctrl->my_init_chunk->init_fixed.sequenced_streams, smctrl->my_init_chunk->init_fixed.initial_tsn);

			/*5.6) get local addr list and append them to INIT ACK*/
			tmp_local_addreslist_size_ = mdi_validate_localaddrs_before_write_to_init(tmp_local_addreslist_,
				last_source_addr_, 1, tmp_peer_supported_types_, true);
			mch_write_vlp_addrlist(init_ack_cid, tmp_local_addreslist_, tmp_local_addreslist_size_);

			/*5.7) generate and append cookie to INIT ACK*/
			mch_write_cookie(init_cid, init_ack_cid, mch_read_init_fixed(init_cid), mch_read_init_fixed(init_ack_cid),
				mch_read_cookie_preserve(init_cid, ignore_cookie_life_spn_from_init_chunk_, msm_get_cookielife()),
				/* unexpected case: existing channel found, set both NOT zero*/
				smctrl->local_tie_tag, smctrl->peer_tie_tag, last_dest_port_, last_src_port_, tmp_local_addreslist_,
				tmp_local_addreslist_size_, do_we_support_unreliability(), do_we_support_addip(), tmp_peer_addreslist_,
				tmp_peer_addreslist_size_);

			/* 5.8) check unrecognized geco_instance_params */
			ret = mch_validate_init_vlps(init_cid, init_ack_cid);
			if (ret < 0 || ret == ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM)
			{
				/* 6.9) peer's init chunk has icorrect chunk length or
				 stop prcess when meeting unrecognized chunk type
				 both cases should not send init ack-> discard*/
				mch_free_simple_chunk(init_ack_cid);
			}
			else
			{
				/* 5.10) MUST send INIT ACK caried unknown geco_instance_params to the peer
				 * if he has unknown geco_instance_params in its init chunk
				 * as we SHOULD let peer's imple to finish the
				 * unnormal connection handling precedures*/

				 /* send all bundled chunks to ensure init ack is the only chunk sent
				  * in the whole geco packet*/
				mdi_unlock_bundle_ctrl();
				mdi_send_bundled_chunks();
				// bundle INIT ACK if full will send and empty bundle then copy init ack
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(init_ack_cid));
				mdi_send_bundled_chunks();  // send init ack
				mch_free_simple_chunk(init_ack_cid);
				EVENTLOG(INTERNAL_EVENT, "event: initAck sent at state of cookie echoed");
			}
		}
		else if (channel_state == ChannelState::ShutdownAckSent)
		{
			/* RFC 4960 (section 9.2 starting from line 6146)
			 We are supposed to discard the Init, and retransmit SHUTDOWN_ACK
			 If an endpoint is in the SHUTDOWN-ACK-SENT state and receives an INIT
			 chunk (e.g., if the SHUTDOWN COMPLETE was lost) with source and
			 destination transport addresses (either in the IP addresses or in the
			 INIT chunk) that belong to this association, it should discard the
			 INIT chunk and retransmit the SHUTDOWN ACK chunk.

			 Note: Receipt of an INIT with the same source and destination IP
			 addresses as used in transport addresses assigned to an endpoint but
			 with a different port number indicates the initialization of a
			 separate association.*/
			EVENTLOG1(VERBOSE, "at line 1 msm_process_init_chunk():CURR BUNDLE SIZE (%d)",
				get_bundle_total_size(mdi_read_mbu()));
			// send all bundled chunks to ensure init ack is the only chunk sent
			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();
			uint shutdownackcid = mch_make_simple_chunk(CHUNK_SHUTDOWN_ACK,
				FLAG_TBIT_UNSET);
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shutdownackcid));
			mch_free_simple_chunk(shutdownackcid);
			mdi_send_bundled_chunks();  //send init ack
			EVENTLOG(INTERNAL_EVENT, "event: initAck sent at state of ShutdownAckSent");
		}
		else
		{
			/* 7) see RFC 4960 - Section 5.2.2
			 Unexpected INIT in States Other than CLOSED, COOKIE-ECHOED,
			 COOKIE-WAIT, and SHUTDOWN-ACK-SENT
			 Unless otherwise stated, upon receipt of an unexpected INIT for this
			 association, the endpoint shall generate an INIT ACK with a State
			 Cookie.  Before responding, the endpoint MUST check to see if the
			 unexpected INIT adds new addresses to the association.*/

			 //ChannelState::Connected:
			 //ChannelState::ShutdownPending:
			 // ChannelState::ShutdownSent:
			 /* 7.1) validate tie tags NOT zeros */
			assert(smctrl->local_tie_tag != 0);
			assert(smctrl->peer_tie_tag != 0);

			/*7.2) validate no new addr aaded from the newly received INIT */
			/* read and validate peer addrlist carried in the received init chunk*/
			assert(my_supported_addr_types_ != 0);
			assert(curr_geco_packet_value_len_ == init->chunk_header.chunk_length);

			tmp_peer_addreslist_size_ = mdi_read_peer_addreslist(tmp_peer_addreslist_, (uchar*)init,
				curr_geco_packet_value_len_, my_supported_addr_types_, &tmp_peer_supported_types_, true, false);

			if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
			{
				EVENTLOG(NOTICE, "msm_process_init_chunk():: UNSUPPOTED ADDR TYPES -> send abort with tbit unset !");
				chunk_id_t abort_cid = mch_make_simple_chunk(CHUNK_ABORT,
					FLAG_TBIT_UNSET);
				const char* errstr = "peer does not supports your adress types !";
				mch_write_error_cause(abort_cid,
					ECC_PEER_NOT_SUPPORT_ADDR_TYPES, (uchar*)errstr, strlen(errstr) + 1);

				mdi_lock_bundle_ctrl();
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abort_cid));
				mch_free_simple_chunk(abort_cid);
				mdi_unlock_bundle_ctrl();
				mdi_send_bundled_chunks();
				return discard;
			}

			/*compare if there is new addr presenting*/
			bool new_addr_found = false;
			for (uint idx = 0; idx < curr_channel_->remote_addres_size; idx++)
			{
				for (int inner = 0; inner < tmp_peer_addreslist_size_; inner++)
				{
					if (!saddr_equals(curr_channel_->remote_addres + idx, tmp_peer_addreslist_ + inner))
					{
						new_addr_found = true;
					}
					else
					{
						new_addr_found = false;
						break;
					}
				}
			}

			if (new_addr_found)
			{
				EVENTLOG(NOTICE,
					"new addr found in received INIT at CookieEchoed state -> send ABORT with ECC_RESTART_WITH_NEW_ADDRESSES  !");
				chunk_id_t abort_cid = mch_make_simple_chunk(
					CHUNK_ABORT, FLAG_TBIT_UNSET);
				//mch_write_error_cause(abort_cid,
				//	ECC_RESTART_WITH_NEW_ADDRESSES, (uchar*)tmp_peer_addreslist_ + start_idx, num * sizeof(sockaddrunion));
				mdi_lock_bundle_ctrl();
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abort_cid));
				mdi_unlock_bundle_ctrl();
				mdi_send_bundled_chunks();
				mch_free_simple_chunk(abort_cid);
				/* remove NOT free INIT CHUNK before return */
				mch_remove_simple_chunk(init_cid);
				return STOP_PROCESS_CHUNK_FOR_FOUND_NEW_ADDR;
			}

			/*7.2) get in out stream number*/
			ordered_streams = mch_read_ordered_streams(init_cid);
			sequenced_streams = mch_read_sequenced_streams(init_cid);

			/* 7.3) prepare init ack
			 -the INIT ACK MUST contain a new Initiate Tag(randomly generated;
			 see Section 5.3.1).
			 -Other parameters for the endpoint SHOULD be copied from the existing
			 parameters of the association (e.g., number of outbound streams) into
			 the INIT ACK and cookie.*/
			init_tag = mdi_generate_itag();

			// save a-sides init-tag from init-chunk to be used as a verification tag of the sctp-
			// message carrying the initAck (required since peer may have changed the verification tag).
			init_ack_cid = mch_make_init_ack_chunk(init_tag, curr_channel_->receive_control->my_rwnd,
				curr_channel_->deliverman_control->numOrderedStreams, curr_channel_->deliverman_control->numSequencedStreams,
				smctrl->peer_cookie_chunk->cookie.local_initack.initial_tsn);

			/*7.4) get local addr list and append them to INIT ACK*/
			tmp_local_addreslist_size_ = mdi_validate_localaddrs_before_write_to_init(tmp_local_addreslist_,
				last_source_addr_, 1, tmp_peer_supported_types_, true);
			mch_write_vlp_addrlist(init_ack_cid, tmp_local_addreslist_, tmp_local_addreslist_size_);

			/*6.7) generate and append cookie to INIT ACK*/
			mch_write_cookie(init_cid, init_ack_cid, mch_read_init_fixed(init_cid), mch_read_init_fixed(init_ack_cid),
				mch_read_cookie_preserve(init_cid, ignore_cookie_life_spn_from_init_chunk_, msm_get_cookielife()),
				/* unexpected case:  channel existing, set both NOT zero*/
				smctrl->local_tie_tag, smctrl->peer_tie_tag, last_dest_port_, last_src_port_, tmp_local_addreslist_,
				tmp_local_addreslist_size_, do_we_support_unreliability(), do_we_support_addip(), tmp_peer_addreslist_,
				tmp_peer_addreslist_size_);

			/* 6.8) check unrecognized geco_instance_params*/
			ret = mch_validate_init_vlps(init_cid, init_ack_cid);
			if (ret < 0 || ret == ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM)
			{
				/* 6.9) peer's init chunk has icorrect chunk length or
				 stop prcess when meeting unrecognized chunk type
				 both cases should not send init ack-> discard*/
				mch_free_simple_chunk(init_ack_cid);
			}
			else
			{
				/* 6.10) MUST send INIT ACK caried unknown geco_instance_params to the peer
				 * if he has unknown geco_instance_params in its init chunk
				 * as we SHOULD let peer's imple to finish the
				 * unnormal connection handling precedures*/

				 /*send all bundled chunks to ensure init ack is the only chunk sent*/
				EVENTLOG1(VERBOSE, "at line 1674 msm_process_init_chunk():CURR BUNDLE SIZE (%d)",
					get_bundle_total_size(mdi_read_mbu()));
				assert(get_bundle_total_size(mdi_read_mbu()) == GECO_PACKET_FIXED_SIZE);
				mdi_unlock_bundle_ctrl();
				mdi_send_bundled_chunks();
				// bundle INIT ACK if full will send and empty bundle then copy init ack
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(init_ack_cid));
				/* trying to send bundle to become more responsive
				 * unlock bundle to send init ack as single chunk in the
				 * whole geco packet */
				mdi_send_bundled_chunks(&smctrl->addr_my_init_chunk_sent_to);
				mch_free_simple_chunk(init_ack_cid);
				EVENTLOG(DEBUG, "event: initAck sent at state of ShutdownSent");
			}
		}
	}  // existing channel

	// 6) remove (NOT free) INIT CHUNK
	mch_remove_simple_chunk(init_cid);
	return ret;
}

void set_channel_remote_addrlist(sockaddrunion destaddrlist[MAX_NUM_ADDRESSES], int noOfAddresses)
{
	EVENTLOG(DEBUG, "------ ENTER set_channel_remote_addrlist");
	if (curr_channel_ == NULL)
	{
		ERRLOG(MINOR_ERROR, "set_channel_destaddrlist(): current cannel is NULL!");
		return;
	}

	if (curr_channel_->remote_addres_size > 0 && curr_channel_->remote_addres != NULL)
	{
		geco_free_ext(curr_channel_->remote_addres, __FILE__, __LINE__);
		channel_map_.clear();
	}
	curr_channel_->remote_addres = (sockaddrunion*)geco_malloc_ext(noOfAddresses * sizeof(sockaddrunion), __FILE__,
		__LINE__);
	assert(curr_channel_->remote_addres != NULL);
	//memcpy(curr_channel_->remote_addres, destaddrlist, noOfAddresses * sizeof(sockaddrunion));
	memcpy_fast(curr_channel_->remote_addres, destaddrlist, noOfAddresses * sizeof(sockaddrunion));
	curr_channel_->remote_addres_size = noOfAddresses;

	//insert channel id to map
	for (uint i = 0; i < curr_channel_->local_addres_size; i++)
	{
		curr_trans_addr_.local_saddr = curr_channel_->local_addres + i;
		curr_trans_addr_.local_saddr->sa.sa_family == AF_INET ?
			curr_trans_addr_.local_saddr->sin.sin_port = htons(curr_channel_->local_port) :
			curr_trans_addr_.local_saddr->sin6.sin6_port = htons(curr_channel_->local_port);
		for (uint ii = 0; ii < curr_channel_->remote_addres_size; ii++)
		{
			curr_trans_addr_.peer_saddr = curr_channel_->remote_addres + ii;
			if (curr_trans_addr_.local_saddr->sa.sa_family != curr_trans_addr_.peer_saddr->sa.sa_family)
				continue;
			if (channel_map_.find(curr_trans_addr_) != channel_map_.end())
				continue;
			channel_map_.insert(std::make_pair(curr_trans_addr_, curr_channel_->channel_id));
		}
	}
	EVENTLOG(DEBUG, "------ LEAVE set_channel_remote_addrlist");
}
bool peer_supports_pr(init_chunk_t* initack)
{
	assert(initack != 0);
	uchar* foundvlp = mch_read_vlparam(VLPARAM_UNRELIABILITY, &initack->variableParams[0],
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
bool peer_supports_addip(init_chunk_t* initack)
{
	assert(initack != 0);
	uchar* foundvlp = mch_read_vlparam(VLPARAM_ADDIP, &initack->variableParams[0],
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
cookie_param_t* mch_read_cookie(init_chunk_t* initack)
{
	assert(initack != 0);
	if (initack->chunk_header.chunk_id == CHUNK_INIT_ACK)
	{
		cookie_param_t* ret = (cookie_param_t*)mch_read_vlparam(VLPARAM_COOKIE, &initack->variableParams[0],
			initack->chunk_header.chunk_length - INIT_CHUNK_FIXED_SIZES);
		return ret;
	}
	else
	{
		return 0;
	}
}

bool peer_supports_pr(cookie_echo_chunk_t* cookie_echo)
{
#ifdef _DEBUG
	EVENTLOG(VERBOSE, "- - - - - Enter peer_supports_pr(cookie_echo_chunk_t)");
#endif

	assert(cookie_echo != 0);
	assert(COOKIE_FIXED_SIZE == sizeof(cookie_fixed_t));
	bool ret = false;
	uchar* foundvlp = mch_read_vlparam(VLPARAM_UNRELIABILITY, cookie_echo->vlparams,
		cookie_echo->chunk_header.chunk_length - CHUNK_FIXED_SIZE - COOKIE_FIXED_SIZE);
	if (foundvlp != NULL)
	{
		if (ntohs(((vlparam_fixed_t*)foundvlp)->param_length) >= VLPARAM_FIXED_SIZE)
		{
			ret = true;
			goto leave;
		}
		else
		{
			EVENTLOG(VERBOSE, " pr vlp too short < 4 bytes");
			goto leave;
		}
	}

leave:
#ifdef _DEBUG
	EVENTLOG1(VERBOSE, "- - - - - Enter peer_supports_pr(cookie_echo_chunk_t)::ret=%d", ret);
#endif
	return ret;
}
bool peer_supports_addip(cookie_echo_chunk_t* cookie_echo)
{
#ifdef _DEBUG
	EVENTLOG(VERBOSE, "- - - - - Enter peer_supports_addip(cookie_echo_chunk_t)");
#endif

	assert(cookie_echo != 0);
	assert(COOKIE_FIXED_SIZE == sizeof(cookie_fixed_t));
	bool ret = false;
	uchar* foundvlp = mch_read_vlparam(VLPARAM_ADDIP, cookie_echo->vlparams,
		cookie_echo->chunk_header.chunk_length - CHUNK_FIXED_SIZE - COOKIE_FIXED_SIZE);
	if (foundvlp != NULL)
	{
		if (ntohs(((vlparam_fixed_t*)foundvlp)->param_length) >= VLPARAM_FIXED_SIZE)
		{
			ret = true;
			goto leave;
		}
		else
		{
			EVENTLOG(VERBOSE, " pr vlp too short < 4 bytes");
			goto leave;
		}
	}

leave:
#ifdef _DEBUG
	EVENTLOG1(VERBOSE, "- - - - - Enter peer_supports_addip(cookie_echo_chunk_t)::ret=%d", ret);
#endif
	return ret;
}

/**
 * after submitting results from a SACK to flowcontrol, the counters in
 * reliable transfer must be reset
 * @param rtx   pointer to a retransmit_controller_t, where acked bytes per address will be reset to 0
 */
inline void mreltx_zero_newly_acked_bytes(reltransfer_controller_t * rtx)
{
	rtx->newly_acked_bytes = 0L;
}
reltransfer_controller_t* mreltx_new(uint numofdestaddrlist, uint iTSN)
{
	EVENTLOG(VERBOSE, "- - - Enter mreltx_new()");

	reltransfer_controller_t* tmp = new reltransfer_controller_t();
	if (tmp == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");

	tmp->lowest_tsn = iTSN - 1;
	tmp->highest_tsn = iTSN - 1;
	tmp->lastSentForwardTSN = iTSN - 1;
	tmp->highest_acked = iTSN - 1;
	tmp->last_received_ctsna = iTSN - 1;
	tmp->newly_acked_bytes = 0L;
	tmp->num_of_chunks = 0L;
	tmp->save_num_of_txm = 0L;
	tmp->peer_arwnd = 0L;
	tmp->shutdown_received = false;
	tmp->fast_recovery_active = false;
	tmp->all_chunks_are_unacked = true;
	tmp->fr_exit_point = 0L;
	tmp->numofdestaddrlist = numofdestaddrlist;
	tmp->advanced_peer_ack_point = iTSN - 1; /* a save bet */
	mreltx_zero_newly_acked_bytes(tmp);

	EVENTLOG(VERBOSE, "- - - Leave mreltx_new()");
	return tmp;
}
void mreltx_free(reltransfer_controller_t* rtx_inst)
{
	EVENTLOG(VERBOSE, "- - - Enter mreltx_free()");
	if (rtx_inst->chunk_list_tsn_ascended.size() > 0)
	{
		EVENTLOG(NOTICE, "mfc_free() : rtx_inst is deleted but chunk_list has size > 0, still queued ...");
		for (auto it = rtx_inst->chunk_list_tsn_ascended.begin(); it != rtx_inst->chunk_list_tsn_ascended.end();)
		{
			free_reltransfer_data_chunk((*it));
			rtx_inst->chunk_list_tsn_ascended.erase(it++);
		}
	}
	// see https://developer.gnome.org/glib/stable/glib-Arrays.html#g-array-free
	for (internal_data_chunk_t* it : rtx_inst->prChunks)
	{
		free_data_chunk(it);
	}
	delete rtx_inst;
	EVENTLOG(VERBOSE, "- - - Leave mreltx_free()");
}

void mfc_stop_timers(void)
{
	EVENTLOG(DEBUG, "- - - Enter mfc_stop_timers()");
	flow_controller_t* fc;
	if ((fc = mdi_read_mfc()) == NULL)
	{
		ERRLOG(WARNNING_ERROR, "flow controller is NULL !");
		return;
	}

	for (uint count = 0; count < fc->numofdestaddrlist; count++)
	{
		if (fc->T3_timer[count] != NULL)
		{
			mtra_timeouts_del(fc->T3_timer[count]);
			fc->T3_timer[count] = NULL;
#ifdef _DEBUG
			EVENTLOG2(DEBUG, "mfc_stop_timers()::Stopping T3-Timer(id=%llu, timer_type=%d) ", (uint64)fc->T3_timer[count],
				fc->T3_timer[count]->callback.type);
#endif
		}
	}
	EVENTLOG(DEBUG, "- - - Leave mfc_stop_timers()");
}
/**
 * Deletes data occupied by a flow_control data structure
 * @param fc_instance pointer to the flow_control data structure
 */
void mfc_free(flow_controller_t* fctrl_inst)
{
	EVENTLOG(VERBOSE, "- - - Enter mfc_free()");
	mfc_stop_timers();
	delete fctrl_inst->cparams;
	delete fctrl_inst->T3_timer;
	delete fctrl_inst->addresses;
	if (!fctrl_inst->chunk_list.empty())
	{
		EVENTLOG(NOTICE, "mfc_free() : fctrl_inst is deleted but chunk_list has size > 0 ...");
		for (auto it = fctrl_inst->chunk_list.begin(); it != fctrl_inst->chunk_list.end();)
		{
			free_flowctrl_data_chunk((*it));
			fctrl_inst->chunk_list.erase(it++);
		}
	}
	delete fctrl_inst;
	EVENTLOG(VERBOSE, "- - - Leave mfc_free()");
}
/**
 * Creates new instance of flowcontrol module and returns pointer to it
 * use lowest MTU 576 per destination address
 * @param  peer_rwnd receiver window that peer allowed us when setting up the association
 * @param  my_iTSN my initial TSN value
 * @param  numofdestaddres the number of paths to the association peer
 * @return  pointer to the new fc_data instance
 */
flow_controller_t* mfc_new(uint peer_rwnd, uint my_iTSN, uint numofdestaddres, uint maxQueueLen)
{
	EVENTLOG4(VERBOSE, "- - - Enter mfc_new(peer_rwnd=%d,numofdestaddres=%d,my_iTSN=%d,maxQueueLen=%d)", peer_rwnd,
		numofdestaddres, my_iTSN, maxQueueLen);

	flow_controller_t* tmp = new flow_controller_t();
	if (tmp == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
	}

	tmp->current_tsn = my_iTSN;
	if ((tmp->cparams = new congestion_parameters_t[numofdestaddres]) == NULL)
	{
		delete tmp;
		ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
	}
	if ((tmp->T3_timer = new timeout*[numofdestaddres]) == NULL)
	{
		delete tmp->cparams;
		delete tmp;
		ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
	}
	if ((tmp->addresses = new uint[numofdestaddres]) == NULL)
	{
		delete tmp->T3_timer;
		delete tmp->cparams;
		delete tmp;
		ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
	}

	for (uint count = 0; count < numofdestaddres; count++)
	{
		tmp->T3_timer[count] = NULL; /* i.e. timer not running */
		tmp->addresses[count] = count;
		(tmp->cparams[count]).cwnd = (uint)PMTU_LOWEST << 1; // pmtu probe will update this
		(tmp->cparams[count]).cwnd2 = 0L;
		(tmp->cparams[count]).partial_bytes_acked = 0L;
		(tmp->cparams[count]).ssthresh = peer_rwnd;
		(tmp->cparams[count]).mtu = PMTU_LOWEST - IP_HDR_SIZE - 12; // PMTU_LOWEST 576 - 20 - 12(geco_packet_fixed_size 12 or udp_packet_fixed_size  8+4) = 544
		tmp->cparams[count].time_of_cwnd_adjustment = gettimestamp();
		tmp->cparams[count].last_send_time = 0;
	}
	tmp->channel_id = curr_channel_->channel_id;
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
	mreltx_set_peer_arwnd(peer_rwnd);

	EVENTLOG1(VERBOSE, "- - - Leave mfc_new(channel id=%d)", tmp->channel_id);
	return tmp;
}

void mfc_restart(uint new_rwnd, uint iTSN, uint maxQueueLen)
{
	flow_controller_t* tmp = mdi_read_mfc();
	assert(tmp != NULL);

	mfc_stop_timers();
	mreltx_set_peer_arwnd(new_rwnd);

	uint count;
	for (count = 0; count < tmp->numofdestaddrlist; count++)
	{
		(tmp->cparams[count]).cwnd = (uint)PMTU_LOWEST << 1;
		(tmp->cparams[count]).cwnd2 = 0L;
		(tmp->cparams[count]).partial_bytes_acked = 0L;
		(tmp->cparams[count]).ssthresh = new_rwnd;
		(tmp->cparams[count]).mtu = PMTU_LOWEST - IP_HDR_SIZE - 12;
		tmp->cparams[count].time_of_cwnd_adjustment = gettimestamp();
		tmp->cparams[count].last_send_time = 0;
	}

	tmp->outstanding_bytes = 0;
	tmp->peerarwnd = new_rwnd;
	tmp->waiting_for_sack = false;
	tmp->shutdown_received = false;
	tmp->t3_retransmission_sent = false;
	tmp->one_packet_inflight = false;
	tmp->doing_retransmission = false;
	tmp->current_tsn = iTSN;
	tmp->maxQueueLen = maxQueueLen;

	for (internal_data_chunk_t* idct : tmp->chunk_list)
	{
		free_flowctrl_data_chunk(idct);
	}

	ERRLOG(MINOR_ERROR, "FLOWCONTROL RESTART : List is deleted...");
	tmp->list_length = 0;
}
/**
 * function deletes a rxc_buffer structure (when it is not needed anymore)
 * @param rxc_instance pointer to a rxc_buffer, that was previously created
 */
void mrecv_free(recv_controller_t* rxc_inst)
{
	EVENTLOG(VERBOSE, "- - - Enter mrecv_free()");
	delete rxc_inst->sack_chunk;
	if (rxc_inst->timer_running)
	{
		mtra_timeouts_del(rxc_inst->sack_timer);
		rxc_inst->timer_running = false;
	}
	rxc_inst->fragmented_data_chunks_list.clear();
	rxc_inst->duplicated_data_chunks_list.clear();
	delete rxc_inst;
	EVENTLOG(VERBOSE, "- - - Leave mrecv_free()");
}
/**
 * function creates and allocs new rxc_buffer structure.
 * There is one such structure per established association
 * @param  remote_initial_TSN initial tsn of the peer
 * @return pointer to the newly created structure
 */
recv_controller_t* mrecv_new(unsigned int remote_initial_TSN, unsigned int number_of_destination_addresses,
	geco_instance_t* geco_instance)
{
	EVENTLOG(VERBOSE, "- - - Enter mrecv_new()");
	recv_controller_t* tmp = new recv_controller_t();
	if (tmp == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");

	tmp->numofdestaddrlist = number_of_destination_addresses;
	tmp->sack_chunk = new sack_chunk_t;
	tmp->sack_chunk->chunk_header.chunk_id = CHUNK_SACK;
	tmp->sack_chunk->chunk_header.chunk_flags = 0;
	tmp->cumulative_tsn = remote_initial_TSN - 1; /* as per section 4.1 */
	tmp->lowest_duplicated_tsn = remote_initial_TSN - 1;
	tmp->highest_tsn = remote_initial_TSN - 1;
	tmp->sack_updated = false;
	tmp->timer_running = false;
	tmp->packet_contain_dchunk_received = -1;
	tmp->sack_flag = 2;
	tmp->last_address = 0;
	tmp->my_rwnd = mdi_read_rwnd();
	tmp->delay = mdi_read_default_delay(geco_instance);
	EVENTLOG2(DEBUG, "channel id %d, local tag %d", curr_channel_->channel_id, curr_channel_->local_tag);

	EVENTLOG(VERBOSE, "- - - Leave mrecv_new()");
	return tmp;
}
/**
 This function is called to instanciate one deliverman for an association.
 It creates and initializes the Lists for Sending and Receiving Data.
 It is called by dispatcher layer. returns: the pointer to the Stream Engine
 */
deliverman_controller_t* mdlm_new(unsigned int numberOrderStreams, unsigned int numberSeqStreams, /* max of streams to receive */

	bool assocSupportsPRSCTP)
{
	EVENTLOG3(VERBOSE,
		"- - - Enter mdlm_new(new_stream_engine: #numberSeqReceiveStreams=%d, #numberOrderReceiveStreams=%d, unreliable == %s)",
		numberSeqStreams, numberOrderStreams, (assocSupportsPRSCTP == true) ? "true" : "false");

	deliverman_controller_t* tmp = new deliverman_controller_t;
	if (tmp == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "deliverman_controller_t Malloc failed");

	if ((tmp->recv_seq_streams = new recv_stream_t[numberSeqStreams]) == NULL || (tmp->recv_order_streams =
		new recv_stream_t[numberOrderStreams]) == NULL)
	{
		delete tmp;
		ERRLOG(FALTAL_ERROR_EXIT, "recv_streams Malloc failed");
	}

	if ((tmp->recv_seq_streams_activated = new bool[numberSeqStreams]) == NULL || (tmp->recv_order_streams_actived =
		new bool[numberOrderStreams]) == NULL)
	{
		delete[] tmp->recv_seq_streams;
		delete[] tmp->recv_order_streams;
		delete tmp;
		ERRLOG(FALTAL_ERROR_EXIT, "recvStreamActivated Malloc failed");
	}

	uint i;
	for (i = 0; i < numberSeqStreams; i++)
		tmp->recv_seq_streams_activated[i] = false;

	for (i = 0; i < numberOrderStreams; i++)
		tmp->recv_order_streams_actived[i] = false;

	if ((tmp->send_order_streams = new send_stream_t[numberOrderStreams]) == NULL || (tmp->send_seq_streams =
		new send_stream_t[numberSeqStreams]) == NULL)
	{
		delete[] tmp->recv_seq_streams_activated;
		delete[] tmp->recv_order_streams_actived;
		delete[] tmp->recv_seq_streams;
		delete[] tmp->recv_order_streams;
		delete tmp;
		ERRLOG(FALTAL_ERROR_EXIT, "send_streams Malloc failed");
	}

	tmp->numOrderedStreams = numberOrderStreams;
	tmp->numSequencedStreams = numberSeqStreams;
	tmp->unreliable = assocSupportsPRSCTP;
	tmp->queuedBytes = 0;

	for (i = 0; i < numberSeqStreams; i++)
	{
		(tmp->recv_seq_streams)[i].nextSSN = 0;
		(tmp->recv_seq_streams)[i].index = 0; /* for ordered chunks, next ssn */
		(tmp->recv_seq_streams)[i].highestSSN = 0;
		(tmp->recv_seq_streams)[i].highestSSNused = false;
		(tmp->send_seq_streams)[i].nextSSN = 0;
	}

	for (i = 0; i < numberOrderStreams; i++)
	{
		(tmp->recv_order_streams)[i].nextSSN = 0;
		(tmp->recv_order_streams)[i].index = 0; /* for ordered chunks, next ssn */
		(tmp->recv_order_streams)[i].highestSSN = 0;
		(tmp->recv_order_streams)[i].highestSSNused = false;
		(tmp->recv_order_streams)[i].nextSSN = 0;
	}

	return (tmp);

	EVENTLOG(VERBOSE, "- - - Leave mdlm_new()");
}
/** Deletes the instance pointed to by streamengine.*/
void mdlm_free(deliverman_controller_t* se)
{
	EVENTLOG(VERBOSE, "- - - Enter mdlm_free()");

	for (uint i = 0; i < se->numOrderedStreams; i++)
	{
		EVENTLOG1(VERBOSE, "delete mdlm_free(): freeing data for receive stream %d", i);
		/* whatever is still in these lists, delete it before freeing the lists */
		auto& pdulist = se->recv_order_streams[i].pduList;
		for (auto it = pdulist.begin(); it != pdulist.end();)
		{
			free_delivery_pdu((*it));
			pdulist.erase(it++);
		}
		auto& predulist = se->recv_order_streams[i].prePduList;
		for (auto it = predulist.begin(); it != predulist.end();)
		{
			free_delivery_pdu((*it));
			predulist.erase(it++);
		}
	}

	for (uint i = 0; i < se->numSequencedStreams; i++)
	{
		EVENTLOG1(VERBOSE, "delete mdlm_free(): freeing data for receive stream %d", i);
		/* whatever is still in these lists, delete it before freeing the lists */
		auto& pdulist = se->recv_seq_streams[i].pduList;
		for (auto it = pdulist.begin(); it != pdulist.end();)
		{
			free_delivery_pdu((*it));
			pdulist.erase(it++);
		}
		auto& predulist = se->recv_seq_streams[i].prePduList;
		for (auto it = predulist.begin(); it != predulist.end();)
		{
			free_delivery_pdu((*it));
			predulist.erase(it++);
		}
	}

	delete[] se->send_order_streams;
	delete[] se->send_seq_streams;
	delete[] se->recv_seq_streams_activated;
	delete[] se->recv_order_streams_actived;
	delete[] se->recv_seq_streams;
	delete[] se->recv_order_streams;
	delete se;

	EVENTLOG(VERBOSE, "- - - Leave mdlm_free()");
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
 * @param  remoteSideReceiverWindow  peer_rwnd size that the peer allowed in this association
 * @param  noOfInStreams  seq stream number
 * @param  noOfOutStreams order stream number
 * @param  remoteInitialTSN     initial  TSN of the peer
 * @param  tagRemote            tag of the peer
 * @param  localInitialTSN      my initial TSN, needed for initializing my flow control
 * @return 0 for success, else 1 for error
 */
ushort mdi_init_channel(uint remoteSideReceiverWindow, ushort noOfOrderStreams, ushort noOfSeqStreams,
	uint remoteInitialTSN, uint tagRemote, uint localInitialTSN, bool assocSupportsPRSCTP, bool assocSupportsADDIP)
{
	EVENTLOG(DEBUG, "- - - Enter mdi_init_channel()");
	assert(curr_channel_ != NULL);

	/**
	 * if  mdi_init_channel has already be called, delete modules and make new ones
	 *  with possibly new data. Multiple calls of of mdi_init_channel can occur on the
	 * a-side in the case of stale cookie errors.
	 */
	if (curr_channel_->remote_tag != 0)
	{
		// channel init was already completed
		EVENTLOG(INFO, "mdi_init_channel()::reset channel members!");
		mfc_free(curr_channel_->flow_control);
		mreltx_free(curr_channel_->reliable_transfer_control);
		mrecv_free(curr_channel_->receive_control);
		mdlm_free(curr_channel_->deliverman_control);
	}
	curr_channel_->remote_tag = tagRemote;
	bool with_pr = assocSupportsPRSCTP && curr_channel_->locally_supported_PRDCTP;
	curr_channel_->locally_supported_PRDCTP = curr_channel_->remotely_supported_PRSCTP = with_pr;
	curr_channel_->reliable_transfer_control = mreltx_new(curr_channel_->remote_addres_size, localInitialTSN);
	curr_channel_->flow_control = mfc_new(remoteSideReceiverWindow, localInitialTSN, curr_channel_->remote_addres_size,
		curr_channel_->maxSendQueue);
	curr_channel_->receive_control = mrecv_new(remoteInitialTSN, curr_channel_->remote_addres_size,
		curr_channel_->geco_inst);
	curr_channel_->deliverman_control = mdlm_new(noOfOrderStreams, noOfSeqStreams, with_pr);

	EVENTLOG2(DEBUG, "channel id %d, local tag %d", curr_channel_->channel_id, curr_channel_->local_tag);
	return 0;
}

void mrecv_stop_sack_timer()
{
	recv_controller_t* rxc = mdi_read_mrecv();
	assert(rxc != NULL);
	rxc->duplicated_data_chunks_list.clear();
	if (rxc->timer_running)
	{
		mtra_timeouts_stop(rxc->sack_timer);
		EVENTLOG(VERBOSE, "mrecv_stop_sack_timer()::Stopped Timer");
		rxc->timer_running = false;
	}
}
void mrecv_restart(int my_rwnd, uint new_remote_TSN)
{
	recv_controller_t* rxc = mdi_read_mrecv();
	assert(rxc != NULL);

	mrecv_stop_sack_timer();
	rxc->fragmented_data_chunks_list.clear();

	rxc->cumulative_tsn = new_remote_TSN - 1;
	rxc->lowest_duplicated_tsn = new_remote_TSN - 1;
	rxc->highest_tsn = new_remote_TSN - 1;

	rxc->sack_updated = false;
	rxc->timer_running = false;
	rxc->packet_contain_dchunk_received = -1;
	rxc->sack_flag = 2;
	rxc->last_address = 0;
	rxc->my_rwnd = my_rwnd;
	rxc->channel_id = mdi_read_curr_channel_id();
}

inline uint mrecv_read_cummulative_tsn_acked()
{
	recv_controller_t* mrxc = mdi_read_mrecv();
	if (mrxc == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "no smctrl with channel presents -> return");
	}
	return (mrxc->cumulative_tsn);
}

inline static reltransfer_controller_t* mreltx_restart(reltransfer_controller_t* mreltx, uint numOfPaths, uint iTSN)
{
	/* ******************************************************************* */
	/* IMPLEMENTATION NOTE: It is an implementation decision on how
	 to handle any pending datagrams. The implementation may elect
	 to either A) send all messages back to its upper layer with the
	 restart report, or B) automatically re-queue any datagrams
	 pending by marking all of them as never-sent and assigning
	 new TSN's at the time of their initial transmissions based upon
	 the updated starting TSN (as defined in section 5).
	 Version 13 says : SCTP data chunks MAY be retained !
	 (this is implementation specific)
	 ******************************************************************** */
	assert(mreltx != NULL);
	EVENTLOG2(INFO, "mreltx_restart()::Restarting Reliable Transfer module with number of Paths=%u, local init TSN=%u",
		numOfPaths, iTSN);
	// For ease of implementation we will delete all old data !
	mreltx_free(mreltx);
	return mreltx_new(numOfPaths, iTSN);
}

static bool mdi_restart_channel(uint new_rwnd, ushort noOfOrderStreams, ushort noOfSeqStreams, uint remoteInitialTSN,
	uint localInitialTSN, short primaryAddress, short noOfPaths, union sockaddrunion *destinationAddressList,
	bool assocSupportsPRSCTP, bool assocSupportsADDIP)
{
	assert(curr_channel_ != NULL && "mdi_restart_channel():: current association is NULL!");
	assert(curr_geco_instance_ != NULL && "mdi_restart_channel():: curr_geco_instance_ is NULL !");

	if (noOfPaths > curr_channel_->remote_addres_size)
	{
		EVENTLOG(NOTICE, "mdi_restart_channel()::peer tries to increase number of paths ! ---> return");
		return false;
	}

	EVENTLOG6(VERBOSE,
		"mdi_restart_channel()::noOfOrderStreams: %u, noOfSeqStreams: %u, rwnd: %u, paths: %u, remote initial TSN:  %u, local initial TSN",
		noOfOrderStreams, noOfSeqStreams, new_rwnd, noOfPaths, remoteInitialTSN, localInitialTSN);
	curr_channel_->reliable_transfer_control = mreltx_restart(curr_channel_->reliable_transfer_control, noOfPaths,
		localInitialTSN);
	mfc_restart(new_rwnd, localInitialTSN, curr_channel_->maxSendQueue);
	mrecv_restart(mdi_read_rwnd(), remoteInitialTSN);

	bool withPRSCTP = assocSupportsPRSCTP && curr_channel_->locally_supported_PRDCTP;
	curr_channel_->remotely_supported_PRSCTP = curr_channel_->locally_supported_PRDCTP = withPRSCTP;

	assert(curr_channel_->deliverman_control != NULL);
	mdlm_free(curr_channel_->deliverman_control);
	curr_channel_->deliverman_control = mdlm_new(noOfOrderStreams, noOfSeqStreams, withPRSCTP);

	assert(curr_channel_->path_control != NULL);
	mpath_free(curr_channel_->path_control);
	// frees old address-list before assigning new one
	mdi_set_channel_remoteaddrlist(destinationAddressList, noOfPaths);
	curr_channel_->path_control = mpath_new(noOfPaths, primaryAddress);
	assert(curr_channel_->path_control != NULL);
	mpath_start_hb_probe(noOfPaths, primaryAddress);

	return true;
}

ChunkProcessResult msm_process_init_ack_chunk(init_chunk_t * initAck)
{
	assert(initAck->chunk_header.chunk_id == CHUNK_INIT_ACK);
	ChunkProcessResult return_state = ChunkProcessResult::Good;
	smctrl_t* smctrl = mdi_read_smctrl();

	//1) alloc chunk id for the received init ack
	chunk_id_t initAckCID = mch_make_simple_chunk((simple_chunk_t*)initAck);
	if (smctrl == NULL)
	{
		mch_remove_simple_chunk(initAckCID);
		ERRLOG(MINOR_ERROR, "msm_process_init_ack_chunk(): mdi_read_smctrl() returned NULL!");
		return return_state;
	}

	int result;
	int process_further = 0;
	uint state, idx;
	ushort ordered_streams, sequenced_streams;
	chunk_id_t errorCID = 0;
	bool preferredSet = false, peerSupportsADDIP = false, peerSupportsIPV4 = false, peerSupportsIPV6 = false;
	short preferredPath;
	sockaddrunion prefered_primary_addr;
	uint peerSupportedTypes = 0, supportedTypes = 0;

	ChannelState channel_state = smctrl->channel_state;
	if (channel_state == ChannelState::CookieWait)
	{
		//2) discard init ack recived in state other than cookie wait
		EVENTLOG(INFO, "************************** RECV INIT ACK CHUNK AT COOKIE WAIT ******************************8");
		if (!mch_read_ordered_streams(initAckCID) || !mch_read_sequenced_streams(initAckCID) || !mch_read_itag(initAckCID))
		{
			EVENTLOG(DEBUG, "2) validate init geco_instance_params [zero streams  or zero init TAG] -> send abort ");

			/*2.1) make and send ABORT with ecc*/
			chunk_id_t abortcid = mch_make_simple_chunk(CHUNK_ABORT,
				FLAG_TBIT_UNSET);
			mch_write_error_cause(abortcid, ECC_INVALID_MANDATORY_PARAM);

			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abortcid));
			mch_free_simple_chunk(abortcid);

			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();

			/*2.2) delete all data of this channel,
			 * smctrl != NULL means current channel MUST exist at this moment */
			if (smctrl != NULL)
			{
				mdi_delete_curr_channel();
				mdi_on_disconnected(ConnectionLostReason::InvalidParam);
				mdi_clear_current_channel();
			}
			return_state = ChunkProcessResult::StopAndDeleteChannel_ValidateInitParamFailedError;
			return return_state;
		}

		if (last_source_addr_ == NULL)
		{
			/* delete all data of this channel,
			 smctrl != NULL means current channel MUST exist at this moment */
			if (smctrl == NULL)
			{
				mdi_clear_current_channel();
				return_state = ChunkProcessResult::StopProcessAndDeleteChannel;
				return return_state;
			}
			else
			{
				if (smctrl->init_timer_id != NULL)
				{
					mtra_timeouts_del(smctrl->init_timer_id);
					smctrl->init_timer_id = NULL;
				}
				mdi_unlock_bundle_ctrl();
				mdi_delete_curr_channel();
				mdi_on_disconnected(ConnectionLostReason::InvalidParam);
				mdi_clear_current_channel();
				return_state = ChunkProcessResult::StopProcessAndDeleteChannel;
				return return_state;
			}
		}
		else
		{
			//memcpy(&tmp_addr_, last_source_addr_, sizeof(sockaddrunion));
			memcpy_fast(&tmp_addr_, last_source_addr_, sizeof(sockaddrunion));
		}

		/*get in out stream number*/
		ordered_streams = mch_read_ordered_streams(initAckCID);
		sequenced_streams = mch_read_sequenced_streams(initAckCID);

		/* read and validate peer addrlist carried in the received initack chunk */
		assert(my_supported_addr_types_ != 0);
		assert(curr_geco_packet_value_len_ == initAck->chunk_header.chunk_length);
		tmp_peer_addreslist_size_ = mdi_read_peer_addreslist(tmp_peer_addreslist_, (uchar*)initAck,
			curr_geco_packet_value_len_, my_supported_addr_types_, &tmp_peer_supported_types_, true, false);
		if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
		{
			const char* errstr = "peer does not supports your adress types !";
			msm_abort_channel(ECC_PEER_NOT_SUPPORT_ADDR_TYPES, (uchar*)errstr, strlen(errstr) + 1);
		}
		set_channel_remote_addrlist(tmp_peer_addreslist_, tmp_peer_addreslist_size_);

		/* initialize channel with infos in init ack*/
		uint peer_itsn = mch_read_itsn(initAckCID);
		uint peer_rwnd = mch_read_rwnd(initAckCID);
		uint peer_itag = mch_read_itag(initAckCID);
		bool peersupportpr = peer_supports_pr(initAck);
		bool peersupportaddip = peer_supports_addip(initAck);
		uint my_init_itag = ntohl(smctrl->my_init_chunk->init_fixed.init_tag);
		mdi_init_channel(peer_rwnd, ordered_streams, sequenced_streams, peer_itsn, peer_itag, my_init_itag, peersupportpr,
			peersupportaddip);

		EVENTLOG2(VERBOSE,
			"msm_process_init_ack_chunk()::called mdi_init_channel(ordered_streams=%u, sequenced_streams=%u)",
			ordered_streams, sequenced_streams);

		// make cookie echo to en to peer
		cookie_param_t* cookie_param = mch_read_cookie(initAck);
		chunk_id_t cookieecho_cid = mch_make_cookie_echo(cookie_param);
		if (cookieecho_cid < 0)
		{
			EVENTLOG(INFO, "received a initAck without cookie");
			// stop shutdown timer
			if (smctrl->init_timer_id != NULL)
			{
				mtra_timeouts_del(smctrl->init_timer_id);
				smctrl->init_timer_id = NULL;
			}

			missing_mandaory_params_err_t missing_mandaory_params_err;
			missing_mandaory_params_err.numberOfParams = htonl(1);
			missing_mandaory_params_err.params[0] = htons(VLPARAM_COOKIE);
			msm_abort_channel(ECC_MISSING_MANDATORY_PARAM, (uchar*)&missing_mandaory_params_err,
				1 * (sizeof(ushort) + sizeof(uint)));

			mdi_unlock_bundle_ctrl();
			smctrl->channel_state = ChannelState::Closed;
			return_state = ChunkProcessResult::StopProcessAndDeleteChannel;
			return return_state;
		}

		chunk_id_t errorCID = mch_make_simple_chunk(CHUNK_ERROR,
			FLAG_TBIT_UNSET);
		process_further = mch_validate_init_vlps(initAckCID, errorCID);
		if (process_further < 0)
		{
			mch_remove_simple_chunk(initAckCID);
			mch_free_simple_chunk(cookieecho_cid);
			if (errorCID > 0)
				mch_free_simple_chunk(errorCID);
			// stop shutdown timer
			if (smctrl->init_timer_id != NULL)
			{
				mtra_timeouts_del(smctrl->init_timer_id);
				smctrl->init_timer_id = NULL;
			}
			mdi_unlock_bundle_ctrl();
			mdi_delete_curr_channel();
			mdi_on_disconnected(ConnectionLostReason::UnknownParam);
			mdi_clear_current_channel();
			smctrl->channel_state = ChannelState::Closed;
			return_state = ChunkProcessResult::StopProcessAndDeleteChannel;
			return return_state;
		}

		smctrl->peer_cookie_chunk = (cookie_echo_chunk_t *)mch_complete_simple_chunk(cookieecho_cid);
		smctrl->local_tie_tag = curr_channel_ == NULL ? 0 : curr_channel_->local_tag;
		smctrl->peer_tie_tag = mch_read_itag(initAckCID);
		smctrl->ordered_streams = ordered_streams;
		smctrl->sequenced_streams = sequenced_streams;
		mch_remove_simple_chunk(cookieecho_cid);
		mch_remove_simple_chunk(initAckCID);

		/* send cookie echo back to peer */
		mdi_bundle_ctrl_chunk((simple_chunk_t*)smctrl->peer_cookie_chunk); // not free cookie echo

		if (process_further == ActionWhenUnknownVlpOrChunkType::STOP_PROCES_PARAM_REPORT_EREASON
			|| process_further == ActionWhenUnknownVlpOrChunkType::SKIP_PARAM_REPORT_EREASON)
		{
			return_state = ChunkProcessResult::Good;
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(errorCID));
		}

		mch_free_simple_chunk(errorCID);
		mdi_unlock_bundle_ctrl();
		mdi_send_bundled_chunks();

		// stop init timer
		if (smctrl->init_timer_id != NULL)
		{
			mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = NULL;
		}

		//start cookie timer
		channel_state = ChannelState::CookieEchoed;
		smctrl->init_timer_id = mtra_timeouts_add(TIMER_TYPE_INIT, smctrl->init_timer_interval, &msm_timer_expired,
			smctrl->channel, NULL);
		EVENTLOG(INFO, "**************** SEND COOKIE ECHOED, ENTER COOKIE ECHOED****************");
	}
	else if (channel_state == ChannelState::CookieEchoed)
	{
		/* Duplicated initAck, ignore */
		EVENTLOG(NOTICE, "event: duplicatied sctlr_initAck in state CookieEchoed ->discard!");
	}
	else if (channel_state == ChannelState::ShutdownSent)
	{
		/* In this states the initAck is unexpected event. */
		EVENTLOG(NOTICE, "event: received init ack in state ShutdownSent ->discard!");
	}

	smctrl->channel_state = channel_state;
	return return_state;
}
int mdis_send_ecc_unrecognized_chunk(uchar* errdata, ushort length)
{
	// build chunk  and add it to chunklist
	chunk_id_t simple_chunk_index_ = add2chunklist((simple_chunk_t*)mch_make_error_chunk(), "add error chunk %u\n");
	// add error cause
	mch_write_error_cause(simple_chunk_index_, ECC_UNRECOGNIZED_CHUNKTYPE, errdata, length);
	// send it
	simple_chunk_t* simple_chunk_t_ptr_ = mch_complete_simple_chunk(simple_chunk_index_);
	mdi_lock_bundle_ctrl();
	mdi_bundle_ctrl_chunk(simple_chunk_t_ptr_);
	mdi_unlock_bundle_ctrl();
	mch_free_simple_chunk(simple_chunk_index_);
	return mdi_send_bundled_chunks();
}
bool cmp_channel(const geco_channel_t& tmp_channel, const geco_channel_t& b)
{
	EVENTLOG2(VERBOSE, "cmp_endpoint_by_addr_port(): checking ep A[id=%d] and ep B[id=%d]", tmp_channel.channel_id,
		b.channel_id);
	if (tmp_channel.remote_port == b.remote_port && tmp_channel.local_port == b.local_port)
	{
		uint i, j;
		/*find if at least there is an ip addr thate quals*/
		for (i = 0; i < tmp_channel.remote_addres_size; i++)
		{
#ifdef _DEBUG
			char buf[MAX_IPADDR_STR_LEN];
			saddr2str(&tmp_channel.remote_addres[i], buf, MAX_IPADDR_STR_LEN,
				NULL);
			EVENTLOG2(VERBOSE, "temp.remote_addres[%d]::%s", i, buf);
#endif
			for (j = 0; j < b.remote_addres_size; j++)
			{
#ifdef _DEBUG
				saddr2str(&(b.remote_addres[j]), buf, MAX_IPADDR_STR_LEN, NULL);
				EVENTLOG2(VERBOSE, "b.remote_addres[%d]::%s", j, buf);
#endif
				if (saddr_equals(&(tmp_channel.remote_addres[i]), &(b.remote_addres[j]), true))
				{
					if (!tmp_channel.deleted && !b.deleted)
					{
#ifdef _DEBUG
						saddr2str(&(b.remote_addres[j]), buf,
							MAX_IPADDR_STR_LEN, NULL);
						EVENTLOG2(VERBOSE, "cmp_endpoint_by_addr_port():found equal channel"
							"set last_src_path_ to index %u, addr %s", j, buf);
#endif
						last_src_path_ = j;
						return true;
					}
				}
			}
		}
		EVENTLOG(VERBOSE, "cmp_endpoint_by_addr_port(): addres NOT Equals !");
		return false;
	}
	else
	{
		EVENTLOG(VERBOSE, "cmp_endpoint_by_addr_port(): port NOT Equals !");
		return false;
	}
}

//////////////////////////////////////////////// Bundle Moudle (bu) Starts \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\/
/**
 * Creates a new bundling instance and returns a pointer to its data.
 * @return pointer to an instance of the bundling data
 */
bundle_controller_t* mbu_new()
{
	bundle_controller_t* bundle_ctrl = NULL;
	if ((bundle_ctrl = (bundle_controller_t*)geco_malloc_ext(sizeof(bundle_controller_t), __FILE__,
		__LINE__)) == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");
		return 0;
	}
	bundle_ctrl->sack_in_buffer = false;
	bundle_ctrl->ctrl_chunk_in_buffer = false;
	bundle_ctrl->data_in_buffer = false;
	bundle_ctrl->got_send_request = false;
	bundle_ctrl->got_send_address = false;
	bundle_ctrl->locked = false;
	bundle_ctrl->requested_destination = 0;
	bundle_ctrl->got_shutdown = false;
	return bundle_ctrl;
}

/////////////////////////////////////////////// Bundle Moudle (bu) Ends \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\/

/////////////////////////////////////////////// Path Management Moudle (pm) Starts \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\/
path_controller_t* mpath_new(short numberOfPaths, short primaryPath)
{
	assert(curr_channel_ != NULL);

	path_controller_t* pmData = NULL;
	if ((pmData = (path_controller_t*)geco_malloc_ext(sizeof(path_controller_t), __FILE__, __LINE__)) == NULL)
		ERRLOG(FALTAL_ERROR_EXIT, "Malloc failed");

	pmData->path_params = NULL;
	pmData->primary_path = primaryPath;
	pmData->path_num = numberOfPaths;
	pmData->channel_id = curr_channel_->channel_id;
	pmData->channel_ptr = curr_channel_;
	pmData->max_retrans_per_path = curr_geco_instance_->default_pathMaxRetransmits;
	pmData->rto_initial = curr_geco_instance_->default_rtoInitial;
	pmData->rto_min = curr_geco_instance_->default_rtoMin;
	pmData->rto_max = curr_geco_instance_->default_rtoMax;
	pmData->min_pmtu = PMTU_LOWEST;
	return pmData;
}
void mpath_free(path_controller_t *pmData)
{
	assert(pmData != NULL && pmData->path_params != NULL);
	EVENTLOG(INFO, "deleting pathmanagement");

	for (int i = 0; i < pmData->path_num; i++)
	{
		if (pmData->path_params[i].hb_timer_id != NULL)
		{
			mtra_timeouts_del(pmData->path_params[i].hb_timer_id);
			pmData->path_params[i].hb_timer_id = 0;
		}
	}
	geco_free_ext(pmData->path_params, __FILE__, __LINE__);
}

/////////////////////////////////////////////// State Machina Moudle (sm) Ends \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\/
smctrl_t* msm_new(void)
{
	assert(curr_channel_ != NULL);
	smctrl_t* tmp = new smctrl_t();
	tmp->channel_state = ChannelState::Closed;
	tmp->init_timer_id = NULL;
	tmp->init_timer_interval = RTO_INITIAL;
	tmp->init_retrans_count = 0;
	tmp->channel_id = curr_channel_->channel_id;
	tmp->my_init_chunk = NULL;
	tmp->peer_cookie_chunk = NULL;
	tmp->ordered_streams = curr_geco_instance_->ordered_streams;
	tmp->sequenced_streams = curr_geco_instance_->sequenced_streams;
	tmp->local_tie_tag = 0;
	tmp->peer_tie_tag = 0;
	tmp->max_init_retrans_count = curr_geco_instance_->default_maxInitRetransmits;
	tmp->max_assoc_retrans_count = curr_geco_instance_->default_assocMaxRetransmits;
	tmp->cookie_lifetime = curr_geco_instance_->default_validCookieLife;
	tmp->instance = curr_geco_instance_;
	tmp->channel = curr_channel_;
	return tmp;
}
/////////////////////////////////////////////// State Machina Moudle (sm) Ends \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\/

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
bool mdi_new_channel(geco_instance_t* instance, ushort local_port, ushort remote_port, uint tagLocal,
	short primaryDestinitionAddress, ushort noOfDestinationAddresses, sockaddrunion *destinationAddressList)
{
	assert(instance != NULL);
	assert(noOfDestinationAddresses > 0);
	assert(destinationAddressList != NULL);
	assert(primaryDestinitionAddress >= 0);
	assert(primaryDestinitionAddress < noOfDestinationAddresses);

	EVENTLOG5(DEBUG, "mdi_new_channel()::Instance: %u, local port %u, rem.port: %u, local tag: %u, primary: %d",
		instance->dispatcher_name, local_port, remote_port, tagLocal, primaryDestinitionAddress);

	curr_channel_ = (geco_channel_t*)geco_malloc_ext(sizeof(geco_channel_t), __FILE__,
		__LINE__);
	assert(curr_channel_ != NULL);
	curr_channel_->geco_inst = instance;
	curr_channel_->local_port = local_port;
	curr_channel_->remote_port = remote_port;
	curr_channel_->local_tag = tagLocal;
	curr_channel_->remote_tag = 0;
	curr_channel_->deleted = false;
	curr_channel_->ulp_dataptr = NULL;
	curr_channel_->ipTos = instance->default_ipTos;
	curr_channel_->maxSendQueue = instance->default_maxSendQueue;
	curr_channel_->maxRecvQueue = instance->default_maxRecvQueue;

	// init local addrlist
	int maxMTU;
	uint ii;

	if (defaultlocaladdrlistsize_ == 0)
	{  //expensicve call, only call it one time
		get_local_addresses(&defaultlocaladdrlist_, &defaultlocaladdrlistsize_,
			mtra_read_ip4rawsock() == 0 ? mtra_read_ip6rawsock() : mtra_read_ip4rawsock(), true, &maxMTU,
			IPAddrType::AllCastAddrTypes);
	}
	if (instance->is_inaddr_any && instance->is_in6addr_any)
	{
		//use all addrlist
		curr_channel_->local_addres_size = defaultlocaladdrlistsize_;
		curr_channel_->local_addres = defaultlocaladdrlist_;
		EVENTLOG1(DEBUG,
			"mdi_new_channel()::gec inst  is_in6addr_any and is_inaddr_any both true, use default local addrlist size %d",
			defaultlocaladdrlistsize_);
	}
	else
	{
		curr_channel_->local_addres_size = 0;  //ip6size
		curr_channel_->remote_addres_size = 0;  //ip4size
		for (ii = 0; ii < defaultlocaladdrlistsize_; ii++)
		{
			if (saddr_family(&(defaultlocaladdrlist_[ii])) == AF_INET6)
				curr_channel_->local_addres_size++;
			else if (saddr_family(&(defaultlocaladdrlist_[ii])) == AF_INET)
				curr_channel_->remote_addres_size++;
			else
				ERRLOG(FALTAL_ERROR_EXIT, "mdi_new_channel()::no such af !");
		}
		if (instance->is_inaddr_any)
		{
			// only use ip4 addrlist
			curr_channel_->local_addres_size = curr_channel_->remote_addres_size;
			curr_channel_->local_addres = defaultlocaladdrlist_;
			EVENTLOG1(DEBUG, "mdi_new_channel()::gec inst  is_inaddr_any  true, use IP4 addres size=%d",
				curr_channel_->local_addres_size);
		}
		else if (instance->is_in6addr_any)  // get all IPv4 addresses
		{
			//only use ip6 addrlist
			curr_channel_->local_addres = defaultlocaladdrlist_ + curr_channel_->remote_addres_size;
			EVENTLOG1(VERBOSE, "mdi_new_channel()::gec inst  is_in6addr_any  true, use addres size=%d",
				curr_channel_->local_addres_size);
		}
		else
		{
			// no any is set, use localaddrlist in geco inst
			curr_channel_->local_addres_size = instance->local_addres_size;
			curr_channel_->local_addres = instance->local_addres_list;
			EVENTLOG1(VERBOSE,
				"mdi_new_channel()::gec inst  is_inaddr_any false, is_in6addr_any  false, use use localaddrlist in geco inst, addrsize=%d",
				curr_channel_->local_addres_size);
		}
	}

	curr_channel_->is_IN6ADDR_ANY = instance->is_in6addr_any;
	curr_channel_->is_INADDR_ANY = instance->is_inaddr_any;
	curr_channel_->remote_addres_size = noOfDestinationAddresses;
	curr_channel_->remote_addres = destinationAddressList;
	curr_channel_->locally_supported_PRDCTP = instance->supportsPRSCTP;
	curr_channel_->remotely_supported_PRSCTP = false;
	curr_channel_->locally_supported_ADDIP = instance->supportsADDIP;
	curr_channel_->remotely_supported_ADDIP = false;

	for (uint i = 0; i < channels_size_; i++)
	{
		if (channels_[i] != NULL && cmp_channel(*curr_channel_, *channels_[i]))
		{
			geco_free_ext(curr_channel_, __FILE__, __LINE__);
			curr_channel_ = NULL;
			ERRLOG(FALTAL_ERROR_EXIT, "mdi_new_channel()::tried to alloc an existing channel -> return false !");
			return false;
		}
	}

	curr_channel_->remote_addres = (sockaddrunion*)geco_malloc_ext(noOfDestinationAddresses * sizeof(sockaddrunion),
		__FILE__, __LINE__);

	//memcpy(curr_channel_->remote_addres, destinationAddressList, noOfDestinationAddresses * sizeof(sockaddrunion));
	memcpy_fast(curr_channel_->remote_addres, destinationAddressList, noOfDestinationAddresses * sizeof(sockaddrunion));

	//insert channel pointer to vector
	if (available_channel_ids_size_ == 0)
	{
		curr_channel_->channel_id = channels_size_;
		channels_[channels_size_] = curr_channel_;
		channels_size_++;
	}
	else
	{
		available_channel_ids_size_--;
		curr_channel_->channel_id = available_channel_ids_[available_channel_ids_size_];
		channels_[curr_channel_->channel_id] = curr_channel_;
	}

	curr_channel_->flow_control = NULL;
	curr_channel_->reliable_transfer_control = NULL;
	curr_channel_->receive_control = NULL;
	curr_channel_->deliverman_control = NULL;

	/* only pathman, bundling and sctp-control are created at this point, the rest is created with mdi_initAssociation */
	curr_channel_->bundle_control = mbu_new();
	EVENTLOG1(DEBUG, "mdi_new_channel()::new bundle module for channel %d", curr_channel_->channel_id);
	curr_channel_->path_control = mpath_new(noOfDestinationAddresses, primaryDestinitionAddress);
	EVENTLOG1(DEBUG, "mdi_new_channel()::new path module for channel %d", curr_channel_->channel_id);
	curr_channel_->state_machine_control = msm_new();
	EVENTLOG1(DEBUG, "mdi_new_channel()::new state machina module for channel %d", curr_channel_->channel_id);

	return true;
}

int mch_read_addrlist_from_cookie(cookie_echo_chunk_t* cookiechunk, uint mySupportedTypes,
	sockaddrunion addresses[MAX_NUM_ADDRESSES], uint*peerSupportedAddressTypes, sockaddrunion* lastSource)
{
#ifdef _DEBUG
	EVENTLOG(VERBOSE, "Enter mch_read_addrlist_from_cookie()");
#endif

	assert(cookiechunk != NULL);
	assert(cookiechunk->chunk_header.chunk_id == CHUNK_COOKIE_ECHO);
	int nAddresses;
	int vl_param_total_length;
	ushort no_loc_ipv4_addresses, no_remote_ipv4_addresses;
	ushort no_loc_ipv6_addresses, no_remote_ipv6_addresses;
	sockaddrunion temp_addresses[MAX_NUM_ADDRESSES];

	no_loc_ipv4_addresses = ntohs(cookiechunk->cookie.no_local_ipv4_addresses);
	no_remote_ipv4_addresses = ntohs(cookiechunk->cookie.no_remote_ipv4_addresses);
	no_loc_ipv6_addresses = ntohs(cookiechunk->cookie.no_local_ipv6_addresses);
	no_remote_ipv6_addresses = ntohs(cookiechunk->cookie.no_remote_ipv6_addresses);
	vl_param_total_length = cookiechunk->chunk_header.chunk_length - CHUNK_FIXED_SIZE - COOKIE_FIXED_SIZE;

#ifdef _DEBUG
	EVENTLOG1(DEBUG, " Computed total length of vparams : %d", vl_param_total_length);
	EVENTLOG2(DEBUG, " Num of local/remote IPv4 addresses %u / %u", no_loc_ipv4_addresses, no_remote_ipv4_addresses);
	EVENTLOG2(DEBUG, " Num of local/remote IPv6 addresses %u / %u", no_loc_ipv6_addresses, no_remote_ipv6_addresses);
#endif

	nAddresses = mdi_read_peer_addreslist(temp_addresses, (uchar*)cookiechunk, cookiechunk->chunk_header.chunk_length,
		curr_geco_instance_->supportedAddressTypes, peerSupportedAddressTypes, false/*ignore dups*/,
		true/*ignore last src addr*/);

	if ((nAddresses
		!= (no_loc_ipv4_addresses + no_remote_ipv4_addresses + no_loc_ipv6_addresses + no_remote_ipv6_addresses))
		|| (!(*peerSupportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV4)
			&& !(*peerSupportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV6))
		|| (no_remote_ipv4_addresses > 0 && !(*peerSupportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV4))
		|| (no_remote_ipv6_addresses > 0 && !(*peerSupportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV6))
		|| (no_loc_ipv4_addresses > 0 && !(mySupportedTypes & SUPPORT_ADDRESS_TYPE_IPV4))
		|| (no_loc_ipv6_addresses > 0 && !(mySupportedTypes & SUPPORT_ADDRESS_TYPE_IPV6)))
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mch_read_addrlist_from_cookie() invalidate addres");
		return -1;
	}

	//copy remote ip4 and ip6 addrlist
	EVENTLOG(DEBUG, "+++++++++++++++++temp_addresses are :: \n");
	print_addrlist(temp_addresses, nAddresses);

	if (no_remote_ipv4_addresses > 0)
		memcpy_fast(addresses, &temp_addresses[no_loc_ipv4_addresses + no_loc_ipv6_addresses],
			no_remote_ipv4_addresses * sizeof(sockaddrunion));

	if (no_remote_ipv6_addresses > 0)
		memcpy_fast(&addresses[no_remote_ipv4_addresses],
			&temp_addresses[no_loc_ipv4_addresses + no_loc_ipv6_addresses + no_remote_ipv4_addresses],
			no_remote_ipv6_addresses * sizeof(sockaddrunion));

#ifdef _DEBUG
	EVENTLOG(DEBUG, "mch_read_addrlist_from_cookie():: remote addr from cookie are:: ");
	print_addrlist(addresses, no_remote_ipv6_addresses + no_remote_ipv4_addresses);
#endif
	return (no_remote_ipv4_addresses + no_remote_ipv6_addresses);
}

void mdi_set_channel_remoteaddrlist(sockaddrunion addresses[MAX_NUM_ADDRESSES], int noOfAddresses)
{
#ifdef _DEBUG
	EVENTLOG1(DEBUG, "- - - - - Enter mdi_set_channel_remoteaddrlist(noOfAddresses =%d)", noOfAddresses);
#endif

	assert(curr_channel_ != NULL);
	if (curr_channel_->remote_addres_size > 0 && curr_channel_->remote_addres != NULL)
	{
		geco_free_ext(curr_channel_->remote_addres, __FILE__, __LINE__);
		channel_map_.clear();
		curr_channel_->remote_addres = NULL;
		curr_channel_->remote_addres_size = 0;
	}

	curr_channel_->remote_addres = (sockaddrunion*)geco_malloc_ext(noOfAddresses * sizeof(sockaddrunion), __FILE__,
		__LINE__);
	assert(curr_channel_->remote_addres != NULL);
	memcpy_fast(curr_channel_->remote_addres, addresses, noOfAddresses * sizeof(sockaddrunion));
	curr_channel_->remote_addres_size = noOfAddresses;

	//insert channel id to map
	for (uint i = 0; i < curr_channel_->local_addres_size; i++)
	{
		curr_trans_addr_.local_saddr = curr_channel_->local_addres + i;
		curr_trans_addr_.local_saddr->sa.sa_family == AF_INET ?
			curr_trans_addr_.local_saddr->sin.sin_port = htons(curr_channel_->local_port) :
			curr_trans_addr_.local_saddr->sin6.sin6_port = htons(curr_channel_->local_port);
		for (uint ii = 0; ii < curr_channel_->remote_addres_size; ii++)
		{
			curr_trans_addr_.peer_saddr = curr_channel_->remote_addres + ii;
			if (curr_trans_addr_.local_saddr->sa.sa_family != curr_trans_addr_.peer_saddr->sa.sa_family)
				continue;
			if (channel_map_.find(curr_trans_addr_) != channel_map_.end())
				continue;
			channel_map_.insert(std::make_pair(curr_trans_addr_, curr_channel_->channel_id));
		}
	}

#ifdef _DEBUG
	EVENTLOG(DEBUG, "mdi_set_channel_remoteaddrlist():: remote addr from cookie are:: ");
	print_addrlist(addresses, noOfAddresses);
#endif
}

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
static void msm_process_cookie_echo_chunk(cookie_echo_chunk_t * cookie_echo)
{
	EVENTLOG(VERBOSE, "Enter msm_process_cookie_echo_chunk()");

	/*
	 @rememberme:
	 cookie_echo_chunk received with channel exists
	 or not can shoare the same authentication prodecures
	 except of cookie life time handle
	 5.1.5 State Cookie Authentication &&
	 5.2.4 Hnadle a cookie echo when a TCB exists*/

	 /* 5.1.5.1)
	  * Compute a MAC using the TCB data carried in the State Cookie and
	  * the secret key (note the timestamp in the State Cookie MAY be
	  * used to determine which secret key to use).*/
	chunk_id_t cookie_echo_cid = mch_make_simple_chunk((simple_chunk_t*)cookie_echo);
	if (cookie_echo->chunk_header.chunk_id != CHUNK_COOKIE_ECHO)
	{
		mch_remove_simple_chunk(cookie_echo_cid);
		EVENTLOG(NOTICE, "cookie_echo->chunk_header.chunk_id != CHUNK_COOKIE_ECHO -> return");
		return;
	}

	/* 5.1.5.2)
	 * Authenticate the State Cookie as one that it previously generated
	 * by comparing the computed MAC against the one carried in the
	 * State Cookie.  If this comparison fails, the SCTP packet,
	 * including the COOKIE ECHO and any DATA chunks, should be silently discarded*/
	if (!mch_verify_hmac(cookie_echo))
	{
		mch_remove_simple_chunk(cookie_echo_cid);
		EVENTLOG(NOTICE, "mch_verify_hmac() failed ! -> return");
		return;
	}

	/* 5.1.5.3)
	 * Compare the port numbers and the Verification Tag contained
	 * within the COOKIE ECHO chunk to the actual port numbers and the
	 * Verification Tag within the SCTP common header of the received
	 * packet.  If these values do not match, the packet MUST be silently discarded.*/
	chunk_id_t initCID = mch_make_init_chunk_from_cookie(cookie_echo);
	chunk_id_t initAckCID = mch_make_init_ack_chunk_from_cookie(cookie_echo);
	uint cookie_remote_tag = mch_read_itag(initCID);
	uint cookie_local_tag = mch_read_itag(initAckCID);
	uint local_tag = mdi_read_local_tag();
	uint remote_tag = mdi_read_remote_tag();

	bool valid = true;
	if (last_veri_tag_ != cookie_local_tag)
	{
		EVENTLOG(NOTICE, "validate cookie echo failed as last_veri_tag_ != cookie_local_tag! -> return");
		valid = false;
	}
	if (last_dest_port_ != ntohs(cookie_echo->cookie.dest_port))
	{
		EVENTLOG(NOTICE, "validate cookie echo failed as last_dest_port_ != cookie.dest_port -> return");
		valid = false;
	}
	if (last_src_port_ != ntohs(cookie_echo->cookie.src_port))
	{
		EVENTLOG(NOTICE, "validate cookie echo failed as last_src_port_ != cookie.src_port -> return");
		valid = false;
	}

	if (valid == false)
	{
		mch_remove_simple_chunk(cookie_echo_cid);
		mch_free_simple_chunk(initCID);
		mch_free_simple_chunk(initAckCID);
		EVENTLOG(NOTICE, "line 4137 msm_process_cookie_echo_chunk()::validate cookie echo failed ! -> return");
		return;
	}

	/* 5.1.5.4)
	 * Compare the creation timestamp in the State Cookie to the current
	 * local time.If the elapsed time is longer than the lifespan
	 * carried in the State Cookie, then the packet, including the
	 *	COOKIE ECHO and any attached DATA chunks, SHOULD be discarded,
	 *	and the endpoint MUST transmit an ERROR chunk with a "Stale
	 *	Cookie" error cause to the peer endpoint.*/
	chunk_id_t errorCID;
	cookiesendtime_ = ntohl(cookie_echo->cookie.sendingTime);
	currtime_ = get_safe_time_ms();
	cookielifetime_ = currtime_ - cookiesendtime_;

	if (cookielifetime_ > ntohl(cookie_echo->cookie.cookieLifetime))
	{
		bool senderror = true;
		if (curr_channel_ != NULL && local_tag == cookie_local_tag && remote_tag == cookie_remote_tag)
		{
			senderror = false;
		}
		if (senderror == true)
		{
			EVENTLOG2(NOTICE,
				curr_channel_ == NULL ? "msm_process_cookie_echo_chunk()::curr_channel_ == NULL and actual cookielifetime_ %u ms > cookie cookielifetime_ %u -> send error chunk of stale cookie! -> discard packet!" : "msm_process_cookie_echo_chunk()::curr_channel_ != NULL and actual cookielifetime_ %u ms > cookie cookielifetime_ %u" "and veri tags not matched (local_tag %u : cookie_local_tag %u, remote_tag %u : cookie_remote_tag %u)->" "send error chunk of stale cookie! -> discard packet!",
				cookie_echo->cookie.cookieLifetime, cookielifetime_);

			last_init_tag_ = cookie_remote_tag; // peer's init tag in previously sent INIT chunk to us
			uint staleness = htonl(cookielifetime_);
			errorCID = mch_make_simple_chunk(CHUNK_ERROR, FLAG_TBIT_UNSET);
			mch_write_error_cause(errorCID, ECC_STALE_COOKIE_ERROR, (uchar*)&staleness, sizeof(uint));
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(errorCID));
			mch_free_simple_chunk(errorCID);
			mch_remove_simple_chunk(cookie_echo_cid);
			mch_free_simple_chunk(initCID);
			mch_free_simple_chunk(initAckCID);
			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();
			return;
		}
	}

	assert(last_source_addr_ != NULL);
	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		if (!mdi_new_channel(curr_geco_instance_, last_dest_port_, last_src_port_, cookie_local_tag,/*local tag*/
			0,/*primaryDestinationAddress*/
			1, /*noOfDestinationAddresses*/
			last_source_addr_))
		{
			EVENTLOG(NOTICE, "line 4191 msm_process_cookie_echo_chunk()::mdi_new_channel() failed ! -> discard!");
			mch_remove_simple_chunk(cookie_echo_cid);
			mch_free_simple_chunk(initCID);
			mch_free_simple_chunk(initAckCID);
			return;
		}
		smctrl = mdi_read_smctrl();
		assert(smctrl != NULL);
	}

	int SendCommUpNotification = 0;
	ChannelState newstate = UnknownChannelState;
	ChannelState state = smctrl->channel_state;
	EVENTLOG5(DEBUG, "State: %u, cookie_remote_tag: %u , cookie_local_tag: %u, remote_tag: %u , local_tag : %u", state,
		cookie_remote_tag, cookie_local_tag, remote_tag, local_tag);

	// Normal Case recv COOKIE_ECHO at CLOSE state
	if (smctrl->channel_state == Closed)
	{
		EVENTLOG(DEBUG, "event: msm_process_cookie_echo_chunk in state CLOSED -> Normal Case");

		// tie tags are only populated at connecting end in process_init_ack()
		// here they must be all zeros as this is normal connection case
		assert(smctrl->local_tie_tag == 0 && smctrl->peer_tie_tag == 0);

		tmp_peer_addreslist_size_ = mch_read_addrlist_from_cookie(cookie_echo, curr_geco_instance_->supportedAddressTypes,
			tmp_peer_addreslist_, &tmp_peer_supported_types_, last_source_addr_);
		if (tmp_peer_addreslist_size_ > 0)
		{
			mdi_set_channel_remoteaddrlist(tmp_peer_addreslist_, tmp_peer_addreslist_size_);
		}

		mdi_init_channel(mch_read_rwnd(initCID), mch_read_ordered_streams(initAckCID),
			mch_read_sequenced_streams(initAckCID), mch_read_itsn(initCID), cookie_remote_tag, mch_read_itsn(initAckCID),
			peer_supports_pr(cookie_echo), peer_supports_addip(cookie_echo));

		//reset mbu
		assert(default_bundle_ctrl_->geco_packet_fixed_size != 0);
		curr_channel_->bundle_control->geco_packet_fixed_size = curr_channel_->bundle_control->ctrl_position =
			curr_channel_->bundle_control->data_position = curr_channel_->bundle_control->sack_position =
			default_bundle_ctrl_->geco_packet_fixed_size;

		smctrl->ordered_streams = mch_read_ordered_streams(initAckCID);
		smctrl->sequenced_streams = mch_read_sequenced_streams(initAckCID);
		ushort cookiesize = cookie_echo->chunk_header.chunk_length;
		smctrl->peer_cookie_chunk = (cookie_echo_chunk_t*)geco_malloc_ext(cookiesize, __FILE__, __LINE__);
		memcpy_fast(smctrl->peer_cookie_chunk, cookie_echo, cookiesize);
		EVENTLOG2(VERBOSE, "set msms ordered_streams to %u, sequenced_streams to %u", smctrl->ordered_streams,
			smctrl->sequenced_streams);

		//bundle and send cookie ack
		cookie_ack_cid_ = mch_make_simple_chunk(CHUNK_COOKIE_ACK, FLAG_TBIT_UNSET);
		mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(cookie_ack_cid_));
		mch_free_simple_chunk(cookie_ack_cid_);

		mdi_unlock_bundle_ctrl();
		mdi_send_bundled_chunks();

		// notification to ULP
		SendCommUpNotification = COMM_UP_RECEIVED_VALID_COOKIE;
		newstate = ChannelState::Connected;
	}

	//Sick Cases Recv COOKIE_ECHO when channel presents
	else
	{
		EVENTLOG(DEBUG, "event: msm_process_cookie_echo_chunk in state other than CLOSED -> Sick Case");

		cookie_local_tie_tag_ = ntohl(cookie_echo->cookie.local_tie_tag);
		cookie_remote_tie_tag_ = ntohl(cookie_echo->cookie.peer_tie_tag);
		EVENTLOG4(VERBOSE, "cookie_remote_tie_tag ; %u , cookie_local_tie_tag : %u,"
			"remote_tag ; %u , local_tag : %u ", cookie_remote_tie_tag_, cookie_local_tie_tag_, remote_tag, local_tag);

		//XXMM->ACTION 5.2.4.A
		if (local_tag != cookie_local_tag && remote_tag != cookie_remote_tag
			&& cookie_local_tie_tag_ == smctrl->local_tie_tag && cookie_remote_tie_tag_ == smctrl->peer_tie_tag)
		{  // what happens to SCTP data chunks is implementation specific
			if (state != ChannelState::ShutdownAckSent)
			{
				tmp_peer_addreslist_size_ = mch_read_addrlist_from_cookie(cookie_echo,
					curr_geco_instance_->supportedAddressTypes, tmp_peer_addreslist_, &tmp_peer_supported_types_,
					last_source_addr_);
				if (mdi_restart_channel(mch_read_rwnd(initCID), /*remoteSideReceiverWindow*/
					mch_read_ordered_streams(initAckCID), mch_read_sequenced_streams(initAckCID), mch_read_itsn(initCID),/*remoteInitialTSN*/
					mch_read_itsn(initAckCID), /*localInitialTSN*/
					0,/*primaryAddress*/
					tmp_peer_addreslist_size_, tmp_peer_addreslist_, peer_supports_pr(cookie_echo),
					peer_supports_addip(cookie_echo)) == true)
				{
					curr_channel_->remote_tag = cookie_remote_tag;
					curr_channel_->local_tag = cookie_local_tag;
					newstate = ChannelState::Connected;	// enters CONNECTED state
					SendCommUpNotification = COMM_UP_RECEIVED_COOKIE_RESTART; // notification to ULP
					//bundle and send cookie ack
					cookie_ack_cid_ = mch_make_simple_chunk(CHUNK_COOKIE_ACK,
						FLAG_TBIT_UNSET);
					mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(cookie_ack_cid_));
					mch_free_simple_chunk(cookie_ack_cid_);
					mdi_unlock_bundle_ctrl();
					mdi_send_bundled_chunks();
					EVENTLOG(INFO, "event: recv COOKIE-ECHO, sick case peer restarts, take action 5.2.4.A -> connected!");
				}
				else
				{
					/* silently discard */
					EVENTLOG(NOTICE,
						"event: recv COOKIE-ECHO, sick case peer restarts, take action 5.2.4.A -> Restart not successful, silently discarding CookieEcho");
					/* process data as usual ? */
				}
			}
			else
			{
				EVENTLOG(INFO,
					"event: recv COOKIE-ECHO, sick case peer restarts, take action 5.2.4.A ->"
					"Peer Restart case at state SHUTDOWN_ACK_SENT->resend CHUNK_SHUTDOWN_ACK and ECC_COOKIE_RECEIVED_DURING_SHUTDWN");
				chunk_id_t shutdownAckCID = mch_make_simple_chunk(
					CHUNK_SHUTDOWN_ACK,
					FLAG_TBIT_UNSET);
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shutdownAckCID));
				mch_free_simple_chunk(shutdownAckCID);

				errorCID = mch_make_simple_chunk(CHUNK_ERROR, FLAG_TBIT_UNSET);
				mch_write_error_cause(errorCID,
					ECC_COOKIE_RECEIVED_DURING_SHUTDWN);
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(errorCID));
				mch_free_simple_chunk(errorCID);

				mdi_unlock_bundle_ctrl();
				mdi_send_bundled_chunks();
			}
		}
		//MXAA, ACTION 5.2.4.B
		else if (local_tag == cookie_local_tag && remote_tag != cookie_remote_tag)
		{
			EVENTLOG(INFO, "event: recv COOKIE-ECHO, it is sick case of connection collision, take action 5.2.4.B !");
			// initalize my channel with cookie geco_instance_params
			if ((tmp_peer_addreslist_size_ = mch_read_addrlist_from_cookie(cookie_echo,
				curr_geco_instance_->supportedAddressTypes, tmp_peer_addreslist_, &tmp_peer_supported_types_,
				last_source_addr_)) > 0)
			{
				mdi_set_channel_remoteaddrlist(tmp_peer_addreslist_, tmp_peer_addreslist_size_);
			}

			ushort ordered_streams = mch_read_ordered_streams(initAckCID);
			ushort sequenced_streams = mch_read_sequenced_streams(initAckCID);
			mdi_init_channel(mch_read_rwnd(initCID), ordered_streams, sequenced_streams, mch_read_itsn(initCID),
				cookie_remote_tag, mch_read_itsn(initAckCID), peer_supports_pr(cookie_echo),
				peer_supports_addip(cookie_echo));

			smctrl->ordered_streams = ordered_streams;
			smctrl->sequenced_streams = sequenced_streams;
			EVENTLOG2(VERBOSE, "set msm ordered_streams to %u, sequenced_streams to %u", smctrl->ordered_streams,
				smctrl->sequenced_streams);

			// update my remote tag with cookie remote tag
			curr_channel_->remote_tag = cookie_remote_tag;
			// enters CONNECTED state
			newstate = ChannelState::Connected;
			// notification to ULP
			SendCommUpNotification = COMM_UP_RECEIVED_VALID_COOKIE;
			// stop t1-init timer
			if (smctrl->init_timer_id != NULL)
			{
				mtra_timeouts_del(smctrl->init_timer_id);
				smctrl->init_timer_id = NULL;
			}
			//bundle and send cookie ack
			cookie_ack_cid_ = mch_make_simple_chunk(CHUNK_COOKIE_ACK,
				FLAG_TBIT_UNSET);
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(cookie_ack_cid_));
			mch_free_simple_chunk(cookie_ack_cid_);
			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();
		}
#ifdef _DEBUG
		//XM00->ACTION 5.2.4.C
		else if (local_tag != cookie_local_tag && remote_tag == cookie_remote_tag && cookie_local_tie_tag_ == 0
			&& cookie_remote_tie_tag_ == 0)
		{
			EVENTLOG(DEBUG,
				"event: recv COOKIE-ECHO, it is sick case of connection collision, take action 5.2.4.C -> Silently discard !");
		}
#endif
		//MMAA, ACTION 5.2.4.D
		else if (local_tag == cookie_local_tag && remote_tag == cookie_remote_tag)
		{  //MMAA, ACTION 5.2.4.D - CONNECTION COLLISION
			EVENTLOG(INFO, "event: recv COOKIE-ECHO, it is sick case of connection collision, take action 5.2.4.D !");
			if (state == ChannelState::CookieEchoed)
			{
				// initalize my channel with cookie geco_instance_params
				if ((tmp_peer_addreslist_size_ = mch_read_addrlist_from_cookie(cookie_echo,
					curr_geco_instance_->supportedAddressTypes, tmp_peer_addreslist_, &tmp_peer_supported_types_,
					last_source_addr_)) > 0)
				{
					mdi_set_channel_remoteaddrlist(tmp_peer_addreslist_, tmp_peer_addreslist_size_);
				}

				uint peer_rwnd = mch_read_rwnd(initCID);
				ushort ordered_streams = mch_read_ordered_streams(initAckCID);
				ushort sequenced_streams = mch_read_sequenced_streams(initAckCID);
				uint peer_itsn = mch_read_itsn(initCID);
				uint our_itsn = mch_read_itsn(initAckCID);
				bool peer_spre = peer_supports_pr(cookie_echo);
				bool peer_saddip = peer_supports_addip(cookie_echo);
				mdi_init_channel(peer_rwnd, ordered_streams, sequenced_streams, peer_itsn, cookie_remote_tag, our_itsn,
					peer_spre, peer_saddip);

				smctrl->ordered_streams = ordered_streams;
				smctrl->sequenced_streams = sequenced_streams;
				EVENTLOG2(VERBOSE, "set msm ordered_streams to %u, sequenced_streams to %u", smctrl->ordered_streams,
					smctrl->sequenced_streams);

				// stop t1-init timer
				if (smctrl->init_timer_id != NULL)
				{
					mtra_timeouts_del(smctrl->init_timer_id);
					smctrl->init_timer_id = NULL;
				}

				newstate = ChannelState::Connected;	 // enters CONNECTED state
				SendCommUpNotification = COMM_UP_RECEIVED_VALID_COOKIE; // notification to ULP
				EVENTLOG(INFO, "****************************** ENTER CONNECTED STATE**********************");

				//bundle and send cookie ack
				cookie_ack_cid_ = mch_make_simple_chunk(CHUNK_COOKIE_ACK,
					FLAG_TBIT_UNSET);
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(cookie_ack_cid_));
				mch_free_simple_chunk(cookie_ack_cid_);
				mdi_unlock_bundle_ctrl();
				mdi_send_bundled_chunks();
			}
		}
#ifdef _DEBUG
		// NOt matched silently discard
		else
		{
			EVENTLOG(DEBUG, "event: recv COOKIE-ECHO, it is sick case with no matched case -> discard !");
			//todo
		}
#endif
	}

	mch_remove_simple_chunk(cookie_echo_cid);
	mch_free_simple_chunk(initCID);
	mch_free_simple_chunk(initAckCID);

	if (newstate != UnknownChannelState)
		smctrl->channel_state = newstate;

	if (SendCommUpNotification == COMM_UP_RECEIVED_VALID_COOKIE)
		mdi_on_peer_connected(SendCommUpNotification);
	else if (SendCommUpNotification == COMM_UP_RECEIVED_COOKIE_RESTART)
		mdi_on_peer_restarted();

	EVENTLOG(VERBOSE, "Leave msm_process_cookie_echo_chunk()");
}

int msm_process_abort_chunk()
{
	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "msm_abort_channel()::smctrl is NULL!");
		return -1;
	}
	if (smctrl->channel_state == ChannelState::Closed)
	{
		EVENTLOG(DEBUG, "event: recv abort chunk  in state CLOSED ---> discard");
		return ChunkProcessResult::Good;
	}

	if (smctrl->init_timer_id != NULL)
	{  //stop init timer
		mtra_timeouts_del(smctrl->init_timer_id);
		smctrl->init_timer_id = NULL;
	}

	mdi_unlock_bundle_ctrl();
	mdi_on_disconnected(ConnectionLostReason::PeerAbortConnection);
	mdi_delete_curr_channel();
	mdi_clear_current_channel();

	return ChunkProcessResult::StopProcessAndDeleteChannel;
}

static void msm_process_stale_cookie(simple_chunk_t* error_chunk)
{
	chunk_id_t errorCID = mch_make_simple_chunk(error_chunk);
	if (mch_read_chunk_type(errorCID) != CHUNK_ERROR)
	{
		/* error logging */
		mch_remove_simple_chunk(errorCID);
		EVENTLOG(NOTICE, "msm_process_stale_cookie()::wrong chunk type ---> return !");
		return;
	}

	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "msm_abort_channel()::smctrl is NULL!");
	}

	if (smctrl->channel_state != ChannelState::CookieEchoed)
	{
		EVENTLOG(NOTICE,
			"msm_process_stale_cookie()::recv stale_cookie error chunk  in state other than CookieEchoed ---> discard!");
	}
	else
	{
		// make chunkHandler init chunk from stored init chunk string
		chunk_id_t initCID = mch_make_simple_chunk((simple_chunk_t*)smctrl->my_init_chunk);
		/* read staleness from error chunk and enter it into the cookie preserv. */
		uint staleness = mch_read_cookie_staleness(errorCID);

		if (staleness > 0)
		{
			mch_write_cookie_preserve(initCID, staleness);
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(initCID)); // resend init
			mdi_send_bundled_chunks();
			mch_remove_simple_chunk(initCID);
			smctrl->channel_state = ChannelState::CookieWait;
		}
	}
}

static void msm_process_error_chunk(simple_chunk_t* errchunk)
{
	//vlparam_fixed_t* header; //unused
	error_chunk_t* chunk = (error_chunk_t *)errchunk;
	error_cause_t *cause = (error_cause_t *)chunk->chunk_value;
	//uchar* data = cause->error_reason; //unused
	ushort err_cause = ntohs(cause->error_reason_code);
	ushort cause_len = ntohs(cause->error_reason_length);

	switch (err_cause)
	{
	case ECC_INVALID_STREAM_ID:
		EVENTLOG1(NOTICE, "Invalid Stream Id Error with Len %u ", cause_len);
		break;
	case ECC_MISSING_MANDATORY_PARAM:
		EVENTLOG1(NOTICE, "Missing Mandatory Parameter Error, Len %u ", cause_len);
		break;
	case ECC_STALE_COOKIE_ERROR:
		EVENTLOG1(NOTICE, "Stale Cookie Error, Len %u ", cause_len);
		msm_process_stale_cookie(errchunk);
		break;
	case ECC_OUT_OF_RESOURCE_ERROR:
		EVENTLOG1(NOTICE, "Out Of Resource Error with Len %u ", cause_len);
		break;
	case ECC_UNRESOLVABLE_ADDRESS:
		EVENTLOG1(NOTICE, "Unresovable Address Error with Len %u ", cause_len);
		break;
	case ECC_UNRECOGNIZED_CHUNKTYPE:
		EVENTLOG1(NOTICE, "Unrecognized Chunk Type Len %u ", cause_len);
		break;
	case ECC_INVALID_MANDATORY_PARAM:
		EVENTLOG1(NOTICE, "Invalid Mandatory Parameter : Len %u ", cause_len);
		break;
	case ECC_UNRECOGNIZED_PARAMS:
		EVENTLOG1(NOTICE, "Unrecognized Params Error with Len %u ", cause_len);
		break;
	case ECC_NO_USER_DATA:
		EVENTLOG1(NOTICE, "No User Data Error with Len %u ", cause_len);
		break;
	case ECC_COOKIE_RECEIVED_DURING_SHUTDWN:
		EVENTLOG1(NOTICE, "Error : Cookie Received During Shutdown, Len: %u ", cause_len);
		break;
	default:
		EVENTLOG2(MINOR_ERROR, "Unrecognized Error Cause %u with Len %u ", err_cause, cause_len);
	}
}

/**
 sctlr_cookieAck is called by bundling when a cookieAck chunk was received from  the peer.
 The only purpose is to inform the active side that peer has received the cookie chunk.
 The association is in established state after this function is called.
 Communication up is signalled to the upper layer in this case.
 @param cookieAck pointer to the received cookie ack chunk
 */
void msm_process_cookie_ack_chunk(simple_chunk_t* cookieAck)
{
	EVENTLOG(INFO, "****************** RECV CHUNK_COOKIE_ACK AT COOKIE_ECHOED STATE ********************");
	if (cookieAck->chunk_header.chunk_id != CHUNK_COOKIE_ACK)
	{
		ERRLOG(MINOR_ERROR, "msm_process_cookie_ack_chunk():  NOT CHUNK_COOKIE_ACK -> RETURN!");
		return;
	}
	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		ERRLOG(MINOR_ERROR, "msm_process_cookie_ack_chunk(): mdi_read_smctrl() returned NULL -> return !");
		return;
	}

	if (smctrl->channel_state != ChannelState::CookieEchoed)
	{
		/*Duplicated or unexpected cookie, ignore, do error logging  */
		EVENTLOG1(NOTICE, "unexpected event: recv cookieAck in state %d rather than CookieEchoed -> return",
			smctrl->channel_state);
		return;
	}

	// stop t1-init timer
	if (smctrl->init_timer_id != NULL)
	{
		mtra_timeouts_del(smctrl->init_timer_id);
		smctrl->init_timer_id = NULL;
	}

	chunk_id_t cookieAckCID = mch_make_simple_chunk(cookieAck);
	smctrl->my_init_chunk = NULL;
	smctrl->peer_cookie_chunk = NULL;
	mch_remove_simple_chunk(cookieAckCID);
	smctrl->channel_state = ChannelState::Connected;
	mdi_on_peer_connected(COMM_UP_RECEIVED_COOKIE_ACK);
}

int msm_process_shutdown_complete_chunk()
{
	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		ERRLOG(MINOR_ERROR, "msm_process_shutdown_complete_chunk(): mdi_read_smctrl() returned NULL -> return !");
		return -1;
	}
	ChunkProcessResult ret = ChunkProcessResult::Good;
	switch (smctrl->channel_state)
	{
	case ChannelState::Closed:
	case ChannelState::CookieWait:
	case ChannelState::CookieEchoed:
	case ChannelState::Connected:
	case ChannelState::ShutdownPending:
	case ChannelState::ShutdownReceived:
	case ChannelState::ShutdownSent:
		EVENTLOG1(NOTICE, "msm_process_shutdown_complete_chunk() in %02d state -> discrding !", smctrl->channel_state);
		break;

	case ChannelState::ShutdownAckSent:
		if (smctrl->init_timer_id == NULL)
			ERRLOG(FALTAL_ERROR_EXIT,
				"msm_process_shutdown_complete_chunk()::Timer not running at state ShutdownAckSent - problem in Program Logic!");
		mtra_timeouts_del(smctrl->init_timer_id);
		smctrl->init_timer_id = NULL;
		mpath_disable_all_hb();
		mdi_unlock_bundle_ctrl();
		mdi_delete_curr_channel();
		smctrl->channel_state = ChannelState::Closed;
		mdi_on_shutdown_completed();
		mdi_clear_current_channel();
		ret = ChunkProcessResult::StopProcessAndDeleteChannel;
		break;

	default:
		ERRLOG1(MINOR_ERROR, "msm_process_shutdown_complete_chunk() in state %02d: unexpected event",
			smctrl->channel_state);
		break;
	}
	return ret;
}

/// indicates gracefully shut down (chapter 10.2.H).Calls the respective ULP callback function.
void mdi_on_peer_shutdown_received()
{
	assert(curr_channel_ != NULL);
	assert(curr_channel_->geco_inst->ulp_callbacks.peerShutdownReceivedNotif != NULL);
	EVENTLOG1(INFO, "mdi_on_peer_shutdown()::channel_id %u", curr_channel_->channel_id);
	curr_channel_->geco_inst->ulp_callbacks.peerShutdownReceivedNotif(curr_channel_->channel_id,
		curr_channel_->ulp_dataptr);
}

/**
 * function that is called by SCTP-Control, when peer indicates
 * shutdown and sends us his last ctsna...this function dequeues
 * all chunks, and returns the number of chunks left in the queue
 * @param  ctsna    up to this tsn we can dequeue all chunks here
 * @return  number of chunks that are still queued
 */
void mrecv_process_ctsna_from_shutdown_chunk(uint ctsna)
{
	throw std::logic_error("The method or operation is not implemented.");
}

int msm_process_shutdown_chunk(simple_chunk_t* simple_chunk)
{
	assert(simple_chunk->chunk_header.chunk_id == CHUNK_SHUTDOWN);
	chunk_id_t shutdownCID = mch_make_simple_chunk(simple_chunk);
	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		ERRLOG(MINOR_ERROR, "msm_process_cookie_ack_chunk(): mdi_read_smctrl() returned NULL -> return !");
		mch_remove_simple_chunk(shutdownCID);
		return -1;
	}

	chunk_id_t abortCID, shutdownAckCID;
	int return_state = Good;
	bool readyForShutdown;

	switch (smctrl->channel_state)
	{
	case ChannelState::Closed:
		EVENTLOG(NOTICE, "event: receive shutdown chunk in state CLOSED, send ABORT ! ");
		abortCID = mch_make_simple_chunk(CHUNK_ABORT, FLAG_TBIT_SET);
		mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abortCID));
		mch_remove_simple_chunk(abortCID);
		mdi_unlock_bundle_ctrl();
		mdi_send_bundled_chunks();

		// delete all data of this association
		mdi_delete_curr_channel();
		mdi_on_disconnected(ConnectionLostReason::NO_TCB);
		mdi_clear_current_channel();
		return_state = StopProcessAndDeleteChannel;
		break;

	case ChannelState::CookieWait:
	case ChannelState::CookieEchoed:
	case ChannelState::ShutdownPending:
		EVENTLOG1(NOTICE, "event: receive shutdown chunk  in state %2u -> discarding !", smctrl->channel_state);
		break;

	case ChannelState::ShutdownReceived:
	case ChannelState::ShutdownAckSent:
		EVENTLOG(NOTICE, "event: receive shutdown chunk  in state SHUTDOWN_RECEIVED/SHUTDOWN_ACK_SENT -> acking CTSNA !");
		mrecv_process_ctsna_from_shutdown_chunk(mch_read_ctsna(shutdownCID));
		break;

	case ChannelState::ShutdownSent:
		EVENTLOG(NOTICE, "event: receive shutdown chunk  in state ShutdownSent -> shutdown collisons !");
		mrecv_process_ctsna_from_shutdown_chunk(mch_read_ctsna(shutdownCID));
		readyForShutdown = (mreltx_get_unacked_chunks_count() == 0 && mfc_get_queued_chunks_count() == 0);
		if (readyForShutdown)
		{
			// retransmissions are not necessary, send shutdownAck
			shutdownAckCID = mch_make_simple_chunk(CHUNK_SHUTDOWN_ACK, FLAG_TBIT_UNSET);
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shutdownAckCID));
			mch_free_simple_chunk(shutdownAckCID);
			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();
			// start shutdown timer
			if (smctrl->init_timer_id != NULL)
				mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = mtra_timeouts_add(TIMER_TYPE_SHUTDOWN, smctrl->init_timer_interval, &msm_timer_expired,
				&smctrl->channel_id);
			smctrl->channel_state = ChannelState::ShutdownAckSent;
		}
		else
		{
			ERRLOG(FALTAL_ERROR_EXIT,
				"Program logic error! SHUTDOWN_SENT state may not be entered from shutdown_pending, if queues are not empty !!!!");
		}
		mdi_on_peer_shutdown_received();
		break;

	case ChannelState::Connected:
		EVENTLOG(INFO, "event: receive shutdown chunk  in Connected State !");
		mrecv_process_ctsna_from_shutdown_chunk(mch_read_ctsna(shutdownCID));
		readyForShutdown = (mreltx_get_unacked_chunks_count() == 0 && mfc_get_queued_chunks_count() == 0);
		if (readyForShutdown)
		{
			// Once all its outstanding data has been acknowledged, send shutdownAckretransmissions are not necessary now
			shutdownAckCID = mch_make_simple_chunk(CHUNK_SHUTDOWN_ACK, FLAG_TBIT_UNSET);
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shutdownAckCID));
			mch_free_simple_chunk(shutdownAckCID);
			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();
			// start shutdown timer
			if (smctrl->init_timer_id != NULL)
				mtra_timeouts_del(smctrl->init_timer_id);
			smctrl->init_timer_id = mtra_timeouts_add(TIMER_TYPE_SHUTDOWN, smctrl->init_timer_interval, &msm_timer_expired,
				&smctrl->channel_id);
			smctrl->channel_state = ChannelState::ShutdownAckSent;
		}
		else
		{
			// accepts no new data from its upper layer,
			// but retransmits data to the far end if necessary to fill gaps
			curr_channel_->flow_control->shutdown_received = true;
			curr_channel_->reliable_transfer_control->shutdown_received = true;
			// waiting for msm_all_chunks_acked() from mreltx
			smctrl->channel_state = ChannelState::ShutdownReceived;
		}
		mdi_on_peer_shutdown_received();
		break;

	default:
		ERRLOG1(MINOR_ERROR, "msm_process_shutdown_chunk() in state %02d: unexpected event", smctrl->channel_state);
		break;
	}
	mch_remove_simple_chunk(shutdownCID);
	return return_state;
}

void mdi_on_shutdown_completed()
{
	assert(curr_channel_ != NULL);
	assert(curr_channel_->geco_inst->ulp_callbacks.shutdownCompleteNotif);
	EVENTLOG1(INFO, "mdi_on_shutdown_completed()::channel_id %u", curr_channel_->channel_id);
	curr_channel_->geco_inst->ulp_callbacks.shutdownCompleteNotif(curr_channel_->channel_id, curr_channel_->ulp_dataptr);
}

int msm_process_shutdown_ack_chunk()
{
	smctrl_t* smctrl = mdi_read_smctrl();
	if (smctrl == NULL)
	{
		ERRLOG(MINOR_ERROR, "msm_process_shutdown_ack_chunk(): mdi_read_smctrl() returned NULL -> return !");
		return -1;
	}

	chunk_id_t shdcCID;
	ChunkProcessResult return_state = ChunkProcessResult::Good;

	switch (smctrl->channel_state)
	{
	case ChannelState::Closed:
		EVENTLOG(NOTICE, "event: receive shutdown ack chunk in state CLOSED, should have been handled before  ! ");
		break;

	case ChannelState::CookieWait:
	case ChannelState::CookieEchoed:
		// see also section 8.5.E.) treat this like OOTB packet, leave T1 timer run !
		EVENTLOG(NOTICE,
			"event: receive shutdown ack chunk in state CookieWait or CookieEchoed ->send shutdown_complete chunk ! ");
		shdcCID = mch_make_simple_chunk(CHUNK_SHUTDOWN_COMPLETE, FLAG_TBIT_SET);
		//@TODO
		break;

	case ChannelState::ShutdownPending:
	case ChannelState::ShutdownReceived:
	case ChannelState::Connected:
		ERRLOG(WARNNING_ERROR, "msm_process_shutdown_ack_chunk() in %02d state -> peer not standard conform!");
		break;

	case ChannelState::ShutdownSent:
	case ChannelState::ShutdownAckSent:
		if (smctrl->init_timer_id == NULL)
			ERRLOG(FALTAL_ERROR_EXIT,
				"msm_process_shutdown_ack_chunk():: shutdown timer is not running in %02d state ->program logic errors!");

		mtra_timeouts_del(smctrl->init_timer_id);
		smctrl->init_timer_id = NULL;

		shdcCID = mch_make_simple_chunk(CHUNK_SHUTDOWN_COMPLETE, FLAG_TBIT_UNSET);
		mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shdcCID));
		mch_free_simple_chunk(shdcCID);
		mdi_unlock_bundle_ctrl();
		mdi_send_bundled_chunks();

		// delete all data of this association
		mdi_on_shutdown_completed();
		mdi_delete_curr_channel();
		mdi_clear_current_channel();
		return_state = StopProcessAndDeleteChannel;
		smctrl->channel_state = ChannelState::Closed;
		break;

	default:
		ERRLOG1(MINOR_ERROR, "msm_process_shutdown_ack_chunk() in state %02d: unexpected event", smctrl->channel_state);
		break;
	}

	return return_state;
}

void mrecv_process_forward_tsn(simple_chunk_t* simple_chunk)
{
	//@TODO
}

void mdi_process_asconf_chunk(simple_chunk_t* simple_chunk)
{
	//@TODO
}

void mdi_process_asconf_ack_chunk(simple_chunk_t* simple_chunk)
{
	//@TODO
}

int mdlm_do_notifications()
{
	deliverman_controller_t* mdlm = mdi_read_mdlm();
	assert(mdlm != NULL);
	int retval = mdlm_search_ready_pdu(mdlm);
	if (retval == MULP_SUCCESS)
		mdlm_deliver_ready_pdu(mdlm);
	return retval;
}

/// Called by recvcontrol, when a SACK must be piggy-backed
/// @param chunk pointer to chunk, that is to be put in the bundling buffer
/// @return error value, 0 on success, -1 on error
int mdi_bundle_sack_chunk(sack_chunk_t* chunk, int* dest_index)
{
	EVENTLOG(VERBOSE, "- -  Enter mdi_bundle_sack_chunk()");
	bundle_controller_t* bundle_ctrl = (bundle_controller_t*)mdi_read_mbu(curr_channel_);

	// no channel exists, so we take the global bundling buffer */
	if (bundle_ctrl == NULL)
	{
		EVENTLOG(VERBOSE, "mdi_bundle_sack_chunk()::use global bundle_ctrl");
		bundle_ctrl = default_bundle_ctrl_;
	}

	ushort chunk_len = get_chunk_length((chunk_fixed_t*)chunk);
	uint bundle_size = get_bundle_total_size(bundle_ctrl);
	if ((bundle_size + chunk_len) > bundle_ctrl->curr_max_pdu)
	{
		// an packet CANNOT hold all data, we send chunks and get bundle empty*/
		EVENTLOG5(VERBOSE, "mdi_bundle_sack_chunk()::Chunk Length(bundlesize %u+chunk_len %u = %u),"
			"exceeded MAX_NETWORK_PACKET_VALUE_SIZE(%u) : sending chunk to address %u !", bundle_size, chunk_len,
			bundle_size + chunk_len, MAX_GECO_PACKET_SIZE, (dest_index == NULL) ? 0 : *dest_index);
		bundle_ctrl->locked = false;/* unlock to allow send bundle*/
		return mdi_send_bundled_chunks(dest_index);
		// we do not unlock because when is is hb packet that must exceed the curr_max_pdu, we want to send hb anyway so do not unlock here anyway
	}

	// an packet CAN hold all data*/
	if (dest_index != NULL)
	{
		bundle_ctrl->got_send_address = true;
		bundle_ctrl->requested_destination = *dest_index;
	}
	else
	{
		bundle_ctrl->got_send_address = false;
		bundle_ctrl->requested_destination = 0;
	}

	// multiple calls between sends
	if (bundle_ctrl->sack_in_buffer)
	{
		EVENTLOG(DEBUG, "mdi_bundle_sack_chunk() was called a second time, deleting first SACK chunk");
		bundle_ctrl->sack_position = mbu->geco_packet_fixed_size;
	}

	// copy new sack chunk to bundle and insert padding, if necessary
	memcpy_fast(&bundle_ctrl->sack_buf[bundle_ctrl->sack_position], chunk, chunk_len);
	bundle_ctrl->sack_position += chunk_len;
	bundle_ctrl->sack_in_buffer = true;

	//SACK always multiple of 32 bytes, do not care about padding
	EVENTLOG3(DEBUG,
		"mdi_bundle_sack_chunk():chunklen %u + geco_packet_fixed_size %u = Total buffer size now (includes pad): %u",
		chunk_len, mbu->geco_packet_fixed_size, get_bundle_total_size(bundle_ctrl));

	EVENTLOG(VERBOSE, "- -  Leave mdi_bundle_sack_chunk()");
	return 0;
}

/// triggered by flow ctrl module, tells mrecv to send SACK to bundling
/// using bu_put_SACK_Chunk() function.
/// @return boolean to indicate, whether a SACK was generated, and should be sent !
bool mrecv_create_sack(int* last_src_path_, bool force_sack)
{
	EVENTLOG2(VVERBOSE, "Enter mrecv_create_sack(address==%u, force_sack==%s",
		((last_src_path_ != NULL) ? *last_src_path_ : 0), (force_sack ? "TRUE" : "FALSE"));
	bool retval;
	recv_controller_t* mrecv = mdi_read_mrecv();
	assert(mrecv != NULL);
	if (mrecv->sack_updated == false)
		mrecv_on_packet_processed(false);

	// send sacks along every second time, generally
	// some timers may want to send a SACK anyway
	if (force_sack)
	{
		mrecv->lowest_duplicated_tsn = mrecv->cumulative_tsn;
		mdi_bundle_sack_chunk(mrecv->sack_chunk, last_src_path_);
		return true;
	}
	else
	{
		if (mrecv->packet_contain_dchunk_received < 0
			/*send sack when receiving first data chunk*/
			|| mrecv->packet_contain_dchunk_received % mrecv->sack_flag != 0
			/*otherwise, send sack every second packet containing dchunk*/)
		{
			EVENTLOG(VVERBOSE, "mrecv_create_sack():: not send SACK here - return");
			return false;
		}

		mrecv->lowest_duplicated_tsn = mrecv->cumulative_tsn;
		mdi_bundle_sack_chunk(mrecv->sack_chunk, last_src_path_);
		return true;
	}
	return false;
}

/**
 * the callback function when the sack timer goes off, and we must sack previously
 * received data (e.g. after 200 msecs)
 * @note make sure you del sack timer when delete channel
 * Has three parameters as all timer callbacks
 * @param   tid id of the timer that has gone off
 * @param   assoc  pointer to the association this event belongs to
 * @param   dummy  pointer that is not used here
 */
int mrecv_sack_timer_cb(timeout* tid)
{
	geco_channel_t* channel = (geco_channel_t*)(tid->callback.arg1);
	recv_controller_t* mrecv = channel->receive_control;
	int* last_address = (int*)(tid->callback.arg2);
	mrecv->timer_running = false;
	mrecv_create_sack(last_address, true);
	return mdi_send_bundled_chunks(last_address);
}

void mrecv_on_packet_processed(bool new_data_received)
{
	static uint pos;
	static ushort count, len16;
	static int num_of_frags, num_of_dups, frag_start32, frag_stop32;
	static segment16_t seg16;
	static duplicate_tsn_t dup;

	recv_controller_t* mrecv = mdi_read_mrecv();
	assert(mrecv != NULL);
	pos = 0;

	if (new_data_received)
		mrecv->packet_contain_dchunk_received++;

	num_of_frags = mrecv->fragmented_data_chunks_list.size();
	num_of_dups = mrecv->duplicated_data_chunks_list.size();
	EVENTLOG2(VVERBOSE, "mrecv_on_packet_processed()::len of frag_list==%u, len of dup_list==%u", num_of_frags,
		num_of_dups);
	// limit number of Fragments/Duplicates according to PATH MTU
	assert(curr_channel_ != NULL);
	last_src_path_ = path_map[*last_source_addr_];
	int max_size = curr_channel_->path_control->path_params[last_src_path_].eff_pmtu - SACK_CHUNK_FIXED_SIZE
		- CHUNK_FIXED_SIZE - num_of_frags * sizeof(uint);
	assert(max_size > 0);
	while (num_of_dups > 0 && num_of_dups * sizeof(uint) > max_size)
		num_of_dups--;
	max_size -= num_of_dups * sizeof(uint);
	while (num_of_frags > 0 && num_of_frags * sizeof(uint) > max_size)
		num_of_frags--;
	max_size -= num_of_frags * sizeof(uint);
	assert(max_size >= 0);
	EVENTLOG3(VERBOSE, "mrecv_on_packet_processed()::num_of_dups %d, num_of_frags %d, remianing pmtu %d", num_of_dups,
		num_of_frags, max_size);

	sack_chunk_t* sack = mrecv->sack_chunk;
	// each frag haa start and end ssn so multiplies another 2
	len16 = SACK_CHUNK_FIXED_SIZE + CHUNK_FIXED_SIZE + num_of_dups * sizeof(uint) + (num_of_frags << 1) * sizeof(ushort);
	sack->chunk_header.chunk_length = htons(len16);
	sack->sack_fixed.cumulative_tsn_ack = htonl(mrecv->cumulative_tsn);
	sack->sack_fixed.num_of_fragments = htons(num_of_frags);
	sack->sack_fixed.num_of_duplicates = htons(num_of_dups);
	// default send sack for every received packet containing dchunk
	// but this can be ignored if force_sack is true
	num_of_frags > 0 ? mrecv->sack_flag = 1 : mrecv->sack_flag = 2;

	// write gaps blocks
	for (auto& f32 : mrecv->fragmented_data_chunks_list)
	{
		if (count >= num_of_frags)
			break;
		EVENTLOG3(VVERBOSE, "cumulative_tsn==%u, fragment.start==%u, fragment.stop==%u", mrecv->cumulative_tsn,
			f32.start_tsn, f32.stop_tsn);
		frag_start32 = (f32.start_tsn - mrecv->cumulative_tsn);
		frag_stop32 = (f32.stop_tsn - mrecv->cumulative_tsn);
		EVENTLOG2(VVERBOSE, "frag_start16==%d, frag_stop16==%d", frag_start32, frag_stop32);
		if (frag_start32 > UINT16_MAX || frag_stop32 > UINT16_MAX) // UINT16_MAX = 65535
		{
			EVENTLOG(NOTICE, "mrecv_on_packet_processed()::Fragment offset becomes too big->BREAK LOOP");
			break;
		}
		seg16.start = (ushort)frag_start32;
		seg16.stop = (ushort)frag_stop32;
		memcpy_fast(&sack->fragments_and_dups[pos], &seg16, sizeof(segment16_t));
		pos += sizeof(segment16_t);
		count++;
	}

	count = 0;

	//write dups
	for (auto& dptr : mrecv->duplicated_data_chunks_list)
	{
		if (count >= num_of_dups)
			break;
		memcpy_fast(&sack->fragments_and_dups[pos], &dptr, sizeof(duplicate_tsn_t));
		pos += sizeof(duplicate_tsn_t);
		count++;
	}

	// start delay ack timer
	if (!mrecv->timer_running && new_data_received)
	{
		if (mrecv->sack_timer != NULL)
			mtra_timeouts_readd(mrecv->sack_timer, mrecv->delay);
		else
			mrecv->sack_timer = mtra_timeouts_add(TIMER_TYPE_SACK, mrecv->delay, &mrecv_sack_timer_cb, curr_channel_,
				&(path_map[*last_source_addr_]));
		mrecv->timer_running = true;
	}
	mrecv->sack_updated = true;
}

/**
 * this function leaves fast recovery if it was activated, and all chunks up to
 * fast recovery exit point were acknowledged.
 */
static inline int mreltx_check_fast_recovery(reltransfer_controller_t* rtx, uint ctsna)
{
	if (rtx->fast_recovery_active)
	{
		if (uafter(ctsna, rtx->fr_exit_point) || ctsna == rtx->fr_exit_point)
		{
			EVENTLOG1(VERBOSE, "=============> Leaving FAST RECOVERY !!! CTSNA: %u <================", ctsna);
			rtx->fast_recovery_active = false;
			rtx->fr_exit_point = 0;
		}
	}
	return MULP_SUCCESS;
}

int mfc_remove_acked_chunks(uint ctsna)
{
	flow_controller_t* mfc = mdi_read_mfc();
	assert(mfc != NULL);

	internal_data_chunk_t* idchunk;
	auto& chunk_list = mfc->chunk_list;
	if (chunk_list.empty() || uafter(ctsna, chunk_list.back()->chunk_tsn))
		return -1;

	do
	{
		idchunk = chunk_list.front();
		if (uafter(idchunk->chunk_tsn, ctsna))
			break;
		chunk_list.pop_front();
		mfc->list_length--;
		EVENTLOG2(VERBOSE, "mfc_remove_acked_chunks()::Removed chunk %u from Flowcontrol-List, Listlength now %u",
			idchunk->chunk_tsn, mfc->list_length);
	} while (!chunk_list.empty());
	return 0;
}

/// remove chunks up to ctsna, updates newly acked bytes
/// @param   ctsna   the ctsna value, that has just been received in a sack
/// @return -1 if error (such as ctsna > than all chunk_tsn), 0 on success
int mreltx_remove_acked_chunks(uint ctsna, uint addr_index)
{
	reltransfer_controller_t* rtx = mdi_read_mreltsf();
	assert(mreltx != NULL);

	// first remove all stale chunks from flowcontrol list
	// so that these are not referenced after they are freed here
	if (mfc_remove_acked_chunks(ctsna) < 0)
		return -1;

	auto& chunk_list = rtx->chunk_list_tsn_ascended;
	if (chunk_list.empty() || uafter(ctsna, chunk_list.back()->chunk_tsn))
		return -1;

	static uint chunk_tsn;
	static internal_data_chunk_t* idchunk;

	do
	{
		idchunk = chunk_list.front();
		chunk_tsn = idchunk->chunk_tsn;
		if (uafter(chunk_tsn, ctsna))  //sorted list, so safe to get out in this case
			break;
		EVENTLOG4(VERBOSE, "dat->num_of_transmissions==%u, chunk_tsn==%u, chunk_len=%u, ctsna==%u ",
			idchunk->num_of_transmissions, chunk_tsn, idchunk->chunk_len, ctsna);
		assert(idchunk->num_of_transmissions >= 1);
		if (!idchunk->hasBeenAcked && !idchunk->hasBeenDropped) //chunks that not acked and dropped
		{
			rtx->newly_acked_bytes += idchunk->chunk_len;
			idchunk->hasBeenAcked = true;
			if (idchunk->num_of_transmissions == 1 && addr_index != idchunk->last_destination)
			{
				rtx->save_num_of_txm = 1;
				rtx->saved_send_time = idchunk->transmission_time;
				EVENTLOG3(VERBOSE, "Saving Time (after dequeue) : %lu secs, %06lu usecs for tsn=%u", idchunk->transmission_time,
					idchunk->transmission_time, idchunk->chunk_tsn);
			}
		}
		EVENTLOG1(VERBOSE, "Now pop chunk with tsn %u from list", chunk_tsn);
		geco_free_ext(idchunk, __FILE__, __LINE__);
		chunk_list.pop_front();

	} while (!chunk_list.empty());
	return 0;
}

/**
* helper function that calls pm_chunksAcked()
* and tells path management, if new chunks have  been acked, and new RTT may be guessed
* @param  adr_idx  CHECKME : address where chunks have been acked (is this correct ?);
may we take src address of the SACK, or must we take destination address of our data ?
* @param    rtx    pointer to the currently active rtx structure
*/
void mreltx_update_rtt(unsigned int adr_idx, reltransfer_controller_t * rtx)
{

}

/**
 * this is called by bundling, when a SACK needs to be processed. This is a LONG function !
 * FIXME : check correct update of rtx->lowest_tsn !
 * FIXME : handling of out-of-order SACKs
 * CHECK : did SACK ack lowest outstanding tsn, restart t3 timer (section 7.2.4.4) )
 * @param  adr_index   index of the address where we got that sack
 * @param  sack_chunk  pointer to the sack chunk
 * @return -1 on error, 0 if okay.
 */
#define mreltx_rtx_chunks_size 512
static internal_data_chunk_t *mreltx_chunks[mreltx_rtx_chunks_size];
int mreltx_process_sack(int adr_index, sack_chunk_t* sack, uint totalLen)
{
	int retval;
	reltransfer_controller_t* rtx = mdi_read_mreltsf();
	assert(rtx != NULL);

	//discard out-of-order sacks (always use newer sack)
	//this is not error so return 0
	// we send 12345 tp peer =>
	// peer sends sack1 with ctsna 1
	// peer sends sack2 with ctsna 2
	// we receive sack2 first and set highest_acked to 2 =>
	// then receive sack1, ubefore(1,2) true =>
	uint ctsna = ntohl(sack->sack_fixed.cumulative_tsn_ack);
	if (ubefore(ctsna, rtx->highest_acked))
		return 0;

	//discard sack with wrong cumulative_tsn_ack beyond [rtx->lowest_tsn, rtx->highest_tsn]
	if (ubefore(ctsna, rtx->lowest_tsn) || uafter(ctsna, rtx->highest_tsn))
		return -1;

	//discard sack with wrong chunk len
	uint chunk_len = ntohs(sack->chunk_header.chunk_length);
	if (chunk_len > totalLen)
		return -2;

	//discard sack with wrong gaps and dups len
	ushort num_of_gaps =
		sack->chunk_header.chunk_flags & SACK_NON_ZERO_FRAGMENT ? ntohs(sack->sack_fixed.num_of_fragments) : 0;
	ushort num_of_dups =
		sack->chunk_header.chunk_flags & SACK_NON_ZERO_DUPLICATE ? ntohs(sack->sack_fixed.num_of_duplicates) : 0;
	ushort var_len = chunk_len - CHUNK_FIXED_SIZE - SACK_CHUNK_FIXED_SIZE;
	ushort gap_len = num_of_gaps * sizeof(uint);
	ushort dup_len = num_of_dups * sizeof(uint);
	if (var_len != gap_len + dup_len)
		return -3;

	// it is likely to receive more than one sack possibly
	// with same ctsna but different gap blocks
	// we have tested ctsna must be beween [rtx->lowest_tsn, rtx->highest_tsn] in the coedes above
	if (mreltx_remove_acked_chunks(ctsna, adr_index) < 0)
	{
		EVENTLOG(VERBOSE,
			"mreltx_process_sack()::no data in queue or bad ctsna arrived in SACK (after all buffered chunks tsn)->discard sack");
		return -4;
	}
	rtx->lowest_tsn = ctsna;
	EVENTLOG2(VERBOSE, "mreltx_process_sack()::Updated rtx->lowest_tsn %u to  %u", rtx->lowest_tsn, ctsna);

	mreltx_check_fast_recovery(rtx, ctsna);

	rtx->sack_arrival_time = gettimestamp();
	rtx->highest_acked = ctsna;
	rtx->last_received_ctsna = ctsna;
	uint old_own_ctsna = rtx->lowest_tsn;
	EVENTLOG2(VERBOSE, "mreltx_process_sack()::Received ctsna==%u, old_own_ctsna==%u", ctsna, old_own_ctsna);
	uint arwnd = ntohl(sack->sack_fixed.a_rwnd);
	EVENTLOG5(VERBOSE, "mreltx_process_sack()::chunk_len=%u, a_rwnd=%u, var_len=%u, gap_len=%u, du_len=%u", chunk_len,
		arwnd, var_len, gap_len, dup_len);

	bool rtx_necessary = false, all_acked = false, new_acked = false;
	uint chunks2rtx = 0, rtx_bytes = 0;

	if (num_of_gaps != 0)
	{
		// we have test chunklist_ascended must NOT be empty in mreltx_remove_acked_chunks()
		EVENTLOG1(VERBOSE, "mreltx_process_sack()::Processing %u fragment reports", num_of_gaps);
	}
	else if (!rtx->all_chunks_are_unacked) // no gaps reported in this sack
	{
		/*	renege must happen in peer as we have chunks in the queue that
			 were acked by a gap report before plus num_of_gaps is zero.
			so reset their status to unacked, since that is what peer reported
			fast retransmit reneged chunks, as per section   6.2.1.D.iii) of RFC 4960 */
		EVENTLOG(VERBOSE,"rtx_process_sack: resetting all *hasBeenAcked* attributes");
		for (auto ptr : rtx->chunk_list_tsn_ascended)
		{
			//  all acked chunks before ctsna have been removed from chunk_list_tsn_ascended in above
			// now the rest of chunks are acked gap blocks or unacked chunks 
			// just loop all chunks and reset acked to unacked
			if ( !ptr->hasBeenDropped &&ptr->hasBeenAcked)
			{
				EVENTLOG1(VERBOSE, "rtx_process_sack: RENEG --> fast retransmitting chunk tsn %u ", ptr->chunk_tsn);
				/* retransmit it, chunk is not yet expired */
				rtx_necessary = true;
				mreltx_chunks[chunks2rtx] = ptr;
				ptr->gap_reports = 0;
				ptr->hasBeenFastRetransmitted = true;
				ptr->hasBeenAcked = false;
				chunks2rtx++;
				chunks2rtx %= mreltx_rtx_chunks_size;
				/* preparation for what is in section 6.2.1.C  add to rwnd*/
				rtx_bytes += ptr->chunk_len;
			}
		}
		rtx->all_chunks_are_unacked = true;
	}

	// also tell mpath, that we got a SACK, possibly updating RTT/RTO.
	mreltx_update_rtt(adr_index, rtx);


	return 0;
}

/*
 pass to relevant module :
 //
 msm:
 CHUNK_INIT,
 CHUNK_INIT_ACK,
 CHUNK_ABORT,
 CHUNK_SHUTDOWN,
 CHUNK_SHUTDOWN_ACK
 CHUNK_COOKIE_ECHO,
 CHUNK_COOKIE_ACK
 CHUNK_ERROR
 //
 mreltx:
 CHUNK_SACK
 //
 mpath:
 CHUNK_HBREQ
 CHUNK_HBACK
 //
 mrecv:
 CHUNK_DATA
 */
int mdi_disassemle_packet()
{
#if defined(_DEBUG)
	EVENTLOG2(DEBUG, "- - - ENTER dispatch_layer_t::disassemle_curr_geco_packet():last_src_path_ %u,packetvallen %u",
		last_src_path_, curr_geco_packet_value_len_);
#endif

	uchar* curr_pos = chunk; /* points to the first chunk in this pdu */
	uint read_len = 0, chunk_len;
	simple_chunk_t* simple_chunk;
	bool data_chunk_received = false;
	int handle_ret = ChunkProcessResult::Good;

	while (read_len < curr_geco_packet_value_len_)
	{
		if (curr_geco_packet_value_len_ - read_len < CHUNK_FIXED_SIZE)
		{
			EVENTLOG(WARNNING_ERROR, "dispatch_layer_t::disassemle_curr_geco_packet()::chunk_len illegal !-> return -1 !");
			mdi_unlock_bundle_ctrl();
			return -1;
		}

		simple_chunk = (simple_chunk_t *)curr_pos;
		chunk_len = ntohs(simple_chunk->chunk_header.chunk_length);
		EVENTLOG2(VERBOSE, "starts process chunk with read_len %u,chunk_len %u", read_len, chunk_len);

		if (chunk_len < CHUNK_FIXED_SIZE || chunk_len + read_len > curr_geco_packet_value_len_)
		{
			EVENTLOG(WARNNING_ERROR, "dispatch_layer_t::disassemle_curr_geco_packet()::chunk_len illegal !-> return -1 !");
			mdi_unlock_bundle_ctrl();
			return -1;
		}

		/*
		 * Add return values to the chunk-functions, where they can indicate what
		 * to do with the rest of the datagram (i.e. DISCARD after stale COOKIE_ECHO
		 * with tie tags that do not match the current ones)
		 */
		switch (simple_chunk->chunk_header.chunk_id)
		{
		case CHUNK_INIT:
			EVENTLOG(DEBUG, "***** Diassemble received CHUNK_INIT");
			handle_ret = msm_process_init_chunk((init_chunk_t *)simple_chunk);
			break;

		case CHUNK_INIT_ACK:
			EVENTLOG(DEBUG, "***** Diassemble received CHUNK_INIT_ACK");
			handle_ret = msm_process_init_ack_chunk((init_chunk_t *)simple_chunk);
			break;

		case CHUNK_COOKIE_ECHO:
			EVENTLOG(DEBUG, "***** Diassemble received CHUNK_COOKIE_ECHO");
			msm_process_cookie_echo_chunk((cookie_echo_chunk_t*)simple_chunk);
			break;

		case CHUNK_COOKIE_ACK:
			EVENTLOG(DEBUG, "***** Diassemble received CHUNK_COOKIE_ACK");
			msm_process_cookie_ack_chunk((simple_chunk_t*)simple_chunk);
			break;

		case CHUNK_DATA:
			EVENTLOG(DEBUG, "***** Diassemble received CHUNK_DATA");
			handle_ret = mrecv_process_data_chunk((data_chunk_t*)chunk, path_map[*last_source_addr_]);
			data_chunk_received = true;
			break;

		case CHUNK_SACK:
			//refer to section 6.2.1 processing a received SACK
			EVENTLOG(DEBUG, "***** Diassemble received CHUNK_SACK");
			handle_ret = mreltx_process_sack(last_src_path_, (sack_chunk_t*)chunk, curr_geco_packet_value_len_);
			break;

		case CHUNK_HBREQ:
			EVENTLOG(DEBUG, "*******************  Bundling received HB_REQ chunk");
			mpath_process_heartbeat_chunk((heartbeat_chunk_t*)chunk, last_src_path_);
			break;

		case CHUNK_HBACK:
			EVENTLOG(DEBUG, "*******************  Bundling received HB_ACK chunk");
			mpath_process_heartbeat_ack_chunk((heartbeat_chunk_t*)simple_chunk);
			break;

		case CHUNK_FORWARD_TSN:
			if (!do_we_support_unreliability())
				continue;
			EVENTLOG(DEBUG, "*******************  Bundling received CHUNK_FORWARD_TSN");
			mrecv_process_forward_tsn(simple_chunk);
			break;

		case CHUNK_ASCONF:
			/* check that ASCONF chunks are standalone chunks, not bundled with any other
			 chunks. Else ignore the ASCONF chunk (but not the others) */
			EVENTLOG(DEBUG, "*******************  Bundling received CHUNK_ASCONF");
			mdi_process_asconf_chunk(simple_chunk);
			break;

		case CHUNK_ASCONF_ACK:
			EVENTLOG(DEBUG, "*******************  Bundling received CHUNK_ASCONF_ACK");
			mdi_process_asconf_ack_chunk(simple_chunk);
			break;

		case CHUNK_ABORT:
			EVENTLOG(DEBUG, "******************* Diassemble received ABORT chunk");
			handle_ret = msm_process_abort_chunk();
			break;

		case CHUNK_ERROR:
			EVENTLOG(DEBUG, "******************* Diassemble received ERROR chunk");
			msm_process_error_chunk(simple_chunk);
			break;

		case CHUNK_SHUTDOWN:
			EVENTLOG(DEBUG, "******************* Diassemble received CHUNK_SHUTDOWN");
			handle_ret = msm_process_shutdown_chunk(simple_chunk);
			break;

		case CHUNK_SHUTDOWN_ACK:
			EVENTLOG(DEBUG, "******************* Diassemble received CHUNK_SHUTDOWN_ACK");
			handle_ret = msm_process_shutdown_ack_chunk();
			break;

		case CHUNK_SHUTDOWN_COMPLETE:
			EVENTLOG(DEBUG, "******************* Diassemble received CHUNK_SHUTDOWN_COMPLETE");
			handle_ret = msm_process_shutdown_complete_chunk();
			break;

		default:
			/*
			 00 - Stop processing this SCTP packet and discard it,
			 do not process any further chunks within it.
			 01 - Stop processing this SCTP packet and discard it, do not process
			 any further chunks within it, and report the unrecognized
			 parameter in an 'Unrecognized Parameter Type' (in either an
			 ERROR or in the INIT ACK).
			 10 - Skip this chunk and continue processing.
			 11 - Skip this chunk and continue processing,
			 but report in an ERROR Chunk using the 'Unrecognized Chunk Type' cause of error.
			 0XC0 = 11000000 */
			switch ((uchar)(simple_chunk->chunk_header.chunk_id & 0xC0))
			{
			case 0x0:  //00
				read_len = curr_geco_packet_value_len_;
#ifdef _DEBUG
				EVENTLOG(DEBUG, "Unknown chunktype -> Stop processing and discard");
#endif
				break;
			case 0x40:  //01
				read_len = curr_geco_packet_value_len_;
				//todo
				handle_ret = mdis_send_ecc_unrecognized_chunk((uchar*)simple_chunk, chunk_len);
#ifdef _DEBUG
				EVENTLOG(DEBUG, "Unknown chunktype ->  01 - Stop processing, discard it and eport");
#endif
				break;
			case 0x80:  //10
				EVENTLOG(DEBUG, "Unknown chunktype ->  10 - Skip this chunk and continue processing.");
				break;
			case 0xC0:  //11
				EVENTLOG(DEBUG, " Unknown chunktype -> 11 Skip this chunk and continue processing");
				handle_ret = mdis_send_ecc_unrecognized_chunk((uchar*)simple_chunk, chunk_len);
				break;
			default:  // never reach here
				ERRLOG(MINOR_ERROR, "unfound chuntype flag !");
				break;
			}
			break;
		}
		read_len += chunk_len;
		while (read_len & 3)
			++read_len;
		curr_pos = chunk + read_len;
		if (handle_ret != ChunkProcessResult::Good)  // to break whileloop
			read_len = curr_geco_packet_value_len_;
		EVENTLOG2(VERBOSE, "end process chunk with read_len %u,chunk_len %u", read_len, chunk_len);
	}

	if (handle_ret != ChunkProcessResult::StopProcessAndDeleteChannel)
	{
		// fill SACK chunk, update datagram counter and start delayed-sack timer
		mrecv_on_packet_processed(data_chunk_received);

		// optionally also add a SACK chunk, at least for every second packet
		if (data_chunk_received)
		{
			mdlm_do_notifications();
			if (mrecv_create_sack(&last_src_path_, false))
				mdi_send_bundled_chunks(&last_src_path_);
		}
	}

	return 0;
}

geco_channel_t* mdi_find_channel(sockaddrunion * src_addr, ushort src_port, ushort dest_port)
{
	tmp_channel_.remote_addres_size = 1;
	tmp_channel_.remote_addres = &tmp_addr_;

	switch (saddr_family(src_addr))
	{
	case AF_INET:
		tmp_channel_.remote_addres[0].sa.sa_family = AF_INET;
		tmp_channel_.remote_addres[0].sin.sin_addr.s_addr = s4addr(src_addr);
		tmp_channel_.remote_addres[0].sin.sin_port = src_addr->sin.sin_port;
		tmp_channel_.remote_port = src_port;
		tmp_channel_.local_port = dest_port;
		tmp_channel_.deleted = false;
		break;
	case AF_INET6:
		tmp_channel_.remote_addres[0].sa.sa_family = AF_INET6;
		//memcpy(&(tmp_channel_.remote_addres[0].sin6.sin6_addr.s6_addr), (s6addr(src_addr)), sizeof(struct in6_addr));
		memcpy_fast(&(tmp_channel_.remote_addres[0].sin6.sin6_addr.s6_addr), (s6addr(src_addr)), sizeof(struct in6_addr));
		tmp_channel_.remote_addres[0].sin6.sin6_port = src_addr->sin6.sin6_port;
		tmp_channel_.remote_port = src_port;
		tmp_channel_.local_port = dest_port;
		tmp_channel_.deleted = false;
		break;
	default:
		EVENTLOG1(FALTAL_ERROR_EXIT, "mdi_find_channel():Unsupported Address Family %d in mdi_find_channel()",
			saddr_family(src_addr));
		break;
	}

	/* search for this endpoint from list*/
	geco_channel_t* result = NULL;
	for (uint i = 0; i < channels_size_; i++)
	{
		if (cmp_channel(tmp_channel_, *channels_[i]))
		{
			result = channels_[i];
			break;
		}
	}

	if (result != NULL)
	{
		if (result->deleted)
		{
			EVENTLOG1(VERBOSE, "mdi_find_channel():Found channel that should be deleted, with id %u", result->channel_id);
			result = NULL;
		}
		else
		{
			EVENTLOG1(VERBOSE, "mdi_find_channel():Found valid channel with id %u", result->channel_id);
		}
	}
	else
	{
		EVENTLOG(VERBOSE, "mdi_find_channel()::channel indexed by transport address not in list");
	}

	return result;
}

/* search for this endpoint from list*/
geco_channel_t* mdi_find_channel()
{
	static auto enditer = channel_map_.end();
	geco_channel_t* result = NULL;
	auto iter = channel_map_.find(curr_trans_addr_);
	if (enditer != iter)
	{
		result = channels_[iter->second];
		if (result->deleted)
		{
			return NULL;
		}
		return result;
	}
	return result;
}
uint find_chunk_types(uchar* packet_value, uint packet_val_len, uint* total_chunk_count)
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

	if (total_chunk_count != NULL)
	{
		*total_chunk_count = 0;
	}

	uint result = 0;
	uint chunk_len = 0;
	uint read_len = 0;
	uint padding_len;
	chunk_fixed_t* chunk;
	uchar* curr_pos = packet_value;

	while (read_len < packet_val_len)
	{
		EVENTLOG2(VVERBOSE, "find_chunk_types()::packet_val_len=%d, read_len=%d", packet_val_len, read_len);

		if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
		{
			ERRLOG(MINOR_ERROR, "find_chunk_types()::INCOMPLETE CHUNK_FIXED_SIZE(4 bytes) invalid !");
			return result;
		}

		chunk = (chunk_fixed_t*)curr_pos;
		chunk_len = get_chunk_length(chunk);

		if (chunk_len < CHUNK_FIXED_SIZE)
		{
			ERRLOG1(MINOR_ERROR, "find_chunk_types():chunk_len (%u) < CHUNK_FIXED_SIZE(4 bytes)!", chunk_len);
			return result;
		}
		if (chunk_len + read_len > packet_val_len)
		{
			ERRLOG3(MINOR_ERROR, "find_chunk_types():chunk_len(%u) + read_len(%u) < packet_val_len(%u)!", chunk_len, read_len,
				packet_val_len);
			return result;
		}

		if (chunk->chunk_id <= 30)
		{
			result |= (1 << chunk->chunk_id);
			EVENTLOG2(VERBOSE, "find_chunk_types()::Chunktype %u,result:%s", chunk->chunk_id,
				Bitify(sizeof(result) * 8, (char*)&result));
		}
		else
		{
			result |= (1 << 31);
			EVENTLOG2(VERBOSE, "find_chunk_types()::Chunktype %u,setting bit 31,result %s", chunk->chunk_id,
				Bitify(sizeof(result) * 8, (char*)&result));
		}

		if (total_chunk_count != NULL)
		{
			(*total_chunk_count)++;
		}

		read_len += chunk_len;
		padding_len = ((read_len & 3) == 0) ? 0 : (4 - (read_len & 3));
		read_len += padding_len;
		curr_pos = packet_value + read_len;
	}
	return result;
}
bool cmp_geco_instance(const geco_instance_t& traget, const geco_instance_t& b)
{
	/* compare local port*/
	if (traget.local_port != b.local_port)
	{
		return false;
	}
	else
	{
		is_there_at_least_one_equal_dest_port_ = true;
	}

	uchar af = saddr_family(traget.local_addres_list);
	if (b.is_inaddr_any && b.is_in6addr_any)
	{
		//we supports both of ip4and6
		if (af == AF_INET || af == AF_INET6)
			return true;
	}
	else if (b.is_in6addr_any && !b.is_inaddr_any)
	{
		//we only supports ip6
		if (af == AF_INET6)
			return true;
	}
	else if (!b.is_in6addr_any && b.is_inaddr_any)
	{
		//we only supports ip4
		if (af == AF_INET)
			return true;
	}
	else //!curr_geco_instance_->is_inaddr_any && !curr_geco_instance_->is_in6addr_any
	{
		// find if at least there is an ip addr thate quals
		for (int i = 0; i < traget.local_addres_size; i++)
		{
			for (int j = 0; j < b.local_addres_size; j++)
			{
				if (saddr_equals(&(traget.local_addres_list[i]), &(b.local_addres_list[j]), true))
				{
					return true;
				}
			}
		}
	}
	return false;

	//if (!a.is_in6addr_any && !b.is_in6addr_any && !a.is_inaddr_any && !b.is_inaddr_any)
	//{
	//	int i, j;
	//	/*find if at least there is an ip addr thate quals*/
	//	for (i = 0; i < a.local_addres_size; i++)
	//	{
	//		for (j = 0; j < b.local_addres_size; j++)
	//		{
	//			if (saddr_equals(&(a.local_addres_list[i]), &(b.local_addres_list[j]), true))
	//			{
	//				return true;
	//			}
	//		}
	//	}
	//	return false;
	//}
	//else
	//{
	//	/* one has IN_ADDR_ANY OR IN6_ADDR_ANY : return equal ! */
	//	return true;
	//}
}

geco_instance_t* mdi_find_geco_instance(sockaddrunion* dest_addr, ushort dest_port)
{
	if (geco_instances_.size() == 0)
	{
		ERRLOG(MAJOR_ERROR, "dispatch_layer_t::mdi_find_geco_instance()::geco_instances_.size() == 0");
		return NULL;
	}

	/* search for this endpoint from list*/
	tmp_geco_instance_.local_port = dest_port;
	tmp_geco_instance_.local_addres_size = 1;
	tmp_geco_instance_.local_addres_list = dest_addr;
	tmp_geco_instance_.is_in6addr_any = false;
	tmp_geco_instance_.is_inaddr_any = false;

	is_there_at_least_one_equal_dest_port_ = false;
	geco_instance_t* result = NULL;
	for (auto& i : geco_instances_)
	{
		if (cmp_geco_instance(tmp_geco_instance_, *i))
		{
			result = i;
			break;
		}
	}
	return result;
}
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

bool validate_dest_addr(sockaddrunion * dest_addr)
{
	/* 1)
	 * we can receive this packet means that dest addr is good no matter it is
	 * ip4 or ip6, it maybe different addr type from the one in inst, which cause null inst found.
	 *
	 * this case will be specially treated after the call to validate_dest_addr()
	 * reason is there is a special case that when channel not found as src addr unequals
	 * and inst not found as dest addr type(ip4 vs ip6 for example, see explaination above)  unequals,
	 * if this packet is setup chunk, we probably
	 * stil can find a previous channel with the a new src addr found in init chunk address parameters,
	 * old src port and old dest port, and this precious channel must have a non-null inst;
	 * so here we return true to let the follwoing codes to handle this case.
	 */
	if (curr_geco_instance_ == NULL && curr_channel_ == NULL)
		return true;

	// either channel or inst is NULL
	// or both are not null

	// here we have checked src addr in find channel mtd now
	// we need make sure dst src is also presenting in channel's
	// local_addr_list. if not, just discard it.
	if (curr_channel_ != NULL)
	{
		/* 2) check if dest saadr and type in curr_channel_'s local addresses list*/
		for (uint j = 0; j < curr_channel_->local_addres_size; j++)
		{
			// all channels' addr unions MUST have the port setup same to the individual one
			// channel->remote port = all remote ports in remote addr list
			// channel->local port = all local port pports in local addt list = geco instance locla port
			// so dest port  must be equal to the one found in local addres list
			if (saddr_equals(&curr_channel_->local_addres[j], dest_addr))
			{
				EVENTLOG(VVERBOSE, "dispatch_layer_t::validate_dest_addr()::found equal dest addr");
				return true;
			}
		}
	}

	if (curr_geco_instance_ != NULL)
	{
		uchar af = saddr_family(dest_addr);
		if (curr_geco_instance_->is_inaddr_any && curr_geco_instance_->is_in6addr_any)
		{            //we supports both of ip4and6
			if (af == AF_INET || af == AF_INET6)
				return true;
		}
		else if (curr_geco_instance_->is_in6addr_any && !curr_geco_instance_->is_inaddr_any)
		{            //we only supports ip6
			if (af == AF_INET6)
				return true;
			else
				curr_ecc_reason_ = &af;
		}
		else if (!curr_geco_instance_->is_in6addr_any && curr_geco_instance_->is_inaddr_any)
		{            //we only supports ip4
			if (af == AF_INET)
				return true;
			else
				curr_ecc_reason_ = &af;
		}
		else //!curr_geco_instance_->is_inaddr_any && !curr_geco_instance_->is_in6addr_any
		{  // we found inst in compare_geco_instance(), here return true
			return true;
		}
	}
	return false;
}

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

int mdi_recv_geco_packet(int socket_fd, char *dctp_packet, uint dctp_packet_len, sockaddrunion * source_addr,
	sockaddrunion * dest_addr)
{
	EVENTLOG2(DEBUG, "- - - - - - - - - - Enter recv_geco_packet(%d bytes, fd %d) - - - - - - - - - -", dctp_packet_len,
		socket_fd);

	// validate port numbers
	curr_geco_packet_fixed_ = (geco_packet_fixed_t*)dctp_packet;
	curr_geco_packet_ = (geco_packet_t*)dctp_packet;

	static int rawsockip4 = mtra_read_ip4rawsock();
	static int rawsockip6 = mtra_read_ip6rawsock();
	static int udpsockip4 = mtra_read_ip4udpsock();
	if (socket_fd == rawsockip4 || socket_fd == rawsockip6)
	{
		// validate packet hdr size, checksum and if aligned 4 bytes
		if ((dctp_packet_len & 3) != 0 || dctp_packet_len < MIN_GECO_PACKET_SIZE || dctp_packet_len > MAX_GECO_PACKET_SIZE
			|| !gvalidate_checksum(dctp_packet, dctp_packet_len))
		{
			EVENTLOG(NOTICE, "mdi_recv_geco_packet()::received corrupted datagramm -> discard");
			return recv_geco_packet_but_integrity_check_failed;
		}
		last_src_port_ = ntohs(curr_geco_packet_fixed_->src_port);
		last_dest_port_ = ntohs(curr_geco_packet_fixed_->dest_port);
		mdi_udp_tunneled_ = false;
		curr_geco_packet_value_len_ = dctp_packet_len - GECO_PACKET_FIXED_SIZE;
		chunk = curr_geco_packet_->chunk;
	}
	else if (socket_fd == udpsockip4)
	{
		// validate packet hdr size, checksum and if aligned 4 bytes
		if ((dctp_packet_len & 3) != 0 || dctp_packet_len < MIN_UDP_PACKET_SIZE || dctp_packet_len > MAX_UDP_PACKET_SIZE)
		{
			EVENTLOG(NOTICE, "mdi_recv_geco_packet()::received corrupted datagramm -> discard");
			return recv_geco_packet_but_integrity_check_failed;
		}
		last_src_port_ = ntohs(source_addr->sin.sin_port);
		last_dest_port_ = ntohs(dest_addr->sin.sin_port);
		mdi_udp_tunneled_ = true;
		curr_geco_packet_value_len_ = dctp_packet_len - GECO_PACKET_FIXED_SIZE_USE_UDP;
		chunk = curr_geco_packet_->chunk - GECO_PACKET_FIXED_SIZE + sizeof(uint);
	}
	else
	{
		// validate packet hdr size, checksum and if aligned 4 bytes
		if ((dctp_packet_len & 3) != 0 || dctp_packet_len < MIN_UDP_PACKET_SIZE || dctp_packet_len > MAX_UDP_PACKET_SIZE)
		{
			EVENTLOG(NOTICE, "mdi_recv_geco_packet()::received corrupted datagramm -> discard");
			return recv_geco_packet_but_integrity_check_failed;
		}
		last_src_port_ = ntohs(source_addr->sin6.sin6_port);
		last_dest_port_ = ntohs(dest_addr->sin6.sin6_port);
		mdi_udp_tunneled_ = true;
		curr_geco_packet_value_len_ = dctp_packet_len - GECO_PACKET_FIXED_SIZE_USE_UDP;
		chunk = curr_geco_packet_->chunk - GECO_PACKET_FIXED_SIZE + sizeof(uint);
	}

	if (last_src_port_ == 0 || last_dest_port_ == 0)
	{
		/* refers to RFC 4960 Section 3.1 at line 867 and line 874*/
		ERRLOG(NOTICE, "dispatch_layer_t:: invalid ports number (0)");
		last_src_port_ = 0;
		last_dest_port_ = 0;
		EVENTLOG(NOTICE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
		return recv_geco_packet_but_port_numbers_check_failed;
	}

	/* 3) validate ip addresses
	 #include <netinet/in.h>
	 int IN6_IS_ADDR_UNSPECIFIED(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_LOOPBACK(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MULTICAST(const struct in6_addr * aptr);
	 //Link-local addresses for IPv4 are defined in the address block 169.254.0.0/16,
	 //in CIDR notation. In IPv6, they are assigned with the prefix fe80::/64
	 int IN6_IS_ADDR_LINKLOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_SITELOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_V4MAPPED(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_V4COMPAT(const struct in6_addr * aptr);
	 // multicast macros
	 int IN6_IS_ADDR_MC_NODELOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MC_LINKLOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MC_SITELOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MC_ORGLOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MC_GLOBAL(const struct in6_addr * aptr);
	 //返回值：非零表示IPv6地址是指定类型的，否则返回零
	 Note: A sender MUST NOT use an IPv4-mapped IPv6 address [RFC4291],
	 but should instead use an IPv4 Address parameter for an IPv4 address.
	 */
	should_discard_curr_geco_packet_ = false;
	dest_addr_type_ = saddr_family(dest_addr);
	if (dest_addr_type_ == AF_INET)
	{
		dest_addr_type_ = SUPPORT_ADDRESS_TYPE_IPV4; // peer snd us an IP4-formate address
		dest_addr->sin.sin_port = htons(last_dest_port_);
		ip4_saddr_ = ntohl(dest_addr->sin.sin_addr.s_addr);

		if (IN_CLASSD(ip4_saddr_))
		{
			EVENTLOG(VERBOSE, "IN_CLASSD(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN_EXPERIMENTAL(ip4_saddr_))
		{
			EVENTLOG(VERBOSE, "IN_EXPERIMENTAL(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN_BADCLASS(ip4_saddr_))
		{
			EVENTLOG(VERBOSE, "IN_BADCLASS(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (INADDR_ANY == ip4_saddr_)
		{
			EVENTLOG(VERBOSE, "INADDR_ANY(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (INADDR_BROADCAST == ip4_saddr_)
		{
			EVENTLOG(VERBOSE, "INADDR_BROADCAST(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
	}
	else if (dest_addr_type_ == AF_INET6)
	{
		dest_addr_type_ = SUPPORT_ADDRESS_TYPE_IPV6; // peer snd us an IP6-formate address
		dest_addr->sin6.sin6_port = htons(last_dest_port_);
		ip6_saddr_ = &(dest_addr->sin6.sin6_addr);

		if (IN6_IS_ADDR_UNSPECIFIED(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_UNSPECIFIED(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_MULTICAST(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_MULTICAST(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_V4COMPAT(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_V4COMPAT(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_V4MAPPED(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_V4MAPPED(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_ADDR_EQUAL(&in6addr_any, ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6ADDR_ANY(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
	}
	else
	{
		// we only supports IP archetecture either ip4 or ip6 so discard it
		EVENTLOG(VERBOSE, "AddrFamily(dest_addr) -> discard!");
		should_discard_curr_geco_packet_ = true;
	}

	if (saddr_family(source_addr) == AF_INET)
	{
		source_addr->sin.sin_port = htons(last_src_port_);
		ip4_saddr_ = ntohl(source_addr->sin.sin_addr.s_addr);

		if (IN_CLASSD(ip4_saddr_))
		{
			EVENTLOG(NOTICE, "IN_CLASSD(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN_EXPERIMENTAL(ip4_saddr_))
		{
			EVENTLOG(NOTICE, "IN_EXPERIMENTAL(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN_BADCLASS(ip4_saddr_))
		{
			EVENTLOG(NOTICE, "IN_BADCLASS(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (INADDR_ANY == ip4_saddr_)
		{
			EVENTLOG(NOTICE, "INADDR_ANY(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (INADDR_BROADCAST == ip4_saddr_)
		{
			EVENTLOG(NOTICE, "INADDR_BROADCAST(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
	}
	else if (saddr_family(source_addr) == AF_INET6)
	{
		source_addr->sin6.sin6_port = htons(last_src_port_);
		ip6_saddr_ = &(source_addr->sin6.sin6_addr);

		if (IN6_IS_ADDR_UNSPECIFIED(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_UNSPECIFIED(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_MULTICAST(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_MULTICAST(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_V4COMPAT(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_V4COMPAT(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_V4MAPPED(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_V4MAPPED(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_ADDR_EQUAL(&in6addr_any, ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6ADDR_ANY(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
	}
	else
	{
		// we only supports IP archetecture either ip4 or ip6 so discard it
		EVENTLOG(VERBOSE, "AddrFamily((source_addr)) -> discard!");
		should_discard_curr_geco_packet_ = true;
	}
#ifdef _DEBUG
	ushort msrcport;
	ushort mdestport;
	saddr2str(source_addr, src_addr_str_, MAX_IPADDR_STR_LEN, &msrcport);
	saddr2str(dest_addr, dest_addr_str_, MAX_IPADDR_STR_LEN, &mdestport);
#endif

	if (should_discard_curr_geco_packet_)
	{
		last_src_port_ = 0;
		last_dest_port_ = 0;
#ifdef _DEBUG
		EVENTLOG4(VERBOSE, "discarding packet for incorrect address src addr : %s:%d, dest addr%s:%d", src_addr_str_,
			last_src_port_, dest_addr_str_, last_dest_port_);
#endif
		EVENTLOG(NOTICE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
		return recv_geco_packet_but_addrs_formate_check_failed;
	}
	else
	{
		// we can assign addr as they are good to use now
		mdi_send_sfd_ = socket_fd;
		last_source_addr_ = source_addr;
		last_dest_addr_ = dest_addr;
		curr_trans_addr_.local_saddr = dest_addr;
		curr_trans_addr_.peer_saddr = source_addr;
		saddr2str(curr_trans_addr_.peer_saddr, src_addr_str_, MAX_IPADDR_STR_LEN, &msrcport);
		saddr2str(curr_trans_addr_.local_saddr, dest_addr_str_, MAX_IPADDR_STR_LEN, &mdestport);
		EVENTLOG4(DEBUG, "peer_saddr %s:%d, local_saddr %s:%d", src_addr_str_, msrcport, dest_addr_str_, mdestport);
	}

	/*4) find the endpoint for this packet */
  // cmp_channel() will set last_src_path_ to the one found src's
  // index in channel's remote addr list
	curr_channel_ = mdi_find_channel();
	if (curr_channel_ != NULL)
	{
		EVENTLOG1(INFO, "Found channel %d", curr_channel_->channel_id);
		/*5) get the sctp instance for this packet from channel*/
		curr_geco_instance_ = curr_channel_->geco_inst;
		if (curr_geco_instance_ == NULL)
		{
			ERRLOG(MAJOR_ERROR, "Foundchannel, but no geo Instance -> abort app -> FIXME imple errors !");
			clear();
			return recv_geco_packet_but_found_channel_has_no_instance;
		}
		else
		{
			my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
		}
	}
	else
	{
		/* 6) find  instance for this packet if this packet is for a server dctp instance,
		 *  we will find that  instance and let it handle this packet (i.e. we have an
		 *  instance's localPort set and it matches the packet's destination port)
		 */
		curr_geco_instance_ = mdi_find_geco_instance(last_dest_addr_, last_dest_port_);
		if (curr_geco_instance_ == NULL)
		{
			// Possible Reasons: dest af not matched || dest addr not matched || dest port not matched
			my_supported_addr_types_ = SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6;
#ifdef _DEBUG
			EVENTLOG3(VERBOSE, "Couldn't find an Instance with dest addr %s:%u, default support addr types ip4 and ip6 %u !",
				src_addr_str_, last_dest_port_, my_supported_addr_types_);
#endif
		}
		else
		{
			EVENTLOG1(INFO, "Found instance %d", curr_geco_instance_->dispatcher_name);
			// use user sepecified supported addr types
			my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
#ifdef _DEBUG
			EVENTLOG3(VERBOSE, "Find an Instance with dest addr %s:%u, user sepecified support addr types:%u !",
				src_addr_str_, last_dest_port_, my_supported_addr_types_);
#endif
		}
	}

	tmp_peer_addreslist_size_ = 0;
	curr_uchar_init_chunk_ = NULL;
	send_abort_ = false;
	last_veri_tag_ = ntohl(curr_geco_packet_->pk_comm_hdr.verification_tag);

	/*9) fetch all chunk types contained in this packet value field for use in the folowing */
	chunk_types_arr_ = find_chunk_types(chunk, curr_geco_packet_value_len_, &total_chunks_count_);

	/* 10) validate individual chunks
	 * (see section 3.1 of RFC 4960 at line 931 init chunk MUST be the only chunk
	 * in the  packet carrying it)*/
	init_chunk_num_ = contains_chunk(CHUNK_INIT, chunk_types_arr_);
	if (init_chunk_num_ > 1 || /*only one int ack with other type chunks*/
		(init_chunk_num_ == 1 && total_chunks_count_ > 1)/*there are repeated init ack chunks*/)
	{
		ERRLOG(MINOR_ERROR, "recv_geco_packet(): discarding illegal packet (init is not only one !)");
		clear();
		return recv_geco_packet_but_morethanone_init;
	}

	init_chunk_num_ = contains_chunk(CHUNK_INIT_ACK, chunk_types_arr_);
	if (init_chunk_num_ > 1 || (init_chunk_num_ == 1 && total_chunks_count_ > 1))
	{
		ERRLOG(MINOR_ERROR, "recv_geco_packet(): discarding illegal packet (init ack is not only chunk!)");
		clear();
		return recv_geco_packet_but_morethanone_init_ack;
	}

	init_chunk_num_ = contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr_);
	if (init_chunk_num_ > 1 || (init_chunk_num_ == 1 && total_chunks_count_ > 1))
	{
		ERRLOG(MINOR_ERROR, "recv_geco_packet(): discarding illegal packet (shutdown complete is not the only chunk !)");
		clear();
		return recv_geco_packet_but_morethanone_shutdown_complete;
	}

	found_init_chunk_ = false;
	cookie_echo_found_ = false;
	init_chunk_fixed_ = NULL;
	vlparam_fixed_ = NULL;

	/* founda matching channel using the source addr*/
	/* 11) try to find an existed channel for this packet from setup chunks */
	if (curr_channel_ == NULL)
	{
		if (curr_geco_instance_ != NULL || is_there_at_least_one_equal_dest_port_)
		{

			curr_uchar_init_chunk_ = mch_find_first_chunk_of(chunk, curr_geco_packet_value_len_,
				CHUNK_INIT_ACK);
			if (curr_uchar_init_chunk_ != NULL)
			{
				assert(
					curr_geco_packet_value_len_ == ntohs(((init_chunk_t*)curr_uchar_init_chunk_)->chunk_header.chunk_length));
				tmp_peer_addreslist_size_ = mdi_read_peer_addreslist(tmp_peer_addreslist_, curr_uchar_init_chunk_,
					curr_geco_packet_value_len_, my_supported_addr_types_,
					NULL, true, false) - 1;
				for (; tmp_peer_addreslist_size_ >= 0; tmp_peer_addreslist_size_--)
				{
					curr_trans_addr_.peer_saddr = &tmp_peer_addreslist_[tmp_peer_addreslist_size_];
					if ((curr_channel_ = mdi_find_channel()) != NULL)
					{
						EVENTLOG(VERBOSE, "Found an existing channel  in INIT ACK chunk's addrlist vlp !");
						break;
					}
				}
			}
			else // as there is only one init chunk in an packet, we use else for efficiency
			{
				curr_uchar_init_chunk_ = mch_find_first_chunk_of(chunk, curr_geco_packet_value_len_,
					CHUNK_INIT);
				if (curr_uchar_init_chunk_ != NULL)
				{
					EVENTLOG(VERBOSE, "Looking for source address in INIT CHUNK");
					assert(
						curr_geco_packet_value_len_
						== ntohs(((init_chunk_t*)curr_uchar_init_chunk_)->chunk_header.chunk_length));
					tmp_peer_addreslist_size_ = mdi_read_peer_addreslist(tmp_peer_addreslist_, curr_uchar_init_chunk_,
						curr_geco_packet_value_len_, my_supported_addr_types_, NULL, true, false) - 1;
					for (; tmp_peer_addreslist_size_ >= 0; tmp_peer_addreslist_size_--)
					{
						curr_trans_addr_.peer_saddr = &tmp_peer_addreslist_[tmp_peer_addreslist_size_];
						if ((curr_channel_ = mdi_find_channel()) != NULL)
						{
							EVENTLOG(VERBOSE, "Found an existing channel  in INIT chunk's addrlist vlp !");
							break;
						}
					}
				}  //if (curr_uchar_init_chunk_ != NULL) CHUNK_INIT
			}

			/* 12)
			 * this may happen when a previously-connected endpoint re-connect to us
			 * puting a new source addr in IP packet (this is why curr_channel_ is NULL above)
			 * but also put the previously-used source addr in vlp, with the previous channel
			 * still alive (this is why curr_channel_ becomes NOT NULL ).
			 * anyway, use the previous channel to handle this packet
			 */
			if (curr_channel_ != NULL)
			{
				EVENTLOG(VERBOSE, "recv_geco_packet(): Found an existing channel from INIT (ACK) addrlist vlp");
				curr_geco_instance_ = curr_channel_->geco_inst;
				my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
			}
#ifdef _DEBUG
			else
			{
				EVENTLOG(VERBOSE, "recv_geco_packet(): Not found an existing channel from INIT (ACK) addrlist vlp");
			}
#endif
		}
	}

	is_found_init_chunk_ = false;
	is_found_cookie_echo_ = false;
	is_found_abort_chunk_ = false;

	/* 13) process non-OOTB chunks that belong to a found channel */
	if (curr_channel_ != NULL)
	{
		EVENTLOG(INFO, "non-ootb packet");

		// when peer restarts with different sfd to its previous connection, we need update
		if (curr_channel_->state_machine_control->channel_state == ChannelState::Connected)
		{
			if (mdi_udp_tunneled_)
			{
				if (curr_channel_->bundle_control->geco_packet_fixed_size != GECO_PACKET_FIXED_SIZE_USE_UDP)
				{
					curr_channel_->bundle_control->geco_packet_fixed_size =
						curr_channel_->bundle_control->geco_packet_fixed_size = curr_channel_->bundle_control->sack_position =
						curr_channel_->bundle_control->data_position = curr_channel_->bundle_control->ctrl_position =
						GECO_PACKET_FIXED_SIZE_USE_UDP;
					curr_channel_->bundle_control->curr_max_pdu = PMTU_LOWEST - IP_HDR_SIZE - UDP_HDR_SIZE;
				}
			}
			else
			{
				if (curr_channel_->bundle_control->geco_packet_fixed_size != GECO_PACKET_FIXED_SIZE)
				{
					curr_channel_->bundle_control->geco_packet_fixed_size =
						curr_channel_->bundle_control->geco_packet_fixed_size = curr_channel_->bundle_control->sack_position =
						curr_channel_->bundle_control->data_position = curr_channel_->bundle_control->ctrl_position =
						GECO_PACKET_FIXED_SIZE;
					curr_channel_->bundle_control->curr_max_pdu = PMTU_LOWEST - IP_HDR_SIZE;
				}
			}

		}

		/*13.1 validate curr_geco_instance_*/
		if (curr_geco_instance_ == NULL)
		{
			curr_geco_instance_ = curr_channel_->geco_inst;
			if (curr_geco_instance_ == NULL)
			{
				ERRLOG(MAJOR_ERROR, "We have an Association, but no Instance, FIXME !");
				clear();
				return recv_geco_packet_but_found_channel_has_no_instance;
			}
			else
			{
				my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
				EVENTLOG(VERBOSE, "Assign inst with the one from found channel!");
			}
		}
		else if (curr_channel_->geco_inst != curr_geco_instance_)
		{
			// we found a previously-connected channel in 12) from setup chunk
			//  the instance it holds MUST == curr_geco_instance_
			ERRLOG(WARNNING_ERROR, "We have an curr_channel_, but its Instance != found instance -> reset it!");
			curr_geco_instance_ = curr_channel_->geco_inst;
			if (curr_geco_instance_ == NULL)
			{
				ERRLOG(MAJOR_ERROR, "We have an Association, but no Instance, FIXME !");
				clear();
				return recv_geco_packet_but_found_channel_has_no_instance;
			}
		}

		/*13.2 CHUNK_INIT
		 see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
		 A) Rules for packet carrying INIT:
		 The sender MUST set the Verification Tag of the packet to 0.
		 When an endpoint receives an SCTP packet with the Verification
		 Tag set to 0, it should verify that the packet contains only an
		 INIT chunk.  Otherwise, the receiver MUST silently should_discard_curr_geco_packet_ the
		 packet.*/
		if (curr_uchar_init_chunk_ == NULL) // we MAY have found it from 11) at line 290
			curr_uchar_init_chunk_ = mch_find_first_chunk_of(chunk, curr_geco_packet_value_len_,
				CHUNK_INIT);

		/*msm_process_init_chunk() will furtherly handle this INIT chunk in the follwing method
		 here we just validate some fatal errors*/
		if (curr_uchar_init_chunk_ != NULL)
		{
			EVENTLOG(VERBOSE, "Find an INIT CHUNK");

			// we have tested it INIT, init-ack and shutdown complete is the only chunk above
			// at 10) at line 240
			is_found_init_chunk_ = true;

			// make sure init chunk has zero ver tag
			// last_init_tag_ has be aisigned a value at above
			if (last_veri_tag_ != 0)
			{
				ERRLOG(MINOR_ERROR, "Found INIT chunk  in non-ootb-packet, but its verifi tag != 0 ->discard !");
				clear();
				return recv_geco_packet_but_init_chunk_has_zero_verifi_tag;
			}

			init_chunk_fixed_ = &(((init_chunk_t*)curr_uchar_init_chunk_)->init_fixed);
			// if you need send ABORT later on  (i.e.for peer requests 0 streams), this give you the right tag
			last_init_tag_ = ntohl(init_chunk_fixed_->init_tag);
			EVENTLOG1(VERBOSE, "Its initiation-tag is %u", last_init_tag_);

			vlparam_fixed_ = (vlparam_fixed_t*)mch_read_vlparam_init_chunk(curr_uchar_init_chunk_,
				curr_geco_packet_value_len_,
				VLPARAM_HOST_NAME_ADDR);
			if (vlparam_fixed_ != NULL)
			{
				EVENTLOG(VERBOSE, "Found VLPARAM_HOST_NAME_ADDR  ->  do dns");
				// @TODO refers to RFC 4096 SECTION 5.1.2.  Handle Address Parameters DNS QUERY
				do_dns_query_for_host_name_ = true;
			}
#ifdef _DEBUG
			else
			{
				EVENTLOG(VERBOSE, "Not found VLPARAM_HOST_NAME_ADDR from INIT CHUNK -> Not do DNS!");
			}
#endif
		}

		/*13.3 CHUNK_ABORT
		 see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
		 B) Rules for packet carrying ABORT:
		 - The receiver of an ABORT MUST accept the packet if the
		 Verification Tag field of the packet matches its own tag and the
		 T bit is not set OR if it is set to its peer's tag and the T bit
		 is set in the Chunk Flags.  Otherwise, the receiver MUST silently
		 discard  packet and take no further action.

		 Reflecting tag T bit = 0
		 The T bit is set to 0 if the sender filled in the Verification Tag
		 expected by the peer. this is reflecting tag
		 the packet carries the receiver's indentification like the receiver name of a letter

		 Reflected tag T bit = 1
		 The T bit is set to 1 if the sender filled in the Verification Tag
		 of its own. this is reflected tag
		 the packet carries the sender's indentification like the sender name of a letter

		 the main role of TBIT is to resolve unnormal predcures due to retx. eg.
		 we recv more than one shutdownack from the correct peer
		 when recv first shutdownack, we delete the channel, and send shutdown complete to peer
		 when recv the second shutdown ack, we still need to

		 */
		if (contains_chunk(CHUNK_ABORT, chunk_types_arr_) > 0)
		{
			uchar* abortchunk = mch_find_first_chunk_of(chunk, curr_geco_packet_value_len_, CHUNK_ABORT);
			bool is_tbit_set = (((chunk_fixed_t*)abortchunk)->chunk_flags & 0x01);
			if ((is_tbit_set && last_veri_tag_ == curr_channel_->remote_tag)
				|| (!is_tbit_set && last_veri_tag_ == curr_channel_->local_tag))
			{
#ifdef _DEBUG
				EVENTLOG2(VERBOSE, "Found ABORT  in non-ootb-packet, is_tbit_set(%u), last_init_tag_(%u)-> processing!",
					is_tbit_set, last_init_tag_);
#endif
				is_found_abort_chunk_ = true;
			}
			else
			{
				clear();
				EVENTLOG(NOTICE, "Found ABORT  in non-ootb-packet, but verifi tag is illegal-> discard !");
				EVENTLOG(NOTICE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
				return recv_geco_packet_but_nootb_abort_chunk_has_ielegal_verifi_tag;
			}
		}

		/*13.4)  see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
		 C) Rules for packet carrying SHUTDOWN COMPLETE:
		 -   When sending a SHUTDOWN COMPLETE, if the receiver of the SHUTDOWN
		 ACK (the peer ) has a channel in our side, then the destination endpoint's tag
		 MUST be used,and the T bit MUST NOT be set.  Only where no TCB exists should
		 the sender use the Verification Tag from the SHUTDOWN ACK, and MUST set the T bit.
		 -   The receiver of a SHUTDOWN COMPLETE shall accept the packet if
		 the Verification Tag field of the packet matches its own tag and
		 the T bit is not set OR if it is set to its peer's tag and the T
		 bit is set in the Chunk Flags.  Otherwise, the receiver MUST
		 silently discard the packet and take no further action.
		 An endpoint MUST ignore the SHUTDOWN COMPLETE if it is not in the
		 SHUTDOWN-ACK-SENT state.*/
		if (contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr_) > 0)
		{
			if (get_curr_channel_state() != ChannelState::ShutdownAckSent)
			{
				EVENTLOG(VERBOSE, "Found SHUTDOWN_COMPLETE  in non-ootb-packet,"
					"at state other than SHUTDOWNACK_SENT -> discard !");
				clear();
				return recv_geco_packet_but_nootb_sdc_recv_otherthan_sdc_ack_sentstate;
			}
			uchar* shutdowncomplete = mch_find_first_chunk_of(chunk, curr_geco_packet_value_len_,
				CHUNK_SHUTDOWN_COMPLETE);
			bool is_tbit_set = (((chunk_fixed_t*)shutdowncomplete)->chunk_flags & FLAG_TBIT_SET);
			if ((is_tbit_set && last_veri_tag_ == curr_channel_->remote_tag)
				|| (!is_tbit_set && last_veri_tag_ == curr_channel_->local_tag))
			{
#ifdef _DEBUG
				EVENTLOG2(VERBOSE,
					"Found SHUTDOWN_COMPLETE  in non-ootb-packet, is_tbit_set(%u), last_init_tag_(%u)-> processing!",
					is_tbit_set, last_init_tag_);
#endif
				is_found_abort_chunk_ = true;
				//reuse this variable to avoid veritag check at the end of this block codes
			}
			else
			{
				EVENTLOG(NOTICE, "Found SHUTDOWN_COMPLETE  in non-ootb-packet, but verifi tag is illegal-> discard !");
				clear();
				return recv_geco_packet_but_nootb_sdc_recv_verifitag_illegal;
			}
		}

		/*13.5) see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
		 see E) Rules for packet carrying a SHUTDOWN ACK
		 If the receiver is in COOKIE-ECHOED or COOKIE-WAIT state the
		 procedures in Section 8.4 SHOULD be followed:
		 If the packet contains a SHUTDOWN ACK chunk, the receiver should
		 respond to the sender of the OOTB packet with a SHUTDOWN
		 COMPLETE.  When sending the SHUTDOWN COMPLETE, the receiver of
		 the OOTB packet must fill in the Verification Tag field of the
		 outbound packet with the Verification Tag received in the
		 SHUTDOWN ACK and set the T bit in the Chunk Flags to indicate
		 that the Verification Tag is reflected.
		 */
		if (contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types_arr_) > 0)
		{
			uint state = get_curr_channel_state();
			if (state == ChannelState::CookieEchoed || state == ChannelState::CookieWait)
			{
				EVENTLOG(NOTICE, "Found SHUTDOWN_ACK "
					" in non-ootb-packet  at state cookie echoed or cookie wait state, "
					"-> send SHUTDOWN_COMPLETE to the peer!");
				// should be treated as an Out Of The Blue packet. so use FLAG_TBIT_SET
				uint shutdown_complete_cid = mch_make_simple_chunk(
					CHUNK_SHUTDOWN_COMPLETE, FLAG_TBIT_SET);
				// this method will internally send all bundled chunks if exceeding packet max
				mdi_lock_bundle_ctrl();
				mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shutdown_complete_cid));
				mdi_unlock_bundle_ctrl();
				mdi_send_bundled_chunks();
				mch_free_simple_chunk(shutdown_complete_cid);
				clear();
				return discard;
			}
#ifdef _DEBUG
			else
			{
				EVENTLOG(NOTICE, "Found SHUTDOWN_ACK in non-ootb-packet at state other than "
					"cookie echoed or cookie wait state -> processing!");
			}
#endif
		}

		/* 13.6) see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
		 D) Rules for packet carrying a COOKIE ECHO
		 -   When sending a COOKIE ECHO, the endpoint MUST use the value of
		 the Initiate Tag received in the INIT ACK.
		 -   The receiver of a COOKIE ECHO follows the procedures in Section 5.2.1.
		 there are many deails in this case where we have to validate cookie jar,
		 here we just print it out and process further in another dedicated method*/
#ifdef _DEBUG
		if (contains_chunk(CHUNK_COOKIE_ECHO, chunk_types_arr_) > 0)
		{
			EVENTLOG(NOTICE, "Found CHUNK_COOKIE_ECHO in non-ootb-packet -> process further!");
			cookie_echo_found_ = true;
		}
#endif

		/* 13.6)
		 5.2.3.  Unexpected INIT ACK
		 If an INIT ACK is received by an endpoint in any state other than the
		 COOKIE-WAIT state, the endpoint should discard it. An unexpected
		 INIT ACK usually indicates the processing of an old or duplicated INIT chunk.*/
		if (contains_chunk(CHUNK_INIT_ACK, chunk_types_arr_) > 0)
		{
			if (get_curr_channel_state() != ChannelState::CookieWait)
			{
				EVENTLOG(NOTICE,
					"Found INIT_ACK in non-ootb-packet at state other than COOKIE-WAIT -> should_discard_curr_geco_packet_!");
				clear();
				return recv_geco_packet_but_nootb_initack_otherthan_cookiew_state;
			}

			vlparam_fixed_ = (vlparam_fixed_t*)mch_read_vlparam_init_chunk(curr_uchar_init_chunk_,
				curr_geco_packet_value_len_,
				VLPARAM_HOST_NAME_ADDR);
			if (vlparam_fixed_ != NULL)
			{
				EVENTLOG(VERBOSE, "found VLPARAM_HOST_NAME_ADDR  -> DNS QUERY");
				// @TODO refers to RFC 4096 SECTION 5.1.2.  Handle Address Parameters
				// need do DNS QUERY instead of simply ABORT
				do_dns_query_for_host_name_ = true;
			}
		}

		// finally verify verifi tag in this packet
		// init chunj must has zero verifi tag value except of it
		// abort chunk has T bit set cannot that has its own filtering conditions
		// cookie_echo may be sent by restarted host with new itag that is different from the old one
		if (!cookie_echo_found_ && !is_found_init_chunk_ && !is_found_abort_chunk_
			&& last_veri_tag_ != curr_channel_->local_tag)
		{
			ERRLOG(MINOR_ERROR, "found channel:non-ootb-packet:check verifi-tag:"
				"this packet's verifi-tag != channel's local-tag -> discard !!");
			clear();
			return recv_geco_packet_but_nootb_packet_verifitag_illegal;
		}
#ifdef _DEBUG
		else
		{
			EVENTLOG(INFO, "disassemble  packet");
		}
#endif
	}
	else  // (curr_channel_ == NULL)
	{
		/* 14)
		 * filtering and pre-process OOB chunks that have no channel found
		 * refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets */
		EVENTLOG(INFO, "ootb packet");

		if (mdi_udp_tunneled_)
		{
			if (default_bundle_ctrl_->geco_packet_fixed_size != GECO_PACKET_FIXED_SIZE_USE_UDP)
			{
				default_bundle_ctrl_->geco_packet_fixed_size = default_bundle_ctrl_->sack_position =
					default_bundle_ctrl_->data_position = default_bundle_ctrl_->ctrl_position = GECO_PACKET_FIXED_SIZE_USE_UDP;
				curr_channel_->bundle_control->curr_max_pdu = PMTU_LOWEST - IP_HDR_SIZE - UDP_HDR_SIZE;
			}
		}
		else
		{
			if (default_bundle_ctrl_->geco_packet_fixed_size != GECO_PACKET_FIXED_SIZE)
			{
				default_bundle_ctrl_->geco_packet_fixed_size = default_bundle_ctrl_->sack_position =
					default_bundle_ctrl_->data_position = default_bundle_ctrl_->ctrl_position = GECO_PACKET_FIXED_SIZE;
				curr_channel_->bundle_control->curr_max_pdu = PMTU_LOWEST - IP_HDR_SIZE;
			}
		}

		/*15)
		 * refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (2)
		 * If the OOTB packet contains an ABORT chunk, the receiver MUST
		 * silently the OOTB packet and take no further action
		 * no need to fetch ecc from it as at this moment we have not connected*/
		if (contains_chunk(CHUNK_ABORT, chunk_types_arr_) > 0)
		{
			clear();
			EVENTLOG(DEBUG, "Found ABORT in ootb-packet, discarding it !");
			EVENTLOG(DEBUG, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
			return recv_geco_packet_but_it_is_ootb_abort_discard;
		}

		/*16) refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (5)
		 If the packet contains a SHUTDOWN ACK chunk, the receiver should
		 respond to the sender of the OOTB packet with a SHUTDOWN
		 COMPLETE.  When sending the SHUTDOWN COMPLETE, the receiver of
		 the OOTB packet must fill in the Verification Tag field of the
		 outbound packet with the Verification Tag received in the
		 SHUTDOWN ACK and set the T bit in the Chunk Flags to indicate
		 that the Verification Tag is reflected*/
		if (contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types_arr_) > 0)
		{
			EVENTLOG(DEBUG, "Found SHUTDOWN_ACK -> send SHUTDOWN_COMPLETE and return!");
			uint shutdown_complete_cid = mch_make_simple_chunk(CHUNK_SHUTDOWN_COMPLETE, FLAG_TBIT_SET);
			mdi_lock_bundle_ctrl();
			mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(shutdown_complete_cid));
			mdi_unlock_bundle_ctrl();
			mdi_send_bundled_chunks();
			mch_free_simple_chunk(shutdown_complete_cid);
			clear();
			EVENTLOG(DEBUG, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
			return recv_geco_packet_but_it_is_ootb_sdack_send_sdc;
		}

		/*17) refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (6)
		 If the packet contains a SHUTDOWN COMPLETE chunk, the receiver
		 should silently discard the packet and take no further action.
		 this is good because when receiving st-cp chunk, the peer has finished
		 shutdown pharse withdeleting TCB and all related data, channek is NULL
		 is actually what we want*/
		if (contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr_) > 0)
		{
			EVENTLOG(INFO, "Found SHUTDOWN_COMPLETE in OOB packet, discard !");
			clear();
			return recv_geco_packet_but_it_is_ootb_sdc_discard;
		}

		/* 18)
		 * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (7)
		 * If th packet contains  a COOKIE ACK, the SCTP packet should be silently discarded*/
		if (contains_chunk(CHUNK_COOKIE_ACK, chunk_types_arr_) > 0)
		{
			EVENTLOG(INFO, "Found CHUNK_COOKIE_ACK  in OOB packet, discarding it!");
			clear();
			return recv_geco_packet_but_it_is_ootb_cookie_ack_discard;
		}

		/* 19)
		 * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (7)
		 * If th packet contains a "Stale Cookie" ERROR, the SCTP packet should be silently discarded*/
		if (contains_error_chunk(chunk, curr_geco_packet_value_len_,
			ECC_STALE_COOKIE_ERROR))
		{
			EVENTLOG(INFO, "Found ECC_STALE_COOKIE_ERROR  in OOB packet,discarding it!");
			clear();
			return recv_geco_packet_but_it_is_ootb_stale_cookie_err_discard;
		}

		/* 20)
		 Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (3)
		 If the packet contains an INIT chunk with a Verification Tag set
		 to '0', process it as described in Section 5.1.  If, for whatever
		 reason, the INIT cannot be processed normally and an ABORT has to
		 be sent in response, the Verification Tag of the packet
		 containing the ABORT chunk MUST be the Initiate Tag of the
		 received INIT chunk, and the T bit of the ABORT chunk has to be
		 set to 0, indicating that the Verification Tag is NOT reflected.*/

		 // if this packet has channel, codes in 11 if (curr_channel_ == NULL)
		 // at line 260 will not actually run, that is why we find it again here
		if (curr_uchar_init_chunk_ == NULL)
		{
			curr_uchar_init_chunk_ = mch_find_first_chunk_of(chunk, curr_geco_packet_value_len_,
				CHUNK_INIT);
		}

		if (curr_uchar_init_chunk_ != NULL)
		{
			EVENTLOG(INFO, "found INIT CHUNK in ootb packet");
			if (last_veri_tag_ != 0)
			{
				EVENTLOG(DEBUG, " but verification_tag in INIT != 0 -> DISCARD! ");
				return recv_geco_packet_but_ootb_init_chunk_has_non_zero_verifi_tag;
			}

			// update last_init_tag_ with value of init tag carried in this chunk
			init_chunk_fixed_ = &(((init_chunk_t*)curr_uchar_init_chunk_)->init_fixed);
			last_init_tag_ = ntohl(init_chunk_fixed_->init_tag);
			EVENTLOG1(DEBUG, "Found init_tag (%u) from INIT CHUNK", last_init_tag_);

			// we have an instance up listenning on that port just validate geco_instance_params
			// this is normal connection pharse
			if (curr_geco_instance_ != NULL)
			{
				if (curr_geco_instance_->local_port == 0)
				{
					EVENTLOG(MAJOR_ERROR, "an instance found, but curr_geco_instance's local port is 0 -> discard !");
					return recv_geco_packet_but_local_instance_has_zero_portnum;
				}

#ifdef _DEBUG
				EVENTLOG(DEBUG, "curr_geco_instance found -> processing!");
#endif

				vlparam_fixed_ = (vlparam_fixed_t*)mch_read_vlparam_init_chunk(curr_uchar_init_chunk_,
					curr_geco_packet_value_len_,
					VLPARAM_HOST_NAME_ADDR);
				if (vlparam_fixed_ != NULL)
				{
					EVENTLOG(DEBUG, "found VLPARAM_HOST_NAME_ADDR from INIT CHUNK --->  TODO DNS QUERY");
					// TODO refers to RFC 4096 SECTION 5.1.2.  Handle Address Parametersd.
					do_dns_query_for_host_name_ = true;
				}
#ifdef _DEBUG
				else
					EVENTLOG(DEBUG, "Not VLPARAM_HOST_NAME_ADDR from INIT CHUNK ---> NOT DO DNS!");
				EVENTLOG(DEBUG, "---> Start to pass this INIT CHUNK to disassembl() for further processing!");
#endif
			}  // if (curr_geco_instance_ != NULL) at line 460
			else
			{
				/*20)
				 Refers to RFC 4960 Sectiion 5.1
				 If an endpoint receives an INIT, INIT ACK, or COOKIE ECHO chunk but
				 decides not to establish the new association due to missing mandatory
				 parameters in the received INIT or INIT ACK, invalid parameter values,
				 or lack of local resources, it MUST respond with an ABORT chunk
				 we do not have an instance up listening on that port-> ABORT
				 this may happen when a peer is connecting WITH wrong dest port,
				 or wrong addr type of dest addr, send  ABORT  +  ECC_UNRESOLVABLE_ADDRESS*/
				EVENTLOG(NOTICE, "Not found an instance -> send ABORT "
					"with ECC_PEER_NOT_LISTENNING_ADDR or ECC_PEER_NOT_LISTENNING_PORT");
				is_there_at_least_one_equal_dest_port_ ? curr_ecc_code_ =
					ECC_PEER_NOT_LISTENNING_ADDR :
					curr_ecc_code_ =
					ECC_PEER_NOT_LISTENNING_PORT;
				chunkflag2use_ = FLAG_TBIT_UNSET;
				curr_ecc_reason_ = (uchar*)last_dest_addr_;
				curr_ecc_len_ = sizeof(sockaddrunion);
				send_abort_ = true;
			}
		}  // if (init_chunk != NULL)
		else if (contains_chunk(CHUNK_COOKIE_ECHO, chunk_types_arr_) > 0)
		{
			/* 21)
			 * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (4)
			 * If the packet contains a COOKIE ECHO in the first chunk, process
			 *  it as described in Section 5.1. */
			EVENTLOG(DEBUG, "Found CHUNK_COOKIE_ECHO in ootb packet -> processing it");

			// validate that cookie echo chunk must be the first chunk
			if (((chunk_fixed_t*)(chunk))->chunk_id != CHUNK_COOKIE_ECHO)
			{
				EVENTLOG(VERBOSE, "but it is not the first chunk in the packet ---> discarding");
				clear();
				return recv_geco_packet_but_ootb_cookie_echo_is_not_first_chunk;
			}

			if (curr_geco_instance_ == NULL)
			{ // cannot find inst for this packet, it does not belong to us. discard it!
				EVENTLOG(VERBOSE, "but cannot found inst for it ---> send abort with ecc");
				// need send abort because peer have channel instance built
				is_there_at_least_one_equal_dest_port_ ? curr_ecc_code_ =
					ECC_PEER_NOT_LISTENNING_ADDR :
					curr_ecc_code_ =
					ECC_PEER_NOT_LISTENNING_PORT;
				curr_ecc_reason_ = (uchar*)last_dest_addr_;
				curr_ecc_len_ = sizeof(sockaddrunion);
				send_abort_ = true;
			}
			//clear();
			//return discard;
		}
		else  //Found unecpected chunks in ootb packet
		{
			/* 22)
			 Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (8)
			 The receiver should respond to the sender of OOTB packet with
			 an ABORT.  When sending the ABORT, the receiver of the OOTB
			 packet MUST fill in the Verification Tag field of the outbound
			 packet with the value found in the Verification Tag field of the
			 OOTB packet and set the T bit in the Chunk Flags to indicate that
			 the Verification Tag is reflected.  After sending this ABORT, the
			 receiver of the OOTB packet shall should_discard  the OOTB packet and
			 take no further action.*/
			 // HOWEVER I think rfc is wrong here
			 // the peer is sending unkown chunks to us without
			 // normal connection built,which is likely to be attacks so just discard to save network data
			EVENTLOG(NOTICE, "Found unrecognized chunks in ootb packet -> discard!");
			return discard;
			//send_abort_ = true;
			//curr_ecc_code_ = ECC_UNRECOGNIZED_CHUNKTYPE;
			//curr_ecc_len_ = 0;
			//curr_ecc_reason_ = 0;
		}
	}

	/*23) may send ABORT to the peer */
	if (send_abort_)
	{
		// we never send abort to a unconnected peer
		if (curr_channel_ == NULL && !send_abort_for_oob_packet_)
		{
			EVENTLOG(VERBOSE, "this is ootb packet AND send_abort_for_oob_packet_==false -> not send abort !");
			clear();
			return recv_geco_packet_but_not_send_abort_for_ootb_packet;
		}

		EVENTLOG1(NOTICE, "Send ABORT with ecc code %u", curr_ecc_code_);
		if (chunkflag2use_ < 0)
			curr_channel_ == NULL ? chunkflag2use_ = FLAG_TBIT_SET : chunkflag2use_ =
			FLAG_TBIT_UNSET;

		chunk_id_t abort_cid = mch_make_simple_chunk(CHUNK_ABORT, chunkflag2use_);
		mch_write_error_cause(abort_cid, curr_ecc_code_, curr_ecc_reason_, curr_ecc_len_ - 4);

		mdi_lock_bundle_ctrl();
		mdi_bundle_ctrl_chunk(mch_complete_simple_chunk(abort_cid));
		mch_free_simple_chunk(abort_cid);
		mdi_unlock_bundle_ctrl();
		mdi_send_bundled_chunks();

		clear();
		return reply_abort;
	}  // 23 send_abort_ == true

  // forward packet value to bundle ctrl module for disassemblings
	mdi_lock_bundle_ctrl();
	mdi_disassemle_packet();
	mdi_unlock_bundle_ctrl();

	// no need to clear last_src_port_ and last_dest_port_ MAY be used by other functions
	last_src_path_ = -1;
	do_dns_query_for_host_name_ = false;

	EVENTLOG(NOTICE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
	return geco_return_enum::good;
}

/* port management array */
unsigned char portsSeized[65536];
unsigned int numberOfSeizedPorts;

// unused
//static void dummy_tick_task_cb(void* userdata)
//{
//  static int counter = 0;
//  counter++;
//  if (counter > 300)
//  {
//    EVENTLOG1(DEBUG, "task_cb called 300 times with tick of 10ms(userdata = %s) should never be called",
//        (char* )userdata);
//    counter = 0;
//  }
//}
//static void dummy_ip6_socket_cb(int sfd, char* data, int datalen, sockaddrunion* from, sockaddrunion* to)
//{
//  EVENTLOG3(VERBOSE, "dummy_ip6_socket_cb() should never be called!\n", datalen, data, sfd);
//}
//static void dummy_ip4_socket_cb(int sfd, char* data, int datalen, sockaddrunion* from, sockaddrunion* to)
//{
//  EVENTLOG3(VERBOSE, "dummy_ip4_socket_cb() should never be called!\n", datalen, data, sfd);
//}

int initialize_library(void)
{
	if (library_initiaized == true)
		return MULP_LIBRARY_ALREADY_INITIALIZED;
#if !defined(WIN32) && !defined(USE_UDP)
	/* check privileges. Must be root or setuid-root for now ! */
	if (geteuid() != 0)
	{
		EVENTLOG(NOTICE, "You must be root to use the lib (or make your program SETUID-root !).");
		return MULP_INSUFFICIENT_PRIVILEGES;
	}
	EVENTLOG1(DEBUG, "uid=%d", geteuid());
#endif

	read_trace_levels();
	int i, ret, maxMTU = 0;

	if ((ret = mtra_init(&myRWND)) < 0)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "initialize_library()::initialize transport module failed !!!");
	}

	cbunion_t cbunion;

	//cbunion.socket_cb_fun = dummy_ip4_socket_cb; //we do not need dummy sock cb
	cbunion.socket_cb_fun = 0;
	mtra_set_expected_event_on_fd(mtra_read_ip4rawsock(), EVENTCB_TYPE_SCTP,
		POLLIN | POLLPRI, cbunion, 0);
	mtra_set_expected_event_on_fd(mtra_read_ip4udpsock(), EVENTCB_TYPE_UDP,
		POLLIN | POLLPRI, cbunion, 0);

	//cbunion.socket_cb_fun = dummy_ip6_socket_cb;
	cbunion.socket_cb_fun = 0;
	mtra_set_expected_event_on_fd(mtra_read_ip6rawsock(), EVENTCB_TYPE_SCTP,
		POLLIN | POLLPRI, cbunion, 0);
	mtra_set_expected_event_on_fd(mtra_read_ip6udpsock(), EVENTCB_TYPE_UDP,
		POLLIN | POLLPRI, cbunion, 0);

	//const char* userdataa = "dummy_user_data";
	//mtra_set_tick_task_cb(dummy_tick_task_cb, (void*)userdataa);

	mdi_init();

	/* initialize ports seized */
	for (i = 0; i < 65536; i++)
		portsSeized[i] = 0;
	numberOfSeizedPorts = 0x00000000;

	/* initialize bundling, i.e. the common buffer for sending chunks when no association exists. */
	default_bundle_ctrl_ = mbu_new();

	/* this block is to be executed only once for the lifetime of sctp-software */
	get_secre_key(KEY_INIT);

	if (!get_local_addresses(&defaultlocaladdrlist_, &defaultlocaladdrlistsize_,
		mtra_read_ip4rawsock() != 0 ? mtra_read_ip4rawsock() : mtra_read_ip6rawsock(), true, &maxMTU,
		IPAddrType::AllCastAddrTypes))
		return MULP_SPECIFIC_FUNCTION_ERROR;

	library_initiaized = true;
	return MULP_SUCCESS;
}
void free_library(void)
{
	mtra_destroy();
	library_initiaized = false;
	geco_free_ext(default_bundle_ctrl_, __FILE__, __LINE__);
}
/**
 * allocatePort Allocate a given port.
 * @return usable port otherwise 0 if port is occupied.
 */
unsigned short unused(unsigned short port)
{
	if (port == UINT16_MAX || port < 0)
		ERRLOG(FALTAL_ERROR_EXIT, "port=%d must less than 65535");
	if (portsSeized[port] == 0)
	{
		portsSeized[port] = 1;
		numberOfSeizedPorts++;
		return (port);
	}
	return (0);
}
/**
 * seizePort return a free port number.
 * @return free port otherwise 0 if no port found.
 */
unsigned short allocport(void)
{
	unsigned short seizePort = 0;
	/* problem: no more available ports ?! */
	if (numberOfSeizedPorts >= 0xFBFF)
		return 0x0000;
	seizePort = (unsigned short)(generate_random_uint32() % 0xFFFF);
	while (portsSeized[seizePort] || seizePort < 1024) // make sure port not used and > 1024
	{
		seizePort = (unsigned short)(generate_random_uint32() % 0xFFFF);
	}
	numberOfSeizedPorts++;
	portsSeized[seizePort] = 1;
	return seizePort;
}
/**
 * releasePort frees a previously used port.
 * @param portSeized port that is to be freed.
 */
void freeport(unsigned short portSeized)
{
	if (portsSeized[portSeized] == 0 || portSeized == 0)
	{
		ERRLOG(MINOR_ERROR, "Warning: release of port that is not seized");
		return;
	}
	numberOfSeizedPorts--;
	portsSeized[portSeized] = 0;
}

int mulp_new_geco_instance(unsigned short localPort, unsigned short noOfOrderStreams, unsigned short noOfSeqStreams,
	unsigned int noOfLocalAddresses, unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN],
	ulp_cbs_t ULPcallbackFunctions)
{
	EXIT_CHECK_LIBRARY;

	unsigned int i;
	int ret;
	union sockaddrunion su;
	memset(&su, 0, sizeof(sockaddrunion));
	bool with_ipv4 = false;
	bool with_ipv6 = false;

	geco_instance_t* old_Instance = curr_geco_instance_;
	geco_channel_t* old_assoc = curr_channel_;

	// validate streams
	if ((noOfOrderStreams == 0) || (noOfSeqStreams == 0) || (noOfLocalAddresses == 0) || (localAddressList == NULL))
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mulp_new_geco_instance()::invalid parameters !");
	}

	// alloc port number
	localPort = localPort > 0 ? unused(localPort) : allocport();
	if (localPort == 0)
	{
		ERRLOG(FALTAL_ERROR_EXIT,
			"mulp_new_geco_instance()::Parameter Problem in mulp_new_geco_instance - local port has been used !");
	}

	bool is_inaddr_any = false;
	bool is_in6addr_any = false;
	uint mysupportedaddr = 0;

	//setup addrseslist
	for (i = 0; i < noOfLocalAddresses; i++)
	{
		if (str2saddr(&su, (const char*)localAddressList[i], localPort) < 0)
		{
			freeport(localPort);
			ERRLOG1(FALTAL_ERROR_EXIT, "mulp_new_geco_instance()::illegal local Address (%s) !!!", localAddressList[i]);
		}
		if (su.sa.sa_family == AF_INET)
		{
			with_ipv4 = true;
			mysupportedaddr |= SUPPORT_ADDRESS_TYPE_IPV4;
			if (su.sin.sin_addr.s_addr == INADDR_ANY)
			{
				is_inaddr_any = true;
			}
		}
		else if (su.sa.sa_family == AF_INET6)
		{
			with_ipv6 = true;
			mysupportedaddr |= SUPPORT_ADDRESS_TYPE_IPV6;
			if (IN6_ADDR_EQUAL(&in6addr_any, &su.sin6.sin6_addr))
			{
				is_in6addr_any = true;
			}
		}
		else
		{
			freeport(localPort);
			ERRLOG1(FALTAL_ERROR_EXIT, "mulp_new_geco_instance()::illegal address family (%d) !!!", su.sa.sa_family);
		}
	}

	EVENTLOG2(VERBOSE, "mulp_new_geco_instance()::with_ipv4 =%d, with_ipv6 = %d ", with_ipv4, with_ipv6);
	if (!with_ipv4 && !with_ipv6)
	{
		freeport(localPort);
		ERRLOG(FALTAL_ERROR_EXIT, "mulp_new_geco_instance()::No valid address");
	}

	// alloc instance and init it
	if ((curr_geco_instance_ = (geco_instance_t*)malloc(sizeof(geco_instance_t))) == NULL)
	{
		curr_geco_instance_ = old_Instance;
		freeport(localPort);
		ERRLOG(FALTAL_ERROR_EXIT, "mulp_new_geco_instance()::malloc geco instace failed!!!");
	}

	curr_geco_instance_->local_port = localPort;
	curr_geco_instance_->ordered_streams = noOfOrderStreams;
	curr_geco_instance_->sequenced_streams = noOfSeqStreams;
	curr_geco_instance_->is_inaddr_any = is_inaddr_any;
	curr_geco_instance_->is_in6addr_any = is_in6addr_any;
	curr_geco_instance_->use_ip4 = with_ipv4;
	curr_geco_instance_->use_ip6 = with_ipv6;
	curr_geco_instance_->supportedAddressTypes = mysupportedaddr;
	curr_geco_instance_->supportsPRSCTP = support_pr_;
	curr_geco_instance_->supportsADDIP = support_addip_;
	curr_geco_instance_->ulp_callbacks = ULPcallbackFunctions;
	curr_geco_instance_->default_rtoInitial = RTO_INITIAL;
	curr_geco_instance_->default_validCookieLife = VALID_COOKIE_LIFE_TIME;
	curr_geco_instance_->default_assocMaxRetransmits =
		ASSOCIATION_MAX_RETRANS_ATTEMPTS;
	curr_geco_instance_->default_pathMaxRetransmits = MAX_PATH_RETRANS_TIMES;
	curr_geco_instance_->default_maxInitRetransmits = MAX_INIT_RETRANS_ATTEMPTS;
	/* using the  variable defined after initialization of the adaptation layer */
	curr_geco_instance_->default_myRwnd = myRWND / 2;
	curr_geco_instance_->default_delay = delayed_ack_interval_;
	curr_geco_instance_->default_ipTos = (uchar)IPTOS_DEFAULT;
	curr_geco_instance_->default_rtoMin = RTO_MIN;
	curr_geco_instance_->default_rtoMax = RTO_MAX;
	curr_geco_instance_->default_maxSendQueue = DEFAULT_MAX_SENDQUEUE;
	curr_geco_instance_->default_maxRecvQueue = DEFAULT_MAX_RECVQUEUE;
	curr_geco_instance_->default_maxBurst = DEFAULT_MAX_BURST;

	//#ifdef _DEBUG
	//	char strs[MAX_IPADDR_STR_LEN];
	//#endif

	//copy addrlist to curr geco inst
	if (!is_inaddr_any && !is_in6addr_any)
	{
		bool found;
		curr_geco_instance_->local_addres_list = (sockaddrunion*)malloc(noOfLocalAddresses * sizeof(sockaddrunion));
		for (i = 0; i < noOfLocalAddresses; i++)
		{
			str2saddr(&curr_geco_instance_->local_addres_list[i], (const char*)localAddressList[i], localPort);
			//#ifdef _DEBUG
			//			saddr2str(&curr_geco_instance_->local_addres_list[i], strs, MAX_IPADDR_STR_LEN);
			//			EVENTLOG1(VERBOSE, "Try to find addr %s from default local addr list", strs);
			//#endif
			found = false;
			for (uint j = 0; j < defaultlocaladdrlistsize_; j++)
			{
				//#ifdef _DEBUG
				//				saddr2str(&defaultlocaladdrlist_[j], strs, MAX_IPADDR_STR_LEN);
				//				EVENTLOG1(VERBOSE, "curr addr = %s", strs);
				//#endif
				if (saddr_equals(&defaultlocaladdrlist_[j], &curr_geco_instance_->local_addres_list[i], true))
				{
					found = true;
				}
			}
			// LOOPBACK addr is not in defaultlocaladdrlist_ so handle it sepratly
			if (curr_geco_instance_->local_addres_list[i].sa.sa_family == AF_INET
				&& curr_geco_instance_->local_addres_list[i].sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK)
				&& curr_geco_instance_->local_addres_list[i].sin.sin_port == htons(localPort))
			{
				found = true;
			}
			if (curr_geco_instance_->local_addres_list[i].sa.sa_family == AF_INET6
				&& IN6_ADDR_EQUAL(&curr_geco_instance_->local_addres_list[i].sin6.sin6_addr, &in6addr_loopback)
				&& curr_geco_instance_->local_addres_list[i].sin6.sin6_port == htons(localPort))
			{
				found = true;
			}
			if (!found)
			{
				freeport(localPort);
				free(curr_geco_instance_->local_addres_list);
				free(curr_geco_instance_);
				curr_geco_instance_ = old_Instance;
				ERRLOG(FALTAL_ERROR_EXIT, "mulp_new_geco_instance()::Not found addr from default local addrlist");
			}
		}
		curr_geco_instance_->local_addres_size = noOfLocalAddresses;
	}
	else
	{
		curr_geco_instance_->local_addres_list = NULL;
		curr_geco_instance_->local_addres_size = 0;
	}

	if (with_ipv4)
		ipv4_sockets_geco_instance_users++;
	if (with_ipv6)
		ipv6_sockets_geco_instance_users++;

	ret = -1;
	for (int idx = 0; i < geco_instances_.size(); idx++)
	{
		if (geco_instances_[idx] == NULL)
		{
			ret = idx;
			curr_geco_instance_->dispatcher_name = ret;
			break;
		}
	}

	if (ret < 0)
		ERRLOG(FALTAL_ERROR_EXIT, "mulp_new_geco_instance()::too many geco instances !!!");

	geco_instances_[ret] = curr_geco_instance_;
	curr_geco_instance_ = old_Instance;
	curr_channel_ = old_assoc;
	EVENTLOG1(DEBUG, "mulp_new_geco_instance()::instance_idx=%d", ret);
	return ret;
}
int mulp_delete_geco_instance(int instance_idx)
{
	EXIT_CHECK_LIBRARY;

	int ret = MULP_SUCCESS;
	geco_instance_t* instance_name = geco_instances_[instance_idx];
	if (instance_name == NULL)
	{
		EVENTLOG(WARNNING_ERROR, "mulp_delete_geco_instance()::MULP_INSTANCE_NOT_FOUND!!!");
		return MULP_INSTANCE_NOT_FOUND;
	}

	if (instance_name->use_ip4)
		ipv4_sockets_geco_instance_users--;
	if (instance_name->use_ip6)
		ipv6_sockets_geco_instance_users--;

	for (uint i = 0; i < channels_size_; i++)
	{
		if (channels_[i] != NULL && channels_[i]->geco_inst == instance_name)
		{
			EVENTLOG(WARNNING_ERROR, "mulp_delete_geco_instance()::MULP_INSTANCE_IN_USE, CANNOT BE REMOVED!!!");
			return MULP_INSTANCE_IN_USE;
		}
	}

	if (mtra_read_ip4rawsock() > 0 && ipv4_sockets_geco_instance_users == 0)
	{
		EVENTLOG1(VVERBOSE, "sctp_unregisterInstance : Removed IPv4 RAW SOCKET, registered FDs: %u ",
			mtra_read_ip4rawsock());
		mtra_remove_event_handler(mtra_read_ip4rawsock());
	}
	if (mtra_read_ip6rawsock() > 0 && ipv6_sockets_geco_instance_users == 0)
	{
		EVENTLOG1(VVERBOSE, "sctp_unregisterInstance : Removed IPv6 RAW SOCKET, registered FDs: %u ",
			mtra_read_ip6rawsock());
		ret = mtra_remove_event_handler(mtra_read_ip6rawsock());
	}
	if (mtra_read_ip4udpsock() > 0 && ipv4_sockets_geco_instance_users == 0)
	{
		EVENTLOG1(VVERBOSE, "sctp_unregisterInstance : Removed IPv4 UDP SOCKET, registered FDs: %u ",
			mtra_read_ip4udpsock());
		ret = mtra_remove_event_handler(mtra_read_ip4udpsock());
	}
	if (mtra_read_ip6udpsock() > 0 && ipv6_sockets_geco_instance_users == 0)
	{
		EVENTLOG1(VVERBOSE, "sctp_unregisterInstance : Removed IPv6 UDP SOCKET", mtra_read_ip6udpsock());
		ret = mtra_remove_event_handler(mtra_read_ip6udpsock());
	}

	if (instance_name->is_in6addr_any == false)
	{
		EVENTLOG(VVERBOSE, "sctp_unregisterInstance : IN6ADDR_ANY == false");
	}
	if (instance_name->is_inaddr_any == false)
	{
		EVENTLOG(VVERBOSE, "sctp_unregisterInstance : INADDR_ANY == false");
	}

	if (instance_name->local_addres_size > 0)
	{
		free(instance_name->local_addres_list);
	}

	freeport(instance_name->local_port);
	free(instance_name);
	geco_instances_[instance_idx] = NULL;

	EVENTLOG1(DEBUG, "mulp_delete_geco_instance()::instance_idx=%d::good ", instance_idx);
	return ret;
}

int mulp_connect(unsigned int instanceid, unsigned short noOfOrderStreams, unsigned short noOfSeqStreams,
	char destinationAddress[MAX_IPADDR_STR_LEN], unsigned short destinationPort, void* ulp_data)
{
	char dAddress[1][MAX_IPADDR_STR_LEN];
	//memcpy(dAddress, destinationAddress, MAX_IPADDR_STR_LEN);
	memcpy_fast(dAddress, destinationAddress, MAX_IPADDR_STR_LEN);
	return mulp_connectx(instanceid, noOfOrderStreams, noOfSeqStreams, dAddress, 1, 1, destinationPort, ulp_data);
}
int mulp_connectx(unsigned int instanceid, unsigned short noOfOrderStreams, unsigned short noOfSeqStreams,
	char destinationAddresses[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN], unsigned int noOfDestinationAddresses,
	unsigned int maxSimultaneousInits, unsigned short destinationPort, void* ulp_data)
{
	EXIT_CHECK_LIBRARY;
	if (destinationPort == 0)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mulp_connectx()::destination port is zero....this is not allowed !");
	}

	union sockaddrunion dest_su[MAX_NUM_ADDRESSES];
	IPAddrType filterFlags = AllCastAddrTypes;

	for (uint count = 0; count < noOfDestinationAddresses; count++)
	{
		if (str2saddr(&dest_su[count], (char*)destinationAddresses[count], destinationPort) < 0)
		{
			ERRLOG(FALTAL_ERROR_EXIT, "mulp_connectx()::str2saddr(destination adress) failed !");
		}
		if (typeofaddr(&dest_su[count], filterFlags))				// is type of filtered addr
		{
			ERRLOG(FALTAL_ERROR_EXIT, "mulp_connectx():: illegal addr formate !");
		}
	}

	if (geco_instances_[instanceid] == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mulp_connectx()::not found geco instance !");
	}

	curr_geco_instance_ = geco_instances_[instanceid];
	ushort localPort;

	if (curr_geco_instance_->local_port == 0)
	{
		localPort = allocport();
		curr_geco_instance_->local_port = localPort;
		if (localPort == 0)
			ERRLOG(FALTAL_ERROR_EXIT, "mulp_connectx():: no usable local port!");
	}
	else
		localPort = curr_geco_instance_->local_port;

	uint itag = mdi_generate_itag();
	if (!mdi_new_channel(curr_geco_instance_, localPort,/* local client port */
		destinationPort,/* remote server port */
		itag, 0, noOfDestinationAddresses, dest_su))
	{
		ERRLOG(FALTAL_ERROR_EXIT, "mulp_connectx()::Creation of association failed !");
	}

	curr_channel_->ulp_dataptr = ulp_data;
	if (mdi_connect_udp_sfd_)
	{
		curr_channel_->bundle_control->geco_packet_fixed_size = curr_channel_->bundle_control->data_position =
			curr_channel_->bundle_control->sack_position = curr_channel_->bundle_control->ctrl_position =
			GECO_PACKET_FIXED_SIZE_USE_UDP;
		curr_channel_->bundle_control->curr_max_pdu = PMTU_LOWEST - IP_HDR_SIZE - UDP_HDR_SIZE;
	}
	else
	{
		curr_channel_->bundle_control->geco_packet_fixed_size = curr_channel_->bundle_control->data_position =
			curr_channel_->bundle_control->sack_position = curr_channel_->bundle_control->ctrl_position =
			GECO_PACKET_FIXED_SIZE;
		curr_channel_->bundle_control->curr_max_pdu = PMTU_LOWEST - IP_HDR_SIZE;
	}

	//insert channel id to map
	for (uint i = 0; i < curr_channel_->local_addres_size; i++)
	{
		curr_trans_addr_.local_saddr = curr_channel_->local_addres + i;
		curr_trans_addr_.local_saddr->sa.sa_family == AF_INET ?
			curr_trans_addr_.local_saddr->sin.sin_port = htons(localPort) : curr_trans_addr_.local_saddr->sin6.sin6_port =
			htons(localPort);
		for (uint ii = 0; ii < curr_channel_->remote_addres_size; ii++)
		{
			curr_trans_addr_.peer_saddr = curr_channel_->remote_addres + ii;
			if (curr_trans_addr_.local_saddr->sa.sa_family != curr_trans_addr_.peer_saddr->sa.sa_family)
				continue;
			if (channel_map_.find(curr_trans_addr_) != channel_map_.end())
				continue;
			channel_map_.insert(std::make_pair(curr_trans_addr_, curr_channel_->channel_id));
		}
	}
	// we always try
	if (noOfOrderStreams < curr_geco_instance_->ordered_streams)
		noOfOrderStreams = curr_geco_instance_->ordered_streams;
	if (noOfSeqStreams < curr_geco_instance_->sequenced_streams)
		noOfSeqStreams = curr_geco_instance_->sequenced_streams;
	msm_connect(noOfOrderStreams, noOfSeqStreams, dest_su, noOfDestinationAddresses);
	uint channel_id = curr_channel_->channel_id;
	return channel_id;
}

int mulp_abort(unsigned int connectionid)
{
	// Ungracefully closes an association.  Any locally queued user data
	// will be discarded, and an ABORT chunk is sent to the peer.  A success
	// code will be returned on successful abort of the association.  If
	// attempting to abort the association results in a failure, an error
	// code shall be returned.
	geco_channel_t *old_assoc = curr_channel_;
	curr_channel_ = channels_[connectionid];
	if (curr_channel_ != NULL)
	{
		curr_geco_instance_ = curr_channel_->geco_inst;
		// Forward shutdown to the addressed association
		msm_abort_channel(ECC_USER_INITIATED_ABORT);
	}
	else
	{
		ERRLOG(MINOR_ERROR, "mulp_abort(): addressed association does not exist");
		return MULP_ASSOC_NOT_FOUND;
	}
	curr_geco_instance_ = old_assoc->geco_inst;
	curr_channel_ = old_assoc;
	return MULP_SUCCESS;
}

int mulp_shutdown(unsigned int connectionid)
{
	// Gracefully closes an association.  Any locally queued user data will
	// be delivered to the peer.  The association will be terminated only
	// after the peer acknowledges all the SCTP packets sent.  A success
	// code will be returned on successful termination of the association.
	// If attempting to terminate the association results in a failure, an
	// error code shall be returned.
	geco_channel_t *old_assoc = curr_channel_;
	curr_channel_ = channels_[connectionid];
	if (curr_channel_ != NULL)
	{
		curr_geco_instance_ = curr_channel_->geco_inst;
		// Forward shutdown to the addressed association
		msm_shutdown();
	}
	else
	{
		ERRLOG(MINOR_ERROR, "mulp_abort(): addressed association does not exist");
		return MULP_ASSOC_NOT_FOUND;
	}
	curr_geco_instance_ = old_assoc->geco_inst;
	curr_channel_ = old_assoc;
	return MULP_SUCCESS;
}

int mulp_set_lib_params(lib_params_t *lib_params)
{
	EXIT_CHECK_LIBRARY;
	if (lib_params == NULL)
		return MULP_PARAMETER_PROBLEM;
	int ret;
	mtra_write_udp_local_bind_port(lib_params->udp_bind_port);
	send_abort_for_oob_packet_ = lib_params->send_ootb_aborts;
	support_addip_ = lib_params->support_dynamic_addr_config;
	support_pr_ = lib_params->support_particial_reliability;
	lib_params->pmtu_lowest == 0 ? PMTU_LOWEST = 576 : PMTU_LOWEST = lib_params->pmtu_lowest;
	if ((delayed_ack_interval_ = lib_params->delayed_ack_interval) >= 500)
	{
		ret = MULP_PARAMETER_PROBLEM;
		ERRLOG(FALTAL_ERROR_EXIT, "mulp_set_lib_params()::delayed_ack_interval cannot be greater than 500MS!");
		return ret;
	}
	if (lib_params->checksum_algorithm == MULP_CHECKSUM_ALGORITHM_CRC32C)
	{
		checksum_algorithm_ = lib_params->checksum_algorithm;
		gset_checksum = set_crc32_checksum;
		gvalidate_checksum = validate_crc32_checksum;
	}
	else if (lib_params->checksum_algorithm == MULP_CHECKSUM_ALGORITHM_MD5)
	{
		checksum_algorithm_ = lib_params->checksum_algorithm;
		gset_checksum = set_md5_checksum;
		gvalidate_checksum = validate_md5_checksum;
	}
	else
	{
		ret = MULP_PARAMETER_PROBLEM;
		ERRLOG(FALTAL_ERROR_EXIT, "mulp_set_lib_params()::no such checksum_algorithm!");
		return ret;
	}
	EVENTLOG6(VERBOSE,
		"mulp_set_lib_params():: \nsend_ootb_aborts %s,\nchecksum_algorithm %s,\nsupport_dynamic_addr_config %s,\nsupport_particial_reliability %s,\n"
		"delayed_ack_interval %d", (send_abort_for_oob_packet_ == true) ? "true" : "false",
		(checksum_algorithm_ == MULP_CHECKSUM_ALGORITHM_CRC32C) ? "CRC32C" : "MD5",
		(support_addip_ == true) ? "true" : "false", (support_pr_ == true) ? "true" : "false", delayed_ack_interval_,
		mtra_read_udp_local_bind_port());
	return MULP_SUCCESS;
}
int mulp_get_lib_params(lib_params_t *lib_params)
{
	EXIT_CHECK_LIBRARY;
	if (lib_params == NULL)
		return MULP_PARAMETER_PROBLEM;
	lib_params->send_ootb_aborts = send_abort_for_oob_packet_;
	lib_params->checksum_algorithm = checksum_algorithm_;
	lib_params->support_dynamic_addr_config = support_addip_;
	lib_params->support_particial_reliability = support_pr_;
	lib_params->delayed_ack_interval = delayed_ack_interval_;
	lib_params->udp_bind_port = mtra_read_udp_local_bind_port();
	EVENTLOG6(VERBOSE,
		"\nmulp_get_lib_params():: \nsend_ootb_aborts %s,\nchecksum_algorithm %s,\nsupport_dynamic_addr_config %s,\nsupport_particial_reliability %s,\n"
		"delayed_ack_interval %d,udp_bind_port %d\n", (send_abort_for_oob_packet_ == true) ? "true" : "false",
		(checksum_algorithm_ == MULP_CHECKSUM_ALGORITHM_CRC32C) ? "CRC32C" : "MD5",
		(support_addip_ == true) ? "true" : "false", (support_pr_ == true) ? "true" : "false", delayed_ack_interval_,
		mtra_read_udp_local_bind_port());
	return MULP_SUCCESS;
}
int mulp_set_connection_default_params(unsigned int instanceid, geco_instance_params_t* params)
{
	EXIT_CHECK_LIBRARY;
	if (params == NULL)
		return MULP_PARAMETER_PROBLEM;
	geco_instance_t* instance = geco_instances_[instanceid];
	instance->default_rtoInitial = params->rtoInitial;
	instance->default_rtoMin = params->rtoMin;
	instance->default_rtoMax = params->rtoMax;
	instance->default_validCookieLife = params->validCookieLife;
	instance->default_assocMaxRetransmits = params->assocMaxRetransmits;
	instance->default_pathMaxRetransmits = params->pathMaxRetransmits;
	instance->default_maxInitRetransmits = params->maxInitRetransmits;
	instance->default_myRwnd = params->myRwnd;
	instance->default_delay = params->delay;
	instance->default_ipTos = params->ipTos;
	instance->default_maxSendQueue = params->maxSendQueue;
	instance->default_maxRecvQueue = params->maxRecvQueue;
	instance->ordered_streams = params->ordered_streams;
	instance->sequenced_streams = params->sequenced_streams;
	return MULP_SUCCESS;
}
int mulp_get_connection_default_params(unsigned int instanceid, geco_instance_params_t* geco_instance_params)
{
	EXIT_CHECK_LIBRARY;
	if (geco_instance_params == NULL)
		return MULP_PARAMETER_PROBLEM;
	geco_instance_t* instance = geco_instances_[instanceid];
	unsigned int numOfAddresses = 0, count = 0;
	ushort port = 0;
	if (instance->local_addres_size > MAX_NUM_ADDRESSES)
		numOfAddresses = MAX_NUM_ADDRESSES;
	else
		numOfAddresses = instance->local_addres_size;
	if (numOfAddresses == 0)
	{
		geco_instance_params->noOfLocalAddresses = defaultlocaladdrlistsize_;
		for (count = 0; count < (uint)defaultlocaladdrlistsize_; count++)
		{
			saddr2str(&defaultlocaladdrlist_[count], (char*)geco_instance_params->localAddressList[count],
				MAX_IPADDR_STR_LEN, &port);
		}
	}
	else
	{
		geco_instance_params->noOfLocalAddresses = numOfAddresses;
		for (count = 0; count < numOfAddresses; count++)
		{
			saddr2str(&instance->local_addres_list[count], (char*)geco_instance_params->localAddressList[count],
				MAX_IPADDR_STR_LEN, &port);
		}
	}
	geco_instance_params->rtoInitial = instance->default_rtoInitial;
	geco_instance_params->rtoMin = instance->default_rtoMin;
	geco_instance_params->rtoMax = instance->default_rtoMax;
	geco_instance_params->validCookieLife = instance->default_validCookieLife;
	geco_instance_params->assocMaxRetransmits = instance->default_assocMaxRetransmits;
	geco_instance_params->pathMaxRetransmits = instance->default_pathMaxRetransmits;
	geco_instance_params->maxInitRetransmits = instance->default_maxInitRetransmits;
	geco_instance_params->myRwnd = instance->default_myRwnd;
	geco_instance_params->delay = instance->default_delay;
	geco_instance_params->ipTos = instance->default_ipTos;
	geco_instance_params->maxSendQueue = instance->default_maxSendQueue;
	geco_instance_params->maxRecvQueue = instance->default_maxRecvQueue;
	geco_instance_params->ordered_streams = instance->ordered_streams;
	geco_instance_params->sequenced_streams = instance->sequenced_streams;
	return MULP_SUCCESS;
}

int mulp_get_connection_params(unsigned int connectionid, connection_infos_t* status)
{
	EXIT_CHECK_LIBRARY;
	if (status == NULL)
		return MULP_PARAMETER_PROBLEM;
	int ret = MULP_SUCCESS;
	geco_instance_t* old_Instance = curr_geco_instance_;
	geco_channel_t* old_assoc = curr_channel_;
	curr_channel_ = channels_[connectionid];
	if (curr_channel_ != NULL)
	{
		curr_geco_instance_ = curr_channel_->geco_inst;
		status->state = curr_channel_->state_machine_control->channel_state;
		status->numberOfAddresses = curr_channel_->remote_addres_size;
		status->sourcePort = curr_channel_->local_port;
		status->destPort = curr_channel_->remote_port;
		status->primaryAddressIndex = mpath_read_primary_path();
		saddr2str(&curr_channel_->remote_addres[status->primaryAddressIndex], (char*)status->primaryDestinationAddress,
			MAX_IPADDR_STR_LEN,
			NULL);
		status->inStreams = mdlm_read_istreams();
		status->outStreams = mdlm_read_ostreams();
		status->currentReceiverWindowSize = mreltx_get_peer_rwnd();
		status->outstandingBytes = mfc_get_outstanding_bytes();
		status->noOfChunksInSendQueue = mfc_get_queued_chunks_count();
		status->noOfChunksInRetransmissionQueue = mreltx_get_unacked_chunks_count();
		status->noOfChunksInReceptionQueue = mdlm_read_queued_chunks();
		status->rtoInitial = mpath_get_rto_initial();
		status->rtoMin = mpath_get_rto_min();
		status->rtoMax = mpath_get_rto_max();
		status->pathMaxRetransmits = mpath_get_max_retrans_per_path();
		status->validCookieLife = msm_get_cookielife();
	}
	else
	{
		ret = MULP_ASSOC_NOT_FOUND;
		ERRLOG1(MAJOR_ERROR, "mulp_get_connection_params()::association %u does not exist!", connectionid);
	}
	curr_channel_ = old_assoc;
	curr_geco_instance_ = old_Instance;
	return ret;
}
int mulp_set_connection_params(unsigned int connectionid, connection_infos_t* new_status)
{
	EXIT_CHECK_LIBRARY;
	if (new_status == NULL)
		return MULP_PARAMETER_PROBLEM;
	ushort ret;
	geco_instance_t* old_Instance = curr_geco_instance_;
	geco_channel_t* old_assoc = curr_channel_;
	return MULP_SUCCESS;
}

