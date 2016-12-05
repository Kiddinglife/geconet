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
  * Created on 20 May 2016 by Jake Zhang
  * Reviewed on 07 May 2016 by Jakze Zhang
  */

#ifndef __INCLUDE_PROTOCOL_STACK_H
#define __INCLUDE_PROTOCOL_STACK_H

#include "geco-net-common.h"

  /* Here are some error codes that are returned by some functions         */
  /* this list may be enhanced or become more extensive in future releases */
#define MULP_SUCCESS                        0
#define MULP_LIBRARY_NOT_INITIALIZED        -1
#define MULP_INSTANCE_NOT_FOUND             -2
#define MULP_ASSOC_NOT_FOUND                -3
#define MULP_PARAMETER_PROBLEM              -4
#define MULP_MODULE_NOT_FOUND               -5
#define MULP_OUT_OF_RESOURCES               -6
#define MULP_NOT_SUPPORTED                  -7
#define MULP_INSUFFICIENT_PRIVILEGES        -8
#define MULP_LIBRARY_ALREADY_INITIALIZED    -9
#define MULP_UNSPECIFIED_ERROR              -10
#define MULP_QUEUE_EXCEEDED                 -11
#define MULP_WRONG_ADDRESS                  -12
#define MULP_WRONG_STATE                    -13
#define MULP_BUFFER_TOO_SMALL               -14
#define MULP_NO_CHUNKS_IN_QUEUE             -15
#define MULP_INSTANCE_IN_USE                -16
#define MULP_SPECIFIC_FUNCTION_ERROR        1

/* the possible 7 states of an association */
enum ChannelState
{
	Closed,
	CookieWait,
	CookieEchoed,
	Connected,
	ShutdownPending,
	ShutdownReceived,
	ShutdownSent,
	ShutdownAckSent,
	ChannelStateSize,
	UnknownChannelState,
};

/* Return codes for a number of functions that treat incoming chunks */
/* these are used in  bundle controller !
 /* stop -> stop processing not sending replying chunk */
enum ChunkProcessResult
	: int
{
	Good,
	Stop,
	SKIP_PROCESS_PARAM_REPORT_ERROR,
	SKIP_PROCESS_PARAM,
	StopProcessForUnrecognizedParamError,
	StopProcessForNewAddrAddedError,
	StopProcessAndDeleteChannel,
	StopAndDeleteChannel_LastSrcPortNullError,
	StopAndDeleteChannel_ValidateInitParamFailedError,
	ChunkProcessResultSize
};

/* for COMMUNICATION LOST or COMMUNICATION UP callbacks */
enum ConnectionLostReason
	:int
{
	PeerAbortConnection,
	PeerUnreachable,
	exceed_max_retrans_count,
	no_tcb,
	invalid_param,
	unknown_param,
	/* maybe some others............. */
	ConnectionLostReasonSize  // number od reasons
};

const uint COMM_UP_RECEIVED_VALID_COOKIE = 1;
const uint COMM_UP_RECEIVED_COOKIE_ACK = 2;
const uint COMM_UP_RECEIVED_COOKIE_RESTART = 3;
const uint MULP_CHECKSUM_ALGORITHM_MD5 = 1;
const uint MULP_CHECKSUM_ALGORITHM_CRC32C = 2;

/**
 * This struct contains parameters that may be set globally with
 * mulp_setLibraryParams(). For now, it only contains one flag.
 */
struct lib_params_t
{
	/*
	 * flag that controls whether an implementation will send
	 * ABORT chunks for OOTB mulp packets, or whether it will
	 * silently discard these. In the later case, you will be
	 * able to run the implementation twice on one machine, without
	 * the two interfering with each other (also for tests on localhost)
	 * By default, this variable is set to TRUE (==1)
	 * Allowed values are 0 (==FALSE) or 1, else function will fail !!
	 */
	bool send_ootb_aborts;
	/*
	 * This allows for globally setting the used checksum algorithm
	 * may be either
	 * - MULP_CHECKSUM_ALGORITHM_MD5 (1,default)
	 * - MULP_CHECKSUM_ALGORITHM_CRC32C (2)
	 */
	int checksum_algorithm;
	bool support_particial_reliability; /* does the assoc support unreliable transfer*/
	bool support_dynamic_addr_config; /* does the assoc support adding/deleting IP addresses*/
	uint delayed_ack_interval;
	ushort udp_bind_port; /*the well knwon local binding port for udp-based stack*/
};

/**
 * This struct contains some parameters that may be set or
 * got with the mulp_getAssocDefaults()/mulp_setAssocDefaults()
 * functions. So these may also be specified/retrieved for
 * servers, before an association is established !
 */
struct geco_instance_params_t
{
	/* @{ */
	/* this is read-only (get) */
	unsigned int noOfLocalAddresses;
	/* this is read-only (get) */
	unsigned char localAddressList[32][MAX_IPADDR_STR_LEN];
	/* the initial round trip timeout */
	unsigned int rtoInitial;
	/* the minimum timeout value */
	unsigned int rtoMin;
	/* the maximum timeout value */
	unsigned int rtoMax;
	/* the lifetime of a cookie */
	unsigned int validCookieLife;
	/*  (get/set) */
	unsigned short outStreams;
	/*  (get/set) */
	unsigned short inStreams;
	/* does the assoc support unreliable transfer*/
	bool support_particial_reliability;
	/* does the assoc support adding/deleting IP addresses*/
	bool support_dynamic_addr_config;
	/* maximum retransmissions per association */
	unsigned int assocMaxRetransmits;
	/* maximum retransmissions per path */
	unsigned int pathMaxRetransmits;
	/* maximum initial retransmissions */
	unsigned int maxInitRetransmits;
	/* from recvcontrol : my receiver window */
	unsigned int myRwnd;
	/* recvcontrol: delay for delayed ACK in msecs */
	unsigned int delay;
	/* per instance: for the IP type of service field. */
	unsigned char ipTos;
	/* limit the number of chunks queued in the send queue */
	unsigned int maxSendQueue;
	/* currently unused, may limit the number of chunks queued in the receive queue later.
	 *  Is this really needed ? The protocol limits the receive queue with
	 *  window advertisement of arwnd==0  */
	unsigned int maxRecvQueue;
	/*
	 * maximum number of connections we want. Is this limit greater than 0,
	 * implementation will automatically send ABORTs to incoming INITs, when
	 * there are that many associations !
	 */
	unsigned int maxNumberOfAssociations;
	/* @} */
};

/**
 * this struct contains path specific parameters, so these
 * values can only be retrieved/set, when the association
 * already exists !
 */
struct path_infos_t
{
	/* @{ */
	/**   */
	unsigned char destinationAddress[MAX_IPADDR_STR_LEN];
	/**  mulp_PATH_ACTIVE  0, mulp_PATH_INACTIVE   1    */
	short state;
	/** smoothed round trip time in msecs */
	unsigned int srtt;
	/** current rto value in msecs */
	unsigned int rto;
	/** round trip time variation, in msecs */
	unsigned int rttvar;
	/** defines the rate at which heartbeats are sent */
	unsigned int heartbeatIntervall;
	/**  congestion window size (flowcontrol) */
	unsigned int cwnd;
	/**  congestion window size 2 (flowcontrol) */
	unsigned int cwnd2;
	/**  Partial Bytes Acked (flowcontrol) */
	unsigned int partialBytesAcked;
	/**  Slow Start Threshold (flowcontrol) */
	unsigned int ssthresh;
	/**  from flow control */
	unsigned int outstandingBytesPerAddress;
	/**  Current MTU (flowcontrol) */
	unsigned int mtu;
	/** per path ? per instance ? for the IP type of service field. */
	unsigned char ipTos;
	/* @} */
};

/**
 *  This struct contains the data to be returned to the ULP with the
 *  mulp_getAssocStatus() function primitive. It is marked whether data
 *  may only be retrieved using the  mulp_getAssocStatus() function, or
 *  also set using the  mulp_setAssocStatus() function.
 */
struct connection_infos_t
{
	/* @{ */
	/** (get)  */
	unsigned short state;
	/**  (get) */
	unsigned short numberOfAddresses;
	/**  (get) */
	unsigned char primaryDestinationAddress[MAX_IPADDR_STR_LEN];
	/**  (get) */
	unsigned short sourcePort;
	/**  (get) */
	unsigned short destPort;
	/**  (get) */
	unsigned short outStreams;
	/**  (get) */
	unsigned short inStreams;
	/** does the assoc support unreliable streams  no==0, yes==1 */
	unsigned int supportUnreliableStreams;
	/** does the assoc support adding/deleting IP addresses no==0, yes==1 */
	unsigned int supportADDIP;
	/**  (get/set) */
	unsigned short primaryAddressIndex;
	/**  (get) */
	unsigned int currentReceiverWindowSize;
	/**  (get) */
	unsigned int outstandingBytes;
	/**  (get) */
	unsigned int noOfChunksInSendQueue;
	/**  (get) */
	unsigned int noOfChunksInRetransmissionQueue;
	/**  (get) */
	unsigned int noOfChunksInReceptionQueue;
	/** (get/set) the initial round trip timeout */
	unsigned int rtoInitial;
	/** (get/set) the minimum RTO timeout */
	unsigned int rtoMin;
	/** (get/set) the maximum RTO timeout */
	unsigned int rtoMax;
	/** (get/set) the lifetime of a cookie */
	unsigned int validCookieLife;
	/** (get/set) maximum retransmissions per association */
	unsigned int assocMaxRetransmits;
	/** (get/set) maximum retransmissions per path */
	unsigned int pathMaxRetransmits;
	/** (get/set) maximum initial retransmissions */
	unsigned int maxInitRetransmits;
	/** (get/set) from recvcontrol : my receiver window */
	unsigned int myRwnd;
	/** (get/set) recvcontrol: delay for delayed ACK in msecs */
	unsigned int delay;
	/** (get/set) per instance: for the IP type of service field. */
	unsigned char ipTos;
	/**  limit the number of chunks queued in the send queue */
	unsigned int maxSendQueue;
	/** currently unused, may limit the number of chunks queued in the receive queue later.
	 *  Is this really needed ? The protocol limits the receive queue with
	 *  window advertisement of arwnd==0  */
	unsigned int maxRecvQueue;
	/* @} */
};

/**
 This struct containes the pointers to ULP callback functions.
 Each mulp-instance can have its own set of callback functions.
 The callback functions of each mulp-instance can be found by
 first reading the datastruct of an association from the list of
 associations. The datastruct of the association contains the name
 of the mulp instance to which it belongs. With the name of the mulp-
 instance its datastruct can be read from the list of mulp-instances.
 */
struct ulp_cbs_t
{
	/* @{ */
	/**
	 * indicates that new data arrived from peer (chapter 10.2.A).
	 *  @param 1 connectionid
	 *  @param 2 streamID
	 *  @param 3 length of data
	 *  @param 4 stream sequence number
	 *  @param 5 tsn of (at least one) chunk belonging to the message
	 *  @param 6 protocol ID
	 *  @param 7 unordered flag (TRUE==1==unordered, FALSE==0==normal, numbered chunk)
	 *  @param 8 pointer to ULP data
	 */
	void(*dataArriveNotif)(unsigned int, unsigned short, unsigned int, unsigned short,
		unsigned int, unsigned int, unsigned int, void*);
	/**
	 * indicates a send failure (chapter 10.2.B).
	 *  @param 1 connectionid
	 *  @param 2 pointer to data not sent
	 *  @param 3 dataLength
	 *  @param 4 pointer to context from sendChunk
	 *  @param 5 pointer to ULP data
	 */
	void(*sendFailureNotif)(unsigned int, unsigned char *, unsigned int, unsigned int *,
		void*);
	/**
	 * indicates a change of network status (chapter 10.2.C).
	 *  @param 1 connectionid
	 *  @param 2 destinationAddresses
	 *  @param 3 newState
	 *  @param 4 pointer to ULP data
	 */
	void(*networkStatusChangeNotif)(unsigned int, short, unsigned short, void*);
	/**
	 * indicates that a association is established (chapter 10.2.D).
	 *  @param 1 connectionid
	 *  @param 2 status, type of event
	 *  @param 3 number of destination addresses
	 *  @param 4 number input streamns
	 *  @param 5 number output streams
	 *  @param 6 int  supportPRmulp (0=FALSE, 1=TRUE)
	 *  @param 7 pointer to ULP data, usually NULL
	 *  @return the callback is to return a pointer, that will be transparently returned with every callback
	 */
	void* (*communicationUpNotif)(unsigned int, int, unsigned int, unsigned short,
		unsigned short, int, void*);
	/**
	 * indicates that communication was lost to peer (chapter 10.2.E).
	 *  @param 1 connectionid
	 *  @param 2 status, type of event
	 *  @param 3 pointer to ULP data
	 */
	void(*communicationLostNotif)(unsigned int, unsigned short, void*);
	/**
	 * indicates that communication had an error. (chapter 10.2.F)
	 * Currently not implemented !?
	 *  @param 1 connectionid
	 *  @param 2 status, type of error
	 *  @param 3 pointer to ULP data
	 */
	void(*communicationErrorNotif)(unsigned int, unsigned short, void*);
	/**
	 * indicates that a RESTART has occurred. (chapter 10.2.G)
	 *  @param 1 connectionid
	 *  @param 2 pointer to ULP data
	 */
	void(*restartNotif)(unsigned int, void*);
	/**
	 * indicates that a SHUTDOWN has been received by the peer. Tells the
	 * application to stop sending new data.
	 *  @param 0 instanceID
	 *  @param 1 connectionid
	 *  @param 2 pointer to ULP data
	 */
	void(*peerShutdownReceivedNotif)(unsigned int, void*);
	/**
	 * indicates that a SHUTDOWN has been COMPLETED. (chapter 10.2.H)
	 *  @param 0 instanceID
	 *  @param 1 connectionid
	 *  @param 2 pointer to ULP data
	 */
	void(*shutdownCompleteNotif)(unsigned int, void*);
	/**
	 * indicates that a queue length has exceeded (or length has dropped
	 * below) a previously determined limit
	 *  @param 0 connectionid
	 *  @param 1 queue type (in-queue, out-queue, stream queue etc.)
	 *  @param 2 queue identifier (maybe for streams ? 0 if not used)
	 *  @param 3 queue length (either bytes or messages - depending on type)
	 *  @param 4 pointer to ULP data
	 */
	void(*queueStatusChangeNotif)(unsigned int, int, int, int, void*);
	/**
	 * indicates that a ASCONF request from the ULP has succeeded or failed.
	 *  @param 0 connectionid
	 *  @param 1 correlation ID
	 *  @param 2 result (int, negative for error)
	 *  @param 3 pointer to a temporary, request specific structure (NULL if not needed)
	 *  @param 4 pointer to ULP data
	 */
	void(*asconfStatusNotif)(unsigned int, unsigned int, int, void*, void*);
	/* @} */
};

/**
 * Function that needs to be called in advance to all library calls.
 * It initializes all file descriptors etc. and sets up some variables
 * @return 0 for success, 1 for adaptation level error, -1 if already called
 * (i.e. the function has already been called before), -2 for insufficient rights
 * (you need root-rights to open RAW sockets !).
 */
int initialize_library(void);
void free_library(void);

/**
 *  sctp_registerInstance is called to initialize one SCTP-instance.
 *  Each Adaption-Layer of the ULP must create its own SCTP-instance, and
 *  define and register appropriate callback functions.
 *  An SCTP-instance may define an own port, or zero here ! Servers and clients
 *  that care for their source port must chose a port, clients that do not really
 *  care which source port they use, chose ZERO, and have the implementation chose
 *  a free source port.
 *
 *  @param port                   wellknown port of this sctp-instance
 *  @param noOfLocalAddresses     number of local addresses
 *  @param localAddressList       local address list (pointer to a string-array)
 *  @param ULPcallbackFunctions   call back functions for primitives passed from sctp to ULP
 *  @return     instance id  otherwise  fatal error exit
 */
int mulp_new_geco_instance(unsigned short localPort,
	unsigned short noOfInStreams,
	unsigned short noOfOutStreams,
	unsigned int noOfLocalAddresses,
	unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN],
	ulp_cbs_t ULPcallbackFunctions);

// success returns MULP_SUCCESS 
// error returns MULP_INSTANCE_NOT_FOUND MULP_INSTANCE_IN_USE
int mulp_delete_geco_instance(int instance_name);

/**
 * This function is called to setup an association.
 *  The ULP must specify the instance id to which this association belongs to.
 *  @param instanceid     the instance this association belongs to.
 *  if the local port of this SCTP instance is zero, we will get a port num,
 *  else we will use the one from the SCTP instance !
 *  @param noOfOutStreams        number of output streams the ULP would like to have
 *  @param destinationAddress    destination address
 *  @param destinationPort       destination port
 *  @param ulp_data             pointer to an ULP data structure, will be passed with callbacks !
 *  @return connection ID, 0 in case of failures
 */
int mulp_connect(unsigned int instanceid,
	unsigned short noOfOutStreams,
	char destinationAddress[MAX_IPADDR_STR_LEN],
	unsigned short destinationPort,
	void* ulp_data);
int mulp_connectx(unsigned int instanceid,
	unsigned short noOfOutStreams,
	char destinationAddresses[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN],
	unsigned int noOfDestinationAddresses,
	unsigned int maxSimultaneousInits,
	unsigned short destinationPort,
	void* ulp_data);

int mulp_shutdown(unsigned int connectionid);
int mulp_abort(unsigned int connectionid);

/*----------------------------------------------------------------------------------------------*/
/*  These are the new function for getting/setting parameters per instance, association or path */
/*----------------------------------------------------------------------------------------------*/
int mulp_set_lib_params(lib_params_t *lib_params);
int mulp_get_lib_params(lib_params_t *lib_params);
int mulp_set_connection_default_params(unsigned int instanceid,
	geco_instance_params_t* geco_instance_params);
int mulp_get_connection_default_params(unsigned int instanceid,
	geco_instance_params_t* geco_instance_params);
int mulp_get_connection_params(unsigned int connectionid, connection_infos_t* status);
int mulp_set_connection_params(unsigned int connectionid, connection_infos_t* new_status);
int mulp_get_path_params(unsigned int connectionid, short path_id, path_infos_t* status);
int mulp_set_path_params(unsigned int connectionid, short path_id, path_infos_t *new_status);
/*----------------------------------------------------------------------------------------------*/
#endif
