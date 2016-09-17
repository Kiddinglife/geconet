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

/* the possible 7 states of an association */
enum ChannelState :int
{
	Closed,
	CookieWait,
	CookieEchoed,
	Connected,
	ShutdownPending,
	ShutdownReceived,
	ShutdownSent,
	ShutdownAckSent,
	ChannelStateSize
};

/* Return codes for a number of functions that treat incoming chunks */
/* these are used in  bundle controller !                         
/* stop -> stop processing not sending replying chunk */
enum ChunkProcessResult : int
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
enum ConnectionLostReason :int
{
	PeerAbortConnection,
	PeerUnreachable,
	exceed_max_retrans_count,
	no_tcb,
	invalid_param,
	unknown_param,
	/* maybe some others............. */
	ConnectionLostReasonSize // number od reasons 
};

#define SCTP_COMM_UP_RECEIVED_VALID_COOKIE       1
#define SCTP_COMM_UP_RECEIVED_COOKIE_ACK         2
#define SCTP_COMM_UP_RECEIVED_COOKIE_RESTART     3

#endif
