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
enum channel_state_t
{
    closed,
    cookie_wait,
    cookie_echoed,
    connected,
    shutdown_pending,
    shutdown_received,
    shutdown_sent,
    shutdown_ack_sent,
    unknown,
};

/* Return codes for a number of functions that treat incoming chunks */
/* these are used in  bundle controller !                          */
enum chunk_process_result_t
{
    ok,
    stop,
    delete_channel_for_invalid_param,
    aborted,
    peer_endpoint_unreachable,
    exceed_max_retrans_count,
    no_tcb,
    invalid_param,
};

/* for COMMUNICATION LOST or COMMUNICATION UP callbacks */
enum connection_lost_reason_t
{
    aborted,
    peer_endpoint_unreachable,
    exceed_max_retrans_count,
    no_tcb,
    invalid_param,
    unknown_param,
    /* maybe some others............. */
    reason_count, // number od reasons 
};

enum geco_lib_error_t
{
    module_not_found,
    invalid_param,
};
#define SCTP_COMM_UP_RECEIVED_VALID_COOKIE       1
#define SCTP_COMM_UP_RECEIVED_COOKIE_ACK         2
#define SCTP_COMM_UP_RECEIVED_COOKIE_RESTART     3

#endif