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
  */

#ifndef __INCLUDE_POLLER_H
#define __INCLUDE_POLLER_H

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cerrno>

#include "geco-net-common.h"
#include "geco-ds-timer.h"
#include "geco-net-dispatch.h"

  /**
   * Structure for callback events. The function "action" is called by the event-handler,
   * when an event occurs on the file-descriptor.
   */
struct event_handler_t
{
	int sfd;
	int eventcb_type;
	/* pointer to possible arguments, associations etc. */
	cbunion_t action;
	void* arg1, *arg2, *userData;
};
struct stdin_data_t
{
	typedef void(*stdin_cb_func_t)(char* in, size_t datalen);
	unsigned long len;
	char buffer[1024];
	stdin_cb_func_t stdin_cb_;
#ifdef _WIN32
	HANDLE event, eventback; // only used on win32 plateform
#endif
};

struct socket_despt_t
{
	int event_handler_index;
	int fd;
	int events;
	int revents;
	long revision;
#ifdef _WIN32
	HANDLE event; // only used on win32 plateform
	WSANETWORKEVENTS trigger_event;
#endif
};

struct test_dummy_t
{
	bool enable_stub_error_;

	// transport_layer::send_ip_packet()::sendto()
	bool enable_stub_sendto_in_tspt_sendippacket_;
	char* out_geco_packet_;
	int out_geco_packet_len_;
	int out_sfd_;
	sockaddrunion *out_dest;
	uchar out_tos_;
};

struct timer_mgr;
extern timer_mgr& mtra_read_timer();
extern int mtra_read_ip4rawsock();
extern int mtra_read_ip6rawsock();
extern int mtra_read_ip4udpsock();
extern int mtra_read_ip6udpsock();
extern int mtra_read_icmp_socket();
extern void mtra_zero_ip4rawsock();
extern void mtra_zero_ip6rawsock();
extern void mtra_zero_icmp_socket();

extern void mtra_write_udp_local_bind_port(ushort newport);
extern ushort mtra_read_udp_local_bind_port();

extern int mtra_init(int * myRwnd);
extern void mtra_destroy();

extern void mtra_set_expected_event_on_fd(int sfd, int eventcb_type, int event_mask, cbunion_t action, void* userData);
extern int mtra_remove_event_handler(int sfd);
// cb will be called each tick 10ms
extern void mtra_set_tick_task_cb(task_cb_fun_t taskcb, void* userdata);

//@pre  to->sin.sin_port MUST be assigned by caller with our well-knwon local port
extern int mtra_recv_udpsocks(int sfd, char *dest, int maxlen, sockaddrunion *from, sockaddrunion *to);
extern int mtra_recv_rawsocks(int sfd, char *dest, int maxlen, sockaddrunion *from, sockaddrunion *to);

extern int mtra_send_udpscoks(int sfd, char* buf, int length, sockaddrunion* destsu, uchar tos);
extern int mtra_send_rawsocks(int sfd, char *buf, int len, sockaddrunion *dest, uchar tos);

#endif
