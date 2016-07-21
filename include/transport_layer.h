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

#ifndef _WIN32
#include <sys/time.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include <arpa/inet.h>      /* for inet_ntoa() under both SOLARIS/LINUX */
#include <sys/errno.h>
#include <sys/uio.h>        /* for struct iovec */
#include <sys/param.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <net/if.h>
#ifdef USE_UDP
#include <netinet/udp.h>
#endif
#include <asm/types.h>
#include <linux/rtnetlink.h>
#else
#include <winsock2.h>
#include <WS2tcpip.h>
#include <Netioapi.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <sys/timeb.h>
#endif

#if defined (__linux__)
#include <asm/types.h>
#include <linux/rtnetlink.h>
#else /* this may not be okay for SOLARIS !!! */
#ifndef _WIN32
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#ifndef __sun
#include <net/if_var.h>
#include <machine/param.h>
#else
#include <sys/sockio.h>
#endif
#endif
#endif

#define MAX_COUNT_LOCAL_IP_ADDR 8

#if defined( __linux__) || defined(__unix__)
#include <sys/poll.h>
#else
#define POLLIN     0x001 //2base    0001
#define POLLPRI    0x002 //2base    0010
#define POLLOUT    0x004 //2base  0100
#define POLLERR    0x008//2base    1000
#endif

#define IFA_BUFFER_LENGTH   1024
#define POLL_FD_UNUSED     -1
#define MAX_FD_SIZE     32
#define    EVENTCB_TYPE_SCTP       1
#define    EVENTCB_TYPE_UDP        2
#define    EVENTCB_TYPE_USER       3
#define    EVENTCB_TYPE_ROUTING    4
#define    EVENTCB_TYPE_STDIN          5

#define GECO_CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )
#define GECO_CMSG_SPACE(len) \
(GECO_CMSG_ALIGN(sizeof(struct cmsghdr)) + GECO_CMSG_ALIGN(len))
#define GECO_CMSG_LEN(len) (GECO_CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#define GECO_CMSG_DATA(cmsg) \
((unsigned char*)(cmsg)+GECO_CMSG_ALIGN(sizeof(struct cmsghdr)))


#include "globals.h"
#ifndef _WIN32
#define LINUX_PROC_IPV6_FILE "/proc/net/if_inet6"
#else
#define ADDRESS_LIST_BUFFER_SIZE        4096
//#define IFNAMSIZ 64   /* Windows has no IFNAMSIZ. Just define it. */
#define IFNAMSIZ IF_NAMESIZE
struct iphdr
{
    uchar version_length;
    uchar typeofservice; /* type of service */
    ushort length; /* total length */
    ushort identification; /* identification */
    ushort fragment_offset; /* fragment offset field */
    uchar ttl; /* time to live */
    uchar protocol; /* protocol */
    ushort checksum; /* checksum */
    struct in_addr src_addr; /* source and dest address */
    struct in_addr dst_addr;
};

#define msghdr _WSAMSG
#define iovec _WSABUF 
#endif

#ifndef _WIN32
//#define USES_BSD_4_4_SOCKET
#ifndef __sun
#define ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))
#define NEXT_SA(ap) \
ap = (struct sockaddr *)((caddr_t) ap + (ap->sa_len ? \
ROUNDUP(ap->sa_len, sizeof (u_long)) : sizeof(u_long)))
#else
#define NEXT_SA(ap) ap = (struct sockaddr *) ((caddr_t) ap + sizeof(struct sockaddr))
#define RTAX_MAX RTA_NUMBITS
#define RTAX_IFA 5
#define _NO_SIOCGIFMTU_
#endif
#endif

/* Defines the callback function that is called when an event occurs
on an internal GECO or UDP socket
Params: 1. file-descriptor of the socket
2. pointer to the datagram data, if any was received
3. length of datagram data, if any was received
4. source Address  (as string, may be IPv4 or IPv6 address string, in numerical format)
5. source port number for UDP sockets, 0 for SCTP raw sockets
*/
typedef void(*socket_cb_fun_t)(int sfd, char* data, int datalen,
    const char* addr, ushort port);

/* Defines the callback function that is called when an event occurs
on a user file-descriptor
Params: 1. file-descriptor
Params: 2. received events mask
Params: 3. pointer to registered events mask.
It may be changed by the callback function.
Params: 4. user data
*/
typedef void(*user_cb_fun_t)(int, short int revents, int* settled_events, void* usrdata);


union cbunion_t
{
    socket_cb_fun_t socket_cb_fun;
    user_cb_fun_t user_cb_fun;
};

/**
* Structure for callback events. The function "action" is called by the event-handler,
* when an event occurs on the file-descriptor.
*/
struct event_handler_t
{
    //int used;
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

#include "gecotimer.h"
#include "dispatch_layer.h"
struct network_interface_t;

struct reactor_t
{
#ifdef _WIN32
    HANDLE win32events_[MAX_FD_SIZE];
#endif
    event_handler_t event_callbacks[MAX_FD_SIZE];
    //int num_of_triggered_events;
    socket_despt_t socket_despts[MAX_FD_SIZE];
    int socket_despts_size_;
    int revision_;

    stdin_data_t stdin_input_data_;

    timer_mgr timer_mgr_;
    timer_id_t curr_timer_id_;

    network_interface_t* nit_ptr_;
    char* internal_udp_buffer_;
    char* internal_dctp_buffer;

    sockaddrunion src, dest;
    socklen_t src_addr_len_;
    int recvlen_;
    ushort portnum_;
    char src_address[MAX_IPADDR_STR_LEN];
    iphdr* iph;
    int iphdrlen;

    dispatch_layer_t dispatch_layer_;
    cbunion_t cbunion_;

    reactor_t()
    {
        internal_udp_buffer_ = (char*)malloc(USE_UDP_BUFSZ);
        internal_dctp_buffer = (char*)malloc(MAX_MTU_SIZE + 20);
        socket_despts_size_ = 0;
        revision_ = 0;
        src_addr_len_ = sizeof(src);
        recvlen_ = 0;
        portnum_ = 0;

        /*initializes the array of win32_fds_ we want to use for listening to events
        POLL_FD_UNUSED to differentiate between used/unused win32_fds_ !*/
        for (int i = 0; i < MAX_FD_SIZE; i++)
        {
            set_expected_event_on_fd_(i, POLL_FD_UNUSED, 0); // init geco socket despts 
        }
    }

    ~reactor_t()
    {
        free(internal_udp_buffer_);
        free(internal_dctp_buffer);
    }
    /**
     * poll_socket_despts()
     * An extended poll() implementation based on select()
     *
     * During the select() call, another thread may change the FD list,
     * a revision number keeps track that results are only reported
     * when the FD has already been registered before select() has
     * been called. Otherwise, the event will be reported during the
     * next select() call.
     * This solves the following problem:
     * - Thread #1 registers user callback for socket n
     * - Thread #2 starts select()
     * - A read event on socket n occurs
     * - poll_socket_despts() returns
     * - Thread #2 sends a notification (e.g. using pthread_condition) to thread #1
     * - Thread #2 again starts select()
     * - Since Thread #1 has not yet read the data, there is a read event again
     * - Now, the thread scheduler selects the next thread
     * - Thread #1 now gets CPU time, deregisters the callback for socket n
     *      and completely reads the incoming data. There is no more data to read!
     * - Thread #1 again registers user callback for socket n
     * - Now, thread #2 gets the CPU again and can send a notification
     *      about the assumed incoming data to thread #1
     * - Thread #1 gets the read notification and tries to read. There is no
     *      data, so the socket blocks (possibily forever!) or the read call
     *      fails.
     *      0 timer timeouts >0 event number
     */
    int poll_fds(socket_despt_t* despts, int* count, int timeout,
        void(*lock)(void* data), void(*unlock)(void* data), void* data);

    /**
     * function calls the respective callback funtion, that is to be executed as a timer
     * event, passing it two arguments
     * -1 no timers, 0 timeouts, >0 interval before next timeouts
     */
    int poll_timers();

    /**
     * this function is responsible for calling the callback functions belonging
     * to all of the file descriptors that have indicated an event !
     * todo : check handling of POLLERR situation
     * @param num_of_events  number of events indicated by poll()
     */
    void fire_event(int num_of_events);

    /**
     *  function to check for events on all poll fds (i.e. open sockets),
     *  or else execute the next timer event.
     *  Executed timer events are removed from the list.
     *  Wrapper to poll() -- returns after timeout or read event
     *  @return  number of events that where seen on the socket fds,
     *  0 for timer event, -1 for error
     */
    int poll(void(*lock)(void* data) = 0, void(*unlock)(void* data) = 0, void* data = 0);

    //! function to set an event mask to a certain socket despt
    void set_expected_event_on_fd_(int fd_index, int sfd, int event_mask);

    /**
     * function to register a file descriptor, that gets activated for certain read/write events
     * when these occur, the specified callback funtion is activated and passed the parameters
     * that are pointed to by the event_callback struct
     * when this method failed, will exit() directly
     * no no need to check ret val so no ret value given
     */
    void set_expected_event_on_fd(int sfd, int eventcb_type, int event_mask,
        cbunion_t action, void* userData);

    /**
     *    function to close a bound socket from our list of socket descriptors
     *    @return  >= 0 number of closed fds or eh , if close socket error will abort program
     */
    int remove_event_handler(int sfd);

    /**
     * remove a sfd from the poll_list, and shift that list to the left
     * @return number of sfd's removed...
     * use socket_despt_size as insert index
     */
    int remove_socket_despt(int sfd);

    void add_stdin_cb(stdin_data_t::stdin_cb_func_t stdincb);
    int remove_stdin_cb();

    void debug_print_events()
    {
        for (int i = 0; i < MAX_FD_SIZE; i++)
        {
            if (socket_despts[i].fd > 0)
            {

                EVENTLOG7(VERBOSE,
                    "{event_handler_index:%d {sfd:%d, etype:%d}\nsocket_despts[i].events : %d\nsocket_despts[i].fd, %d\nsocket_despts[i].revents %d\nsocket_despts[i].revision: %d\n}",
                    socket_despts[i].event_handler_index,
                    event_callbacks[socket_despts[i].event_handler_index].sfd,
                    event_callbacks[socket_despts[i].event_handler_index].eventcb_type,
                    socket_despts[i].events, socket_despts[i].fd,
                    socket_despts[i].revents, socket_despts[i].revision);
            }
        }
    }
};

struct network_interface_t
{
    int ip4_socket_despt_; /* socket fd for standard SCTP port....      */
    int ip6_socket_despt_; /* socket fd for standard SCTP port....      */
    int icmp_socket_despt_; /* socket fd for ICMP messages */

    bool use_udp_; /* enable udp-based-impl */
#ifdef USE_UDP
    udp_packet_fixed_t* udp_hdr_ptr_;
#endif

    int dummy_ipv4_udp_despt_;
    int dummy_ipv6_udp_despt_;

    /* counter for stats we should have more counters !  */
    uint stat_send_event_size_;
    uint stat_recv_event_size_;
    uint stat_recv_bytes_;
    uint stat_send_bytes_;

    reactor_t poller_;
    cbunion_t cbunion_;

    network_interface_t()
    {
        ip4_socket_despt_ = -1;
        ip6_socket_despt_ = -1;
        icmp_socket_despt_ = -1;

        use_udp_ = false;
        dummy_ipv4_udp_despt_ = -1;
        dummy_ipv6_udp_despt_ = -1;

#ifdef USE_UDP
        udp_hdr_ptr_ = 0;
#endif

        stat_send_event_size_ = 0;
        stat_recv_event_size_ = 0;
        stat_recv_bytes_ = 0;
        stat_send_bytes_ = 0;
        poller_.nit_ptr_ = this;
        poller_.dispatch_layer_.transport_layer_ = this;
    }

    ~network_interface_t()
    {
#ifdef _WIN32
        WSACleanup();
#endif
    }

    /**
     * this function is supposed to register a callback function for catching
     * input from the Unix STDIN file descriptor. We expect this to be useful
     * in test programs mainly, so it is provided here for convenience.
     * @param  scf  callback funtion that is called (when return is hit)
     */
    void add_user_cb(int fd, user_cb_fun_t cbfun, void* userData,
        short int eventMask);
    /**
     * @return return the number of fds removed
     */
    int remove_user_cb(int fd)
    {
        return poller_.remove_event_handler(fd);
    }
    /**
     * this function is supposed to open and bind a UDP socket listening on a port
     * to incoming udp_packet_fixed pakets on a local interface (a local union sockaddrunion address)
     * @param  me   pointer to a local address, that will trigger callback, if it receives UDP data
     * @param  scf  callback funtion that is called when data has arrived
     * @return new UDP socket file descriptor, or -1 if error ocurred
     */
    int add_udpsock_ulpcb(const char* addr, ushort my_port,
        socket_cb_fun_t scb);

    /**
     * @return return the number of fds removed
     */
    int remove_udpsock_ulpcb(int udp_sfd)
    {
        if (udp_sfd <= 0)
            return -1;
        if (udp_sfd == ip4_socket_despt_)
            return -1;
        if (udp_sfd == ip6_socket_despt_)
            return -1;
        return poller_.remove_event_handler(udp_sfd);
    }
    /**
     * This function binds a local socket for incoming requests
     * @return socket file descriptor for the newly opened and bound socket
     * @param address (local) port to bind to
     *  rwnd is in and out param the default value is 10*0xffff
     *  will use this value to set recv buffer of socket,
     */
    int open_ipproto_geco_socket(int af, int* rwnd = NULL);

    /**
     * if used in registerudpcb()
     * This function creates a UDP socket bound to localhost, for asynchronous
     * interprocess communication with an Upper Layer process.
     * wILL be binded to specific adrress and port
     * @return the socket file descriptor. Used to register a callback function
     *
     * if used in init(), it is dummy udp socketbinding on anyadress with
     * USED_UDP_PORT,
     * return sfd
     */
    int open_ipproto_udp_socket(sockaddrunion* me, int* rwnd = NULL);

    /* @retval -1 error, >0 the settled new recv buffer size */
    int set_sockdespt_recvbuffer_size(int sfd, int new_size);

    /**
     * this function initializes the data of this module.
     * opens raw sockets for capturing geco packets,
     * opens ICMP sockets, so we can get ICMP events,e.g.  for Path-MTU discovery !
     * if USE_UDP defined, open udp socket with specified port
     * on dummy sadress 0.0.0.0
     */
    // ???????????????  // do we really need this USE_USP in the init() at line 696
    int init(int * myRwnd, bool ip4);

    /**
     * function to be called when we get a message from a peer sctp instance in the poll loop
     * @param  sfd the socket file descriptor where data can be read...
     * @param  buf pointer to a buffer, where we data is stored
     * @param  len number of bytes to be sent, including the iphdr header !
     * @param  address, where data goes from
     * @param    dest_len size of the address
     * @return returns number of bytes actually sent, or error
     */
    int send_udp_packet(int sfd, char* buf, int length, sockaddrunion* destsu);

    /**
     * function to be called when library sends a message on an SCTP socket
     * @param  sfd the socket file descriptor where data will be sent
     * @param  buf pointer to a buffer, where data to be sent is stored
     * @param  len number of bytes to be sent
     * it is len of geco packet (udp hdr(MAYBE 0 length) + geco hdr + chunks) ,
     * @param  destination address, where data is to be sent
     * @param    dest_len size of the address
     * @return returns number of bytes actually sent, or error
     */
    int send_ip_packet(int sfd, char *buf, int len, sockaddrunion *dest,
        uchar tos);

    /**
     * function to be called when we get an sctp message. This function gives also
     * the source and destination addresses.
     *
     * @param  sfd      the socket file descriptor where data can be read...
     * @param  dest     pointer to a buffer, where we can store the received data
     * @param  maxlen   maximum number of bytes that can be received with call
     * @param  from     address, where we got the data from
     * @param  to       destination address of that message
     * @return returns number of bytes received with this call
     */
    int recv_ip_packet(int sfd, char *dest, int maxlen, sockaddrunion *from,
        sockaddrunion *to);

    /**
     * function to be called when we get a message from a peer sctp instance in the poll loop
     * @param  sfd the socket file descriptor where data can be read...
     * @param  dest pointer to a buffer, where we can store the received data
     * @param  maxlen maximum number of bytes that can be received with call
     * @param  address, where we got the data from
     * @param    from_len size of the address
     * @return returns number of bytes received with this call
     */
    int recv_udp_packet(int sfd, char *dest, int maxlen, sockaddrunion *from,
        socklen_t *from_len);

    timer_id_t start_timer(uint milliseconds, timer::Action timercb, int ttype,
        void *param1, void *param2)
    {
        return this->poller_.timer_mgr_.add_timer(ttype, milliseconds, timercb, param1, param2);
    }

    /**
    *      This function adds a callback that is to be called some time from now. It realizes
    *      the timer (in an ordered list).
    *      @param      tid        timer-id of timer to be removed
    *      @return     returns 0 on success, 1 if tid not in the list, -1 on error
    *      @author     ajung
    */
    void stop_timer(timer_id_t& tid)
    {
        if (tid != poller_.curr_timer_id_)
            this->poller_.timer_mgr_.delete_timer(tid);
    }

    /**
    *      Restarts a timer currently running
    *      @param      timer_id   the value returned by set_timer for a certain timer
    *      @param      milliseconds  action is to be started in milliseconds ms from now
    *      @return     new timer id , -1 when there is an error (i.e. no timer) 0 success
    */
    int restart_timer(timer_id_t& tid, unsigned int milliseconds)
    {
        return this->poller_.timer_mgr_.reset_timer(tid, milliseconds);
    }

    /**
    * An address filtering function
    * @param newAddress  a pointer to a sockaddrunion address
    * @param flags       bit mask hiding (i.e. filtering) address classes
    * returns true if address is not filtered, else FALSE if address is filtered by mask
    */
    bool get_local_addresses(union sockaddrunion **addresses,
        int *numberOfNets,
        int sctp_fd,
        bool with_ipv6,
        int *max_mtu,
        const IPAddrType  flags);
    int  get_local_ip_addresses(sockaddrunion addresses[MAX_COUNT_LOCAL_IP_ADDR])
    {
        memset(addresses, 0,
            MAX_COUNT_LOCAL_IP_ADDR*sizeof(sockaddrunion));
        char buf[MAX_IPADDR_STR_LEN];
        if (gethostname(buf, 80) < 0)
            return -1;

        struct hostent *phe = gethostbyname(buf);
        if (phe == 0)
            return -1;

        uint addr = 0;
        int idx;
        int j = 0;
        for (idx = 0; idx < MAX_COUNT_LOCAL_IP_ADDR; idx++)
        {
            if (phe->h_addr_list[idx] == 0) break;
            if (*(uint*)phe->h_addr_list[idx] != addr)
            {
                memcpy(&addresses[idx].sin.sin_addr, phe->h_addr_list[idx], sizeof(in_addr));
                addresses[idx].sin.sin_family = AF_INET;
                addr = *(uint*)phe->h_addr_list[idx];
            }
            else
            {
                j++;
            }

        }
        return idx - j;
    }

    /**
     * An address filtering function
     * @param newAddress  a pointer to a sockunion address
     * @param flags  bit mask hiding (i.e. filtering) address classes
     * @return TRUE  address type is found in newAddress
     * else FALSE  address type NOT found in newAddress
     */
    bool typeofaddr(union sockaddrunion* newAddress, IPAddrType  flags);
};
#endif
