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

#include "globals.h"
#include "gecotimer.h"

#include <random>
#include <algorithm>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#include <sys/timeout.h>
#include <netinet/in_systm.h>
#include <netinet/iphdr.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include <arpa/inet.h>      /* for inet_ntoa() under both SOLARIS/LINUX */
#include <sys/errno.h>
#include <sys/uio.h>        /* for struct iovec */
#include <sys/param.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <net/if.h>
#ifdef SCTP_OVER_UDP
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

#ifndef IN_EXPERIMENTAL
#define  IN_EXPERIMENTAL(a)   ((((int) (a)) & 0xf0000000) == 0xf0000000)
#endif

#ifndef IN_BADCLASS
#define  IN_BADCLASS(a)    IN_EXPERIMENTAL((a))
#endif

#if defined( __linux__) || defined(__unix__)
#include <sys/poll.h>
#else
#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008
#endif

#define IFA_BUFFER_LENGTH   1024
#define POLL_FD_UNUSED     -1
#define MAX_FD_SIZE     20
#define    EVENTCB_TYPE_SCTP       1
#define    EVENTCB_TYPE_UDP        2
#define    EVENTCB_TYPE_USER       3
#define    EVENTCB_TYPE_ROUTING    4

#define GECO_CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )
#define GECO_CMSG_SPACE(len) \
(GECO_CMSG_ALIGN(sizeof(struct cmsghdr)) + GECO_CMSG_ALIGN(len))
#define GECO_CMSG_LEN(len) (GECO_CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#define GECO_CMSG_DATA(cmsg) \
((unsigned char*)(cmsg)+GECO_CMSG_ALIGN(sizeof(struct cmsghdr)))

/*================ struct sockaddr =================*/
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

struct input_data
{
    unsigned long len;
    char buffer[1024];
    void* event;
    void* eventback;
};

#define msghdr _WSAMSG
#define iovec _WSABUF 
#endif

#ifndef _WIN32
#define USES_BSD_4_4_SOCKET
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

#define s4addr(X)   (((struct sockaddr_in *)(X))->sin_addr.s_addr)
#define sin4addr(X)   (((struct sockaddr_in *)(X))->sin_addr)
#define s6addr(X)  (((struct sockaddr_in6 *)(X))->sin6_addr.s6_addr)
#define sin6addr(X)  (((struct sockaddr_in6 *)(X))->sin6_addr)
#define saddr_family(X)  (X)->sa.sa_family

#define SUPPORT_ADDRESS_TYPE_IPV4        0x00000001
#define SUPPORT_ADDRESS_TYPE_IPV6        0x00000002
#define SUPPORT_ADDRESS_TYPE_DNS         0x00000004

#define DEFAULT_MTU_CEILING     1500

enum hide_address_flag_t
{
    flag_HideLoopback = (1 << 0),
    flag_HideLinkLocal = (1 << 1),
    flag_HideSiteLocal = (1 << 2),
    flag_HideLocal = flag_HideLoopback | flag_HideLinkLocal
    | flag_HideSiteLocal,
    flag_HideAnycast = (1 << 3),
    flag_HideMulticast = (1 << 4),
    flag_HideBroadcast = (1 << 5),
    flag_HideReserved = (1 << 6),
    flag_Default = flag_HideBroadcast | flag_HideMulticast | flag_HideAnycast,
    flag_HideAllExceptLoopback = (1 << 7),
    flag_HideAllExceptLinkLocal = (1 << 8),
    flag_HideAllExceptSiteLocal = (1 << 9)
};

/* union for handling either type of addresses: ipv4 and ipv6 */
union sockaddrunion
{
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
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
    void(*action)();
    void *arg1, *arg2, *userData;
};

struct data_t
{
    char* dat;
    int   len;
    void(*cb)();
};

struct socket_despt_t
{
    int event_handler_index;
    int       fd;
    int events;
    int revents;
    long      revision;
};

/* converts address-string
* (hex for ipv6, dotted decimal for ipv4 to a sockaddrunion structure)
*  str == NULL will bitzero saddr
*  port number will be always >0
*  default  is IPv4
*  @return 0 for success, else -1.*/
extern int str2saddr(sockaddrunion *su, const char * str, ushort port = 0, bool ip4 = true);
extern int saddr2str(sockaddrunion *su, char * buf, size_t len);
extern bool saddr_equals(sockaddrunion *one, sockaddrunion *two);
static void safe_cloe_soket(int sfd)
{
    if (sfd <= 0)
    {
        error_log(loglvl_major_error_abort, "invalid sfd!\n");
        return;
    }

#ifdef WIN32
    if (closesocket(sfd) < 0)
    {
#else
    if (close(sfd) < 0)
    {
#endif
#ifdef _WIN32
        error_logi(loglvl_major_error_abort,
            "safe_cloe_soket()::close socket failed! {%d} !\n",
            WSAGetLastError());
#else
        error_logi(loglvl_major_error_abort,
            "safe_cloe_soket()::close socket failed! {%d} !\n", errno);
#endif
    }
}

struct poller_t
{
    int revision_;

    event_handler_t event_callbacks[MAX_FD_SIZE];
    //int avaiable_event_index;

    socket_despt_t socket_despts[MAX_FD_SIZE];
    int socket_despts_size_;

#ifdef _WIN32
    int win32_fds_[MAX_FD_SIZE];
    int win32_fdnum_;
    HANDLE            win32_handler_;
    HANDLE            win32_handlers_[2];
    HANDLE  win32_stdin_handler;
    HANDLE       win32_stdin_handler_;
    input_data   win32_input_data_;
#endif

    timer_mgr timer_mgr_;

    /*
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

    poll()函数：这个函数是某些Unix系统提供的用于执行与select()函数同等功能的函数，
    下面是这个函数的声明：
    #include <poll.h>
    int poll(struct pollfd win32_fds_[], nfds_t nfds, int timeout)；
    参数说明:
    fds：是一个struct pollfd结构类型的数组，用于存放需要检测其状态的Socket描述符；
    每当调用这个函数之后，系统不会清空这个数组，操作起来比较方便；特别是对于
    socket连接比较多的情况下，在一定程度上可以提高处理的效率；这一点与select()函
    数不同，调用select()函数之后，select()函数会清空它所检测的socket描述符集合，
    导致每次调用select()之前都必须把socket描述符重新加入到待检测的集合中；
    因此，select()函数适合于只检测一个socket描述符的情况，
    而poll()函数适合于大量socket描述符的情况；
    nfds：nfds_t类型的参数，用于标记数组fds中的结构体元素的总数量；
    timeout：是poll函数调用阻塞的时间，单位：毫秒；
    返回值:
    >0：数组fds中准备好读、写或出错状态的那些socket描述符的总数量；
    ==0：数组fds中没有任何socket描述符准备好读、写，或出错；此时poll超时，
    超时时间是timeout毫秒；换句话说，如果所检测的socket描述符上没有任何事件发生
    的话，那么poll()函数会阻塞timeout所指定的毫秒时间长度之后返回，如果
    timeout==0，那么poll() 函数立即返回而不阻塞，如果timeout==INFTIM，那么poll()
    函数会一直阻塞下去，直到所检测的socket描述符上的感兴趣的事件发生是才返回，
    如果感兴趣的事件永远不发生，那么poll()就会永远阻塞下去；
    -1： poll函数调用失败，同时会自动设置全局变量errno；
    */
    int poller_t::poll_socket_despts(socket_despt_t* despts,
        int* count,
        int timeout,
        void(*lock)(void* data),
        void(*unlock)(void* data),
        void* data);

    //! function to set an event mask to a certain socket despt
    void set_event_on_geco_sdespt(int fd_index, int sfd, int event_mask);
    void set_event_on_win32_sdespt(int fd_index, int sfd);

    /**
    * function to register a file descriptor, that gets activated for certain read/write events
    * when these occur, the specified callback funtion is activated and passed the parameters
    * that are pointed to by the event_callback struct
    * when this method failed, will exit() directly
    * no no need to check ret val so no ret value given
    */
    void add_event_handler(
        int sfd,
        int eventcb_type,
        int event_mask,
        void(*action) (),
        void* userData);

    /**
    *    function to close a bound socket from our list of socket descriptors
    *    @return  >= 0 number of closed fds or eh , if close socket error will abort program
    */
    int remove_event_handler(event_handler_t* eh);

    /**
    * remove a sfd from the poll_list, and shift that list to the left
    * @return number of sfd's removed...
    * use socket_despt_size as insert index
    */
    int remove_socket_despt(int sfd);
};

struct network_interface_t
{
    int ip4_socket_despt_;       /* socket fd for standard SCTP port....      */
    int ip6_socket_despt_;       /* socket fd for standard SCTP port....      */
    int icmp_socket_despt_;       /* socket fd for ICMP messages */
    bool is_ip4_socket_;
    /* a static receive buffer  */
    char internal_receive_buffer[MAX_MTU_SIZE + 20];

#ifdef USE_UDP
    char      internal_udp_send__buffer_[65536];
    network_packet_fixed_t* udp_hdr_ptr_;
    int dummy_ipv4_udp_despt_;
    int dummy_ipv6_udp_despt_;
#endif

    /* counter for stats we should have more counters !  */
    uint stat_send_event_size_;
    uint stat_recv_event_size_;
    uint stat_recv_bytes_;
    uint stat_send_bytes_;

    poller_t poller_;

    network_interface_t()
    {
        ip4_socket_despt_ = -1;
        ip6_socket_despt_ = -1;
        icmp_socket_despt_ = -1;

        stat_send_event_size_ = 0;
        stat_recv_event_size_ = 0;
        stat_recv_bytes_ = 0;
        stat_send_bytes_ = 0;
    }

    /** This function binds a local socket for incoming requests
      * @return socket file descriptor for the newly opened and bound socket
      * @param address (local) port to bind to
      *  rwnd is in and out param the default value is 10*0xffff
      *  will use this value to set recv buffer of socket, */
    int open_ipproto_geco_socket(int af, int* rwnd = NULL);

    /**
     * This function creates a UDP socket bound to localhost, for asynchronous
     * interprocess communication with an Upper Layer process.
     * @return the socket file descriptor. Used to register a callback function
     */
    int open_ipproto_udp_socket(sockaddrunion* me, int* rwnd = NULL);

    /* @retval -1 error, >0 the settled new recv buffer size */
    int set_sockdespt_recvbuffer_size(int sfd, int new_size);

    /** this function initializes the data of this module.
     * opens raw sockets for capturing geco packets,
     * opens ICMP sockets, so we can get ICMP events,e.g.  for Path-MTU discovery !
     * if USE_UDP defined, open udp socket with specified port on dummy sadress 0.0.0.0*/
    int init_poller(int * myRwnd, bool ip4);

    /** function to be called when we get a message from a peer sctp instance in the poll loop
    * @param  sfd the socket file descriptor where data can be read...
    * @param  buf pointer to a buffer, where we data is stored
    * @param  len number of bytes to be sent, including the iphdr header !
    * @param  address, where data goes from
    * @param    dest_len size of the address
    * @return returns number of bytes actually sent, or error*/
    int send_udp_msg(int sfd, char* buf, int length, sockaddrunion* destsu);

    /**
    * function to be called when library sends a message on an SCTP socket
    * @param  sfd the socket file descriptor where data will be sent
    * @param  buf pointer to a buffer, where data to be sent is stored
    * @param  len number of bytes to be sent
    * @param  destination address, where data is to be sent
    * @param    dest_len size of the address
    * @return returns number of bytes actually sent, or error
    */
    int send_geco_msg(int sfd, char *buf, int len, sockaddrunion *dest, char tos);

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
    int recv_geco_msg(int sfd, char *dest, int maxlen,
        sockaddrunion *from, sockaddrunion *to);

    /**
    * function to be called when we get a message from a peer sctp instance in the poll loop
    * @param  sfd the socket file descriptor where data can be read...
    * @param  dest pointer to a buffer, where we can store the received data
    * @param  maxlen maximum number of bytes that can be received with call
    * @param  address, where we got the data from
    * @param    from_len size of the address
    * @return returns number of bytes received with this call
    */
    int recv_udp_msg(int sfd, char *dest, int maxlen,
        sockaddrunion *from, socklen_t *from_len);
};
#endif
