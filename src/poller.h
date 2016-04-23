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
#ifdef SCTP_OVER_UDP
#include <netinet/udp.h>
#endif
#include <asm/types.h>
#include <linux/rtnetlink.h>
#else
#include <winsock2.h>
#include <WS2tcpip.h>
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

namespace geco
{
    namespace net
    {
        /*=====================cb event defs=====================*/

        //! Structure for callback events. The function "action" is called by the event-handler,
        //! when an event occurs on the file-descriptor.
        struct event_cb_t
        {
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
            int       fd;
            int events;
            int revents;
            long      revision;
        };

        class poller_t
        {
            private:
            long revision;
            event_cb_t *event_callbacks[MAX_FD_SIZE];
            /* a static counter - for stats we should have more counters !  */
            unsigned int stat_send_event_size;
            /* a static value that keeps currently treated timer id */
            geco::ultils::timer_mgr::timer_id_t curr_timer;

            /* a static receive buffer  */
            uchar internal_receive_buffer[MAX_MTU_SIZE + 20];

            socket_despt_t socket_despts[MAX_FD_SIZE];
            int socket_despts_size;

            int ip4_socket_despt;       /* socket fd for standard SCTP port....      */
            int ip6_socket_despt;
            int icmp_socket_despt;       /* socket fd for ICMP messages */

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
            int poll(struct pollfd fds[], nfds_t nfds, int timeout)；
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
            void set_event_mask(int fd_index, int sfd, int event_mask)
            {
                if (fd_index > MAX_FD_SIZE)
                    error_log(loglvl_fatal_error_exit, "FD_Index bigger than MAX_FD_SIZE ! bye !\n");

                socket_despts[fd_index].fd = sfd; /* file descriptor */
                socket_despts[fd_index].events = event_mask;
                /*
                * Set the entry's revision to the current poll_socket_despts() revision.
                * If another thread is currently inside poll_socket_despts(), poll_socket_despts()
                * will notify that this entry is new and skip the possibly wrong results
                * until the next invocation.
                */
                socket_despts[fd_index].revision = revision;
                socket_despts[fd_index].revents = 0;
            }

            public:
            poller_t()
            {
                revision = 0;
                stat_send_event_size = 0;
                socket_despts_size = 0;
                ip4_socket_despt = -1;
                ip6_socket_despt = -1;
                icmp_socket_despt = -1;
            }

            int ip4_socket_despt(){ return this->ip4_socket_despt; }
            int ip6_socket_despt(){ return this->ip6_socket_despt; }
        };
    }
}
#endif
