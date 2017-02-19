/* $Id: adaptation.c 2771 2013-05-30 09:09:07Z dreibh $
 * --------------------------------------------------------------------------
 *
 *           //=====   //===== ===//=== //===//  //       //   //===//
 *          //        //         //    //    // //       //   //    //
 *         //====//  //         //    //===//  //       //   //===<<
 *              //  //         //    //       //       //   //    //
 *       ======//  //=====    //    //       //=====  //   //===//
 *
 * -------------- An SCTP implementation according to RFC 4960 --------------
 *
 * Copyright (C) 2000 by Siemens AG, Munich, Germany.
 * Copyright (C) 2001-2004 Andreas Jungmaier
 * Copyright (C) 2004-2013 Thomas Dreibholz
 *
 * Acknowledgements:
 * Realized in co-operation between Siemens AG and the University of
 * Duisburg-Essen, Institute for Experimental Mathematics, Computer
 * Networking Technology group.
 * This work was partially funded by the Bundesministerium fuer Bildung und
 * Forschung (BMBF) of the Federal Republic of Germany
 * (Förderkennzeichen 01AK045).
 * The authors alone are responsible for the contents.
 *
 * This library is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contact: sctp-discussion@sctp.de
 *          dreibh@iem.uni-due.de
 *          tuexen@fh-muenster.de
 *          andreas.jungmaier@web.de
 */

#include "adaptation.h"
#include "timer_list.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>


#ifndef WIN32
   #include <sys/time.h>
   #include <netinet/in_systm.h>
   #include <netinet/ip.h>
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
#else
    #include <winsock2.h>
    #include <WS2tcpip.h>

    #include <sys/timeb.h>
    #define ADDRESS_LIST_BUFFER_SIZE        4096
    struct ip
    {
        unsigned char ip_verlen;
       unsigned char ip_tos;        /* type of service */
        u_short ip_len;             /* total length */
        u_short ip_id;              /* identification */
        u_short ip_off;             /* fragment offset field */
        unsigned char ip_ttl;       /* time to live */
        unsigned char ip_p;            /* protocol */
        u_short ip_sum;             /* checksum */
        struct in_addr ip_src, ip_dst; /* source and dest address */
    };

#endif

#ifdef HAVE_IPV6
    #if defined (LINUX)
        #include <netinet/ip6.h>
    #else
        /* include files for IPv6 header structs */
    #endif
#endif

#if defined (LINUX)
    #define LINUX_PROC_IPV6_FILE "/proc/net/if_inet6"
    #include <asm/types.h>
    #include <linux/rtnetlink.h>
#else /* this may not be okay for SOLARIS !!! */
#ifndef WIN32
    #define USES_BSD_4_4_SOCKET
    #include <net/if.h>
    #include <net/if_dl.h>
    #include <net/if_types.h>
    #include <net/route.h>
#ifndef SOLARIS
    #include <net/if_var.h>
    #include <machine/param.h>
    #define ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))
    #define NEXT_SA(ap) ap = (struct sockaddr *) \
        ((caddr_t) ap + (ap->sa_len ? ROUNDUP(ap->sa_len, sizeof (u_long)) : sizeof(u_long)))
#else
   #include <sys/sockio.h>
   #define NEXT_SA(ap) ap = (struct sockaddr *) ((caddr_t) ap + sizeof(struct sockaddr))
   #define RTAX_MAX RTA_NUMBITS
   #define RTAX_IFA 5
   #define _NO_SIOCGIFMTU_
#endif
#endif
#endif

#define     IFA_BUFFER_LENGTH   1024

#ifndef IN_EXPERIMENTAL
#define  IN_EXPERIMENTAL(a)   ((((int) (a)) & 0xf0000000) == 0xf0000000)
#endif

#ifndef IN_BADCLASS
#define  IN_BADCLASS(a)    IN_EXPERIMENTAL((a))
#endif

#ifdef HAVE_SYS_POLL_H
    #include <sys/poll.h>
#else
    #define POLLIN     0x001
    #define POLLPRI    0x002
    #define POLLOUT    0x004
    #define POLLERR    0x008
#endif

#ifdef LIBRARY_DEBUG
 #define ENTER_TIMER_DISPATCHER printf("Entering timer dispatcher.\n"); fflush(stdout);
 #define LEAVE_TIMER_DISPATCHER printf("Leaving  timer dispatcher.\n"); fflush(stdout);
 #define ENTER_EVENT_DISPATCHER printf("Entering event dispatcher.\n"); fflush(stdout);
 #define LEAVE_EVENT_DISPATCHER printf("Leaving  event dispatcher.\n"); fflush(stdout);
#else
 #define ENTER_TIMER_DISPATCHER
 #define LEAVE_TIMER_DISPATCHER
 #define ENTER_EVENT_DISPATCHER
 #define LEAVE_EVENT_DISPATCHER
#endif


#define POLL_FD_UNUSED     -1
#define NUM_FDS     20

#define    EVENTCB_TYPE_SCTP       1
#define    EVENTCB_TYPE_UDP        2
#define    EVENTCB_TYPE_USER       3
#define    EVENTCB_TYPE_ROUTING    4


#ifdef SCTP_OVER_UDP
int dummy_sctp_udp;
int dummy_sctpv6_udp;

guint32 inet_checksum(const void* ptr, size_t count)
{
   guint16* addr = (guint16*)ptr;
   guint32  sum  = 0;

   while(count > 1)  {
     sum += *(guint16*)addr++;
     count -= 2;
   }

   if(count > 0) {
      sum += *(unsigned char*)addr;
   }

   while(sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
   }

   return(~sum);
}
#endif


/**
 *  Structure for callback events. The function "action" is called by the event-handler,
 *  when an event occurs on the file-descriptor.
 */
struct event_cb
{
    int sfd;
    int eventcb_type;
    /* pointer to possible arguments, associations etc. */
    void *arg1;
    void *arg2;
    void (*action) ();
    void* userData;
};

struct data {
   char* dat;
   int   len;
   void (*cb)();
};

#ifdef HAVE_RANDOM
static long rstate[2];
#endif

#ifdef WIN32
struct input_data {
    DWORD len;
    char buffer[1024];
    HANDLE event, eventback;
};



static int fds[NUM_FDS];
static int fdnum;
HANDLE            hEvent, handles[2];
static HANDLE  stdin_thread_handle;
WSAEVENT       stdinevent;
static struct input_data   idata;
#endif

unsigned int
adl_random(void)
{
#ifdef HAVE_RANDOM
    return (unsigned int) random();
#else
    return (unsigned int)rand();
#endif
}

/*
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
 * - extendedPoll() returns
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
 */

static long revision = 0;

struct extendedpollfd {
   int       fd;
   short int events;
   short int revents;
   long      revision;
};

int extendedPoll(struct extendedpollfd* fdlist,
                 int*                   count,
                 int                    time,
                 void                   (*lock)(void* data),
                 void                   (*unlock)(void* data),
                 void*                  data)
{
   struct timeval    timeout;
   struct timeval*   to;
   fd_set            readfdset;
   fd_set            writefdset;
   fd_set            exceptfdset;
   int               fdcount;
   int               n;
   int               ret;
   int i;

   if(time < 0) {
      to = NULL;
   }
   else {
      to = &timeout;
      timeout.tv_sec  = time / 1000;
      timeout.tv_usec = (time % 1000) * 1000;
   }


   /* Initialize structures for select() */
   fdcount = 0;
   n = 0;
   FD_ZERO(&readfdset);
   FD_ZERO(&writefdset);
   FD_ZERO(&exceptfdset);

   for(i = 0; i < *count; i++) {
      if(fdlist[i].fd < 0) {
         continue;
      }
      n = MAX(n,fdlist[i].fd);
      if(fdlist[i].events & (POLLIN|POLLPRI)) {
         FD_SET(fdlist[i].fd, &readfdset);
      }
      if(fdlist[i].events & POLLOUT) {
         FD_SET(fdlist[i].fd, &writefdset);
      }
      if(fdlist[i].events & (POLLIN|POLLOUT)) {
         FD_SET(fdlist[i].fd, &exceptfdset);
      }
      fdcount++;
   }


   if(fdcount == 0) {
      ret = 0;
   }
   else {
      /*
       * Set the revision number of all entries to the current revision.
       */
      for(i = 0; i < *count; i++) {
         fdlist[i].revision = revision;
      }

      /*
       * Increment the revision number by one -> New entries made by
       * another thread during select() call will get this new revision number.
       */
      revision++;


      if(unlock) {
         unlock(data);
      }

      ret = select(n + 1, &readfdset, &writefdset, &exceptfdset, to);

      if(lock) {
         lock(data);
      }


      for(i = 0; i < *count; i++) {
         fdlist[i].revents = 0;
         if(fdlist[i].revision >= revision) {
            FD_CLR(fdlist[i].fd, &readfdset);
            FD_CLR(fdlist[i].fd, &writefdset);
            FD_CLR(fdlist[i].fd, &exceptfdset);
         }
      }

      if(ret > 0) {
         for(i = 0; i < *count; i++) {
            fdlist[i].revents = 0;
            /*
             * If fdlist's revision is equal the current revision, then the fdlist entry
             * has been added by another thread during the poll() call. If this is the
             * case, skip the results here (they will be reported again when select()
             * is called the next time).
             */
            if(fdlist[i].revision < revision) {
               if((fdlist[i].events & POLLIN) && FD_ISSET(fdlist[i].fd, &readfdset)) {
                  fdlist[i].revents |= POLLIN;
               }
               if((fdlist[i].events & POLLOUT) && FD_ISSET(fdlist[i].fd, &writefdset)) {
                  fdlist[i].revents |= POLLOUT;
               }
               if((fdlist[i].events & (POLLIN|POLLOUT)) && FD_ISSET(fdlist[i].fd, &exceptfdset)) {
                  fdlist[i].revents |= POLLERR;
               }
            }
         }
      }
   }

   return(ret);
}



/* a static counter - for stats we should have more counters !  */
static unsigned int number_of_sendevents = 0;
/* a static receive buffer  */
static unsigned char rbuf[MAX_MTU_SIZE + 20];
/* a static value that keeps currently treated timer id */
static unsigned int current_tid = 0;


static struct extendedpollfd poll_fds[NUM_FDS];
static int num_of_fds = 0;

static int sctp_sfd = -1;       /* socket fd for standard SCTP port....      */

#ifdef HAVE_IPV6
static int sctpv6_sfd = -1;
#endif

/* will be added back later....
   static int icmp_sfd = -1;  */      /* socket fd for ICMP messages */

static struct event_cb *event_callbacks[NUM_FDS];

/**
 *  converts address-string (hex for ipv6, dotted decimal for ipv4
 *  to a sockunion structure
 *  @return 0 for success, else -1.
 */
int adl_str2sockunion(guchar * str, union sockunion *su)
{
    int ret;

    memset((void*)su, 0, sizeof(union sockunion));

#ifndef WIN32
   ret = inet_aton((const char *)str, &su->sin.sin_addr);
#else
   if ((su->sin.sin_addr.s_addr = inet_addr(str)) == INADDR_NONE)
      ret=0;
   else {
      ret=1;
   }
#endif
    if (ret > 0) {              /* Valid IPv4 address format. */
        su->sin.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
        su->sin.sin_len = sizeof(struct sockaddr_in);
#endif                          /* HAVE_SIN_LEN */
        return 0;
    }
#ifdef HAVE_IPV6
    ret = inet_pton(AF_INET6, (const char *)str, &su->sin6.sin6_addr);
    if (ret > 0) {              /* Valid IPv6 address format. */
        su->sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
        su->sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif                          /* SIN6_LEN */
        su->sin6.sin6_scope_id = 0;
        return 0;
    }
#endif                          /* HAVE_IPV6 */
    return -1;
}


int adl_sockunion2str(union sockunion *su, guchar * buf, size_t len)
{
    char        ifnamebuffer[IFNAMSIZ];
    const char* ifname;

    if (su->sa.sa_family == AF_INET){
        if (len > 16) len = 16;
        strncpy((char *)buf, inet_ntoa(su->sin.sin_addr), len);
        return(1);
    }
#ifdef HAVE_IPV6
    else if (su->sa.sa_family == AF_INET6) {
        if (inet_ntop(AF_INET6, &su->sin6.sin6_addr, (char *)buf, len)==NULL) return 0;
        if (IN6_IS_ADDR_LINKLOCAL(&su->sin6.sin6_addr)) {
             ifname = if_indextoname(su->sin6.sin6_scope_id, (char*)&ifnamebuffer);
             if(ifname == NULL) {
                /* printf("Bad scope: %s!\n", buf); */
                return(0);   /* Bad scope ID! */
             }
             if(strlen((const char*)buf) + strlen(ifname) + 2 >= len) {
                return(0);   /* Not enough space! */
             }
             strcat((char*)buf, "%");
             strcat((char*)buf, ifname);
        }
        return (1);
    }
#endif                          /* HAVE_IPV6 */
    return 0;
}

boolean adl_equal_address(union sockunion * a, union sockunion * b)
{
#ifdef HAVE_IPV6
   union sockunion        my_a;
   union sockunion        my_b;
   const union sockunion* one;
   const union sockunion* two;
   unsigned int           count;

#if defined __APPLE__ || defined FreeBSD
#define s6_addr32 __u6_addr.__u6_addr32
#endif

   if(a->sa.sa_family == AF_INET) {
      my_a.sin6.sin6_family = AF_INET6;
      my_a.sin6.sin6_port   = a->sin.sin_port;
      my_a.sin6.sin6_addr.s6_addr32[0] = 0x00000000;
      my_a.sin6.sin6_addr.s6_addr32[1] = 0x00000000;
      my_a.sin6.sin6_addr.s6_addr32[2] = 0x00000000;
      my_a.sin6.sin6_addr.s6_addr32[3] = a->sin.sin_addr.s_addr;
      one = &my_a;
   }
   else {
      one = a;
   }
   if(b->sa.sa_family == AF_INET) {
      my_b.sin6.sin6_family = AF_INET6;
      my_b.sin6.sin6_port   = b->sin.sin_port;
      my_b.sin6.sin6_addr.s6_addr32[0] = 0x00000000;
      my_b.sin6.sin6_addr.s6_addr32[1] = 0x00000000;
      my_b.sin6.sin6_addr.s6_addr32[2] = 0x00000000;
      my_b.sin6.sin6_addr.s6_addr32[3] = b->sin.sin_addr.s_addr;
      two = &my_b;
   }
   else {
      two = b;
   }
#else
   const union sockunion* one = a;
   const union sockunion* two = b;
#endif

    switch (sockunion_family(one)) {
    case AF_INET:
        if (sockunion_family(two) != AF_INET)
            return FALSE;
        return (sock2ip(one) == sock2ip(two));
        break;
#ifdef HAVE_IPV6
    case AF_INET6:
        if (sockunion_family(two) != AF_INET6)
            return FALSE;
        for (count = 0; count < 16; count++)
            if (sock2ip6(one)[count] != sock2ip6(two)[count])
                return FALSE;
        return TRUE;
        break;
#endif
    default:
        error_logi(ERROR_MAJOR, "Address family %d not supported", sockunion_family(one));
        return FALSE;
        break;
    }
}


int adl_setReceiveBufferSize(int sfd,int new_size)
{
    int ch = new_size;
    if (setsockopt (sfd, SOL_SOCKET, SO_RCVBUF, (void*)&ch, sizeof(ch)) < 0) {
        error_log(ERROR_MAJOR, "setsockopt: SO_RCVBUF failed !");
        return -1;
    }
    event_logi(INTERNAL_EVENT_0, "set receive buffer size to : %d bytes",ch);
    return 0;
}


gint adl_open_sctp_socket(int af, int* myRwnd)
{
    int sfd, ch;
    socklen_t opt_size;
#ifdef WIN32
    struct sockaddr_in me;
#endif

#ifdef SCTP_OVER_UDP
    if ((sfd = socket(af, SOCK_RAW, IPPROTO_UDP)) < 0) {
#else
    if ((sfd = socket(af, SOCK_RAW, IPPROTO_SCTP)) < 0) {
#endif
        return sfd;
    }

#ifdef WIN32
    /* binding to INADDR_ANY to make Windows happy... */
    memset((void *)&me, 0, sizeof(me));
    me.sin_family      = AF_INET;
#ifdef HAVE_SIN_LEN
    me.sin_len         = sizeof(me);
#endif
    me.sin_addr.s_addr = INADDR_ANY;
    bind(sfd, (const struct sockaddr *)&me, sizeof(me));
#endif

    switch (af) {
        case AF_INET:
            *myRwnd = 0;
            opt_size=sizeof(*myRwnd);
            if (getsockopt (sfd, SOL_SOCKET, SO_RCVBUF, (void*)myRwnd, &opt_size) < 0) {
                error_log(ERROR_FATAL, "getsockopt: SO_RCVBUF failed !");
                *myRwnd = -1;
            }
            event_logi(INTERNAL_EVENT_0, "receive buffer size initially is : %d", *myRwnd);

#if defined (LINUX)
            adl_setReceiveBufferSize(sfd, 10*0xFFFF);

            ch = IP_PMTUDISC_DO;
            if (setsockopt(sfd, IPPROTO_IP, IP_MTU_DISCOVER, (char *) &ch, sizeof(ch)) < 0) {
                error_log(ERROR_FATAL, "setsockopt: IP_PMTU_DISCOVER failed !");
            }
            opt_size=sizeof(*myRwnd);
            if (getsockopt (sfd, SOL_SOCKET, SO_RCVBUF, (void*)myRwnd, &opt_size) < 0) {
                error_log(ERROR_FATAL, "getsockopt: SO_RCVBUF failed !");
                *myRwnd = -1;
            }
            event_logi(INTERNAL_EVENT_0, "receive buffer size finally is : %d", *myRwnd);
#endif
            break;
#ifdef HAVE_IPV6
        case AF_INET6:
            *myRwnd = 0;
            opt_size=sizeof(*myRwnd);
            if (getsockopt (sfd, SOL_SOCKET, SO_RCVBUF, (void*)myRwnd, &opt_size) < 0) {
                error_log(ERROR_FATAL, "getsockopt: SO_RCVBUF failed !");
                *myRwnd = -1;
            }
            event_logi(INTERNAL_EVENT_0, "receive buffer size is : %d",*myRwnd);
            /* also receive packetinfo on IPv6 sockets, for getting dest address */
            ch = 1;
#ifdef HAVE_IPV6_RECVPKTINFO
            /* IMPORTANT:
               The new option name is now IPV6_RECVPKTINFO!
               IPV6_PKTINFO expects an extended parameter structure now
               and had to be replaced to provide the original functionality! */
            if (setsockopt(sfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &ch, sizeof(ch)) < 0) {
                error_log(ERROR_FATAL, "setsockopt: IPV6_RECVPKTINFO failed");
                abort();
            }
#else
            if (setsockopt(sfd, IPPROTO_IPV6, IPV6_PKTINFO, &ch, sizeof(ch)) < 0) {
                error_log(ERROR_FATAL, "setsockopt: IPV6_PKTINFO failed");
                abort();
            }
#endif
            break;
#endif
        default:
            error_log(ERROR_MINOR, "Unknown address family.");
            break;
    }
    event_logi(INTERNAL_EVENT_0, "Created raw socket %d with options\n", sfd);
    return (sfd);
}


gint adl_get_sctpv4_socket(void)
{
    /* this is a static variable ! */
    return sctp_sfd;
}


#ifdef HAVE_IPV6
gint adl_get_sctpv6_socket(void)
{
    /* this is a static variable ! */
    return sctpv6_sfd;
}
#endif


/**
 * This function creates a UDP socket bound to localhost, for asynchronous
 * interprocess communication with an Upper Layer process.
 * @return the socket file descriptor. Used to register a callback function
 */
int adl_open_udp_socket(union sockunion* me)
{
    guchar buf[1000];
    int ch, sfd;

    switch (sockunion_family(me)) {
        case AF_INET:
            if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                error_log(ERROR_FATAL, "SCTP: socket creation failed for UDP socket !");
            }
            ch = bind(sfd, (struct sockaddr *)me, sizeof(struct sockaddr_in));
            adl_sockunion2str(me, buf, SCTP_MAX_IP_LEN);
            event_logiii(VERBOSE,
                 " adl_open_udp_socket : Create socket %u, binding to address %s, result %d",sfd, buf, ch);
            if (ch == 0)
                return (sfd);
            return -1;
            break;
#ifdef HAVE_IPV6
        case AF_INET6:
            if ((sfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
                error_log(ERROR_FATAL, "SCTP: socket creation failed for UDPv6 socket");
            }
            ch = bind(sfd, (struct sockaddr *)me, sizeof(struct sockaddr_in6));
            adl_sockunion2str(me, buf, SCTP_MAX_IP_LEN);
            event_logiii(VERBOSE,
                 " adl_open_udp_socket : Create socket %u, binding to address %s, result %d",sfd, buf, ch);
            if (ch == 0)
                return (sfd);
            return -1;
            break;
#endif
        default:
            return -1;
            break;
     }

}

/**
 * function to be called when we get a message from a peer sctp instance in the poll loop
 * @param  sfd the socket file descriptor where data can be read...
 * @param  buf pointer to a buffer, where we data is stored
 * @param  len number of bytes to be sent, including the ip header !
 * @param  address, where data goes from
 * @param    dest_len size of the address
 * @return returns number of bytes actually sent, or error
 */
int adl_sendUdpData(int sfd, unsigned char* buf, int length,
                     unsigned char destination[], unsigned short dest_port)
{
    union sockunion dest_su;
    int dest_len;
    int result;

    if (sfd < 0) {
        error_log(ERROR_MAJOR, "You are trying to send UDP data on an invalid fd");
        return -1;
    }

    if ((sfd == sctp_sfd)
#ifdef HAVE_IPV6
        || (sfd == sctpv6_sfd)
#endif
                               ) {
        error_log(ERROR_MAJOR, "You are trying to send UDP data on a SCTP socket");
        return -1;
    }
    result = adl_str2sockunion(destination, &dest_su);

    if (result != 0) {
        error_logi(ERROR_MAJOR, "Invalid destination address in sctp_sendUdpData(%s)",destination);
        return -1;
    }
    if (buf == NULL) {
        error_log(ERROR_MAJOR, "Invalid buffer sctp_sendUdpData()");
        return -1;
    }
    if (dest_port == 0) {
        error_log(ERROR_MAJOR, "Invalid port in sctp_sendUdpData()");
        return -1;
    }
    switch (sockunion_family(&dest_su)) {
        case AF_INET:
            dest_su.sin.sin_port = htons(dest_port);
            dest_len = sizeof(struct sockaddr_in);
            result = sendto(sfd, buf, length, 0, (struct sockaddr *) &(dest_su.sin), dest_len);
            break;
#ifdef HAVE_IPV6
        case AF_INET6:
            dest_su.sin6.sin6_port = htons(dest_port);
            dest_len = sizeof(struct sockaddr_in6);
            result = sendto(sfd, buf, length, 0, (struct sockaddr *) &(dest_su.sin6), dest_len);
            break;
#endif
        default :
            error_logi(ERROR_MAJOR, "Invalid address family in sctp_sendUdpData(%s)",destination);
            result = -1;
            break;
    }
    return result;
}



/**
 * function to be called when library sends a message on an SCTP socket
 * @param  sfd the socket file descriptor where data will be sent
 * @param  buf pointer to a buffer, where data to be sent is stored
 * @param  len number of bytes to be sent
 * @param  destination address, where data is to be sent
 * @param    dest_len size of the address
 * @return returns number of bytes actually sent, or error
 */
int adl_send_message(int sfd, void *buf, int len, union sockunion *dest, unsigned char tos)
{
    int txmt_len = 0;
    unsigned char old_tos;
    socklen_t opt_len;
    int tmp;
#ifdef SCTP_OVER_UDP
    guchar      outBuffer[65536];
    udp_header* udp;
#endif

#ifdef HAVE_IPV6
    guchar hostname[MAX_MTU_SIZE];
#endif

    switch (sockunion_family(dest)) {

    case AF_INET:
        number_of_sendevents++;
        opt_len = sizeof(old_tos);
        tmp = getsockopt(sfd, IPPROTO_IP, IP_TOS, &old_tos, &opt_len);
        tmp = setsockopt(sfd, IPPROTO_IP, IP_TOS, &tos, sizeof(unsigned char));
        event_logii(VVERBOSE, "adl_send_message: set IP_TOS %u, result=%d", tos,tmp);

        event_logiiii(VERBOSE,
                     "AF_INET : adl_send_message : sfd : %d, len %d, destination : %s, send_events %u",
                     sfd, len, inet_ntoa(dest->sin.sin_addr), number_of_sendevents);

#ifdef SCTP_OVER_UDP
        if(len + sizeof(udp_header) > sizeof(outBuffer)) {
           error_log(ERROR_FATAL, "Data block too large ! bye !\n");
        }
        memcpy(&outBuffer[sizeof(udp_header)], buf, len);

        udp = (udp_header*)&outBuffer;
        udp->src_port = htons(SCTP_OVER_UDP_UDPPORT);
        udp->dest_port = htons(SCTP_OVER_UDP_UDPPORT);
        udp->length = htons(sizeof(udp_header) + len);
        udp->checksum = 0x0000;

        txmt_len = sendto(sfd, (char*)&outBuffer, sizeof(udp_header) + len,
                          0, (struct sockaddr *) &(dest->sin), sizeof(struct sockaddr_in));
        if(txmt_len >= (int)sizeof(udp_header)) {
           txmt_len -= (int)sizeof(udp_header);
        }
#else
        txmt_len = sendto(sfd, buf, len, 0, (struct sockaddr *) &(dest->sin), sizeof(struct sockaddr_in));
#endif

        if (txmt_len < 0) {
            error_logi(ERROR_MAJOR, "AF_INET : sendto()=%d !", txmt_len);
        }
        tmp = setsockopt(sfd, IPPROTO_IP, IP_TOS, &old_tos, sizeof(unsigned char));
    break;
#ifdef HAVE_IPV6
    case AF_INET6:
        number_of_sendevents++;
        inet_ntop(AF_INET6, sock2ip6(dest), (char *)hostname, MAX_MTU_SIZE);

        event_logiiii(VVERBOSE,
                     "AF_INET6: adl_send_message : sfd : %d, len %d, destination : %s, send_events: %u",
                        sfd, len, hostname, number_of_sendevents);

#ifdef SCTP_OVER_UDP
        if(len + sizeof(udp_header) > sizeof(outBuffer)) {
           error_log(ERROR_FATAL, "Data block too large ! bye !\n");
        }
        memcpy(&outBuffer[sizeof(udp_header)], buf, len);

        udp = (udp_header*)&outBuffer;
        udp->src_port = htons(SCTP_OVER_UDP_UDPPORT);
        udp->dest_port = htons(SCTP_OVER_UDP_UDPPORT);
        udp->length = htons(sizeof(udp_header) + len);
        udp->checksum = 0x0000;

        txmt_len = sendto(sfd, (char*)&outBuffer, sizeof(udp_header) + len,
                          0, (struct sockaddr *) &(dest->sin6), sizeof(struct sockaddr_in6));
        if(txmt_len >= (int)sizeof(udp_header)) {
           txmt_len -= (int)sizeof(udp_header);
        }
#else
        txmt_len = sendto(sfd, buf, len, 0, (struct sockaddr *)&(dest->sin6), sizeof(struct sockaddr_in6));
#endif
        break;
#endif
    default:
        error_logi(ERROR_MAJOR,
                   "adl_send_message : Adress Family %d not supported here",
                   sockunion_family(dest));
        txmt_len = -1;
    }
    return txmt_len;
}

/**
 * function to assign an event mask to a certain poll
 */
void assign_poll_fd(int fd_index, int sfd, int event_mask)
{
    if (fd_index > NUM_FDS)
        error_log(ERROR_FATAL, "FD_Index bigger than NUM_FDS ! bye !\n");

    poll_fds[fd_index].fd = sfd; /* file descriptor */
    poll_fds[fd_index].events = event_mask;
    /*
     * Set the entry's revision to the current extendedPoll() revision.
     * If another thread is currently inside extendedPoll(), extendedPoll()
     * will notify that this entry is new and skip the possibly wrong results
     * until the next invocation.
     */
    poll_fds[fd_index].revision = revision;
    poll_fds[fd_index].revents  = 0;
}


/**
 * remove a sfd from the poll_list, and shift that list to the left
 * @return number of sfd's removed...
 */
int adl_remove_poll_fd(gint sfd)
{
    int i, tmp, counter = 0;
    for (i = 0, tmp = 0; i < NUM_FDS; i++, tmp++) {
        if (tmp < NUM_FDS) {
            poll_fds[i].fd = poll_fds[tmp].fd;
            poll_fds[i].events = poll_fds[tmp].events;
            poll_fds[i].revents = poll_fds[tmp].revents;
            poll_fds[i].revision = poll_fds[tmp].revision;
            event_callbacks[i] = event_callbacks[tmp];
        } else {
            poll_fds[i].fd = POLL_FD_UNUSED;
            poll_fds[i].events = 0;
            poll_fds[i].revents = 0;
            poll_fds[i].revision = 0;
            event_callbacks[i] = NULL;
        }
        if (poll_fds[i].fd == sfd) {
            tmp = i + 1;
            if (tmp < NUM_FDS) {
                poll_fds[i].fd = poll_fds[tmp].fd;
                poll_fds[i].events = poll_fds[tmp].events;
                poll_fds[i].revents = poll_fds[tmp].revents;
                poll_fds[i].revision = poll_fds[tmp].revision;
                free(event_callbacks[i]);
                event_callbacks[i] = event_callbacks[tmp];
            } else {
                poll_fds[i].fd = POLL_FD_UNUSED;
                poll_fds[i].events = 0;
                poll_fds[i].revents = 0;
                poll_fds[i].revision = 0;
                free(event_callbacks[i]);
                event_callbacks[i] = NULL;
            }
            counter++;
            num_of_fds -= 1;
        }
      #ifdef WIN32
      for (i = 0; i < NUM_FDS; i++)
   {
      if (fds[i]==sfd)
      {
         fds[i]=-1;
         fdnum--;
         break;
      }
   }
#endif
    }
    return (counter);
}

/**
 * function to register a file descriptor, that gets activated for certain read/write events
 * when these occur, the specified callback funtion is activated and passed the parameters
 * that are pointed to by the event_callback struct
 */

int
adl_register_fd_cb(int sfd, int eventcb_type, int event_mask,
                   void (*action) (void *, void *) , void* userData)
{
   #ifdef WIN32

int ret, i;
if (sfd!=0)
{

   ret = WSAEventSelect(sfd, hEvent, FD_READ | FD_WRITE |
   FD_ACCEPT | FD_CLOSE | FD_CONNECT);
    if (ret == SOCKET_ERROR)
    {
        error_log(ERROR_FATAL, "WSAEventSelect() failed\n");
        return (-1);
    }
   for (i=0; i<NUM_FDS;i++)
   {
      if (fds[i]==-1)
      {
         fds[i]=sfd;
         fdnum++;
         break;
      }
   }
}
#endif

    if (num_of_fds < NUM_FDS && sfd >= 0) {
        assign_poll_fd(num_of_fds, sfd, event_mask);
        event_callbacks[num_of_fds] = (struct event_cb*)malloc(sizeof(struct event_cb));
        if (!event_callbacks[num_of_fds])
            error_log(ERROR_FATAL, "Could not allocate memory in  register_fd_cb \n");
        event_callbacks[num_of_fds]->sfd = sfd;
        event_callbacks[num_of_fds]->eventcb_type = eventcb_type;

        event_callbacks[num_of_fds]->action = (void (*) (void))action;
        event_callbacks[num_of_fds]->userData = userData;
        num_of_fds++;
        return num_of_fds;
    } else
        return (-1);
}

#ifndef CMSG_ALIGN
#ifdef ALIGN
#define CMSG_ALIGN ALIGN
#else
#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )
#endif
#endif

#ifndef CMSG_SPACE
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#endif

#ifndef CMSG_LEN
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif

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
int adl_receive_message(int sfd, void *dest, int maxlen, union sockunion *from, union sockunion *to)
{
    int len;
#ifdef SCTP_OVER_UDP
#ifdef LINUX
    udp_header*    udp;
#else
    struct udphdr * udp;
#endif
    unsigned char* ptr;
    int            i;
#endif
#ifdef HAVE_IPV6
    struct msghdr rmsghdr;
    struct cmsghdr *rcmsgp;
    struct iovec  data_vec;
#endif
#ifdef LINUX
    struct iphdr *iph;
#else
    struct ip *iph;
#endif

#ifdef HAVE_IPV6
    unsigned char m6buf[(CMSG_SPACE(sizeof (struct in6_pktinfo)))];
    struct in6_pktinfo *pkt6info;
#endif

    len = -1;
    if ((dest == NULL) || (from == NULL) || (to == NULL)) return -1;

    if (sfd == sctp_sfd) {
        len = recv (sfd, dest, maxlen, 0);
#ifdef LINUX
        iph = (struct iphdr *)dest;
#else
        iph = (struct ip *)dest;
#endif
        to->sa.sa_family = AF_INET;
        to->sin.sin_port = htons(0);
#ifdef LINUX
        to->sin.sin_addr.s_addr = iph->daddr;
#else
        to->sin.sin_addr.s_addr = iph->ip_dst.s_addr;
#endif
        from->sa.sa_family = AF_INET;
        from->sin.sin_port = htons(0);
#ifdef LINUX
        from->sin.sin_addr.s_addr = iph->saddr;
#else
        from->sin.sin_addr.s_addr = iph->ip_src.s_addr;
#endif

#ifdef SCTP_OVER_UDP
#ifdef LINUX
        if(len < (int)sizeof(struct iphdr) + (int)sizeof(udp_header)) {
#else
        if(len < (int)sizeof(struct ip) + (int)sizeof(struct udphdr)) {
#endif
            return -1;
        }
#ifdef LINUX
        udp = (udp_header*)((long)dest + (long)sizeof(struct iphdr));
#else
        udp = (struct udphdr *)((long)dest + (long)sizeof(struct ip));
#endif
#ifdef LINUX
        if(ntohs(udp->dest_port) != SCTP_OVER_UDP_UDPPORT) {
#else
       if(ntohs(udp->uh_dport) != SCTP_OVER_UDP_UDPPORT) {
#endif
            return -1;
        }
        ptr = (unsigned char*)udp;
#ifdef LINUX
        for(i = 0;i < len - (int)(sizeof(struct iphdr) + sizeof(udp_header));i++) {
           *ptr = ptr[sizeof(udp_header)];
#else
        for(i = 0;i < len - (int)(sizeof(struct ip) + sizeof(struct udphdr));i++) {
           *ptr = ptr[sizeof(struct udphdr)];
#endif
           ptr++;
        }
#ifdef LINUX
        len -= sizeof(udp_header);
#else
        len -= sizeof(struct udphdr);
#endif
#endif
    }
#ifdef HAVE_IPV6
    data_vec.iov_base = dest;
    data_vec.iov_len  = maxlen;
    if (sfd == sctpv6_sfd) {
        rcmsgp = (struct cmsghdr *)m6buf;
        pkt6info = (struct in6_pktinfo *)(CMSG_DATA(rcmsgp));

        /* receive control msg */
        rcmsgp->cmsg_level = IPPROTO_IPV6;
        rcmsgp->cmsg_type = IPV6_PKTINFO;
        rcmsgp->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));

        rmsghdr.msg_flags = 0;
        rmsghdr.msg_iov = &data_vec;
        rmsghdr.msg_iovlen = 1;
        rmsghdr.msg_name =      (caddr_t) &(from->sin6);
        rmsghdr.msg_namelen =   sizeof (struct sockaddr_in6);
        rmsghdr.msg_control = (caddr_t) m6buf;
        rmsghdr.msg_controllen = sizeof (m6buf);
        memset (from, 0, sizeof (struct sockaddr_in6));
        memset (to,   0, sizeof (struct sockaddr_in6));

        len = recvmsg (sfd, &rmsghdr, 0);

        /* Linux sets this, so we reset it, as we don't want to run into trouble if
           we have a port set on sending...then we would get INVALID ARGUMENT  */
        from->sin6.sin6_port = htons(0);

        to->sa.sa_family = AF_INET6;
        to->sin6.sin6_port = htons(0);
        to->sin6.sin6_flowinfo = htonl(0);
        memcpy(&(to->sin6.sin6_addr), &(pkt6info->ipi6_addr), sizeof(struct in6_addr));

#ifdef SCTP_OVER_UDP
#ifdef LINUX
        if(len < (int)sizeof(udp_header)) {
#else
        if(len < (int)sizeof(struct udphdr)) {
#endif
            return -1;
        }
#ifdef LINUX
        udp = (udp_header*)dest;
#else
        udp = (struct udphdr *)dest;
#endif
#ifdef LINUX
	if(ntohs(udp->dest_port) != SCTP_OVER_UDP_UDPPORT) {
#else
	if(ntohs(udp->uh_dport) != SCTP_OVER_UDP_UDPPORT) {
#endif
            return -1;
        }
        ptr = (unsigned char*)udp;
#ifdef LINUX
        for(i = 0;i < len - (int)sizeof(udp_header);i++) {
           *ptr = ptr[sizeof(udp_header)];
#else
        for(i = 0;i < len - (int)sizeof(struct udphdr);i++) {
           *ptr = ptr[sizeof(struct udphdr)];
#endif
           ptr++;
        }
#ifdef LINUX
        len -= sizeof(udp_header);
#else
        len -= sizeof(struct udphdr);
#endif
#endif
    }
#endif

    if (len < 0) error_log(ERROR_MAJOR, "recvmsg()  failed in adl_receive_message() !");

    return len;
}


/**
 * function to be called when we get a message from a peer sctp instance in the poll loop
 * @param  sfd the socket file descriptor where data can be read...
 * @param  dest pointer to a buffer, where we can store the received data
 * @param  maxlen maximum number of bytes that can be received with call
 * @param  address, where we got the data from
 * @param    from_len size of the address
 * @return returns number of bytes received with this call
 */
int adl_get_message(int sfd, void *dest, int maxlen, union sockunion *from, socklen_t *from_len)
{
    int len;

    len = recvfrom(sfd, dest, maxlen, 0, (struct sockaddr *) from, from_len);
    if (len < 0)
        error_log(ERROR_FATAL, "recvfrom  failed in get_message(), aborting !");

    return len;
}

/**
 * this function is responsible for calling the callback functions belonging
 * to all of the file descriptors that have indicated an event !
 * TODO : check handling of POLLERR situation
 * @param num_of_events  number of events indicated by poll()
 */
void dispatch_event(int num_of_events)
{
    int i = 0;
    int length=0;
    socklen_t src_len;
    union sockunion src, dest;
    struct sockaddr_in *src_in;
    guchar src_address[SCTP_MAX_IP_LEN];
    unsigned short portnum=0;

#if !defined (LINUX)
    struct ip *iph;
#else
    struct iphdr *iph;
#endif
    int hlen=0;
    ENTER_EVENT_DISPATCHER;
    for (i = 0; i < num_of_fds; i++) {

    if (!poll_fds[i].revents)
        continue;

        if (poll_fds[i].revents & POLLERR) {
            /* We must have specified this callback funtion for treating/logging the error */
            if (event_callbacks[i]->eventcb_type == EVENTCB_TYPE_USER) {
                event_logi(VERBOSE, "Poll Error Condition on user fd %d", poll_fds[i].fd);
                ((sctp_userCallback)*(event_callbacks[i]->action)) (poll_fds[i].fd, poll_fds[i].revents, &poll_fds[i].events, event_callbacks[i]->userData);
            } else {
                error_logi(ERROR_MINOR, "Poll Error Condition on fd %d", poll_fds[i].fd);
                ((sctp_socketCallback)*(event_callbacks[i]->action)) (poll_fds[i].fd, NULL, 0, NULL, 0);
            }
        }

        if ((poll_fds[i].revents & POLLPRI) || (poll_fds[i].revents & POLLIN) || (poll_fds[i].revents & POLLOUT)) {
            if (event_callbacks[i]->eventcb_type == EVENTCB_TYPE_USER) {
                    event_logi(VERBOSE, "Activity on user fd %d - Activating USER callback", poll_fds[i].fd);
                    ((sctp_userCallback)*(event_callbacks[i]->action)) (poll_fds[i].fd, poll_fds[i].revents, &poll_fds[i].events, event_callbacks[i]->userData);

            } else if (event_callbacks[i]->eventcb_type == EVENTCB_TYPE_UDP) {
                src_len = sizeof(src);
                length = adl_get_message(poll_fds[i].fd, rbuf, MAX_MTU_SIZE, &src, &src_len);
                event_logi(VERBOSE, "Message %d bytes - Activating UDP callback", length);
                adl_sockunion2str(&src, src_address, SCTP_MAX_IP_LEN);

                switch (sockunion_family(&src)) {
                    case AF_INET :
                        portnum = ntohs(src.sin.sin_port);
                        break;
#ifdef HAVE_IPV6
                    case AF_INET6:
                        portnum = ntohs(src.sin6.sin6_port);
                        break;
#endif
                    default:
                        portnum = 0;
                        break;
                }
                ((sctp_socketCallback)*(event_callbacks[i]->action)) (poll_fds[i].fd, rbuf, length, src_address, portnum);

            } else if (event_callbacks[i]->eventcb_type == EVENTCB_TYPE_SCTP) {
                length = adl_receive_message(poll_fds[i].fd, rbuf, MAX_MTU_SIZE, &src, &dest);

                if(length < 0) break;

                event_logiiii(VERBOSE, "SCTP-Message on socket %u , len=%d, portnum=%d, sockunion family %u",
                     poll_fds[i].fd, length, portnum, sockunion_family(&src));

                switch (sockunion_family(&src)) {
                case AF_INET:
                    src_in = (struct sockaddr_in *) &src;
                    event_logi(VERBOSE, "IPv4/SCTP-Message from %s -> activating callback",
                               inet_ntoa(src_in->sin_addr));
#if defined (LINUX)
                    iph = (struct iphdr *) rbuf;
                    hlen = iph->ihl << 2;
#elif defined (WIN32)
                    iph = (struct ip *) rbuf;
                    hlen = (iph->ip_verlen & 0x0F) << 2;
#else
                    iph = (struct ip *) rbuf;
                    hlen = iph->ip_hl << 2;
#endif
                    if (length < hlen) {
                        error_logii(ERROR_MINOR,
                                    "dispatch_event : packet too short (%d bytes) from %s",
                                    length, inet_ntoa(src_in->sin_addr));
                    } else {
                        length -= hlen;
                        mdi_receiveMessage(poll_fds[i].fd, &rbuf[hlen], length, &src, &dest);
                    }
                    break;
#ifdef HAVE_IPV6
                case AF_INET6:
                    adl_sockunion2str(&src, src_address, SCTP_MAX_IP_LEN);
                    /* if we have additional options, we must parse them, and deduct the sizes :-( */
                    event_logii(VERBOSE, "IPv6/SCTP-Message from %s (%d bytes) -> activating callback",
                                   src_address, length);

                    mdi_receiveMessage(poll_fds[i].fd, &rbuf[hlen], length, &src, &dest);
                    break;

#endif                          /* HAVE_IPV6 */
                default:
                    error_logi(ERROR_MAJOR, "Unsupported Address Family Type %u ", sockunion_family(&src));
                    break;

                }
            }
        }
        poll_fds[i].revents = 0;
    }                       /*   for(i = 0; i < num_of_fds; i++) */
    LEAVE_EVENT_DISPATCHER;
}


/**
 * function calls the respective callback funtion, that is to be executed as a timer
 * event, passing it two arguments
 */
void dispatch_timer(void)
{
    int tid, result;
    AlarmTimer* event;

    ENTER_TIMER_DISPATCHER;
    if (timer_list_empty()) {
        LEAVE_TIMER_DISPATCHER;
        return;
    }
    result = get_msecs_to_nexttimer();

    if (result == 0) {  /* i.e. a timer expired */
        result = get_next_event(&event);

        tid = event->timer_id;
        current_tid = tid;

        (*(event->action)) (tid, event->arg1, event->arg2);
        current_tid = 0;

        result = remove_timer(event);
        if (result) /* this can happen for a timeout that occurs on a deleted assoc ? */
            error_logi(ERROR_MAJOR, "remove_item returned %d", result);
    }
    LEAVE_TIMER_DISPATCHER;
    return;
}


void adl_add_msecs_totime(struct timeval *t, unsigned int msecs)
{
    long seconds = 0, microseconds = 0;
    struct timeval tmp, res;
    seconds = msecs / 1000;
    microseconds = (msecs % 1000) * 1000;
    tmp.tv_sec = seconds;
    tmp.tv_usec = microseconds;

    timeradd(t, &tmp, &res);
    memcpy(t, &res, sizeof(res));
    return;
}

/**
 * helper function for the sake of a cleaner interface :-)
 */
int adl_gettime(struct timeval *tv)
{
#ifdef WIN32
      struct timeb tb;
      ftime(&tb);
      tv->tv_sec=tb.time;
      tv->tv_usec=tb.millitm*1000;
   return 0;
#else
   return (gettimeofday(tv, (struct timezone *) NULL));
#endif
}

/**
 * function is to return difference in msecs between time a and b (i.e. a-b)
 * @param a later time (e.g. current time)
 * @param b earlier time
 * @return -1 if a is earlier than b, else msecs that passed from b to a
 */
int adl_timediff_to_msecs(struct timeval *a, struct timeval *b)
{
    struct timeval result;
    int retval;
    /* result = a-b */
    timersub(a, b, &result);
    retval = result.tv_sec * 1000 + result.tv_usec / 1000;
    event_logi(VVERBOSE, "Computed Time Difference : %d msecs", retval);
    return ((retval < 0) ? -1 : retval);
}

/**
 * function initializes the array of fds we want to use for listening to events
 * USE    POLL_FD_UNUSED to differentiate between used/unused fds !
 */
int init_poll_fds(void)
{
    int i;
    for (i = 0; i < NUM_FDS; i++) {
        assign_poll_fd(i, POLL_FD_UNUSED, 0);
      #ifdef WIN32
      fds[i]=-1;
#endif
    }
    num_of_fds = 0;
#ifdef WIN32
   fdnum=0;
#endif
    return (0);
}




/**
 *  function to check for events on all poll fds (i.e. open sockets), or else
 *  execute the next timer event. Executed timer events are removed from the list.
 *  Wrapper to poll() -- returns after timeout or read event
 *  @return  number of events that where seen on the socket fds, 0 for timer event, -1 for error
 *  @author  ajung, dreibh
 */
int adl_extendedEventLoop(void (*lock)(void* data), void (*unlock)(void* data), void* data)
{
    int result;
    unsigned int u_res;
    int msecs;



    if(lock != NULL) {
       lock(data);
    }

    msecs = get_msecs_to_nexttimer();

    /* returns -1 if no timer in list */
    /* if (msecs > GRANULARITY || msecs < 0) */
    if (msecs < 0)
        msecs = GRANULARITY;
    if (msecs == 0) {
        dispatch_timer();
        if(unlock != NULL) {
           unlock(data);
        }
        return (0);
    }

    /*  print_debug_list(INTERNAL_EVENT_0); */
    result = extendedPoll(poll_fds, &num_of_fds, msecs, lock, unlock, data);
    switch (result) {
    case -1:
        result = 0;
        break;
    case 0:
        dispatch_timer();
        break;
    default:
        u_res = (unsigned int) result;
        event_logi(INTERNAL_EVENT_0,
                   "############### %d Read Event(s) occurred -> dispatch_event() #############",
                   u_res);
        dispatch_event(result);
        break;
    }

    if(unlock != NULL) {
        unlock(data);
    }
    return (result);
}

/**
 *  function to check for events on all poll fds (i.e. open sockets), or else
 *  execute the next timer event. Executed timer events are removed from the list.
 *  Wrapper to poll() -- returns after timeout or read event
 *    @return  number of events that where seen on the socket fds, 0 for timer event, -1 for error
 *  @author  ajung
 *  @author  dreibh
 */
int adl_eventLoop()
{
#ifdef WIN32

   int n, ret,i, j;
   WSANETWORKEVENTS  ne;
   int length=0, hlen=0, msecs;
   union sockunion src, dest;
   struct ip *iph;
   struct sockaddr_in *src_in;
   unsigned short portnum;


   msecs = get_msecs_to_nexttimer();

   /* returns -1 if no timer in list */
   if (msecs < 0)
      msecs = GRANULARITY;
   if (msecs == 0) {
      dispatch_timer();
   return (0);
   }

   n = MsgWaitForMultipleObjects(2, handles, FALSE, msecs, QS_KEY);
      if (n==1 && idata.len>0)
      {
         for (i=0; i< NUM_FDS; i++)
         {

            if (event_callbacks[i]->sfd==0)
            {

               (*(event_callbacks[i]->action))(idata.buffer,idata.len);
               SetEvent(idata.eventback);
               memset(idata.buffer, 0, sizeof(idata.buffer));
               idata.len=0;
               break;
            }
         }
      }
      else if (n==0)
      {
         for (i=0; i<fdnum; i++)
         {
         ret = WSAEnumNetworkEvents(fds[i], hEvent, &ne);
            if (ret == SOCKET_ERROR)
            {
               error_log(ERROR_FATAL, "WSAEnumNetworkEvents() failed!");
               return (-1);
            }
            if (ne.lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE))
            {
               for (j=0; j<NUM_FDS; j++)
                  if (event_callbacks[i]->sfd==fds[i])
                  {
                  length = adl_receive_message(fds[i], rbuf, MAX_MTU_SIZE, &src, &dest);
                  portnum = ntohs(src.sin.sin_port);
                  if(length < 0) break;
                  event_logiiii(VERBOSE, "SCTP-Message on socket %u , len=%d, portnum=%d, sockunion family %u",
                     fds[i], length, portnum, sockunion_family(&src));

                    src_in = (struct sockaddr_in *) &src;
                    event_logi(VERBOSE, "IPv4/SCTP-Message from %s -> activating callback",
                               inet_ntoa(src_in->sin_addr));
                  iph = (struct ip *) rbuf;
                    hlen = (iph->ip_verlen & 0x0F) << 2;
               if (length < hlen)
               {
                        error_logii(ERROR_MINOR,
                                    "dispatch_event : packet too short (%d bytes) from %s",
                                    length, inet_ntoa(src_in->sin_addr));
                    } else
               {
                        length -= hlen;
                        mdi_receiveMessage(fds[i], &rbuf[hlen], length, &src, &dest);
                    }
                    break;
                  }

            }
         }
      }
      return 1;
#else

   return(adl_extendedEventLoop(NULL, NULL, NULL));
#endif
}


int adl_extendedGetEvents(void (*lock)(void* data), void (*unlock)(void* data), void* data)
{
   int result;
   unsigned int u_res;

   if(lock != NULL) {
     lock(data);
   }
   result = extendedPoll(poll_fds, &num_of_fds, 0, lock, unlock, data);
   if(unlock != NULL) {
     unlock(data);
   }

   switch (result) {
   case -1:
      result =  0;
     break;
   case 0:
      result =  0;
    break;
   default:
      u_res = (unsigned int) result;
      event_logi(INTERNAL_EVENT_0,
                 "############### %d Read Event(s) occurred -> dispatch_event()#############",
                 u_res);
      dispatch_event(result);
      result = 1;
    break;
   }

   return (result);
}


/**
 *     function to check for events on all poll fds (i.e. open sockets), or else
 *     execute the next timer event. Executed timer events are removed from the list.
 *  Wrapper to poll() -- returns at once or after a read event
 *    @return  0 if no file descriptor event occurred, -1 for error
 *    @author  ajung
 */
int adl_getEvents(void)
{
   return(adl_extendedGetEvents(NULL, NULL, NULL));
}


#ifdef WIN32

static DWORD WINAPI stdin_read_thread(void *param)
{
    struct input_data *indata = (struct input_data *) param;

    HANDLE inhandle;

    inhandle = GetStdHandle(STD_INPUT_HANDLE);

   while (ReadFile(inhandle, indata->buffer, sizeof(indata->buffer),
          &indata->len, NULL) && indata->len > 0)
   {
   SetEvent(indata->event);

   WaitForSingleObject(indata->eventback, INFINITE);
   memset(indata->buffer, 0, sizeof(indata->buffer));
    }
    indata->len = 0;
   memset(indata->buffer, 0, sizeof(indata->buffer));
    SetEvent(indata->event);

   return 0;
}
#endif


#ifdef SCTP_OVER_UDP
int open_dummy_socket(int family)
{
   struct sockaddr_in in;
   struct sockaddr_in6 in6;
   int sd;
   int on;

   if(family == AF_INET6) {
      memset(&in6, 0, sizeof(in6));
      in6.sin6_family = AF_INET6;
      in6.sin6_port   = htons(SCTP_OVER_UDP_UDPPORT);
   }
   else {
      memset(&in, 0, sizeof(in));
      in.sin_family = AF_INET;
      in.sin_port   = htons(SCTP_OVER_UDP_UDPPORT);
   }

   sd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
   if(sd < 0) {
      return -1;
   }

   on = 1;
   if(setsockopt(sd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) < 0) {
      close(sd);
      return -1;
   }

   if(family == AF_INET6) {
      if(bind(sd, (struct sockaddr*)&in6, sizeof(in6)) < 0) {
         return -1;
      }
   }
   else {
      if(bind(sd, (struct sockaddr*)&in, sizeof(in)) < 0) {
         return -1;
      }
   }

   return sd;
}
#endif


int adl_init_adaptation_layer(int * myRwnd)
{
    struct timeval curTime;
#ifdef WIN32
    WSADATA        wsaData;
    int            Ret;
#endif
#ifdef HAVE_IPV6
    int myRwnd6 = 32767;
#endif

#ifdef WIN32
    if ((Ret = WSAStartup(MAKEWORD(2,2), &wsaData)) != 0)
    {
        error_log(ERROR_FATAL, "WSAStartup failed.");
        return SCTP_SPECIFIC_FUNCTION_ERROR;
    }
   hEvent = WSACreateEvent();
    if (hEvent == NULL)
    {
        error_log(ERROR_FATAL, "WSACreateEvent() of hEvent failed!");
        return -1;
    }

   stdinevent = WSACreateEvent();
    if (stdinevent == NULL)
    {
        error_log(ERROR_FATAL, "WSACreateEvent() of stdinevent failed!");
        return -1;
    }

   handles[0]=hEvent;
   handles[1]=stdinevent;
#endif

    /* initialize random number generator */
    adl_gettime(&curTime);
#ifdef HAVE_RANDOM
    rstate[0] = curTime.tv_sec;
    rstate[1] = curTime.tv_usec;
    initstate(curTime.tv_sec, (char *) rstate, 8);
    setstate((char *) rstate);
#else
    /* FIXME: this may be too weak (better than nothing however) */
    srand(curTime.tv_usec);
#endif

    init_poll_fds();
    init_timer_list();
    /*  print_debug_list(INTERNAL_EVENT_0); */
    sctp_sfd = adl_open_sctp_socket(AF_INET, myRwnd);
    /* set a safe default */
    if (*myRwnd == -1) *myRwnd = 8192;

    if (sctp_sfd < 0) return sctp_sfd;

#ifdef SCTP_OVER_UDP
    dummy_sctp_udp = open_dummy_socket(AF_INET);
    if(dummy_sctp_udp < 0) {
        error_log(ERROR_MAJOR, "Could not open UDP dummy socket !");
        return dummy_sctp_udp;
    }
#endif

    /* we should - in a later revision - add back the a function that opens
       appropriate ICMP sockets (IPv4 and/or IPv6) and registers these with
       callback functions that also set PATH MTU correctly */
#ifdef HAVE_IPV6
    /* icmpv6_sfd = int adl_open_icmpv6_socket(); */
    sctpv6_sfd = adl_open_sctp_socket(AF_INET6, &myRwnd6);
    if (sctpv6_sfd < 0) {
        error_log(ERROR_MAJOR, "Could not open IPv6 socket - running IPv4 only !");
        sctpv6_sfd = -1;
    }
    else {
#ifdef SCTP_OVER_UDP
       dummy_sctpv6_udp = open_dummy_socket(AF_INET6);
       if(dummy_sctpv6_udp < 0) {
           error_log(ERROR_MAJOR, "Could not open UDP/IPv6 dummy socket !");
           sctpv6_sfd = -1;
       }
#endif
    }

    /* adl_register_socket_cb(icmpv6_sfd, adl_icmpv6_cb); */

    /* set a safe default */
    if (myRwnd6 == -1) *myRwnd = 8192;
#endif

    /* icmp_sfd = int adl_open_icmp_socket(); */
    /* adl_register_socket_cb(icmp_sfd, adl_icmp_cb); */

/* #if defined(HAVE_SETUID) && defined(HAVE_GETUID) */
     /* now we could drop privileges, if we did not use setsockopt() calls for IP_TOS etc. later */
     /* setuid(getuid()); */
/* #endif   */
     return 0;
}


/**
 * this function is supposed to open and bind a UDP socket listening on a port
 * to incoming udp pakets on a local interface (a local union sockunion address)
 * @param  me   pointer to a local address, that will trigger callback, if it receives UDP data
 * @param  scf  callback funtion that is called when data has arrived
 * @return new UDP socket file descriptor, or -1 if error ocurred
 */
int adl_registerUdpCallback(unsigned char me[],
                            unsigned short my_port,
                            sctp_socketCallback scf)
{
    int result, new_sfd;
    union sockunion my_address;

#ifdef WIN32
   error_log(ERROR_MAJOR, "WIN32: Registering ULP-Callbacks for UDP not installed !");
        return -1;
#endif
   if (ntohs(my_port) == 0) {
        error_log(ERROR_MAJOR, "Port 0 is not allowed ! Fix your program !");
        return -1;
    }
    if (adl_str2sockunion(me, &my_address) < 0) {
        error_logi(ERROR_MAJOR, "Could not convert address string %s !", me);
        return -1;
    }

    switch (sockunion_family(&my_address)) {
        case AF_INET:
            event_logi(VERBOSE, "Registering ULP-Callback for UDP socket on port %u",ntohs(my_port));
            my_address.sin.sin_port = htons(my_port);
            break;
#ifdef HAVE_IPV6
        case AF_INET6:
            event_logi(VERBOSE, "Registering ULP-Callback for UDPv6 socket on port %u",ntohs(my_port));
            my_address.sin6.sin6_port = htons(my_port);
            break;
#endif
        default:
            error_log(ERROR_MINOR, "UNKNOWN ADDRESS TYPE - CHECK YOUR PROGRAM !");
            break;
    }

    new_sfd = adl_open_udp_socket(&my_address);

    if (new_sfd != -1) {
        result = adl_register_fd_cb(new_sfd, EVENTCB_TYPE_UDP, POLLIN | POLLPRI, (void(*)(void *,void *))scf, NULL);
        event_logi(INTERNAL_EVENT_0, "Registered ULP-Callback: now %d registered callbacks !!!",result);
        return  new_sfd;
    }
    return -1;
}



int adl_unregisterUdpCallback(int udp_sfd)
{
    if (udp_sfd <= 0) return -1;
    if (udp_sfd == sctp_sfd) return -1;
#ifdef HAVE_IPV6
    if (udp_sfd == sctpv6_sfd) return -1;
#endif
    return adl_remove_cb(udp_sfd);
}


/**
 * this function is supposed to register a callback function for catching
 * input from the Unix STDIN file descriptor. We expect this to be useful
 * in test programs mainly, so it is provided here for convenience.
 * @param  scf  callback funtion that is called (when return is hit)
 * @return 0, or -1 if error ocurred
 */
int adl_registerUserCallback(int fd, sctp_userCallback sdf, void* userData, short int eventMask)
{
    int result;
   #ifdef WIN32
   error_log(ERROR_MAJOR, "WIN32: Registering User Callbacks not installed !");
        return -1;
#endif
    /* 0 is the standard input ! */
    result = adl_register_fd_cb(fd, EVENTCB_TYPE_USER, eventMask, (void (*) (void *,void *))sdf, userData);
    if (result != -1) {
        event_logii(EXTERNAL_EVENT,"----------> Registered User Callback: fd=%d result=%d -------\n", fd, result);
    }
    return result;
}

#ifndef WIN32
void readCallback(int fd, short int revents, short int* events, void* userData)
{
   int n;

   struct data *udata=(struct data *)userData;

   n=read(0,(char *)udata->dat, udata->len);
   ((sctp_StdinCallback )udata->cb)(udata->dat, n);
}
#endif

int adl_registerStdinCallback(sctp_StdinCallback sdf, char* buffer, int length)
{
    int result;


#ifdef WIN32
   unsigned long in_threadid;
   idata.event = stdinevent;
   idata.eventback = CreateEvent(NULL, FALSE, FALSE, NULL);

   if (!(stdin_thread_handle=CreateThread(NULL, 0, stdin_read_thread,
               &idata, 0, &in_threadid))) {
      fprintf(stderr, "Unable to create input thread\n");
      return -1;
    }

    result = adl_register_fd_cb(0, EVENTCB_TYPE_USER, 0, (void (*) (void *,void *))sdf, NULL);
#else
   struct data *userData;
   userData = (struct data*)malloc(sizeof (struct data));
    memset(userData, 0, sizeof(struct data));
   userData->dat=buffer;
   userData->len=length;
   userData->cb=(void (*) (void))sdf;
   result = adl_register_fd_cb(0, EVENTCB_TYPE_USER, POLLIN | POLLPRI, (void (*) (void *,void *))readCallback,userData);
#endif
   if (result != -1) {
        event_logii(EXTERNAL_EVENT,"----------> Registered Stdin Callback: fd=%d result=%d -------\n", 0, result);
    }
    return result;
}


int adl_unregisterStdinCallback()
{
    #ifdef WIN32
   TerminateThread(stdin_thread_handle,0);
   #endif
   adl_remove_poll_fd(0);
    return 0;
}



int adl_unregisterUserCallback(int fd)
{
    adl_remove_poll_fd(fd);
    return 0;
}


int
adl_register_socket_cb(gint sfd, sctp_socketCallback scf)
{
    return (adl_register_fd_cb(sfd, EVENTCB_TYPE_SCTP, POLLIN | POLLPRI, (void(*)(void *,void *))scf, NULL));
}


/**
 *      This function adds a callback that is to be called some time from now. It realizes
 *      the timer (in an ordered list).
 *      @param      milliseconds  action is to be started in milliseconds ms from now
 *      @param      action        pointer to a function to be executed, when timer goes off
 *      @return     returns an id value, that can be used to cancel a timer
 *      @author     ajung
 */
unsigned int adl_startMicroTimer(unsigned int seconds, unsigned int microseconds,
                            sctp_timerCallback timer_cb, int ttype, void *param1, void *param2)
{
    unsigned int result = 0;
    AlarmTimer* item;
    struct timeval talarm, delta, now;

    delta.tv_sec = seconds;
    /* make sure, user cannot confuse us :-) */
    delta.tv_sec += (microseconds / 1000000);  /* usually 0 */
    delta.tv_usec = (microseconds % 1000000);

    adl_gettime(&now);
    item = (AlarmTimer*)malloc(sizeof(AlarmTimer));
    if (item == NULL) return 0;

    timeradd(&now, &delta, &talarm);
    item->timer_type = ttype;
    item->action_time = talarm;
    item->action = timer_cb;
    item->arg1 = param1;
    item->arg2 = param2;
    result = insert_item(item);

    return (result);
}

unsigned int
adl_startTimer(unsigned int milliseconds, sctp_timerCallback timer_cb, int ttype,
                void *param1, void *param2)
{
    unsigned int secs, usecs;
    unsigned int result = 0;

    secs = milliseconds / 1000;
    usecs =  (milliseconds - (secs * 1000))*1000;
    result = adl_startMicroTimer(secs, usecs, timer_cb, ttype, param1, param2);
    return result;
}

/**
 *      This function adds a callback that is to be called some time from now. It realizes
 *      the timer (in an ordered list).
 *      @param      tid        timer-id of timer to be removed
 *      @return     returns 0 on success, 1 if tid not in the list, -1 on error
 *      @author     ajung
 */
int adl_stopTimer(unsigned int tid)
{
    if (tid != current_tid)
        return (remove_item(tid));
    else
        return 0;
}

/**
 *      Restarts a timer currently running
 *      @param      timer_id   the value returned by set_timer for a certain timer
 *      @param      milliseconds  action is to be started in milliseconds ms from now
 *      @return     new timer id , zero when there is an error (i.e. no timer)
 *      @author     ajung
 */
unsigned int adl_restartTimer(unsigned int timer_id, unsigned int milliseconds)
{
    unsigned int result;
    result = update_item(timer_id, milliseconds);
    event_logiii(VVERBOSE,
                 "Restarted Timer : timer_id = %u, msecs = %u, result = %u",
                 timer_id, milliseconds, result);
    return result;
}

unsigned int adl_restartMicroTimer(unsigned int timer_id, unsigned int seconds, unsigned int microseconds)
{
    unsigned int result;
    result = micro_update_item(timer_id, seconds, microseconds);
    event_logiiii(VVERBOSE,
                 "Restarted Micro-Timer : timer_id = %u, secs = %u, usecs=%u result = %u",
                 timer_id, seconds, microseconds, result);
    return result;

}


/**
 *    function to close a bound socket from our list of socket descriptors
 *    @param    sfd    socket file descriptor to be closed
 *    @return  0 on success, -1 for error, 1 if socket was not bound
 *    @author  ajung
 */
int adl_remove_cb(int sfd)
{
    int result;
#ifdef WIN32
   result = closesocket(sfd);
#else
    result = close(sfd);
#endif
    if (result < 0)
        error_log(ERROR_FATAL, "Close Socket resulted in an error");
    adl_remove_poll_fd(sfd);
    return result;
}

/**
 * An address filtering function
 * @param newAddress  a pointer to a sockunion address
 * @param flags       bit mask hiding (i.e. filtering) address classes
 * returns TRUE if address is not filtered, else FALSE if address is filtered by mask
 */
gboolean adl_filterInetAddress(union sockunion* newAddress, AddressScopingFlags  flags)
{
    switch (sockunion_family(newAddress)) {
        case AF_INET :
            event_log(VERBOSE, "Trying IPV4 address");
            if (
                (IN_MULTICAST(ntohl(newAddress->sin.sin_addr.s_addr)) && (flags & flag_HideMulticast)) ||
                (IN_EXPERIMENTAL(ntohl(newAddress->sin.sin_addr.s_addr)) && (flags & flag_HideReserved)) ||
                (IN_BADCLASS(ntohl(newAddress->sin.sin_addr.s_addr)) && (flags & flag_HideReserved)) ||
                ((INADDR_BROADCAST == ntohl(newAddress->sin.sin_addr.s_addr)) && (flags & flag_HideBroadcast))||
                ((INADDR_LOOPBACK == ntohl(newAddress->sin.sin_addr.s_addr)) && (flags & flag_HideLoopback)) ||
                ((INADDR_LOOPBACK != ntohl(newAddress->sin.sin_addr.s_addr)) && (flags & flag_HideAllExceptLoopback))||
      (ntohl(newAddress->sin.sin_addr.s_addr) == INADDR_ANY)
                ) {
            event_log(VERBOSE, "Filtering IPV4 address");
            return FALSE;
         }
         break;
#ifdef HAVE_IPV6
      case AF_INET6 :
 #if defined (LINUX)
        if (
            (!IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr.s6_addr)) && (flags & flag_HideAllExceptLoopback)) ||
            (IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr.s6_addr)) && (flags & flag_HideLoopback)) ||
            (IN6_IS_ADDR_LINKLOCAL(&(newAddress->sin6.sin6_addr.s6_addr)) && (flags & flag_HideLinkLocal)) ||
            (!IN6_IS_ADDR_LINKLOCAL(&(newAddress->sin6.sin6_addr.s6_addr)) && (flags & flag_HideAllExceptLinkLocal)) ||
            (!IN6_IS_ADDR_SITELOCAL(&(newAddress->sin6.sin6_addr.s6_addr)) && (flags & flag_HideAllExceptSiteLocal)) ||
            (IN6_IS_ADDR_SITELOCAL(&(newAddress->sin6.sin6_addr.s6_addr)) && (flags & flag_HideSiteLocal)) ||
            (IN6_IS_ADDR_MULTICAST(&(newAddress->sin6.sin6_addr.s6_addr)) && (flags & flag_HideMulticast)) ||
             IN6_IS_ADDR_UNSPECIFIED(&(newAddress->sin6.sin6_addr.s6_addr))
                 ) {
            event_log(VERBOSE, "Filtering IPV6 address");
            return FALSE;
        }
 #else
        if (
            (!IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr)) && (flags & flag_HideAllExceptLoopback)) ||
            (IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr)) && (flags & flag_HideLoopback)) ||
            (!IN6_IS_ADDR_LINKLOCAL(&(newAddress->sin6.sin6_addr)) && (flags & flag_HideAllExceptLinkLocal)) ||
            (!IN6_IS_ADDR_SITELOCAL(&(newAddress->sin6.sin6_addr)) && (flags & flag_HideAllExceptSiteLocal)) ||
            (IN6_IS_ADDR_LINKLOCAL(&(newAddress->sin6.sin6_addr)) && (flags & flag_HideLinkLocal)) ||
            (IN6_IS_ADDR_SITELOCAL(&(newAddress->sin6.sin6_addr)) && (flags & flag_HideSiteLocal)) ||
            (IN6_IS_ADDR_MULTICAST(&(newAddress->sin6.sin6_addr)) && (flags & flag_HideMulticast)) ||
             IN6_IS_ADDR_UNSPECIFIED(&(newAddress->sin6.sin6_addr))
                 ) {
            event_log(VERBOSE, "Filtering IPV6 address");
            return FALSE;
        }
 #endif
         break;
#endif
      default :
        event_log(VERBOSE, "Default : Filtering Address");
        return FALSE;
        break;
    }
    return TRUE;
}




/*
 * this is an ugly part to code, so it was taken an adapted from the
 * SCTP reference implementation by Randy Stewart
 * see http://www.sctp.org
 * returns TRUE is successful, else FALSE
 *
 * Changed by Stefan Jansen <stefan.jansen@gmx.de>, Aug 1st, 2002.
 * When going through the ifreq array, numAlocAddr was used as upper bound.
 * But at this time numAlocAddr counts also IPv6 addresses from
 * /proc/net/if_inet6 and is therefore too much. Thus I introduced a new
 * counter named numAlocIPv4Addr.
 * This error lead to a kernel error message because the kernel tried to load
 * a kernel module when the non-existing network devices were accessed on
 * SuSE Linux 7.3, kernel 2.4.16-4GB, GCC 2.95.3, glibc-2.2.4-64.
 *
 * Changed by Amedeo Bonfiglio <amedeo.bonfiglio@rcm.inet.it>, Dec 07 th, 2009.
 * When porting to Neutrino RTOS 6.4.1, ioctl(sctp_fd, SIOCGIFCONF) has been adapted
 * as shown in
 * http://www.qnx.com/developers/docs/6.4.0/io-pkt_en/user_guide/migrating.html#Coexistence
 * The modifications are controlled by #ifdef NEUTRINO_RTOS, but the modified code is applicable
 * to any OS.
 *
 */
gboolean adl_gatherLocalAddresses(union sockunion **addresses,
     int *numberOfNets,
     int sctp_fd,
     gboolean with_ipv6,
     int *max_mtu,
     const AddressScopingFlags  flags)

{

#ifdef WIN32
   union sockunion *localAddresses=NULL;

   SOCKET           s[MAXIMUM_WAIT_OBJECTS];
    WSAEVENT         hEvent[MAXIMUM_WAIT_OBJECTS];
    WSAOVERLAPPED    ol[MAXIMUM_WAIT_OBJECTS];
    struct addrinfo *local=NULL,hints,
                    *ptr=NULL;
    SOCKET_ADDRESS_LIST *slist=NULL;
    DWORD            bytes;
    char             addrbuf[ADDRESS_LIST_BUFFER_SIZE],host[NI_MAXHOST],serv[NI_MAXSERV];
    int              socketcount=0,
                     addrbuflen=ADDRESS_LIST_BUFFER_SIZE,
                     rc,i, j,hostlen = NI_MAXHOST,servlen = NI_MAXSERV;
   struct sockaddr_in Addr;


    /* Enumerate the local bind addresses - to wait for changes we only need
        one socket but to enumerate the addresses for a particular address
      family, we need a socket of that type  */

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    if ((rc = getaddrinfo(NULL,"0",&hints,&local))!=0)
    {
        local=NULL;
      fprintf(stderr, "Unable to resolve the bind address!\n");
        return -1;
    }

     /* Create a socket and event for each address returned*/
    ptr = local;
    while (ptr)
    {
        s[socketcount] = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (s[socketcount] == INVALID_SOCKET)
        {
            fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
            return -1;
        }

        hEvent[socketcount] = WSACreateEvent();
        if (hEvent == NULL)
        {
            fprintf(stderr, "WSACreateEvent failed: %d\n", WSAGetLastError());
            return -1;
        }

        socketcount++;

        ptr = ptr->ai_next;

        if (ptr && (socketcount > MAXIMUM_WAIT_OBJECTS))
        {
            printf("Too many address families returned!\n");
            break;
        }
    }

        for(i=0; i < socketcount ;i++)
        {
            memset(&ol[i], 0, sizeof(WSAOVERLAPPED));
            ol[i].hEvent = hEvent[i];
            if ((rc = WSAIoctl(s[i],SIO_ADDRESS_LIST_QUERY,NULL,0,addrbuf,addrbuflen,
                   &bytes,NULL, NULL))== SOCKET_ERROR)
            {
                fprintf(stderr, "WSAIoctl: SIO_ADDRESS_LIST_QUERY failed: %d\n", WSAGetLastError());
                return -1;
            }

            slist = (SOCKET_ADDRESS_LIST *)addrbuf;
         localAddresses = calloc(slist->iAddressCount,sizeof(union sockunion));
            for(j=0; j < slist->iAddressCount ;j++)
            {
            if ((rc = getnameinfo(slist->Address[j].lpSockaddr, slist->Address[j].iSockaddrLength,
               host,hostlen,serv,servlen,NI_NUMERICHOST | NI_NUMERICSERV))!=0)
               fprintf(stderr, "%s: getnameinfo failed: %d\n", __FILE__, rc);
            Addr.sin_family=slist->Address[j].lpSockaddr->sa_family;
            Addr.sin_addr.s_addr=inet_addr(host);
            memcpy(&((localAddresses)[j]),&Addr,sizeof(Addr));
            }

            /* Register for change notification*/
           if ((rc = WSAIoctl(s[i],SIO_ADDRESS_LIST_CHANGE,NULL,0,NULL,0,&bytes,&ol[i],NULL))== SOCKET_ERROR)
            {
                if (WSAGetLastError() != WSA_IO_PENDING)
                {
                    fprintf(stderr, "WSAIoctl: SIO_ADDRESS_LIST_CHANGE failed: %d\n", WSAGetLastError());
                    return -1;
                }
            }
        }

       freeaddrinfo(local);

    for(i=0; i < socketcount ;i++)
        closesocket(s[i]);

   *addresses = localAddresses;
    *numberOfNets=slist->iAddressCount;
   *max_mtu=1500;
   return TRUE;
#else
#if defined (LINUX)
    int addedNets;
    char addrBuffer[256];
    FILE *v6list;
    struct sockaddr_in6 sin6;
    int numAlocIPv4Addr = 0;
#endif

    char addrBuffer2[64];
    /* unsigned short intf_flags; */
    struct ifconf cf;
    int pos=0,copSiz=0,numAlocAddr=0,ii;
    char buffer[8192];
    struct sockaddr *toUse;
    int saveMTU = 1500; /* default maximum MTU for now */
#ifdef HAS_SIOCGLIFADDR
    struct if_laddrreq lifaddr;
#endif
    struct ifreq local;
    struct ifreq *ifrequest,*nextif;
    int dup,xxx,tmp;
    union sockunion * localAddresses = NULL;

    cf.ifc_buf = buffer;
    cf.ifc_len = 8192;
    *max_mtu = 0;
    *numberOfNets = 0;

    /* Now gather the master address information */
    if(ioctl(sctp_fd, SIOCGIFCONF, (char *)&cf) == -1) {
        return(FALSE);
    }

#ifdef USES_BSD_4_4_SOCKET
    for (pos = 0; pos < cf.ifc_len; ) {
        ifrequest = (struct ifreq *)&buffer[pos];
#ifdef SOLARIS
      pos += (sizeof(struct sockaddr) + sizeof(ifrequest->ifr_name));
#else
#ifdef NEUTRINO_RTOS
      if (ifrequest->ifr_addr.sa_len + IFNAMSIZ > sizeof(struct ifreq)) {
          pos += ifrequest->ifr_addr.sa_len + IFNAMSIZ;
      } else {
          pos += sizeof(struct ifreq);
      }
#else
        pos += (ifrequest->ifr_addr.sa_len + sizeof(ifrequest->ifr_name));

        if (ifrequest->ifr_addr.sa_len == 0) {
            /* if the interface has no address then you must
             * skip at a minium a sockaddr structure
             */
            pos += sizeof(struct sockaddr);
        }
#endif // NEUTRINO_RTOS
#endif
        numAlocAddr++;
    }
#else
    numAlocAddr = cf.ifc_len / sizeof(struct ifreq);
    /* ????????????  numAlocAddr++; */
    ifrequest = cf.ifc_req;
#endif
#if defined  (LINUX)
    numAlocIPv4Addr = numAlocAddr;
    addedNets = 0;
    v6list = fopen(LINUX_PROC_IPV6_FILE,"r");
    if (v6list != NULL) {
        while(fgets(addrBuffer,sizeof(addrBuffer),v6list) != NULL){
            addedNets++;
        }
        fclose(v6list);
    }
    numAlocAddr += addedNets;
    event_logii(VERBOSE, "Found additional %d v6 addresses, total now %d\n",addedNets,numAlocAddr);
#endif
    /* now allocate the appropriate memory */
    localAddresses = (union sockunion*)calloc(numAlocAddr,sizeof(union sockunion));

    if(localAddresses == NULL){
        error_log(ERROR_MAJOR, "Out of Memory in adl_gatherLocalAddresses() !");
        return(FALSE);
    }

     pos = 0;
     /* Now we go through and pull each one */

#if defined (LINUX)
    v6list = fopen(LINUX_PROC_IPV6_FILE,"r");
    if(v6list != NULL){
        memset((char *)&sin6,0,sizeof(sin6));
        sin6.sin6_family = AF_INET6;

        while(fgets(addrBuffer,sizeof(addrBuffer),v6list) != NULL){
            if(strncmp(addrBuffer,"00000000000000000000000000000001",32) == 0) {
                event_log(VVERBOSE, "At least I found the local IPV6 address !");
                if(inet_pton(AF_INET6,"::1",(void *)&sin6.sin6_addr) > 0){
                    sin6.sin6_family = AF_INET6;
                    memcpy(&((localAddresses)[*numberOfNets]),&sin6,sizeof(sin6));
                    event_logiiiii(VVERBOSE, "copied the local IPV6 address %x:%x:%x:%x, family %x",
                        sin6.sin6_addr.s6_addr32[3], sin6.sin6_addr.s6_addr32[2], sin6.sin6_addr.s6_addr32[1],
                        sin6.sin6_addr.s6_addr32[0], sin6.sin6_family);
                    (*numberOfNets)++;
                }
                continue;
            }
            memset(addrBuffer2,0,sizeof(addrBuffer2));
            strncpy(addrBuffer2,addrBuffer,4);
            addrBuffer2[4] = ':';
            strncpy(&addrBuffer2[5],&addrBuffer[4],4);
            addrBuffer2[9] = ':';
            strncpy(&addrBuffer2[10],&addrBuffer[8],4);
            addrBuffer2[14] = ':';
            strncpy(&addrBuffer2[15],&addrBuffer[12],4);
            addrBuffer2[19] = ':';
            strncpy(&addrBuffer2[20],&addrBuffer[16],4);
            addrBuffer2[24] = ':';
            strncpy(&addrBuffer2[25],&addrBuffer[20],4);
            addrBuffer2[29] = ':';
            strncpy(&addrBuffer2[30],&addrBuffer[24],4);
            addrBuffer2[34] = ':';
            strncpy(&addrBuffer2[35],&addrBuffer[28],4);

            if(inet_pton(AF_INET6,addrBuffer2,(void *)&sin6.sin6_addr) > 0){
                if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr)) {
                   sscanf((const char*)&addrBuffer[34], "%x", &sin6.sin6_scope_id);
                }
                memcpy(&((localAddresses)[*numberOfNets]),&sin6,sizeof(sin6));

            }else{
                error_logi(ERROR_FATAL, "Could not translate string %s",addrBuffer2);
            }
        }
        fclose(v6list);
    }
#endif

    /* set to the start, i.e. buffer[0] */
    ifrequest = (struct ifreq *)&buffer[pos];

#if defined (LINUX)
    for(ii=0; ii < numAlocIPv4Addr; ii++,ifrequest=nextif){
#else
    for(ii=0; ii < numAlocAddr; ii++,ifrequest=nextif){
#endif
#ifdef USES_BSD_4_4_SOCKET
        /* use the sa_len to calculate where the next one will be */
#ifdef SOLARIS
      pos += (sizeof(struct sockaddr) + sizeof(ifrequest->ifr_name));
#else
#ifdef NEUTRINO_RTOS
      if (ifrequest->ifr_addr.sa_len + IFNAMSIZ > sizeof(struct ifreq)) {
          pos += ifrequest->ifr_addr.sa_len + IFNAMSIZ;
      } else {
          pos += sizeof(struct ifreq);
      }
#else
        pos += (ifrequest->ifr_addr.sa_len + sizeof(ifrequest->ifr_name));

        if (ifrequest->ifr_addr.sa_len == 0){
            /* if the interface has no address then you must
             * skip at a minium a sockaddr structure
             */
            pos += sizeof(struct sockaddr);
        }
#endif // NEUTRINO_RTOS
#endif
        nextif = (struct ifreq *)&buffer[pos];
#else
        nextif = ifrequest + 1;
#endif

#ifdef _NO_SIOCGIFMTU_
        *max_mtu = DEFAULT_MTU_CEILING;
#else
        memset(&local, 0, sizeof(local));
        memcpy(local.ifr_name,ifrequest->ifr_name,IFNAMSIZ);
        event_logiii(VERBOSE, "Interface %d, NAME %s, Hex: %x",ii,local.ifr_name,local.ifr_name);

        if (ioctl(sctp_fd, SIOCGIFMTU, (char *)&local) == -1) {
            /* cant get the flags? */
            continue;
        }
        saveMTU = local.ifr_mtu;
        event_logii(VERBOSE, "Interface %d, MTU %d",ii,saveMTU);
#endif
        toUse = &ifrequest->ifr_addr;

        adl_sockunion2str((union sockunion*)toUse, (guchar *)addrBuffer2, SCTP_MAX_IP_LEN);
        event_logi(VERBOSE, "we are talking about the address %s", addrBuffer2);


        memset(&local, 0, sizeof(local));
        memcpy(local.ifr_name, ifrequest->ifr_name, IFNAMSIZ);

        if(ioctl(sctp_fd, SIOCGIFFLAGS, (char *)&local) == -1){
            /* can't get the flags, skip this guy */
            continue;
        }
        /* Ok get the address and save the flags */
        /*        intf_flags = local.ifr_flags; */

        if(!(local.ifr_flags & IFF_UP)) {
            /* Interface is down */
            continue;
        }


        if (flags & flag_HideLoopback){
            if (adl_filterInetAddress((union sockunion*)toUse, flag_HideLoopback) == FALSE){
                /* skip the loopback */
                event_logi(VERBOSE, "Interface %d, skipping loopback",ii);
                continue;
            }
        }
        if (adl_filterInetAddress((union sockunion*)toUse, flag_HideReserved) == FALSE) {
            /* skip reserved */
            event_logi(VERBOSE, "Interface %d, skipping reserved",ii);
            continue;
        }

        if(toUse->sa_family== AF_INET){
            copSiz = sizeof(struct sockaddr_in);
        } else if (toUse->sa_family == AF_INET6){
            copSiz = sizeof(struct sockaddr_in6);
        }
        if (*max_mtu < saveMTU) *max_mtu = saveMTU;

         /* Now, we may have already gathered this address, if so skip
          * it
          */
        event_logii(VERBOSE, "Starting checking for duplicates ! MTU = %d, nets: %d",saveMTU, *numberOfNets);

        if(*numberOfNets) {
            tmp = *numberOfNets;
            dup = 0;
            /* scan for the dup */
            for(xxx=0; xxx < tmp; xxx++) {
                event_logi(VERBOSE, "duplicates loop xxx=%d",xxx);
                if(adl_equal_address(&localAddresses[xxx], (union sockunion*)toUse)) {
#ifdef HAVE_IPV6
                   if((localAddresses[xxx].sa.sa_family == AF_INET6) &&
                      (toUse->sa_family == AF_INET) &&
                      (IN6_IS_ADDR_V4MAPPED(&localAddresses[xxx].sin6.sin6_addr) ||
                       IN6_IS_ADDR_V4COMPAT(&localAddresses[xxx].sin6.sin6_addr))) {
                      /* There are multiple interfaces, one has ::ffff:a.b.c.d or
                         ::a.b.c.d address. Use address which is IPv4 native instead. */
                      memcpy(&localAddresses[xxx], toUse, sizeof(localAddresses[xxx]));
                   }
                   else {
#endif
                      event_log(VERBOSE, "Interface %d, found duplicate");
                      dup = 1;
#ifdef HAVE_IPV6
                   }
#endif
                }
            }
            if(dup) {
                /* skip the duplicate name/address we already have it*/
                continue;
            }
        }

        /* copy address */
        event_logi(VVERBOSE, "Copying %d bytes",copSiz);
        memcpy(&localAddresses[*numberOfNets],(char *)toUse,copSiz);
        event_log(VVERBOSE, "Setting Family");
        /* set family */
        (&(localAddresses[*numberOfNets]))->sa.sa_family = toUse->sa_family;

#ifdef USES_BSD_4_4_SOCKET
#ifndef SOLARIS
        /* copy the length */
        (&(localAddresses[*numberOfNets]))->sa.sa_len = toUse->sa_len;
#endif
#endif
        (*numberOfNets)++;
        event_logii(VERBOSE, "Interface %d, Number of Nets: %d",ii, *numberOfNets);
    }

    event_logi(VERBOSE, "adl_gatherLocalAddresses: Found %d addresses", *numberOfNets);
    for(ii = 0; ii < (*numberOfNets); ii++) {
        adl_sockunion2str(&(localAddresses[ii]), (guchar *)addrBuffer2, SCTP_MAX_IP_LEN);
        event_logii(VERBOSE, "adl_gatherAddresses : Address %d: %s",ii, addrBuffer2);

    }
    *addresses = localAddresses;
    return(TRUE);
#endif
}

