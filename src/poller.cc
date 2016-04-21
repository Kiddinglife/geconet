
#include "poller.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef WIN32
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
#ifdef SCTP_OVER_UDP
#include <netinet/udp.h>
#endif
#include <asm/types.h>
#include <linux/rtnetlink.h>
#define LINUX_PROC_IPV6_FILE "/proc/net/if_inet6"
#else
#include <winsock2.h>
#include <WS2tcpip.h>
#include <sys/timeb.h>
#define ADDRESS_LIST_BUFFER_SIZE        4096
struct ip
{
    uchar version_length;
    uchar typeofservice;        /* type of service */
    ushort length;             /* total length */
    ushort identification;              /* identification */
    ushort  fragment_offset;             /* fragment offset field */
    uchar ttl;       /* time to live */
    uchar protocol;            /* protocol */
    ushort checksum;             /* checksum */
    struct in_addr src_addr; /* source and dest address */
    struct in_addr dst_addr;
};

#define IFNAMSIZ 64   /* Windows has no IFNAMSIZ. Just define it. */
#endif