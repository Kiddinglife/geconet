#include "poller.h"
#include <stdlib.h>

#ifdef USE_UDP
static uint inet_checksum(const void* ptr, size_t count)
{
    ushort* addr = (ushort*)ptr;
    uint sum = 0;

    while (count > 1)
    {
        sum += *(ushort*)addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(uchar*)addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (~sum);
}
#endif

int str2saddr(sockaddrunion *su, const char * str, ushort hs_port, bool ip4)
{
    int ret;
    memset((void*)su, 0, sizeof(union sockaddrunion));

    if (hs_port <= 0)
    {
        error_log(loglvl_major_error_abort, "Invalid port \n");
        return -1;
    }

    if (ip4)
    {
        if (str != NULL && strlen(str) > 0)
        {
#ifndef WIN32
            ret = inet_aton(str, &su->sin.sin_addr);
#else
            (su->sin.sin_addr.s_addr = inet_addr(str)) == INADDR_NONE ? ret = 0 : ret = 1;
#endif
        }
        else
        {
            event_log(loglvl_verbose, "no s_addr specified, set to all zeros\n");
            ret = 1;
        }

        if (ret > 0)  /* Valid IPv4 address format. */
        {
            su->sin.sin_family = AF_INET;
            su->sin.sin_port = htons(hs_port);
#ifdef HAVE_SIN_LEN
            su->sin.sin_len = sizeof(struct sockaddr_in);
#endif                          
            return 0;
        }
    }
    else
    {
        if (str != NULL && strlen(str) > 0)
        {
            ret = inet_pton(AF_INET6, (const char *)str, &su->sin6.sin6_addr);
        }
        else
        {
            event_log(loglvl_verbose, "no s_addr specified, set to all zeros\n");
            ret = 1;
        }

        if (ret > 0)     /* Valid IPv6 address format. */
        {
            su->sin6.sin6_family = AF_INET6;
            su->sin6.sin6_port = htons(hs_port);
#ifdef SIN6_LEN
            su->sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif      
            su->sin6.sin6_scope_id = 0;
            return 0;
        }
    }
    return -1;
}
int saddr2str(sockaddrunion *su, char * buf, size_t len)
{

    if (su->sa.sa_family == AF_INET)
    {
        if (len > 16) len = 16;
        strncpy(buf, inet_ntoa(su->sin.sin_addr), len);
        return (1);
    }
    else if (su->sa.sa_family == AF_INET6)
    {
        char        ifnamebuffer[IFNAMSIZ];
        const char* ifname = 0;

        if (inet_ntop(AF_INET6, &su->sin6.sin6_addr, buf, len) == NULL) return 0;
        if (IN6_IS_ADDR_LINKLOCAL(&su->sin6.sin6_addr))
        {
#ifdef _WIN32
            NET_LUID luid;
            ConvertInterfaceIndexToLuid(su->sin6.sin6_scope_id, &luid);
            ifname = (char*)ConvertInterfaceLuidToNameA(&luid, (char*)&ifnamebuffer, IFNAMSIZ);
#else
            ifname = if_indextoname(su->sin6.sin6_scope_id, (char*)&ifnamebuffer);
#endif
            if (ifname == NULL)
            {
                return(0);   /* Bad scope ID! */
            }
            if (strlen(buf) + strlen(ifname) + 2 >= len)
            {
                return(0);   /* Not enough space! */
            }
            strcat(buf, "%");
            strcat(buf, ifname);
        }
        return (1);
    }
    return 0;
}
bool saddr_equals(sockaddrunion *a, sockaddrunion *b)
{
    switch (saddr_family(a))
    {
        case AF_INET:
            return
                saddr_family(b) == AF_INET &&
                s4addr(&a->sin) == s4addr(&b->sin) &&
                a->sin.sin_port == b->sin.sin_port;
            break;
        case AF_INET6:
            return saddr_family(b) == AF_INET6 &&
                a->sin6.sin6_port == b->sin6.sin6_port &&
                memcmp(s6addr(&a->sin6), s6addr(&b->sin6),
                sizeof(s6addr(&a->sin6)) == 0);
            break;
        default:
            error_logi(loglvl_major_error_abort,
                "Address family %d not supported",
                saddr_family(a));
            return false;
            break;
    }
}

int poller_t::remove_socket_despt(int sfd)
{
    int i, counter = 0;
    for (i = 0; i < MAX_FD_SIZE; i++)
    {
        if (socket_despts[i].fd == sfd)
        {
            socket_despts[i].fd = POLL_FD_UNUSED;
            socket_despts[i].events = 0;
            socket_despts[i].revents = 0;
            socket_despts[i].revision = 0;
            event_callbacks[i] = NULL;
        }
    }
    return 0;
}

int network_interface_t::init_poller(int * myRwnd, bool ip4)
{
    // create handles
#ifdef WIN32
    WSADATA        wsaData;
    int Ret = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (Ret != 0)
    {
        error_log(loglvl_fatal_error_exit, "WSAStartup failed!\n");
        return -1;
    }

    poller_.hEvent_ = WSACreateEvent();
    if (poller_.hEvent_ == NULL)
    {
        error_log(loglvl_fatal_error_exit, "WSACreateEvent() of hEvent_ failed!\n");
        return -1;
    }

    poller_.stdin_event_ = WSACreateEvent();
    if (poller_.stdin_event_ == NULL)
    {
        error_log(loglvl_fatal_error_exit, "WSACreateEvent() of stdin_event_ failed!\n");
        return -1;
    }

    poller_.handles_[0] = poller_.hEvent_;
    poller_.handles_[1] = poller_.stdin_event_;
#endif

    struct timeval curTime;
    if (gettimenow(&curTime) != 0)
    {
        error_log(loglvl_fatal_error_exit, "gettimenow() failed!\n");
        return -1;
    }

    /* initialize random number generator */
    /* FIXME: this may be too weak (better than nothing however) */
    srand(curTime.tv_usec);

    /*init members */
    poller_.revision_ = 0;
    poller_.socket_despts_size_ = 0;
#ifdef WIN32
    poller_.fdnum = 0;
#endif

    /*initializes the array of fds we want to use for listening to events
    POLL_FD_UNUSED to differentiate between used/unused fds !*/
    for (int i = 0; i < MAX_FD_SIZE; i++)
    {
        poller_.set_event_mask(i, POLL_FD_UNUSED, 0); // init geco socket despts 
#ifdef WIN32
        poller_.fds[i] = POLL_FD_UNUSED; // init windows fds
#endif
    }

    //open geco socket depst
    if (ip4)
    {
        ip4_socket_despt_ = open_ipproto_geco_socket(AF_INET, myRwnd);
        if (ip4_socket_despt_ < 0) return -1;
    }
    else
    {
        ip6_socket_despt_ = open_ipproto_geco_socket(AF_INET6, myRwnd);
        if (ip6_socket_despt_ < 0) return -1;
    }
    if (*myRwnd == -1) *myRwnd = DEFAULT_RWND_SIZE;     /* set a safe default */

    //open udp socket despt binf to dummy sadress 0.0.0.0 to recv all datagrams
    // destinated to any adress with matched port
#ifdef USE_UDP
    sockaddrunion su;
    str2saddr(&su, NULL, USED_UDP_PORT, ip4);
    if (ip4)
    {
        dummy_ipv4_udp_despt_ = open_ipproto_udp_socket(&su, myRwnd);
        if (dummy_ipv4_udp_despt_ < 0)
        {
            error_log(loglvl_major_error_abort, "Could not open UDP dummy socket !\n");
            return dummy_ipv4_udp_despt_;
        }
        event_logi(loglvl_verbose,
            "init_poller()::dummy_ipv4_udp_despt_(%u)", 
            dummy_ipv4_udp_despt_);
    }
    else
    {
        dummy_ipv6_udp_despt_ = open_ipproto_udp_socket(&su, myRwnd);
        if (dummy_ipv6_udp_despt_ < 0)
        {
            error_log(loglvl_major_error_abort, "Could not open UDP dummy socket !\n");
            return dummy_ipv6_udp_despt_;
        }
        event_logi(loglvl_verbose,
            "init_poller()::dummy_ipv6_udp_despt_(%u)",
            dummy_ipv6_udp_despt_);
    }
#endif
    return 0;
}
int poller_t::poll_socket_despts(socket_despt_t* despts,
    int* count,
    int timeout,
    void(*lock)(void* data),
    void(*unlock)(void* data),
    void* data)
{
    struct timeval tv;
    struct timeval* to;

    fd_set            rd_fdset;;
    fd_set            wt_fdset;
    fd_set            except_fdset;
    int               fdcount;
    int               n;
    int               ret;
    int i;

    // fill timeval 
    if (timeout < 0)
    {
        to = nullptr;
    }
    else
    {
        to = &tv;
        fills_timeval(to, timeout);
    }

    // Initialize structures for select() 
    fdcount = 0;
    n = 0;
    FD_ZERO(&rd_fdset);
    FD_ZERO(&wt_fdset);
    FD_ZERO(&except_fdset);

    for (i = 0; i < (*count); i++)
    {
        // only filter out the illegal fd less than zero, 
        // if it is a no-evevent-specified-fd,
        // we  treats it as correct fd as select() will detect what event happened on it.
        if (despts[i].fd < 0) continue;
        n = MAX(n, despts[i].fd);
        if (despts[i].events & (POLLIN | POLLPRI))
        {
            FD_SET(despts[i].fd, &rd_fdset);
        }
        if (despts[i].events & POLLOUT) {
            FD_SET(despts[i].fd, &wt_fdset);
        }
        if (despts[i].events & (POLLIN | POLLOUT)) {
            FD_SET(despts[i].fd, &except_fdset);
        }
        fdcount++;
    }

    if (fdcount == 0)
    {
        ret = 0; // fds are all illegal we return zero, means no events triggered
    }
    else
    {
        //Set the revision number of all entries to the current revision.
        for (i = 0; i < *count; i++)
        {
            despts[i].revision = this->revision_;
        }

        /*
        * Increment the revision_ number by one -> New entries made by
        * another thread during select() call will get this new revision_ number.
        */
        ++this->revision_;

        if (unlock)
        {
            unlock(data);
        }

        ret = select(n + 1, &rd_fdset, &wt_fdset, &except_fdset, to);

        if (lock)
        {
            lock(data);
        }

        for (i = 0; i < *count; i++)
        {
            despts[i].revents = 0;
            /*If despts's revision is equal or greater than the current revision, then the despts entry
            * has been added by another thread during the poll() call.
            * If this is the case, clr all fdsets to skip the event results
            * (they will be reported again when select() is called the next timeout).*/
            if (despts[i].revision >= this->revision_)
            {
                FD_CLR(despts[i].fd, &rd_fdset);
                FD_CLR(despts[i].fd, &wt_fdset);
                FD_CLR(despts[i].fd, &except_fdset);
            }
        }

        // ret >0 means some events occured, we need handle them
        if (ret > 0)
        {
            for (i = 0; i < *count; i++)
            {
                despts[i].revents = 0;
                if (despts[i].revision < revision_)
                {
                    if ((despts[i].events & POLLIN) && FD_ISSET(despts[i].fd, &rd_fdset))
                    {
                        despts[i].revents |= POLLIN;
                    }
                    if ((despts[i].events & POLLOUT) && FD_ISSET(despts[i].fd, &wt_fdset))
                    {
                        despts[i].revents |= POLLOUT;
                    }
                    if ((despts[i].events & (POLLIN | POLLOUT)) && FD_ISSET(despts[i].fd, &except_fdset))
                    {
                        despts[i].revents |= POLLERR;
                    }
                }
            }
        }
    }

    return ret;
}

int network_interface_t::set_sockdespt_recvbuffer_size(int sfd, int new_size)
{
    int new_sizee = 0;
    socklen_t opt_size = sizeof(int);
    if (getsockopt(sfd, SOL_SOCKET, SO_RCVBUF,
        (char*)&new_sizee, &opt_size) < 0)
    {
        return -1;
    }
    else
    {
        event_logi(loglvl_verbose, "init receive buffer size is : %d bytes", new_sizee);
    }

    if (setsockopt(sfd, SOL_SOCKET, SO_RCVBUF,
        (const char*)&new_size, sizeof(new_size)) < 0)
    {
        return -1;
    }

    // then test if we set it correctly
    new_sizee = new_size;
    opt_size = sizeof(int);
    if (getsockopt(sfd, SOL_SOCKET, SO_RCVBUF,
        (char*)&new_sizee, &opt_size) < 0
        || new_size != new_sizee)
    {
        return -1;
    }
    else
    {
        event_logi(loglvl_verbose, "settled receive buffer size is : %u bytes", new_size);
        return new_size;
    }
}
int network_interface_t::open_ipproto_geco_socket(int af, int* rwnd)
{
    int sockdespt;
    int optval;
    socklen_t opt_size;

    if (rwnd == NULL)
    {
        int val = DEFAULT_RWND_SIZE;
        rwnd = &val;
    }
    else
    {
        if (*rwnd < DEFAULT_RWND_SIZE) //default recv size is 1mb 
            *rwnd = DEFAULT_RWND_SIZE;
    }


#ifdef USE_UDP
    sockdespt = socket(af, SOCK_RAW, IPPROTO_UDP);
#else
    sockdespt = socket(af, SOCK_RAW, IPPROTO_GECO);
#endif
    if (sockdespt < 0)
    {
        error_logi(loglvl_major_error_abort, "socket()  return  %d !\n", sockdespt);
        return sockdespt;
    }

#ifdef WIN32
    struct sockaddr_in me;
    /* binding to INADDR_ANY to make Windows happy... */
    memset((void *)&me, 0, sizeof(me));
    me.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
    me.sin_len = sizeof(me);
#endif
    me.sin_addr.s_addr = INADDR_ANY; // bind any can recv all  ip packets
    bind(sockdespt, (const struct sockaddr *)&me, sizeof(me));
#endif

    //setup recv buffer option
    *rwnd = set_sockdespt_recvbuffer_size(sockdespt, *rwnd); // 655360 bytes
    if (*rwnd < 0)
    {
        error_logi(loglvl_major_error_abort,
            "setsockopt: Try to set SO_RCVBUF {%d} but failed !",
            *rwnd);
    }

    //setup mtu discover option
    /**
    IP_PMTU_DISCOVER
    为套接字设置或接收Path MTU Discovery setting(路径MTU发现设置).
    当允许时,Linux会在该套接字上执行定义于RFC1191中的Path MTU Discovery(路径MTU发现).
    don't 段标识会设置在所有外发的数据报上. 系统级别的缺省值是这样的：
    SOCK_STREAM 套接字由 ip_no_pmtu_disc sysctl 控制，
    而对其它所有的套接字都被都屏蔽掉了，
    对于非 SOCK_STREAM 套接字而言, 用户有责任按照MTU的大小对数据分块并在必要的情况
    下进行中继重发.如果设置了该标识 (用 EMSGSIZE ),内核会拒绝比已知路径MTU更大的包.

    Path MTU discovery(路径MTU发现)标识	含义
    IP_PMTUDISC_WANT	对每条路径进行设置.
    IP_PMTUDISC_DONT	从不作Path MTU Discovery(路径MTU发现).
    IP_PMTUDISC_DO	总作Path MTU Discovery(路径MTU发现).

    当允许 PMTU （路径MTU）搜索时, 内核会自动记录每个目的主机的path MTU(路径MTU).
    当它使用 connect(2) 连接到一个指定的对端机器时,可以方便地使用 IP_MTU 套接字选项检索
    当前已知的 path MTU(路径MTU)(比如，在发生了一个 EMSGSIZE 错误后).它可能随着时间的
    推移而改变. 对于带有许多目的端的非连接的套接字,一个特定目的端的新到来的 MTU 也可
    以使用错误队列(参看 IP_RECVERR) 来存取访问.

    新的错误会为每次到来的 MTU 的更新排队等待.
    当进行 MTU 搜索时,来自数据报套接字的初始包可能会被丢弃.
    使用 UDP 的应用程序应该知道这个并且考虑其包的中继传送策略.
    为了在未连接的套接字上引导路径 MTU 发现进程, 我们可以用一个大的数据报(头尺寸超过
    64K字节)启动, 并令其通过更新路径 MTU 逐步收缩. 为了获得路径MTU连接的初始估计,
    可通过使用 connect(2) 把一个数据报套接字连接到目的地址,
    并通过调用带 IP_MTU选项的 getsockopt(2) 检索该MTU.

    IP_MTU
    检索当前套接字的当前已知路径MTU.只有在套接字被连接时才是有效的.返回一个整数.
    只有作为一个 getsockopt(2) 才有效.
    */
#if defined (__linux__)
    optval = IP_PMTUDISC_DO;
    if (setsockopt(sockdespt, IPPROTO_IP, IP_MTU_DISCOVER,
        (char *)&optval, sizeof(optval)) < 0)
    {
        error_log(loglvl_major_error_abort, "setsockopt: IP_PMTU_DISCOVER failed !");
    }

    // test to make sure we set it correctly
    opt_size = sizeof(int);
    if (getsockopt(sockdespt, SOL_SOCKET, IP_MTU_DISCOVER,
        (char*)optval, &opt_size) < 0)
    {
        error_log(loglvl_major_error_abort, "getsockopt: SO_RCVBUF failed !");
    }
    else
    {
        event_logi(loglvl_intevent, "setsockopt: IP_PMTU_DISCOVER succeed!", optval);
    }
#endif

    /* also receive packetinfo for IPv6 sockets, for getting dest address */
    if (af == AF_INET6)
    {
        int optval = 1;
#ifdef HAVE_IPV6_RECVPKTINFO
        /* IMPORTANT:
        The new option name is now IPV6_RECVPKTINFO!
        IPV6_PKTINFO expects an extended parameter structure now
        and had to be replaced to provide the original functionality! */
        if (setsockopt(sockdespt, IPPROTO_IPV6, IPV6_RECVPKTINFO,
            (const char*)&optval, sizeof(optval)) < 0)
        {
            return -1;
        }
#else
        if (setsockopt(sockdespt, IPPROTO_IPV6, IPV6_PKTINFO,
            (const char*)&optval, sizeof(optval)) < 0)
        {
            return -1;
        }
#endif
    }

    event_logii(loglvl_verbose,
        "Created raw socket %d, recv buffer %d with options\n",
        sockdespt, *rwnd);
    return (sockdespt);
}
int network_interface_t::open_ipproto_udp_socket(sockaddrunion* me, int* rwnd)
{
    char buf[IFNAMSIZ];
    int ch, sfd;
    int af;

    if (rwnd == NULL)
    {
        int val = DEFAULT_RWND_SIZE;
        rwnd = &val;
    }
    else
    {
        if (*rwnd < DEFAULT_RWND_SIZE) //default recv size is 1mb 
            *rwnd = DEFAULT_RWND_SIZE;
    }

    switch (saddr_family(me))
    {
        case AF_INET:
            af = AF_INET;
            break;
        case AF_INET6:
            af = AF_INET6;
            break;
        default:
            error_log(loglvl_major_error_abort, "upd ip4 socket() failed!\n");
            break;
    }

    /*If IPPROTO_IP(0) is specified, the caller does not wish to specify a protocol
    and the serviceprovider will choose the protocol to use.*/
    if ((sfd = socket(af, SOCK_DGRAM, IPPROTO_IP)) < 0)
    {
        error_log(loglvl_major_error_abort, "upd ip4 socket() failed!\n");
    }

    if (*rwnd < DEFAULT_RWND_SIZE) //default recv size is 1mb 
        *rwnd = DEFAULT_RWND_SIZE;

    //setup recv buffer option
    *rwnd = set_sockdespt_recvbuffer_size(sfd, *rwnd); // 650KB
    if (*rwnd < 0)
    {
        error_logi(loglvl_major_error_abort,
            "setsockopt: Try to set SO_RCVBUF {%d} but failed !",
            *rwnd);
    }

    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&ch, sizeof(ch)) < 0)
    {
        //close(sd);
        error_log(loglvl_major_error_abort, "setsockopt: Try to set SO_REUSEADDR but failed !");
        return -1;
    }

    /* we only recv theudp datagrams destinated to this ip address */
    ch = bind(sfd, &me->sa, sizeof(struct sockaddr_in));
    if (ch < 0)
    {
        error_log(loglvl_major_error_abort, "bind() failed, please check if adress exits !\n");
        return -1;
    }


    saddr2str(me, buf, IFNAMSIZ);
    event_logiii(loglvl_verbose,
        "open_ipproto_udp_socket : Create socket %d, recvbuf %d, binding to address %s",
        sfd, *rwnd, buf);
    return (sfd);
}
int network_interface_t::send_udp_msg(int sfd, char* buf, int length, sockaddrunion* destsu)
{
    if (sfd <= 0)
    {
        error_log(loglvl_major_error_abort, "send UDP data on an invalid fd!\n");
        return -1;
    }

    if (length <= 0)
    {
        error_log(loglvl_major_error_abort, "Invalid length!\n");
        return -1;
    }

    if (buf == NULL)
    {
        error_log(loglvl_major_error_abort, "Invalid buf in send_udp_msg(%s)\n");
        return -1;
    }

    if (sfd == this->ip4_socket_despt_ || sfd == this->ip6_socket_despt_)
    {
        error_log(loglvl_major_error_abort, "cannot send UDP msg on a geco socket!\n");
        return -1;
    }

    //if (dest_port == 0)
    //{
    //    error_log(loglvl_major_error_abort, "Invalid port \n");
    //    return -1;
    //}

    //sockaddrunion destsu;
    //if (str2saddr(&destsu, destination, dest_port, ip4_socket_despt_ > 0) < 0)
    //{
    //    error_logi(loglvl_major_error_abort,
    //        "Invalid destination address in send_udp_msg(%s)\n", destination);
    //    return -1;
    //}

    //int destlen;
    int result;
    switch (saddr_family(destsu))
    {
        case AF_INET:
            //destsu.sin.sin_port = htons(dest_port);
            result = sendto(sfd, buf, length, 0,
                (struct sockaddr *) &(destsu->sin), sizeof(struct sockaddr_in));
            break;
        case AF_INET6:
            //destsu.sin6.sin6_port = htons(dest_port);
            result = sendto(sfd, buf, length, 0,
                (struct sockaddr *) &(destsu->sin6), sizeof(struct sockaddr_in6));
            break;
        default:
            error_log(loglvl_major_error_abort, "Invalid AF address family in send_udp_msg()\n");
            result = -1;
            break;
    }
    event_logi(loglvl_verbose, "send_udp_msg(%d bytes data)", result);
    return result;
}

int network_interface_t::send_geco_msg(int sfd, char *buf, int len,
    sockaddrunion *dest, char tos)
{
    printf("%d\n", ntohs(dest->sin.sin_port));
    int txmt_len = 0;
    char old_tos;
    socklen_t opt_len;
    int tmp;

#ifdef USE_UDP
    // len is the length of chunks ,
    // len+NETWORK_PACKET_FIXED_SIZE is the length of the total packet
    // here we test if the default udp send buffer cannot hold this packet
    int packet_total_length = len + NETWORK_PACKET_FIXED_SIZE;
    if (sizeof(internal_udp_send__buffer_) < packet_total_length)
    {
        error_log(loglvl_fatal_error_exit, "msg is too large ! bye !\n");
        return -1;
    }

    memcpy(&internal_udp_send__buffer_[NETWORK_PACKET_FIXED_SIZE], buf, len);
    udp_hdr_ptr_ = (network_packet_fixed_t*)&internal_udp_send__buffer_;
    udp_hdr_ptr_->src_port = htons(USED_UDP_PORT);
    udp_hdr_ptr_->dest_port = htons(USED_UDP_PORT);
    udp_hdr_ptr_->length = htons(packet_total_length);
    udp_hdr_ptr_->checksum = 0x0000;
#endif

    switch (saddr_family(dest))
    {
        case AF_INET:
            opt_len = sizeof(old_tos);
            tmp = getsockopt(sfd, IPPROTO_IP, IP_TOS, &old_tos, &opt_len);
            if (tmp < 0)
            {
                error_log(loglvl_major_error_abort, "getsockopt(IP_TOS) failed!\n");
                return -1;
            }
            tmp = setsockopt(sfd, IPPROTO_IP, IP_TOS, &tos, sizeof(char));
            if (tmp < 0)
            {
                error_log(loglvl_major_error_abort, "setsockopt(tos) failed!\n");
                return -1;
            }
            event_logiiiiii(loglvl_verbose, "AF_INET :: send_geco_msg : set IP_TOS %u, result=%d, sfd : %d, len %d, destination : %s::%u\n",
                tos, tmp, sfd, len, inet_ntoa(dest->sin.sin_addr), ntohs(dest->sin.sin_port));

#ifdef USE_UDP
            txmt_len = sendto(sfd, internal_udp_send__buffer_, packet_total_length,
                0, (struct sockaddr *) &(dest->sin), sizeof(struct sockaddr_in));
            if (txmt_len >= (int)NETWORK_PACKET_FIXED_SIZE)
            {
                txmt_len -= (int)NETWORK_PACKET_FIXED_SIZE;
            }
#else
            txmt_len = sendto(sfd, buf, len, 0,
                (struct sockaddr *) &(dest->sin), sizeof(struct sockaddr_in));
#endif
            break;

        case AF_INET6:
            char hostname[IFNAMSIZ];
            if (inet_ntop(AF_INET6, s6addr(dest), (char *)hostname, IFNAMSIZ) == NULL)
            {
                error_log(loglvl_major_error_abort, "inet_ntop()  buffer is too small !\n");
                return -1;
            }
            event_logiiii(loglvl_verbose,
                "AF_INET6 :: send_geco_msg :sfd : %d, len %d, destination : %s::%u\n",
                sfd, len, hostname, ntohs(dest->sin6.sin6_port));

#ifdef USE_UDP
            txmt_len = sendto(sfd, (char*)&internal_udp_send__buffer_, packet_total_length, 0,
                (struct sockaddr *) &(dest->sin6), sizeof(struct sockaddr_in6));
            if (txmt_len >= (int)NETWORK_PACKET_FIXED_SIZE)
            {
                txmt_len -= (int)NETWORK_PACKET_FIXED_SIZE;
            }
#else
            txmt_len = sendto(sfd, buf, len, 0,
                (struct sockaddr *)&(dest->sin6), sizeof(struct sockaddr_in6));
#endif
            break;
        default:
            error_logi(loglvl_major_error_abort,
                "no such Adress Family %u !\n",
                saddr_family(dest));
            return -1;
            break;
    }

    stat_send_event_size_++;
    stat_send_bytes_ += len;
    event_logii(loglvl_verbose,
        "stat_send_event_size_ %u, stat_send_bytes_ %u\n",
        stat_send_event_size_, stat_send_bytes_);

    return txmt_len;
}