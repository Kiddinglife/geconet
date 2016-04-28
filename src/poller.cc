#include "poller.h"
#include <stdlib.h>

static void safe_close_soket(int sfd)
{
    if (sfd <= 0)
    {
        error_log(major_error_abort, "invalid sfd!\n");
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
        error_logi(major_error_abort,
                "safe_cloe_soket()::close socket failed! {%d} !\n",
                WSAGetLastError());
#else
        error_logi(major_error_abort,
                "safe_cloe_soket()::close socket failed! {%d} !\n", errno);
#endif
    }
}

#ifdef _WIN32
static inline int writev(int sock, const struct iovec *iov, int nvecs)
{
    DWORD ret;
    if (WSASend(sock, (LPWSABUF)iov, nvecs, &ret, 0, NULL, NULL) == 0)
    {
        return ret;
    }
    return -1;
}
static inline int readv(int sock, const struct iovec *iov, int nvecs)
{
    DWORD ret;
    if (WSARecv(sock, (LPWSABUF)iov, nvecs, &ret, 0, NULL, NULL) == 0)
    {
        return ret;
    }
    return -1;
}

static LPFN_WSARECVMSG recvmsg = NULL;
static LPFN_WSARECVMSG getwsarecvmsg()
{
    LPFN_WSARECVMSG lpfnWSARecvMsg = NULL;
    GUID guidWSARecvMsg = WSAID_WSARECVMSG;
    SOCKET sock = INVALID_SOCKET;
    DWORD dwBytes = 0;
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (SOCKET_ERROR == WSAIoctl(sock,
                    SIO_GET_EXTENSION_FUNCTION_POINTER,
                    &guidWSARecvMsg,
                    sizeof(guidWSARecvMsg),
                    &lpfnWSARecvMsg,
                    sizeof(lpfnWSARecvMsg),
                    &dwBytes,
                    NULL,
                    NULL
            ))
    {
        error_log(major_error_abort,
                "WSAIoctl SIO_GET_EXTENSION_FUNCTION_POINTER\n");
        return NULL;
    }
    safe_close_soket(sock);
    return lpfnWSARecvMsg;
}
#endif

static uint udp_checksum(const void* ptr, size_t count)
{
    ushort* addr = (ushort*) ptr;
    uint sum = 0;

    while (count > 1)
    {
        sum += *(ushort*) addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(uchar*) addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (~sum);
}

int str2saddr(sockaddrunion *su, const char * str, ushort hs_port, bool ip4)
{
    int ret;
    memset((void*) su, 0, sizeof(union sockaddrunion));

    if (hs_port <= 0)
    {
        error_log(major_error_abort, "Invalid port \n");
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
            event_log(verbose, "no s_addr specified, set to all zeros\n");
            ret = 1;
        }

        if (ret > 0) /* Valid IPv4 address format. */
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
            ret = inet_pton(AF_INET6, (const char *) str, &su->sin6.sin6_addr);
        }
        else
        {
            event_log(verbose, "no s_addr specified, set to all zeros\n");
            ret = 1;
        }

        if (ret > 0) /* Valid IPv6 address format. */
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
        if (len > 16)
            len = 16;
        strncpy(buf, inet_ntoa(su->sin.sin_addr), len);
        return (1);
    }
    else if (su->sa.sa_family == AF_INET6)
    {
        char ifnamebuffer[IFNAMSIZ];
        const char* ifname = 0;

        if (inet_ntop(AF_INET6, &su->sin6.sin6_addr, buf, len) == NULL)
            return 0;
        if (IN6_IS_ADDR_LINKLOCAL(&su->sin6.sin6_addr))
        {
#ifdef _WIN32
            NET_LUID luid;
            ConvertInterfaceIndexToLuid(su->sin6.sin6_scope_id, &luid);
            ifname = (char*)ConvertInterfaceLuidToNameA(&luid, (char*)&ifnamebuffer, IFNAMSIZ);
#else
            ifname = if_indextoname(su->sin6.sin6_scope_id,
                    (char*) &ifnamebuffer);
#endif
            if (ifname == NULL)
            {
                return (0); /* Bad scope ID! */
            }
            if (strlen(buf) + strlen(ifname) + 2 >= len)
            {
                return (0); /* Not enough space! */
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
        s4addr(&a->sin) == s4addr(&b->sin)
                && a->sin.sin_port == b->sin.sin_port;
        break;
    case AF_INET6:
        return saddr_family(b) == AF_INET6
                && a->sin6.sin6_port == b->sin6.sin6_port
                && memcmp(s6addr(&a->sin6), s6addr(&b->sin6),
                        sizeof(s6addr(&a->sin6)) == 0);
        break;
    default:
        error_logi(major_error_abort, "Address family %d not supported",
                saddr_family(a));
        return false;
        break;
    }
}

void poller_t::init()
{
    socket_despts_size_ = 0;
    revision_ = 0;

#ifdef _WIN32
    win32_fdnum_ = 0;
    win32_handler_ = win32_stdin_handler_ = 0;
    memset(win32_handlers_, 0, sizeof(win32_handlers_));
#endif

    /*initializes the array of win32_fds_ we want to use for listening to events
     POLL_FD_UNUSED to differentiate between used/unused win32_fds_ !*/
    for (int i = 0; i < MAX_FD_SIZE; i++)
    {
        set_event_on_geco_sdespt(i, POLL_FD_UNUSED, 0); // init geco socket despts 
#ifdef WIN32
                win32_fds_[i] = POLL_FD_UNUSED; // init windows win32_fds_
#endif
    }
}

#ifdef _WIN32
void poller_t::set_event_on_win32_sdespt(int fd_index, int sfd)
{
    if ((WSAEventSelect(sfd,
                            win32_handler_,
                            FD_READ | FD_WRITE |
                            FD_ACCEPT | FD_CLOSE | FD_CONNECT))
            == SOCKET_ERROR)
    {
        error_logi(loglvl_fatal_error_exit, "WSAEventSelect(%d) failed\n", WSAGetLastError());
    }

    win32_fds_[fd_index] = sfd;
}
#endif

void poller_t::set_event_on_geco_sdespt(int fd_index, int sfd, int event_mask)
{
    if (fd_index > MAX_FD_SIZE)
        error_log(loglvl_fatal_error_exit,
                "FD_Index bigger than MAX_FD_SIZE ! bye !\n");

    socket_despts[fd_index].event_handler_index = fd_index;
    socket_despts[fd_index].fd = sfd; /* file descriptor */
    socket_despts[fd_index].events = event_mask;
    /*
     * Set the entry's revision to the current poll_socket_despts() revision.
     * If another thread is currently inside poll_socket_despts(), poll_socket_despts()
     * will notify that this entry is new and skip the possibly wrong results
     * until the next invocation.
     */
    socket_despts[fd_index].revision = revision_;
    socket_despts[fd_index].revents = 0;
}

int poller_t::remove_socket_despt(int sfd)
{
    int counter = 0;
    int i, j;

#ifdef _WIN32
    for (i = 0; i < win32_fdnum_; i++)
    {

        if (win32_fds_[i] == sfd)
        {
            counter++;
            if (i == socket_despts_size_ - 1)
            {
                win32_fds_[i] = POLL_FD_UNUSED;
                win32_fdnum_--;
                break;
            }

            // counter a same fd, we start scan from end
            // replace it with a different valid sfd
            for (j = win32_fdnum_ - 1; j >= i; j--)
            {
                if (win32_fds_[j] == sfd)
                {
                    if (j == i)
                    counter--;
                    counter++;
                    win32_fds_[j] = POLL_FD_UNUSED;
                    win32_fdnum_--;
                }
                else
                {
                    // swap it
                    win32_fds_[i] = win32_fds_[j];
                    win32_fds_[j] = POLL_FD_UNUSED;
                    win32_fdnum_--;
                    break;
                }
            }
        }
    }
#else
    for (i = 0; i < socket_despts_size_; i++)
    {
        if (socket_despts[i].fd == sfd)
        {
            counter++;
            if (i == socket_despts_size_ - 1)
            {
                socket_despts[i].fd = POLL_FD_UNUSED;
                socket_despts[i].events = 0;
                socket_despts[i].revents = 0;
                socket_despts[i].revision = 0;
                socket_despts_size_--;
                break;
            }

            // counter a same fd, we start scan from end
            // replace it with a different valid sfd
            for (j = socket_despts_size_ - 1; j >= i; j--)
            {
                if (socket_despts[j].fd == sfd)
                {
                    if (j == i)
                        counter--;
                    counter++;
                    socket_despts[j].fd = POLL_FD_UNUSED;
                    socket_despts[j].events = 0;
                    socket_despts[j].revents = 0;
                    socket_despts[j].revision = 0;
                    socket_despts_size_--;
                }
                else
                {
                    // swap it
                    socket_despts[i].fd = socket_despts[j].fd;
                    socket_despts[i].events = socket_despts[j].events;
                    socket_despts[i].revents = socket_despts[j].revents;
                    socket_despts[i].revision = socket_despts[j].revision;
                    int temp = socket_despts[i].event_handler_index;
                    socket_despts[i].event_handler_index =
                            socket_despts[j].event_handler_index;

                    socket_despts[j].event_handler_index = temp;
                    socket_despts[j].fd = POLL_FD_UNUSED;
                    socket_despts[j].events = 0;
                    socket_despts[j].revents = 0;
                    socket_despts[j].revision = 0;

                    socket_despts_size_--;
                    break;
                }
            }
        }
    }
#endif
    event_logii(major_error_abort, "remove %d sfd(%d)\n", counter, sfd);
    return counter;
}
int poller_t::remove_event_handler(int sfd)
{
    safe_close_soket(sfd);
    return remove_socket_despt(sfd);
}
void poller_t::add_event_handler(int sfd, int eventcb_type, int event_mask,
        void (*action)(), void* userData)
{

    if (sfd <= 0)
    {
        error_log(loglvl_fatal_error_exit, "invlaid sfd ! \n");
        return;
    }

    if (socket_despts_size_ >= MAX_FD_SIZE
#ifdef WIN32
    || win32_fdnum_ >= MAX_FD_SIZE
#endif
    )
    {
        error_log(major_error_abort,
                "FD_Index bigger than MAX_FD_SIZE ! bye !\n");
        return;
    }

#ifdef WIN32
    set_event_on_win32_sdespt(win32_fdnum_, sfd);
    win32_fdnum_++;
#else
    set_event_on_geco_sdespt(socket_despts_size_, sfd, event_mask);
    socket_despts_size_++;
    int index = socket_despts[socket_despts_size_ - 1].event_handler_index;
    event_callbacks[index].sfd = sfd;
    event_callbacks[index].eventcb_type = eventcb_type;
    event_callbacks[index].action = action;
    event_callbacks[index].userData = userData;
#endif
}
int poller_t::poll_timers()
{
    if (this->timer_mgr_.empty())
        return -1;

    int result = timer_mgr_.timeouts();
    if (result == 0) // this timer has timeouts
    {
        timer_mgr::timer_id_t tid = timer_mgr_.get_front_timer();
        tid->action(tid->timer_id, tid->arg1, tid->arg2);
        timer_mgr_.delete_timer(tid);
    }
    return result;
}
//TODO
void poller_t::fire_event(int num_of_events)
{

}

int poller_t::poll(void (*lock)(void* data), void (*unlock)(void* data),
        void* data)
{
#ifdef WIN32
//TODO
#else
    if (lock != NULL)
           lock(data);

       int msecs = poll_timers();
       if (unlock != NULL)
           unlock(data);

       // timer timeouts
       if (msecs == 0)
           return msecs;

       // no timers, we use a default timeout for select
       if (msecs < 0)
           msecs = GRANULARITY;

       return poll_fds(socket_despts, &socket_despts_size_, msecs, lock,
               unlock, data);
#endif
}
int network_interface_t::init(int * myRwnd, bool ip4)
{
    /*initializes the array of win32_fds_ we want to use for listening to events
     POLL_FD_UNUSED to differentiate between used/unused win32_fds_ !*/
    poller_.init();

// create handles
#ifdef WIN32
    WSADATA wsaData;
    int Ret = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (Ret != 0)
    {
        error_log(loglvl_fatal_error_exit, "WSAStartup failed!\n");
        return -1;
    }

    poller_.win32_handler_ = WSACreateEvent();
    if (poller_.win32_handler_ == NULL)
    {
        error_log(loglvl_fatal_error_exit, "WSACreateEvent() of win32_handler_ failed!\n");
        return -1;
    }

    poller_.win32_stdin_handler_ = WSACreateEvent();
    if (poller_.win32_stdin_handler_ == NULL)
    {
        error_log(loglvl_fatal_error_exit, "WSACreateEvent() of win32_stdin_handler_ failed!\n");
        return -1;
    }

    poller_.win32_handlers_[0] = poller_.win32_handler_;
    poller_.win32_handlers_[1] = poller_.win32_stdin_handler_;

    if (recvmsg == NULL)
    {
        recvmsg = getwsarecvmsg();
    }

#endif

// generate random number
    struct timeval curTime;
    if (gettimenow(&curTime) != 0)
    {
        error_log(loglvl_fatal_error_exit, "gettimenow() failed!\n");
        return -1;
    }
    else
    {
        /* FIXME: this may be too weak (better than nothing however) */
        srand(curTime.tv_usec);
    }

    /*open geco socket depst*/
    if (ip4)
    {
        ip4_socket_despt_ = open_ipproto_geco_socket(AF_INET, myRwnd);
        if (ip4_socket_despt_ < 0)
            return -1;
    }
    else
    {
        ip6_socket_despt_ = open_ipproto_geco_socket(AF_INET6, myRwnd);
        if (ip6_socket_despt_ < 0)
            return -1;
    }

    if (*myRwnd == -1)
        *myRwnd = DEFAULT_RWND_SIZE; /* set a safe default */

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
            error_log(major_error_abort,
                    "Could not open UDP dummy socket !\n");
            return dummy_ipv4_udp_despt_;
        }
        event_logi(verbose, "init()::dummy_ipv4_udp_despt_(%u)",
                dummy_ipv4_udp_despt_);
    }
    else
    {
        dummy_ipv6_udp_despt_ = open_ipproto_udp_socket(&su, myRwnd);
        if (dummy_ipv6_udp_despt_ < 0)
        {
            error_log(major_error_abort,
                    "Could not open UDP dummy socket !\n");
            return dummy_ipv6_udp_despt_;
        }
        event_logi(verbose, "init()::dummy_ipv6_udp_despt_(%u)",
                dummy_ipv6_udp_despt_);
    }
#endif

    // FIXME
    /* we should - in a later revision - add back the a function that opens
     appropriate ICMP sockets (IPv4 and/or IPv6) and registers these with
     callback functions that also set PATH MTU correctly */
    /* icmp_socket_despt = int open_icmp_socket(); */
    /* adl_register_socket_cb(icmp_socket_despt, adl_icmp_cb); */

    /* #if defined(HAVE_SETUID) && defined(HAVE_GETUID) */
    /* now we could drop privileges, if we did not use setsockopt() calls for IP_TOS etc. later */
    /* setuid(getuid()); */
    /* #endif   */
    return 0;
}

int poller_t::poll_fds(socket_despt_t* despts, int* count,
        int timeout, void (*lock)(void* data), void (*unlock)(void* data),
        void* data)
{
    struct timeval tv;
    struct timeval* to;
    if (timeout < 0) // -1 means no timers added
    {
        to = NULL;
    }
    else
    {
        to = &tv;
        fills_timeval(to, timeout);
    }

    int ret;
    int i;
    int fdcount = 0;
    int nfd = 0;
    fd_set rd_fdset;
    fd_set wt_fdset;
    fd_set except_fdset;
    FD_ZERO(&rd_fdset);
    FD_ZERO(&wt_fdset);
    FD_ZERO(&except_fdset);

    if (lock != NULL)
    {
        lock(data);
    }

    for (i = 0; i < (*count); i++)
    {
        nfd = MAX(nfd, despts[i].fd);
        if (despts[i].events & (POLLIN | POLLPRI))
        {
            FD_SET(despts[i].fd, &rd_fdset);
        }
        if (despts[i].events & POLLOUT)
        {
            FD_SET(despts[i].fd, &wt_fdset);
        }
        if (despts[i].events & (POLLIN | POLLOUT))
        {
            FD_SET(despts[i].fd, &except_fdset);
        }
        fdcount++;
    }

    if (unlock)
    {
        unlock(data);
    }

    if (fdcount == 0)
    {
        ret = 0; // win32_fds_ are all illegal we return zero, means no events triggered
    }
    else
    {
        if (lock != NULL)
        {
            lock(data);
        }

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

        //  nfd is the max fd number plus one
        ret = select(nfd + 1, &rd_fdset, &wt_fdset, &except_fdset, to);

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
            event_logi(verbose,
                    "############### event %d occurred, dispatch it#############",
                    (unsigned int )ret);

            for (i = 0; i < *count; i++)
            {
                despts[i].revents = 0;
                if (despts[i].revision < revision_)
                {
                    if ((despts[i].events & POLLIN)
                            && FD_ISSET(despts[i].fd, &rd_fdset))
                    {
                        despts[i].revents |= POLLIN;
                    }
                    if ((despts[i].events & POLLOUT)
                            && FD_ISSET(despts[i].fd, &wt_fdset))
                    {
                        despts[i].revents |= POLLOUT;
                    }
                    if ((despts[i].events & (POLLIN | POLLOUT))
                            && FD_ISSET(despts[i].fd, &except_fdset))
                    {
                        despts[i].revents |= POLLERR;
                    }
                }
            }
            this->fire_event(ret);
        }
        else if (ret == 0) //timeouts
        {
            poll_timers();
        }
        else // -1 error
        {
            if (unlock)
            {
                unlock(data);
            }
            error_logi(major_error_abort, "select()  return -1 , errorno %d!\n",
                    errno);
        }

        if (unlock)
        {
            unlock(data);
        }
    }
    return ret;
}

int network_interface_t::set_sockdespt_recvbuffer_size(int sfd, int new_size)
{
    int new_sizee = 0;
    socklen_t opt_size = sizeof(int);
    if (getsockopt(sfd, SOL_SOCKET, SO_RCVBUF, (char*) &new_sizee, &opt_size)
            < 0)
    {
        return -1;
    }
    event_logi(verbose, "init receive buffer size is : %d bytes", new_sizee);

    if (setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, (char*) &new_size,
            sizeof(new_size)) < 0)
    {
        return -1;
    }

// then test if we set it correctly
    if (getsockopt(sfd, SOL_SOCKET, SO_RCVBUF, (char*) &new_sizee, &opt_size)
            < 0)
    {
        return -1;
    }

    event_logii(verbose,
            "line 648 expected buffersize %d, actual buffersize %d", new_size,
            new_sizee);
    return new_sizee;
}

int network_interface_t::open_ipproto_geco_socket(int af, int* rwnd)
{
    int sockdespt;
    int optval;
    socklen_t opt_size = sizeof(int);

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
    sockdespt = socket(af, SOCK_RAW, IPPROTO_UDP); // do we really need this?
#else
    sockdespt = socket(af, SOCK_RAW, IPPROTO_GECO);
#endif
    if (sockdespt < 0)
    {
        error_logii(major_error_abort, "socket()  return  %d, errorno %d!\n",
                sockdespt, errno);
        return sockdespt;
    }

    sockaddrunion me;
    memset((void *) &me, 0, sizeof(me));
    if (af == AF_INET)
    {
        /* binding to INADDR_ANY to make Windows happy... */
        me.sin.sin_family = AF_INET;
        // bind any can recv all  ip packets
        me.sin.sin_addr.s_addr = INADDR_ANY;
#ifdef HAVE_SIN_LEN
        me.sin_len = sizeof(me);
#endif
        //#ifdef USE_UDP
        //        str2saddr(&me, "127.0.0.1", USED_UDP_PORT, true);
        //#endif
    }
    else
    {
        /* binding to INADDR_ANY to make Windows happy... */
        me.sin6.sin6_family = AF_INET6;
        // bind any can recv all  ip packets
        memset(&me.sin6.sin6_addr.s6_addr, 0, sizeof(struct in6_addr));
#ifdef HAVE_SIN_LEN
        me.sin_len = sizeof(me);
#endif

        //#ifdef USE_UDP
        //        str2saddr(&me, "::1", USED_UDP_PORT, false);
        //#endif
    }
    bind(sockdespt, (const struct sockaddr *) &me.sa, sizeof(struct sockaddr));

//setup recv buffer option
    *rwnd = set_sockdespt_recvbuffer_size(sockdespt, *rwnd); // 655360 bytes
    if (*rwnd < 0)
    {
        safe_close_soket(sockdespt);
        error_logii(major_error_abort,
                "setsockopt: Try to set SO_RCVBUF {%d} but failed errno %d\n!",
                *rwnd, errno);
    }

    if (setsockopt(sockdespt, SOL_SOCKET, SO_REUSEADDR, (char*) &optval,
            opt_size) < 0)
    {
        safe_close_soket(sockdespt);
#ifdef _WIN32
        error_logi(major_error_abort,
                "setsockopt: Try to set SO_REUSEADDR but failed ! {%d} !\n",
                WSAGetLastError());
#else
        error_logi(major_error_abort,
                "setsockopt: Try to set SO_REUSEADDR but failed ! !\n", errno);
#endif
        return -1;
    }

//setup mtu discover option
#if defined (__linux__)
    optval = IP_PMTUDISC_DO;
    if (setsockopt(sockdespt, IPPROTO_IP, IP_MTU_DISCOVER,
            (const char *) &optval, optval) < 0)
    {
        safe_close_soket(sockdespt);
        error_log(major_error_abort, "setsockopt: IP_PMTU_DISCOVER failed !");
    }

// test to make sure we set it correctly
    if (getsockopt(sockdespt, SOL_SOCKET, IP_MTU_DISCOVER, (char*) &optval,
            &opt_size) < 0)
    {
        safe_close_soket(sockdespt);
        error_log(major_error_abort, "getsockopt: SO_RCVBUF failed !");
    }
    else
    {
        event_logi(loglvl_intevent, "setsockopt: IP_PMTU_DISCOVER succeed!",
                optval);
    }
#endif

    /* also receive packetinfo for IPv6 sockets, for getting dest address */
    if (af == AF_INET6)
    {
        optval = 1;
#ifdef HAVE_IPV6_RECVPKTINFO
        /* IMPORTANT:
         The new option name is now IPV6_RECVPKTINFO!
         IPV6_PKTINFO expects an extended parameter structure now
         and had to be replaced to provide the original functionality! */
        if (setsockopt(sockdespt, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                        (const char*)&optval, sizeof(optval)) < 0)
        {
            safe_close_soket(sockdespt);
            return -1;
        }
#else
        if (setsockopt(sockdespt, IPPROTO_IPV6, IPV6_PKTINFO,
                (const char*) &optval, optval) < 0)
        {
            safe_close_soket(sockdespt);
            return -1;
        }
#endif
    }

    event_logii(verbose, "Created raw socket %d, recv buffer %d with options\n",
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
        error_log(major_error_abort, "upd ip4 socket() failed!\n");
        break;
    }

    /*If IPPROTO_IP(0) is specified, the caller does not wish to specify a protocol
     and the serviceprovider will choose the protocol to use.*/
    if ((sfd = socket(af, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
#ifdef _WIN32
        error_logi(major_error_abort,
                "upd ip4 socket() failed error code (%d)!\n",
                WSAGetLastError());
#else
        error_logi(major_error_abort,
                "upd ip4 socket() failed error code (%d)!\n", errno);
#endif
    }

    if (*rwnd < DEFAULT_RWND_SIZE) //default recv size is 1mb
        *rwnd = DEFAULT_RWND_SIZE;

//setup recv buffer option
    *rwnd = set_sockdespt_recvbuffer_size(sfd, *rwnd); // 650KB
    if (*rwnd < 0)
    {
#ifdef _WIN32
        error_logi(major_error_abort,
                "setsockopt: Try to set SO_RCVBUF {%d} but failed {%d} !\n",
                *rwnd, WSAGetLastError());
#else
        error_logii(major_error_abort,
                "setsockopt: Try to set SO_RCVBUF {%d} but failed {%d} !\n",
                *rwnd, errno);
#endif
    }

    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char*) &ch, sizeof(ch))
            < 0)
    {
        safe_close_soket(sfd);
#ifdef _WIN32
        error_logi(major_error_abort,
                "setsockopt: Try to set SO_REUSEADDR but failed ! {%d} !\n",
                WSAGetLastError());
#else
        error_logi(major_error_abort,
                "setsockopt: Try to set SO_REUSEADDR but failed ! !\n", errno);
#endif
        return -1;
    }

    /* we only recv theudp datagrams destinated to this ip address */
    ch = bind(sfd, &me->sa, sizeof(struct sockaddr_in));
    if (ch < 0)
    {
        safe_close_soket(sfd);
        error_log(major_error_abort,
                "bind() failed, please check if adress exits !\n");
        return -1;
    }

    saddr2str(me, buf, IFNAMSIZ);
    event_logiii(verbose,
            "open_ipproto_udp_socket : Create socket %d, recvbuf %d, binding to address %s",
            sfd, *rwnd, buf);
    return (sfd);
}

int network_interface_t::send_udp_msg(int sfd, char* buf, int length,
        sockaddrunion* destsu)
{
    if (sfd <= 0)
    {
        error_log(major_error_abort, "send UDP data on an invalid fd!\n");
        return -1;
    }

    if (length <= 0)
    {
        error_log(major_error_abort, "Invalid length!\n");
        return -1;
    }

    if (buf == NULL)
    {
        error_log(major_error_abort, "Invalid buf in send_udp_msg(%s)\n");
        return -1;
    }

    if (sfd == this->ip4_socket_despt_ || sfd == this->ip6_socket_despt_)
    {
        error_log(major_error_abort, "cannot send UDP msg on a geco socket!\n");
        return -1;
    }

//int destlen;
    int result;
    switch (saddr_family(destsu))
    {
    case AF_INET:
        //destsu.sin.sin_port = htons(dest_port);
        result = sendto(sfd, buf, length, 0, (struct sockaddr *) &(destsu->sin),
                sizeof(struct sockaddr_in));
        break;
    case AF_INET6:
        //destsu.sin6.sin6_port = htons(dest_port);
        result = sendto(sfd, buf, length, 0,
                (struct sockaddr *) &(destsu->sin6),
                sizeof(struct sockaddr_in6));
        break;
    default:
        error_log(major_error_abort,
                "Invalid AF address family in send_udp_msg()\n");
        result = -1;
        break;
    }
    event_logi(verbose, "send_udp_msg(%d bytes data)", result);
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
    size_t packet_total_length = len + NETWORK_PACKET_FIXED_SIZE;
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
            error_log(major_error_abort, "getsockopt(IP_TOS) failed!\n");
            return -1;
        }
        tmp = setsockopt(sfd, IPPROTO_IP, IP_TOS, &tos, sizeof(char));
        if (tmp < 0)
        {
            error_log(major_error_abort, "setsockopt(tos) failed!\n");
            return -1;
        }
        event_logiiiiii(verbose,
                "AF_INET :: send_geco_msg : set IP_TOS %u, result=%d, sfd : %d, len %d, destination : %s::%u\n",
                tos, tmp, sfd, len, inet_ntoa(dest->sin.sin_addr),
                ntohs(dest->sin.sin_port));

#ifdef USE_UDP
        txmt_len = sendto(sfd, internal_udp_send__buffer_, packet_total_length,
                0, (struct sockaddr *) &(dest->sin),
                sizeof(struct sockaddr_in));
        if (txmt_len >= (int)NETWORK_PACKET_FIXED_SIZE)
        {
            txmt_len -= (int)NETWORK_PACKET_FIXED_SIZE;
        }
#else
        txmt_len = sendto(sfd, buf, len, 0, (struct sockaddr *) &(dest->sin),
                sizeof(struct sockaddr_in));
#endif
        break;

    case AF_INET6:
        char hostname[IFNAMSIZ];
        if (inet_ntop(AF_INET6, s6addr(dest), (char *) hostname,
        IFNAMSIZ) == NULL)
        {
            error_log(major_error_abort,
                    "inet_ntop()  buffer is too small !\n");
            return -1;
        }
        event_logiiii(verbose,
                "AF_INET6 :: send_geco_msg :sfd : %d, len %d, destination : %s::%u\n",
                sfd, len, hostname, ntohs(dest->sin6.sin6_port));

#ifdef USE_UDP
        txmt_len = sendto(sfd, (char*)&internal_udp_send__buffer_,
                packet_total_length, 0, (struct sockaddr *) &(dest->sin6),
                sizeof(struct sockaddr_in6));
        if (txmt_len >= (int)NETWORK_PACKET_FIXED_SIZE)
        {
            txmt_len -= (int)NETWORK_PACKET_FIXED_SIZE;
        }
#else
        txmt_len = sendto(sfd, buf, len, 0, (struct sockaddr *) &(dest->sin6),
                sizeof(struct sockaddr_in6));
#endif
        break;
    default:
        error_logi(major_error_abort, "no such Adress Family %u !\n",
                saddr_family(dest));
        return -1;
        break;
    }

    stat_send_event_size_++;
    stat_send_bytes_ += len;
    event_logii(verbose, "stat_send_event_size_ %u, stat_send_bytes_ %u\n",
            stat_send_event_size_, stat_send_bytes_);

    return txmt_len;
}

int network_interface_t::recv_geco_msg(int sfd, char *dest, int maxlen,
        sockaddrunion *from, sockaddrunion *to)
{
    if ((dest == NULL) || (from == NULL) || (to == NULL))
        return -1;

    int len = -1;
    struct iphdr *iph;

    if (ip4_socket_despt_ > 0)
    {
        //#ifdef USE_UDP
        //len = recvfrom(sfd, dest, maxlen, 0, (struct sockaddr *) from, &val);
        //#else
        len = recv(sfd, dest, maxlen, 0);
        //#endif
        iph = (struct iphdr *) dest;

        to->sa.sa_family = AF_INET;
        to->sin.sin_port = 0; //iphdr does NOT have port so we just set it to zero
#ifdef __linux__
        to->sin.sin_addr.s_addr = iph->daddr;
#else
        to->sin.sin_addr.s_addr = iph->dst_addr.s_addr;
#endif

        from->sa.sa_family = AF_INET;
        from->sin.sin_port = 0;
#ifdef __linux__
        from->sin.sin_addr.s_addr = iph->daddr;
#else
        from->sin.sin_addr.s_addr = iph->dst_addr.s_addr;
#endif

    }
    else if (ip6_socket_despt_ > 0)
    {
        struct msghdr rmsghdr;
        struct cmsghdr *rcmsgp;
        struct iovec data_vec;

        char m6buf[(GECO_CMSG_SPACE(sizeof(struct in6_pktinfo)))];
        struct in6_pktinfo *pkt6info;

        rcmsgp = (struct cmsghdr *) m6buf;
        pkt6info = (struct in6_pktinfo *) (GECO_CMSG_DATA(rcmsgp));

        /* receive control msg */
        rcmsgp->cmsg_level = IPPROTO_IPV6;
        rcmsgp->cmsg_type = IPV6_PKTINFO;
        rcmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

#ifdef _WIN32
        data_vec.buf = dest;
        data_vec.len = maxlen;
        rmsghdr.dwFlags = 0;
        rmsghdr.lpBuffers = &data_vec;
        rmsghdr.dwBufferCount = 1;
        rmsghdr.name = (sockaddr*)&(from->sin6);
        rmsghdr.namelen = sizeof(struct sockaddr_in6);
        rmsghdr.Control.buf = m6buf;
        rmsghdr.Control.len = sizeof(m6buf);
        len = recvmsg(sfd, (LPWSAMSG)&rmsghdr, 0, NULL, NULL);
#else
        rmsghdr.msg_flags = 0;
        rmsghdr.msg_iov = &data_vec;
        rmsghdr.msg_iovlen = 1;
        rmsghdr.msg_name = (void*) &(from->sin6);
        rmsghdr.msg_namelen = sizeof(struct sockaddr_in6);
        rmsghdr.msg_control = (void*) m6buf;
        rmsghdr.msg_controllen = sizeof(m6buf);
        len = recvmsg(sfd, &rmsghdr, 0);
#endif

        /* Linux sets this, so we reset it, as we don't want to run into trouble if
         we have a port set on sending...then we would get INVALID ARGUMENT  */
        from->sin6.sin6_port = 0;

        to->sa.sa_family = AF_INET6;
        to->sin6.sin6_port = 0;
        to->sin6.sin6_flowinfo = 0;
        memcpy(&(to->sin6.sin6_addr), &(pkt6info->ipi6_addr),
                sizeof(struct in6_addr));
    }
    else
    {
        error_log(major_error_abort, "recv_geco_msg()::no such AF!\n");
        return -1;
    }

#ifdef USE_UDP
    int ip_pk_hdr_len = (int) sizeof(struct iphdr)
    + (int)NETWORK_PACKET_FIXED_SIZE;
    if (len < ip_pk_hdr_len)
    {
        return -1;
    }

// check dest_port legal
    network_packet_fixed_t* udp_packet_fixed =
    (network_packet_fixed_t*)((char*)dest + sizeof(struct iphdr));
    if (ntohs(udp_packet_fixed->dest_port) != USED_UDP_PORT)
    {
        return -1;
    }

// currently it is [iphdr] + [udphdr] + [data]
// now we need move the data to the next of iphdr, skipping all bytes in updhdr
// as if udphdr never exists
    char* ptr = (char*)udp_packet_fixed;
    memmove(ptr, &ptr[NETWORK_PACKET_FIXED_SIZE], (len - ip_pk_hdr_len));
    len -= (int)NETWORK_PACKET_FIXED_SIZE;
#endif

    if (len < 0)
        error_log(major_error_abort, "recv()  failed () !");
    event_logi(verbose, "recv_geco_msg():: recv %u bytes od data\n", len);
    return len;
}
int network_interface_t::recv_udp_msg(int sfd, char *dest, int maxlen,
        sockaddrunion *from, socklen_t *from_len)
{
    int len;
    if ((len = recvfrom(sfd, dest, maxlen, 0, (struct sockaddr *) from,
            from_len)) < 0)
        error_log(major_error_abort,
                "recvfrom  failed in get_message(), aborting !\n");
    return len;
}
int network_interface_t::add_udpsock_ulpcb(const char* addr, ushort my_port,
        socket_cb_fun_t scb)
{
#ifdef _WIN32
    error_log(major_error_abort,
            "WIN32: Registering ULP-Callbacks for UDP not installed !\n");
    return -1;
#endif

    sockaddrunion my_address;
    str2saddr(&my_address, addr, my_port, ip4_socket_despt_ > 0);
    if (ip4_socket_despt_ > 0)
    {
        event_logii(verbose,
                "Registering ULP-Callback for UDP socket on {%s :%u}\n", addr,
                my_port);
        str2saddr(&my_address, addr, my_port, true);
    }
    else if (ip6_socket_despt_ > 0)
    {
        event_logii(verbose,
                "Registering ULP-Callback for UDP socket on {%s :%u}\n", addr,
                my_port);
        str2saddr(&my_address, addr, my_port, false);
    }
    else
    {
        error_log(major_error_abort,
                "UNKNOWN ADDRESS TYPE - CHECK YOUR PROGRAM !\n");
        return -1;
    }
    int new_sfd = open_ipproto_udp_socket(&my_address);
    poller_.add_event_handler(new_sfd,
    EVENTCB_TYPE_UDP, POLLIN | POLLPRI, (void (*)())scb, NULL);
    event_logi(verbose,
            "Registered ULP-Callback: now %d registered callbacks !!!\n",
            new_sfd);
    return new_sfd;
}
void network_interface_t::add_user_cb(int fd, user_cb_fun_t cbfun,
        void* userData, short int eventMask)
{
#ifdef _WIN32
    error_log(major_error_abort,
            "WIN32: Registering User Callbacks not installed !\n");
#endif
    /* 0 is the standard input ! */
    poller_.add_event_handler(fd, EVENTCB_TYPE_USER, eventMask,
            (void (*)())cbfun, userData);
            event_logii(verbose,
            "Registered User Callback: fd=%d eventMask=%d\n",
            fd, eventMask);
        }

