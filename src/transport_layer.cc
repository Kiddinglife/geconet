#include <cstdlib>
#include "transport_layer.h"
#define STD_INPUT_FD 0

static void safe_close_soket(int sfd)
{
    if (sfd < 0)
    {
        ERRLOG(MAJOR_ERROR, "invalid sfd!\n");
        return;
    }

#ifdef WIN32
    if (sfd == 0)
    return;

    if (closesocket(sfd) < 0)
    {
#else
    if (close(sfd) < 0)
    {
#endif
#ifdef _WIN32
        ERRLOG1(MAJOR_ERROR,
                "safe_cloe_soket()::close socket failed! {%d} !\n",
                WSAGetLastError());
#else
        ERRLOG1(MAJOR_ERROR, "safe_cloe_soket()::close socket failed! {%d} !\n",
                errno);
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
        ERRLOG(MAJOR_ERROR,
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
        ERRLOG(MAJOR_ERROR, "Invalid port \n");
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
            EVENTLOG(VERBOSE, "no s_addr specified, set to all zeros\n");
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
            EVENTLOG(VERBOSE, "no s_addr specified, set to all zeros\n");
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
int saddr2str(sockaddrunion *su, char * buf, size_t len, ushort* portnum)
{

    if (su->sa.sa_family == AF_INET)
    {
        if (buf != NULL)
            strncpy(buf, inet_ntoa(su->sin.sin_addr), 16);
        if (portnum != NULL)
            *portnum = ntohs(su->sin.sin_port);
        return (1);
    }
    else if (su->sa.sa_family == AF_INET6)
    {
        if (buf != NULL)
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

            if (portnum != NULL)
                *portnum = ntohs(su->sin6.sin6_port);
        }
        return (1);
    }
    return 0;
}


void reactor_t::set_expected_event_on_fd_(int fd_index, int sfd, int event_mask)
{
    if (fd_index > MAX_FD_SIZE)
        ERRLOG(FALTAL_ERROR_EXIT, "FD_Index bigger than MAX_FD_SIZE ! bye !\n");

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

#ifdef _WIN32
    // this is init and so we set it to null
    if (sfd == POLL_FD_UNUSED)
    {
        socket_despts[fd_index].event = NULL;
        socket_despts[fd_index].trigger_event =
        {   0};
    }
    else
    {
        // bind sfd with expecred event, when something happens on the fd, 
        // event will be signaled and then wait objects will return
        if (sfd != (int)STD_INPUT_FD)
        {
            socket_despts[fd_index].event = CreateEvent(NULL, false, false, NULL);
            int ret = WSAEventSelect(sfd, socket_despts[fd_index].event,
                    FD_READ | FD_WRITE | FD_ACCEPT | FD_CLOSE | FD_CONNECT);

            if (ret == SOCKET_ERROR)
            {
                ERRLOG(FALTAL_ERROR_EXIT, "WSAEventSelect() failed\n");
            }
            else
            {
                win32events_[fd_index] = socket_despts[fd_index].event;
            }
        }
        else
        {
            // this is used by stdin thread to notify us the stdin event
            // stdin thread will setevent() to trigger us
            win32events_[fd_index] = GetStdHandle(STD_INPUT_HANDLE);
            stdin_input_data_.event = win32events_[fd_index];

            // this one is used for us to tell stdin thread to 
            // keep reading from stdinputafter we called stfin cb
            stdin_input_data_.eventback = CreateEvent(NULL, false, false, NULL);
        }
    }
#endif
}

int reactor_t::remove_socket_despt(int sfd)
{
    int counter = 0;
    int i, j;

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
    EVENTLOG2(VERBOSE, "remove %d sfd(%d)\n", counter, sfd);
    return counter;
}
int reactor_t::remove_event_handler(int sfd)
{
    safe_close_soket(sfd);
    return remove_socket_despt(sfd);
}
void reactor_t::set_expected_event_on_fd(int sfd, int eventcb_type,
        int event_mask, cbunion_t action, void* userData)
{

    if (sfd < 0)
    {
        ERRLOG(FALTAL_ERROR_EXIT, "invlaid sfd ! \n");
        return;
    }

    if (socket_despts_size_ >= MAX_FD_SIZE)
    {
        ERRLOG(MAJOR_ERROR, "FD_Index bigger than MAX_FD_SIZE ! bye !\n");
        return;
    }

    set_expected_event_on_fd_(socket_despts_size_, sfd, event_mask);
    socket_despts_size_++;
    int index = socket_despts[socket_despts_size_ - 1].event_handler_index;
    event_callbacks[index].sfd = sfd;
    event_callbacks[index].eventcb_type = eventcb_type;
    event_callbacks[index].action = action;
    event_callbacks[index].userData = userData;
}
int reactor_t::poll_timers()
{
    if (this->timer_mgr_.empty())
        return -1;

    int result = timer_mgr_.timeouts();
    if (result == 0) // this timer has timeouts
    {
        timer_id_t tid = timer_mgr_.get_front_timer();
        if (tid->action(tid, tid->arg1, tid->arg2) == NOT_RESET_TIMER_FROM_CB)
            timer_mgr_.delete_timer(tid);
    }
    return result;
}

void reactor_t::fire_event(int num_of_events)
{
#ifdef _WIN32
    if (num_of_events == socket_despts_size_ && stdin_input_data_.len > 0)
    {
        //EVENTLOG1(VERBOSE,
        //    "Activity on user fd %d - Activating USER callback\n",
        //    socket_despts[num_of_events].fd);
        if (event_callbacks[num_of_events].action.user_cb_fun != NULL)
        event_callbacks[num_of_events].action.user_cb_fun(
                socket_despts[num_of_events].fd, socket_despts[num_of_events].revents,
                &socket_despts[num_of_events].events, event_callbacks[num_of_events].userData);
        SetEvent(stdin_input_data_.eventback);
        memset(stdin_input_data_.buffer, 0, sizeof(stdin_input_data_.buffer));
        stdin_input_data_.len = 0;
        return;
    }
#endif

    int i;
    for (i = 0; i < socket_despts_size_; i++)
    {
#ifdef _WIN32
        int ret = WSAEnumNetworkEvents(socket_despts[i].fd, socket_despts[i].event, &socket_despts[i].trigger_event);
        if (ret == SOCKET_ERROR)
        {
            ERRLOG(FALTAL_ERROR_EXIT, "WSAEnumNetworkEvents() failed!\n");
            return;
        }
        else
        {

            if (socket_despts[i].trigger_event.lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE))
            goto cb_dispatcher;
            else
            return;
        }
#endif

        if (socket_despts[i].revents == 0)
            continue;

        // fixme this is for debug can be removed
        //socket_despts[i].revents = 0;
        //socket_despts[i].revents |= POLLERR;
        //socket_despts[i].revents |= POLLERR;

        // handle error event
        if (socket_despts[i].revents & POLLERR)
        {
            /* Assumed this callback funtion has been setup by ulp user
             *for treating/logging the error
             */
            if (event_callbacks[i].eventcb_type == EVENTCB_TYPE_USER)
            {
                EVENTLOG1(VERBOSE, "Poll Error Condition on user fd %d\n",
                        socket_despts[i].fd);
                event_callbacks[i].action.user_cb_fun(socket_despts[i].fd,
                        socket_despts[i].revents, &socket_despts[i].events,
                        event_callbacks[i].userData);
            }
            else
            {
                ERRLOG1(MINOR_ERROR, "Poll Error Condition on fd %d\n",
                        socket_despts[i].fd);
                event_callbacks[i].action.socket_cb_fun(socket_despts[i].fd,
                NULL, 0, NULL, 0);
            }

            // we only have pollerr
            if (socket_despts[i].revents == POLLERR)
                return;
        }

        cb_dispatcher: switch (event_callbacks[i].eventcb_type)
        {
        case EVENTCB_TYPE_USER:
            EVENTLOG1(VERBOSE,
                    "Activity on user fd %d - Activating USER callback\n",
                    socket_despts[i].fd);
            if (event_callbacks[i].action.user_cb_fun != NULL)
                event_callbacks[i].action.user_cb_fun(socket_despts[i].fd,
                        socket_despts[i].revents, &socket_despts[i].events,
                        event_callbacks[i].userData);
            break;

        case EVENTCB_TYPE_UDP:
            recvlen_ = nit_ptr_->recv_udp_packet(socket_despts[i].fd,
                    internal_udp_buffer_, MAX_MTU_SIZE, &src, &src_addr_len_);
            saddr2str(&src, src_address, MAX_IPADDR_STR_LEN, &portnum_);
            if (event_callbacks[i].action.socket_cb_fun != NULL)
                event_callbacks[i].action.socket_cb_fun(socket_despts[i].fd,
                        internal_udp_buffer_, recvlen_, src_address, portnum_);
            EVENTLOG4(VERBOSE,
                    "EVENTCB_TYPE_UDP\n,UDP-Messag,\n on socket %u , recvlen_ %d, %s:%d\n",
                    socket_despts[i].fd, recvlen_, src_address, portnum_);
            break;

        case EVENTCB_TYPE_SCTP:
            recvlen_ = nit_ptr_->recv_ip_packet(socket_despts[i].fd,
                    internal_dctp_buffer, MAX_MTU_SIZE, &src, &dest);
            // if <0, mus be something thing wrong with UDP length or
            // port number is not USED_UDP_PORT, if so, just skip this msg
            // as if we never receive it
            if (recvlen_ < 0)
                break;

#ifdef _DEBUG
            saddr2str(&src, src_address, MAX_IPADDR_STR_LEN, &portnum_);
#endif

            if (saddr_family(&src) == AF_INET)
            {
                EVENTLOG4(VERBOSE,
                        "EVENTCB_TYPE_SCTP\n, recv a IPV4/DCTP-Messag from raw socket %u  %d bytes of data from %s:%d, port is zero as this is raw socket\n",
                        socket_despts[i].fd, recvlen_, src_address, portnum_);

                iph = (struct iphdr *) internal_dctp_buffer;
#if defined (__linux__)
                // 首部长度(4位):IP层头部包含多少个4字节 -- 32位
                // <<2 to get the byte size
                iphdrlen = iph->ihl << 2;
#elif defined (_WIN32)
                iphdrlen = (iph->version_length & 0x0F) << 2;
#else
                iphdrlen = iph->ip_hl << 2;
#endif
                if (recvlen_ < iphdrlen)
                {
                    ERRLOG1(WARNNING_ERROR,
                            "fire_event() : packet too short, less than a ip header (%d bytes)",
                            recvlen_);
                }
                else // now we have at lest a enpty ip packet
                {
                    // calculate ip payload size, which is DCTP packet size
                    recvlen_ -= iphdrlen;
                }
            }
            else
            {
                EVENTLOG4(VERBOSE,
                        "EVENTCB_TYPE_SCTP\n, recv a IPV6/DCTP-Messag,\nsocket %u , recvlen_ %d, bytes data from %s:%d\n",
                        socket_despts[i].fd, recvlen_, src_address, portnum_);
                iphdrlen = 0; // for ip6, we pass the whole ip packet to dispath layer
            }

            if (event_callbacks[i].action.socket_cb_fun != NULL)
                event_callbacks[i].action.socket_cb_fun(socket_despts[i].fd,
                        &internal_dctp_buffer[iphdrlen], recvlen_, src_address,
                        portnum_);

            dispatch_layer_.recv_geco_packet(socket_despts[i].fd,
                    &(internal_dctp_buffer[iphdrlen]), recvlen_, &src, &dest);
            break;

        default:
            ERRLOG1(MAJOR_ERROR, "No such  eventcb_type %d",
                    event_callbacks[i].eventcb_type);
            break;
        }
        socket_despts[i].revents = 0;
    }
}

#ifdef WIN32

static DWORD WINAPI stdin_read_thread(void *param)
{
    stdin_data_t *indata = (struct stdin_data_t *) param;

    while (ReadFile(indata->event, indata->buffer, sizeof(indata->buffer),
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

static void read_stdin(int fd, short int revents, int* settled_events,
        void* usrdata)
{
    if (fd != 0)
        ERRLOG1(FALTAL_ERROR_EXIT, "this sgould be stdin fd 0! instead of %d\n",
                fd);

    stdin_data_t* indata = (stdin_data_t*) usrdata;

#ifndef _WIN32
    indata->len = read(STD_INPUT_FD, indata->buffer, sizeof(indata->buffer));
#endif

    if (indata->len > 2)
    {
        indata->buffer[indata->len - 2] = '\0';
        indata->stdin_cb_(indata->buffer, indata->len - 1);
    }
    memset(indata->buffer, 0, sizeof(indata->buffer));
    indata->len = 0;
}

#ifdef _WIN32
static DWORD fdwMode, fdwOldMode;
HANDLE hStdIn;
HANDLE stdin_thread_handle;
#endif
void reactor_t::add_stdin_cb(stdin_data_t::stdin_cb_func_t stdincb)
{
    stdin_input_data_.stdin_cb_ = stdincb;
    cbunion_.user_cb_fun = read_stdin;
    set_expected_event_on_fd(STD_INPUT_FD, EVENTCB_TYPE_USER, POLLIN | POLLPRI,
            cbunion_, &stdin_input_data_);
    socket_despts_size_--;

#ifdef _WIN32
    hStdIn = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdIn, &fdwOldMode);
    // disable mouse and window input
    fdwMode = fdwOldMode ^ ENABLE_MOUSE_INPUT ^ ENABLE_WINDOW_INPUT;
    SetConsoleMode(hStdIn, fdwMode);
    // flush to remove existing events
    FlushConsoleInputBuffer(hStdIn);
    unsigned long in_threadid;
    if (!(CreateThread(NULL, 0, stdin_read_thread, &stdin_input_data_, 0, &in_threadid)))
    {
        fprintf(stderr, "Unable to create input thread\n");
    }
#endif
}

int reactor_t::remove_stdin_cb()
{
    // restore console mode when exit
#ifdef WIN32
    SetConsoleMode(hStdIn, fdwOldMode);
    TerminateThread(stdin_thread_handle, 0);
#endif
    return remove_event_handler(STD_INPUT_FD);
}

int reactor_t::poll(void (*lock)(void* data), void (*unlock)(void* data),
        void* data)
{
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

    return poll_fds(socket_despts, &socket_despts_size_, msecs, lock, unlock,
            data);
}
int network_interface_t::init(int * myRwnd, bool ip4)
{
    // create handles for stdin fd and socket fd
#ifdef WIN32
    WSADATA wsaData;
    int Ret = WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (Ret != 0)
    {
        ERRLOG(FALTAL_ERROR_EXIT, "WSAStartup failed!\n");
        return -1;
    }

    if (recvmsg == NULL)
    {
        recvmsg = getwsarecvmsg();
    }
#endif

    // generate random number
    struct timeval curTime;
    if (gettimenow(&curTime) != 0)
    {
        ERRLOG(FALTAL_ERROR_EXIT, "gettimenow() failed!\n");
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
            ERRLOG(MAJOR_ERROR, "Could not open UDP dummy socket !\n");
            return dummy_ipv4_udp_despt_;
        }
        EVENTLOG1(VERBOSE, "init()::dummy_ipv4_udp_despt_(%u)",
                dummy_ipv4_udp_despt_);
    }
    else
    {
        dummy_ipv6_udp_despt_ = open_ipproto_udp_socket(&su, myRwnd);
        if (dummy_ipv6_udp_despt_ < 0)
        {
            ERRLOG(MAJOR_ERROR, "Could not open UDP dummy socket !\n");
            return dummy_ipv6_udp_despt_;
        }
        EVENTLOG1(VERBOSE, "init()::dummy_ipv6_udp_despt_(%u)",
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

int reactor_t::poll_fds(socket_despt_t* despts, int* count, int timeout,
        void (*lock)(void* data), void (*unlock)(void* data), void* data)
{
    int i;
    int ret;

#ifdef _WIN32
    if (timeout < 0) // -1 means no timers added
    {
        timeout = GRANULARITY;
    }

    ret = MsgWaitForMultipleObjects(*count + 1, win32events_, false, timeout, QS_KEY);
    this->fire_event(ret);
    return 1;
#else
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
        // max fd to feed to select()
        nfd = MAX(nfd, despts[i].fd);

        // link fd with expected events
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
            EVENTLOG1(VERBOSE,
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
#ifdef _WIN32
            ERRLOG1(MAJOR_ERROR,
                    "select():: failed! {%d} !\n",
                    WSAGetLastError());
#else
            ERRLOG1(MAJOR_ERROR, "select():: failed! {%d} !\n", errno);
#endif
        }

        if (unlock)
        {
            unlock(data);
        }
    }
    return ret;
#endif
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
    EVENTLOG1(VERBOSE, "init receive buffer size is : %d bytes", new_sizee);

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

    EVENTLOG2(VERBOSE, "line 648 expected buffersize %d, actual buffersize %d",
            new_size, new_sizee);
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

#ifdef USE_UDP  //FIXME  not work on windows
    sockdespt = socket(af, SOCK_RAW, IPPROTO_UDP); // do we really need this?
#else
            sockdespt = socket(af, SOCK_RAW, IPPROTO_GECO);
#endif
    if (sockdespt < 0)
    {
        ERRLOG2(MAJOR_ERROR, "socket()  return  %d, errorno %d!\n", sockdespt,
                errno);
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
#ifdef USE_UDP
        me.sin.sin_port = USED_UDP_PORT;
#endif
#ifdef HAVE_SIN_LEN
        me.sin_len = sizeof(me);
#endif
    }
    else
    {
        /* binding to INADDR_ANY to make Windows happy... */
        me.sin6.sin6_family = AF_INET6;
        // bind any can recv all  ip packets
        memset(&me.sin6.sin6_addr.s6_addr, 0, sizeof(struct in6_addr));
#ifdef USE_UDP
        me.sin6.sin6_port = USED_UDP_PORT;
#endif
#ifdef HAVE_SIN_LEN
        me.sin_len = sizeof(me);
#endif
    }
    bind(sockdespt, (const struct sockaddr *) &me.sa, sizeof(struct sockaddr));

    //setup recv buffer option
    *rwnd = set_sockdespt_recvbuffer_size(sockdespt, *rwnd); // 655360 bytes
    if (*rwnd < 0)
    {
        safe_close_soket(sockdespt);
        ERRLOG2(MAJOR_ERROR,
                "setsockopt: Try to set SO_RCVBUF {%d} but failed errno %d\n!",
                *rwnd, errno);
    }

    if (setsockopt(sockdespt, SOL_SOCKET, SO_REUSEADDR, (char*) &optval,
            opt_size) < 0)
    {
        safe_close_soket(sockdespt);
#ifdef _WIN32
        ERRLOG1(MAJOR_ERROR,
                "setsockopt: Try to set SO_REUSEADDR but failed ! {%d} !\n",
                WSAGetLastError());
#else
        ERRLOG1(MAJOR_ERROR,
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
        ERRLOG(MAJOR_ERROR, "setsockopt: IP_PMTU_DISCOVER failed !");
    }

    // test to make sure we set it correctly
    if (getsockopt(sockdespt, SOL_SOCKET, IP_MTU_DISCOVER, (char*) &optval,
            &opt_size) < 0)
    {
        safe_close_soket(sockdespt);
        ERRLOG(MAJOR_ERROR, "getsockopt: SO_RCVBUF failed !");
    }
    else
    {
        EVENTLOG1(INTERNAL_TRACE, "setsockopt: IP_PMTU_DISCOVER succeed!",
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

    EVENTLOG2(VERBOSE, "Created raw socket %d, recv buffer %d with options\n",
            sockdespt, *rwnd);
    return (sockdespt);
}
int network_interface_t::open_ipproto_udp_socket(sockaddrunion* me, int* rwnd)
{
    char buf[MAX_IPADDR_STR_LEN];
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
        ERRLOG(MAJOR_ERROR, "upd ip4 socket() failed!\n");
        break;
    }

    /*If IPPROTO_IP(0) is specified, the caller does not wish to specify a protocol
     and the serviceprovider will choose the protocol to use.*/
    if ((sfd = socket(af, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
#ifdef _WIN32
        ERRLOG1(MAJOR_ERROR,
                "upd ip4 socket() failed error code (%d)!\n",
                WSAGetLastError());
#else
        ERRLOG1(MAJOR_ERROR, "upd ip4 socket() failed error code (%d)!\n",
                errno);
#endif
    }

    if (*rwnd < DEFAULT_RWND_SIZE) //default recv size is 1mb
        *rwnd = DEFAULT_RWND_SIZE;

    //setup recv buffer option
    *rwnd = set_sockdespt_recvbuffer_size(sfd, *rwnd); // 650KB
    if (*rwnd < 0)
    {
#ifdef _WIN32
        ERRLOG1(MAJOR_ERROR,
                "setsockopt: Try to set SO_RCVBUF {%d} but failed {%d} !\n",
                *rwnd, WSAGetLastError());
#else
        ERRLOG2(MAJOR_ERROR,
                "setsockopt: Try to set SO_RCVBUF {%d} but failed {%d} !\n",
                *rwnd, errno);
#endif
    }

    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char*) &ch, sizeof(ch))
            < 0)
    {
        safe_close_soket(sfd);
#ifdef _WIN32
        ERRLOG1(MAJOR_ERROR,
                "setsockopt: Try to set SO_REUSEADDR but failed ! {%d} !\n",
                WSAGetLastError());
#else
        ERRLOG1(MAJOR_ERROR,
                "setsockopt: Try to set SO_REUSEADDR but failed ! !\n", errno);
#endif
        return -1;
    }

    /* we only recv theudp datagrams destinated to this ip address */
    ch = bind(sfd, &me->sa, sizeof(struct sockaddr_in));
    if (ch < 0)
    {
        safe_close_soket(sfd);
        ERRLOG(MAJOR_ERROR, "bind() failed, please check if adress exits !\n");
        return -1;
    }
    ushort portnum = 0;
    saddr2str(me, buf, MAX_IPADDR_STR_LEN, &portnum);
    EVENTLOG4(VERBOSE,
            "open_ipproto_udp_socket : Create socket %d,recvbuf %d, binding to address %s:%u\n",
            sfd, *rwnd, buf, portnum);
    return (sfd);
}

int network_interface_t::send_udp_packet(int sfd, char* buf, int length,
        sockaddrunion* destsu)
{
    if (sfd <= 0)
    {
        ERRLOG(MAJOR_ERROR, "send UDP data on an invalid fd!\n");
        return -1;
    }

    if (length <= 0)
    {
        ERRLOG(MAJOR_ERROR, "Invalid length!\n");
        return -1;
    }

    if (buf == NULL)
    {
        ERRLOG(MAJOR_ERROR, "Invalid buf in send_udp_msg(%s)\n");
        return -1;
    }

    if (sfd == this->ip4_socket_despt_ || sfd == this->ip6_socket_despt_)
    {
        ERRLOG(MAJOR_ERROR, "cannot send UDP msg on a geco socket!\n");
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
        ERRLOG(MAJOR_ERROR, "Invalid AF address family in send_udp_msg()\n");
        result = -1;
        break;
    }
    EVENTLOG1(VERBOSE, "send_udp_msg(%d bytes data)", result);
    return result;
}
int network_interface_t::send_ip_packet(int sfd, char *buf, int len,
        sockaddrunion *dest, uchar tos)
{
    printf("%d\n", ntohs(dest->sin.sin_port));
    int txmt_len = 0;
    uchar old_tos;
    socklen_t opt_len;
    int tmp;

#ifdef USE_UDP
    // len+GECO_PACKET_FIXED_SIZE is the length of the total packet
    // here we test if the default udp send buffer cannot hold this packet
    //size_t packet_total_length = len + GECO_PACKET_FIXED_SIZE;
    if (USE_UDP_BUFSZ < len)
    {
        ERRLOG(FALTAL_ERROR_EXIT, "msg is too large ! bye !\n");
        return -1;
    }

    //    memcpy(poller_.internal_udp_buffer_, buf, len);
    //    udp_hdr_ptr_ = (geco_packet_fixed_t*)poller_.internal_udp_buffer_;
    udp_hdr_ptr_ = (udp_packet_fixed_t*) buf;
    udp_hdr_ptr_->src_port = htons(USED_UDP_PORT);
    udp_hdr_ptr_->dest_port = htons(USED_UDP_PORT);
    udp_hdr_ptr_->length = htons(len);
    udp_hdr_ptr_->checksum = 0x0000;
    //udp_hdr_ptr_->checksum = udp_checksum(udp_hdr_ptr_, packet_total_length);
#endif

    switch (saddr_family(dest))
    {
    case AF_INET:
        opt_len = sizeof(old_tos);
        tmp = getsockopt(sfd, IPPROTO_IP, IP_TOS, (char*) &old_tos, &opt_len);
        if (tmp < 0)
        {
            ERRLOG(MAJOR_ERROR, "getsockopt(IP_TOS) failed!\n");
            return -1;
        }
        tmp = setsockopt(sfd, IPPROTO_IP, IP_TOS, (char*) &tos, sizeof(char));
        if (tmp < 0)
        {
            ERRLOG(MAJOR_ERROR, "setsockopt(tos) failed!\n");
            return -1;
        }
        EVENTLOG6(VERBOSE,
                "AF_INET :: send_ip_packet : set IP_TOS %u, result=%d, sfd : %d, len %d, destination : %s::%u\n",
                tos, tmp, sfd, len, inet_ntoa(dest->sin.sin_addr),
                ntohs(dest->sin.sin_port));

        txmt_len = sendto(sfd, buf, len, 0, (struct sockaddr *) &(dest->sin),
                sizeof(struct sockaddr_in));

#ifdef USE_UDP
        if (txmt_len >= (int) UDP_PACKET_FIXED_SIZE)
        {
            txmt_len -= (int) UDP_PACKET_FIXED_SIZE;
        }
#endif
        break;

    case AF_INET6:
        char hostname[IFNAMSIZ];
        if (inet_ntop(AF_INET6, s6addr(dest), (char *) hostname,
        IFNAMSIZ) == NULL)
        {
            ERRLOG(MAJOR_ERROR, "inet_ntop()  buffer is too small !\n");
            return -1;
        }
        EVENTLOG4(VERBOSE,
                "AF_INET6 :: send_ip_packet :sfd : %d, len %d, destination : %s::%u\n",
                sfd, len, hostname, ntohs(dest->sin6.sin6_port));

        txmt_len = sendto(sfd, buf, len, 0, (struct sockaddr *) &(dest->sin6),
                sizeof(struct sockaddr_in6));

#ifdef USE_UDP
        if (txmt_len >= (int) UDP_PACKET_FIXED_SIZE)
        {
            txmt_len -= (int) UDP_PACKET_FIXED_SIZE;
        }
#endif

        break;
    default:
        ERRLOG1(MAJOR_ERROR, "no such Adress Family %u !\n",
                saddr_family(dest));
        return -1;
        break;
    }

    stat_send_event_size_++;
    stat_send_bytes_ += txmt_len;
    EVENTLOG3(VERBOSE,
            "stat_send_event_size_ %u, stat_send_bytes_ %u, packet len %u\n",
            stat_send_event_size_, stat_send_bytes_,
            len - UDP_PACKET_FIXED_SIZE);

    return txmt_len;
}

int network_interface_t::recv_ip_packet(int sfd, char *dest, int maxlen,
        sockaddrunion *from, sockaddrunion *to)
{
    if ((dest == NULL) || (from == NULL) || (to == NULL))
    {
        ERRLOG(MAJOR_ERROR, "some param is NULL !\n");
        return -1;
    }

    int len = -1;
    struct iphdr *iph;

    if (ip4_socket_despt_ > 0)
    {
        //        #ifdef USE_UDP
        //        len = recvfrom(sfd, dest, maxlen, 0, (struct sockaddr *) from, &val);
        //        #else
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
        ERRLOG(MAJOR_ERROR, "recv_geco_msg()::no such AF!\n");
        return -1;
    }

#ifdef USE_UDP
    int ip_pk_hdr_len = (int) sizeof(struct iphdr)
            + (int) GECO_PACKET_FIXED_SIZE;
    if (len < ip_pk_hdr_len)
    {
        ERRLOG(WARNNING_ERROR, "recv_geco_msg():: ip_pk_hdr_len illegal!\n");
        return -1;
    }

    // check dest_port legal
    geco_packet_fixed_t* udp_packet_fixed = (geco_packet_fixed_t*) ((char*) dest
            + sizeof(struct iphdr));
    if (ntohs(udp_packet_fixed->dest_port) != USED_UDP_PORT)
    {
        ERRLOG(WARNNING_ERROR, "recv_geco_msg()::dest_port illegal !\n");
        return -1;
    }

    // currently it is [iphdr] + [udphdr] + [data]
    // now we need move the data to the next of iphdr, skipping all bytes in updhdr
    // as if udphdr never exists
    char* ptr = (char*) udp_packet_fixed;
    memmove(ptr, &ptr[GECO_PACKET_FIXED_SIZE], (len - ip_pk_hdr_len));
    len -= (int) GECO_PACKET_FIXED_SIZE;
#endif

    if (len < 0)
        ERRLOG(MAJOR_ERROR, "recv()  failed () !");
    EVENTLOG1(VERBOSE, "recv_geco_msg():: recv %u bytes od data\n", len);
    return len;
}
int network_interface_t::recv_udp_packet(int sfd, char *dest, int maxlen,
        sockaddrunion *from, socklen_t *from_len)
{
    int len;
    if ((len = recvfrom(sfd, dest, maxlen, 0, (struct sockaddr *) from,
            from_len)) < 0)
        ERRLOG(MAJOR_ERROR, "recvfrom  failed in get_message(), aborting !\n");
    return len;
}
int network_interface_t::add_udpsock_ulpcb(const char* addr, ushort my_port,
        socket_cb_fun_t scb)
{
#ifdef _WIN32
    ERRLOG(MAJOR_ERROR,
            "WIN32: Registering ULP-Callbacks for UDP not installed !\n");
    return -1;
#endif

    sockaddrunion my_address;
    str2saddr(&my_address, addr, my_port, ip4_socket_despt_ > 0);
    if (ip4_socket_despt_ > 0)
    {
        EVENTLOG2(VERBOSE,
                "Registering ULP-Callback for UDP socket on {%s :%u}\n", addr,
                my_port);
        str2saddr(&my_address, addr, my_port, true);
    }
    else if (ip6_socket_despt_ > 0)
    {
        EVENTLOG2(VERBOSE,
                "Registering ULP-Callback for UDP socket on {%s :%u}\n", addr,
                my_port);
        str2saddr(&my_address, addr, my_port, false);
    }
    else
    {
        ERRLOG(MAJOR_ERROR, "UNKNOWN ADDRESS TYPE - CHECK YOUR PROGRAM !\n");
        return -1;
    }
    int new_sfd = open_ipproto_udp_socket(&my_address);
    cbunion_.socket_cb_fun = scb;
    poller_.set_expected_event_on_fd(new_sfd,
    EVENTCB_TYPE_UDP, POLLIN | POLLPRI, cbunion_, NULL);
    EVENTLOG1(VERBOSE,
            "Registered ULP-Callback: now %d registered callbacks !!!\n",
            new_sfd);
    return new_sfd;
}
void network_interface_t::add_user_cb(int fd, user_cb_fun_t cbfun, void* userData,
        short int eventMask)
{
#ifdef _WIN32
    ERRLOG(MAJOR_ERROR,
            "WIN32: Registering User Callbacks not installed !\n");
#endif
    cbunion_.user_cb_fun = cbfun;
    /* 0 is the standard input ! */
    poller_.set_expected_event_on_fd(fd, EVENTCB_TYPE_USER, eventMask, cbunion_,
            userData);
    EVENTLOG2(VERBOSE, "Registered User Callback: fd=%d eventMask=%d\n", fd,
            eventMask);
}

bool network_interface_t::get_local_addresses(union sockaddrunion **addresses,
        int *numberOfNets, int sctp_fd, bool with_ipv6, int *max_mtu,
        const IPAddrType flags)
{
#ifdef WIN32
    union sockaddrunion *localAddresses = NULL;

    SOCKET s[MAXIMUM_WAIT_OBJECTS];
    WSAEVENT hEvent[MAXIMUM_WAIT_OBJECTS];
    WSAOVERLAPPED ol[MAXIMUM_WAIT_OBJECTS];
    struct addrinfo *local = NULL, hints,
    *ptr = NULL;
    SOCKET_ADDRESS_LIST *slist = NULL;
    DWORD bytes;
    char addrbuf[ADDRESS_LIST_BUFFER_SIZE], host[NI_MAXHOST], serv[NI_MAXSERV];
    int socketcount = 0,
    addrbuflen = ADDRESS_LIST_BUFFER_SIZE,
    rc, i, j, hostlen = NI_MAXHOST, servlen = NI_MAXSERV;
    struct sockaddr_in Addr;

    /* Enumerate the local bind addresses - to wait for changes we only need
     one socket but to enumerate the addresses for a particular address
     family, we need a socket of that type  */

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    if ((rc = getaddrinfo(NULL, "0", &hints, &local)) != 0)
    {
        local = NULL;
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

    for (i = 0; i < socketcount; i++)
    {
        memset(&ol[i], 0, sizeof(WSAOVERLAPPED));
        ol[i].hEvent = hEvent[i];
        if ((rc = WSAIoctl(s[i], SIO_ADDRESS_LIST_QUERY, NULL, 0, addrbuf, addrbuflen,
                                &bytes, NULL, NULL)) == SOCKET_ERROR)
        {
            fprintf(stderr, "WSAIoctl: SIO_ADDRESS_LIST_QUERY failed: %d\n", WSAGetLastError());
            return -1;
        }

        slist = (SOCKET_ADDRESS_LIST *)addrbuf;
        localAddresses = (sockaddrunion*)calloc(slist->iAddressCount, sizeof(union sockaddrunion));
        for (j = 0; j < slist->iAddressCount; j++)
        {
            if ((rc = getnameinfo(slist->Address[j].lpSockaddr, slist->Address[j].iSockaddrLength,
                                    host, hostlen, serv, servlen, NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
            fprintf(stderr, "%s: getnameinfo failed: %d\n", __FILE__, rc);
            Addr.sin_family = slist->Address[j].lpSockaddr->sa_family;
            Addr.sin_addr.s_addr = inet_addr(host);
            memcpy(&((localAddresses)[j]), &Addr, sizeof(Addr));
        }

        /* Register for change notification*/
        if ((rc = WSAIoctl(s[i], SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &bytes, &ol[i], NULL)) == SOCKET_ERROR)
        {
            if (WSAGetLastError() != WSA_IO_PENDING)
            {
                fprintf(stderr, "WSAIoctl: SIO_ADDRESS_LIST_CHANGE failed: %d\n", WSAGetLastError());
                return -1;
            }
        }
    }

    freeaddrinfo(local);

    for (i = 0; i < socketcount; i++)
    closesocket(s[i]);

    *addresses = localAddresses;
    *numberOfNets = slist->iAddressCount;
    *max_mtu = 1500;
    return true;
#else
#if defined (__linux__)
    int addedNets;
    char addrBuffer[256];
    FILE *v6list;
    struct sockaddr_in6 sin6;
    int numAlocIPv4Addr = 0;
#endif

    char addrBuffer2[64];
    /* unsigned short intf_flags; */
    struct ifconf cf;
    int pos = 0, copSiz = 0, numAlocAddr = 0, ii;
    char buffer[8192];
    struct sockaddr *toUse;
    int saveMTU = 1500; /* default maximum MTU for now */
#ifdef HAS_SIOCGLIFADDR
    struct if_laddrreq lifaddr;
#endif
    struct ifreq local;
    struct ifreq *ifrequest, *nextif;
    int dup, xxx, tmp;
    union sockaddrunion * localAddresses = NULL;

    cf.ifc_buf = buffer;
    cf.ifc_len = 8192;
    *max_mtu = 0;
    *numberOfNets = 0;

    /* Now gather the master address information */
    if (ioctl(sctp_fd, SIOCGIFCONF, (char *) &cf) == -1)
    {
        return (false);
    }

#ifdef USES_BSD_4_4_SOCKET
    for (pos = 0; pos < cf.ifc_len;)
    {
        ifrequest = (struct ifreq *)&buffer[pos];
#ifdef SOLARIS
        pos += (sizeof(struct sockaddr) + sizeof(ifrequest->ifr_name));
#else
#ifdef NEUTRINO_RTOS
        if (ifrequest->ifr_addr.sa_len + IFNAMSIZ > sizeof(struct ifreq))
        {
            pos += ifrequest->ifr_addr.sa_len + IFNAMSIZ;
        }
        else
        {
            pos += sizeof(struct ifreq);
        }
#else
        pos += (ifrequest->ifr_addr.sa_len + sizeof(ifrequest->ifr_name));

        if (ifrequest->ifr_addr.sa_len == 0)
        {
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
#if defined  (__linux__)
    numAlocIPv4Addr = numAlocAddr;
    addedNets = 0;
    v6list = fopen(LINUX_PROC_IPV6_FILE, "r");
    if (v6list != NULL)
    {
        while (fgets(addrBuffer, sizeof(addrBuffer), v6list) != NULL)
        {
            addedNets++;
        }
        fclose(v6list);
    }
    numAlocAddr += addedNets;
    EVENTLOG2(VERBOSE, "Found additional %d v6 addresses, total now %d\n",
            addedNets, numAlocAddr);
#endif
    /* now allocate the appropriate memory */
    localAddresses = (union sockaddrunion*) calloc(numAlocAddr,
            sizeof(union sockaddrunion));

    if (localAddresses == NULL)
    {
        ERRLOG(FALTAL_ERROR_EXIT,
                "Out of Memory in adl_gatherLocalAddresses() !");
        return (false);
    }

    pos = 0;
    /* Now we go through and pull each one */

#if defined (__linux__)
    v6list = fopen(LINUX_PROC_IPV6_FILE, "r");
    if (v6list != NULL)
    {
        memset((char *) &sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;

        while (fgets(addrBuffer, sizeof(addrBuffer), v6list) != NULL)
        {
            if (strncmp(addrBuffer, "00000000000000000000000000000001", 32)
                    == 0)
            {
                EVENTLOG(VERBOSE, "At least I found the local IPV6 address !");
                if (inet_pton(AF_INET6, "::1", (void *) &sin6.sin6_addr) > 0)
                {
                    sin6.sin6_family = AF_INET6;
                    memcpy(&((localAddresses)[*numberOfNets]), &sin6,
                            sizeof(sin6));
                    EVENTLOG5(VERBOSE,
                            "copied the local IPV6 address %x:%x:%x:%x, family %x",
                            sin6.sin6_addr.s6_addr32[3],
                            sin6.sin6_addr.s6_addr32[2],
                            sin6.sin6_addr.s6_addr32[1],
                            sin6.sin6_addr.s6_addr32[0], sin6.sin6_family);
                    (*numberOfNets)++;
                }
                continue;
            }
            memset(addrBuffer2, 0, sizeof(addrBuffer2));
            strncpy(addrBuffer2, addrBuffer, 4);
            addrBuffer2[4] = ':';
            strncpy(&addrBuffer2[5], &addrBuffer[4], 4);
            addrBuffer2[9] = ':';
            strncpy(&addrBuffer2[10], &addrBuffer[8], 4);
            addrBuffer2[14] = ':';
            strncpy(&addrBuffer2[15], &addrBuffer[12], 4);
            addrBuffer2[19] = ':';
            strncpy(&addrBuffer2[20], &addrBuffer[16], 4);
            addrBuffer2[24] = ':';
            strncpy(&addrBuffer2[25], &addrBuffer[20], 4);
            addrBuffer2[29] = ':';
            strncpy(&addrBuffer2[30], &addrBuffer[24], 4);
            addrBuffer2[34] = ':';
            strncpy(&addrBuffer2[35], &addrBuffer[28], 4);

            if (inet_pton(AF_INET6, addrBuffer2, (void *) &sin6.sin6_addr) > 0)
            {
                if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr))
                {
                    sscanf((const char*) &addrBuffer[34], "%x",
                            &sin6.sin6_scope_id);
                }
                memcpy(&((localAddresses)[*numberOfNets]), &sin6, sizeof(sin6));

            }
            else
            {
                ERRLOG1(FALTAL_ERROR_EXIT, "Could not translate string %s",
                        addrBuffer2);
            }
        }
        fclose(v6list);
    }
#endif

    /* set to the start, i.e. buffer[0] */
    ifrequest = (struct ifreq *) &buffer[pos];

#if defined (__linux__)
    for (ii = 0; ii < numAlocIPv4Addr; ii++, ifrequest = nextif)
    {
#else
        for (ii = 0; ii < numAlocAddr; ii++, ifrequest = nextif)
        {
#endif
#ifdef USES_BSD_4_4_SOCKET
        /* use the sa_len to calculate where the next one will be */
#ifdef SOLARIS
        pos += (sizeof(struct sockaddr) + sizeof(ifrequest->ifr_name));
#else
#ifdef NEUTRINO_RTOS
        if (ifrequest->ifr_addr.sa_len + IFNAMSIZ > sizeof(struct ifreq))
        {
            pos += ifrequest->ifr_addr.sa_len + IFNAMSIZ;
        }
        else
        {
            pos += sizeof(struct ifreq);
        }
#else
        pos += (ifrequest->ifr_addr.sa_len + sizeof(ifrequest->ifr_name));

        if (ifrequest->ifr_addr.sa_len == 0)
        {
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
        memcpy(local.ifr_name, ifrequest->ifr_name, IFNAMSIZ);
        EVENTLOG3(VERBOSE, "Interface %d, NAME %s, Hex: %x", ii, local.ifr_name,
                local.ifr_name);

        if (ioctl(sctp_fd, SIOCGIFMTU, (char *) &local) == -1)
        {
            /* cant get the flags? */
            continue;
        }
        saveMTU = local.ifr_mtu;
        EVENTLOG2(VERBOSE, "Interface %d, MTU %d", ii, saveMTU);
#endif
        toUse = &ifrequest->ifr_addr;

        saddr2str((union sockaddrunion*) toUse, addrBuffer2, MAX_IPADDR_STR_LEN,
        NULL);
        EVENTLOG1(VERBOSE, "we are talking about the address %s", addrBuffer2);

        memset(&local, 0, sizeof(local));
        memcpy(local.ifr_name, ifrequest->ifr_name, IFNAMSIZ);

        if (ioctl(sctp_fd, SIOCGIFFLAGS, (char *) &local) == -1)
        {
            /* can't get the flags, skip this guy */
            continue;
        }
        /* Ok get the address and save the flags */
        /*        intf_flags = local.ifr_flags; */

        if (!(local.ifr_flags & IFF_UP))
        {
            /* Interface is down */
            continue;
        }

        if (flags & LoopBackAddrType)
        {
            if (this->typeofaddr((union sockaddrunion*) toUse,
                    LoopBackAddrType))
            {
                /* skip the loopback */
                EVENTLOG1(VERBOSE, "Interface %d, skipping loopback", ii);
                continue;
            }
        }
        if (this->typeofaddr((union sockaddrunion*) toUse,
                ReservedAddrType))
        {
            /* skip reserved */
            EVENTLOG1(VERBOSE, "Interface %d, skipping reserved", ii);
            continue;
        }

        if (toUse->sa_family == AF_INET)
        {
            copSiz = sizeof(struct sockaddr_in);
        }
        else if (toUse->sa_family == AF_INET6)
        {
            copSiz = sizeof(struct sockaddr_in6);
        }
        if (*max_mtu < saveMTU)
            *max_mtu = saveMTU;

        /* Now, we may have already gathered this address, if so skip
         * it
         */
        EVENTLOG2(VERBOSE,
                "Starting checking for duplicates ! MTU = %d, nets: %d",
                saveMTU, *numberOfNets);

        if (*numberOfNets)
        {
            tmp = *numberOfNets;
            dup = 0;
            /* scan for the dup */
            for (xxx = 0; xxx < tmp; xxx++)
            {
                EVENTLOG1(VERBOSE, "duplicates loop xxx=%d", xxx);
                if (saddr_equals(&localAddresses[xxx],
                        (union sockaddrunion*) toUse))
                {
#ifdef HAVE_IPV6
                    if ((localAddresses[xxx].sa.sa_family == AF_INET6) &&
                            (toUse->sa_family == AF_INET) &&
                            (IN6_IS_ADDR_V4MAPPED(&localAddresses[xxx].sin6.sin6_addr) ||
                                    IN6_IS_ADDR_V4COMPAT(&localAddresses[xxx].sin6.sin6_addr)))
                    {
                        /* There are multiple interfaces, one has ::ffff:a.b.c.d or
                         ::a.b.c.d address. Use address which is IPv4 native instead. */
                        memcpy(&localAddresses[xxx], toUse, sizeof(localAddresses[xxx]));
                    }
                    else
                    {
#endif
                    EVENTLOG(VERBOSE, "Interface %d, found duplicate");
                    dup = 1;
#ifdef HAVE_IPV6
                }
#endif
                }
            }
            if (dup)
            {
                /* skip the duplicate name/address we already have it*/
                continue;
            }
        }

        /* copy address */
        EVENTLOG1(VERBOSE, "Copying %d bytes", copSiz);
        memcpy(&localAddresses[*numberOfNets], (char *) toUse, copSiz);
        EVENTLOG(VERBOSE, "Setting Family");
        /* set family */
        (&(localAddresses[*numberOfNets]))->sa.sa_family = toUse->sa_family;

#ifdef USES_BSD_4_4_SOCKET
#ifndef SOLARIS
        /* copy the length */
        (&(localAddresses[*numberOfNets]))->sa.sa_len = toUse->sa_len;
#endif
#endif
        (*numberOfNets)++;
        EVENTLOG2(VERBOSE, "Interface %d, Number of Nets: %d", ii,
                *numberOfNets);
    }

    EVENTLOG1(VERBOSE, "adl_gatherLocalAddresses: Found %d addresses",
            *numberOfNets);
    for (ii = 0; ii < (*numberOfNets); ii++)
    {
        saddr2str(&(localAddresses[ii]), addrBuffer2, MAX_IPADDR_STR_LEN, NULL);
        EVENTLOG2(VERBOSE, "adl_gatherAddresses : Address %d: %s", ii,
                addrBuffer2);

    }
    *addresses = localAddresses;
    return (true);
#endif
}

bool network_interface_t::typeofaddr(union sockaddrunion* newAddress,
        IPAddrType flags)
{
    switch (saddr_family(newAddress))
    {
    case AF_INET:
        EVENTLOG(VERBOSE, "Trying IPV4 address\n");
        if ((IN_MULTICAST(ntohl(newAddress->sin.sin_addr.s_addr))
                && (flags & MulticastAddrType))
                || (IN_EXPERIMENTAL(ntohl(newAddress->sin.sin_addr.s_addr))
                        && (flags & ReservedAddrType))
                || (IN_BADCLASS(ntohl(newAddress->sin.sin_addr.s_addr))
                        && (flags & ReservedAddrType))
                || ((INADDR_BROADCAST == ntohl(newAddress->sin.sin_addr.s_addr))
                        && (flags & BroadcastAddrType))
                || ((INADDR_LOOPBACK == ntohl(newAddress->sin.sin_addr.s_addr))
                        && (flags & LoopBackAddrType))
                || ((INADDR_LOOPBACK != ntohl(newAddress->sin.sin_addr.s_addr))
                        && (flags & AllExceptLoopbackAddrTypes))
                || (ntohl(newAddress->sin.sin_addr.s_addr) == INADDR_ANY))
        {
            EVENTLOG(VERBOSE, "Filtering IPV4 address\n");
            return true;
        }
        break;
    case AF_INET6:
#if defined (__linux__)
        if ((!IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr.s6_addr))
                && (flags & AllExceptLoopbackAddrTypes))
                || (IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr.s6_addr))
                        && (flags & LoopBackAddrType))
                || (IN6_IS_ADDR_LINKLOCAL(&(newAddress->sin6.sin6_addr.s6_addr))
                        && (flags & LinkLocalAddrType))
                || (!IN6_IS_ADDR_LINKLOCAL(
                        &(newAddress->sin6.sin6_addr.s6_addr))
                        && (flags & AllExceptLinkLocalAddrTypes))
                || (!IN6_IS_ADDR_SITELOCAL(
                        &(newAddress->sin6.sin6_addr.s6_addr))
                        && (flags & ExceptSiteLocalAddrTypes))
                || (IN6_IS_ADDR_SITELOCAL(&(newAddress->sin6.sin6_addr.s6_addr))
                        && (flags & SiteLocalAddrType))
                || (IN6_IS_ADDR_MULTICAST(&(newAddress->sin6.sin6_addr.s6_addr))
                        && (flags & MulticastAddrType))
                || IN6_IS_ADDR_UNSPECIFIED(
                        &(newAddress->sin6.sin6_addr.s6_addr)))
        {
            EVENTLOG(VERBOSE, "Filtering IPV6 address");
            return true;
        }
#else
        if (
                (!IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr)) && (flags & AllExceptLoopbackAddrTypes)) ||
                (IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr)) && (flags & LoopBackAddrType)) ||
                (!IN6_IS_ADDR_LINKLOCAL(&(newAddress->sin6.sin6_addr)) && (flags & AllExceptLinkLocalAddrTypes)) ||
                (!IN6_IS_ADDR_SITELOCAL(&(newAddress->sin6.sin6_addr)) && (flags & ExceptSiteLocalAddrTypes)) ||
                (IN6_IS_ADDR_LINKLOCAL(&(newAddress->sin6.sin6_addr)) && (flags & LinkLocalAddrType)) ||
                (IN6_IS_ADDR_SITELOCAL(&(newAddress->sin6.sin6_addr)) && (flags & SiteLocalAddrType)) ||
                (IN6_IS_ADDR_MULTICAST(&(newAddress->sin6.sin6_addr)) && (flags & MulticastAddrType)) ||
                IN6_IS_ADDR_UNSPECIFIED(&(newAddress->sin6.sin6_addr))
        )
        {
            EVENTLOG(VERBOSE, "Filtering IPV6 address");
            return true;
        }
#endif
        break;
    default:
        EVENTLOG(VERBOSE, "Default : Filtering Address");
        return true;
        break;
    }
    return false;
}
