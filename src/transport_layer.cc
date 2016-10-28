#include <cstdlib>
#include "transport_layer.h"

#define STD_INPUT_FD 0

#ifdef _WIN32
static HANDLE win32events_[MAX_FD_SIZE];
#endif
event_handler_t event_callbacks[MAX_FD_SIZE];
//int num_of_triggered_events;
socket_despt_t socket_despts[MAX_FD_SIZE];
int socket_despts_size_;
static int revision_;

static stdin_data_t stdin_input_data_;
timer_mgr mtra_timer_mgr_;
static timer_id_t curr_timer_id_;

static char* internal_udp_buffer_;
static char* internal_dctp_buffer;

static sockaddrunion src, dest;
static socklen_t src_addr_len_;
static int recvlen_;
static ushort portnum_;
static char src_address[MAX_IPADDR_STR_LEN];
static iphdr* iph;
static int iphdrlen;

//static dispatch_layer_t dispatch_layer_;
static cbunion_t cbunion_;

static int mtra_ip4_socket_despt_; /* socket fd for standard SCTP port....      */
static int mtra_ip6_socket_despt_; /* socket fd for standard SCTP port....      */
static int mtra_icmp_socket_despt_; /* socket fd for ICMP messages */

int mtra_read_ip4_socket()
{
    return mtra_ip4_socket_despt_;
}
int mtra_read_ip6_socket()
{
    return mtra_ip6_socket_despt_;
}
int mtra_read_icmp_socket()
{
    return mtra_icmp_socket_despt_;
}
void mtra_zero_ip4_socket()
{
    mtra_ip4_socket_despt_ = 0;
}
void mtra_zero_ip6_socket()
{
    mtra_ip6_socket_despt_ = 0;
}
void mtra_zero_icmp_socket()
{
    mtra_icmp_socket_despt_ = 0;
}

static void errorno(uint level)
{
#ifdef _WIN32
    EVENTLOG1(level, "errorno %d", WSAGetLastError());
#elif defined(__linux__)
    EVENTLOG1(level, "errorno %d", errno);
#else
    EVENTLOG1(level, "errorno unknown plateform !");
#endif
}

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
static LPFN_WSARECVMSG recvmsg = NULL;
#endif

#ifdef WIN32
static DWORD WINAPI stdin_read_thread(void *param)
{
    stdin_data_t *indata = (struct stdin_data_t *) param;
    int i = 1;
    while (ReadFile(indata->event, indata->buffer, sizeof(indata->buffer),
                    &indata->len, NULL) && indata->len > 0)
    {
        SetEvent(indata->event);
        WaitForSingleObject(indata->eventback, INFINITE);
        //memset(indata->buffer, 0, sizeof(indata->buffer));
    }
    //memset(indata->buffer, 0, sizeof(indata->buffer));
    indata->len = 0;
    SetEvent(indata->event);
    return 0;
}
#endif

static void read_stdin(int fd, short int revents, int* settled_events,
        void* usrdata)
{
    if (fd != 0)
    ERRLOG1(FALTAL_ERROR_EXIT, "this sgould be stdin fd 0! instead of %d", fd);

    stdin_data_t* indata = (stdin_data_t*) usrdata;

#ifndef _WIN32
    indata->len = read(STD_INPUT_FD, indata->buffer, sizeof(indata->buffer));
#endif
    int i = 1;
    while (indata->buffer[indata->len - i] == '\r' || indata->buffer[indata->len - i] == '\n')
    {
        i++;
        if (i > indata->len)
        {
            indata->len = 0;
            return;
        }
    }
    indata->buffer[indata->len - i + 1] = '\0';
    indata->stdin_cb_(indata->buffer, indata->len - i + 2);
}

#ifdef _WIN32
static DWORD fdwMode, fdwOldMode;
HANDLE hStdIn;
HANDLE stdin_thread_handle;
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

int str2saddr(sockaddrunion *su, const char * str, ushort hs_port)
{
    int ret;
    memset((void*) su, 0, sizeof(union sockaddrunion));

    if (hs_port < 0)
    {
        ERRLOG(MAJOR_ERROR, "Invalid port \n");
        return -1;
    }

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

void mtra_set_expected_event_on_fd(int fd_index, int sfd, int event_mask)
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
void mtra_set_expected_event_on_fd(int sfd, int eventcb_type,
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

    mtra_set_expected_event_on_fd(socket_despts_size_, sfd, event_mask);
    socket_despts_size_++;
    int index = socket_despts[socket_despts_size_ - 1].event_handler_index;
    event_callbacks[index].sfd = sfd;
    event_callbacks[index].eventcb_type = eventcb_type;
    event_callbacks[index].action = action;
    event_callbacks[index].userData = userData;
}

static int mtra_remove_socket_despt(int sfd)
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
    EVENTLOG2(VERBOSE, "remove %d sfd(%d)", counter, sfd);
    return counter;
}
int mtra_remove_event_handler(int sfd)
{
    safe_close_soket(sfd);
    return mtra_remove_socket_despt(sfd);
}

void mtra_add_stdin_cb(stdin_data_t::stdin_cb_func_t stdincb)
{
    EVENTLOG(VERBOSE, "ENTER selector::add_stdin_cb()");
    stdin_input_data_.stdin_cb_ = stdincb;
    cbunion_.user_cb_fun = read_stdin;
    mtra_set_expected_event_on_fd(STD_INPUT_FD, EVENTCB_TYPE_USER, POLLIN | POLLPRI,
            cbunion_, &stdin_input_data_);

#ifdef _WIN32
    socket_despts_size_--;
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
int mtra_remove_stdin_cb()
{
    // restore console mode when exit
#ifdef WIN32
    SetConsoleMode(hStdIn, fdwOldMode);
    TerminateThread(stdin_thread_handle, 0);
#endif
    return mtra_remove_event_handler(STD_INPUT_FD);
}

static int mtra_poll_timers()
{
    if (mtra_timer_mgr_.empty())
    return -1;

    int result = mtra_timer_mgr_.timeouts();
    if (result == 0)  // this timer has timeouts
    {
        timer_id_t tid = mtra_timer_mgr_.get_front_timer();
        if (tid->action(tid, tid->arg1, tid->arg2) == NOT_RESET_TIMER_FROM_CB)
        mtra_timer_mgr_.delete_timer(tid);
    }
    return result;
}
static void mtra_fire_event(int num_of_events)
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
#ifdef _WIN32
        cb_dispatcher :
#endif
        switch (event_callbacks[i].eventcb_type)
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
                recvlen_ = mtra_recv_udp_packet(socket_despts[i].fd,
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
                recvlen_ = mtra_recv_ip_packet(socket_despts[i].fd,
                        internal_dctp_buffer, MAX_MTU_SIZE, &src, &dest);
                // if <0, mus be something thing wrong with UDP length or
                // port number is not USED_UDP_PORT, if so, just skip this msg
                // as if we never receive it
                if (recvlen_ < 0)
                break;

//                if (saddr_family(&src) == AF_INET)
//                {
//                    EVENTLOG4(VERBOSE,
//                            "EVENTCB_TYPE_SCTP\n, recv a IPV4/DCTP-Messag from raw socket %u "
//                                    "%d bytes of data from %s:%d, port is zero as this is raw socket\n",
//                            socket_despts[i].fd, recvlen_, src_address, portnum_);
//
//                    iph = (struct iphdr *) internal_dctp_buffer;
//#if defined (__linux__)
//                    // 首部长度(4位):IP层头部包含多少个4字节 -- 32位
//                    // <<2 to get the byte size
//                    iphdrlen = iph->ihl << 2;
//#elif defined (_WIN32)
//                    iphdrlen = (iph->version_length & 0x0F) << 2;
//#else
//                    iphdrlen = iph->ip_hl << 2;
//#endif
//                    if (recvlen_ < iphdrlen)
//                    {
//                        ERRLOG1(WARNNING_ERROR,
//                                "fire_event() : packet too short, less than a ip header (%d bytes)",
//                                recvlen_);
//                    }
//                    else  // now we have at lest a enpty ip packet
//                    {
//                        // calculate ip payload size, which is DCTP packet size
//                        recvlen_ -= iphdrlen;
//                    }
//                }
//                else
//                {
//                    EVENTLOG4(VERBOSE,
//                            "EVENTCB_TYPE_SCTP\n, recv a IPV6/DCTP-Messag,\nsocket %u , recvlen_ %d, bytes data from %s:%d\n",
//                            socket_despts[i].fd, recvlen_, src_address, portnum_);
//                    iphdrlen = 0;  // for ip6, we pass the whole ip packet to dispath layer
//                }

//                if (event_callbacks[i].action.socket_cb_fun != NULL)
//                event_callbacks[i].action.socket_cb_fun(socket_despts[i].fd,
//                        &internal_dctp_buffer[iphdrlen], recvlen_, src_address,
//                        portnum_);

//                mdis_recv_geco_packet(socket_despts[i].fd, &(internal_dctp_buffer[iphdrlen]),
//                        recvlen_, &src, &dest);

#ifdef _DEBUG
                saddr2str(&src, src_address, MAX_IPADDR_STR_LEN, &portnum_);
#endif
                //recvlen_ = geco packet
                // internal_dctp_buffer = start point of  geco packet
                // src and dest port nums are carried in geco packet hdr at this moment
                if (event_callbacks[i].action.socket_cb_fun != NULL)
                event_callbacks[i].action.socket_cb_fun(socket_despts[i].fd, internal_dctp_buffer,
                        recvlen_, src_address, portnum_);
                mdis_recv_geco_packet(socket_despts[i].fd, internal_dctp_buffer, recvlen_, &src,
                        &dest);
                break;

            default:
                ERRLOG1(MAJOR_ERROR, "No such  eventcb_type %d",
                        event_callbacks[i].eventcb_type);
                break;
        }
        socket_despts[i].revents = 0;
    }
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
static struct timeval tv;
static struct timeval* to;
static int fdcount = 0;
static int nfd = 0;
static fd_set rd_fdset;
static fd_set wt_fdset;
static fd_set except_fdset;
static int mtra_poll_fds(socket_despt_t* despts, int* count, int timeout,
        void (*lock)(void* data), void (*unlock)(void* data), void* data)
{
    int i;
    int ret;
#ifdef _WIN32
    ret = MsgWaitForMultipleObjects(*count + 1, win32events_, false, timeout, QS_KEY);
    mtra_fire_event(ret);
    return 1;
#else
    to = &tv;
    fills_timeval(to, timeout);

    fdcount = 0;
    nfd = 0;
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
        ret = 0;  // win32_fds_ are all illegal we return zero, means no events triggered
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
            despts[i].revision = revision_;
        }

        /*
         * Increment the revision_ number by one -> New entries made by
         * another thread during select() call will get this new revision_ number.
         */
        ++revision_;

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
            if (despts[i].revision >= revision_)
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
            mtra_fire_event(ret);
        }
        else if (ret == 0)  //timeouts
        {
            mtra_poll_timers();
        }
        else  // -1 error
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
int mtra_poll(void (*lock)(void* data) = NULL, void (*unlock)(void* data) = NULL,
        void* data = NULL)
{
    if (lock != NULL) lock(data);
    int msecs = mtra_poll_timers();
    if (unlock != NULL) unlock(data);
    // timer timeouts
    if (msecs == 0) return msecs;
    // no timers, we use a default timeout for select
    if (msecs < 0 || msecs > GRANULARITY) msecs = GRANULARITY;

    return
    mtra_poll_fds(socket_despts, &socket_despts_size_, msecs, lock, unlock, data);
}

static bool use_udp_; /* enable udp-based-impl */
#ifdef USE_UDP
static udp_packet_fixed_t* udp_hdr_ptr_;
#endif

static int dummy_ipv4_udp_despt_;
static int dummy_ipv6_udp_despt_;

/* counter for stats we should have more counters !  */
static uint stat_send_event_size_;
static uint stat_recv_event_size_;
static uint stat_recv_bytes_;
static uint stat_send_bytes_;

#ifdef ENABLE_UNIT_TEST
test_dummy_t test_dummy_;
int dummy_sendto(int sfd, char *buf, int len, sockaddrunion *dest, uchar tos)
{
    test_dummy_.out_sfd_ = sfd;
    test_dummy_.out_tos_ = tos;
    test_dummy_.out_geco_packet_ = buf;
    test_dummy_.out_geco_packet_len_ = len;
    test_dummy_.out_dest = dest;
    return len;
}
#endif

void mtra_ctor()
{
    mtra_ip4_socket_despt_ = -1;
    mtra_ip6_socket_despt_ = -1;
    mtra_icmp_socket_despt_ = -1;

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

#ifdef ENABLE_UNIT_TEST
    test_dummy_.enable_stub_sendto_in_tspt_sendippacket_ = true;
    test_dummy_.enable_stub_error_ = true;
#endif

    internal_udp_buffer_ = (char*) malloc(USE_UDP_BUFSZ);
    internal_dctp_buffer = (char*) malloc(MAX_MTU_SIZE + 20);
    socket_despts_size_ = 0;
    revision_ = 0;
    src_addr_len_ = sizeof(src);
    recvlen_ = 0;
    portnum_ = 0;

    /*initializes the array of win32_fds_ we want to use for listening to events
     POLL_FD_UNUSED to differentiate between used/unused win32_fds_ !*/
    for (int i = 0; i < MAX_FD_SIZE; i++)
    {
        mtra_set_expected_event_on_fd(i, POLL_FD_UNUSED, 0);  // init geco socket despts
    }
}

void mtra_dtor()
{
    free(internal_udp_buffer_);
    free(internal_dctp_buffer);
    mtra_timer_mgr_.timers.clear();
    mtra_remove_stdin_cb();
    mtra_remove_event_handler(mtra_read_ip4_socket());
    mtra_remove_event_handler(mtra_read_ip6_socket());
}

static int mtra_set_sockdespt_recvbuffer_size(int sfd, int new_size)
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
static int open_ipproto_geco_socket(int af, int* rwnd)
{
    int level;

    int optname_ippmtudisc;
    int optval_ippmtudisc_do;

    int sockdespt;
    int optval = 1;
    socklen_t opt_size = sizeof(optval);
    int sockaddr_size;

    if (rwnd == NULL)
    {
        int val = DEFAULT_RWND_SIZE;
        rwnd = &val;
    }
    else
    {
        if (*rwnd < DEFAULT_RWND_SIZE)  //default recv size is 1mb
        *rwnd = DEFAULT_RWND_SIZE;
    }

#ifdef USE_UDP  //must be admin user in windows or root in linux
    sockdespt = socket(af, SOCK_RAW, IPPROTO_UDP);
#else
    sockdespt = socket(af, SOCK_RAW, IPPROTO_GECO);
#endif
    if (sockdespt < 0)
    {
        errorno(DEBUG);
        ERRLOG1(FALTAL_ERROR_EXIT, "socket()  return  %d!", sockdespt);
    }
    sockaddrunion me;
    memset(&me, 0, sizeof(sockaddrunion));
    if (af == AF_INET)
    {
        EVENTLOG1(DEBUG, "ip4 socket()::sockdespt =%d", sockdespt);
        level = IPPROTO_IP;

#if defined(Q_OS_LINUX)//only linux has IP_MTU_DISCOVER
        optname_ippmtudisc = IP_MTU_DISCOVER;
        optval_ippmtudisc_do = IP_PMTUDISC_DO;
#endif

        sockaddr_size = sizeof(struct sockaddr_in);
        /* binding to INADDR_ANY to make Windows happy... */
        me.sin.sin_family = AF_INET;
        // bind any can recv all  ip packets
        me.sin.sin_addr.s_addr = INADDR_ANY;
#ifdef USE_UDP
        me.sin.sin_port = htons(USED_UDP_PORT);
#endif
#ifdef HAVE_SIN_LEN
        me.sin_len = htons(sizeof(me));
#endif
    }
    else  //IP6
    {
        EVENTLOG1(DEBUG, "ip6 socket()::sockdespt =%d", sockdespt);

        level = IPPROTO_IPV6;

#if defined(Q_OS_LINUX) || defined(Q_OS_BSD4)
        optname_ippmtudisc = IPV6_MTU_DISCOVER;
        optval_ippmtudisc_do = IPV6_PMTUDISC_DO;
#endif

        sockaddr_size = sizeof(struct sockaddr_in6);
        /* binding to INADDR_ANY to make Windows happy... */
        me.sin6.sin6_family = AF_INET6;
        // bind any can recv all  ip packets
        me.sin6.sin6_addr = in6addr_any;
#ifdef USE_UDP
        me.sin.sin_port = htons(USED_UDP_PORT);
#endif
#ifdef HAVE_SIN_LEN
        me.sin_len = htons(sizeof(me));
#endif

#if defined(_WIN32) || defined(Q_OS_UNIX) //linux does not have IPV6_V6ONLY
        /*
         * it is OK to faile set this as we will filter out all ip4-mapped-addr in mdi
         * see http://stackoverflow.com/questions/5587935/cant-turn-off-socket-option-ipv6-v6only
         * FreeBSD since 5.x has disabled IPv4 mapped on IPv6 addresses and thus unless you turn that feature backon
         * by setting the required configuration flag in rc.conf you won't be able to use it.
         * */
        optval = 1;
        setsockopt(sockdespt, IPPROTO_IPV6, IPV6_V6ONLY, (const char*) &optval, opt_size);
#endif

        /*
         also receive packetinfo for IPv6 sockets, for getting dest address
         see http://www.sbras.ru/cgi-bin/www/unix_help/unix-man?ip6+4
         If IPV6_PKTINFO is enabled, the destination IPv6 address and the arriving
         interface index will be available via struct in6_pktinfo on ancillary
         data stream.You can pick the structure by checking for an ancillary
         data item with cmsg_level equals to IPPROTO_IPV6, and cmsg_type equals to
         IPV6_PKTINFO.
         */
        optval = 1;
        if (setsockopt(sockdespt, IPPROTO_IPV6, IPV6_PKTINFO,
                (const char*) &optval, sizeof(optval)) < 0)
        {
            // no problem we can try IPV6_RECVPKTINFO next
            EVENTLOG(DEBUG, "setsockopt: Try to set IPV6_PKTINFO but failed ! ");
        }
        else
        EVENTLOG(VERBOSE, "setsockopt(IPV6_PKTINFO) good");

#if defined(Q_OS_LINUX) || defined(Q_OS_UNIX)
        optval = 1;
        if (setsockopt(sockdespt, level, IPV6_RECVPKTINFO, (const char*) &optval, opt_size) < 0)
        {
            safe_close_soket(sockdespt);
            ERRLOG(FALTAL_ERROR_EXIT, "setsockopt: Try to set IPV6_PKTINFO but failed ! ");
        }
        EVENTLOG(VERBOSE, "setsockopt(IPV6_RECVPKTINFO) good");
#endif
    }

    //do not frag
#if defined (Q_OS_LINUX)
    /*
     * set IP_PMTUDISC_DO is actually setting DF, linux does not have constant of IP_DONTFRAGMENT
     * http://stackoverflow.com/questions/973439/how-to-set-the-dont-fragment-df-flag-on-a-socket?noredirect=1&lq=1
     * IP_MTU_DISCOVER: Sets or receives the Path MTU Discovery setting for a socket.
     * When enabled, Linux will perform Path MTU Discovery as defined in RFC 1191 on this socket.
     * The don't fragment flag is set on all outgoing datagrams.
     * */
    if (setsockopt(sockdespt, level, optname_ippmtudisc,
            (const char *) &optval_ippmtudisc_do, sizeof(optval_ippmtudisc_do)) < 0)
    {
        safe_close_soket(sockdespt);
        ERRLOG(FALTAL_ERROR_EXIT, "setsockopt: Try to set IP_MTU_DISCOVER but failed ! ");
    }
    // test to make sure we set it correctly
    if (getsockopt(sockdespt, level, optname_ippmtudisc, (char*) &optval, &opt_size) < 0)
    {
        safe_close_soket(sockdespt);
        ERRLOG(FALTAL_ERROR_EXIT, "getsockopt: IP_MTU_DISCOVER failed");
    }
    EVENTLOG1(DEBUG, "setsockopt: IP_PMTU_DISCOVER succeed!", optval);
#elif defined(_WIN32)
    optval = 1;
    if (setsockopt(sockdespt, level, IP_DONTFRAGMENT, (const char*)&optval, optval) < 0)
    {
        safe_close_soket(sockdespt);
        ERRLOG(FALTAL_ERROR_EXIT, "setsockopt: Try to set IP_DONTFRAGMENT but failed !  ");
    }
#elif defined(Q_OS_UNIX)
    optval = 1;
    if (setsockopt(sockdespt, level, IP_DONTFRAG, (const char*)&optval, optval) < 0)
    {
        safe_close_soket(sockdespt);
        ERRLOG(FALTAL_ERROR_EXIT, "setsockopt: Try to set IP_DONTFRAGMENT but failed !  ");
    }
#endif

    *rwnd = mtra_set_sockdespt_recvbuffer_size(sockdespt, *rwnd);  // 655360 bytes
    if (*rwnd < 0)
    {
        safe_close_soket(sockdespt);
        ERRLOG(FALTAL_ERROR_EXIT, "setsockopt: Try to set SO_RCVBUF but failed ! {%d} ! ");
    }

    optval = 1;
    if (setsockopt(sockdespt, SOL_SOCKET, SO_REUSEADDR, (const char*) &optval, opt_size) < 0)
    {
        safe_close_soket(sockdespt);
        ERRLOG(FALTAL_ERROR_EXIT, "setsockopt: Try to set SO_REUSEADDR but failed ! {%d} ! ");
    }

    if (bind(sockdespt, &me.sa, sockaddr_size) < 0)
    {
        ERRLOG3(FALTAL_ERROR_EXIT, "bind  %s sockdespt %d but failed %d!",
                af == AF_INET ? "ip4" : "ip6",
                sockdespt, errno);
    }

    return sockdespt;
}

static int mtra_open_ipproto_udp_socket(sockaddrunion* me, int* rwnd)
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
        if (*rwnd < DEFAULT_RWND_SIZE)  //default recv size is 1mb
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

    if (*rwnd < DEFAULT_RWND_SIZE)  //default recv size is 1mb
    *rwnd = DEFAULT_RWND_SIZE;

    //setup recv buffer option
    *rwnd = mtra_set_sockdespt_recvbuffer_size(sfd, *rwnd);  // 650KB
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
static int mtra_add_udpsock_ulpcb(const char* addr, ushort my_port, socket_cb_fun_t scb)
{
#ifdef _WIN32
    ERRLOG(MAJOR_ERROR,
            "WIN32: Registering ULP-Callbacks for UDP not installed !\n");
    return -1;
#endif

    sockaddrunion my_address;
    str2saddr(&my_address, addr, my_port);
    if (mtra_ip4_socket_despt_ > 0)
    {
        EVENTLOG2(VERBOSE,
                "Registering ULP-Callback for UDP socket on {%s :%u}\n", addr,
                my_port);
        str2saddr(&my_address, addr, my_port);
    }
    else if (mtra_ip6_socket_despt_ > 0)
    {
        EVENTLOG2(VERBOSE,
                "Registering ULP-Callback for UDP socket on {%s :%u}\n", addr,
                my_port);
        str2saddr(&my_address, addr, my_port);
    }
    else
    {
        ERRLOG(MAJOR_ERROR, "UNKNOWN ADDRESS TYPE - CHECK YOUR PROGRAM !\n");
        return -1;
    }
    int new_sfd = mtra_open_ipproto_udp_socket(&my_address, 0);
    cbunion_.socket_cb_fun = scb;
    mtra_set_expected_event_on_fd(new_sfd,
    EVENTCB_TYPE_UDP, POLLIN | POLLPRI, cbunion_, NULL);
    EVENTLOG1(VERBOSE,
            "Registered ULP-Callback: now %d registered callbacks !!!\n",
            new_sfd);
    return new_sfd;
}
void add_user_cb(int fd, user_cb_fun_t cbfun, void* userData, short int eventMask)
{
#ifdef _WIN32
    ERRLOG(MAJOR_ERROR,
            "WIN32: Registering User Callbacks not installed !\n");
#endif
    cbunion_.user_cb_fun = cbfun;
    /* 0 is the standard input ! */
    mtra_set_expected_event_on_fd(fd, EVENTCB_TYPE_USER, eventMask, cbunion_,
            userData);
    EVENTLOG2(VERBOSE, "Registered User Callback: fd=%d eventMask=%d\n", fd,
            eventMask);
}
int mtra_send_udp_packet(int sfd, char* buf, int length, sockaddrunion* destsu)
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

    if (sfd == mtra_ip4_socket_despt_ || sfd == mtra_ip6_socket_despt_)
    {
        ERRLOG(MINOR_ERROR, "cannot send udp msg on a geco socket!\n");
    }

    //int destlen;
    int result;
    switch (saddr_family(destsu))
    {
        case AF_INET:
            //destsu.sin.sin_port = htons(dest_port);
            result = sendto(sfd, buf, length, 0, &(destsu->sa), sizeof(struct sockaddr_in));
            break;
        case AF_INET6:
            //destsu.sin6.sin6_port = htons(dest_port);
            result = sendto(sfd, buf, length, 0, &(destsu->sa),
                    sizeof(struct sockaddr_in6));
            break;
        default:
            ERRLOG(MAJOR_ERROR, "Invalid AF address family in send_udp_msg()\n");
            result = -1;
            break;
    }
    EVENTLOG2(VERBOSE, "send_udp_msg(%d bytes data) to sfd (%d)", result, sfd);
    return result;
}
int mtra_send_ip_packet(int sfd, char *buf, int len,
        sockaddrunion *dest, uchar tos)
{
    EVENTLOG(VERBOSE, "- - - - - -Enter mtra_send_ip_packet()- - - - - - ");

    static int txmt_len = 0;
    static uchar old_tos;
    static socklen_t opt_len;
    static int tmp;

#ifdef USE_UDP
    //len = udphdr placeholder 8 vytes + data
    // buf is the start of packet pointing to udphdr
    if (USE_UDP_BUFSZ < len)
    {
        ERRLOG(FALTAL_ERROR_EXIT, "msg is too large ! bye !\n");
        return -1;
    }

    udp_hdr_ptr_ = (udp_packet_fixed_t*) buf;
    udp_hdr_ptr_->src_port = htons(USED_UDP_PORT);
    udp_hdr_ptr_->length = htons(len);
    udp_hdr_ptr_->checksum = 0x0000;
    //udp_hdr_ptr_->checksum = udp_checksum(udp_hdr_ptr_, packet_total_length);
#endif

    switch (saddr_family(dest))
    {
        case AF_INET:
            udp_hdr_ptr_->dest_port = dest->sin.sin_port;
            dest->sin.sin_port = 0;
            opt_len = sizeof(old_tos);
            tmp = getsockopt(sfd, IPPROTO_IP, IP_TOS, (char*) &old_tos, &opt_len);
            if (tmp < 0)
            {
#if ENABLE_UNIT_TEST ==1
                if (!test_dummy_.enable_stub_error_)
                {
                    ERRLOG(MAJOR_ERROR, "getsockopt(tos) failed!\n");
                    return -1;
                }
                else
                EVENTLOG(DEBUG, "mock -> skip getsockopt(tos) error");
#else
                ERRLOG(MAJOR_ERROR, "getsockopt(tos) failed!\n");
                return -1;
#endif
            }
            tmp = setsockopt(sfd, IPPROTO_IP, IP_TOS, (char*) &tos, sizeof(char));
            if (tmp < 0)
            {
#if ENABLE_UNIT_TEST ==1
                if (!test_dummy_.enable_stub_error_)
                {
                    ERRLOG(MAJOR_ERROR, "setsockopt(tos) failed!\n");
                    return -1;
                }
                else
                EVENTLOG(DEBUG, "mock -> skip setsockopt(tos) error");
#else
                ERRLOG(MAJOR_ERROR, "setsockopt(tos) failed!\n");
                return -1;
#endif
            }
            txmt_len = sendto(sfd, buf, len, 0, &(dest->sa), sizeof(struct sockaddr_in));
            EVENTLOG6(VERBOSE,
                    "sendto(sfd %d,len %d,destination %s::%u,IP_TOS %u) returns txmt_len %d",
                    sfd, len, inet_ntoa(dest->sin.sin_addr), ntohs(dest->sin.sin_port), tos,
                    txmt_len);
            if (txmt_len < 0) return txmt_len;
            break;

        case AF_INET6:
            udp_hdr_ptr_->dest_port = dest->sin6.sin6_port;
            dest->sin6.sin6_port = 0;  //reset to zero otherwise invalidate argu error

            char hostname[MAX_IPADDR_STR_LEN];
            if (inet_ntop(AF_INET6, s6addr(dest), (char *) hostname,
            MAX_IPADDR_STR_LEN) == NULL)
            {
                ERRLOG(MAJOR_ERROR, "inet_ntop()  buffer is too small !\n");
                return -1;
            }

            txmt_len = sendto(sfd, buf, len, 0, &(dest->sa), sizeof(struct sockaddr_in6));
            EVENTLOG6(VERBOSE,
                    "sendto(sfd %d,len %d,destination %s::%u,IP_TOS %u) returns txmt_len %d",
                    sfd, len, hostname, ntohs(dest->sin6.sin6_port), tos, txmt_len);
            if (txmt_len < 0) return txmt_len;
            break;
        default:
            ERRLOG1(MAJOR_ERROR, "no such Adress Family %u !",
                    saddr_family(dest));
            return -1;
            break;
    }

#ifdef USE_UDP
    if (txmt_len >= (int) UDP_PACKET_FIXED_SIZE)
    {
        txmt_len -= (int) UDP_PACKET_FIXED_SIZE;
    }
#endif

    stat_send_event_size_++;
    stat_send_bytes_ += txmt_len;

    EVENTLOG3(VERBOSE,
            "send times %u, send total bytes_ %u, packet len %u",
            stat_send_event_size_, stat_send_bytes_,
            len - UDP_PACKET_FIXED_SIZE);

    EVENTLOG(VERBOSE, "- - - - - -Leave mtra_send_ip_packet()- - - - - - ");
    return txmt_len;
}
int mtra_recv_ip_packet(int sfd, char *dest, int maxlen,
        sockaddrunion *from, sockaddrunion *to)
{
    if ((dest == NULL) || (from == NULL) || (to == NULL))
    {
        ERRLOG(MAJOR_ERROR, "some param is NULL !\n");
        return -1;
    }

    int len = -1;
    int iphdrlen;

    if (sfd == mtra_ip4_socket_despt_)
    {
        //recv packet = iphdr + [upphdr] + data
        //len = len(iphdr + [upphdr] + data)
        len = recv(sfd, dest, maxlen, 0);        // recv a packet each time
        static struct iphdr *iph;
        iph = (struct iphdr *) dest;
        iphdrlen = (int) sizeof(struct iphdr);

        to->sa.sa_family = AF_INET;
        to->sin.sin_port = 0;        //iphdr does NOT have port so we just set it to zero
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
    else if (sfd == mtra_ip6_socket_despt_)
    {
        //recv packet = iphdr + [upphdr] + data
        //len = len([upphdr] + data) so iphdrlen is set to zero
        iphdrlen = 0;

        struct msghdr rmsghdr;
        struct cmsghdr *rcmsgp;
        struct iovec data_vec;
        data_vec.iov_base = dest;
        data_vec.iov_len = maxlen;
        char m6buf[(CMSG_SPACE(sizeof(struct in6_pktinfo)))];
        struct in6_pktinfo *pkt6info;

        rcmsgp = (struct cmsghdr *) m6buf;
        pkt6info = (struct in6_pktinfo *) (MY_CMSG_DATA(rcmsgp));

        /* receive control msg */
        rcmsgp->cmsg_level = IPPROTO_IPV6;
        rcmsgp->cmsg_type = IPV6_PKTINFO;
        rcmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

#ifdef _WIN32
        DWORD dwBytes = 0;
        data_vec.buf = dest;
        data_vec.len = maxlen;
        rmsghdr.dwFlags = 0;
        rmsghdr.lpBuffers = &data_vec;
        rmsghdr.dwBufferCount = 1;
        rmsghdr.name = (sockaddr*)&(from->sin6);
        rmsghdr.namelen = sizeof(struct sockaddr_in6);
        rmsghdr.Control.buf = m6buf;
        rmsghdr.Control.len = sizeof(m6buf);
        recvmsg(sfd, (LPWSAMSG)&rmsghdr, &dwBytes, NULL, NULL);
        len = dwBytes;
#else
        rmsghdr.msg_flags = 0;
        rmsghdr.msg_iov = &data_vec;
        rmsghdr.msg_iovlen = 1;
        rmsghdr.msg_name = (caddr_t) &(from->sin6);
        rmsghdr.msg_namelen = sizeof(struct sockaddr_in6);
        rmsghdr.msg_control = (caddr_t) m6buf;
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
        ERRLOG(MAJOR_ERROR, "recv_geco_msg()::no such AF!");
        return -1;
    }

#ifdef USE_UDP
    int ip_pk_hdr_len = iphdrlen + (int) UDP_PACKET_FIXED_SIZE;
    if (len < ip_pk_hdr_len)
    {
        ERRLOG(WARNNING_ERROR, "recv_geco_msg():: ip_pk_hdr_len illegal!");
        return -1;
    }

    // check dest_port legal
    // nat only changes src addr and src port, never changing dest port
    if (ntohs(((udp_packet_fixed_t*) (dest + iphdrlen))->dest_port) != USED_UDP_PORT)
    {
        //ERRLOG(WARNNING_ERROR, "recv_geco_msg()::dest_port != USED_UDP_PORT !");
        return -1;
    }

    // currently  iphdr+udphdr + data, now we need move data to the front of this packet,
    // skipping all bytes in iphdr and updhdr as if hey  never exists
    memmove(dest, dest + ip_pk_hdr_len, len - ip_pk_hdr_len);
    len -= ip_pk_hdr_len;
#endif

    EVENTLOG1(VERBOSE, "recv_geco_msg():: recv %d bytes od data\n", len);
    return len;
}
int mtra_recv_udp_packet(int sfd, char *dest, int maxlen,
        sockaddrunion *from, socklen_t *from_len)
{
    int len;
    if ((len = recvfrom(sfd, dest, maxlen, 0, (struct sockaddr *) from,
            from_len)) < 0)
    ERRLOG(MAJOR_ERROR, "recvfrom  failed in get_message(), aborting !\n");
    return len;
}

void mtra_destroy()
{
    mtra_dtor();
}
int mtra_init(int * myRwnd)
{
    mtra_ctor();  // init mtra variables

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

    /*open two sockets for ip4 and ip6 */
    if ((mtra_ip4_socket_despt_ = open_ipproto_geco_socket(AF_INET, myRwnd)) < 0)
    return mtra_ip4_socket_despt_;
    if ((mtra_ip6_socket_despt_ = open_ipproto_geco_socket(AF_INET6, myRwnd)) < 0)
    return mtra_ip6_socket_despt_;
    if (*myRwnd == -1) *myRwnd = DEFAULT_RWND_SIZE; /* set a safe default */

//open udp socket despt binf to dummy sadress 0.0.0.0 to recv all datagrams
// destinated to any adress with matched port

//@FIXME we do not need this because we use raw udp socket
//#ifdef USE_UDP
//	sockaddrunion su;
//	str2saddr(&su, NULL, USED_UDP_PORT);
//	dummy_ipv4_udp_despt_ = mtra_open_ipproto_udp_socket(&su, myRwnd);
//	if (dummy_ipv4_udp_despt_ < 0)
//	{
//		ERRLOG(MAJOR_ERROR, "Could not open UDP dummy socket !\n");
//		return dummy_ipv4_udp_despt_;
//	}
//	EVENTLOG1(VERBOSE, "init()::dummy_ipv4_udp_despt_(%u)",
//		dummy_ipv4_udp_despt_);
//	dummy_ipv6_udp_despt_ = mtra_open_ipproto_udp_socket(&su, myRwnd);
//	if (dummy_ipv6_udp_despt_ < 0)
//	{
//		ERRLOG(MAJOR_ERROR, "Could not open UDP dummy socket !\n");
//		return dummy_ipv6_udp_despt_;
//	}
//	EVENTLOG1(VERBOSE, "init()::dummy_ipv6_udp_despt_(%u)",
//		dummy_ipv6_udp_despt_);
//#endif

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
