#include "poller.h"

#ifdef SCTP_OVER_UDP
int dummy_sctp_udp;
int dummy_sctpv6_udp;
static uint inet_checksum(const void* ptr, size_t count)
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
#endif



/*================ Poll Implementation =================*/
struct extendedpollfd
{
    int       fd;
    int events;
    int revents;
    long      revision;
};


#ifdef _WIN32
struct input_data {
    DWORD len;
    char buffer[1024];
    HANDLE event, eventback;
};

static int fds[MAX_FD_SIZE];
static int fdnum;
HANDLE            hEvent, handles[2];
static HANDLE  stdin_thread_handle;
WSAEVENT       stdinevent;
static struct input_data   idata;
#endif

static long revision = 0;
static long rstate[2];

/* a static counter - for stats we should have more counters !  */
static unsigned int stat_send_event_size = 0;
/* a static receive buffer  */
static unsigned char internal_receive_buffer[MAX_MTU_SIZE + 20];
/* a static value that keeps currently treated timer id */
static unsigned int curr_timer = 0;


static struct extendedpollfd poll_fds[MAX_FD_SIZE];
static int num_of_fds = 0;

static int socket_fd_port = -1;       /* socket fd for standard SCTP port....      */
static int sctpv6_sfd = -1;
static int icmp_sfd = -1;        /* socket fd for ICMP messages */

static struct event_cb *event_callbacks[MAX_FD_SIZE];
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