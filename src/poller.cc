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

#ifdef _WIN32
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

static long rstate[2];
