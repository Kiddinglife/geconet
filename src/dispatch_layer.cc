#include "dispatch_layer.h"
#include "globals.h"

void dispatch_layer_t::recv_dctp_packet(int socket_fd, char *buffer,
    int bufferLength, union sockaddrunion * source_addr,
union sockaddrunion * dest_addr)
{
    event_logii(verbose, "recv_dctp_packet()::recvied  data %d from dctp fd %d\n", 
        *(int*)buffer, socket_fd);
}