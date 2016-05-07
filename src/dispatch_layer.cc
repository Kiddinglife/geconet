#include "dispatch_layer.h"
#include "globals.h"

void dispatch_layer_t::recv_dctp_packet(int socket_fd, char *dctp_packet,
    int dctp_packet_len, union sockaddrunion * source_addr,
union sockaddrunion * dest_addr)
{
    event_logiii(verbose, "recv_dctp_packet()::recvied  %d bytes of data %s from dctp fd %d\n",
        dctp_packet_len, dctp_packet, socket_fd);

    /* sanity check for size (min,max, aligned 4 bytes, validate checksum)
     * skip this packet if incorrect */
    if (dctp_packet_len % 4 != 0 ||
        dctp_packet_len < MIN_NETWORK_PACKET_HDR_SIZES ||
        dctp_packet_len > MAX_NETWORK_PACKET_HDR_SIZES ||
        !validate_crc32_checksum(dctp_packet, dctp_packet_len))
    {
        event_log(loglvl_intevent, "received corrupted datagramm\n");
        last_source_addr_ = NULL;
        last_dest_addr_ = NULL;
        return;
    }

    /* check port numbers */
    dctp_packet_fixed_t* dctp_packet_fixed = (dctp_packet_fixed_t*)dctp_packet;
    last_src_port_ = ntohs(dctp_packet_fixed->src_port);
    last_dest_port_ = ntohs(dctp_packet_fixed->dest_port);
    if (last_src_port_ == 0 || last_dest_port_ == 0)
    {
        error_log(loglvl_minor_error,
            " dispatch_layer_t::recv_dctp_packet():: invalid ports number (0)\n");
        last_source_addr_ = NULL;
        last_dest_addr_ = NULL;
        last_src_port_ = 0;
        last_dest_port_ = 0;
        return;
    }

    /* check ip addresses */
    bool discard = false;
    int address_type;
    switch (saddr_family(dest_addr))
    {
        case AF_INET:
            event_log(verbose,
                "dispatch_layer_t::recv_dctp_packet()::checking for correct IPV4 addresses\n");
            address_type = SUPPORT_ADDRESS_TYPE_IPV4;
            uint saddr = ntohl(dest_addr->sin.sin_addr.s_addr);
            if (IN_CLASSD(saddr)) discard = true;
            if (IN_EXPERIMENTAL(saddr)) discard = true;
            if (IN_BADCLASS(saddr)) discard = true;
            if (INADDR_ANY == saddr) discard = true;
            if (INADDR_BROADCAST == saddr) discard = true;

            saddr = ntohl(source_addr->sin.sin_addr.s_addr);
            if (IN_CLASSD(saddr)) discard = true;
            if (IN_EXPERIMENTAL(saddr)) discard = true;
            if (IN_BADCLASS(saddr)) discard = true;
            if (INADDR_ANY == saddr) discard = true;
            if (INADDR_BROADCAST == saddr) discard = true;

            /* if ((INADDR_LOOPBACK != ntohl(source_addr->sin.sin_addr.s_addr)) &&
            (source_addr->sin.sin_addr.s_addr == dest_addr->sin.sin_addr.s_addr)) discard = true;*/
            break;
        case AF_INET6:
            address_type = SUPPORT_ADDRESS_TYPE_IPV6;
            event_log(verbose, "recv_dctp_packet: checking for correct IPV6 addresses\n");
#if defined (__linux__)
            if (IN6_IS_ADDR_UNSPECIFIED(&(dest_addr->sin6.sin6_addr.s6_addr))) discard = true;
            if (IN6_IS_ADDR_MULTICAST(&(dest_addr->sin6.sin6_addr.s6_addr))) discard = true;
            /* if (IN6_IS_ADDR_V4COMPAT(&(dest_addr->sin6.sin6_addr.s6_addr))) discard = true; */

            if (IN6_IS_ADDR_UNSPECIFIED(&(source_addr->sin6.sin6_addr.s6_addr))) discard = true;
            if (IN6_IS_ADDR_MULTICAST(&(source_addr->sin6.sin6_addr.s6_addr))) discard = true;
            /*  if (IN6_IS_ADDR_V4COMPAT(&(source_addr->sin6.sin6_addr.s6_addr))) discard = true; */
            /*
            if ((!IN6_IS_ADDR_LOOPBACK(&(source_addr->sin6.sin6_addr.s6_addr))) &&
            IN6_ARE_ADDR_EQUAL(&(source_addr->sin6.sin6_addr.s6_addr),
            &(dest_addr->sin6.sin6_addr.s6_addr))) discard = true;
            */
#else
            if (IN6_IS_ADDR_UNSPECIFIED(&(dest_addr->sin6.sin6_addr))) discard = true;
            if (IN6_IS_ADDR_MULTICAST(&(dest_addr->sin6.sin6_addr))) discard = true;
            /* if (IN6_IS_ADDR_V4COMPAT(&(dest_addr->sin6.sin6_addr))) discard = true; */

            if (IN6_IS_ADDR_UNSPECIFIED(&(source_addr->sin6.sin6_addr))) discard = true;
            if (IN6_IS_ADDR_MULTICAST(&(source_addr->sin6.sin6_addr))) discard = true;

            /* if (IN6_IS_ADDR_V4COMPAT(&(source_addr->sin6.sin6_addr))) discard = true; */
            /*
            if ((!IN6_IS_ADDR_LOOPBACK(&(source_addr->sin6.sin6_addr))) &&
            IN6_ARE_ADDR_EQUAL(&(source_addr->sin6.sin6_addr),
            &(dest_addr->sin6.sin6_addr))) discard = true;
            */
#endif
            break;
        default:
            error_log(loglvl_fatal_error_exit,
                "recv_dctp_packet()::Unsupported AddressType Received !\n");
            discard = true;
            break;
    }

    char src_addr_str[MAX_IPADDR_STR_LEN];
    saddr2str(source_addr, src_addr_str, MAX_IPADDR_STR_LEN, NULL);
    char dest_addr_str[MAX_IPADDR_STR_LEN];
    saddr2str(dest_addr, dest_addr_str, MAX_IPADDR_STR_LEN, NULL);
    event_logiiiii(loglvl_extevent,
        "recv_dctp_packet : len %d, sourceaddress : %s, src_port %u,dest: %s, dest_port %u",
        dctp_packet_len, src_addr_str, last_src_port_, dest_addr_str, last_dest_port_);

    if (discard)
    {
        last_source_addr_ = NULL;
        last_dest_addr_ = NULL;
        last_src_port_ = 0;
        last_dest_port_ = 0;
        event_logii(loglvl_intevent, "recv_dctp_packet()::discarding packet for incorrect address\n src addr : %s,\ndest addr%s", 
            src_addr_str, dest_addr_str);
        return;
    }

    //@todo here ........

    int chunk_total_len = dctp_packet_len - DCTP_PACKET_FIXED_SIZE;
    init_chunk_fixed_t* init_chunk_fixed;
    vlparam_fixed_t* vlparam_fixed;

    uchar* init_ptr;
    char src_addr_str[MAX_IPADDR_STR_LEN];
    char dest_addr_str[MAX_IPADDR_STR_LEN];

    sockaddrunion alternate_addr;
    dispatcher_t temp_dispatcher;
}