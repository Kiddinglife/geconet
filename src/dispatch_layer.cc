#include "dispatch_layer.h"
#include <algorithm>
#include "globals.h"

dispatch_layer_t::dispatch_layer_t()
{
    sctpLibraryInitialized = false;
    dispatcher_ = NULL;
    last_source_addr_ = last_dest_addr_ = 0;
    last_src_path_ = last_dest_port_ = 0;
    last_init_tag_ = 0;
    endpoints_list_.reserve(DEFAULT_ENDPOINT_SIZE);
}

void dispatch_layer_t::recv_dctp_packet(int socket_fd, char *dctp_packet,
    int dctp_packet_len,
    sockaddrunion * source_addr,
    sockaddrunion * dest_addr)
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
    uint saddr;
    switch (saddr_family(dest_addr))
    {
        case AF_INET:
            event_log(verbose,
                "dispatch_layer_t::recv_dctp_packet()::checking for correct IPV4 addresses\n");
            address_type = SUPPORT_ADDRESS_TYPE_IPV4;
            saddr = ntohl(dest_addr->sin.sin_addr.s_addr);
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

    /*retrive the related endpoint*/
    curr_endpoint_ptr_ = find_endpoint_by_addr(last_source_addr_, last_src_port_, last_dest_port_);

    int supported_addr_types = 0;
    if (curr_endpoint_ptr_ != NULL)
    {
        /* meaning we MUST have an instance with no fixed port */
        dispatcher_ = curr_endpoint_ptr_->dispatcher;
        supported_addr_types = 0;
    }
    else
    {
        /*
        OK - if this packet is for a server, we will find an SCTP instance, that shall
        handle it (i.e. we have the SCTP instance's localPort set and it matches the
        packet's destination port
        */
    }


    int chunk_total_len = dctp_packet_len - DCTP_PACKET_FIXED_SIZE;
    init_chunk_fixed_t* init_chunk_fixed;
    vlparam_fixed_t* vlparam_fixed;

    uchar* init_ptr;

    sockaddrunion alternate_addr;
    dispatcher_t temp_dispatcher;
}


endpoint_t* dispatch_layer_t::find_endpoint_by_addr(
    sockaddrunion * src_addr,
    ushort src_port,
    ushort dest_port)
{
    tmp_endpoint_.remote_addres_size = 1;
    tmp_endpoint_.remote_addres = &tmp_addr;

    switch (saddr_family(src_addr))
    {
        case AF_INET:
            event_logi(loglvl_intevent,
                "Looking for IPv4 Address %x (in NBO)", s4addr(src_addr));
            tmp_endpoint_.remote_addres[0].sa.sa_family = AF_INET;
            tmp_endpoint_.remote_addres[0].sin.sin_addr.s_addr = s4addr(src_addr);
            tmp_endpoint_.remote_port = src_port;
            tmp_endpoint_.local_port = dest_port;
            tmp_endpoint_.deleted = false;
            break;
        case AF_INET6:
            tmp_endpoint_.remote_addres[0].sa.sa_family = AF_INET6;
            memcpy(&(tmp_endpoint_.remote_addres[0].sin6.sin6_addr.s6_addr),
                (s6addr(src_addr)), sizeof(struct in6_addr));
            event_logi(loglvl_intevent, "Looking for IPv6 Address %x, check NTOHX() ! ",
                tmp_endpoint_.remote_addres[0].sin6.sin6_addr.s6_addr);
            tmp_endpoint_.remote_port = src_port;
            tmp_endpoint_.local_port = dest_port;
            tmp_endpoint_.deleted = false;
            break;
        default:
            error_logi(loglvl_fatal_error_exit,
                "Unsupported Address Family %d in find_endpoint_by_addr()",
                saddr_family(src_addr));
            break;
    }

    /* search for this endpoint from list*/
    endpoint_t* result = NULL;
    for (auto i = endpoints_list_.begin(); i != endpoints_list_.end(); i++)
    {
        if (cmp_endpoint_by_addr_port(tmp_endpoint_, *(*i)))
        {
            result = *i;
            break;
        }
    }

    if (result != NULL)
    {
        if (result->deleted)
        {
            event_logi(verbose,
                "Found endpoint that should be deleted, with id %u\n", result->ep_id);
            result = NULL;
        }
        else
        {
            event_logi(verbose, "Found valid endpoint with id %u\n", result->ep_id);
        }
    }
    else
    {
        event_log(loglvl_intevent, "endpoint indexed by transport address not in list");
    }

    return result;
}

bool dispatch_layer_t::cmp_endpoint_by_addr_port(const endpoint_t& a, const endpoint_t& b)
{
    event_logii(verbose,
        "cmp_endpoint_by_addr_port(): checking ep A[id=%d] and ep B[id=%d]\n",
        a.ep_id, b.ep_id);
    if (a.remote_port == b.remote_port && a.local_port == b.local_port)
    {
        int i, j;
        /*find if at least there is an ip addr thate quals*/
        for (i = 0; i < a.remote_addres_size; i++)
        {
            for (j = 0; j < b.remote_addres_size; j++)
            {
                if (saddr_equals(&(a.remote_addres[i]), &(b.remote_addres[j])))
                {
                    if (!a.deleted && !b.deleted)
                    {
                        event_log(verbose,
                            "cmp_endpoint_by_addr_port(): found TWO equal ep !");
                        return true;
                    }
                }
            }
        }
        event_log(verbose,
            "cmp_endpoint_by_addr_port(): found No equal ep !");
        return false;
    }
    else
    {
        event_log(verbose,
            "cmp_endpoint_by_addr_port(): found No equal ep !");
        return false;
    }
}