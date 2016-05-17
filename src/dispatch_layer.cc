#include "dispatch_layer.h"
#include "geco-ds-malloc.h"
#include <algorithm>

#define NULL_DEST_INDEX NULL

dispatch_layer_t::dispatch_layer_t()
{
    assert(MAX_NETWORK_PACKET_VALUE_SIZE == sizeof(simple_chunk_t));

    sctpLibraryInitialized = false;
    curr_channel_ = NULL;
    curr_geco_instance_ = NULL;

    last_source_addr_ = last_dest_addr_ = 0;
    last_src_port_ = last_dest_port_ = 0;
    last_init_tag_ = 0;
    last_src_path_ = 0;

    endpoints_list_.reserve(DEFAULT_ENDPOINT_SIZE);
    memset(found_addres_, 0, MAX_NUM_ADDRESSES * sizeof(sockaddrunion));

    free_chunk_id_ = 0;
    memset(simple_chunks_, 0, MAX_NETWORK_PACKET_VALUE_SIZE * MAX_CHUNKS_SIZE);
    memset(write_cursors_, 0, MAX_CHUNKS_SIZE);
    memset(completed_chunks_, 0, MAX_CHUNKS_SIZE);

    send_abort_for_oob_packet_ = true;
}

void dispatch_layer_t::recv_dctp_packet(int socket_fd, char *dctp_packet,
    uint dctp_packet_len, sockaddrunion * source_addr,
    sockaddrunion * dest_addr)
{
    event_logiii(verbose,
        "recv_dctp_packet()::recvied  %d bytes of data %s from dctp fd %d\n",
        dctp_packet_len, dctp_packet, socket_fd);

    /* 1) validate packet hdr size, checksum and if aligned 4 bytes */
    if (dctp_packet_len % 4 != 0
        || dctp_packet_len < MIN_NETWORK_PACKET_HDR_SIZES
        || dctp_packet_len > MAX_NETWORK_PACKET_HDR_SIZES
        || !validate_crc32_checksum(dctp_packet, dctp_packet_len))
    {
        event_log(loglvl_intevent, "received corrupted datagramm\n");
        return;
    }

    /* 2) validate port numbers */
    geco_packet_fixed_t* dctp_packet_fixed = (geco_packet_fixed_t*)dctp_packet;
    last_src_port_ = ntohs(dctp_packet_fixed->src_port);
    last_dest_port_ = ntohs(dctp_packet_fixed->dest_port);
    if (last_src_port_ == 0 || last_dest_port_ == 0)
    {
        /* refers to RFC 4960 Section 3.1 at line 867 and line 874*/
        error_log(loglvl_minor_error,
            " dispatch_layer_t::recv_dctp_packet():: invalid ports number (0)\n");
        last_src_port_ = 0;
        last_dest_port_ = 0;
        return;
    }

    /* 3) validate ip addresses */
    bool discard;
    int address_type;
    int supported_addr_types;
    uint ip4_saddr;
    switch (saddr_family(dest_addr))
    {
        case AF_INET:
            event_log(verbose,
                "dispatch_layer_t::recv_dctp_packet()::checking for correct IPV4 addresses\n");
            address_type = SUPPORT_ADDRESS_TYPE_IPV4;
            ip4_saddr = ntohl(dest_addr->sin.sin_addr.s_addr);
            if (IN_CLASSD(ip4_saddr))
                discard = true;
            if (IN_EXPERIMENTAL(ip4_saddr))
                discard = true;
            if (IN_BADCLASS(ip4_saddr))
                discard = true;
            if (INADDR_ANY == ip4_saddr)
                discard = true;
            if (INADDR_BROADCAST == ip4_saddr)
                discard = true;

            ip4_saddr = ntohl(source_addr->sin.sin_addr.s_addr);
            if (IN_CLASSD(ip4_saddr))
                discard = true;
            if (IN_EXPERIMENTAL(ip4_saddr))
                discard = true;
            if (IN_BADCLASS(ip4_saddr))
                discard = true;
            if (INADDR_ANY == ip4_saddr)
                discard = true;
            if (INADDR_BROADCAST == ip4_saddr)
                discard = true;

            /* we should not discard the msg sent to ourself */
            /* if ((INADDR_LOOPBACK != ntohl(source_addr->sin.sin_addr.s_addr)) &&
             (source_addr->sin.sin_addr.s_addr == dest_addr->sin.sin_addr.s_addr)) discard = true;*/
            break;

        case AF_INET6:
            event_log(verbose,
                "recv_dctp_packet: checking for correct IPV6 addresses\n");
            address_type = SUPPORT_ADDRESS_TYPE_IPV6;
#if defined (__linux__)
            if (IN6_IS_ADDR_UNSPECIFIED(dest_addr->sin6.sin6_addr.s6_addr))
                discard = true;
            if (IN6_IS_ADDR_MULTICAST(dest_addr->sin6.sin6_addr.s6_addr))
                discard = true;
            /* if (IN6_IS_ADDR_V4COMPAT(&(dest_addr->sin6.sin6_addr.s6_addr))) discard = true; */

            if (IN6_IS_ADDR_UNSPECIFIED(source_addr->sin6.sin6_addr.s6_addr))
                discard = true;
            if (IN6_IS_ADDR_MULTICAST(source_addr->sin6.sin6_addr.s6_addr))
                discard = true;
            /*  if (IN6_IS_ADDR_V4COMPAT(&(source_addr->sin6.sin6_addr.s6_addr))) discard = true; */
            /*
             if ((!IN6_IS_ADDR_LOOPBACK(&(source_addr->sin6.sin6_addr.s6_addr))) &&
             IN6_ARE_ADDR_EQUAL(&(source_addr->sin6.sin6_addr.s6_addr),
             &(dest_addr->sin6.sin6_addr.s6_addr))) discard = true;
             */
#else
            if (IN6_IS_ADDR_UNSPECIFIED(&dest_addr->sin6.sin6_addr)) discard = true;
            if (IN6_IS_ADDR_MULTICAST(&dest_addr->sin6.sin6_addr)) discard = true;
            /* if (IN6_IS_ADDR_V4COMPAT(&(dest_addr->sin6.sin6_addr))) discard = true; */

            if (IN6_IS_ADDR_UNSPECIFIED(&source_addr->sin6.sin6_addr)) discard = true;
            if (IN6_IS_ADDR_MULTICAST(&source_addr->sin6.sin6_addr)) discard = true;

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
        "recv_dctp_packet : packet_val_len %d, sourceaddress : %s, src_port %u,dest: %s, dest_port %u",
        dctp_packet_len, src_addr_str, last_src_port_, dest_addr_str,
        last_dest_port_);

    if (discard)
    {
        last_src_port_ = 0;
        last_dest_port_ = 0;
        event_logii(loglvl_intevent,
            "recv_dctp_packet()::discarding packet for incorrect address\n src addr : %s,\ndest addr%s",
            src_addr_str, dest_addr_str);
        return;
    }

    last_source_addr_ = source_addr;
    last_dest_addr_ = dest_addr;

    /*4) find the endpoint for this packet */
    curr_channel_ = find_channel_by_transport_addr(last_source_addr_,
        last_src_port_, last_dest_port_);

    if (curr_channel_ != NULL)
    {
        event_log(loglvl_intevent, "Found channel from this packet!");
        /*5) get the sctp instance for this packet from channel*/
        supported_addr_types = 0;
        curr_geco_instance_ = curr_channel_->dispatcher;
        if (curr_geco_instance_ == NULL)
        {
            error_log(loglvl_fatal_error_exit,
                "Foundchannel, but no geo Instance, FIXME !");
            return;
        }
    }
    else
    {
        /* 6) find dctp instancefor this packet
         *  if this packet is for a server dctp instance,
         *  we will find that dctp instance and let it handle this packet
         *  (i.e. we have the dctp instance's localPort set and
         *  it matches the packet's destination port) */
        curr_geco_instance_ = find_geco_instance_by_transport_addr(dest_addr,
            address_type);
        if (curr_geco_instance_ == NULL)
        {
            /* 7) may be an an endpoint that is a client (with instance port 0) */
            event_logi(verbose,
                "Couldn't find SCTP Instance for Port %u and Address in List !",
                last_dest_port_);
            address_type == SUPPORT_ADDRESS_TYPE_IPV4 ?
                supported_addr_types = SUPPORT_ADDRESS_TYPE_IPV4 :
                supported_addr_types = SUPPORT_ADDRESS_TYPE_IPV4
                | SUPPORT_ADDRESS_TYPE_IPV6;
        }
        else
        {
            supported_addr_types = curr_geco_instance_->supportedAddressTypes;
            event_logii(verbose,
                "Found an SCTP Instance for Port %u and Address in the list, types: %d !",
                last_dest_port_, supported_addr_types);
        }
    }

    /*8) now we can validate if dest_addr in localaddress */
    if (!validate_dest_addr(dest_addr))
    {
        event_log(verbose,
            "recv_dctp_packet()::this packet is not for me, DISCARDING !!!");
        clear();
        return;
    }

    /*9) fetch all chunk types contained in this packet value field for use in the folowing */
    int packet_value_len = dctp_packet_len - GECO_PACKET_FIXED_SIZE;
    uint chunk_types_arr = find_chunk_types(
        ((dctp_packet_t*)dctp_packet)->chunk, packet_value_len);

    int i = 0;
    int retval = 0;
    uchar* init_chunk = NULL;
    sockaddrunion addr_from_init_or_ack_chunk;
    bool found_existed_channel_from_init_chunks;

    /* 10) validate individual chunks
     * (see section 3.1 of RFC 4960 at line 931 init chunk MUST be the only chunk
     * in the SCTP packet carrying it)*/
    if (contains_chunk((uchar)CHUNK_INIT, chunk_types_arr) == 2
        || contains_chunk((uchar)CHUNK_INIT_ACK, chunk_types_arr) == 2
        || contains_chunk((uchar)CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr)
        == 2)
    {
        /* silently discard */
        error_log(loglvl_minor_error,
            "recv_dctp_packet(): discarding illegal packet (init init ack or sdcomplete)\n");
        clear();
        return;
    }

    last_src_path_ = 0;
    bool send_abort = false;
    bool found_init_chunk = false;
    init_chunk_fixed_t* init_chunk_fixed = NULL;
    vlparam_fixed_t* vlparam_fixed = NULL;

    /* 11)
     * we need find if there are the setup chunks
     * when no channel found for this packet */
    if (curr_channel_ == NULL)
    {
        // it is init ack chunk
        init_chunk = find_first_chunk(((dctp_packet_t*)dctp_packet)->chunk,
            packet_value_len, (uchar)CHUNK_INIT_ACK);
        if (init_chunk != NULL)
        {
            event_log(verbose,
                "recv_dctp_packet()::Looking for source address in CHUNK_INIT_ACK");
            i = find_sockaddres(init_chunk, packet_value_len,
                supported_addr_types) - 1;
            for (; i >= 0; i--)
            {
                curr_channel_ = find_channel_by_transport_addr(
                    &found_addres_[i], last_src_port_, last_dest_port_);
            }
        }  //if (init_chunk != NULL) CHUNK_INIT_ACK

        // if it is init chunk
        init_chunk = find_first_chunk(((dctp_packet_t*)dctp_packet)->chunk,
            packet_value_len, (uchar)CHUNK_INIT);
        if (init_chunk != NULL)
        {
            event_log(verbose,
                "recv_dctp_packet()::Looking for source address in INIT CHUNK");
            i = find_sockaddres(init_chunk, packet_value_len,
                supported_addr_types) - 1;
            for (; i >= 0; i--)
            {
                curr_channel_ = find_channel_by_transport_addr(
                    &found_addres_[i], last_src_port_, last_dest_port_);
            }
            // fixme this is official way
            //            do
            //            {
            //                retval = find_sockaddres(init_chunk,
            //                        packet_value_len, i, &addr_from_init_or_ack_chunk,
            //                        supported_addr_types);
            //                if (retval == 0) // found an addr
            //                {
            //                    curr_channel_ = find_channel_by_transport_addr(
            //                            &addr_from_init_or_ack_chunk, last_src_port_,
            //                            last_dest_port_);
            //                }
            //                i++;
            //            } while (curr_channel_ == NULL && retval == 0);
        }        //if (init_chunk != NULL) CHUNK_INIT

        /* 12)
         * this may happen when a previously-connected endpoint re-connect to us
         * puting a new source addr in IP packet (this is why curr_channel_ is NULL above)
         * but also put the previously-used source addr in vlp, with the previous channel
         * still alive (this is why curr_channel_ becomes NOT NULL ).
         * anyway, use the previous channel to handle this packet
         */
        if (curr_channel_ != NULL)
        {
            event_log(verbose,
                "recv_dctp_packet(): found previous channel from setup chunk");
            found_existed_channel_from_init_chunks = true;
        }
        else
        {
            event_log(verbose,
                "recv_dctp_packet(): NOT found previous channel from INIT (ACK) CHUNK");
            found_existed_channel_from_init_chunks = false;
        }
    }

    /* 13) If the association exists, both ports of the sctp_packet must be equal to the ports
     of the association and the source address must be in the addresslist of the peer
     of this association, this has been validated in find_channel_by_transport_addr() above*/
    if (curr_channel_ != NULL)
    {
        event_log(verbose,
            "recv_dctp_packet(): process packets with channel found");

    }
    /*14) refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets
     * curr_channel_ null means no channel found for this chunk */
    else
    {
        event_log(verbose,
            "recv_dctp_packet()::current channel ==NULL, start process OOB packets!\n");

        /*15)
         * refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (2)
         * TODO discard this packet is delegant, better to notify remote endpoint and ulp
         * the abort and the error casuse carried in the ABORT*/
        if (contains_chunk((uchar)CHUNK_ABORT, chunk_types_arr) > 0)
        {
            event_log(verbose,
                "recv_dctp_packet()::Found ABORT in oob packet, discarding it !");
            clear();
            return;
        }

        /*16) refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (5)
         If the packet contains a SHUTDOWN ACK chunk, the receiver should
         respond to the sender of the OOTB packet with a SHUTDOWN
         COMPLETE.  When sending the SHUTDOWN COMPLETE, the receiver of
         the OOTB packet must fill in the Verification Tag field of the
         outbound packet with the Verification Tag received in the
         SHUTDOWN ACK and set the T bit in the Chunk Flags to indicate
         that the Verification Tag is reflected*/
        if (contains_chunk((uchar)CHUNK_SHUTDOWN_ACK, chunk_types_arr) > 0)
        {
            uchar shutdown_complete_cid = alloc_simple_chunk(
                (uchar)CHUNK_SHUTDOWN_COMPLETE, FLAG_NO_TCB);
            curr_simple_chunk_ptr_ = get_simple_chunk(shutdown_complete_cid);
            // this method will internally send all bundled chunks if exceeding packet max
            bundle_simple_chunk(curr_simple_chunk_ptr_);
            // FIXME need more considerations about why locked or unlocked?
            unlock_bundle_ctrl();
            // explicitely call send to send this simple chunk
            send_bundled_chunks();
            // free this simple chunk
            free_simple_chunk(shutdown_complete_cid);
            clear();

            event_log(verbose,
                "recv_dctp_packet()::Found SHUTDOWN_ACK in OOB packet, will send SHUTDOWN_COMPLETE to the peer!");
            return;
        }

        /*17) refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (6)
         If the packet contains a SHUTDOWN COMPLETE chunk, the receiver
         should silently discard the packet and take no further action.
         this is good because when receiving st-cp chunk, the peer has finished
         shutdown pharse withdeleting TCB and all related data, channek is NULL
         is actually what we want*/
        if (contains_chunk((uchar)CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr)
                > 0)
        {
            clear();
            event_log(loglvl_intevent,
                "recv_dctp_packet()::Found SHUTDOWN_COMPLETE in OOB packet, discarding it\n!");
            return;
        }

        /* 18)
         * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (7)
         * If th packet contains  a COOKIE ACK,
         * the SCTP packet should be silently discarded*/
        if (contains_chunk((uchar)CHUNK_COOKIE_ACK, chunk_types_arr) > 0)
        {
            clear();
            event_log(loglvl_intevent,
                "recv_dctp_packet()::Found CHUNK_COOKIE_ACK  in OOB packet, discarding it\n!");
            return;
        }

        /* 19)
         * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (7)
         * If th packet contains a "Stale Cookie" ERROR,
         * the SCTP packet should be silently discarded*/
        if (contains_error_chunk(((dctp_packet_t*)dctp_packet)->chunk,
            packet_value_len, ECC_STALE_COOKIE_ERROR))
        {
            clear();
            event_log(loglvl_intevent,
                "recv_dctp_packet()::Found ECC_STALE_COOKIE_ERROR  in OOB packet,discarding it\n!");
            return;
        }

        /* 20)
         Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (3)
         If the packet contains an INIT chunk with a Verification Tag set
         to '0', process it as described in Section 5.1.  If, for whatever
         reason, the INIT cannot be processed normally and an ABORT has to
         be sent in response, the Verification Tag of the packet
         containing the ABORT chunk MUST be the Initiate Tag of the
         received INIT chunk, and the T bit of the ABORT chunk has to be
         set to 0, indicating that the Verification Tag is NOT reflected.*/
        if (init_chunk != NULL)
        {
            event_log(loglvl_intevent,
                "recv_dctp_packet()::Found INIT in OOB packet -> processing it");

            last_veri_tag_ = dctp_packet_fixed->verification_tag;
            if (last_veri_tag_ != 0)
            {
                event_log(loglvl_intevent,
                    "warnning verification_tag in INIT != 0 -> ABORT");
                send_abort = true;
            }

            // debug init tag carried in this chunk
            init_chunk_fixed = &(((init_chunk_t*)init_chunk)->init_fixed);
            last_init_tag_ = ntohl(init_chunk_fixed->init_tag);
            event_logi(verbose, "setting last_init_tag_ to %u", last_init_tag_);

            // we have an instance up listenning on that port just validate params
            if (curr_geco_instance_ != NULL)
            {
                event_log(loglvl_intevent, "an instance found -> processing");

                if (curr_geco_instance_->local_port == 0)
                {
                    event_log(loglvl_major_error_abort,
                        "recv_dctp_packet()::got INIT Message, but curr_geco_instance_ local port is zero!\n");
                    return;
                }

                /*20)
                 Refers to RFC 4960 Sectiion 5.1
                 If an endpoint receives an INIT, INIT ACK, or COOKIE ECHO chunk but
                 decides not to establish the new association due to missing mandatory
                 parameters in the received INIT or INIT ACK, invalid parameter values,
                 or lack of local resources, it MUST respond with an ABORT chunk */

                // validate dest port
                if (last_dest_port_ != curr_geco_instance_->local_port)
                {
                    // destination port is not the listening port of this this SCTP-instance.
                    event_logii(verbose,
                        "dest port (%u) does not equals to curr_geco_instance_ listenning local port (%u) -> ABORT",
                        last_dest_port_, curr_geco_instance_->local_port);
                    send_abort = true;
                }

                // validate fixme checkme if we need to see if there are ip4 or ip6 addres
                // present in the packet, need check rfc 4060 to confirm that ?
                vlparam_fixed =
                    (vlparam_fixed_t*)find_vlparam_fixed_from_setup_chunk(
                    init_chunk, packet_value_len,
                    VLPARAM_HOST_NAME_ADDR);
                if (vlparam_fixed != NULL)
                {
                    event_log(loglvl_intevent,
                        "found VLPARAM_HOST_NAME_ADDR  -> ABORT");
                    send_abort = true;
                }
            } // if (curr_geco_instance_ != NULL) at line 460
            else
            {
                // we do not have an instance up listening on that port-> ABORT
                event_log(loglvl_intevent,
                    "got INIT Message, but no instance found -> ABORT");
                send_abort = true;
            }
        } // if (init_chunk != NULL) at line 458

        /* 21)
         * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (4)
         * If the packet contains a COOKIE ECHO in the first chunk, process
         *  it as described in Section 5.1. */
        if (contains_chunk((uchar)CHUNK_COOKIE_ECHO, chunk_types_arr) > 0)
        {
            event_log(loglvl_intevent,
                "recv_dctp_packet()::Found CHUNK_COOKIE_ECHO in OOB packet -> processing it");

            // we have an instance up listenning on that port just validate params
            if (curr_geco_instance_ != NULL)
            {
                event_log(loglvl_intevent, "an instance found -> processing");

                if (curr_geco_instance_->local_port == 0)
                {
                    event_log(loglvl_major_error_abort,
                        "curr_geco_instance_ local port is zero!\n");
                    return;
                }

                /*
                 Refers to RFC 4960 Sectiion 5.1
                 If an endpoint receives an INIT, INIT ACK, or COOKIE ECHO chunk but
                 decides not to establish the new association due to missing mandatory
                 parameters in the received INIT or INIT ACK, invalid parameter values,
                 or lack of local resources, it MUST respond with an ABORT chunk */
                // validate dest port
                if (last_dest_port_ != curr_geco_instance_->local_port)
                {
                    // destination port is not the listening port of this this geco instance.
                    event_logii(loglvl_intevent,
                        "dest port (%u) != curr_geco_instance_ listenning local port (%u) -> ABORT",
                        last_dest_port_, curr_geco_instance_->local_port);
                    send_abort = true;
                }
            }
            else
            {
                // we do not have an instance up listening on that port-> ABORT
                event_log(loglvl_intevent,
                    "got INIT Message, but no instance found -> discarding");
                clear();
            }
        }

        /* 22)
         Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (8)
         The receiver should respond to the sender of the OOTB packet with
         an ABORT.  When sending the ABORT, the receiver of the OOTB
         packet MUST fill in the Verification Tag field of the outbound
         packet with the value found in the Verification Tag field of the
         OOTB packet and set the T bit in the Chunk Flags to indicate that
         the Verification Tag is reflected.  After sending this ABORT, the
         receiver of the OOTB packet shall discard the OOTB packet and
         take no further action.*/
        event_log(loglvl_intevent,
            "recv_dctp_packet()::send ABORT with ignoring OOTB - see section 8.4.8)");
        send_abort = true;
    }

    /*23) may send ABORT to the peer */
    if (send_abort)
    {
        event_log(loglvl_intevent,
            "recv_dctp_packet()::discarded packet and sending ABORT");
        if (!send_abort_for_oob_packet_)
        {
            event_log(verbose,
                "send_abort_for_oob_packet_==FALSE -> Discarding packet,not sending ABORT");
            clear();
            /* and discard that packet */
            return;
        }

        /*build ABORT and send it*/
        // allocate simple chunk
        uchar abort_cid = (
            curr_channel_ == NULL ?
            alloc_simple_chunk((uchar)CHUNK_ABORT,
            FLAG_NO_TCB) :
            alloc_simple_chunk((uchar)CHUNK_ABORT, FLAG_NONE));
        curr_simple_chunk_ptr_ = get_simple_chunk(abort_cid);

        // this method will internally send all bundled chunks if exceeding packet max
        bundle_simple_chunk(curr_simple_chunk_ptr_);
        // FIXME need more considerations about why locked or unlocked?
        unlock_bundle_ctrl();
        // explicitely call send to send this simple chunk
        send_bundled_chunks();
        // free this simple chunk
        free_simple_chunk(abort_cid);
        clear();

        event_log(verbose,
            "send_abort_for_oob_packet_==TRUE -> sending ABORT with veri-tag and T-Bit reflected");
        return;
    }

    // forward packet vlue  to bundling
    handle_chunks_from_geco_packet(last_src_path_,
        ((dctp_packet_t*)dctp_packet)->chunk, packet_value_len);

    // no need to clear last_src_port_ and last_dest_port_ MAY be used by other functions
    last_src_path_ = -1; /* only valid for functions called via recv_dctp_packet */
}

int dispatch_layer_t::handle_chunks_from_geco_packet(uint address_index,
    uchar * datagram, int len)
{
    //fixme add imple here
    return 0;
}

uchar* dispatch_layer_t::find_vlparam_fixed_from_setup_chunk(
    uchar * setup_chunk, uint chunk_len, ushort param_type)
{
    /*1) validate packet length*/
    uint read_len = CHUNK_FIXED_SIZE + INIT_CHUNK_FIXED_SIZE;
    if (chunk_len < read_len)
    {
        event_logii(loglvl_warnning_error,
            "chunk_len(%u) < CHUNK_FIXED_SIZE( %u bytes) return NULL !\n",
            chunk_len, read_len);
        return NULL;
    }

    /*2) validate chunk id inside this chunk*/
    init_chunk_t* init_chunk = (init_chunk_t*)setup_chunk;
    if (init_chunk->chunk_header.chunk_id != CHUNK_INIT
        && init_chunk->chunk_header.chunk_id != CHUNK_INIT_ACK)
    {
        return NULL;
    }

    uint len = ntohs(init_chunk->chunk_header.chunk_length);
    uchar* curr_pos = init_chunk->variableParams;

    uint vlp_len;
    uint padding_len;
    vlparam_fixed_t* vlp;

    /*3) parse all vlparams in this chunk*/
    while (read_len < len)
    {
        event_logii(verbose,
            "find_params_from_setup_chunk() : len==%u, processed_len == %u",
            len, read_len);

        if (len - read_len < VLPARAM_FIXED_SIZE)
        {
            event_log(loglvl_warnning_error,
                "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            return NULL;
        }

        vlp = (vlparam_fixed_t*)curr_pos;
        vlp_len = ntohs(vlp->param_length);
        if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len)
            return NULL;

        /*4) find param in this chunk*/
        if (ntohs(vlp->param_type) == param_type)
        {
            return curr_pos;
        }

        read_len += vlp_len;
        padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
        read_len += padding_len;
        curr_pos += read_len;
    } // while

    return NULL;
}

int dispatch_layer_t::send_bundled_chunks(uint * addr_idx)
{
    bundle_controller_t* bundle_ctrl =
        (bundle_controller_t*)get_bundle_control(curr_channel_);

    /*1) no channel exists, so we take the global bundling buffer */
    if (bundle_ctrl == NULL)
    {
        event_log(verbose, "Copying Control Chunk to global bundling buffer ");
        bundle_ctrl = &default_bundle_ctrl_;
    }

    if (bundle_ctrl->locked)
    {
        bundle_ctrl->got_send_request = true;
        if (addr_idx != NULL)
        {
            bundle_ctrl->got_send_address = true;
            bundle_ctrl->requested_destination = *addr_idx;
        }
        event_log(verbose,
            "send_bundled_chunks ()::sender is LOCKED ---> returning");
        return 1;
    }

    int ret, send_len = 0;
    uchar* send_buffer = NULL;
    int idx;

    /* 2) 
    determine  idx to use as dest addr
    TODO - more intelligent path selection strategy  
    should take into account PM_INACTIVE */
    if (addr_idx != NULL)
    {
        if (*addr_idx > 0xFFFF)
        {
            error_log(loglvl_fatal_error_exit, "address_index too big !");
            return -1;
        }else
        {
            idx = *addr_idx;
        }
    }else
    {
        if (bundle_ctrl->got_send_address)
        {
            idx = bundle_ctrl->requested_destination;
        }else
        {
            idx = -1; // use last src path
        }
    }
    event_logi(verbose, "send_bundled_chunks : send to path %d ", idx);

    //if (bundle_ctrl->sack_in_buffer)
    //    send_buffer = bundle_ctrl->sack_buf;
    //else if (bundle_ctrl->ctrl_chunk_in_buffer)
    //    send_buffer = bundle_ctrl->ctrl_buf;
    //else if (bundle_ctrl->data_in_buffer)
    //    send_buffer = bundle_ctrl->data_buf;
    //else
    //{
    //    error_log(loglvl_minor_error,
    //        "Nothing to send, but send_bundled_chunks() was called !");
    //    return 1;
    //}

    if (bundle_ctrl->sack_in_buffer)
    {
        stop_sack_timer();

        // SACKs by default go to the last active address, from which data arrived 
        send_len = bundle_ctrl->sack_position; // at least sizeof(geco_packet_fixed_t)

        // at most pointing to the end of SACK chunk 
        event_logi(verbose, "send_bundled_chunks(sack) : send_len == %d ", send_len);


    }
}

int dispatch_layer_t::bundle_simple_chunk(simple_chunk_t * chunk,
    uint * dest_index)
{

    bundle_controller_t* bundle_ctrl =
        (bundle_controller_t*)get_bundle_control(curr_channel_);

    /*1) no channel exists, so we take the global bundling buffer */
    if (bundle_ctrl == NULL)
    {
        event_log(verbose, "Copying Control Chunk to global bundling buffer ");
        bundle_ctrl = &default_bundle_ctrl_;
    }

    bool locked;
    ushort chunk_len = get_chunk_length((chunk_fixed_t*)chunk);
    if (get_bundle_total_size(bundle_ctrl)
        + chunk_len >= MAX_NETWORK_PACKET_VALUE_SIZE)
    {
        /*2) an packet CANNOT hold all data, we send chunks and get bundle empty*/
        event_logi(verbose,
            "Chunk Length exceeded MAX_NETWORK_PACKET_VALUE_SIZE : sending chunk to address %u !",
            (dest_index == NULL) ? 0 : *dest_index);

        locked = bundle_ctrl->locked;
        if (locked)
            bundle_ctrl->locked = false;
        send_bundled_chunks(dest_index);
        if (locked)
            bundle_ctrl->locked = true;
    }
    else
    {
        /*3) an packet CAN hold all data*/
        if (dest_index != NULL)
        {
            bundle_ctrl->got_send_address = true;
            bundle_ctrl->requested_destination = *dest_index;
        }
        else
        {
            bundle_ctrl->got_send_address = false;
            bundle_ctrl->requested_destination = 0;
        }
    }

    /*3) copy new chunk to bundle and insert padding, if necessary*/
    memcpy(&bundle_ctrl->ctrl_buf[bundle_ctrl->ctrl_position], chunk,
        chunk_len);
    bundle_ctrl->ctrl_position += chunk_len;
    chunk_len = 4 - (chunk_len % 4);
    bundle_ctrl->ctrl_chunk_in_buffer = true;
    bundle_ctrl->curr_data_buf = bundle_ctrl->ctrl_buf;
    if (chunk_len < 4)
    {
        memset(&(bundle_ctrl->ctrl_buf[bundle_ctrl->ctrl_position]), 0,
            chunk_len);
        bundle_ctrl->ctrl_position += chunk_len;
    }

    event_logii(verbose,
        "bundle_simple_chunk() : %u , Total buffer size now (includes pad): %u\n",
        get_chunk_length((chunk_fixed_t *)chunk),
        get_bundle_total_size(bundle_ctrl));
    return 0;
}

simple_chunk_t* dispatch_layer_t::get_simple_chunk(uchar chunkID)
{
    if (simple_chunks_[chunkID] == NULL)
    {
        error_log(loglvl_warnning_error, "Invalid chunk ID\n");
        return NULL;
    }

    simple_chunks_[chunkID]->chunk_header.chunk_length = htons(
        (simple_chunks_[chunkID]->chunk_header.chunk_length
        + write_cursors_[chunkID]));
    completed_chunks_[chunkID] = true;
    return simple_chunks_[chunkID];
}

int dispatch_layer_t::find_sockaddres(uchar * chunk, uint chunk_len,
    int supportedAddressTypes)
{
    /*1) validate method input params*/
    uint read_len = CHUNK_FIXED_SIZE + INIT_CHUNK_FIXED_SIZE;
    if (chunk_len < read_len)
    {
        event_logii(loglvl_warnning_error,
            "chunk_len(%u) < CHUNK_FIXED_SIZE( %u bytes) RETURN -1 !\n",
            chunk_len, read_len);
        return -1;
    }

    /*2) validate chunk id inside this chunk*/
    init_chunk_t* init_chunk = (init_chunk_t*)chunk;
    if (init_chunk->chunk_header.chunk_id != CHUNK_INIT
        && init_chunk->chunk_header.chunk_id != CHUNK_INIT_ACK)
    {
        return -1;
    }

    uint len = ntohs(init_chunk->chunk_header.chunk_length);
    uchar* curr_pos = init_chunk->variableParams;

    uint vlp_len;
    uint padding_len;
    vlparam_fixed_t* vlp;
    ip_address_t* addres;
    uint found_addr_number = 0;

    /*3) parse all vlparams in this chunk*/
    while (read_len < len)
    {
        event_logii(verbose, "find_sockaddres() : len==%u, processed_len == %u",
            len, read_len);

        if (len - read_len < VLPARAM_FIXED_SIZE)
        {
            event_log(loglvl_warnning_error,
                "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            return -1;
        }

        vlp = (vlparam_fixed_t*)curr_pos;
        vlp_len = ntohs(vlp->param_length);
        if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len)
            return -1;

        /*4) validate received addresses in this chunk*/
        switch (ntohs(vlp->param_type))
        {
            case VLPARAM_IPV4_ADDRESS:
                if ((supportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV4))
                {
                    addres = (ip_address_t*)curr_pos;
                    found_addres_[found_addr_number].sa.sa_family = AF_INET;
                    found_addres_[found_addr_number].sin.sin_port = 0;
                    found_addres_[found_addr_number].sin.sin_addr.s_addr =
                        addres->dest_addr_un.ipv4_addr;
                    found_addr_number++;
                }
                break;
            case VLPARAM_IPV6_ADDRESS:
                if ((supportedAddressTypes & VLPARAM_IPV6_ADDRESS))
                {
                    addres = (ip_address_t*)curr_pos;
                    found_addres_[found_addr_number].sa.sa_family = AF_INET6;
                    found_addres_[found_addr_number].sin6.sin6_port = 0;
                    found_addres_[found_addr_number].sin6.sin6_flowinfo = 0;
#ifdef HAVE_SIN6_SCOPE_ID
                    foundAddress[found_addr_number].sin6.sin6_scope_id = 0;
#endif
                    memcpy(found_addres_[found_addr_number].sin6.sin6_addr.s6_addr,
                        addres->dest_addr_un.ipv6_addr,
                        sizeof(struct in6_addr));
                    found_addr_number++;
                }
                break;
        }
        read_len += vlp_len;
        padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
        read_len += padding_len;
        curr_pos += read_len;
    } // while
    return found_addr_number;
}
int dispatch_layer_t::find_sockaddres(uchar * chunk, uint chunk_len, uint n,
    sockaddrunion* foundAddress, int supportedAddressTypes)
{
    /*1) validate method input params*/
    uint read_len = CHUNK_FIXED_SIZE + INIT_CHUNK_FIXED_SIZE;
    if (chunk_len < read_len)
    {
        event_log(loglvl_warnning_error,
            "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
        return -1;
    }

    if (foundAddress == NULL || n < 1 || n > MAX_NUM_ADDRESSES)
    {
        event_log(loglvl_fatal_error_exit,
            "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
        return -1;
    }

    /*2) validate chunk id inside this chunk*/
    init_chunk_t* init_chunk = (init_chunk_t*)chunk;
    if (init_chunk->chunk_header.chunk_id != CHUNK_INIT
        && init_chunk->chunk_header.chunk_id != CHUNK_INIT_ACK)
    {
        return -1;
    }

    uint len = ntohs(init_chunk->chunk_header.chunk_length);
    uchar* curr_pos = init_chunk->variableParams;

    uint vlp_len;
    uint padding_len;
    vlparam_fixed_t* vlp;
    ip_address_t* addres;
    uint found_addr_number = 0;

    /*3) parse all vlparams in this chunk*/
    while (read_len < len)
    {
        event_logii(verbose, "find_sockaddres() : len==%u, processed_len == %u",
            len, read_len);

        if (len - read_len < VLPARAM_FIXED_SIZE)
        {
            event_log(loglvl_warnning_error,
                "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            return -1;
        }

        vlp = (vlparam_fixed_t*)curr_pos;
        vlp_len = ntohs(vlp->param_length);
        if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len)
            return -1;

        /*4) validate received addresses in this chunk*/
        switch (ntohs(vlp->param_type))
        {
            case VLPARAM_IPV4_ADDRESS:
                if ((supportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV4))
                {
                    found_addr_number++;
                    if (found_addr_number == n)
                    {
                        addres = (ip_address_t*)curr_pos;
                        foundAddress->sa.sa_family = AF_INET;
                        foundAddress->sin.sin_port = 0;
                        foundAddress->sin.sin_addr.s_addr =
                            addres->dest_addr_un.ipv4_addr;
                        return 0;
                    }
                }
                break;
            case VLPARAM_IPV6_ADDRESS:
                if ((supportedAddressTypes & VLPARAM_IPV6_ADDRESS))
                {
                    found_addr_number++;
                    if (found_addr_number == n)
                    {
                        addres = (ip_address_t*)curr_pos;
                        foundAddress->sa.sa_family = AF_INET6;
                        foundAddress->sin6.sin6_port = 0;
                        foundAddress->sin6.sin6_flowinfo = 0;
#ifdef HAVE_SIN6_SCOPE_ID
                        foundAddress->sin6.sin6_scope_id = 0;
#endif
                        memcpy(foundAddress->sin6.sin6_addr.s6_addr,
                            addres->dest_addr_un.ipv6_addr,
                            sizeof(struct in6_addr));
                        return 0;
                    }
                }
                break;
        }
        read_len += chunk_len;
        padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
        read_len += padding_len;
        curr_pos += read_len;
    } // while
    return 1;
}
uchar* dispatch_layer_t::find_first_chunk(uchar * packet_value,
    uint packet_val_len, uchar chunk_type)
{
    uint chunk_len = 0;
    uint read_len = 0;
    uint padding_len;
    chunk_fixed_t* chunk;
    uchar* curr_pos = packet_value;

    while (read_len < packet_val_len)
    {
        event_logii(verbose,
            "find_first_chunk()::packet_val_len=%d, read_len=%d",
            packet_val_len, read_len);

        if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
        {
            event_log(loglvl_warnning_error,
                "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
            return NULL;
        }
        chunk = (chunk_fixed_t*)curr_pos;
        if (chunk->chunk_id == chunk_type)
            return curr_pos;

        chunk_len = get_chunk_length(chunk);
        if (chunk_len < CHUNK_FIXED_SIZE
            || chunk_len + read_len > packet_val_len)
            return NULL;

        read_len += chunk_len;
        padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
        read_len += padding_len;
        curr_pos += read_len;
    }
    return NULL;
}

bool dispatch_layer_t::contains_error_chunk(uchar * packet_value,
    uint packet_val_len, ushort error_cause)
{
    uint chunk_len = 0;
    uint read_len = 0;
    uint padding_len;
    chunk_fixed_t* chunk;
    uchar* curr_pos = packet_value;
    vlparam_fixed_t* err_chunk;

    while (read_len < packet_val_len)
    {
        event_logii(verbose,
            "contains_error_chunk()::packet_val_len=%d, read_len=%d",
            packet_val_len, read_len);

        if (packet_val_len - read_len < (int)CHUNK_FIXED_SIZE)
        {
            event_log(loglvl_warnning_error,
                "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
            return false;
        }

        chunk = (chunk_fixed_t*)curr_pos;
        chunk_len = get_chunk_length(chunk);
        if (chunk_len < (int)CHUNK_FIXED_SIZE
            || chunk_len + read_len > packet_val_len)
            return false;

        if (chunk->chunk_id == CHUNK_ERROR)
        {
            event_log(loglvl_intevent,
                "contains_error_chunk()::Error Chunk Found");
            uint err_param_len = 0;
            uchar* simple_chunk;
            uint param_len = 0;
            // search for target error param
            while (err_param_len < chunk_len - (int)CHUNK_FIXED_SIZE)
            {
                if (chunk_len - CHUNK_FIXED_SIZE
                    - err_param_len < VLPARAM_FIXED_SIZE)
                {
                    event_log(loglvl_warnning_error,
                        "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
                    return false;
                }

                simple_chunk =
                    &((simple_chunk_t*)chunk)->chunk_value[err_param_len];
                err_chunk = (vlparam_fixed_t*)simple_chunk;
                if (ntohs(err_chunk->param_type) == error_cause)
                {
                    event_logi(verbose,
                        "contains_error_chunk()::Error Cause %u found -> Returning true",
                        error_cause);
                    return true;
                }
                param_len = ntohs(err_chunk->param_length);
                err_param_len += param_len;
                param_len = ((param_len % 4) == 0) ? 0 : (4 - param_len % 4);
                err_param_len += param_len;
            }
        }

        read_len += chunk_len;
        padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
        read_len += padding_len;
        curr_pos += read_len;
    }
    return false;
}

uint dispatch_layer_t::find_chunk_types(uchar* packet_value, uint packet_val_len)
{
    // 0000 0000 ret = 0 at beginning
    // 0000 0001 1
    // 1                chunktype init
    // 0000 0010 ret
    // 2                chunktype init ack 
    // 0000 0110 ret
    // 7                chunktype shutdown 
    // 1000 0110 ret
    // 192            chunktype shutdown 
    // 1000 0000-byte0-byte0-1000 0110 ret

    uint result = 0;
    uint chunk_len = 0;
    uint read_len = 0;
    uint padding_len;
    chunk_fixed_t* chunk;
    uchar* curr_pos = packet_value;

    while (read_len < packet_val_len)
    {
        event_logii(verbose,
            "find_chunk_types()::packet_val_len=%d, read_len=%d",
            packet_val_len, read_len);

        if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
            event_log(loglvl_warnning_error,
            "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");

        chunk = (chunk_fixed_t*)curr_pos;
        chunk_len = get_chunk_length(chunk);
        if (chunk_len < CHUNK_FIXED_SIZE
            || chunk_len + read_len > packet_val_len)
            return result;

        if (chunk->chunk_id <= 30)
        {
            result |= (1 << chunk->chunk_id);
            event_logii(verbose,
                "dispatch_layer_t::find_chunk_types()::Chunk type==%u, result == %x",
                chunk->chunk_id,
                Bitify(sizeof(result) * 8, (char*)&result));
        }
        else
        {
            result |= (1 << 31);
            event_logii(verbose,
                "dispatch_layer_t::find_chunk_types()::Chunk type==%u setting bit 31 --> result == %s",
                chunk->chunk_id,
                Bitify(sizeof(result) * 8, (char*)&result));
        }

        read_len += chunk_len;
        padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
        read_len += padding_len;
        curr_pos += read_len;
    }
    return result;
}

bool dispatch_layer_t::cmp_geco_instance(const geco_instance_t& a,
    const geco_instance_t& b)
{
    event_logii(verbose,
        "DEBUG: cmp_geco_instance()::comparing instance a port %u, instance b port %u",
        a.local_port, b.local_port);

    if (a.local_port < b.local_port)
        return false;
    if (a.local_port > b.local_port)
        return false;

    if (!a.is_in6addr_any && !b.is_in6addr_any && a.is_inaddr_any
        && b.is_inaddr_any)
    {
        int i, j;
        /*find if at least there is an ip addr thate quals*/
        for (i = 0; i < a.local_addres_size; i++)
        {
            for (j = 0; j < b.local_addres_size; j++)
            {
                if (saddr_equals(&(a.local_addres_list[i]),
                    &(b.local_addres_list[j])))
                {
                    event_log(verbose,
                        "find_dispatcher_by_port(): found TWO equal dispatchers !");
                    return true;
                }
            }
        }
        return false;
    }
    else
    {
        /* one has IN(6)ADDR_ANY : return equal ! */
        return true;
    }
}

geco_instance_t* dispatch_layer_t::find_geco_instance_by_transport_addr(
    sockaddrunion* dest_addr, uint address_type)
{
    /* search for this endpoint from list*/
    tmp_dispather_.local_port = last_dest_port_;
    tmp_dispather_.local_addres_size = 1;
    tmp_dispather_.is_in6addr_any = false;
    tmp_dispather_.is_inaddr_any = false;
    tmp_dispather_.local_addres_list = dest_addr;
    tmp_dispather_.supportedAddressTypes = address_type;

    geco_instance_t* result = NULL;
    for (auto i = dispathers_list_.begin(); i != dispathers_list_.end(); i++)
    {
        if (cmp_geco_instance(tmp_dispather_, *(*i)))
        {
            result = *i;
            break;
        }
    }
    return result;
}

channel_t* dispatch_layer_t::find_channel_by_transport_addr(
    sockaddrunion * src_addr, ushort src_port, ushort dest_port)
{
    tmp_endpoint_.remote_addres_size = 1;
    tmp_endpoint_.remote_addres = &tmp_addr_;

    switch (saddr_family(src_addr))
    {
        case AF_INET:
            event_logi(loglvl_intevent, "Looking for IPv4 Address %x (in NBO)",
                s4addr(src_addr));
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
            event_logi(loglvl_intevent,
                "Looking for IPv6 Address %x, check NTOHX() ! ",
                tmp_endpoint_.remote_addres[0].sin6.sin6_addr.s6_addr);
            tmp_endpoint_.remote_port = src_port;
            tmp_endpoint_.local_port = dest_port;
            tmp_endpoint_.deleted = false;
            break;
        default:
            error_logi(loglvl_fatal_error_exit,
                "Unsupported Address Family %d in find_channel_by_transport_addr()",
                saddr_family(src_addr));
            break;
    }

    /* search for this endpoint from list*/
    channel_t* result = NULL;
    for (auto i = endpoints_list_.begin(); i != endpoints_list_.end(); i++)
    {
        if (cmp_channel(tmp_endpoint_, *(*i)))
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
                "Found endpoint that should be deleted, with id %u\n",
                result->channel_id);
            result = NULL;
        }
        else
        {
            event_logi(verbose, "Found valid endpoint with id %u\n",
                result->channel_id);
        }
    }
    else
    {
        event_log(loglvl_intevent,
            "endpoint indexed by transport address not in list");
    }

    return result;
}

bool dispatch_layer_t::cmp_channel(const channel_t& a, const channel_t& b)
{
    event_logii(verbose,
        "cmp_endpoint_by_addr_port(): checking ep A[id=%d] and ep B[id=%d]\n",
        a.channel_id, b.channel_id);
    if (a.remote_port == b.remote_port && a.local_port == b.local_port)
    {
        uint i, j;
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
        event_log(verbose, "cmp_endpoint_by_addr_port(): found No equal ep !");
        return false;
    }
    else
    {
        event_log(verbose, "cmp_endpoint_by_addr_port(): found No equal ep !");
        return false;
    }
}

bool dispatch_layer_t::validate_dest_addr(sockaddrunion * dest_addr)
{
    /* 1)
     * this case will be specially treated
     * after the call to validate_dest_addr()
     * when curr_channel_ not null, curr_geco_instance_ MUST NOT be null*/
    if (curr_geco_instance_ == NULL && curr_channel_ == NULL)
        return true;

    uint j;
    if (curr_channel_ != NULL)
    {
        /* 2) check if it is in curr_channel_'s local addresses list*/
        for (j = 0; j < curr_channel_->local_addres_size; j++)
        {
            if (saddr_equals(&curr_channel_->local_addres[j], dest_addr))
            {
                event_logii(verbose,
                    "dispatch_layer_t::validate_dest_addr()::Checking dest addr  %x, local %x",
                    s4addr(dest_addr),
                    s4addr(&(curr_channel_->local_addres[j])));
                return true;
            }
        }
    }

    ushort af = saddr_family(dest_addr);
    bool any_set = false;

    /* 3) check whether _instance_ has INADDR_ANY
     * curr_geco_instance_ MUST NOT be null at the moment */
    if (curr_geco_instance_->is_inaddr_any)
    {
        any_set = true;

        if (af == AF_INET)
            return true;

        if (af == AF_INET6)
            return false;
    }

    if (curr_geco_instance_->is_in6addr_any)
    {
        any_set = true;

        if (af == AF_INET || af == AF_INET6)
            return true;
    }

    if (any_set)
        return false;

    /* 4) search through local address list of this dctp instance */
    for (j = 0; j < curr_geco_instance_->local_addres_size; j++)
    {
        if (saddr_equals(dest_addr,
            &(curr_geco_instance_->local_addres_list[j])))
        {
            return true;
        }
    }

    return false;
}
