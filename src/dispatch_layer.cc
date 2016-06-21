#include <algorithm>
#include "dispatch_layer.h"
#include "geco-ds-malloc.h"
#include "transport_layer.h"
#include "auth.h"

dispatch_layer_t::dispatch_layer_t()
{
    assert(MAX_NETWORK_PACKET_VALUE_SIZE == sizeof(simple_chunk_t));
    found_init_chunk_ = false;
    defaultlocaladdrlistsize_ = 0;
    found_existed_channel_from_init_chunks_ = false;
    abort_found_with_channel_not_nil = false;
    tmp_peer_supported_types_ = 0;
    my_supported_addr_types_ = 0;
    curr_channel_ = NULL;
    curr_geco_instance_ = NULL;
    curr_geco_packet_ = NULL;
    library_support_unreliability_ = true;
    dispatch_layer_initialized = false;
    curr_channel_ = NULL;
    curr_geco_instance_ = NULL;
    simple_chunk_t_ptr_ = NULL;
    last_source_addr_ = last_dest_addr_ = 0;
    last_src_port_ = last_dest_port_ = 0;
    last_init_tag_ = 0;
    last_src_path_ = 0;
    last_veri_tag_ = 0;
    do_dns_query_for_host_name_ = false;

    channels_.reserve(DEFAULT_ENDPOINT_SIZE);
    memset(tmp_local_addreslist_, 0,
    MAX_NUM_ADDRESSES * sizeof(sockaddrunion));
    memset(tmp_peer_addreslist_, 0,
    MAX_NUM_ADDRESSES * sizeof(sockaddrunion));

    simple_chunk_index_ = 0;
    memset(simple_chunks_, 0, MAX_CHUNKS_SIZE);
    memset(curr_write_pos_, 0, MAX_CHUNKS_SIZE);
    memset(completed_chunks_, 0, MAX_CHUNKS_SIZE);

    send_abort_for_oob_packet_ = true;
    curr_ecc_code_ = 0;
    curr_ecc_reason_ = NULL;
    transport_layer_ = NULL;
}

void dispatch_layer_t::recv_geco_packet(int socket_fd, char *dctp_packet,
        uint dctp_packet_len, sockaddrunion * source_addr,
        sockaddrunion * dest_addr)
{
    EVENTLOG3(VERBOSE,
            "recv_geco_packet()::recvied  %d bytes of data %s from dctp fd %d\n",
            dctp_packet_len, dctp_packet, socket_fd);

    /* 1) validate packet hdr size, checksum and if aligned 4 bytes */
    if (dctp_packet_len % 4 != 0
            || dctp_packet_len < MIN_NETWORK_PACKET_HDR_SIZES
            || dctp_packet_len > MAX_NETWORK_PACKET_HDR_SIZES
            || !validate_crc32_checksum(dctp_packet, dctp_packet_len))
    {
        EVENTLOG(INTERNAL_TRACE, "received corrupted datagramm\n");
        return;
    }

    /* 2) validate port numbers */
    curr_geco_packet_fixed_ = (geco_packet_fixed_t*) dctp_packet;
    curr_geco_packet_ = (geco_packet_t*) dctp_packet;
    last_src_port_ = ntohs(curr_geco_packet_fixed_->src_port);
    last_dest_port_ = ntohs(curr_geco_packet_fixed_->dest_port);
    if (last_src_port_ == 0 || last_dest_port_ == 0)
    {
        /* refers to RFC 4960 Section 3.1 at line 867 and line 874*/
        ERRLOG(MINOR_ERROR,
                " dispatch_layer_t::recv_geco_packet():: invalid ports number (0)\n");
        last_src_port_ = 0;
        last_dest_port_ = 0;
        return;
    }

    /* 3) validate ip addresses */
    switch (saddr_family(dest_addr))
    {
        case AF_INET:
            EVENTLOG(VERBOSE,
                    "dispatch_layer_t::recv_geco_packet()::checking for correct IPV4 addresses\n");
            source_addr->sin.sin_port = last_src_port_;
            dest_addr->sin.sin_port = last_dest_port_;
            address_type_ = SUPPORT_ADDRESS_TYPE_IPV4;
            ip4_saddr_ = ntohl(dest_addr->sin.sin_addr.s_addr);
            if (IN_CLASSD(ip4_saddr_))
                should_discard_curr_geco_packet_ = true;
            if (IN_EXPERIMENTAL(ip4_saddr_))
                should_discard_curr_geco_packet_ = true;
            if (IN_BADCLASS(ip4_saddr_))
                should_discard_curr_geco_packet_ = true;
            if (INADDR_ANY == ip4_saddr_)
                should_discard_curr_geco_packet_ = true;
            if (INADDR_BROADCAST == ip4_saddr_)
                should_discard_curr_geco_packet_ = true;

            ip4_saddr_ = ntohl(source_addr->sin.sin_addr.s_addr);
            if (IN_CLASSD(ip4_saddr_))
                should_discard_curr_geco_packet_ = true;
            if (IN_EXPERIMENTAL(ip4_saddr_))
                should_discard_curr_geco_packet_ = true;
            if (IN_BADCLASS(ip4_saddr_))
                should_discard_curr_geco_packet_ = true;
            if (INADDR_ANY == ip4_saddr_)
                should_discard_curr_geco_packet_ = true;
            if (INADDR_BROADCAST == ip4_saddr_)
                should_discard_curr_geco_packet_ = true;

            /* we should not should_discard_curr_geco_packet_ the msg sent to ourself */
            /* if ((INADDR_LOOPBACK != ntohl(source_addr->sin.sin_addr.s_addr)) &&
             (source_addr->sin.sin_addr.s_addr == dest_addr->sin.sin_addr.s_addr)) should_discard_curr_geco_packet_ = true;*/
            break;

        case AF_INET6:
            EVENTLOG(VERBOSE,
                    "recv_geco_packet: checking for correct IPV6 addresses\n");
            address_type_ = SUPPORT_ADDRESS_TYPE_IPV6;
            source_addr->sin6.sin6_port = last_src_port_;
            dest_addr->sin6.sin6_port = last_dest_port_;
#if defined (__linux__)
            if (IN6_IS_ADDR_UNSPECIFIED(dest_addr->sin6.sin6_addr.s6_addr))
                should_discard_curr_geco_packet_ = true;
            if (IN6_IS_ADDR_MULTICAST(dest_addr->sin6.sin6_addr.s6_addr))
                should_discard_curr_geco_packet_ = true;
            if (IN6_IS_ADDR_V4COMPAT(&(dest_addr->sin6.sin6_addr.s6_addr)))
                should_discard_curr_geco_packet_ = true;

            if (IN6_IS_ADDR_UNSPECIFIED(source_addr->sin6.sin6_addr.s6_addr))
                should_discard_curr_geco_packet_ = true;
            if (IN6_IS_ADDR_MULTICAST(source_addr->sin6.sin6_addr.s6_addr))
                should_discard_curr_geco_packet_ = true;
            if (IN6_IS_ADDR_V4COMPAT(&(source_addr->sin6.sin6_addr.s6_addr)))
                should_discard_curr_geco_packet_ = true;
            /*
             if ((!IN6_IS_ADDR_LOOPBACK(&(source_addr->sin6.sin6_addr.s6_addr))) &&
             IN6_ARE_ADDR_EQUAL(&(source_addr->sin6.sin6_addr.s6_addr),
             &(dest_addr->sin6.sin6_addr.s6_addr))) should_discard_curr_geco_packet_ = true;
             */
#else
            if (IN6_IS_ADDR_UNSPECIFIED(&dest_addr->sin6.sin6_addr)) should_discard_curr_geco_packet_ = true;
            if (IN6_IS_ADDR_MULTICAST(&dest_addr->sin6.sin6_addr)) should_discard_curr_geco_packet_ = true;
            if (IN6_IS_ADDR_V4COMPAT(&(dest_addr->sin6.sin6_addr))) should_discard_curr_geco_packet_ = true;

            if (IN6_IS_ADDR_UNSPECIFIED(&source_addr->sin6.sin6_addr)) should_discard_curr_geco_packet_ = true;
            if (IN6_IS_ADDR_MULTICAST(&source_addr->sin6.sin6_addr)) should_discard_curr_geco_packet_ = true;

            if (IN6_IS_ADDR_V4COMPAT(&(source_addr->sin6.sin6_addr))) should_discard_curr_geco_packet_ = true;
            /*
             if ((!IN6_IS_ADDR_LOOPBACK(&(source_addr->sin6.sin6_addr))) &&
             IN6_ARE_ADDR_EQUAL(&(source_addr->sin6.sin6_addr),
             &(dest_addr->sin6.sin6_addr))) should_discard_curr_geco_packet_ = true;
             */
#endif
            break;

        default:
            ERRLOG(FALTAL_ERROR_EXIT,
                    "recv_geco_packet()::Unsupported AddressType Received !\n");
            should_discard_curr_geco_packet_ = true;
            break;
    }

#ifdef _DEBUG
    saddr2str(source_addr, src_addr_str_, MAX_IPADDR_STR_LEN, NULL);
    saddr2str(dest_addr, dest_addr_str_, MAX_IPADDR_STR_LEN, NULL);
    EVENTLOG5(EXTERNAL_TRACE,
            "recv_geco_packet : packet_val_len %d, sourceaddress : %s, src_port %u,dest: %s, dest_port %u",
            dctp_packet_len, src_addr_str_, last_src_port_, dest_addr_str_,
            last_dest_port_);
#endif

    if (should_discard_curr_geco_packet_)
    {
        last_src_port_ = 0;
        last_dest_port_ = 0;
        saddr2str(source_addr, src_addr_str_, MAX_IPADDR_STR_LEN, NULL);
        saddr2str(dest_addr, dest_addr_str_, MAX_IPADDR_STR_LEN, NULL);
        EVENTLOG2(INTERNAL_TRACE,
                "recv_geco_packet()::discarding packet for incorrect address\n src addr : %s,\ndest addr%s",
                src_addr_str_, dest_addr_str_);
        return;
    }

    last_source_addr_ = source_addr;
    last_dest_addr_ = dest_addr;

    /*4) find the endpoint for this packet */
    curr_channel_ = find_channel_by_transport_addr(last_source_addr_,
            last_src_port_, last_dest_port_);
    if (curr_channel_ != NULL)
    {
        EVENTLOG(INTERNAL_TRACE, "Found channel from this packet!");
        /*5) get the sctp instance for this packet from channel*/
        curr_geco_instance_ = curr_channel_->geco_inst;
        if (curr_geco_instance_ == NULL)
        {
            ERRLOG(FALTAL_ERROR_EXIT,
                    "Foundchannel, but no geo Instance, FIXME !");
            return;
        }
        else
        {
            my_supported_addr_types_ =
                    curr_geco_instance_->supportedAddressTypes;
        }
    }
    /* 6) find dctp instancefor this packet
     *  if this packet is for a server dctp instance,
     *  we will find that dctp instance and let it handle this packet
     *  (i.e. we have the dctp instance's localPort set and
     *  it matches the packet's destination port) */
    else
    {
        curr_geco_instance_ = find_geco_instance_by_transport_addr(dest_addr,
                address_type_);
        if (curr_geco_instance_ == NULL)
        {
            /* 7) may be an an endpoint that is a client (with instance port 0) */
            EVENTLOG1(VERBOSE,
                    "Couldn't find SCTP Instance for Port %u and Address in List !",
                    last_dest_port_);
            address_type_ == SUPPORT_ADDRESS_TYPE_IPV4 ?
                    my_supported_addr_types_ = SUPPORT_ADDRESS_TYPE_IPV4 :
                    my_supported_addr_types_ = SUPPORT_ADDRESS_TYPE_IPV4
                            | SUPPORT_ADDRESS_TYPE_IPV6;
        }
        else
        {
            my_supported_addr_types_ =
                    curr_geco_instance_->supportedAddressTypes;
            EVENTLOG2(VERBOSE,
                    "Found an SCTP Instance for Port %u and Address in the list, types: %d !",
                    last_dest_port_, my_supported_addr_types_);
        }
    }

    /*8)
     * now we can validate if dest_addr in localaddress
     * this method internally uses curr_geco_instance_ and curr_channel_
     * so we must call it right here */
    if (!validate_dest_addr(dest_addr))
    {
        EVENTLOG(VERBOSE,
                "recv_geco_packet()::this packet is not for me, DISCARDING !!!");
        clear();
        return;
    }

    /*9) fetch all chunk types contained in this packet value field for use in the folowing */
    curr_geco_packet_value_len_ = dctp_packet_len - GECO_PACKET_FIXED_SIZE;
    chunk_types_arr_ = find_chunk_types(curr_geco_packet_->chunk,
            curr_geco_packet_value_len_, &total_chunks_count_);

    tmp_peer_addreslist_size_ = 0;
    curr_uchar_init_chunk_ = NULL;

    /* 10) validate individual chunks
     * (see section 3.1 of RFC 4960 at line 931 init chunk MUST be the only chunk
     * in the SCTP packet carrying it)*/
    init_chunk_num_ = contains_chunk(CHUNK_INIT, chunk_types_arr_);
    if (init_chunk_num_ > 1
            || (init_chunk_num_ == 1 && total_chunks_count_ > 1))
    {
        /* silently should_discard_curr_geco_packet_ */
        ERRLOG(MINOR_ERROR,
                "recv_geco_packet(): discarding illegal packet (init init ack or sdcomplete)\n");
        clear();
        return;
    }
    init_chunk_num_ = contains_chunk(CHUNK_INIT_ACK, chunk_types_arr_);
    if (init_chunk_num_ > 1 || /*only one int ack with other type chunks*/
    (init_chunk_num_ == 1 && total_chunks_count_ > 1)
    /*there are repeated init ack chunks*/)
    {
        /* silently should_discard_curr_geco_packet_ */
        ERRLOG(MINOR_ERROR,
                "recv_geco_packet(): discarding illegal packet (init init ack or sdcomplete)\n");
        clear();
        return;
    }
    init_chunk_num_ = contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr_);
    if (init_chunk_num_ > 1
            || (init_chunk_num_ == 1 && total_chunks_count_ > 1))
    {
        /* silently should_discard_curr_geco_packet_ */
        ERRLOG(MINOR_ERROR,
                "recv_geco_packet(): discarding illegal packet (init init ack or sdcomplete)\n");
        clear();
        return;
    }

    last_src_path_ = 0;
    send_abort_ = false;
    found_init_chunk_ = false;
    init_chunk_fixed_ = NULL;
    vlparam_fixed_ = NULL;

    /* 11) try to find an channel for this packet from setup chunks */
    if (curr_channel_ == NULL)
    {
        curr_uchar_init_chunk_ = find_first_chunk_of(curr_geco_packet_->chunk,
                curr_geco_packet_value_len_, CHUNK_INIT_ACK);
        if (curr_uchar_init_chunk_ != NULL)
        {
            EVENTLOG(VERBOSE,
                    "recv_geco_packet()::Looking for source address in CHUNK_INIT_ACK");
            tmp_peer_addreslist_size_ = read_peer_addreslist(
                    tmp_peer_addreslist_, curr_uchar_init_chunk_,
                    curr_geco_packet_value_len_, my_supported_addr_types_) - 1;
            for (; tmp_peer_addreslist_size_ >= 0; tmp_peer_addreslist_size_--)
            {
                curr_channel_ = find_channel_by_transport_addr(
                        &tmp_peer_addreslist_[tmp_peer_addreslist_size_],
                        last_src_port_, last_dest_port_);
                if (curr_channel_ != NULL)
                {
                    last_src_path_ = tmp_peer_addreslist_size_;
                    break;
                }
            }
        }
        else // as there is only one init chunk in an packet, we use else for efficiency
        {
            curr_uchar_init_chunk_ = find_first_chunk_of(
                    curr_geco_packet_->chunk, curr_geco_packet_value_len_,
                    CHUNK_INIT);
            if (curr_uchar_init_chunk_ != NULL)
            {
                EVENTLOG(VERBOSE,
                        "recv_geco_packet()::Looking for source address in INIT CHUNK");
                tmp_peer_addreslist_size_ = read_peer_addreslist(
                        tmp_peer_addreslist_, curr_uchar_init_chunk_,
                        curr_geco_packet_value_len_, my_supported_addr_types_)
                        - 1;
                for (; tmp_peer_addreslist_size_ >= 0;
                        tmp_peer_addreslist_size_--)
                {
                    curr_channel_ = find_channel_by_transport_addr(
                            &tmp_peer_addreslist_[tmp_peer_addreslist_size_],
                            last_src_port_, last_dest_port_);
                    if (curr_channel_ != NULL)
                    {
                        last_src_path_ = tmp_peer_addreslist_size_;
                        break;
                    }
                }
            } //if (curr_uchar_init_chunk_ != NULL) CHUNK_INIT
        }

        /* 12)
         * this may happen when a previously-connected endpoint re-connect to us
         * puting a new source addr in IP packet (this is why curr_channel_ is NULL above)
         * but also put the previously-used source addr in vlp, with the previous channel
         * still alive (this is why curr_channel_ becomes NOT NULL ).
         * anyway, use the previous channel to handle this packet
         */
        if (curr_channel_ != NULL)
        {
            EVENTLOG(VERBOSE,
                    "recv_geco_packet(): found previous channel from setup chunk");
            my_supported_addr_types_ = 0; // we will
            found_existed_channel_from_init_chunks_ = true;
        }
        else
        {
            EVENTLOG(VERBOSE,
                    "recv_geco_packet(): NOT found previous channel from INIT (ACK) CHUNK");
            found_existed_channel_from_init_chunks_ = false;
        }
    }

    /* 13)
     * filtering and pre-process non-OOB chunks that belong to a channel
     * If the channel exists, both ports of the geco packet must be equal to the ports
     * of the channel and the source address must be in the addresslist of the peer
     * of this channel, this has been validated in find_channel_by_transport_addr() above*/
    init_found_with_channel_not_nil = false;
    cookie_echo_found_with_channel_not_nil = false;
    abort_found_with_channel_not_nil = false;
    if (curr_channel_ != NULL)
    {
        EVENTLOG(VERBOSE,
                "recv_geco_packet(): process packets with channel found");

        /*13.1 valdate curr_geco_instance_*/
        if (curr_geco_instance_ == NULL)
        {
            curr_geco_instance_ = curr_channel_->geco_inst;
            if (curr_geco_instance_ == NULL)
            {
                clear();
                ERRLOG(MAJOR_ERROR,
                        "We have an Association, but no Instance, FIXME !");
            }
            else
            {
                my_supported_addr_types_ =
                        curr_geco_instance_->supportedAddressTypes;
            }
        }
        else
        {
            // we found a previously-connected channel in 12) from setup chunk
            //  the instance it holds MUST == curr_geco_instance_
            if (curr_channel_->geco_inst != curr_geco_instance_)
            {
                ERRLOG(WARNNING_ERROR,
                        "We have an curr_channel_, but its Instance != found instance !");
                curr_geco_instance_ = curr_channel_->geco_inst;
                if (curr_geco_instance_ == NULL)
                {
                    clear();
                    ERRLOG(MAJOR_ERROR,
                            "We have an Association, but no Instance, FIXME !");
                }
            }
        }

        /*13.2 CHUNK_INIT
         see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
         A) Rules for packet carrying INIT:
         The sender MUST set the Verification Tag of the packet to 0.
         When an endpoint receives an SCTP packet with the Verification
         Tag set to 0, it should verify that the packet contains only an
         INIT chunk.  Otherwise, the receiver MUST silently should_discard_curr_geco_packet_ the
         packet.*/

        if (curr_uchar_init_chunk_ == NULL) // we MAY have found it from 11) at line 290
            curr_uchar_init_chunk_ = find_first_chunk_of(
                    curr_geco_packet_->chunk, curr_geco_packet_value_len_,
                    CHUNK_INIT);

        /*process_init_chunk() will furtherly handle this INIT chunk in the follwing method
         here we just validate some fatal errors*/
        if (curr_uchar_init_chunk_ != NULL)
        {
            // we have tested it INIT, init-ack and shutdown complete is the only chunk above
            // at 10) at line 240

            init_found_with_channel_not_nil = true;

            // this should not happen ! if it happens, only reason is we forhot to clear()
            if (last_init_tag_ != 0)
            {
                ERRLOG(MAJOR_ERROR,
                        "found INIT chunk, but last_init_tag_ != 0, FIXME !");
                clear();
                return;
            }

            init_chunk_fixed_ =
                    &(((init_chunk_t*) curr_uchar_init_chunk_)->init_fixed);
            last_init_tag_ = ntohl(init_chunk_fixed_->init_tag);

            EVENTLOG1(VERBOSE, "Got an INIT CHUNK with initiation-tag %u",
                    last_init_tag_);

            // make sure init chunk has zero ver tag
            if (curr_geco_packet_fixed_->verification_tag != 0)
            {
                ERRLOG(WARNNING_ERROR,
                        "found an INIT chunk, but  verification_tag != 0 -> ABORT !");
                send_abort_ = true;
                curr_ecc_code_ = ECC_INIT_CHUNK_VER_TAG_NOT_ZERO;
                curr_ecc_reason_ = "INIT chunk has non-zero verification tag!";
                clear();
                return;
            }

            vlparam_fixed_ = (vlparam_fixed_t*) find_vlparam_from_setup_chunk(
                    curr_uchar_init_chunk_, curr_geco_packet_value_len_,
                    VLPARAM_HOST_NAME_ADDR);
            if (vlparam_fixed_ != NULL)
            {
                EVENTLOG(INTERNAL_TRACE, "found VLPARAM_HOST_NAME_ADDR  -> ");
                // TODO
                // refers to RFC 4096 SECTION 5.1.2.  Handle Address Parameters DNS QUERY
                do_dns_query_for_host_name_ = true;
            }

        }

        /*13.3 CHUNK_ABORT
         see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
         B) Rules for packet carrying ABORT:
         - The receiver of an ABORT MUST accept the packet if the
         Verification Tag field of the packet matches its own tag and the
         T bit is not set OR if it is set to its peer's tag and the T bit
         is set in the Chunk Flags.  Otherwise, the receiver MUST silently
         should_discard_curr_geco_packet_ the packet and take no further action.

         Reflecting tag T bit = 0
         The T bit is set to 0 if the sender filled in the Verification Tag
         expected by the peer. this is reflecting tag

         Reflected tag T bit = 1
         The T bit is set to 1 if the sender filled in the Verification Tag
         of its own. this is reflected tag
         */
        if (contains_chunk(CHUNK_ABORT, chunk_types_arr_) > 0)
        {
            if (init_found_with_channel_not_nil)
            {
                EVENTLOG(VERBOSE,
                        "Found ABORT with INIT chunk also presents-> should_discard_curr_geco_packet_!");
                clear();
                return;
            }

            EVENTLOG(VERBOSE,
                    "recv_geco_packet()::Found ABORT with channel found -> processing!");
            abort_found_with_channel_not_nil = true;
            uchar* abortchunk = find_first_chunk_of(curr_geco_packet_->chunk,
                    curr_geco_packet_value_len_, CHUNK_ABORT);
            bool is_tbit_set = ((chunk_fixed_t*) abortchunk)->chunk_flags == 1;

            if (!(is_tbit_set && last_init_tag_ == curr_channel_->remote_tag)
                    && !(!is_tbit_set
                            && last_init_tag_ == curr_channel_->local_tag))
            {
                clear();
                EVENTLOG(VERBOSE,
                        " T-BIT illegal -> should_discard_curr_geco_packet_!");
                return;
            }
            abort_found_with_channel_not_nil = true;
        }

        /*13.4 CHUNK_SHUTDOWN_COMPLETE
         see RFC 4960
         8.5.1.  Exceptions in Verification Tag Rules
         C) Rules for packet carrying SHUTDOWN COMPLETE:
         -   When sending a SHUTDOWN COMPLETE, if the receiver of the SHUTDOWN
         ACK has a TCB, then the destination endpoint's tag MUST be used,
         and the T bit MUST NOT be set.  Only where no TCB exists should
         the sender use the Verification Tag from the SHUTDOWN ACK, and
         MUST set the T bit.
         -   The receiver of a SHUTDOWN COMPLETE shall accept the packet if
         the Verification Tag field of the packet matches its own tag and
         the T bit is not set OR if it is set to its peer's tag and the T
         bit is set in the Chunk Flags.  Otherwise, the receiver MUST
         silently should_discard_curr_geco_packet_ the packet and take no further action.  An
         endpoint MUST ignore the SHUTDOWN COMPLETE if it is not in the
         SHUTDOWN-ACK-SENT state.*/
        if (contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr_) > 0)
        {
            EVENTLOG(VERBOSE,
                    "recv_geco_packet()::Found CHUNK_SHUTDOWN_COMPLETE with channel found -> processing!");
            uchar* abortchunk = find_first_chunk_of(curr_geco_packet_->chunk,
                    curr_geco_packet_value_len_, CHUNK_SHUTDOWN_COMPLETE);
            bool is_tbit_set = ((chunk_fixed_t*) abortchunk)->chunk_flags == 1;
            if (!(is_tbit_set && last_init_tag_ == curr_channel_->remote_tag)
                    && !(!is_tbit_set
                            && last_init_tag_ == curr_channel_->local_tag))
            {
                clear();
                EVENTLOG(VERBOSE,
                        " T-BIT illegal -> should_discard_curr_geco_packet_!");
                return;
            }

            if (get_curr_channel_state() != ChannelState::ShutdownSent)
            {
                clear();
                EVENTLOG(VERBOSE,
                        " recv shutdown complete but not in SHUTDOWNACK_SENT state -> should_discard_curr_geco_packet_!");
                return;
            }
        }

        /*13.5 CHUNK_SHUTDOWN_ACK
         see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
         see E) Rules for packet carrying a SHUTDOWN ACK
         -   If the receiver is in COOKIE-ECHOED or COOKIE-WAIT state the
         procedures in Section 8.4 SHOULD be followed; in other words, it
         should be treated as an Out Of The Blue packet.*/
        if (contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types_arr_) > 0)
        {
            uint state = get_curr_channel_state();
            if (state == ChannelState::CookieEchoed
                    || state == ChannelState::CookieWait)
            {
                EVENTLOG(VERBOSE,
                        "recv_geco_packet()::Found SHUTDOWN_ACK in non-packet at state cookie echoed or cookie wait state, will send SHUTDOWN_COMPLETE to the peer!");

                uchar shutdown_complete_cid = alloc_simple_chunk(
                        (uchar) CHUNK_SHUTDOWN_COMPLETE, FLAG_NO_TCB);
                simple_chunk_t_ptr_ = complete_simple_chunk(
                        shutdown_complete_cid);
                // this method will internally send all bundled chunks if exceeding packet max
                bundle_ctrl_chunk(simple_chunk_t_ptr_);
                // FIXME need more considerations about why locked or unlocked?
                unlock_bundle_ctrl();
                // explicitely call send to send this simple chunk
                send_bundled_chunks();
                // free this simple chunk
                free_simple_chunk(shutdown_complete_cid);
                clear();
                return;
            }
            else
            {
                //we should ne shutdown-pending state
                // this is normal shutdown pharse, give it to nomral precedures to
                // handle this, we here just validate the state
                if (state != ChannelState::ShutdownPending)
                {
                    EVENTLOG(WARNNING_ERROR,
                            "recv_geco_packet()::Found SHUTDOWN_ACK in non-packet at illegal state -> should_discard_curr_geco_packet_!");
                    clear();
                    return;
                }

            }
        }

        /*13.6 CHUNK_COOKIE_ECHO
         see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
         D) Rules for packet carrying a COOKIE ECHO
         -   When sending a COOKIE ECHO, the endpoint MUST use the value of
         the Initiate Tag received in the INIT ACK.
         -   The receiver of a COOKIE ECHO follows the procedures in Section
         5.2.1.*/
        if (contains_chunk(CHUNK_COOKIE_ECHO, chunk_types_arr_) > 0)
        {
            // this is treated as normal init pharse, give it to nomral precedures
            // in section 5 to handle this, now we just validate ver tag
            if (curr_geco_packet_fixed_->verification_tag
                    != curr_channel_->local_tag)
            {
                EVENTLOG(WARNNING_ERROR,
                        "recv_geco_packet()::Found CHUNK_COOKIE_ECHO in non-packet, ver tag != local tag -> should_discard_curr_geco_packet_!");
                clear();
                return;
            }
            else
            {
                EVENTLOG(VERBOSE,
                        "recv_geco_packet()::Found CHUNK_COOKIE_ECHO in non-packet -> processing!");
            }

        }

        /*13.6
         5.2.3.  Unexpected INIT ACK
         If an INIT ACK is received by an endpoint in any state other than the
         COOKIE-WAIT state, the endpoint should should_discard_curr_geco_packet_ the INIT ACK chunk.
         An unexpected INIT ACK usually indicates the processing of an old or
         duplicated INIT chunk.*/
        if (contains_chunk(CHUNK_INIT_ACK, chunk_types_arr_) > 0)
        {
            if (get_curr_channel_state() != ChannelState::CookieWait)
            {
                EVENTLOG(WARNNING_ERROR,
                        "found CHUNK_INIT_ACK in non-packet in state other than COOKIE-WAIT -> should_discard_curr_geco_packet_!");
                clear();
                return;
            }

            vlparam_fixed_ = (vlparam_fixed_t*) find_vlparam_from_setup_chunk(
                    curr_uchar_init_chunk_, curr_geco_packet_value_len_,
                    VLPARAM_HOST_NAME_ADDR);
            if (vlparam_fixed_ != NULL)
            {
                EVENTLOG(INTERNAL_TRACE,
                        "found VLPARAM_HOST_NAME_ADDR  -> DNS QUERY");
                // TODO refers to RFC 4096 SECTION 5.1.2.  Handle Address Parameters
                // need do DNS QUERY instead of simply ABORT
                do_dns_query_for_host_name_ = true;
            }

            if (curr_geco_packet_fixed_->verification_tag
                    != curr_channel_->local_tag)
            {
                EVENTLOG(WARNNING_ERROR,
                        "recv_geco_packet()::Found CHUNK_INIT_ACK in non-packet, ver tag != local tag -> should_discard_curr_geco_packet_!");
                clear();
                return;
            }
        }
    }
    else // (curr_channel_ == NULL)
    {
        /* 14)
         * filtering and pre-process OOB chunks that have no channel found
         * refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets */
        EVENTLOG(VERBOSE,
                "recv_geco_packet()::current channel ==NULL, start process OOB packets!\n");

        /*15)
         * refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (2)
         * If the OOTB packet contains an ABORT chunk, the receiver MUST
         * silently should_discard_curr_geco_packet_ the OOTB packet and take no further action*/
        if (contains_chunk(CHUNK_ABORT, chunk_types_arr_) > 0)
        {
            EVENTLOG(VERBOSE,
                    "recv_geco_packet()::Found ABORT in oob packet, discarding it !");
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
        if (contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types_arr_) > 0)
        {
            uchar shutdown_complete_cid = alloc_simple_chunk(
            CHUNK_SHUTDOWN_COMPLETE, FLAG_NO_TCB);
            simple_chunk_t_ptr_ = complete_simple_chunk(shutdown_complete_cid);
            // this method will internally send all bundled chunks if exceeding packet max
            bundle_ctrl_chunk(simple_chunk_t_ptr_);
            // FIXME need more considerations about why locked or unlocked?
            unlock_bundle_ctrl();
            // explicitely call send to send this simple chunk
            send_bundled_chunks();
            // free this simple chunk
            free_simple_chunk(shutdown_complete_cid);
            clear();

            EVENTLOG(VERBOSE,
                    "recv_geco_packet()::Found SHUTDOWN_ACK in OOB packet, will send SHUTDOWN_COMPLETE to the peer!");
            return;
        }

        /*17) refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (6)
         If the packet contains a SHUTDOWN COMPLETE chunk, the receiver
         should silently should_discard_curr_geco_packet_ the packet and take no further action.
         this is good because when receiving st-cp chunk, the peer has finished
         shutdown pharse withdeleting TCB and all related data, channek is NULL
         is actually what we want*/
        if (contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr_) > 0)
        {
            clear();
            EVENTLOG(INTERNAL_TRACE,
                    "recv_geco_packet()::Found SHUTDOWN_COMPLETE in OOB packet, discarding it\n!");
            return;
        }

        /* 18)
         * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (7)
         * If th packet contains  a COOKIE ACK,
         * the SCTP packet should be silently discarded*/
        if (contains_chunk(CHUNK_COOKIE_ACK, chunk_types_arr_) > 0)
        {
            clear();
            EVENTLOG(INTERNAL_TRACE,
                    "recv_geco_packet()::Found CHUNK_COOKIE_ACK  in OOB packet, discarding it\n!");
            return;
        }

        /* 19)
         * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (7)
         * If th packet contains a "Stale Cookie" ERROR,
         * the SCTP packet should be silently discarded*/
        if (contains_error_chunk(curr_geco_packet_->chunk,
                curr_geco_packet_value_len_, ECC_STALE_COOKIE_ERROR))
        {
            clear();
            EVENTLOG(INTERNAL_TRACE,
                    "recv_geco_packet()::Found ECC_STALE_COOKIE_ERROR  in OOB packet,discarding it\n!");
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

        // if this packet has channel, codes in 11 if (curr_channel_ == NULL)
        // at line 260 will not actually run, that is why we find it again here
        if (curr_uchar_init_chunk_ == NULL)
            curr_uchar_init_chunk_ = find_first_chunk_of(
                    curr_geco_packet_->chunk, curr_geco_packet_value_len_,
                    CHUNK_INIT);
        if (curr_uchar_init_chunk_ != NULL)
        {
            EVENTLOG(INTERNAL_TRACE,
                    "recv_geco_packet()::Found INIT in OOB packet -> processing it");

            last_veri_tag_ = curr_geco_packet_fixed_->verification_tag;
            if (last_veri_tag_ != 0)
            {
                EVENTLOG(WARNNING_ERROR,
                        "warnning verification_tag in INIT != 0 -> ABORT");
                send_abort_ = true;
            }

            // update last_init_tag_ with value of init tag carried in this chunk
            init_chunk_fixed_ =
                    &(((init_chunk_t*) curr_uchar_init_chunk_)->init_fixed);
            last_init_tag_ = ntohl(init_chunk_fixed_->init_tag);
            EVENTLOG1(VERBOSE, "setting last_init_tag_ to %u", last_init_tag_);

            // we have an instance up listenning on that port just validate params
            // this is normal connection pharse
            if (curr_geco_instance_ != NULL)
            {
                EVENTLOG(INTERNAL_TRACE, "an instance found -> processing");

                if (curr_geco_instance_->local_port == 0)
                {
                    EVENTLOG(MAJOR_ERROR,
                            "recv_geco_packet()::got INIT Message, but curr_geco_instance_ local port is zero!\n");
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
                    EVENTLOG2(VERBOSE,
                            "dest port (%u) does not equals to curr_geco_instance_ listenning local port (%u) -> ABORT",
                            last_dest_port_, curr_geco_instance_->local_port);
                    send_abort_ = true;
                }

                vlparam_fixed_ =
                        (vlparam_fixed_t*) find_vlparam_from_setup_chunk(
                                curr_uchar_init_chunk_,
                                curr_geco_packet_value_len_,
                                VLPARAM_HOST_NAME_ADDR);
                if (vlparam_fixed_ != NULL)
                {
                    EVENTLOG(INTERNAL_TRACE,
                            "found VLPARAM_HOST_NAME_ADDR  -> ");
                    // TODO refers to RFC 4096 SECTION 5.1.2.  Handle Address Parameters
                    // need do DNS QUERY instead of simply ABORT
                    // should use asy dns query
                    // 1. createan bitarrary to indicate which dns query fail or success
                    // 2. create an thread who will do all the dns queryies
                    //     this thread will make a copy of its own of bitarrary, when it finishes an dns,
                    // it will mark it as done (true). since this flag is only writte by dns thread and only
                    // read by network thread sono need to lock it.
                    // 3. start a dns query checking task  (will be called in each tick select() returns)
                    //     this task will read bitarrary to check which dns results are ready
                    //     it also check if a dns query timeouts, if tmeouts, the thread will be forced
                    //     destroyed and then recreate a new thread to do the rest dns query again
                    // until all dns query are all done, checking taks will be canncelled.
                    do_dns_query_for_host_name_ = true;
                }
            } // if (curr_geco_instance_ != NULL) at line 460
            else
            {
                // we do not have an instance up listening on that port-> ABORT
                // this may happen when a peer is connecting, ulp is not started
                // todo tell ECC_GECO_INSTANCE_NOT_FOUND error to peer
                EVENTLOG(INTERNAL_TRACE,
                        "got INIT Message, but no instance found -> ABORT");
                curr_ecc_code_ = ECC_PEER_INSTANCE_NOT_FOUND;
                curr_ecc_reason_ =
                        "cannot find the peer with the port you specified!";
                send_abort_ = true;
            }
        } // if (init_chunk != NULL) at line 458

        /* 21)
         * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (4)
         * If the packet contains a COOKIE ECHO in the first chunk, process
         *  it as described in Section 5.1. */
        if (contains_chunk(CHUNK_COOKIE_ECHO, chunk_types_arr_) > 0)
        {
            EVENTLOG(INTERNAL_TRACE,
                    "recv_geco_packet()::Found CHUNK_COOKIE_ECHO in OOB packet -> processing it");

            // we have an instance up listenning on that port just validate params
            if (curr_geco_instance_ != NULL)
            {
                EVENTLOG(INTERNAL_TRACE, "an instance found -> processing");

                if (curr_geco_instance_->local_port == 0)
                {
                    EVENTLOG(MAJOR_ERROR,
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
                    EVENTLOG2(INTERNAL_TRACE,
                            "dest port (%u) != curr_geco_instance_ listenning local port (%u) -> ABORT",
                            last_dest_port_, curr_geco_instance_->local_port);
                    curr_ecc_code_ = ECC_PEER_NOT_LISTENNING_PORT;
                    curr_ecc_reason_ =
                            "found peer but he is not listenning on the port you specified!";
                    send_abort_ = true;
                }
            }
            else
            {
                // we do not have an instance up listening on that port-> ABORT
                EVENTLOG(INTERNAL_TRACE,
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
         receiver of the OOTB packet shall should_discard_curr_geco_packet_ the OOTB packet and
         take no further action.*/
        EVENTLOG(INTERNAL_TRACE,
                "recv_geco_packet()::send ABORT with ignoring OOTB - see section 8.4.8)");
        send_abort_ = true;
    }

    /*23) may send ABORT to the peer */
    if (send_abort_)
    {
        EVENTLOG(INTERNAL_TRACE,
                "recv_geco_packet()::discarded packet and sending ABORT");
        if (!send_abort_for_oob_packet_)
        {
            EVENTLOG(VERBOSE,
                    "send_abort_for_oob_packet_==FALSE -> Discarding packet,not sending ABORT");
            clear();
            /* and should_discard_curr_geco_packet_ that packet */
            return;
        }

        /*build ABORT and send it*/
        // allocate simple chunk
        uchar abort_cid = (
                curr_channel_ == NULL ?
                        alloc_simple_chunk(CHUNK_ABORT,
                        FLAG_NO_TCB) :
                        alloc_simple_chunk(CHUNK_ABORT, FLAG_NONE));
        simple_chunk_t_ptr_ = complete_simple_chunk(abort_cid);
        if (curr_ecc_code_ != 0)
        {
            error_cause_t* curr_ecc_ptr_ =
                    ((error_cause_t*) simple_chunk_t_ptr_->chunk_value);
            curr_ecc_ptr_->error_reason_code = curr_ecc_code_;
            curr_ecc_ptr_->error_reason_length = 4 + strlen(curr_ecc_reason_);
            simple_chunk_t_ptr_->chunk_header.chunk_length +=
                    curr_ecc_ptr_->error_reason_length;
            strcpy((char*) curr_ecc_ptr_->error_reason, curr_ecc_reason_);
        }
        // this method will internally send all bundled chunks if exceeding packet max
        bundle_ctrl_chunk(simple_chunk_t_ptr_);
        // FIXME need more considerations about why locked or unlocked?
        unlock_bundle_ctrl();
        // explicitely call send to send this simple chunk
        send_bundled_chunks();
        // free this simple chunk
        free_simple_chunk(abort_cid);

        EVENTLOG2(VERBOSE,
                "ecc %u:%s, \nsend_abort_for_oob_packet_==TRUE -> sending ABORT with veri-tag and T-Bit reflected",
                curr_ecc_code_, curr_ecc_reason_);

        clear();
        return;
    } // 23 send_abort_ == true

    // forward packet value to bundle ctrl module for disassemblings
    disassemle_curr_geco_packet();

    // no need to clear last_src_port_ and last_dest_port_ MAY be used by other functions
    last_src_path_ = -1;
    do_dns_query_for_host_name_ = false;
}

int dispatch_layer_t::disassemle_curr_geco_packet()
{
    /*
     Get first chunk-id and length, pass pointers & len on to relevant module :

     CHUNK_INIT,
     CHUNK_INIT_ACK,
     CHUNK_COOKIE_ECHO,
     CHUNK_COOKIE_ACK
     CHUNK_SHUTDOWN,
     CHUNK_SHUTDOWN_ACK
     CHUNK_ABORT,
     go to state machina controller (change of association state)

     CHUNK_HBREQ,
     CHUNK_HBACK
     go to PATH_MAN instance

     CHUNK_SACK
     goes to RELIABLE_TRANSFER

     CHUNK_ERROR
     probably to SCTP_CONTROL as well  (at least there !)

     CHUNK_DATA
     goes to RX_CONTROL
     */

    uchar* curr_pos = curr_geco_packet_->chunk; /* points to the first chunk in this pdu */
    uint read_len = 0, chunk_len;
    uint padding_len;
    simple_chunk_t* chunk;

    EVENTLOG(INTERNAL_TRACE, "Entered disassemle_curr_geco_packet()...... ");
    lock_bundle_ctrl();

    while (read_len < curr_geco_packet_value_len_)
    {
        if (curr_geco_packet_value_len_ - read_len < GECO_PACKET_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
                    "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            unlock_bundle_ctrl();
            return 1;
        }

        chunk = (simple_chunk_t *) curr_pos;
        chunk_len = ntohs(chunk->chunk_header.chunk_length);
        EVENTLOG4(VERBOSE,
                "disassemle_curr_geco_packet(address=%u) : len==%u, processed_len = %u, chunk_len=%u",
                last_src_path_, curr_geco_packet_value_len_, read_len,
                chunk_len);

        if (chunk_len < GECO_PACKET_FIXED_SIZE
                || chunk_len + read_len > curr_geco_packet_value_len_)
        {
            EVENTLOG(WARNNING_ERROR,
                    "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            unlock_bundle_ctrl();
            return 1;
        }

        /*
         * TODO :
         * Add return values to the chunk-functions, where they can indicate what
         * to do with the rest of the datagram (i.e. DISCARD after stale COOKIE_ECHO
         * with tie tags that do not match the current ones)
         */
        bool data_chunk_received = false;
        int handle_ret;
        switch (chunk->chunk_header.chunk_id)
        {
            case CHUNK_DATA:
                EVENTLOG(INTERNAL_TRACE, "***** Bundling received CHUNK_DATA");
                handle_ret = process_data_chunk((data_chunk_t*) chunk,
                        last_src_path_);
                data_chunk_received = true;
                break;
            case CHUNK_INIT:
                EVENTLOG(INTERNAL_TRACE, "***** Bundling received CHUNK_INIT");
                handle_ret = process_init_chunk((init_chunk_t *) chunk);
                break;
            case CHUNK_INIT_ACK:
                EVENTLOG(INTERNAL_TRACE,
                        "***** Bundling received CHUNK_INIT_ACK");
                handle_ret = process_init_ack_chunk((init_chunk_t *) chunk);
                break;
            case CHUNK_SACK:
                EVENTLOG(INTERNAL_TRACE, "***** Bundling received CHUNK_SACK");
                handle_ret = process_sack_chunk(last_src_path_, chunk,
                        curr_geco_packet_value_len_);
                break;
            default:
                break;
        }
        unlock_bundle_ctrl();

        //switch (handle_ret)
        //{
        //    case ChunkProcessResult::delete_channel_for_invalid_param:
        //        unlock_bundle_ctrl();
        //        delete_curr_channel();
        //        on_connection_lost(CONNECTION_LOST_REASON::invalid_param);
        //        null_curr_channel_and_geco_instance();
        //        break;
        //    case ChunkProcessResult::exceed_max_retrans_count:
        //        break;
        //    case ChunkProcessResult::aborted:
        //        break;
        //    case ChunkProcessResult::Good:
        //        break;
        //    default:
        //        break;
        //}
    }
    return 0;
}

int dispatch_layer_t::process_data_chunk(data_chunk_t * data_chunk, uint ad_idx)
{
    return 0;
}
int dispatch_layer_t::process_init_chunk(init_chunk_t * init)
{
    EVENTLOG(VERBOSE, "process_init_chunk() is executed");

    /*1) put init chunk into chunk  array */
    uint ret = ChunkProcessResult::Good;
    uchar init_cid = alloc_simple_chunk((simple_chunk_t*) init);
    if (get_simple_chunk_id(init_cid) != CHUNK_INIT)
    {
        ERRLOG(MAJOR_ERROR, "process_init_chunk: wrong chunk type");
        remove_simple_chunk(init_cid);
        return ret;
    }

    /*2) validate init params*/
    uchar abortcid;
    state_machine_controller_t* smctrl = get_state_machine_controller();
    if (read_outbound_stream(init_cid) == 0
            || read_inbound_stream(init_cid) == 0 || read_init_tag(init_cid))
    {
        EVENTLOG(EXTERNAL_TRACE,
                "event: received init with zero number of streams, or zero init TAG");

        /*2.1) make and send ABORT with error cause setup*/
        abortcid = alloc_simple_chunk(CHUNK_ABORT, FLAG_NONE);
        append_ecc(abortcid, ECC_INVALID_MANDATORY_PARAM);
        bundle_ctrl_chunk(complete_simple_chunk(abortcid));
        send_bundled_chunks();
        free_simple_chunk(abortcid);

        /*2.2) delete all data of this channel,
         * smctrl != NULL means current channel MUST exist at this moment */
        if (smctrl != NULL)
        {
            /* only when channel presents, unlock makes sense.
             * as the data transfer is aloowed only
             * when channel established*/
            unlock_bundle_ctrl();
            delete_curr_channel();
            on_connection_lost(ConnectionLostReason::invalid_param);
            clear_current_channel();
        }
        ret =
                ChunkProcessResult::StopAndDeleteChannel_ValidateInitParamFailedError;
        return ret;
    }

    /*3) validate source addr */
    if (last_source_addr_ == NULL)
    {
        /* 3.1) delete all data of this channel,
         * smctrl != NULL means current channel MUST exist at this moment */
        if (smctrl == NULL)
        {
            clear_current_channel();
            ret = ChunkProcessResult::StopAndDeleteChannel_LastSrcPortNullError;
            return ret;
        }
        else
        {
            if (smctrl->init_timer_id->timer_id != 0)
            {
                timer_mgr_.delete_timer(smctrl->init_timer_id);
            }
            unlock_bundle_ctrl();
            delete_curr_channel();
            on_connection_lost(ConnectionLostReason::invalid_param);
            clear_current_channel();
            ret = ChunkProcessResult::StopAndDeleteChannel_LastSrcPortNullError;
            return ret;
        }
    }
    else
    {
        memcpy(&tmp_addr_, last_source_addr_, sizeof(sockaddrunion));
    }

    ushort inbound_stream = 0;
    ushort outbound_stream = 0;
    uchar init_ack_cid;
    uint init_tag;
    /* 4) this branch handles the cases below:
     * 1) RFC 4960 - 5.2.1.INIT Received in COOKIE-WAIT or COOKIE-ECHOED State - (B)
     * Both sides are trying to initialize the association at about the same time.
     * (unexpected INIT sent to an endpoint without existing assciation)
     * 2) RFC 4960 - 5.1.Normal Establishment of an Association - (B)
     * "Z" shall respond immediately with an INIT ACK chunk.*/
    if (smctrl == NULL)
    {
        EVENTLOG(INTERNAL_TRACE,
                "come into branch at process_init_chunk() -> if(smctrl == NULL)!");

        /*4.1) get in out stream number*/
        inbound_stream = std::min(read_outbound_stream(init_cid),
                get_local_inbound_stream());
        outbound_stream = std::min(read_inbound_stream(init_cid),
                get_local_outbound_stream());

        /* 4.2) alloc init ack chunk, init tag used as init tsn */
        // todo use safe generate_init_tag from libcat
        init_tag = generate_init_tag();
        init_ack_cid = alloc_init_ack_chunk(init_tag,
                curr_geco_instance_->default_myRwnd, outbound_stream,
                inbound_stream, init_tag);

        /*4.3) read and validate peer addrlist carried in the received init chunk*/
        assert(my_supported_addr_types_ != 0);
        tmp_peer_addreslist_size_ = read_peer_addreslist(tmp_peer_addreslist_,
                (uchar*) init, curr_geco_packet_value_len_,
                my_supported_addr_types_, &tmp_peer_supported_types_);
        if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
            ERRLOG(FALTAL_ERROR_EXIT,
                    "BAKEOFF: Program error, no common address types in process_init_chunk()");

        /*4.4) get local addr list and append them to INIT ACK*/
        tmp_local_addreslist_size_ = get_local_addreslist(tmp_local_addreslist_,
                last_source_addr_, 1, tmp_peer_supported_types_, true);
        write_addrlist(init_ack_cid, tmp_local_addreslist_,
                tmp_local_addreslist_size_);

        /*4.5) generate and append cookie to INIT ACK*/
        write_cookie(init_cid, init_ack_cid, get_init_fixed(init_cid),
                get_init_fixed(init_ack_cid), get_cookie_lifespan(init_cid), 0,
                0, /* normal case: no existing channel, set both zero*/
                last_dest_port_, last_src_port_, tmp_local_addreslist_,
                tmp_local_addreslist_size_, tmp_peer_addreslist_,
                tmp_peer_addreslist_size_);

        /* 4.6) check unrecognized params*/
        int rett = process_unknown_params_from_init_chunk(init_cid,
                init_ack_cid, my_supported_addr_types_);
        if (rett < 0)
        {
            /* peer's init has chunk length error ververy bad error!,
             * we should discard peer's connection by not bunding init ack*/
            ret = ChunkProcessResult::Stop;
        }
        else
        {
            if (rett != 0)
            {
                /* as specified in rfc 4960, when the init from peer hasunkown params,
                 * we should discard peer's connection by not bunding init ack*/
                ERRLOG(WARNNING_ERROR,
                        "peer init has unknown params -> discard !");
                free_simple_chunk(init_ack_cid);
                remove_simple_chunk(init_cid);
                return ChunkProcessResult::StopProcessInitChunk_UnkownParamError;
            }
            else
            {
                /* param type has  skip prcessing set, so we just skip it*/
                ret = ChunkProcessResult::SkipProcessInitChunk_UnkownParamError;

                /* send all bundled chunks to ensure init ack is the only chunk sent
                 * in the whole geco packet*/
                unlock_bundle_ctrl();
                send_bundled_chunks();

                /* bundle INIT ACK if full will send, may empty bundle and copy init ack*/
                bundle_ctrl_chunk(complete_simple_chunk(init_ack_cid));
                send_bundled_chunks(); // send init ack
                free_simple_chunk(init_ack_cid);
                EVENTLOG(INTERNAL_EVENT, "event: initAck sent");
            }
        }
    }

    /* 4) this branch handles the cases below:
     * 1) RFC 4960 - 5.2.2.
     * Unexpected INIT in States Other than CLOSED, COOKIE-ECHOED,
     * COOKIE-WAIT, and SHUTDOWN-ACK-SENT
     * 2) RFC 4960 - 5.2.4.  Handle a COOKIE ECHO when a TCB Exists */
    else
    {
        EVENTLOG(INTERNAL_TRACE,
                "come into branch at process_init_chunk() -> if(smctrl != NULL)!");

        ChannelState channel_state = smctrl->channel_state;
        EVENTLOG1(EXTERNAL_TRACE, "received INIT chunk in state %02u",
                channel_state);
        int primary_path = get_primary_path();
        my_supported_addr_types_;
        uint init_i_sent_cid;
        int rett;
        switch (channel_state)
        {
            /* 5)
             RFC 4960-5.2.1.INIT Received in COOKIE-WAIT or COOKIE-ECHOED State
             (Item B)
             When responding in either state (COOKIE-WAIT or COOKIE-ECHOED) with
             an INIT ACK, the original parameters are combined with those from the
             newly received INIT chunk.  The endpoint shall also generate a State
             Cookie with the INIT ACK.  The endpoint uses the parameters sent in
             its INIT to calculate the State Cookie.
             After that, the endpoint MUST NOT change its state, the T1-init timer
             shall be left running, and the corresponding TCB MUST NOT be
             destroyed.  The normal procedures for handling State Cookies when a
             TCB exists will resolve the duplicate INITs to a single association. */
            case ChannelState::CookieEchoed:
                /* 5.1)
                 - Upon receipt of an INIT in the COOKIE-ECHOED state, an endpoint MUST
                 respond with an INIT ACK using the same parameters it sent in its
                 original INIT chunk (including its Initiate Tag, unchanged), provided
                 that no NEW address has been added to the forming association.  If
                 the INIT message indicates that a new address has been added to the
                 association, then the entire INIT MUST be discarded, and NO changes
                 should be made to the existing association.  An ABORT SHOULD be sent
                 in response that MAY include the error 'Restart of an association
                 with new addresses'.  The error SHOULD list the addresses that were
                 added to the restarting association.
                 - For an endpoint that is in the COOKIE-ECHOED state, it MUST populate
                 its Tie-Tags within both the association TCB and inside the State
                 Cookie (see Section 5.2.2 for a description of the Tie-Tags).*/

                /* 5.2) validate tie tags NOT zeros */
                if (smctrl->local_tie_tag == 0 || smctrl->peer_tie_tag == 0)
                {
                    ERRLOG2(FALTAL_ERROR_EXIT,
                            "a zero Tie tag in Cookie Echoed state, local %u and peer %u",
                            smctrl->local_tie_tag, smctrl->peer_tie_tag);
                }

                /*5.2) validate no new addr aaded from the newly received INIT */
                /* read and validate peer addrlist carried in the received init chunk*/
                assert(my_supported_addr_types_ != 0);
                tmp_peer_addreslist_size_ = read_peer_addreslist(
                        tmp_peer_addreslist_, (uchar*) init,
                        curr_geco_packet_value_len_, my_supported_addr_types_,
                        &tmp_peer_supported_types_);
                if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
                    ERRLOG(FALTAL_ERROR_EXIT,
                            "BAKEOFF: Program error, no common address types in process_init_chunk()");

                /*compare if there is new addr presenting*/
                for (uint idx = 0; idx < curr_channel_->remote_addres_size;
                        idx++)
                {
                    for (uint inner = 0; inner < tmp_peer_addreslist_size_;
                            inner++)
                    {
                        if (!saddr_equals(curr_channel_->remote_addres + idx,
                                tmp_peer_addreslist_ + inner))
                        {
                            EVENTLOG(VERBOSE,
                                    "new addr found in received INIT at CookieEchoed state -> discard !");
                            /* remove NOT free INIT CHUNK before return */
                            remove_simple_chunk(init_cid);
                            return ChunkProcessResult::StopProcessInitChunk_NewAddrAddedError;
                        }
                    }
                }

                /* 5.3)
                 * For an endpoint that is in the COOKIE-ECHOED state it MUST populate
                 * its Tie-Tags with random values so that possible attackers cannot guess
                 * real tag values of the association (see Implementer's Guide > version 10)*/
                smctrl->local_tie_tag = generate_init_tag();
                smctrl->peer_tie_tag = generate_init_tag();

                /*5.4) get in out stream number*/
                inbound_stream = std::min(read_outbound_stream(init_cid),
                        get_local_inbound_stream());
                outbound_stream = std::min(read_inbound_stream(init_cid),
                        get_local_outbound_stream());

                /*5.5) an INIT ACK using the same parameters it sent in its
                 original INIT chunk (including its Initiate Tag, unchanged) */
                if (smctrl->my_init_chunk == NULL)
                    ERRLOG(FALTAL_ERROR_EXIT,
                            "smctrl->my_init_chunk == NULL !");

                /* make and fills init ack*/
                init_ack_cid = alloc_init_ack_chunk(
                        smctrl->my_init_chunk->init_fixed.init_tag,
                        smctrl->my_init_chunk->init_fixed.rwnd,
                        smctrl->my_init_chunk->init_fixed.outbound_streams,
                        smctrl->my_init_chunk->init_fixed.inbound_streams,
                        smctrl->my_init_chunk->init_fixed.initial_tsn);

                /*5.6) get local addr list and append them to INIT ACK*/
                tmp_local_addreslist_size_ = get_local_addreslist(
                        tmp_local_addreslist_, last_source_addr_, 1,
                        tmp_peer_supported_types_, true);
                write_addrlist(init_ack_cid, tmp_local_addreslist_,
                        tmp_local_addreslist_size_);

                /*5.7) generate and append cookie to INIT ACK*/
                write_cookie(init_cid, init_ack_cid, get_init_fixed(init_cid),
                        get_init_fixed(init_ack_cid),
                        get_cookie_lifespan(init_cid),
                        /* unexpected case: existing channel found, set both NOT zero*/
                        smctrl->local_tie_tag, smctrl->peer_tie_tag,
                        last_dest_port_, last_src_port_, tmp_local_addreslist_,
                        tmp_local_addreslist_size_, tmp_peer_addreslist_,
                        tmp_peer_addreslist_size_);

                /* 5.8) check unrecognized params */
                rett = process_unknown_params_from_init_chunk(init_cid,
                        init_ack_cid, my_supported_addr_types_);
                if (rett < 0)
                {
                    /* 5.9) peer's init chunk has icorrect chunk length,
                     * discard peer's connection by not bunding init ack*/
                    free_simple_chunk(init_ack_cid);
                    ret = ChunkProcessResult::Stop;
                }
                else
                {
                    /* 5.10) MUST send INIT ACK caried unknown params to the peer
                     * if he has unknown params in its init chunk
                     * as we SHOULD let peer's imple to finish the
                     * unnormal connection handling precedures*/

                    if (rett != 0)
                    {
                        free_simple_chunk(init_ack_cid);
                        remove_simple_chunk(init_cid);
                        return ChunkProcessResult::StopProcessInitChunk_UnkownParamError;
                    }
                    else
                    {
                        ret =
                                ChunkProcessResult::SkipProcessInitChunk_UnkownParamError;
                    }

                    /* send all bundled chunks to ensure init ack is the only chunk sent
                     * in the whole geco packet*/
                    unlock_bundle_ctrl();
                    send_bundled_chunks();
                    // bundle INIT ACK if full will send and empty bundle then copy init ack
                    bundle_ctrl_chunk(complete_simple_chunk(init_ack_cid));
                    send_bundled_chunks(); // send init ack
                    free_simple_chunk(init_ack_cid);
                    EVENTLOG(INTERNAL_EVENT,
                            "event: initAck sent at state of cookie echoed");
                }
                break;

            case ChannelState::CookieWait:
                /* 6.1)
                 Upon receipt of an INIT in the COOKIE-WAIT state, an endpoint MUST
                 respond with an INIT ACK using the same parameters it sent in its
                 original INIT chunk (including its Initiate Tag, unchanged).  When
                 responding, the endpoint MUST send the INIT ACK back to the same
                 address that the original INIT (sent by this endpoint) was sent.*/

                if (smctrl->local_tie_tag != 0 || smctrl->peer_tie_tag != 0)
                {
                    ERRLOG2(FALTAL_ERROR_EXIT,
                            "Tie tags NOT zero in COOKIE_WAIT, but %u and %u",
                            smctrl->local_tie_tag, smctrl->peer_tie_tag);
                }

                /* reassign to zeros means no existing channel founs in this state */
                smctrl->local_tie_tag = 0;
                smctrl->peer_tie_tag = 0;

                /* make and fills init ack*/
                init_ack_cid = alloc_init_ack_chunk(
                        smctrl->my_init_chunk->init_fixed.init_tag,
                        smctrl->my_init_chunk->init_fixed.rwnd,
                        smctrl->my_init_chunk->init_fixed.outbound_streams,
                        smctrl->my_init_chunk->init_fixed.inbound_streams,
                        smctrl->my_init_chunk->init_fixed.initial_tsn);

                /*6.6) get local addr list and append them to INIT ACK*/
                tmp_local_addreslist_size_ = get_local_addreslist(
                        tmp_local_addreslist_, last_source_addr_, 1,
                        tmp_peer_supported_types_, true);
                write_addrlist(init_ack_cid, tmp_local_addreslist_,
                        tmp_local_addreslist_size_);

                /*6.7) generate and append cookie to INIT ACK*/
                write_cookie(init_cid, init_ack_cid, get_init_fixed(init_cid),
                        get_init_fixed(init_ack_cid),
                        get_cookie_lifespan(init_cid),
                        /* unexpected case: existing channel found, set both NOT zero*/
                        smctrl->local_tie_tag, smctrl->peer_tie_tag,
                        last_dest_port_, last_src_port_, tmp_local_addreslist_,
                        tmp_local_addreslist_size_, tmp_peer_addreslist_,
                        tmp_peer_addreslist_size_);

                /* 6.8) check unrecognized params*/
                rett = process_unknown_params_from_init_chunk(init_cid,
                        init_ack_cid, my_supported_addr_types_);
                if (rett < 0)
                {
                    /* 6.9) peer's init chunk has icorrect chunk length,
                     * discard peer's connection by not bunding init ack*/
                    free_simple_chunk(init_ack_cid);
                    remove_simple_chunk(init_cid);
                    return ChunkProcessResult::Stop;
                }
                else
                {
                    /* 6.10) MUST send INIT ACK caried unknown params to the peer
                     * if he has unknown params in its init chunk
                     * as we SHOULD let peer's imple to finish the
                     * unnormal connection handling precedures*/
                    if (rett != 0)
                    {
                        ret =
                                ChunkProcessResult::StopProcessInitChunk_UnkownParamError;
                    }
                    else
                    {
                        ret =
                                ChunkProcessResult::SkipProcessInitChunk_UnkownParamError;
                    }

                    /* send all bundled chunks to ensure init ack is the only chunk sent
                     * in the whole geco packet*/
                    unlock_bundle_ctrl();
                    send_bundled_chunks();

                    // bundle INIT ACK if full will send and empty bundle then copy init ack
                    bundle_ctrl_chunk(complete_simple_chunk(init_ack_cid));
                    send_bundled_chunks(&smctrl->addr_my_init_chunk_sent_to);
                    free_simple_chunk(init_ack_cid);
                    EVENTLOG(INTERNAL_EVENT,
                            "event: initAck sent at state of cookie wait");
                }

                /* 7) see RFC 4960 - Section 5.2.2
                 Unexpected INIT in States Other than CLOSED, COOKIE-ECHOED,
                 COOKIE-WAIT, and SHUTDOWN-ACK-SENT
                 Unless otherwise stated, upon receipt of an unexpected INIT for this
                 association, the endpoint shall generate an INIT ACK with a State
                 Cookie.  Before responding, the endpoint MUST check to see if the
                 unexpected INIT adds new addresses to the association.*/
            case ChannelState::Connected:
            case ChannelState::ShutdownPending:
            case ChannelState::ShutdownSent:
                /* 7.1) validate tie tags NOT zeros */
                if (smctrl->local_tie_tag == 0 || smctrl->peer_tie_tag == 0)
                {
                    ERRLOG2(FALTAL_ERROR_EXIT,
                            "a zero Tie tag in Cookie Echoed state, local %u and peer %u",
                            smctrl->local_tie_tag, smctrl->peer_tie_tag);
                }

                /*7.2) validate no new addr aaded from the newly received INIT */
                /* read and validate peer addrlist carried in the received init chunk*/
                assert(my_supported_addr_types_ != 0);
                tmp_peer_addreslist_size_ = read_peer_addreslist(
                        tmp_peer_addreslist_, (uchar*) init,
                        curr_geco_packet_value_len_, my_supported_addr_types_,
                        &tmp_peer_supported_types_);
                if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
                    ERRLOG(FALTAL_ERROR_EXIT,
                            "BAKEOFF: Program error, no common address types in process_init_chunk()");

                /*compare if there is new addr presenting*/
                for (uint idx = 0; idx < curr_channel_->remote_addres_size;
                        idx++)
                {
                    for (uint inner = 0; inner < tmp_peer_addreslist_size_;
                            inner++)
                    {
                        if (!saddr_equals(curr_channel_->remote_addres + idx,
                                tmp_peer_addreslist_ + inner))
                        {
                            EVENTLOG(VERBOSE,
                                    "new addr found in received INIT at CookieEchoed state -> discard !");
                            /* remove NOT free INIT CHUNK before return */
                            remove_simple_chunk(init_cid);
                            return ChunkProcessResult::StopProcessInitChunk_NewAddrAddedError;
                        }
                    }
                }

                /*7.2) get in out stream number*/
                inbound_stream = std::min(read_outbound_stream(init_cid),
                        get_local_inbound_stream());
                outbound_stream = std::min(read_inbound_stream(init_cid),
                        get_local_outbound_stream());

                /* 7.3) prepare init ack
                 -the INIT ACK MUST contain a new Initiate Tag(randomly generated;
                 see Section 5.3.1).
                 -Other parameters for the endpoint SHOULD be copied from the existing
                 parameters of the association (e.g., number of outbound streams) into
                 the INIT ACK and cookie.*/
                init_tag = generate_init_tag(); // todo use safe generate_init_tag
                init_ack_cid = alloc_init_ack_chunk(init_tag,
                        curr_channel_->receive_control->curr_rwnd,
                        curr_channel_->deliverman_control->numSendStreams,
                        curr_channel_->deliverman_control->numReceiveStreams,
                        smctrl->my_init_chunk->init_fixed.initial_tsn);

                /*7.4) get local addr list and append them to INIT ACK*/
                tmp_local_addreslist_size_ = get_local_addreslist(
                        tmp_local_addreslist_, last_source_addr_, 1,
                        tmp_peer_supported_types_, true);
                write_addrlist(init_ack_cid, tmp_local_addreslist_,
                        tmp_local_addreslist_size_);

                /*6.7) generate and append cookie to INIT ACK*/
                write_cookie(init_cid, init_ack_cid, get_init_fixed(init_cid),
                        get_init_fixed(init_ack_cid),
                        get_cookie_lifespan(init_cid),
                        /* unexpected case:  channel existing, set both NOT zero*/
                        smctrl->local_tie_tag, smctrl->peer_tie_tag,
                        last_dest_port_, last_src_port_, tmp_local_addreslist_,
                        tmp_local_addreslist_size_, tmp_peer_addreslist_,
                        tmp_peer_addreslist_size_);

                /* 6.8) check unrecognized params*/
                rett = process_unknown_params_from_init_chunk(init_cid,
                        init_ack_cid, my_supported_addr_types_);
                if (rett < 0)
                {
                    /* 6.9) peer's init chunk has icorrect chunk length,
                     * discard peer's connection by not bunding init ack*/
                    free_simple_chunk(init_ack_cid);
                    ret = ChunkProcessResult::Stop;
                }
                else
                {
                    /* 6.10) MUST send INIT ACK caried unknown params to the peer
                     * if he has unknown params in its init chunk
                     * as we SHOULD let peer's imple to finish the
                     * unnormal connection handling precedures*/

                    if (rett != 0)
                    {
                        ret =
                                ChunkProcessResult::StopProcessInitChunk_UnkownParamError;
                    }
                    else
                    {
                        ret =
                                ChunkProcessResult::SkipProcessInitChunk_UnkownParamError;
                    }
                    /*send all bundled chunks to ensure init ack is the only chunk sent*/
                    unlock_bundle_ctrl();
                    send_bundled_chunks();
                    // bundle INIT ACK if full will send and empty bundle then copy init ack
                    bundle_ctrl_chunk(complete_simple_chunk(init_ack_cid));
                    /* trying to send bundle to become more responsive
                     * unlock bundle to send init ack as single chunk in the
                     * whole geco packet */
                    send_bundled_chunks(&smctrl->addr_my_init_chunk_sent_to);
                    free_simple_chunk(init_ack_cid);
                    EVENTLOG(INTERNAL_EVENT,
                            "event: initAck sent at state of ShutdownSent");
                }
                break;
            case ChannelState::ShutdownAckSent:
                /* RFC 4960 (section 9.2 starting from line 6146)
                 We are supposed to discard the Init, and retransmit SHUTDOWN_ACK
                 If an endpoint is in the SHUTDOWN-ACK-SENT state and receives an INIT
                 chunk (e.g., if the SHUTDOWN COMPLETE was lost) with source and
                 destination transport addresses (either in the IP addresses or in the
                 INIT chunk) that belong to this association, it should discard the
                 INIT chunk and retransmit the SHUTDOWN ACK chunk.

                 Note: Receipt of an INIT with the same source and destination IP
                 addresses as used in transport addresses assigned to an endpoint but
                 with a different port number indicates the initialization of a
                 separate association.*/
                uint shutdownackcid = alloc_simple_chunk(CHUNK_SHUTDOWN_ACK,
                FLAG_NONE);
                /*send all bundled chunks to ensure init ack is the only chunk sent*/
                unlock_bundle_ctrl();
                send_bundled_chunks();
                bundle_ctrl_chunk(complete_simple_chunk(shutdownackcid));
                send_bundled_chunks(); //send init ack
                free_simple_chunk(shutdownackcid);
                EVENTLOG(INTERNAL_EVENT,
                        "event: initAck sent at state of ShutdownAckSent");
                break;
        }
    }

    /*6) remove NOT free INIT CHUNK*/
    remove_simple_chunk(init_cid);
    return ret;
}
int dispatch_layer_t::process_unknown_params_from_init_chunk(uint initCID,
        uint AckCID, uint supportedAddressTypes)
{
    if (simple_chunks_[initCID] == NULL || simple_chunks_[AckCID] == NULL)
    {
        ERRLOG(FALTAL_ERROR_EXIT, "write_cookie()::Invalid chunk ID");
        return -1;
    }
    //    /* scan init chunk for unrecognized parameters ! */
    //    bool with_ipv4 = false, with_ipv6 = false;
    //    supportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV4 ?
    //            with_ipv4 = true : with_ipv4 = false;
    //    supportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV6 ?
    //            with_ipv6 = true : with_ipv6 = false;
    //    EVENTLOG3(VERBOSE,
    //            "Scan initk for Errors -- supported types = %u, IPv4: %s, IPv6: %s",
    //            supportedAddressTypes, with_ipv4 ? "TRUE" : "FALSE",
    //            with_ipv6 ? "TRUE" : "FALSE");

    init_chunk_t* chunk = ((init_chunk_t*) simple_chunks_[initCID]);
    uchar* curr_vlp_start = chunk->variableParams;
    uint total_len_vlps = chunk->chunk_header.chunk_length
            - INIT_CHUNK_FIXED_SIZES;
    chunk = ((init_chunk_t*) simple_chunks_[AckCID]);

    uint read_len = 0;
    ushort pType;
    ushort pLen;
    ushort padding_len;
    vlparam_fixed_t* vlparam_fixed;
    uchar* init_ack_str;

    while (read_len < total_len_vlps)
    {
        if (total_len_vlps - read_len < VLPARAM_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
                    "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            return -1;
        }
        init_ack_str = chunk->variableParams + curr_write_pos_[AckCID];
        vlparam_fixed = (vlparam_fixed_t*) curr_vlp_start;
        pType = ntohs(vlparam_fixed->param_type);
        pLen = ntohs(vlparam_fixed->param_length);
        // vlp length too short or patial vlp problem
        if (pLen < VLPARAM_FIXED_SIZE || pLen + read_len > total_len_vlps)
            return -1;

        EVENTLOG3(VERBOSE,
                "Scan variable parameters: type %u, len: %u, position %u",
                pType, pLen, curr_vlp_start);

        /* handle unrecognized params */
        if (pType != VLPARAM_COOKIE_PRESEREASONV
                && pType != VLPARAM_SUPPORTED_ADDR_TYPES
                && pType != VLPARAM_IPV4_ADDRESS
                && pType != VLPARAM_IPV6_ADDRESS
                && pType != VLPARAM_UNRELIABILITY)
        {
            EVENTLOG2(VERBOSE,
                    "found unknown parameter type %u len %u in message", pType,
                    pLen);
            if (STOP_PROCESS_PARAM(pType))
            {
                write_unknown_param_error(init_ack_str, AckCID, pLen,
                        curr_vlp_start);
                return STOP_PROCESS_PARAM;
            }
            if (STOP_PROCES_PARAM_REPORT_EREASON(pType))
            {
                write_unknown_param_error(init_ack_str, AckCID, pLen,
                        curr_vlp_start);
                return STOP_PROCES_PARAM_REPORT_EREASON;
            }
            if (SKIP_PARAM_REPORT_EREASON(pType))
            {
                write_unknown_param_error(init_ack_str, AckCID, pLen,
                        curr_vlp_start);
            }
            // if(STOP_PARAM_REPORT_EREASON){} DO NOTHING FOR THIS BRANCH
        }

        read_len += pLen;
        padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
        read_len += padding_len;
        curr_vlp_start += read_len;
    }
    return 0;
}
int dispatch_layer_t::write_cookie(uint initCID, uint initAckID,
        init_chunk_fixed_t* peer_init, init_chunk_fixed_t* local_initack,
        uint cookieLifetime, uint local_tie_tag, uint peer_tie_tag,
        ushort last_dest_port, ushort last_src_port,
        sockaddrunion local_Addresses[], uint num_local_Addresses,
        sockaddrunion peer_Addresses[], uint num_peer_Addresses)
{
    /*                         5.1.3.  Generating State Cookie
     When sending an INIT ACK as a response to an INIT chunk, the sender
     of INIT ACK creates a State Cookie and sends it in the State Cookie
     parameter of the INIT ACK.  Inside this State Cookie, the sender
     should include a MAC (see [RFC2104] for an example), a timestamp on
     when the State Cookie is created, and the lifespan of the State
     Cookie, along with all the information necessary for it to establish
     the association.

     The following steps SHOULD be taken to generate the State Cookie:
     1)  Create an association TCB using information from both the
     received INIT and the outgoing INIT ACK chunk,
     2)  In the TCB, set the creation time to the current time of day, and
     the lifespan to the protocol parameter 'Valid.Cookie.Life' (see
     Section 15),
     3)  From the TCB, identify and collect the minimal subset of
     information needed to re-create the TCB, and generate a MAC using
     this subset of information and a secret key (see [RFC2104] for an
     example of generating a MAC), and
     4)  Generate the State Cookie by combining this subset of information
     and the resultant MAC.*/
    init_chunk_t* initack = (init_chunk_t*) (simple_chunks_[initAckID]);
    if (initack == NULL)
    {
        ERRLOG(FALTAL_ERROR_EXIT, "write_cookie()::Invalid chunk ID");
        return -1;
    }
    if (initack->chunk_header.chunk_id != CHUNK_INIT_ACK)
    {
        ERRLOG(FALTAL_ERROR_EXIT, "write_cookie()::chunk type not initAck");
        return -1;
    }
    if (completed_chunks_[initAckID])
    {
        ERRLOG(FALTAL_ERROR_EXIT, "write_cookie()::Invalid chunk ID");
        return -1;
    }

    cookie_param_t* cookie = (cookie_param_t*) (initack->variableParams
            + curr_write_pos_[initAckID]);
    cookie->vlparam_header.param_type = htons(VLPARAM_COOKIE);
    cookie->ck.local_initack = *local_initack;
    cookie->ck.peer_init = *peer_init;
    cookie->ck.local_tie_tag = htonl(local_tie_tag);
    cookie->ck.peer_tie_tag = htonl(peer_tie_tag);
    cookie->ck.src_port = last_src_port;
    cookie->ck.dest_port = last_dest_port;

    uint count;
    uint no_local_ipv4_addresses = 0;
    uint no_remote_ipv4_addresses = 0;
    uint no_local_ipv6_addresses = 0;
    uint no_remote_ipv6_addresses = 0;
    for (count = 0; count < num_local_Addresses; count++)
    {
        switch (saddr_family(&(local_Addresses[count])))
        {
            case AF_INET:
                no_local_ipv4_addresses++;
                break;
            case AF_INET6:
                no_local_ipv6_addresses++;
                break;
            default:
                ERRLOG(FALTAL_ERROR_EXIT, "write_cookie: Address Type Error !");
                break;
        }
    }
    for (count = 0; count < num_peer_Addresses; count++)
    {
        switch (saddr_family(&(peer_Addresses[count])))
        {
            case AF_INET:
                no_remote_ipv4_addresses++;
                break;
            case AF_INET6:
                no_remote_ipv6_addresses++;
                break;
            default:
                ERRLOG(FALTAL_ERROR_EXIT, "write_cookie: Address Type Error !");
                break;
        }
    }

    cookie->ck.no_local_ipv4_addresses = htons(no_local_ipv4_addresses);
    cookie->ck.no_remote_ipv4_addresses = htons(no_remote_ipv4_addresses);
    cookie->ck.no_local_ipv6_addresses = htons(no_local_ipv6_addresses);
    cookie->ck.no_remote_ipv6_addresses = htons(no_remote_ipv6_addresses);
    uint wr = curr_write_pos_[initAckID];
    curr_write_pos_[initAckID] += COOKIE_PARAM_SIZE;

    EVENTLOG2(VERBOSE, "Building Cookie with %u local, %u peer addresses",
            num_local_Addresses, num_peer_Addresses);
    write_addrlist(initAckID, local_Addresses, num_local_Addresses);
    write_addrlist(initAckID, peer_Addresses, num_peer_Addresses);

    /* append peer unre to init ack will align internally */
    int peer_support_unre = write_vlp_unreliability(initCID, initAckID);

    /* check if endpoint is ADD-IP capable, store result, and put HIS chunk in cookie */
    if (write_add_ip_chunk(initAckID, initCID) > 0)
    { //todo impl these two enpty fucntions
        /* check for set primary chunk ? Maybe add this only after Cookie Chunk ! */
        write_set_primary_chunk(initAckID, initCID);
    }

    /* total length of cookie including vlp fixed, cookie fixed except of hmac*/
    cookie->vlparam_header.param_length = htons(
            curr_write_pos_[initAckID] - wr);

    /* hmac */
    cookie->ck.sendingTime = get_safe_time_ms();
    cookie->ck.cookieLifetime = cookieLifetime;
    cookie->ck.hmac[0] = 0;
    cookie->ck.hmac[1] = 0;
    cookie->ck.hmac[2] = 0;
    cookie->ck.hmac[3] = 0;
    write_hmac(cookie);

    /* cookie params is all filledup and now let us align it to 4
     * by default cookie SHOULD be self-aligned as all internal variables are
     * 4 bytes aligned, here we just double check that
     * the rest of ecn and unre will have a aligned start writing pos
     * they may need do align internally */
    while ((curr_write_pos_[initAckID] % 4) != 0)
        curr_write_pos_[initAckID]++;

    write_ecn_chunk(initAckID, initCID);

    /* if both support PRSCTP, enter our PRSCTP parameter to INIT ACK chunk */
    if ((peer_support_unre >= 0) && support_unreliability())
    {
        /* this is variable-length-data, this fuction will internally do alignment */
        write_vlp_to_init_chunk(initAckID, VLPARAM_UNRELIABILITY, 0, NULL);
    }

    return 0;
}

ushort dispatch_layer_t::get_local_inbound_stream(uint* geco_inst_id)
{
    if (curr_channel_ != NULL)
    {
        return curr_channel_->geco_inst->noOfInStreams;
    }
    else if (curr_geco_instance_ != NULL)
    {
        return curr_geco_instance_->noOfInStreams;
    }
    else
    {
        if (geco_inst_id != NULL)
        {
            curr_geco_instance_ = find_geco_instance_by_id(*geco_inst_id);
            if (curr_geco_instance_ != NULL)
            {
                uint ins = curr_geco_instance_->noOfInStreams;
                curr_geco_instance_ = NULL;
                return ins;
            }
        }

    }
    return 0;
}
ushort dispatch_layer_t::get_local_outbound_stream(uint* geco_inst_id)
{
    if (curr_channel_ != NULL)
    {
        return curr_channel_->geco_inst->noOfOutStreams;
    }
    else if (curr_geco_instance_ != NULL)
    {
        return curr_geco_instance_->noOfOutStreams;
    }
    else
    {
        if (geco_inst_id != NULL)
        {
            curr_geco_instance_ = find_geco_instance_by_id(*geco_inst_id);
            if (curr_geco_instance_ != NULL)
            {
                uint ins = curr_geco_instance_->noOfOutStreams;
                curr_geco_instance_ = NULL;
                return ins;
            }
        }

    }
    return 0;
}

uint dispatch_layer_t::get_local_addreslist(sockaddrunion* local_addrlist,
        sockaddrunion *peerAddress, uint numPeerAddresses, uint addressTypes,
        bool receivedFromPeer)
{
    /*1) make sure either curr channel or curr geco instance presents */
    if (curr_channel_ == NULL && curr_geco_instance_ == NULL)
    {
        ERRLOG(FALTAL_ERROR_EXIT,
                "dispatch_layer_t::get_local_addreslist()::neither assoc nor instance set - error !");
        return 0;
    }
    if (curr_geco_instance_ == NULL)
    {
        ERRLOG(MAJOR_ERROR,
                "get_local_addreslist():: curr_geco_instance_ not set - program error");
        curr_geco_instance_ = curr_channel_->geco_inst;
    }

    /* 2) Determine address type of peer addres
     * localHostFound == false:
     * localhost not found means we are NOT sending msg to ourselves
     * this is from a normal address, so we need filter out except loopback
     * and cast addres
     * localHostFound == true:
     * localhost Found means we are sending msg to ourselves
     * peer addr is actually our local address, so we need filter out
     * all illegal addres */
    uint count, tmp;
    IPAddrType filterFlags = (IPAddrType) 0;
    bool localHostFound = false, linkLocalFound = false, siteLocalFound = false;
    for (count = 0; count < numPeerAddresses; count++)
    {
        localHostFound = contains_local_host_addr(peerAddress + count, 1);
        linkLocalFound = transport_layer_->typeofaddr(peerAddress + count,
                LinkLocalAddrType);
        siteLocalFound = transport_layer_->typeofaddr(peerAddress + count,
                SiteLocalAddrType);
    }

    /* 3) Should we add @param peerAddress to @param local_addrlist ?
     * receivedFromPeer == FALSE:
     * I send an INIT with my addresses to the peer
     * receivedFromPeer == TRUE:
     * I got an INIT with addresses from the peer */
    if (receivedFromPeer == false && localHostFound == true)
    {
        /* 3.1) this means:
         * I sent an INIT with my addresses to myself
         * should filter out all illgal addres from geco instance's local addr list
         * and then addall legal ones to @param local_addrlist of my own. */
        filterFlags = AllCastAddrTypes;
    }
    else if (receivedFromPeer == false && localHostFound == false)
    {
        /* 3.2) this means:
         * I sent an INIT with my addresses to other hosts
         * however, this 'other hosts' MAY also include myself
         * in the case that:
         * I use my loop back local host of 127.0.0.1 to initilize geco instance,
         * then I send INIT with my loop back local host of 127.0.0.1 to myself,
         * but this addr is automatically put and changed to ethernet addr
         * 192.168.1.107 if I am in LAN or public addr 222.12,123 if i am in LAN
         * (both are my local addr) by IP layer.
         *
         * at this moment, the received peer addr is 192.168.1.107 or  222.12,123
         * when contains_local_host_addr() called,
         * it CANNOT match peer addr of 192.168.1.107 or or  222.12,123.
         * So localHostFound will be set to FASLE, but actually I am sending to myself.
         *
         * Action to take for such case is that:
         * when we send msg to a loopback addr (127.0.0.1) in the case above,
         * should filter out 127.0.0.1 from geco instance's local addr list
         * and then add all other legal ones to @param local_addrlist of my own. */
        filterFlags = (IPAddrType) (AllCastAddrTypes | LoopBackAddrType);
    }
    else if (receivedFromPeer == true && localHostFound == false)
    {
        /* 3.3) this means:
         * I received an INIT with addresses from others which is a normal case.
         * should filter out all illgal addres from geco instance's local addr list
         * and then addall legal ones to @param local_addrlist of my own. */
        if (linkLocalFound)
        {
            filterFlags = (IPAddrType) (AllCastAddrTypes | LoopBackAddrType);
        }
        else if (siteLocalFound)
        {
            filterFlags = (IPAddrType) (AllCastAddrTypes | LinkLocalAddrType
                    | LoopBackAddrType);
        }
        else
        {
            filterFlags = (IPAddrType) (AllCastAddrTypes | AllLocalAddrTypes);
        }
    }
    else // (receivedFromPeer == true && localHostFound == true)
    {
        /* 3.4) this means:
         * I received an INIT with addresses from myself
         * should filter out all illgal addres from geco instance's local addr list
         * and then add all legal ones to @param local_addrlist of my own. */
        filterFlags = AllCastAddrTypes;
    }

    /*4) filter local addres and copy them to @param local_addrlist of my own*/
    count = 0;
    uint af;
    if (curr_geco_instance_->is_inaddr_any)
    {
        /* 4.1) geco instance has any addr 4 setup,
         * we use @param defaultlocaladdrlist_*/
        for (tmp = 0; tmp < defaultlocaladdrlistsize_; tmp++)
        {
            if (saddr_family(&(defaultlocaladdrlist_[tmp])) == AF_INET)
            {
                if (addressTypes & SUPPORT_ADDRESS_TYPE_IPV4)
                {
                    if (!transport_layer_->typeofaddr(
                            &(defaultlocaladdrlist_[tmp]), filterFlags))
                    {
                        // addr looks good copy it
                        memcpy(&(local_addrlist[count]),
                                &(defaultlocaladdrlist_[tmp]),
                                sizeof(sockaddrunion));
                        count++;
                    }
                }
            }
            else
            {
                EVENTLOG(WARNNING_ERROR,
                        "get_local_addreslist(): no such af !");
            }
        }
        EVENTLOG2(VERBOSE,
                "get_local_addreslist(): found %u local addresses from INADDR_ANY (from %u)",
                count, defaultlocaladdrlistsize_);
    }
    else if (curr_geco_instance_->is_in6addr_any)
    {
        /* 4.2) geco instance has any addr 6 setup,
         * we use @param defaultlocaladdrlist_*/
        for (tmp = 0; tmp < defaultlocaladdrlistsize_; tmp++)
        {
            af = saddr_family(&(defaultlocaladdrlist_[tmp]));
            if (af == AF_INET)
            {
                if (addressTypes & SUPPORT_ADDRESS_TYPE_IPV4)
                {
                    if (!transport_layer_->typeofaddr(
                            &(defaultlocaladdrlist_[tmp]), filterFlags))
                    {
                        // addr looks good copy it
                        memcpy(&(local_addrlist[count]),
                                &(defaultlocaladdrlist_[tmp]),
                                sizeof(sockaddrunion));
                        count++;
                    }
                }
            }
            else if (af == AF_INET6)
            {
                if (addressTypes & SUPPORT_ADDRESS_TYPE_IPV6)
                {
                    if (!transport_layer_->typeofaddr(
                            &(defaultlocaladdrlist_[tmp]), filterFlags))
                    {
                        // addr looks good copy it
                        memcpy(&(local_addrlist[count]),
                                &(defaultlocaladdrlist_[tmp]),
                                sizeof(sockaddrunion));
                        count++;
                    }
                }
            }
            else
            {
                EVENTLOG(WARNNING_ERROR,
                        "get_local_addreslist(): no such af !");
            }
        }
        EVENTLOG2(VERBOSE,
                "get_local_addreslist(): found %u local addresses from INADDR_6ANY (from %u)",
                count, defaultlocaladdrlistsize_);
    }
    else
    {
        /* 4.3) geco instance has NO any addr (6) setup,
         * search from local addr list of geco instance*/
        for (tmp = 0; tmp < curr_geco_instance_->local_addres_size; tmp++)
        {
            af = saddr_family(&(curr_geco_instance_->local_addres_list[tmp]));
            if (af == AF_INET)
            {
                if (addressTypes & SUPPORT_ADDRESS_TYPE_IPV4)
                {
                    if (!transport_layer_->typeofaddr(
                            &(defaultlocaladdrlist_[tmp]), filterFlags))
                    {
                        // addr looks good copy it
                        memcpy(&(local_addrlist[count]),
                                &(curr_geco_instance_->local_addres_list[tmp]),
                                sizeof(sockaddrunion));
                        count++;
                    }
                }
            }
            else if (af == AF_INET6)
            {
                if (addressTypes & SUPPORT_ADDRESS_TYPE_IPV6)
                {
                    if (!transport_layer_->typeofaddr(
                            &(curr_geco_instance_->local_addres_list[tmp]),
                            filterFlags))
                    {
                        // addr looks good copy it
                        memcpy(&(local_addrlist[count]),
                                &(curr_geco_instance_->local_addres_list[tmp]),
                                sizeof(sockaddrunion));
                        count++;
                    }
                }
            }
            else
            {
                EVENTLOG(WARNNING_ERROR,
                        "get_local_addreslist(): no such af !");
            }
        }
        EVENTLOG2(VERBOSE,
                "get_local_addreslist(): found %u local addresses from INADDR_6ANY (from %u)",
                count, defaultlocaladdrlistsize_);
    }

    EVENTLOG1(INTERNAL_TRACE,
            "get_local_addreslist() : returning %u addresses !", count);
    if (count == 0)
        EVENTLOG(FALTAL_ERROR_EXIT, "get_local_addreslist(): found no addres!");
    return count;
}

void dispatch_layer_t::delete_curr_channel(void)
{
    uint path_id;
    if (curr_channel_ != NULL)
    {
        for (path_id = 0; path_id < curr_channel_->remote_addres_size;
                path_id++)
        {
            stop_heart_beat_timer(path_id);
        }
        // fc_stop_timers();         // TODO
        stop_sack_timer();

        /* mark channel as deleted, it will be deleted
         when get_channel(..) encounters a "deleted" channel*/
        curr_channel_->deleted = true;
        EVENTLOG1(INTERNAL_EVENT, "channel ID %u marked for deletion",
                curr_channel_->channel_id);
    }
}
void dispatch_layer_t::on_connection_lost(uint status)
{
    geco_instance_t* old_ginst = curr_geco_instance_;
    channel_t* old_channel = curr_channel_;
    if (curr_channel_ != NULL)
    {
        EVENTLOG2(INTERNAL_TRACE, "on_connection_lost(assoc %u, status %u)",
                curr_channel_->channel_id, status);
        if (curr_geco_instance_->applicaton_layer_cbs.communicationLostNotif
                != NULL)
        {
            ENTER_CALLBACK("communicationLostNotif");
            curr_geco_instance_->applicaton_layer_cbs.communicationLostNotif(
                    curr_channel_->channel_id, status,
                    curr_channel_->application_layer_dataptr);
            LEAVE_CALLBACK("communicationLostNotif");
        }
    }
    curr_geco_instance_ = old_ginst;
    curr_channel_ = old_channel;
}
int dispatch_layer_t::process_init_ack_chunk(init_chunk_t * initAck)
{
    return 0;
}
int dispatch_layer_t::process_sack_chunk(uint adr_index, void *sack_chunk,
        uint totalLen)
{
    return 0;
}
uchar* dispatch_layer_t::find_vlparam_from_setup_chunk(uchar * setup_chunk,
        uint chunk_len, ushort param_type)
{
    /*1) validate packet length*/
    uint read_len = CHUNK_FIXED_SIZE + INIT_CHUNK_FIXED_SIZE;
    if (chunk_len < read_len)
    {
        EVENTLOG2(WARNNING_ERROR,
                "chunk_len(%u) < CHUNK_FIXED_SIZE( %u bytes) return NULL !\n",
                chunk_len, read_len);
        return NULL;
    }

    /*2) validate chunk id inside this chunk*/
    init_chunk_t* init_chunk = (init_chunk_t*) setup_chunk;
    if (init_chunk->chunk_header.chunk_id != CHUNK_INIT
            && init_chunk->chunk_header.chunk_id != CHUNK_INIT_ACK)
    {
        return NULL;
    }

    uint len = ntohs(init_chunk->chunk_header.chunk_length);
    uchar* curr_pos = init_chunk->variableParams;

    ushort vlp_len;
    uint padding_len;
    vlparam_fixed_t* vlp;

    /*3) parse all vlparams in this chunk*/
    while (read_len < len)
    {
        EVENTLOG2(VERBOSE,
                "find_params_from_setup_chunk() : len==%u, processed_len == %u",
                len, read_len);

        if (len - read_len < VLPARAM_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
                    "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            return NULL;
        }

        vlp = (vlparam_fixed_t*) curr_pos;
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

int dispatch_layer_t::send_geco_packet(char* geco_packet, uint length,
        short destAddressIndex)
{
    if (geco_packet == NULL)
    {
        ERRLOG(MINOR_ERROR,
                "dispatch_layer::send_geco_packet(): no message to send !!!");
        return 1;
    }

    geco_packet_t* geco_packet_ptr = ((geco_packet_t*) geco_packet);
    simple_chunk_t* chunk = ((simple_chunk_t*) (geco_packet_ptr->chunk));

    /*1)
     * when sending OOB chunk without channel found, we use last_source_addr_
     * carried in OOB packet as the sending dest addr
     * see recv_geco_packet() for details*/
    sockaddrunion dest_addr;
    sockaddrunion* dest_addr_ptr;
    uchar tos;
    int primary_path;
    int len = 0;

    if (curr_channel_ == NULL)
    {
        if (last_source_addr_ == NULL || last_init_tag_ == 0
                || last_dest_port_ == 0 || last_src_port_ == 0)
        {
            ERRLOG(MAJOR_ERROR,
                    "dispatch_layer_t::send_geco_packet(): invalid params !");
            return 1;
        }

        memcpy(&dest_addr, last_source_addr_, sizeof(sockaddrunion));
        dest_addr_ptr = &dest_addr;
        geco_packet_ptr->pk_comm_hdr.verification_tag = htonl(last_init_tag_);
        last_init_tag_ = 0; //reset it
        // swap port number
        geco_packet_ptr->pk_comm_hdr.src_port = htons(last_dest_port_);
        geco_packet_ptr->pk_comm_hdr.dest_port = htons(last_src_port_);
        curr_geco_instance_ == NULL ?
                tos = (uchar) IPTOS_DEFAULT :
                tos = curr_geco_instance_->default_ipTos;
        EVENTLOG4(VERBOSE,
                "dispatch_layer_t::send_geco_packet() : tos = %u, tag = %x, src_port = %u , dest_port = %u",
                tos, last_init_tag_, last_dest_port_, last_src_port_);
    } // curr_channel_ == NULL
    else // curr_channel_ != NULL
    {
        /*2) normal send with channel found*/
        if (destAddressIndex < -1
                || destAddressIndex >= curr_channel_->remote_addres_size)
        {
            ERRLOG(MINOR_ERROR,
                    "dispatch_layer::send_geco_packet(): invalid destAddressIndex!!!");
            return 1;
        }

        if (destAddressIndex != -1) // 0<=destAddressIndex<remote_addres_size
        {
            /* 3) Use given destination address from current association */
            dest_addr_ptr = curr_channel_->remote_addres + destAddressIndex;
        }
        else
        {
            /*4) use last src addr*/
            if (last_source_addr_ == NULL)
            {
                /*5) last src addr is NUll, we use primary path*/
                primary_path = get_primary_path();
                EVENTLOG2(VERBOSE,
                        "dispatch_layer::send_geco_packet():sending to primary with index %u (with %u paths)",
                        primary_path, curr_channel_->remote_addres_size);
                if (primary_path < 0
                        || primary_path
                                >= (int) (curr_channel_->remote_addres_size))
                {
                    ERRLOG(MAJOR_ERROR,
                            "dispatch_layer::send_geco_packet(): could not get primary address");
                    return 1;
                }
                dest_addr_ptr = curr_channel_->remote_addres + primary_path;
            }
            else
            {
                /*6) use last src addr*/
                EVENTLOG(VERBOSE,
                        "dispatch_layer::send_geco_packet(): : last_source_addr_ was not NULL");
                memcpy(&dest_addr, last_source_addr_, sizeof(sockaddrunion));
                dest_addr_ptr = &dest_addr;

            }
        }

        /*7) for INIT received when channel presents,
         * we need send INIT-ACK with init tag from INIT of peer*/
        if (is_init_ack_chunk(chunk))
        {
            if (last_init_tag_ == 0)
            {
                ERRLOG(MAJOR_ERROR,
                        "dispatch_layer_t::send_geco_packet(): invalid last_init_tag_ 0 !");
                return 1;
            }
            geco_packet_ptr->pk_comm_hdr.verification_tag = htonl(
                    last_init_tag_);
        }
        /*8) use normal tag stored in curr channel*/
        else
        {
            geco_packet_ptr->pk_comm_hdr.verification_tag = htonl(
                    curr_channel_->remote_tag);
        }

        geco_packet_ptr->pk_comm_hdr.src_port = htons(
                curr_channel_->local_port);
        geco_packet_ptr->pk_comm_hdr.dest_port = htons(
                curr_channel_->remote_port);
        tos = curr_channel_->ipTos;
        EVENTLOG4(VERBOSE,
                "dispatch_layer_t::send_geco_packet() : tos = %u, tag = %x, src_port = %u , dest_port = %u",
                tos, curr_channel_->remote_tag, curr_channel_->local_port,
                curr_channel_->remote_port);
    } // curr_channel_ != NULL

    /*9) calc checksum and insert it TODO - use MD5*/
    set_crc32_checksum((geco_packet + UDP_PACKET_FIXED_SIZE),
            length - UDP_PACKET_FIXED_SIZE);

    switch (saddr_family(dest_addr_ptr))
    {
        case AF_INET:
            len = transport_layer_->send_ip_packet(
                    transport_layer_->ip4_socket_despt_, geco_packet, length,
                    dest_addr_ptr, tos);
            break;
        case AF_INET6:
            len = transport_layer_->send_ip_packet(
                    transport_layer_->ip6_socket_despt_, geco_packet, length,
                    dest_addr_ptr, tos);
            break;
        default:
            ERRLOG(MAJOR_ERROR,
                    "dispatch_layer_t::send_geco_packet() : Unsupported AF_TYPE");
            break;
    }

#ifdef _DEBUG
    saddr2str(dest_addr_ptr, hoststr_, MAX_IPADDR_STR_LEN, NULL);
    EVENTLOG4(INTERNAL_TRACE,
            "sent geco packet of %d bytes to %s:%u, sent bytes %d", length,
            hoststr_, geco_packet_ptr->pk_comm_hdr.dest_port, len);
#endif

    return (len == (int) length) ? 0 : -1;
}

int dispatch_layer_t::send_bundled_chunks(int * ad_idx /*= NULL*/)
{
    bundle_controller_t* bundle_ctrl =
            (bundle_controller_t*) get_bundle_controller(curr_channel_);

    // no channel exists, so we take the global bundling buffer
    if (bundle_ctrl == NULL)
    {
        EVENTLOG(VERBOSE, "Copying Control Chunk to global bundling buffer ");
        bundle_ctrl = &default_bundle_ctrl_;
    }

    if (bundle_ctrl->locked)
    {
        bundle_ctrl->got_send_request = true;
        if (ad_idx != NULL)
        {
            bundle_ctrl->got_send_address = true;
            bundle_ctrl->requested_destination = *ad_idx;
        }
        EVENTLOG(VERBOSE,
                "send_bundled_chunks ()::sender is LOCKED ---> returning");
        return 1;
    }

    /* determine  path_param_id to use as dest addr
     * TODO - more intelligent path selection strategy
     * should take into account  eg. check path inactive or active */
    int path_param_id;
    if (ad_idx != NULL)
    {
        if (*ad_idx > 0xFFFF)
        {
            ERRLOG(FALTAL_ERROR_EXIT, "address_index too big !");
            return -1;
        }
        else
        {
            path_param_id = *ad_idx;
        }
    }
    else
    {
        if (bundle_ctrl->got_send_address)
        {
            path_param_id = bundle_ctrl->requested_destination;
        }
        else
        {
            path_param_id = -1; // use last src path OR primary path
        }
    }
    EVENTLOG1(VERBOSE, "send_bundled_chunks : send to path %d ", path_param_id);

    /* try to bundle ctrl or/and sack chunks with data chunks in an packet*/
    char* send_buffer = NULL;
    int ret, send_len = 0;
    if (bundle_ctrl->sack_in_buffer)
    {
        stop_sack_timer();

        /* send sacks, by default they go to the last active address,
         * from which data arrived*/
        send_buffer = bundle_ctrl->sack_buf;

        // at least sizeof(geco_packet_fixed_t)
        // at most pointing to the end of SACK chunk
        send_len = bundle_ctrl->sack_position;
        EVENTLOG1(VERBOSE, "send_bundled_chunks(sack) : send_len == %d ",
                send_len);

        if (bundle_ctrl->ctrl_chunk_in_buffer)
        {
            ret = bundle_ctrl->ctrl_position - UDP_GECO_PACKET_FIXED_SIZES;
            memcpy(&(send_buffer[send_len]),
                    &(bundle_ctrl->ctrl_buf[UDP_GECO_PACKET_FIXED_SIZES]), ret);
            send_len += ret;
            EVENTLOG1(VERBOSE,
                    "send_bundled_chunks(sack+ctrl) : send_len == %d ",
                    send_len);
        }
        if (bundle_ctrl->data_in_buffer)
        {
            ret = bundle_ctrl->data_position - UDP_GECO_PACKET_FIXED_SIZES;
            memcpy(&(send_buffer[send_len]),
                    &(bundle_ctrl->data_buf[UDP_GECO_PACKET_FIXED_SIZES]), ret);
            send_len += ret;
            EVENTLOG1(VERBOSE,
                    ret == 0 ?
                            "send_bundled_chunks(sack+data) : send_len == %d " :
                            "send_bundled_chunks(sack+ctrl+data) : send_len == %d ",
                    send_len);
        }
    }
    else if (bundle_ctrl->ctrl_chunk_in_buffer)
    {
        send_buffer = bundle_ctrl->ctrl_buf;
        send_len = bundle_ctrl->ctrl_position;
        EVENTLOG1(VERBOSE, "send_bundled_chunks(ctrl) : send_len == %d ",
                send_len);
        if (bundle_ctrl->data_in_buffer)
        {
            ret = bundle_ctrl->data_position - UDP_GECO_PACKET_FIXED_SIZES;
            memcpy(&send_buffer[send_len],
                    &(bundle_ctrl->data_buf[UDP_GECO_PACKET_FIXED_SIZES]), ret);
            send_len += ret;
            EVENTLOG1(VERBOSE,
                    "send_bundled_chunks(ctrl+data) : send_len == %d ",
                    send_len);
        }
    }
    else if (bundle_ctrl->data_in_buffer)
    {
        send_buffer = bundle_ctrl->data_buf;
        send_len = bundle_ctrl->data_position;
        EVENTLOG1(VERBOSE, "send_bundled_chunks(data) : send_len == %d ",
                send_len);
    }
    else
    {
        ERRLOG(MINOR_ERROR,
                "Nothing to send, but send_bundled_chunks() was called !");
        return 1;
    }
    EVENTLOG1(VERBOSE, "send_bundled_chunks(finally) : send_len == %d ",
            send_len);

    /*this should not happen as bundle_xxx_chunk() internally detects
     * if exceeds MAX_GECO_PACKET_SIZE, if so, it will call */
    if (send_len > MAX_GECO_PACKET_SIZE)
    {
        EVENTLOG5(FALTAL_ERROR_EXIT,
                "send len (%u)  exceeded (%u) - aborting\nsack_position: %u, ctrl_position: %u, data_position: %u",
                send_len, MAX_GECO_PACKET_SIZE, bundle_ctrl->sack_position,
                bundle_ctrl->ctrl_position, bundle_ctrl->data_position);
        return -1;
    }

    if (bundle_ctrl->data_in_buffer && path_param_id > 0)
    {
        set_data_chunk_sent_flag(path_param_id);
    }

    EVENTLOG2(VERBOSE,
            "send_bundled_chunks() : sending message len==%u to adress idx=%d",
            send_len, path_param_id);

    // send_len = udp hdr (if presents) + geco hdr + chunks
    ret = this->send_geco_packet(send_buffer, send_len, path_param_id);

    /* reset all positions */
    bundle_ctrl->sack_in_buffer = false;
    bundle_ctrl->ctrl_chunk_in_buffer = false;
    bundle_ctrl->data_in_buffer = false;
    bundle_ctrl->got_send_request = false;
    bundle_ctrl->got_send_address = false;
    bundle_ctrl->data_position = UDP_GECO_PACKET_FIXED_SIZES;
    bundle_ctrl->ctrl_position = UDP_GECO_PACKET_FIXED_SIZES;
    bundle_ctrl->sack_position = UDP_GECO_PACKET_FIXED_SIZES;
    return ret;
}

int dispatch_layer_t::bundle_ctrl_chunk(simple_chunk_t * chunk,
        int * dest_index /*= NULL*/)
{

    bundle_controller_t* bundle_ctrl =
            (bundle_controller_t*) get_bundle_controller(curr_channel_);

    /*1) no channel exists, so we take the global bundling buffer */
    if (bundle_ctrl == NULL)
    {
        EVENTLOG(VERBOSE, "Copying Control Chunk to global bundling buffer ");
        bundle_ctrl = &default_bundle_ctrl_;
    }

    ushort chunk_len = get_chunk_length((chunk_fixed_t* )chunk);
    if (get_bundle_total_size(bundle_ctrl) + chunk_len >= MAX_GECO_PACKET_SIZE)
    {
        /*2) an packet CANNOT hold all data, we send chunks and get bundle empty*/
        EVENTLOG1(VERBOSE,
                "Chunk Length exceeded MAX_NETWORK_PACKET_VALUE_SIZE : sending chunk to address %u !",
                (dest_index == NULL) ? 0 : *dest_index);

        bundle_ctrl->locked = false;/* unlock to allow send bundle*/
        send_bundled_chunks(dest_index);
        bundle_ctrl->locked = true; /* lock it again to disable the next send*/
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
    if (chunk_len < 4)
    {
        memset(&(bundle_ctrl->ctrl_buf[bundle_ctrl->ctrl_position]), 0,
                chunk_len);
        bundle_ctrl->ctrl_position += chunk_len;
    }

    EVENTLOG2(VERBOSE,
            "bundle_ctrl_chunk() : %u , Total buffer size now (includes pad): %u\n",
            get_chunk_length((chunk_fixed_t *)chunk),
            get_bundle_total_size(bundle_ctrl));
    return 0;
}

int dispatch_layer_t::write_addrlist(uint chunkid,
        sockaddrunion local_addreslist[MAX_NUM_ADDRESSES],
        int local_addreslist_size)
{
    if (local_addreslist_size <= 0)
    {
        return 0;
    }

    if (simple_chunks_[chunkid] == NULL)
    {
        ERRLOG(WARNNING_ERROR, "write_addrlist()::Invalid chunk ID");
        return -1;
    }
    if (completed_chunks_[chunkid] == true)
    {
        ERRLOG(WARNNING_ERROR, "write_addrlist()::chunk already completed !");
        return -1;
    }

    ip_address_t* ip_addr;
    int i, length = 0;
    uchar* vlp;

    if (simple_chunks_[chunkid]->chunk_header.chunk_id != CHUNK_ASCONF)
    {
        vlp =
                &((init_chunk_t *) simple_chunks_[chunkid])->variableParams[curr_write_pos_[chunkid]];
    }
    else
    {
        vlp =
                &((asconfig_chunk_t*) simple_chunks_[chunkid])->variableParams[curr_write_pos_[chunkid]];
    }

    for (i = 0; i < local_addreslist_size; i++)
    {
        ip_addr = (ip_address_t*) (vlp + length);
        switch (saddr_family(&(local_addreslist[i])))
        {
            case AF_INET:
                ip_addr->vlparam_header.param_type = htons(
                VLPARAM_IPV4_ADDRESS);
                ip_addr->vlparam_header.param_length = htons(
                        sizeof(struct in_addr) + VLPARAM_FIXED_SIZE);
                ip_addr->dest_addr_un.ipv4_addr = s4addr(
                        &(local_addreslist[i]));
                length += 8;
                break;
            case AF_INET6:
                ip_addr->vlparam_header.param_type = htons(
                VLPARAM_IPV6_ADDRESS);
                ip_addr->vlparam_header.param_length = htons(
                        sizeof(struct in6_addr) + VLPARAM_FIXED_SIZE);
                memcpy(&ip_addr->dest_addr_un.ipv6_addr,
                        &(s6addr(&(local_addreslist[i]))),
                        sizeof(struct in6_addr));
                length += 20;
                break;
            default:
                ERRLOG1(MAJOR_ERROR,
                        "dispatch_layer_t::write_addrlist()::Unsupported Address Family %d",
                        saddr_family(&(local_addreslist[i])));
                break;
        } // switch
    } // for loop
    curr_write_pos_[chunkid] += length; // no need to align because MUST be aliged
    return 0;
}

int dispatch_layer_t::read_peer_addreslist(
        sockaddrunion peer_addreslist[MAX_NUM_ADDRESSES], uchar * chunk,
        uint chunk_len, uint my_supported_addr_types,
        uint* peer_supported_addr_types, bool ignore_dups,
        bool ignore_last_src_addr)
{
    /*1) validate method input params*/
    uint read_len = INIT_CHUNK_FIXED_SIZES;
    if (chunk == NULL || peer_addreslist == NULL || chunk_len < read_len)
    {
        return -1;
    }

    /*2) validate chunk id inside this chunk*/
    init_chunk_t* init_chunk = (init_chunk_t*) chunk;
    if (init_chunk->chunk_header.chunk_id != CHUNK_INIT
            && init_chunk->chunk_header.chunk_id != CHUNK_INIT_ACK)
    {
        return -1;
    }

    uint len = ntohs(init_chunk->chunk_header.chunk_length);
    uchar* curr_pos = chunk + read_len;

    uint vlp_len;
    uint padding_len;
    vlparam_fixed_t* vlp;
    ip_address_t* addres;
    uint found_addr_number = 0;
    bool is_new_addr;
    uint idx;
    IPAddrType flags;

    /*3) parse all vlparams in this chunk*/
    while (read_len < len)
    {
        EVENTLOG2(VERBOSE,
                "read_peer_addreslist() : len==%u, processed_len == %u", len,
                read_len);

        if (len - read_len < VLPARAM_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
                    "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            return -1;
        }

        vlp = (vlparam_fixed_t*) curr_pos;
        vlp_len = ntohs(vlp->param_length);
        // vlp length too short or patial vlp problem
        if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len)
            return -1;

        /*4) validate received addresses in this chunk*/
        switch (ntohs(vlp->param_type))
        {
            case VLPARAM_IPV4_ADDRESS:
                // validate addr type
                if ((my_supported_addr_types & SUPPORT_ADDRESS_TYPE_IPV4))
                {
                    // validate if exceed max num addres allowed
                    if (found_addr_number < MAX_NUM_ADDRESSES)
                    {
                        addres = (ip_address_t*) curr_pos;
                        // validate vlp type and length
                        if (IS_IPV4_ADDRESS_PTR_NBO(addres))
                        {
                            uint ip4_saddr = ntohl(
                                    addres->dest_addr_un.ipv4_addr);
                            // validate addr itself
                            if (!IN_CLASSD(ip4_saddr)
                                    && !IN_EXPERIMENTAL(ip4_saddr)
                                    && !IN_BADCLASS(ip4_saddr)
                                    && INADDR_ANY != ip4_saddr
                                    && INADDR_BROADCAST != ip4_saddr)
                            {
                                peer_addreslist[found_addr_number].sa.sa_family =
                                AF_INET;
                                peer_addreslist[found_addr_number].sin.sin_port =
                                        0;
                                peer_addreslist[found_addr_number].sin.sin_addr.s_addr =
                                        addres->dest_addr_un.ipv4_addr;
                                //current addr duplicated with a previous found addr?
                                is_new_addr = true; // default as new addr
                                if (ignore_dups)
                                {
                                    for (idx = 0; idx < found_addr_number;
                                            idx++)
                                    {
                                        if (saddr_equals(
                                                &peer_addreslist[found_addr_number],
                                                &peer_addreslist[idx]))
                                        {
                                            is_new_addr = false;
                                        }
                                    }
                                }

                                if (is_new_addr)
                                {
                                    found_addr_number++;
                                    if (peer_supported_addr_types != NULL)
                                        (*peer_supported_addr_types) |=
                                        SUPPORT_ADDRESS_TYPE_IPV4;
#ifdef _DEBUG
                                    saddr2str(
                                            &peer_addreslist[found_addr_number
                                                    - 1], hoststr_,
                                            sizeof(hoststr_), 0);
                                    EVENTLOG1(VERBOSE,
                                            "Found NEW IPv4 Address = %s",
                                            hoststr_);
#endif
                                }
                                else
                                {
                                    EVENTLOG(VERBOSE,
                                            "IPv4 was in the INIT or INIT ACK chunk more than once");
                                }
                            }
                        }
                        else // IS_IPV4_ADDRESS_PTR_HBO(addres) == false
                        {
                            ERRLOG(MAJOR_ERROR,
                                    "ip4 vlp has problem, stop read addresses");
                            break;
                        }
                    }
                }
                break;
            case VLPARAM_IPV6_ADDRESS:
                if ((my_supported_addr_types & VLPARAM_IPV6_ADDRESS))
                {
                    /* 5) determine the falgs from last source addr
                     * then this falg will be used to validate other found addres*/
                    bool b1, b2, b3;
                    if (!(b1 = contains_local_host_addr(last_source_addr_, 1)))
                    {
                        /* this is from a normal address,
                         * furtherly filter out except loopbacks */
                        if ((b2 = transport_layer_->typeofaddr(
                                last_source_addr_, LinkLocalAddrType))) //
                        {
                            flags = (IPAddrType) (AllCastAddrTypes
                                    | LoopBackAddrType);
                        }
                        else if ((b3 = transport_layer_->typeofaddr(
                                last_source_addr_, SiteLocalAddrType))) // filtered
                        {
                            flags = (IPAddrType) (AllCastAddrTypes
                                    | LoopBackAddrType | LinkLocalAddrType);
                        }
                        else
                        {
                            flags = (IPAddrType) (AllCastAddrTypes
                                    | AllLocalAddrTypes);
                        }
                    }
                    else
                    {
                        /* this is from a loopback, use default flag*/
                        flags = AllCastAddrTypes;
                    }
                    EVENTLOG3(VERBOSE,
                            "localHostFound: %d,  linkLocalFound: %d, siteLocalFound: %d",
                            b1, b2, b3);

                    /*6) pass by other validates*/
                    if (found_addr_number < MAX_NUM_ADDRESSES)
                    {
                        addres = (ip_address_t*) curr_pos;
                        if (IS_IPV6_ADDRESS_PTR_NBO(addres))
                        {
                            if (IN6_IS_ADDR_UNSPECIFIED(
                                    addres->dest_addr_un.ipv6_addr.s6_addr))
                            {
                                printf("bad");
                            }
                            if (IN6_IS_ADDR_MULTICAST(
                                    addres->dest_addr_un.ipv6_addr.s6_addr))
                            {
                                printf("bad");
                            }
                            if (IN6_IS_ADDR_V4COMPAT(
                                    addres->dest_addr_un.ipv6_addr.s6_addr))
                            {
                                printf("bad");
                            }

                            if (!IN6_IS_ADDR_UNSPECIFIED(
                                    addres->dest_addr_un.ipv6_addr.s6_addr) && !IN6_IS_ADDR_MULTICAST(addres->dest_addr_un.ipv6_addr.s6_addr)
                                    && !IN6_IS_ADDR_V4COMPAT(addres->dest_addr_un.ipv6_addr.s6_addr))
                            {

                                // fillup addrr
                                peer_addreslist[found_addr_number].sa.sa_family =
                                AF_INET6;
                                peer_addreslist[found_addr_number].sin6.sin6_port =
                                        0;
                                peer_addreslist[found_addr_number].sin6.sin6_flowinfo =
                                        0;
#ifdef HAVE_SIN6_SCOPE_ID
                                foundAddress[found_addr_number].sin6.sin6_scope_id = 0;
#endif
                                memcpy(
                                        peer_addreslist[found_addr_number].sin6.sin6_addr.s6_addr,
                                        &(addres->dest_addr_un.ipv6_addr),
                                        sizeof(struct in6_addr));

                                if (!transport_layer_->typeofaddr(
                                        &peer_addreslist[found_addr_number],
                                        flags)) // NOT contains the addr type of [flags]
                                {
                                    // current addr duplicated with a previous found addr?
                                    is_new_addr = true; // default as new addr
                                    if (ignore_dups)
                                    {
                                        for (idx = 0; idx < found_addr_number;
                                                idx++)
                                        {
                                            if (saddr_equals(
                                                    &peer_addreslist[found_addr_number],
                                                    &peer_addreslist[idx]))
                                            {
                                                is_new_addr = false;
                                            }
                                        }
                                    }

                                    if (is_new_addr)
                                    {
                                        found_addr_number++;
                                        if (peer_supported_addr_types != NULL)
                                            (*peer_supported_addr_types) |=
                                            SUPPORT_ADDRESS_TYPE_IPV6;
#ifdef _DEBUG
                                        saddr2str(
                                                &peer_addreslist[found_addr_number
                                                        - 1], hoststr_,
                                                sizeof(hoststr_), 0);
                                        EVENTLOG1(VERBOSE,
                                                "Found NEW IPv6 Address = %s",
                                                hoststr_);
#endif
                                    }
                                    else
                                    {
                                        EVENTLOG(VERBOSE,
                                                "IPv6 was in the INIT or INIT ACK chunk more than once");
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        ERRLOG(WARNNING_ERROR,
                                "Too many addresses found during IPv4 reading");
                    }
                }
                break;
        }
        read_len += vlp_len;
        padding_len = (((read_len & 3)) == 0) ? 0 : (4 - (read_len & 3));
        read_len += padding_len;
        curr_pos = chunk + read_len;
    } // while

    // we do not to validate last_source_assr here as we have done that in recv_geco_pacjet()
    if (!ignore_last_src_addr)
    {
        is_new_addr = true;
        for (idx = 0; idx < found_addr_number; idx++)
        {
            if (saddr_equals(last_source_addr_, &peer_addreslist[idx], true))
            {
                is_new_addr = false;
            }
        }

        if (is_new_addr)
        {
            // always add last_source_addr as it is from received packet
            // which means the path is active on that address
            // if exceed MAX_NUM_ADDRESSES, we rewrite the last addr by last_source_addr
            if (found_addr_number >= MAX_NUM_ADDRESSES)
            {
                found_addr_number = MAX_NUM_ADDRESSES - 1;

            }
            memcpy(&peer_addreslist[found_addr_number], last_source_addr_,
                    sizeof(sockaddrunion));
            if (peer_supported_addr_types != NULL)
            {
                switch (saddr_family(last_source_addr_))
                {
                    case AF_INET:
                        (*peer_supported_addr_types) |=
                                SUPPORT_ADDRESS_TYPE_IPV4;
                        break;
                    case AF_INET6:
                        (*peer_supported_addr_types) |=
                                SUPPORT_ADDRESS_TYPE_IPV6;
                        break;
                    default:
                        ERRLOG(FALTAL_ERROR_EXIT, "no such addr family!");
                        break;
                }
            }
            EVENTLOG2(VERBOSE,
                    "Added also last_source_addr_ to the addresslist at index %u,found_addr_number = %u!",
                    found_addr_number, found_addr_number + 1);
            found_addr_number++;
        }
    }
    return found_addr_number;
}

inline bool dispatch_layer_t::contains_local_host_addr(sockaddrunion* addr_list,
        uint addr_list_num)
{
    bool ret = false;
    uint ii;
    uint idx;
    for (ii = 0; ii < addr_list_num; ii++)
    {
        /*1) check loopback addr first*/
        switch (saddr_family(addr_list + ii))
        {
            case AF_INET:
                if (ntohl(s4addr(&(addr_list[ii]))) == INADDR_LOOPBACK)
                {
                    EVENTLOG1(VERBOSE, "Found IPv4 loopback address ! Num: %u",
                            addr_list_num);
                    ret = true;
                }
                break;
            case AF_INET6:
#ifdef __linux__
                if (IN6_IS_ADDR_LOOPBACK(s6addr(&(addr_list[ii]))))
                {
#else
                    if (IN6_IS_ADDR_LOOPBACK(&sin6addr(&(addr_list[ii]))))
                    {
#endif
                    EVENTLOG1(VERBOSE, "Found IPv6 loopback address ! Num: %u",
                            addr_list_num);
                    ret = true;
                }
                break;
            default:
                ERRLOG(MAJOR_ERROR, "no such addr family!");
                ret = false;
        }
    }
    /*2) otherwise try to find from local addr list stored in curr geco instance*/
    if (curr_geco_instance_ != NULL)
    {
        if (curr_geco_instance_->local_addres_size > 0)
        {
            for (idx = 0; idx < curr_geco_instance_->local_addres_size; idx++)
            {
                if (saddr_equals(addr_list + idx,
                        curr_geco_instance_->local_addres_list + idx))
                {
                    ret = true;
                }
            }
        }
        /*3 otherwise try to find from global local host addres list if geco instace local_addres_size is 0*/
        else
        {
            for (idx = 0; idx < defaultlocaladdrlistsize_; idx++)
            {
                if (saddr_equals(addr_list + idx, defaultlocaladdrlist_ + idx))
                {
                    ret = true;
                }
            }
        }
    }
    /*4 find from global local host addres list if geco instance NULL*/
    else
    {
        for (idx = 0; idx < defaultlocaladdrlistsize_; idx++)
        {
            if (saddr_equals(addr_list + idx, defaultlocaladdrlist_ + idx))
            {
                ret = true;
            }
        }
    }

    EVENTLOG1(VERBOSE, "Found loopback address returns %s",
            (ret == true) ? "TRUE" : "FALSE");
    return ret;
}

int dispatch_layer_t::read_peer_addr(uchar * chunk, uint chunk_len, uint n,
        sockaddrunion* foundAddress, int supportedAddressTypes)
{
    /*1) validate method input params*/
    uint read_len = CHUNK_FIXED_SIZE + INIT_CHUNK_FIXED_SIZE;
    if (chunk_len < read_len)
    {
        EVENTLOG(WARNNING_ERROR,
                "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
        return -1;
    }

    if (foundAddress == NULL || n < 1 || n > MAX_NUM_ADDRESSES)
    {
        EVENTLOG(FALTAL_ERROR_EXIT,
                "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
        return -1;
    }

    /*2) validate chunk id inside this chunk*/
    init_chunk_t* init_chunk = (init_chunk_t*) chunk;
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
        EVENTLOG2(VERBOSE,
                "read_peer_addreslist() : len==%u, processed_len == %u", len,
                read_len);

        if (len - read_len < VLPARAM_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
                    "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            return -1;
        }

        vlp = (vlparam_fixed_t*) curr_pos;
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
                        addres = (ip_address_t*) curr_pos;
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
                        addres = (ip_address_t*) curr_pos;
                        foundAddress->sa.sa_family = AF_INET6;
                        foundAddress->sin6.sin6_port = 0;
                        foundAddress->sin6.sin6_flowinfo = 0;
#ifdef HAVE_SIN6_SCOPE_ID
                        foundAddress->sin6.sin6_scope_id = 0;
#endif
                        memcpy(foundAddress->sin6.sin6_addr.s6_addr,
                                &(addres->dest_addr_un.ipv6_addr),
                                sizeof(struct in6_addr));
                        return 0;
                    }
                }
                break;
        }
        read_len += chunk_len;
        padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
        read_len += padding_len;
        curr_pos = init_chunk->variableParams + read_len;
    } // while
    return 1;
}
uchar* dispatch_layer_t::find_first_chunk_of(uchar * packet_value,
        uint packet_val_len, uint chunk_type)
{
    uint chunk_len = 0;
    uint read_len = 0;
    uint padding_len;
    chunk_fixed_t* chunk;
    uchar* curr_pos = packet_value;

    while (read_len < packet_val_len)
    {
        EVENTLOG2(VERBOSE,
                "find_first_chunk_of()::packet_val_len=%d, read_len=%d",
                packet_val_len, read_len);

        if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
        {
            ERRLOG(MINOR_ERROR,
                    "find_first_chunk_of():not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
            return NULL;
        }

        chunk = (chunk_fixed_t*) curr_pos;
        chunk_len = get_chunk_length(chunk);
        if (chunk_len < CHUNK_FIXED_SIZE)
        {
            ERRLOG(MINOR_ERROR,
                    "find_first_chunk_of():chunk_len < CHUNK_FIXED_SIZE(4 bytes)!\n");
            return NULL;
        }
        if (chunk_len + read_len > packet_val_len)
        {
            ERRLOG(MINOR_ERROR,
                    "find_first_chunk_of():remaining bytes < chunk_len(4 bytes)!\n");
            return NULL;
        }
        if (chunk->chunk_id == chunk_type)
            return curr_pos;

        read_len += chunk_len;
        padding_len = ((read_len & 3) == 0) ? 0 : (4 - (read_len & 3));
        read_len += padding_len;
        curr_pos = packet_value + read_len;
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
        EVENTLOG2(VERBOSE,
                "contains_error_chunk()::packet_val_len=%d, read_len=%d",
                packet_val_len, read_len);

        if (packet_val_len - read_len < (int) CHUNK_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
                    "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
            return false;
        }

        chunk = (chunk_fixed_t*) curr_pos;
        chunk_len = get_chunk_length(chunk);
        if (chunk_len < CHUNK_FIXED_SIZE
                || chunk_len + read_len > packet_val_len)
            return false;

        if (chunk->chunk_id == CHUNK_ERROR)
        {
            EVENTLOG(INTERNAL_TRACE,
                    "contains_error_chunk()::Error Chunk Found");
            uint err_param_len = 0;
            uchar* simple_chunk;
            uint param_len = 0;
            // search for target error param
            while (err_param_len < chunk_len - (int) CHUNK_FIXED_SIZE)
            {
                if (chunk_len - CHUNK_FIXED_SIZE
                        - err_param_len< VLPARAM_FIXED_SIZE)
                {
                    EVENTLOG(WARNNING_ERROR,
                            "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
                    return false;
                }

                simple_chunk =
                        &((simple_chunk_t*) chunk)->chunk_value[err_param_len];
                err_chunk = (vlparam_fixed_t*) simple_chunk;
                if (ntohs(err_chunk->param_type) == error_cause)
                {
                    EVENTLOG1(VERBOSE,
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

uint dispatch_layer_t::find_chunk_types(uchar* packet_value,
        uint packet_val_len, uint* total_chunk_count)
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

    if (total_chunk_count != NULL)
    {
        *total_chunk_count = 0;
    }

    uint result = 0;
    uint chunk_len = 0;
    uint read_len = 0;
    uint padding_len;
    chunk_fixed_t* chunk;
    uchar* curr_pos = packet_value;

    while (read_len < packet_val_len)
    {
        EVENTLOG2(VERBOSE, "find_chunk_types()::packet_val_len=%d, read_len=%d",
                packet_val_len, read_len);

        if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
        {
            ERRLOG(MINOR_ERROR,
                    "find_chunk_types()::INCOMPLETE CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
            return result;
        }

        chunk = (chunk_fixed_t*) curr_pos;
        chunk_len = get_chunk_length(chunk);

        if (chunk_len < CHUNK_FIXED_SIZE)
        {
            ERRLOG(MINOR_ERROR,
                    "find_first_chunk_of():chunk_len < CHUNK_FIXED_SIZE(4 bytes)!\n");
            return result;
        }
        if (chunk_len + read_len > packet_val_len)
        {
            ERRLOG(MINOR_ERROR,
                    "find_first_chunk_of():remaining bytes < chunk_len(4 bytes)!\n");
            return result;
        }

        if (chunk->chunk_id <= 30)
        {
            result |= (1 << chunk->chunk_id);
            EVENTLOG2(VERBOSE,
                    "dispatch_layer_t::find_chunk_types()::Chunk type==%u, result == %s\n",
                    chunk->chunk_id,
                    Bitify(sizeof(result) * 8, (char* )&result));
        }
        else
        {
            result |= (1 << 31);
            EVENTLOG2(VERBOSE,
                    "dispatch_layer_t::find_chunk_types()::Chunk type==%u setting bit 31 --> result == %s\n",
                    chunk->chunk_id,
                    Bitify(sizeof(result) * 8, (char* )&result));
        }

        if (total_chunk_count != NULL)
        {
            (*total_chunk_count)++;
        }

        read_len += chunk_len;
        padding_len = ((read_len & 3) == 0) ? 0 : (4 - (read_len & 3));
        read_len += padding_len;
        curr_pos = packet_value + read_len;
    }
    return result;
}

bool dispatch_layer_t::cmp_geco_instance(const geco_instance_t& a,
        const geco_instance_t& b)
{
    EVENTLOG2(VERBOSE,
            "DEBUG: cmp_geco_instance()::comparing instance a port %u, instance b port %u",
            a.local_port, b.local_port);

    /* compare local port*/
    if (a.local_port != b.local_port)
        return false;

    if (!a.is_in6addr_any && !b.is_in6addr_any && !a.is_inaddr_any
            && !b.is_inaddr_any)
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
                    EVENTLOG(VERBOSE,
                            "find_dispatcher_by_port(): found TWO equal instances !");
                    return true;
                }
            }
        }
        return false;
    }
    else
    {
        /* one has IN_ADDR_ANY OR IN6_ADDR_ANY : return equal ! */
        EVENTLOG(VERBOSE,
                "find_dispatcher_by_port(): found as IN_ADDR_ANY set !");
        return true;
    }
}

geco_instance_t* dispatch_layer_t::find_geco_instance_by_transport_addr(
        sockaddrunion* dest_addr, uint address_type)
{
    /* search for this endpoint from list*/
    tmp_geco_instance_.local_port = last_dest_port_;
    tmp_geco_instance_.local_addres_size = 1;
    tmp_geco_instance_.local_addres_list = dest_addr;
    tmp_geco_instance_.supportedAddressTypes = address_type;
    tmp_geco_instance_.is_in6addr_any = false;
    tmp_geco_instance_.is_inaddr_any = false;

    geco_instance_t* result = NULL;
    for (auto& i : geco_instances_)
    {
        if (cmp_geco_instance(tmp_geco_instance_, *i))
        {
            result = i;
            break;
        }
    }
    return result;
}

channel_t* dispatch_layer_t::find_channel_by_transport_addr(
        sockaddrunion * src_addr, ushort src_port, ushort dest_port)
{
    tmp_channel_.remote_addres_size = 1;
    tmp_channel_.remote_addres = &tmp_addr_;
    EVENTLOG1(VERBOSE, "src addr af is %d\n", saddr_family(src_addr));

    switch (saddr_family(src_addr))
    {
        case AF_INET:
            EVENTLOG5(VERBOSE,
                    "Looking for IPv4 Address %x (in NBO), src port %u, dest port %u, r port %u, r af %u\n",
                    s4addr(src_addr), src_port, dest_port,
                    ntohs(src_addr->sin.sin_port), saddr_family(src_addr));
            tmp_channel_.remote_addres[0].sa.sa_family = AF_INET;
            tmp_channel_.remote_addres[0].sin.sin_addr.s_addr = s4addr(
                    src_addr);
            tmp_channel_.remote_addres[0].sin.sin_port = src_addr->sin.sin_port;
            tmp_channel_.remote_port = src_port;
            tmp_channel_.local_port = dest_port;
            tmp_channel_.deleted = false;
            break;
        case AF_INET6:
            tmp_channel_.remote_addres[0].sa.sa_family = AF_INET6;
            memcpy(&(tmp_channel_.remote_addres[0].sin6.sin6_addr.s6_addr),
                    (s6addr(src_addr)), sizeof(struct in6_addr));
            EVENTLOG1(INTERNAL_TRACE,
                    "Looking for IPv6 Address %x, check NTOHX() ! ",
                    tmp_channel_.remote_addres[0].sin6.sin6_addr.s6_addr);
            tmp_channel_.remote_addres[0].sin6.sin6_port =
                    src_addr->sin6.sin6_port;
            tmp_channel_.remote_port = src_port;
            tmp_channel_.local_port = dest_port;
            tmp_channel_.deleted = false;
            break;
        default:
            EVENTLOG1(FALTAL_ERROR_EXIT,
                    "Unsupported Address Family %d in find_channel_by_transport_addr()",
                    saddr_family(src_addr));
            break;
    }

    /* search for this endpoint from list*/
    channel_t* result = NULL;
    for (auto i = channels_.begin(); i != channels_.end(); i++)
    {
        if (cmp_channel(tmp_channel_, *(*i)))
        {
            result = *i;
            break;
        }
    }

    if (result != NULL)
    {
        if (result->deleted)
        {
            EVENTLOG1(VERBOSE,
                    "Found endpoint that should be deleted, with id %u\n",
                    result->channel_id);
            result = NULL;
        }
        else
        {
            EVENTLOG1(VERBOSE, "Found valid endpoint with id %u\n",
                    result->channel_id);
        }
    }
    else
    {
        EVENTLOG(VERBOSE, "endpoint indexed by transport address not in list");
    }

    return result;
}

bool dispatch_layer_t::cmp_channel(const channel_t& a, const channel_t& b)
{
    EVENTLOG2(VERBOSE,
            "cmp_endpoint_by_addr_port(): checking ep A[id=%d] and ep B[id=%d]\n",
            a.channel_id, b.channel_id);
    if (a.remote_port == b.remote_port && a.local_port == b.local_port)
    {
        uint i, j;
        /*find if at least there is an ip addr thate quals*/
        for (i = 0; i < a.remote_addres_size; i++)
        {
//            char buf[MAX_IPADDR_STR_LEN];
//            ushort port;
//            saddr2str(&(a.remote_addres[i]), buf, sizeof(a.remote_addres[i].sin),
//                    &port);
//            EVENTLOG3(VERBOSE, "a.remote_addres[%d]::%s:%u\n", i, buf,
//                    port);

            for (j = 0; j < b.remote_addres_size; j++)
            {
//                saddr2str(&(b.remote_addres[j]), buf,
//                        sizeof(b.remote_addres[j]), &port);
//                EVENTLOG3(VERBOSE, "b.remote_addres[%d]::%s:%u\n", j, buf,
//                        port);

                if (saddr_equals(&(a.remote_addres[i]), &(b.remote_addres[j])))
                {
                    if (!a.deleted && !b.deleted)
                    {
                        EVENTLOG(VERBOSE,
                                "cmp_endpoint_by_addr_port(): found TWO equal ep !");
                        return true;
                    }
                }
            }
        }
        EVENTLOG(VERBOSE, "cmp_endpoint_by_addr_port(): addres NOT Equals !");
        return false;
    }
    else
    {
        EVENTLOG(VERBOSE, "cmp_endpoint_by_addr_port(): port NOT Equals !");
        return false;
    }
}

bool dispatch_layer_t::validate_dest_addr(sockaddrunion * dest_addr)
{
    /* 1)
     * this case will be specially treated
     * after the call to validate_dest_addr()*/
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
                EVENTLOG2(VERBOSE,
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
    if (curr_geco_instance_ != NULL)
    {
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
    }

    return false;
}
