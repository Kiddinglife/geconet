#include <algorithm>
#include "dispatch_layer.h"
#include "geco-ds-malloc.h"
#include "transport_layer.h"
#include "auth.h"

dispatch_layer_t::dispatch_layer_t()
{
    assert(MAX_NETWORK_PACKET_VALUE_SIZE == sizeof(simple_chunk_t));

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
    memset(tmp_found_addres_, 0,
        MAX_NUM_ADDRESSES * sizeof(sockaddrunion));

    simple_chunk_index_ = 0;
    memset(simple_chunks_, 0, MAX_CHUNKS_SIZE);
    memset(write_cursors_, 0, MAX_CHUNKS_SIZE);
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
    curr_geco_packet_fixed_ = (geco_packet_fixed_t*)dctp_packet;
    curr_geco_packet_ = (geco_packet_t*)dctp_packet;
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
            my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
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
            my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
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

    int found_addres_size_ = 0;
    int retval = 0;
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
    if (init_chunk_num_ > 1
        || (init_chunk_num_ == 1 && total_chunks_count_ > 1))
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
        curr_uchar_init_chunk_ = find_first_chunk(curr_geco_packet_->chunk,
            curr_geco_packet_value_len_, CHUNK_INIT_ACK);
        if (curr_uchar_init_chunk_ != NULL)
        {
            EVENTLOG(VERBOSE,
                "recv_geco_packet()::Looking for source address in CHUNK_INIT_ACK");
            found_addres_size_ = read_all_ip_addres_from_setup_chunk
                (curr_uchar_init_chunk_,
                curr_geco_packet_value_len_, my_supported_addr_types_) - 1;
            for (; found_addres_size_ >= 0; found_addres_size_--)
            {
                curr_channel_ = find_channel_by_transport_addr(
                    &tmp_found_addres_[found_addres_size_], last_src_port_,
                    last_dest_port_);
                if (curr_channel_ != NULL)
                {
                    last_src_path_ = found_addres_size_;
                    break;
                }
            }
        }
        else // as there is only one init chunk in an packet, we use else for efficiency
        {
            curr_uchar_init_chunk_ = find_first_chunk(curr_geco_packet_->chunk,
                curr_geco_packet_value_len_, CHUNK_INIT);
            if (curr_uchar_init_chunk_ != NULL)
            {
                EVENTLOG(VERBOSE,
                    "recv_geco_packet()::Looking for source address in INIT CHUNK");
                found_addres_size_ = read_all_ip_addres_from_setup_chunk
                    (curr_uchar_init_chunk_,
                    curr_geco_packet_value_len_, my_supported_addr_types_)
                    - 1;
                for (; found_addres_size_ >= 0; found_addres_size_--)
                {
                    curr_channel_ = find_channel_by_transport_addr(
                        &tmp_found_addres_[found_addres_size_],
                        last_src_port_, last_dest_port_);
                    if (curr_channel_ != NULL)
                    {
                        last_src_path_ = found_addres_size_;
                        break;
                    }
                }
            }        //if (curr_uchar_init_chunk_ != NULL) CHUNK_INIT
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
            curr_uchar_init_chunk_ = find_first_chunk(curr_geco_packet_->chunk,
            curr_geco_packet_value_len_, CHUNK_INIT);

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
                &(((init_chunk_t*)curr_uchar_init_chunk_)->init_fixed);
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

            vlparam_fixed_ =
                (vlparam_fixed_t*)find_vlparam_from_setup_chunk(
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
            uchar* abortchunk = find_first_chunk(curr_geco_packet_->chunk,
                curr_geco_packet_value_len_, CHUNK_ABORT);
            bool is_tbit_set = ((chunk_fixed_t*)abortchunk)->chunk_flags == 1;

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
            uchar* abortchunk = find_first_chunk(curr_geco_packet_->chunk,
                curr_geco_packet_value_len_, CHUNK_SHUTDOWN_COMPLETE);
            bool is_tbit_set = ((chunk_fixed_t*)abortchunk)->chunk_flags == 1;
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
                    (uchar)CHUNK_SHUTDOWN_COMPLETE, FLAG_NO_TCB);
                simple_chunk_t_ptr_ = get_simple_chunk(shutdown_complete_cid);
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
         5..*/
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
            vlparam_fixed_ =
                (vlparam_fixed_t*)find_vlparam_from_setup_chunk(
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

            if (get_curr_channel_state() != ChannelState::CookieWait)
            {
                EVENTLOG(WARNNING_ERROR,
                    "found CHUNK_INIT_ACK in non-packet in state other than COOKIE-WAIT -> should_discard_curr_geco_packet_!");
                clear();
                return;
            }
        }
    }
    else // (curr_channel_ == NULL)
    {
        /* 14)
         * filtering and pre-process OOB chunks that have no channel found
         * refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets*/

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
            simple_chunk_t_ptr_ = get_simple_chunk(shutdown_complete_cid);
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
            curr_uchar_init_chunk_ = find_first_chunk(curr_geco_packet_->chunk,
            curr_geco_packet_value_len_, CHUNK_INIT);
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
                &(((init_chunk_t*)curr_uchar_init_chunk_)->init_fixed);
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
                    (vlparam_fixed_t*)find_vlparam_from_setup_chunk(
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
        simple_chunk_t_ptr_ = get_simple_chunk(abort_cid);
        if (curr_ecc_code_ != 0)
        {
            error_cause_t* curr_ecc_ptr_ =
                ((error_cause_t*)simple_chunk_t_ptr_->chunk_value);
            curr_ecc_ptr_->error_reason_code = curr_ecc_code_;
            curr_ecc_ptr_->error_reason_length = 4 + strlen(curr_ecc_reason_);
            simple_chunk_t_ptr_->chunk_header.chunk_length +=
                curr_ecc_ptr_->error_reason_length;
            strcpy((char*)curr_ecc_ptr_->error_reason, curr_ecc_reason_);
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

        chunk = (simple_chunk_t *)curr_pos;
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
                handle_ret = process_data_chunk((data_chunk_t*)chunk,
                    last_src_path_);
                data_chunk_received = true;
                break;
            case CHUNK_INIT:
                EVENTLOG(INTERNAL_TRACE, "***** Bundling received CHUNK_INIT");
                handle_ret = process_curr_init_chunk((init_chunk_t *)chunk);
                break;
            case CHUNK_INIT_ACK:
                EVENTLOG(INTERNAL_TRACE, "***** Bundling received CHUNK_INIT_ACK");
                handle_ret = process_init_ack_chunk((init_chunk_t *)chunk);
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
int dispatch_layer_t::process_curr_init_chunk(init_chunk_t * init)
{
    EVENTLOG(VERBOSE, "process_curr_init_chunk() is executed");

    /*1) put init chunk into chunk  array */
    uint ret = ChunkProcessResult::Good;
    uchar init_cid = alloc_simple_chunk((simple_chunk_t*)init);
    if (get_simple_chunk_id(init_cid) != CHUNK_INIT)
    {
        ERRLOG(MAJOR_ERROR, "process_curr_init_chunk: wrong chunk type");
        remove_simple_chunk(init_cid);
        return ret;
    }

    /*2) validate init params*/
    uint suppoted_addr_types;
    uchar abortcid;
    state_machine_controller_t* smctrl = get_state_machine_controller();
    if (read_outbound_stream(init_cid) == 0
        || read_inbound_stream(init_cid) == 0 || read_init_tag(init_cid))
    {
        EVENTLOG(EXTERNAL_TRACE,
            "event: received init with zero number of streams, or zero init TAG");

        // make and send ABORT with error cause setup
        abortcid = alloc_simple_chunk(CHUNK_ABORT, FLAG_NONE);
        append_ecc(abortcid, ECC_INVALID_MANDATORY_PARAM);
        bundle_ctrl_chunk(get_simple_chunk(abortcid));
        send_bundled_chunks();
        free_simple_chunk(abortcid);

        //delete all data of this channel, channel MUST exist at this moment
        if (smctrl != NULL)
        {
            ret = ChunkProcessResult::StopAndDeleteChannel;
            clear_curr_channel()
                ;
        }
        return ret;
    }

    /*3) validate source addr */
    if (last_source_addr_ == NULL)
    {
        EVENTLOG(FALTAL_ERROR_EXIT,
            "last_source_addr_ == NULL, fatal error exit");
        return -1;
    }
    else
    {
        memcpy(&tmp_addr_, last_source_addr_, sizeof(sockaddrunion));
    }

    /* 4)
     refers to RFC 4060 - 5.1.Normal Establishment of an Association - (B)
     "Z" shall respond immediately with an INIT ACK chunk.*/
    ushort inbound_stream = 0;
    ushort outbound_stream = 0;
    uchar init_ack_cid;
    uint peer_supported_types;
    uint peer_addres_size;
    uint my_addres_size;

    if (smctrl == NULL)
    {
        /*
         The destination IP address of the INIT ACK MUST be set to the source
         IP address of the INIT to which this INIT ACK is responding.

         In the response, besides filling in other parameters, "Z" must set
         the Verification Tag field to Tag_A, and also provide its own
         Verification Tag (Tag_Z) in the Initiate Tag field.

         Moreover, "Z" MUST generate and send along with the INIT ACK a
         State Cookie.  See Section 5.1.3 for State Cookie generation.

         Note: After sending out INIT ACK with the State Cookie parameter,
         "Z" MUST NOT allocate any resources or keep any states for the new
         association.  Otherwise, "Z" will be vulnerable to resource
         attacks.
         */
        // get in out stream number
        inbound_stream = std::min(read_outbound_stream(init_cid),
            get_local_inbound_stream());
        outbound_stream = std::min(read_inbound_stream(init_cid),
            get_local_outbound_stream());

        // todo use safe generate_init_tag from libcat
        /*also use init tag as init tsn */
        uint init_tag = generate_init_tag();
        init_ack_cid = alloc_init_ack_chunk(init_tag, curr_geco_instance_->default_myRwnd,
            outbound_stream, inbound_stream, init_tag);

        /* read and validate addrlist from received init chunk*/
        assert(my_supported_addr_types_ != 0);
        peer_addres_size = read_all_ip_addres_from_setup_chunk((uchar*)init,
            curr_geco_packet_value_len_, my_supported_addr_types_, &peer_supported_types);
        if ((my_supported_addr_types_ & peer_supported_types) == 0)
            ERRLOG(FALTAL_ERROR_EXIT,
            "BAKEOFF: Program error, no common address types in process_curr_init_chunk()");



    }
    return ret;
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
uchar* dispatch_layer_t::find_vlparam_from_setup_chunk(
    uchar * setup_chunk, uint chunk_len, ushort param_type)
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
        EVENTLOG2(VERBOSE,
            "find_params_from_setup_chunk() : len==%u, processed_len == %u",
            len, read_len);

        if (len - read_len < VLPARAM_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
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

int dispatch_layer_t::send_geco_packet(char* geco_packet, uint length,
    short destAddressIndex)
{
    if (geco_packet == NULL)
    {
        ERRLOG(MINOR_ERROR,
            "dispatch_layer::send_geco_packet(): no message to send !!!");
        return 1;
    }

    geco_packet_t* geco_packet_ptr = ((geco_packet_t*)geco_packet);
    simple_chunk_t* chunk = ((simple_chunk_t*)(geco_packet_ptr->chunk));

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
            tos = IPTOS_DEFAULT : curr_geco_instance_->default_ipTos;
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
                    || primary_path >= curr_channel_->remote_addres_size)
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
    }  // curr_channel_ != NULL

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

    return (len == (int)length) ? 0 : -1;
}

int dispatch_layer_t::send_bundled_chunks(uint * addr_idx)
{
    bundle_controller_t* bundle_ctrl =
        (bundle_controller_t*)get_bundle_controller(curr_channel_);

    // no channel exists, so we take the global bundling buffer
    if (bundle_ctrl == NULL)
    {
        EVENTLOG(VERBOSE, "Copying Control Chunk to global bundling buffer ");
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
        EVENTLOG(VERBOSE,
            "send_bundled_chunks ()::sender is LOCKED ---> returning");
        return 1;
    }

    /* determine  path_param_id to use as dest addr
     * TODO - more intelligent path selection strategy
     * should take into account  eg. check path inactive or active */
    int path_param_id;
    if (addr_idx != NULL)
    {
        if (*addr_idx > 0xFFFF)
        {
            ERRLOG(FALTAL_ERROR_EXIT, "address_index too big !");
            return -1;
        }
        else
        {
            path_param_id = *addr_idx;
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
            path_param_id = -1; // use last src path
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
    uint * dest_index)
{

    bundle_controller_t* bundle_ctrl =
        (bundle_controller_t*)get_bundle_controller(curr_channel_);

    /*1) no channel exists, so we take the global bundling buffer */
    if (bundle_ctrl == NULL)
    {
        EVENTLOG(VERBOSE, "Copying Control Chunk to global bundling buffer ");
        bundle_ctrl = &default_bundle_ctrl_;
    }

    bool locked;
    ushort chunk_len = get_chunk_length((chunk_fixed_t*)chunk);
    if (get_bundle_total_size(bundle_ctrl) + chunk_len >= MAX_GECO_PACKET_SIZE)
    {
        /*2) an packet CANNOT hold all data, we send chunks and get bundle empty*/
        EVENTLOG1(VERBOSE,
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

int dispatch_layer_t::read_all_ip_addres_from_setup_chunk(uchar * chunk, uint chunk_len,
    uint my_supported_addr_types,
    uint* peer_supported_addr_types,
    bool ignore_dups, bool ignore_last_src_addr)
{
    /*1) validate method input params*/
    uint read_len = CHUNK_FIXED_SIZE + INIT_CHUNK_FIXED_SIZE;
    if (chunk_len < read_len)
    {
        EVENTLOG2(WARNNING_ERROR,
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
    bool is_new_addr;
    uint idx;
    hide_address_flag_t flags;

    /*3) parse all vlparams in this chunk*/
    while (read_len < len)
    {
        EVENTLOG2(VERBOSE, "read_all_ip_addres_from_setup_chunk() : len==%u, processed_len == %u",
            len, read_len);

        if (len - read_len < VLPARAM_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
                "remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !\n");
            return -1;
        }

        vlp = (vlparam_fixed_t*)curr_pos;
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
                        addres = (ip_address_t*)curr_pos;
                        // validate vlp type and length
                        if (IS_IPV4_ADDRESS_PTR_HBO(addres))
                        {
                            uint ip4_saddr = ntohl(addres->dest_addr_un.ipv4_addr);
                            // validate addr itself
                            if (!IN_CLASSD(ip4_saddr) && !IN_EXPERIMENTAL(ip4_saddr)
                                && !IN_BADCLASS(ip4_saddr)
                                && !INADDR_ANY == ip4_saddr
                                && !INADDR_BROADCAST == ip4_saddr)
                            {
                                tmp_found_addres_[found_addr_number].sa.sa_family =
                                    AF_INET;
                                tmp_found_addres_[found_addr_number].sin.sin_port =
                                    0;
                                tmp_found_addres_[found_addr_number].sin.sin_addr.s_addr =
                                    addres->dest_addr_un.ipv4_addr;
                                //current addr duplicated with a previous found addr?
                                is_new_addr = true; // default as new addr
                                if (ignore_dups)
                                {
                                    for (idx = 0; idx < found_addr_number; idx++)
                                    {
                                        if (saddr_equals(
                                            &tmp_found_addres_[found_addr_number],
                                            &tmp_found_addres_[idx]))
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
                                        &tmp_found_addres_[found_addr_number - 1],
                                        hoststr_, sizeof(hoststr_), 0);
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
                        if (!(b2 = transport_layer_->filter_address(
                            last_source_addr_, flag_HideLinkLocal))) //
                        {
                            flags = (hide_address_flag_t)(flag_Default | flag_HideLoopback);
                        }
                        else if (!(b3 = transport_layer_->filter_address(
                            last_source_addr_, flag_HideSiteLocal))) // filtered
                        {
                            flags = (hide_address_flag_t)(flag_Default | flag_HideLoopback |
                                flag_HideLinkLocal);
                        }
                        else
                        {
                            flags = (hide_address_flag_t)(flag_Default | flag_HideLocal);
                        }
                    }
                    else
                    {
                        /* this is from a loopback, use default flag*/
                        flags = flag_Default;
                    }
                    EVENTLOG3(VERBOSE,
                        "localHostFound: %d,  linkLocalFound: %d, siteLocalFound: %d",
                        b1, b2, b3);

                    /*6) pass by other validates*/
                    if (found_addr_number < MAX_NUM_ADDRESSES)
                    {
                        addres = (ip_address_t*)curr_pos;
                        if (IS_IPV6_ADDRESS_PTR_HBO(addres))
                        {
                            if (!IN6_IS_ADDR_UNSPECIFIED(
                                &(addres->dest_addr_un.ipv6_addr)) && !IN6_IS_ADDR_MULTICAST(&(addres->dest_addr_un.ipv6_addr))
                                && !IN6_IS_ADDR_V4COMPAT(&(addres->dest_addr_un.ipv6_addr))
                                && !IN6_IS_ADDR_UNSPECIFIED(
                                &(addres->dest_addr_un.ipv6_addr))
                                && !IN6_IS_ADDR_MULTICAST(&(addres->dest_addr_un.ipv6_addr))
                                && !IN6_IS_ADDR_V4COMPAT(&(addres->dest_addr_un.ipv6_addr)))
                            {

                                // fillup addrr
                                tmp_found_addres_[found_addr_number].sa.sa_family =
                                    AF_INET6;
                                tmp_found_addres_[found_addr_number].sin6.sin6_port =
                                    0;
                                tmp_found_addres_[found_addr_number].sin6.sin6_flowinfo =
                                    0;
#ifdef HAVE_SIN6_SCOPE_ID
                                foundAddress[found_addr_number].sin6.sin6_scope_id = 0;
#endif
                                memcpy(
                                    tmp_found_addres_[found_addr_number].sin6.sin6_addr.s6_addr,
                                    &(addres->dest_addr_un.ipv6_addr),
                                    sizeof(struct in6_addr));

                                if (transport_layer_->filter_address(
                                    &tmp_found_addres_[found_addr_number],
                                    flags)) // this addr passes by the validation tests shown in flags
                                {
                                    // current addr duplicated with a previous found addr?
                                    is_new_addr = true; // default as new addr
                                    if (ignore_dups)
                                    {
                                        for (idx = 0; idx < found_addr_number;
                                            idx++)
                                        {
                                            if (saddr_equals(
                                                &tmp_found_addres_[found_addr_number],
                                                &tmp_found_addres_[idx]))
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
                                            &tmp_found_addres_[found_addr_number
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
        padding_len = ((read_len % 4) == 0) ? 0 : (4 - read_len % 4);
        read_len += padding_len;
        curr_pos += read_len;
    } // while

    // we do not to validate last_source_assr here as we have done that in recv_geco_pacjet()
    if (!ignore_last_src_addr)
    {
        is_new_addr = true;
        for (idx = 0; idx < found_addr_number; idx++)
        {
            if (saddr_equals(last_source_addr_, &tmp_found_addres_[idx]))
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
            memcpy(&tmp_found_addres_[found_addr_number], last_source_addr_,
                sizeof(sockaddrunion));
            switch (saddr_family(last_source_addr_))
            {
                case AF_INET:
                    (*peer_supported_addr_types) |= SUPPORT_ADDRESS_TYPE_IPV4;
                    break;
                case AF_INET6:
                    (*peer_supported_addr_types) |= SUPPORT_ADDRESS_TYPE_IPV6;
                    break;
                default:
                    ERRLOG(FALTAL_ERROR_EXIT, "no such addr family!");
                    break;
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
    /*2) find from local addr list stored in curr geco instance*/
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
        /*3 find from global local host addres list if geco instace local_addres_size is 0*/
        else
        {
            for (idx = 0; idx < glocal_host_addres_size_; idx++)
            {
                if (saddr_equals(addr_list + idx, glocal_host_addres_ + idx))
                {
                    ret = true;
                }
            }
        }
    }
    /*4 find from global local host addres list if geco instance NULL*/
    else
    {
        for (idx = 0; idx < glocal_host_addres_size_; idx++)
        {
            if (saddr_equals(addr_list + idx, glocal_host_addres_ + idx))
            {
                ret = true;
            }
        }
    }

    EVENTLOG1(VERBOSE, "Found loopback address returns %s",
        (ret == true) ? "TRUE" : "FALSE");
    return ret;
}

int dispatch_layer_t::read_an_ip_addr_from_setup_chunk(uchar * chunk, uint chunk_len, uint n,
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
        EVENTLOG2(VERBOSE, "read_all_ip_addres_from_setup_chunk() : len==%u, processed_len == %u",
            len, read_len);

        if (len - read_len < VLPARAM_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
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
        curr_pos += read_len;
    } // while
    return 1;
}
uchar* dispatch_layer_t::find_first_chunk(uchar * packet_value,
    uint packet_val_len, uint chunk_type)
{
    uint chunk_len = 0;
    uint read_len = 0;
    uint padding_len;
    chunk_fixed_t* chunk;
    uchar* curr_pos = packet_value;

    while (read_len < packet_val_len)
    {
        EVENTLOG2(VERBOSE, "find_first_chunk()::packet_val_len=%d, read_len=%d",
            packet_val_len, read_len);

        if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
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
        EVENTLOG2(VERBOSE,
            "contains_error_chunk()::packet_val_len=%d, read_len=%d",
            packet_val_len, read_len);

        if (packet_val_len - read_len < (int)CHUNK_FIXED_SIZE)
        {
            EVENTLOG(WARNNING_ERROR,
                "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
            return false;
        }

        chunk = (chunk_fixed_t*)curr_pos;
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
            while (err_param_len < chunk_len - (int)CHUNK_FIXED_SIZE)
            {
                if (chunk_len - CHUNK_FIXED_SIZE
                    - err_param_len < VLPARAM_FIXED_SIZE)
                {
                    EVENTLOG(WARNNING_ERROR,
                        "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");
                    return false;
                }

                simple_chunk =
                    &((simple_chunk_t*)chunk)->chunk_value[err_param_len];
                err_chunk = (vlparam_fixed_t*)simple_chunk;
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
            EVENTLOG(WARNNING_ERROR,
            "remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !\n");

        chunk = (chunk_fixed_t*)curr_pos;
        chunk_len = get_chunk_length(chunk);
        if (chunk_len < CHUNK_FIXED_SIZE
            || chunk_len + read_len > packet_val_len)
            return result;

        if (chunk->chunk_id <= 30)
        {
            result |= (1 << chunk->chunk_id);
            EVENTLOG2(VERBOSE,
                "dispatch_layer_t::find_chunk_types()::Chunk type==%u, result == %x",
                chunk->chunk_id,
                Bitify(sizeof(result) * 8, (char*)&result));
        }
        else
        {
            result |= (1 << 31);
            EVENTLOG2(VERBOSE,
                "dispatch_layer_t::find_chunk_types()::Chunk type==%u setting bit 31 --> result == %s",
                chunk->chunk_id,
                Bitify(sizeof(result) * 8, (char*)&result));
        }

        if (total_chunk_count != NULL)
        {
            *total_chunk_count++;
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
    EVENTLOG2(VERBOSE,
        "DEBUG: cmp_geco_instance()::comparing instance a port %u, instance b port %u",
        a.local_port, b.local_port);

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
    tmp_geco_instance_.is_in6addr_any = false;
    tmp_geco_instance_.is_inaddr_any = false;
    tmp_geco_instance_.local_addres_list = dest_addr;
    tmp_geco_instance_.supportedAddressTypes = address_type;

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

    switch (saddr_family(src_addr))
    {
        case AF_INET:
            EVENTLOG1(INTERNAL_TRACE, "Looking for IPv4 Address %x (in NBO)",
                s4addr(src_addr));
            tmp_channel_.remote_addres[0].sa.sa_family = AF_INET;
            tmp_channel_.remote_addres[0].sin.sin_addr.s_addr = s4addr(src_addr);
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
        EVENTLOG(INTERNAL_TRACE,
            "endpoint indexed by transport address not in list");
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
            for (j = 0; j < b.remote_addres_size; j++)
            {
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
        EVENTLOG(VERBOSE, "cmp_endpoint_by_addr_port(): found No equal ep !");
        return false;
    }
    else
    {
        EVENTLOG(VERBOSE, "cmp_endpoint_by_addr_port(): found No equal ep !");
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
