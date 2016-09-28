#include "dispatch_layer.h"
#include "transport_layer.h"
#include "chunk_factory.h"
#include "auth.h"
#include "geco-ds-malloc.h"

dispatch_layer_t::dispatch_layer_t()
{
	assert(MAX_NETWORK_PACKET_VALUE_SIZE == sizeof(simple_chunk_t));
	default_bundle_ctrl_.ctrl_chunk_in_buffer = false;
	default_bundle_ctrl_.ctrl_position = UDP_GECO_PACKET_FIXED_SIZES;
	default_bundle_ctrl_.sack_in_buffer = false;
	default_bundle_ctrl_.sack_position = UDP_GECO_PACKET_FIXED_SIZES;
	default_bundle_ctrl_.data_in_buffer = false;
	default_bundle_ctrl_.data_position = UDP_GECO_PACKET_FIXED_SIZES;

	found_init_chunk_ = false;
	is_found_abort_chunk_ = false;
	is_found_cookie_echo_ = false;
	is_found_init_chunk_ = false;
	library_support_unreliability_ = true;
	dispatch_layer_initialized = false;
	is_there_at_least_one_equal_dest_port_ = false;
	should_discard_curr_geco_packet_ = false;
	do_dns_query_for_host_name_ = false;
	// uncomment as we never send abort to a unconnected peer
	send_abort_for_oob_packet_ = true;
	send_abort_ = false;
	enable_test_ = false;
	ignore_cookie_life_spn_from_init_chunk_ = false;
	send_abort_for_oob_packet_ = true;

	curr_channel_ = NULL;
	curr_geco_instance_ = NULL;
	curr_geco_packet_ = NULL;
	curr_uchar_init_chunk_ = NULL;
	curr_channel_ = NULL;
	curr_geco_instance_ = NULL;
	simple_chunk_t_ptr_ = NULL;
	vlparam_fixed_ = NULL;
	ip6_saddr_ = NULL;
	curr_ecc_reason_ = NULL;
	transport_layer_ = NULL;
	curr_geco_packet_fixed_ = NULL;
	init_chunk_fixed_ = NULL;
	defaultlocaladdrlist_ = NULL;

	total_chunks_count_ = 0;
	defaultlocaladdrlistsize_ = 0;
	tmp_peer_supported_types_ = 0;
	my_supported_addr_types_ = 0;
	curr_ecc_len_ = 0;
	curr_ecc_code_ = 0;
	curr_geco_packet_value_len_ = 0;
	chunk_types_arr_ = 0;
	tmp_local_addreslist_size_ = 0;
	tmp_peer_addreslist_size_ = 0;
	init_chunk_num_ = 0;
	last_source_addr_ = last_dest_addr_ = 0;
	last_src_port_ = last_dest_port_ = 0;
	last_init_tag_ = 0;
	last_src_path_ = 0;
	last_veri_tag_ = 0;
	ip4_saddr_ = 0;
	curr_ecc_code_ = 0;
	dest_addr_type_ = -1;
	chunkflag2use_ = -1;
	cookie_ack_cid_ = 0;
	cookie_local_tie_tag_ = 0;
	cookie_remote_tie_tag_ = 0;
	simple_chunk_index_ = 0;

	channels_.reserve(DEFAULT_ENDPOINT_SIZE);
	memset(tmp_local_addreslist_, 0,
		MAX_NUM_ADDRESSES * sizeof(sockaddrunion));
	memset(tmp_peer_addreslist_, 0,
		MAX_NUM_ADDRESSES * sizeof(sockaddrunion));
	memset(simple_chunks_, 0, MAX_CHUNKS_SIZE);
	memset(curr_write_pos_, 0, MAX_CHUNKS_SIZE);
	memset(completed_chunks_, 0, MAX_CHUNKS_SIZE);

#if ENABLE_UNIT_TEST
	enable_mock_dispatcher_disassemle_curr_geco_packet_ = false;
	enable_mock_dispatch_send_geco_packet_ = false;
	enable_mock_dispatcher_process_init_chunk_ = false;
#endif
}

int dispatch_layer_t::recv_geco_packet(int socket_fd, char *dctp_packet, uint dctp_packet_len,
	sockaddrunion * source_addr, sockaddrunion * dest_addr)
{
	EVENTLOG3(NOTICE,
		"- - - - - - - - - - Enter recv_geco_packet(%d bytes, fd %d) - - - - - - - - - -",
		dctp_packet_len, dctp_packet, socket_fd);

	/* 1) validate packet hdr size, checksum and if aligned 4 bytes */
	if ((dctp_packet_len & 3) != 0 || dctp_packet_len < MIN_GECO_PACKET_SIZE
		|| dctp_packet_len > MAX_GECO_PACKET_SIZE
		|| !gvalidate_checksum(dctp_packet, dctp_packet_len))
	{
		EVENTLOG(NOTICE, "received corrupted datagramm -> discard");
		EVENTLOG(NOTICE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
		return recv_geco_packet_but_integrity_check_failed;
	}

	/* 2) validate port numbers */
	curr_geco_packet_fixed_ = (geco_packet_fixed_t*)dctp_packet;
	curr_geco_packet_ = (geco_packet_t*)dctp_packet;
	last_src_port_ = ntohs(curr_geco_packet_fixed_->src_port);
	last_dest_port_ = ntohs(curr_geco_packet_fixed_->dest_port);
	if (last_src_port_ == 0 || last_dest_port_ == 0)
	{
		/* refers to RFC 4960 Section 3.1 at line 867 and line 874*/
		ERRLOG(NOTICE, "dispatch_layer_t:: invalid ports number (0)");
		last_src_port_ = 0;
		last_dest_port_ = 0;
		EVENTLOG(NOTICE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
		return recv_geco_packet_but_port_numbers_check_failed;
	}

	/* 3) validate ip addresses
	 #include <netinet/in.h>
	 int IN6_IS_ADDR_UNSPECIFIED(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_LOOPBACK(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MULTICAST(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_LINKLOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_SITELOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_V4MAPPED(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_V4COMPAT(const struct in6_addr * aptr);
	 // multicast macros
	 int IN6_IS_ADDR_MC_NODELOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MC_LINKLOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MC_SITELOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MC_ORGLOCAL(const struct in6_addr * aptr);
	 int IN6_IS_ADDR_MC_GLOBAL(const struct in6_addr * aptr);
	 //返回值：非零表示IPv6地址是指定类型的，否则返回零
	 Note: A sender MUST NOT use an IPv4-mapped IPv6 address [RFC4291],
	 but should instead use an IPv4 Address parameter for an IPv4 address.
	 */
	should_discard_curr_geco_packet_ = false;
	dest_addr_type_ = saddr_family(dest_addr);
	if (dest_addr_type_ == AF_INET)
	{
		dest_addr_type_ = SUPPORT_ADDRESS_TYPE_IPV4;  // peer snd us an IP4-formate address
		dest_addr->sin.sin_port = curr_geco_packet_fixed_->dest_port;
		ip4_saddr_ = ntohl(dest_addr->sin.sin_addr.s_addr);

		if (IN_CLASSD(ip4_saddr_))
		{
			EVENTLOG(VERBOSE, "IN_CLASSD(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN_EXPERIMENTAL(ip4_saddr_))
		{
			EVENTLOG(VERBOSE, "IN_EXPERIMENTAL(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN_BADCLASS(ip4_saddr_))
		{
			EVENTLOG(VERBOSE, "IN_BADCLASS(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (INADDR_ANY == ip4_saddr_)
		{
			EVENTLOG(VERBOSE, "INADDR_ANY(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (INADDR_BROADCAST == ip4_saddr_)
		{
			EVENTLOG(VERBOSE, "INADDR_BROADCAST(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		//if (IN_CLASSD(ip4_saddr_) || IN_EXPERIMENTAL(ip4_saddr_) || IN_BADCLASS(ip4_saddr_)
		//    || (INADDR_ANY == ip4_saddr_) || (INADDR_BROADCAST == ip4_saddr_))
		//{
		//    should_discard_curr_geco_packet_ = true;
		//}

		/* COMMENT HERE MEANS msg sent to ourself is allowed
		 * if ((INADDR_LOOPBACK != ntohl(source_addr->sin.sin_addr.s_addr))
		 *  &&(source_addr->sin.sin_addr.s_addr == dest_addr->sin.sin_addr.s_addr))
		 *  should_discard_curr_geco_packet_ = true;*/
	}
	else if (dest_addr_type_ == AF_INET6)
	{
		dest_addr_type_ = SUPPORT_ADDRESS_TYPE_IPV6;  // peer snd us an IP6-formate address
		dest_addr->sin6.sin6_port = curr_geco_packet_fixed_->dest_port;
		ip6_saddr_ = &(dest_addr->sin6.sin6_addr);

		if (IN6_IS_ADDR_UNSPECIFIED(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_UNSPECIFIED(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_MULTICAST(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_MULTICAST(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_V4COMPAT(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_V4COMPAT(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_V4MAPPED(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_V4MAPPED(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_ADDR_EQUAL(&in6addr_any, ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6ADDR_ANY(dest_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}

		//if (IN6_IS_ADDR_UNSPECIFIED(ip6_saddr_) || IN6_IS_ADDR_MULTICAST(ip6_saddr_)
		//    || IN6_IS_ADDR_V4COMPAT(ip6_saddr_) || IN6_IS_ADDR_V4MAPPED(ip6_saddr_)
		//    || IN6_ADDR_EQUAL(&in6addr_any, ip6_saddr_)) should_discard_curr_geco_packet_ =
		//    true;
		/* comment here means msg sent to ourself is allowed
		 * if ((!IN6_IS_ADDR_LOOPBACK(&(source_addr->sin6.sin6_addr.s6_addr))) &&
		 * IN6_ARE_ADDR_EQUAL(&(source_addr->sin6.sin6_addr.s6_addr),
		 * &(dest_addr->sin6.sin6_addr.s6_addr))) should_discard_curr_geco_packet_ = true;
		 */
		 //EVENTLOG1(VERBOSE, "filter out dest IPV6 addresses, discard(%d)",
		 //    should_discard_curr_geco_packet_);
	}
	else
	{
		// we only supports IP archetecture either ip4 or ip6 so discard it
		EVENTLOG(VERBOSE, "AddrFamily(dest_addr) -> discard!");
		should_discard_curr_geco_packet_ = true;
	}

	if (saddr_family(source_addr) == AF_INET)
	{
		source_addr->sin.sin_port = curr_geco_packet_fixed_->src_port;
		ip4_saddr_ = ntohl(source_addr->sin.sin_addr.s_addr);

		if (IN_CLASSD(ip4_saddr_))
		{
			EVENTLOG(NOTICE, "IN_CLASSD(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN_EXPERIMENTAL(ip4_saddr_))
		{
			EVENTLOG(NOTICE, "IN_EXPERIMENTAL(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN_BADCLASS(ip4_saddr_))
		{
			EVENTLOG(NOTICE, "IN_BADCLASS(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (INADDR_ANY == ip4_saddr_)
		{
			EVENTLOG(NOTICE, "INADDR_ANY(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (INADDR_BROADCAST == ip4_saddr_)
		{
			EVENTLOG(NOTICE, "INADDR_BROADCAST(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		//if (IN_CLASSD(ip4_saddr_) || IN_EXPERIMENTAL(ip4_saddr_) || IN_BADCLASS(ip4_saddr_)
		//    || (INADDR_ANY == ip4_saddr_) || (INADDR_BROADCAST == ip4_saddr_))
		//{
		//    should_discard_curr_geco_packet_ = true;
		//}
		//EVENTLOG1(VERBOSE, "filter out src addr->discard(%d)",
		//    should_discard_curr_geco_packet_);
	}
	else if (saddr_family(source_addr) == AF_INET6)
	{
		source_addr->sin6.sin6_port = curr_geco_packet_fixed_->src_port;
		ip6_saddr_ = &(source_addr->sin6.sin6_addr);

		if (IN6_IS_ADDR_UNSPECIFIED(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_UNSPECIFIED(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_MULTICAST(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_MULTICAST(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_V4COMPAT(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_V4COMPAT(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_IS_ADDR_V4MAPPED(ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6_IS_ADDR_V4MAPPED(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}
		else if (IN6_ADDR_EQUAL(&in6addr_any, ip6_saddr_))
		{
			EVENTLOG(VERBOSE, "IN6ADDR_ANY(source_addr) -> discard !");
			should_discard_curr_geco_packet_ = true;
		}

		//if (IN6_IS_ADDR_UNSPECIFIED(ip6_saddr_) || IN6_IS_ADDR_MULTICAST(ip6_saddr_)
		//    || IN6_IS_ADDR_V4COMPAT(ip6_saddr_) || IN6_IS_ADDR_V4MAPPED(ip6_saddr_)
		//    || IN6_ADDR_EQUAL(&in6addr_any, ip6_saddr_))
		//{
		//    should_discard_curr_geco_packet_ = true;
		//}
		//EVENTLOG1(VERBOSE, "filter out src addr6 -> discard(%d)",
		//    should_discard_curr_geco_packet_);
	}
	else
	{
		// we only supports IP archetecture either ip4 or ip6 so discard it
		EVENTLOG(VERBOSE, "AddrFamily((source_addr)) -> discard!");
		should_discard_curr_geco_packet_ = true;
	}

	saddr2str(source_addr, src_addr_str_, MAX_IPADDR_STR_LEN, NULL);
	saddr2str(dest_addr, dest_addr_str_, MAX_IPADDR_STR_LEN, NULL);

	if (should_discard_curr_geco_packet_)
	{
		last_src_port_ = 0;
		last_dest_port_ = 0;
		EVENTLOG4(VERBOSE,
			"discarding packet for incorrect address src addr : %s:%d, dest addr%s:%d",
			src_addr_str_, last_src_port_, dest_addr_str_, last_dest_port_);
		EVENTLOG(NOTICE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
		return recv_geco_packet_but_addrs_formate_check_failed;
	}
	else
	{
		// we can assign addr as they are good to use now
		last_source_addr_ = source_addr;
		last_dest_addr_ = dest_addr;
	}

	/*4) find the endpoint for this packet */
	// cmp_channel() will set last_src_path_ to the one found src's
	// index in channel's remote addr list
	last_src_path_ = 0;
	curr_channel_ = find_channel_by_transport_addr(last_source_addr_, last_src_port_,
		last_dest_port_);
	if (curr_channel_ != NULL)
	{
		EVENTLOG(INFO, "Found channel !");
		/*5) get the sctp instance for this packet from channel*/
		curr_geco_instance_ = curr_channel_->geco_inst;
		if (curr_geco_instance_ == NULL)
		{
			ERRLOG(MAJOR_ERROR,
				"Foundchannel, but no geo Instance -> abort app -> FIXME imple errors !");
			return recv_geco_packet_but_found_channel_has_no_instance;
		}
		else
		{
			my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
		}
	}

	/* 6) find  instance for this packet if this packet is for a server dctp instance,
	 *  we will find that  instance and let it handle this packet (i.e. we have an
	 *  instance's localPort set and it matches the packet's destination port)
	 */
	else
	{
		curr_geco_instance_ = find_geco_instance_by_transport_addr(last_dest_addr_,
			last_dest_port_);
		if (curr_geco_instance_ == NULL)
		{
			/* 7) actually this is special case see validate_dest_addr() for details
			 *  basically, the only reason we cannot find inst at this context is
			 *  unequal addr type where ip4 and ip6 addrs that pointer to the
			 *  same machina dest port. handled by following codes at line 791->snd  ABORT
			 */
			my_supported_addr_types_ = SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6;
			EVENTLOG3(VERBOSE,
				"Couldn't find an Instance with dest addr %s:%u, default support addr types ip4 and ip6 %u !",
				src_addr_str_, last_dest_port_, my_supported_addr_types_);
		}
		else
		{
			// use user sepecified supported addr types
			my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
			EVENTLOG3(VERBOSE,
				"Find an Instance with dest addr %s:%u, user sepecified support addr types:%u !",
				src_addr_str_, last_dest_port_, my_supported_addr_types_);
		}
	}

	/* 8)now we can validate if dest_addr is in localaddress send ABORT + ECC_UNRESOLVED_ADDR */
	if (validate_dest_addr(dest_addr) == false)
	{
		EVENTLOG(VERBOSE, "validate_dest_addr() failed -> discard it!");
		clear();
		return recv_geco_packet_but_dest_addr_check_failed;
	}

	/*9) fetch all chunk types contained in this packet value field for use in the folowing */
	last_veri_tag_ = ntohl(curr_geco_packet_->pk_comm_hdr.verification_tag);
	curr_geco_packet_value_len_ = dctp_packet_len - GECO_PACKET_FIXED_SIZE;
	chunk_types_arr_ = find_chunk_types(curr_geco_packet_->chunk, curr_geco_packet_value_len_,
		&total_chunks_count_);
	tmp_peer_addreslist_size_ = 0;
	curr_uchar_init_chunk_ = NULL;
	send_abort_ = false;

	/* 10) validate individual chunks
	 * (see section 3.1 of RFC 4960 at line 931 init chunk MUST be the only chunk
	 * in the  packet carrying it)*/
	init_chunk_num_ = contains_chunk(CHUNK_INIT, chunk_types_arr_);
	if (init_chunk_num_ > 1 || /*only one int ack with other type chunks*/
		(init_chunk_num_ == 1 && total_chunks_count_ > 1)/*there are repeated init ack chunks*/)
	{
		ERRLOG(MINOR_ERROR,
			"recv_geco_packet(): discarding illegal packet (init is not only one !)");
		clear();
		return recv_geco_packet_but_morethanone_init;
	}

	init_chunk_num_ = contains_chunk(CHUNK_INIT_ACK, chunk_types_arr_);
	if (init_chunk_num_ > 1 || (init_chunk_num_ == 1 && total_chunks_count_ > 1))
	{
		ERRLOG(MINOR_ERROR,
			"recv_geco_packet(): discarding illegal packet (init ack is not only chunk!)");
		clear();
		return recv_geco_packet_but_morethanone_init_ack;
	}

	init_chunk_num_ = contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr_);
	if (init_chunk_num_ > 1 || (init_chunk_num_ == 1 && total_chunks_count_ > 1))
	{
		ERRLOG(MINOR_ERROR,
			"recv_geco_packet(): discarding illegal packet (shutdown complete is not the only chunk !)");
		clear();
		return recv_geco_packet_but_morethanone_shutdown_complete;
	}

	found_init_chunk_ = false;
	init_chunk_fixed_ = NULL;
	vlparam_fixed_ = NULL;

	/* founda matching channel using the source addr*/
	/* 11) try to find an existed channel for this packet from setup chunks */
	if (curr_channel_ == NULL)
	{
		if (curr_geco_instance_ != NULL || is_there_at_least_one_equal_dest_port_)
		{

			curr_uchar_init_chunk_ = find_first_chunk_of(curr_geco_packet_->chunk,
				curr_geco_packet_value_len_,
				CHUNK_INIT_ACK);
			if (curr_uchar_init_chunk_ != NULL)
			{
				assert(
					curr_geco_packet_value_len_
					== ntohs(
					((init_chunk_t*)curr_uchar_init_chunk_)->chunk_header.chunk_length));
				tmp_peer_addreslist_size_ = read_peer_addreslist(tmp_peer_addreslist_,
					curr_uchar_init_chunk_, curr_geco_packet_value_len_,
					my_supported_addr_types_) - 1;
				for (; tmp_peer_addreslist_size_ >= 0; tmp_peer_addreslist_size_--)
				{
					if ((curr_channel_ = find_channel_by_transport_addr(
						&tmp_peer_addreslist_[tmp_peer_addreslist_size_], last_src_port_,
						last_dest_port_)) != NULL)
					{
						EVENTLOG(VERBOSE,
							"Found an existing channel  in INIT ACK chunk's addrlist vlp !");
						break;
					}
				}
			}
			else  // as there is only one init chunk in an packet, we use else for efficiency
			{
				curr_uchar_init_chunk_ = find_first_chunk_of(curr_geco_packet_->chunk,
					curr_geco_packet_value_len_,
					CHUNK_INIT);
				if (curr_uchar_init_chunk_ != NULL)
				{
					EVENTLOG(VERBOSE, "Looking for source address in INIT CHUNK");
					assert(
						curr_geco_packet_value_len_
						== ntohs(
						((init_chunk_t*)curr_uchar_init_chunk_)->chunk_header.chunk_length));
					tmp_peer_addreslist_size_ = read_peer_addreslist(tmp_peer_addreslist_,
						curr_uchar_init_chunk_, curr_geco_packet_value_len_,
						my_supported_addr_types_) - 1;
					for (; tmp_peer_addreslist_size_ >= 0; tmp_peer_addreslist_size_--)
					{
						if ((curr_channel_ = find_channel_by_transport_addr(
							&tmp_peer_addreslist_[tmp_peer_addreslist_size_], last_src_port_,
							last_dest_port_)) != NULL)
						{
							EVENTLOG(VERBOSE,
								"Found an existing channel in INIT chunk's addrlist vlp !");
							break;
						}
					}
				}  //if (curr_uchar_init_chunk_ != NULL) CHUNK_INIT
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
					"recv_geco_packet(): Found an existing channel from INIT (ACK) addrlist vlp");
				curr_geco_instance_ = curr_channel_->geco_inst;
				my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
			}
#ifdef _DEBUG
			else
			{
				EVENTLOG(VERBOSE,
					"recv_geco_packet(): Not found an existing channel from INIT (ACK) addrlist vlp");
			}
#endif
		}
	}

	is_found_init_chunk_ = false;
	is_found_cookie_echo_ = false;
	is_found_abort_chunk_ = false;

	/* 13) process non-OOTB chunks that belong to a found channel */
	if (curr_channel_ != NULL)
	{
		EVENTLOG(VERBOSE, "Process non-OOTB chunks");
		/*13.1 validate curr_geco_instance_*/
		if (curr_geco_instance_ == NULL)
		{
			curr_geco_instance_ = curr_channel_->geco_inst;
			if (curr_geco_instance_ == NULL)
			{
				ERRLOG(MAJOR_ERROR, "We have an Association, but no Instance, FIXME !");
				clear();
				return recv_geco_packet_but_found_channel_has_no_instance;
			}
			else
			{
				my_supported_addr_types_ = curr_geco_instance_->supportedAddressTypes;
				EVENTLOG(VERBOSE, "Assign inst with the one from found channel!");
			}
		}
		else if (curr_channel_->geco_inst != curr_geco_instance_)
		{
			// we found a previously-connected channel in 12) from setup chunk
			//  the instance it holds MUST == curr_geco_instance_
			ERRLOG(WARNNING_ERROR,
				"We have an curr_channel_, but its Instance != found instance -> reset it!");
			curr_geco_instance_ = curr_channel_->geco_inst;
			if (curr_geco_instance_ == NULL)
			{
				ERRLOG(MAJOR_ERROR, "We have an Association, but no Instance, FIXME !");
				clear();
				return recv_geco_packet_but_found_channel_has_no_instance;
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
		if (curr_uchar_init_chunk_ == NULL)  // we MAY have found it from 11) at line 290
			curr_uchar_init_chunk_ = find_first_chunk_of(curr_geco_packet_->chunk,
				curr_geco_packet_value_len_, CHUNK_INIT);

		/*process_init_chunk() will furtherly handle this INIT chunk in the follwing method
		 here we just validate some fatal errors*/
		if (curr_uchar_init_chunk_ != NULL)
		{
			EVENTLOG(VERBOSE, "Find an INIT CHUNK");

			// we have tested it INIT, init-ack and shutdown complete is the only chunk above
			// at 10) at line 240
			is_found_init_chunk_ = true;

			// make sure init chunk has zero ver tag
			// last_init_tag_ has be aisigned a value at above
			if (last_veri_tag_ != 0)
			{
				ERRLOG(MINOR_ERROR,
					"Found INIT chunk  in non-ootb-packet, but its verifi tag != 0 ->discard !");
				clear();
				return recv_geco_packet_but_init_chunk_has_zero_verifi_tag;
			}

			init_chunk_fixed_ = &(((init_chunk_t*)curr_uchar_init_chunk_)->init_fixed);
			// if you need send ABORT later on
			// (i.e.for peer requests 0 streams), this give you the right tag
			last_init_tag_ = ntohl(init_chunk_fixed_->init_tag);
			EVENTLOG1(VERBOSE, "Its initiation-tag is %u", last_init_tag_);

			vlparam_fixed_ = (vlparam_fixed_t*)find_vlparam_from_setup_chunk(
				curr_uchar_init_chunk_, curr_geco_packet_value_len_,
				VLPARAM_HOST_NAME_ADDR);
			if (vlparam_fixed_ != NULL)
			{
				EVENTLOG(VERBOSE, "Found VLPARAM_HOST_NAME_ADDR  ->  do dns");
				// @TODO refers to RFC 4096 SECTION 5.1.2.  Handle Address Parameters DNS QUERY
				do_dns_query_for_host_name_ = true;
			}
#ifdef _DEBUG
			else
			{
				EVENTLOG(VERBOSE,
					"Not found VLPARAM_HOST_NAME_ADDR from INIT CHUNK -> Not do DNS!");
			}
#endif
		}

		/*13.3 CHUNK_ABORT
		 see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
		 B) Rules for packet carrying ABORT:
		 - The receiver of an ABORT MUST accept the packet if the
		 Verification Tag field of the packet matches its own tag and the
		 T bit is not set OR if it is set to its peer's tag and the T bit
		 is set in the Chunk Flags.  Otherwise, the receiver MUST silently
		 discard  packet and take no further action.

		 Reflecting tag T bit = 0
		 The T bit is set to 0 if the sender filled in the Verification Tag
		 expected by the peer. this is reflecting tag
		 the packet carries the receiver's indentification like the receiver name of a letter

		 Reflected tag T bit = 1
		 The T bit is set to 1 if the sender filled in the Verification Tag
		 of its own. this is reflected tag
		 the packet carries the sender's indentification like the sender name of a letter

		 the main role of TBIT is to resolve unnormal predcures due to retx. eg.
		 we recv more than one shutdownack from the correct peer
		 when recv first shutdownack, we delete the channel, and send shutdown complete to peer
		 when recv the second shutdown ack, we still need to

		 */
		if (contains_chunk(CHUNK_ABORT, chunk_types_arr_) > 0)
		{
			uchar* abortchunk = find_first_chunk_of(curr_geco_packet_->chunk,
				curr_geco_packet_value_len_, CHUNK_ABORT);
			bool is_tbit_set = (((chunk_fixed_t*)abortchunk)->chunk_flags & 0x01);
			if ((is_tbit_set && last_veri_tag_ == curr_channel_->remote_tag)
				|| (!is_tbit_set && last_veri_tag_ == curr_channel_->local_tag))
			{
#ifdef _DEBUG
				EVENTLOG2(VERBOSE,
					"Found ABORT  in non-ootb-packet, is_tbit_set(%u), last_init_tag_(%u)-> processing!",
					is_tbit_set, last_init_tag_);
#endif
				is_found_abort_chunk_ = true;
			}
			else
			{
				clear();
				EVENTLOG(NOTICE,
					"Found ABORT  in non-ootb-packet, but verifi tag is illegal-> discard !");
				EVENTLOG(NOTICE,
					"- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
				return recv_geco_packet_but_nootb_abort_chunk_has_ielegal_verifi_tag;
			}
		}

		/*13.4)  see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
		 C) Rules for packet carrying SHUTDOWN COMPLETE:
		 -   When sending a SHUTDOWN COMPLETE, if the receiver of the SHUTDOWN
		 ACK (the peer ) has a channel in our side, then the destination endpoint's tag
		 MUST be used,and the T bit MUST NOT be set.  Only where no TCB exists should
		 the sender use the Verification Tag from the SHUTDOWN ACK, and MUST set the T bit.
		 -   The receiver of a SHUTDOWN COMPLETE shall accept the packet if
		 the Verification Tag field of the packet matches its own tag and
		 the T bit is not set OR if it is set to its peer's tag and the T
		 bit is set in the Chunk Flags.  Otherwise, the receiver MUST
		 silently discard the packet and take no further action.
		 An endpoint MUST ignore the SHUTDOWN COMPLETE if it is not in the
		 SHUTDOWN-ACK-SENT state.*/
		if (contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr_) > 0)
		{
			if (get_curr_channel_state() != ChannelState::ShutdownAckSent)
			{
				EVENTLOG(VERBOSE, "Found SHUTDOWN_COMPLETE  in non-ootb-packet,"
					"at state other than SHUTDOWNACK_SENT -> discard !");
				clear();
				return recv_geco_packet_but_nootb_sdc_recv_otherthan_sdc_ack_sentstate;
			}
			uchar* shutdowncomplete = find_first_chunk_of(curr_geco_packet_->chunk,
				curr_geco_packet_value_len_,
				CHUNK_SHUTDOWN_COMPLETE);
			bool is_tbit_set = (((chunk_fixed_t*)shutdowncomplete)->chunk_flags & FLAG_TBIT_SET);
			if ((is_tbit_set && last_veri_tag_ == curr_channel_->remote_tag)
				|| (!is_tbit_set && last_veri_tag_ == curr_channel_->local_tag))
			{
#ifdef _DEBUG
				EVENTLOG2(VERBOSE,
					"Found SHUTDOWN_COMPLETE  in non-ootb-packet, is_tbit_set(%u), last_init_tag_(%u)-> processing!",
					is_tbit_set, last_init_tag_);
#endif
				is_found_abort_chunk_ = true;
				//reuse this variable to avoid veritag check at the end of this block codes
			}
			else
			{
				EVENTLOG(NOTICE,
					"Found SHUTDOWN_COMPLETE  in non-ootb-packet, but verifi tag is illegal-> discard !");
				clear();
				return recv_geco_packet_but_nootb_sdc_recv_verifitag_illegal;
			}
		}

		/*13.5) see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
		 see E) Rules for packet carrying a SHUTDOWN ACK
		 If the receiver is in COOKIE-ECHOED or COOKIE-WAIT state the
		 procedures in Section 8.4 SHOULD be followed:
		 If the packet contains a SHUTDOWN ACK chunk, the receiver should
		 respond to the sender of the OOTB packet with a SHUTDOWN
		 COMPLETE.  When sending the SHUTDOWN COMPLETE, the receiver of
		 the OOTB packet must fill in the Verification Tag field of the
		 outbound packet with the Verification Tag received in the
		 SHUTDOWN ACK and set the T bit in the Chunk Flags to indicate
		 that the Verification Tag is reflected.
		 */
		if (contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types_arr_) > 0)
		{
			uint state = get_curr_channel_state();
			if (state == ChannelState::CookieEchoed || state == ChannelState::CookieWait)
			{
				EVENTLOG(NOTICE, "Found SHUTDOWN_ACK "
					" in non-ootb-packet  at state cookie echoed or cookie wait state, "
					"-> send SHUTDOWN_COMPLETE to the peer!");
				// should be treated as an Out Of The Blue packet. so use FLAG_TBIT_SET
				uint shutdown_complete_cid = alloc_simple_chunk(
					CHUNK_SHUTDOWN_COMPLETE, FLAG_TBIT_SET);
				simple_chunk_t_ptr_ = complete_simple_chunk(shutdown_complete_cid);
				// this method will internally send all bundled chunks if exceeding packet max
				lock_bundle_ctrl();
				bundle_ctrl_chunk(simple_chunk_t_ptr_);
				unlock_bundle_ctrl();
				send_bundled_chunks();
				free_simple_chunk(shutdown_complete_cid);
				clear();
				return discard;
			}
#ifdef _DEBUG
			else
			{
				EVENTLOG(NOTICE, "Found SHUTDOWN_ACK in non-ootb-packet at state other than "
					"cookie echoed or cookie wait state -> processing!");
			}
#endif
		}

		/* 13.6) see RFC 4960 8.5.1.  Exceptions in Verification Tag Rules
		 D) Rules for packet carrying a COOKIE ECHO
		 -   When sending a COOKIE ECHO, the endpoint MUST use the value of
		 the Initiate Tag received in the INIT ACK.
		 -   The receiver of a COOKIE ECHO follows the procedures in Section 5.2.1.
		 there are many deails in this case where we have to validate cookie jar,
		 here we just print it out and process further in another dedicated method*/
#ifdef _DEBUG
		if (contains_chunk(CHUNK_COOKIE_ECHO, chunk_types_arr_) > 0)
		{
			EVENTLOG(VERBOSE, "Found CHUNK_COOKIE_ECHO in non-ootb-packet -> process further!");
		}
#endif

		/* 13.6)
		 5.2.3.  Unexpected INIT ACK
		 If an INIT ACK is received by an endpoint in any state other than the
		 COOKIE-WAIT state, the endpoint should discard it. An unexpected
		 INIT ACK usually indicates the processing of an old or duplicated INIT chunk.*/
		if (contains_chunk(CHUNK_INIT_ACK, chunk_types_arr_) > 0)
		{
			if (get_curr_channel_state() != ChannelState::CookieWait)
			{
				EVENTLOG(NOTICE,
					"Found INIT_ACK in non-ootb-packet at state other than COOKIE-WAIT -> should_discard_curr_geco_packet_!");
				clear();
				return recv_geco_packet_but_nootb_initack_otherthan_cookiew_state;
			}

			vlparam_fixed_ = (vlparam_fixed_t*)find_vlparam_from_setup_chunk(
				curr_uchar_init_chunk_, curr_geco_packet_value_len_,
				VLPARAM_HOST_NAME_ADDR);
			if (vlparam_fixed_ != NULL)
			{
				EVENTLOG(VERBOSE, "found VLPARAM_HOST_NAME_ADDR  -> DNS QUERY");
				// @TODO refers to RFC 4096 SECTION 5.1.2.  Handle Address Parameters
				// need do DNS QUERY instead of simply ABORT
				do_dns_query_for_host_name_ = true;
			}
		}

		/* 13.7)
		 // finally verify verifi tag in this packet
		 // init chunj must has zero verifi tag value except of it
		 // abort chunk has T bit set cannot that has its own filtering conditions */
		if (!is_found_init_chunk_ && !is_found_abort_chunk_
			&& last_veri_tag_ != curr_channel_->local_tag)
		{
			ERRLOG(MINOR_ERROR, "found channel:non-ootb-packet:check verifi-tag:"
				"this packet's verifi-tag != channel's local-tag -> discard !!");
			clear();
			return recv_geco_packet_but_nootb_packet_verifitag_illegal;
		}
#ifdef _DEBUG
		else
		{
			EVENTLOG(NOTICE, "found channel:non-ootb-packet:check verifi-tag:"
				"this packet's verifi-tag == channel's local-tag -> start disassemble it!");
		}
#endif
	}
	else  // (curr_channel_ == NULL)
	{
		/* 14)
		 * filtering and pre-process OOB chunks that have no channel found
		 * refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets */
		EVENTLOG(INFO, "Process OOTB Packet!");

		/*15)
		 * refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (2)
		 * If the OOTB packet contains an ABORT chunk, the receiver MUST
		 * silently the OOTB packet and take no further action
		 * no need to fetch ecc from it as at this moment we have not connected*/
		if (contains_chunk(CHUNK_ABORT, chunk_types_arr_) > 0)
		{
			clear();
			EVENTLOG(INFO, "Found ABORT in ootb-packet, discarding it !");
			EVENTLOG(VERBOSE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
			return recv_geco_packet_but_it_is_ootb_abort_discard;
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
			EVENTLOG(INFO, "Found SHUTDOWN_ACK in ootb-packet "
				"-> send SHUTDOWN_COMPLETE and return!");

			uint shutdown_complete_cid = alloc_simple_chunk(
				CHUNK_SHUTDOWN_COMPLETE, FLAG_TBIT_SET);
			simple_chunk_t_ptr_ = complete_simple_chunk(shutdown_complete_cid);
			lock_bundle_ctrl();
			bundle_ctrl_chunk(simple_chunk_t_ptr_);
			unlock_bundle_ctrl();
			send_bundled_chunks();
			printf("sinple chunk id %u\n", shutdown_complete_cid);
			free_simple_chunk(shutdown_complete_cid);
			printf("sinple chunk id %u\n", shutdown_complete_cid);
			clear();

			EVENTLOG(VERBOSE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
			return recv_geco_packet_but_it_is_ootb_sdack_send_sdc;
		}

		/*17) refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (6)
		 If the packet contains a SHUTDOWN COMPLETE chunk, the receiver
		 should silently discard the packet and take no further action.
		 this is good because when receiving st-cp chunk, the peer has finished
		 shutdown pharse withdeleting TCB and all related data, channek is NULL
		 is actually what we want*/
		if (contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types_arr_) > 0)
		{
			EVENTLOG(INFO, "Found SHUTDOWN_COMPLETE in OOB packet, discard !");
			clear();
			return recv_geco_packet_but_it_is_ootb_sdc_discard;
		}

		/* 18)
		 * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (7)
		 * If th packet contains  a COOKIE ACK, the SCTP packet should be silently discarded*/
		if (contains_chunk(CHUNK_COOKIE_ACK, chunk_types_arr_) > 0)
		{
			EVENTLOG(INFO, "Found CHUNK_COOKIE_ACK  in OOB packet, discarding it!");
			clear();
			return recv_geco_packet_but_it_is_ootb_cookie_ack_discard;
		}

		/* 19)
		 * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (7)
		 * If th packet contains a "Stale Cookie" ERROR, the SCTP packet should be silently discarded*/
		if (contains_error_chunk(curr_geco_packet_->chunk, curr_geco_packet_value_len_,
			ECC_STALE_COOKIE_ERROR))
		{
			EVENTLOG(INFO, "Found ECC_STALE_COOKIE_ERROR  in OOB packet,discarding it!");
			clear();
			return recv_geco_packet_but_it_is_ootb_stale_cookie_err_discard;
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
		{
			curr_uchar_init_chunk_ = find_first_chunk_of(
				curr_geco_packet_->chunk, curr_geco_packet_value_len_,
				CHUNK_INIT);
		}

		if (curr_uchar_init_chunk_ != NULL)
		{
			EVENTLOG(VERBOSE, "Found INIT CHUNK in OOB packet -> processing it");
			if (last_veri_tag_ != 0)
			{
				EVENTLOG(NOTICE, " but verification_tag in INIT != 0 -> DISCARD! ");
				return recv_geco_packet_but_ootb_init_chunk_has_non_zero_verifi_tag;
			}

			// update last_init_tag_ with value of init tag carried in this chunk
			init_chunk_fixed_ = &(((init_chunk_t*)curr_uchar_init_chunk_)->init_fixed);
			last_init_tag_ = ntohl(init_chunk_fixed_->init_tag);
			EVENTLOG1(VERBOSE, "Found init_tag (%u) from INIT CHUNK", last_init_tag_);

			// we have an instance up listenning on that port just validate params
			// this is normal connection pharse
			if (curr_geco_instance_ != NULL)
			{
				if (curr_geco_instance_->local_port == 0)
				{
					EVENTLOG(MAJOR_ERROR,
						"an instance found, but curr_geco_instance's local port is 0 -> discard !");
					return recv_geco_packet_but_local_instance_has_zero_portnum;
				}

#ifdef _DEBUG
				EVENTLOG(VERBOSE, "curr_geco_instance found -> processing!");
#endif

				vlparam_fixed_ = (vlparam_fixed_t*)find_vlparam_from_setup_chunk(
					curr_uchar_init_chunk_, curr_geco_packet_value_len_,
					VLPARAM_HOST_NAME_ADDR);
				if (vlparam_fixed_ != NULL)
				{
					EVENTLOG(VERBOSE,
						"found VLPARAM_HOST_NAME_ADDR from INIT CHUNK --->  TODO DNS QUERY");
					// TODO refers to RFC 4096 SECTION 5.1.2.  Handle Address Parametersd.
					do_dns_query_for_host_name_ = true;
				}
#ifdef _DEBUG
				else
					EVENTLOG(VERBOSE, "Not VLPARAM_HOST_NAME_ADDR from INIT CHUNK ---> NOT DO DNS!");
				EVENTLOG(VERBOSE,
					"---> Start to pass this INIT CHUNK to disassembl() for further processing!");
#endif
			}  // if (curr_geco_instance_ != NULL) at line 460
			else
			{
				/*20)
				 Refers to RFC 4960 Sectiion 5.1
				 If an endpoint receives an INIT, INIT ACK, or COOKIE ECHO chunk but
				 decides not to establish the new association due to missing mandatory
				 parameters in the received INIT or INIT ACK, invalid parameter values,
				 or lack of local resources, it MUST respond with an ABORT chunk
				 we do not have an instance up listening on that port-> ABORT
				 this may happen when a peer is connecting WITH wrong dest port,
				 or wrong addr type of dest addr, send  ABORT  +  ECC_UNRESOLVABLE_ADDRESS*/
				EVENTLOG(INFO,
					"Not found an instance -> send ABORT "
					"with ECC_PEER_NOT_LISTENNING_ADDR or ECC_PEER_NOT_LISTENNING_PORT");
				is_there_at_least_one_equal_dest_port_ ?
					curr_ecc_code_ =
					ECC_PEER_NOT_LISTENNING_ADDR :
					curr_ecc_code_ =
					ECC_PEER_NOT_LISTENNING_PORT;
				chunkflag2use_ = FLAG_TBIT_UNSET;
				curr_ecc_reason_ = (uchar*)last_dest_addr_;
				curr_ecc_len_ = sizeof(sockaddrunion);
				send_abort_ = true;
			}
		}  // if (init_chunk != NULL)
		else if (contains_chunk(CHUNK_COOKIE_ECHO, chunk_types_arr_) > 0)
		{
			/* 21)
			 * Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (4)
			 * If the packet contains a COOKIE ECHO in the first chunk, process
			 *  it as described in Section 5.1. */
			EVENTLOG(DEBUG, "Found CHUNK_COOKIE_ECHO in ootb packet -> processing it");

			// validate that cookie echo chunk must be the first chunk
			if (((chunk_fixed_t*)(curr_geco_packet_->chunk))->chunk_id != CHUNK_COOKIE_ECHO)
			{
				EVENTLOG(VERBOSE, "but it is not the first chunk in the packet ---> discarding");
				clear();
				return recv_geco_packet_but_ootb_cookie_echo_is_not_first_chunk;
			}
			if (curr_geco_instance_ == NULL)
			{  // cannot find inst for this packet, it does not belong to us. discard it!
				EVENTLOG(VERBOSE, "but cannot found inst for it ---> send abort with ecc");
				// need send abort because peer have channel instance built
				is_there_at_least_one_equal_dest_port_ ?
					curr_ecc_code_ =
					ECC_PEER_NOT_LISTENNING_ADDR :
					curr_ecc_code_ =
					ECC_PEER_NOT_LISTENNING_PORT;
				curr_ecc_reason_ = (uchar*)last_dest_addr_;
				curr_ecc_len_ = sizeof(sockaddrunion);
				chunkflag2use_ = FLAG_TBIT_UNSET;
				send_abort_ = true;
			}
			clear();
			return discard;
		}
		else  //Found unecpected chunks in ootb packet
		{
			/* 22)
			 Refers to RFC 4960 Sectiion 8.4 Handle "Out of the Blue" Packets - (8)
			 The receiver should respond to the sender of OOTB packet with
			 an ABORT.  When sending the ABORT, the receiver of the OOTB
			 packet MUST fill in the Verification Tag field of the outbound
			 packet with the value found in the Verification Tag field of the
			 OOTB packet and set the T bit in the Chunk Flags to indicate that
			 the Verification Tag is reflected.  After sending this ABORT, the
			 receiver of the OOTB packet shall should_discard  the OOTB packet and
			 take no further action.*/
			 // HOWEVER I think rfc is wrong here
			 // the peer is sending unkown chunks to us without
			 // normal connection built,which is likely to be attacks so just discard to save network data
			EVENTLOG(NOTICE, "Found unrecognized chunks in ootb packet -> discard!");
			return discard;
			//send_abort_ = true;
			//curr_ecc_code_ = ECC_UNRECOGNIZED_CHUNKTYPE;
			//curr_ecc_len_ = 0;
			//curr_ecc_reason_ = 0;
		}
	}

SEND_ABORT:
	/*23) may send ABORT to the peer */
	if (send_abort_)
	{
		// we never send abort to a unconnected peer
		if (curr_channel_ == NULL && !send_abort_for_oob_packet_)
		{
			EVENTLOG(VERBOSE,
				"this is ootb packet AND send_abort_for_oob_packet_==FALSE -> not send abort !");
			clear();
			return recv_geco_packet_but_not_send_abort_for_ootb_packet;
		}

		EVENTLOG1(NOTICE, "Send ABORT with ecc code %u", curr_ecc_code_);
		if (chunkflag2use_ < 0)
			curr_channel_ == NULL ?
			chunkflag2use_ = FLAG_TBIT_SET :
			chunkflag2use_ = FLAG_TBIT_UNSET;

		chunk_id_t abort_cid = alloc_simple_chunk(CHUNK_ABORT, chunkflag2use_);
		enter_error_cause(abort_cid, curr_ecc_code_, curr_ecc_reason_, curr_ecc_len_ - 4);

		lock_bundle_ctrl();
		bundle_ctrl_chunk(complete_simple_chunk(abort_cid));
		free_simple_chunk(abort_cid);
		unlock_bundle_ctrl();
		send_bundled_chunks();
		clear();
		return reply_abort;
	}  // 23 send_abort_ == true

	// forward packet value to bundle ctrl module for disassemblings
	disassemle_curr_geco_packet();

	// no need to clear last_src_port_ and last_dest_port_ MAY be used by other functions
	last_src_path_ = -1;
	do_dns_query_for_host_name_ = false;

	EVENTLOG(NOTICE, "- - - - - - - - - - Leave recv_geco_packet() - - - - - - - - - -\n");
	return geco_return_enum::good;
}

int dispatch_layer_t::disassemle_curr_geco_packet()
{
#if defined(_DEBUG)
#if ENABLE_UNIT_TEST
	if (enable_mock_dispatcher_disassemle_curr_geco_packet_)
	{
		EVENTLOG(DEBUG, "Mock::dispatch_layer_t::disassemle_curr_geco_packet() is called");
		return 0;
	}
#else
	EVENTLOG2(DEBUG,
		"- - - ENTER dispatch_layer_t::disassemle_curr_geco_packet():last_src_path_ %u,packetvallen %u",
		last_src_path_, curr_geco_packet_value_len_);
#endif
#endif

	uchar* curr_pos = curr_geco_packet_->chunk; /* points to the first chunk in this pdu */
	uint read_len = 0, chunk_len;
	simple_chunk_t* chunk;

	lock_bundle_ctrl();
	while (read_len < curr_geco_packet_value_len_)
	{
		if (curr_geco_packet_value_len_ - read_len < CHUNK_FIXED_SIZE)
		{
			EVENTLOG(WARNNING_ERROR,
				"dispatch_layer_t::disassemle_curr_geco_packet()::chunk_len illegal !-> return -1 !");
			unlock_bundle_ctrl(&last_src_path_);
			return -1;
		}

		chunk = (simple_chunk_t *)curr_pos;
		chunk_len = ntohs(chunk->chunk_header.chunk_length);
		EVENTLOG2(VERBOSE, "starts process chunk with read_len %u,chunk_len %u", read_len,
			chunk_len);

		if (chunk_len < CHUNK_FIXED_SIZE || chunk_len + read_len > curr_geco_packet_value_len_)
		{
			EVENTLOG(WARNNING_ERROR,
				"dispatch_layer_t::disassemle_curr_geco_packet()::chunk_len illegal !-> return -1 !");
			unlock_bundle_ctrl(&last_src_path_);
			return -1;
		}

		/*
		 * TODO :
		 * Add return values to the chunk-functions, where they can indicate what
		 * to do with the rest of the datagram (i.e. DISCARD after stale COOKIE_ECHO
		 * with tie tags that do not match the current ones)
		 */
		bool data_chunk_received = false;
		int handle_ret = ChunkProcessResult::Good;
		switch (chunk->chunk_header.chunk_id)
		{
		case CHUNK_DATA:
			EVENTLOG(VERBOSE, "***** Diassemble received CHUNK_DATA");
			handle_ret = process_data_chunk((data_chunk_t*)chunk, last_src_path_);
			data_chunk_received = true;
			break;
		case CHUNK_INIT:
			EVENTLOG(VERBOSE, "***** Diassemble received CHUNK_INIT");
			handle_ret = process_init_chunk((init_chunk_t *)chunk);
			break;
		case CHUNK_INIT_ACK:
			EVENTLOG(VERBOSE, "***** Diassemble received CHUNK_INIT_ACK");
			handle_ret = process_init_ack_chunk((init_chunk_t *)chunk);
			break;
		case CHUNK_COOKIE_ECHO:
			EVENTLOG(VERBOSE, "***** Diassemble received CHUNK_COOKIE_ECHO");
			process_cookie_echo_chunk((cookie_echo_chunk_t*)chunk);
			break;
		case CHUNK_SACK:
			EVENTLOG(VERBOSE, "***** Diassemble received CHUNK_SACK");
			handle_ret = process_sack_chunk(last_src_path_, chunk, curr_geco_packet_value_len_);
			break;
		default:
			/*
			 00 - Stop processing this SCTP packet and discard it,
			 do not process any further chunks within it.
			 01 - Stop processing this SCTP packet and discard it, do not process
			 any further chunks within it, and report the unrecognized
			 parameter in an 'Unrecognized Parameter Type' (in either an
			 ERROR or in the INIT ACK).
			 10 - Skip this chunk and continue processing.
			 11 - Skip this chunk and continue processing,
			 but report in an ERROR Chunk using the 'Unrecognized Chunk Type' cause of error.
			 0XC0 = 11000000 */
			switch ((uchar)(chunk->chunk_header.chunk_id & 0xC0))
			{
			case 0x0:  //00
				read_len = curr_geco_packet_value_len_;
#ifdef _DEBUG
				EVENTLOG(DEBUG, "Unknown chunktype -> Stop processing and discard");
#endif
				break;
			case 0x40:  //01
				read_len = curr_geco_packet_value_len_;
				//todo
				handle_ret = send_error_chunk_unrecognized_chunk_type((uchar*)chunk,
					chunk_len);
#ifdef _DEBUG
				EVENTLOG(DEBUG,
					"Unknown chunktype ->  01 - Stop processing, discard it and eport");
#endif
				break;
			case 0x80:  //10
				EVENTLOG(DEBUG,
					"Unknown chunktype ->  10 - Skip this chunk and continue processing.");
				break;
			case 0xC0:  //11
				EVENTLOG(DEBUG,
					" Unknown chunktype -> 11 Skip this chunk and continue processing");
				handle_ret = send_error_chunk_unrecognized_chunk_type((uchar*)chunk,
					chunk_len);
				break;
			default:  // never reach here
				ERRLOG(MINOR_ERROR, "unfound chuntype flag !");
				break;
			}
			break;
		}
		read_len += chunk_len;
		while (read_len & 3)
			++read_len;
		curr_pos = curr_geco_packet_->chunk + read_len;
		if (handle_ret != ChunkProcessResult::Good)  // to break whileloop
			read_len = curr_geco_packet_value_len_;
		EVENTLOG2(VERBOSE, "end process chunk with read_len %u,chunk_len %u", read_len, chunk_len);
		//TODO
	}
	return 0;
}

int dispatch_layer_t::process_data_chunk(data_chunk_t * data_chunk, uint ad_idx)
{
	return 0;
}

/* 1) put init chunk into chunk  array */
/* 2) validate init params */
/* 3) validate source addr */
/* 4) If INIT recv in cookie-wait or cookie-echoed */
/* 5) else if  INIT recv in state other than cookie-wait or cookie-echoed */
/* 6) remove NOT free INIT CHUNK */
int dispatch_layer_t::process_init_chunk(init_chunk_t * init)
{
#if defined(_DEBUG)
#if ENABLE_UNIT_TEST
	if (enable_mock_dispatcher_process_init_chunk_)
	{
		EVENTLOG(DEBUG, "Mock::dispatch_layer_t::disassemle_curr_geco_packet() is called");
		return 0;
	}
#else
	EVENTLOG(VERBOSE, "- - - - Enter process_init_chunk() - - -");
#endif
#endif

	/*1) put init chunk into chunk  array */
	int ret = 0;
	uchar init_cid = alloc_simple_chunk((simple_chunk_t*)init);
	if (get_simple_chunk_id(init_cid) != CHUNK_INIT)
	{
		ERRLOG(MAJOR_ERROR, "1) put init chunk into chunk  array : [wrong chunk type]");
		remove_simple_chunk(init_cid);
		return STOP_PROCESS_CHUNK_FOR_WRONG_CHUNK_TYPE;
	}
#ifdef _DEBUG
	ERRLOG1(DEBUG, "1) put init chunk into chunk  array : [good] : init_cid %d", init_cid);
#endif

	/*2) validate init params*/
	uchar abortcid;
	smctrl_t* smctrl = get_state_machine_controller();
	if (!read_outbound_stream(init_cid) || !read_inbound_stream(init_cid) || !read_init_tag(init_cid))
	{
		EVENTLOG(DEBUG, "2) validate init params [zero streams  or zero init TAG] -> send abort ");

		/*2.1) make and send ABORT with ecc*/
		abortcid = alloc_simple_chunk(CHUNK_ABORT, FLAG_TBIT_UNSET);
		enter_error_cause(abortcid, ECC_INVALID_MANDATORY_PARAM);

		bundle_ctrl_chunk(complete_simple_chunk(abortcid));
		free_simple_chunk(abortcid);

		unlock_bundle_ctrl();
		send_bundled_chunks();

		/*2.2) delete all data of this channel,
		 * smctrl != NULL means current channel MUST exist at this moment */
		if (smctrl != NULL)
		{
			delete_curr_channel();
			on_connection_lost(ConnectionLostReason::invalid_param);
			clear_current_channel();
		}
		return STOP_PROCESS_CHUNK_FOR_INVALID_MANDORY_INIT_PARAMS;
	}

	/*3) validate source addr */
	if (last_source_addr_ == NULL)
	{
		/* 3.1) delete all data of this channel,
		 * smctrl != NULL means current channel MUST exist at this moment */
		if (smctrl == NULL)
		{
			clear_current_channel();
			return STOP_PROCESS_CHUNK_FOR_NULL_CHANNEL;
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
			return STOP_PROCESS_CHUNK_FOR_NULL_SRC_ADDR;
		}
	}
	else
	{
		memcpy(&tmp_addr_, last_source_addr_, sizeof(sockaddrunion));
	}

	ushort inbound_stream;
	ushort outbound_stream;
	uchar init_ack_cid;
	uint init_tag;

	/* 4) RFC 4960 - 5.1.Normal Establishment of an Association - (B)
	 * "Z" shall respond immediately with an INIT ACK chunk.*/
	if (smctrl == NULL)
	{
		EVENTLOG(INFO, "event: received normal init chunk from peer");

		/*4.1) get in out stream number*/
		inbound_stream = std::min(read_outbound_stream(init_cid), get_local_inbound_stream());
		outbound_stream = std::min(read_inbound_stream(init_cid), get_local_outbound_stream());

		/* 4.2) alloc init ack chunk, init tag used as init tsn */
		init_tag = generate_init_tag();
		init_ack_cid = alloc_init_ack_chunk(init_tag,
			curr_geco_instance_->default_myRwnd,
			outbound_stream, inbound_stream,
			init_tag);

		/*4.3) read and validate peer addrlist carried in the received init chunk*/
		assert(my_supported_addr_types_ != 0);
		assert(curr_geco_packet_value_len_ == init->chunk_header.chunk_length);
		tmp_peer_addreslist_size_ = read_peer_addreslist(tmp_peer_addreslist_, (uchar*)init,
			curr_geco_packet_value_len_, my_supported_addr_types_, &tmp_peer_supported_types_);
		if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
		{
			EVENTLOG(NOTICE,
				"process_init_chunk():: UNSUPPOTED ADDR TYPES -> send abort with tbit unset !");
			supported_address_types_t saddrtypes;
			uint len = put_vlp_supported_addr_types((uchar*)&saddrtypes,
				my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV4,
				my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV6, false);
			chunk_id_t abort_cid = alloc_simple_chunk(CHUNK_ABORT, FLAG_TBIT_UNSET);
			enter_error_cause(abort_cid, ECC_PEER_NOT_SUPPORT_ADDR_TYPES, (uchar*)&saddrtypes,
				len);
			lock_bundle_ctrl();
			bundle_ctrl_chunk(complete_simple_chunk(abort_cid));
			free_simple_chunk(abort_cid);
			unlock_bundle_ctrl();
			send_bundled_chunks();
			return discard;
		}

		/*4.4) get local addr list and append them to INIT ACK*/
		tmp_local_addreslist_size_ = get_local_addreslist(tmp_local_addreslist_, last_source_addr_,
			1, tmp_peer_supported_types_, true);
		if (tmp_local_addreslist_size_ > 1)
		{
			// if ==1 mus be last dest addr, as we will put it as src addr in outgoing ip header
			// so do not copy it to avoid repeated addr
			enter_vlp_addrlist(init_ack_cid, tmp_local_addreslist_, tmp_local_addreslist_size_);
		}

		// 4.5) generate and append cookie to INIT ACK
		write_cookie(init_cid, init_ack_cid,
			get_init_fixed(init_cid), get_init_fixed(init_ack_cid),
			get_cookie_lifespan(init_cid),
			/* normal case: no existing channel, set both zero*/
			0, /*local tie tag*/
			0,/*local tie tag*/
			last_dest_port_, last_src_port_,
			tmp_local_addreslist_, tmp_local_addreslist_size_,
			tmp_peer_addreslist_, tmp_peer_addreslist_size_);

		/* 4.6) check unrecognized params*/
		int ret = process_unrecognized_vlparams(init_cid, init_ack_cid);
		if (ret < 0 || ret == ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM)
		{
			/* 6.9) peer's init chunk has icorrect chunk length or
			 stop prcess when meeting unrecognized chunk type
			 both cases should not send init ack-> discard*/
			free_simple_chunk(init_ack_cid);
		}
		else
		{
			/* send all bundled chunks to ensure init ack is the only chunk sent
			 * in the whole geco packet*/
#ifdef  _DEBUG
			EVENTLOG(DEBUG,
				"process_init_acke():: call send_bundled_chunks to ensure init ack is the only chunk sent in the whole geco packet ");
#endif //  _DEBUG
			unlock_bundle_ctrl();
			send_bundled_chunks();

			/* bundle INIT ACK if full will send, may empty bundle and copy init ack*/
			bundle_ctrl_chunk(complete_simple_chunk(init_ack_cid));
			send_bundled_chunks();  // send init ack
			free_simple_chunk(init_ack_cid);
			EVENTLOG(INFO, "event: sent normal init ack chunk peer");
		}
	}
	else // existing channel found
	{
		/* the below codes handle the following cases:
		5.2.1.  INIT Received in COOKIE-WAIT or COOKIE-ECHOED State
		5.2.2. Unexpected INIT in States Other than CLOSED,COOKIE-ECHOED COOKIE-WAIT, and SHUTDOWN-ACK-SENT
		5.2.4. Handle a COOKIE ECHO when a TCB Exists */

#ifdef  _DEBUG
		EVENTLOG1(DEBUG, "smctrl != NULL -> channel exisits -> received INIT chunk in state %u", smctrl->channel_state);
#endif

		ChannelState channel_state = smctrl->channel_state;
		int primary_path = get_primary_path();
		uint init_i_sent_cid;

		/* 5)
		5.2.1.INIT Received in COOKIE-WAIT or COOKIE-ECHOED State  (Item B)
		When responding in either state (COOKIE-WAIT or COOKIE-ECHOED) with
		an INIT ACK, the original parameters are combined with those from the newly received INIT chunk.
		The endpoint shall also generate a State Cookie with the INIT ACK.
		The endpoint uses the parameters sent in its INIT to calculate the State Cookie.
		After that, the endpoint MUST NOT change its state, the T1-init timer
		shall be left running, and the corresponding TCB MUST NOT be
		destroyed.  The normal procedures for handling State Cookies when a
		TCB exists will resolve the duplicate INITs to a single association. */
		if (channel_state == ChannelState::CookieWait)
		{
			/* section 5.2.1 - paragrah 2
			Upon receipt of an INIT in the COOKIE-WAIT state, an endpoint MUST
			respond with an INIT ACK using the same parameters it sent in its
			original INIT chunk (including its Initiate Tag, unchanged).  When
			responding, the endpoint MUST send the INIT ACK back to the same
			address that the original INIT (sent by this endpoint) was sent.*/

			// both tie tags of zero value indicates that connection procedures are not done completely.
			// in other words, we are not connected to Z side although channel is not null
			assert(smctrl->local_tie_tag == 0);
			assert(smctrl->peer_tie_tag == 0);
			assert(curr_channel_->local_tag != 0);
			assert(curr_channel_->remote_tag == 0);

			// make init ack with params from init chunk I sent
			init_ack_cid = alloc_init_ack_chunk(smctrl->my_init_chunk->init_fixed.init_tag,
				smctrl->my_init_chunk->init_fixed.rwnd,
				smctrl->my_init_chunk->init_fixed.outbound_streams,
				smctrl->my_init_chunk->init_fixed.inbound_streams,
				smctrl->my_init_chunk->init_fixed.initial_tsn);

			// append localaddrlist to INIT_ACK
			tmp_local_addreslist_size_ = get_local_addreslist(tmp_local_addreslist_,
				last_source_addr_, 1,
				tmp_peer_supported_types_,
				true /*receivedfrompeer*/);
			enter_vlp_addrlist(init_ack_cid, tmp_local_addreslist_, tmp_local_addreslist_size_);

			// generate cookie and append it to INIT ACK
			write_cookie(init_cid, init_ack_cid,
				get_init_fixed(init_cid), get_init_fixed(init_ack_cid),
				get_cookie_lifespan(init_cid),
				0, 0, /*set both tie tags to zero to indicate channel is not null but connection procedures are not done completely
				in other words, we are not connected to Z side although channel is not null*/
				last_dest_port_, last_src_port_,
				tmp_local_addreslist_, tmp_local_addreslist_size_,
				tmp_peer_addreslist_, tmp_peer_addreslist_size_);

			/* 6.8) check unrecognized params*/
			ret = process_unrecognized_vlparams(init_cid, init_ack_cid);
			if (ret < 0 || ret == ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM)
			{
				/* 6.9) peer's init chunk has icorrect chunk length or
				stop prcess when meeting unrecognized chunk type
				both cases should not send init ack-> discard*/
				free_simple_chunk(init_ack_cid);
			}
			else
			{
				/* 6.10) MUST send INIT ACK caried unknown params to the peer
				* if he has unknown params in its init chunk
				* as we SHOULD let peer's imple to finish the
				* unnormal connection handling precedures*/

				// send all bundled chunks to ensure init ack is the only chunk sent in the whole geco packet
				EVENTLOG1(VERBOSE, "at line 1672 process_init_chunk():CURR BUNDLE SIZE (%d)",
					get_bundle_total_size(get_bundle_controller()));
				unlock_bundle_ctrl();
				send_bundled_chunks();

				// bundle INIT ACK if full will send and empty bundle then copy init ack
				bundle_ctrl_chunk(complete_simple_chunk(init_ack_cid));
				send_bundled_chunks(&smctrl->addr_my_init_chunk_sent_to);
				free_simple_chunk(init_ack_cid);
				EVENTLOG(VERBOSE, "event: initAck sent at state of cookie wait");
			}
		}
		else if (channel_state == ChannelState::CookieEchoed)
		{
			/* section 5.2.1 - paragrah 3 and 6
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

			// because we have set up tie tags in process_init_ack() where :
			// smctrl->local_tie_tag is channel's local tag
			// smctrl->peer_tie_tag is the init tag carried in init ack
			assert(smctrl->local_tie_tag != 0);
			assert(smctrl->peer_tie_tag != 0);
			assert(curr_channel_->local_tag != 0);
			assert(curr_channel_->remote_tag != 0);
			assert(curr_channel_->local_tag == smctrl->local_tie_tag);
			assert(curr_channel_->remote_tag == smctrl->peer_tie_tag);

			// 5.2) validate no new addr aaded from the newly received INIT
			// read and validate peer addrlist carried in the received init chunk
			assert(my_supported_addr_types_ != 0);
			assert(curr_geco_packet_value_len_ == init->chunk_header.chunk_length);
			tmp_peer_addreslist_size_ = read_peer_addreslist(tmp_peer_addreslist_,
				(uchar*)init,
				curr_geco_packet_value_len_, my_supported_addr_types_,
				&tmp_peer_supported_types_);
			if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
			{
				EVENTLOG(NOTICE,
					"process_init_chunk():: UNSUPPOTED ADDR TYPES -> send abort with tbit unset !");
				supported_address_types_t saddrtypes;
				uint len = put_vlp_supported_addr_types((uchar*)&saddrtypes,
					my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV4,
					my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV6, false);
				chunk_id_t abort_cid = alloc_simple_chunk(CHUNK_ABORT, FLAG_TBIT_UNSET);
				enter_error_cause(abort_cid, ECC_PEER_NOT_SUPPORT_ADDR_TYPES,
					(uchar*)&saddrtypes, len);
				lock_bundle_ctrl();
				bundle_ctrl_chunk(complete_simple_chunk(abort_cid));
				free_simple_chunk(abort_cid);
				unlock_bundle_ctrl();
				send_bundled_chunks();
				return discard;
			}

			/*compare if there is new addr presenting*/
			for (uint idx = 0; idx < curr_channel_->remote_addres_size; idx++)
			{
				for (int inner = 0; inner < tmp_peer_addreslist_size_; inner++)
				{
					if (saddr_equals(curr_channel_->remote_addres + idx, tmp_peer_addreslist_ + inner, true) == false)
					{
						EVENTLOG(NOTICE, "new addr found in received INIT at CookieEchoed state -> discard !");
						/* remove NOT free INIT CHUNK before return */
						remove_simple_chunk(init_cid);
						return STOP_PROCESS_CHUNK_FOR_FOUND_NEW_ADDR;
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
				ERRLOG(FALTAL_ERROR_EXIT, "smctrl->my_init_chunk == NULL !");

			/* make and fills init ack*/
			init_ack_cid = alloc_init_ack_chunk(smctrl->my_init_chunk->init_fixed.init_tag,
				smctrl->my_init_chunk->init_fixed.rwnd,
				smctrl->my_init_chunk->init_fixed.outbound_streams,
				smctrl->my_init_chunk->init_fixed.inbound_streams,
				smctrl->my_init_chunk->init_fixed.initial_tsn);

			/*5.6) get local addr list and append them to INIT ACK*/
			tmp_local_addreslist_size_ = get_local_addreslist(tmp_local_addreslist_,
				last_source_addr_, 1, tmp_peer_supported_types_, true);
			enter_vlp_addrlist(init_ack_cid, tmp_local_addreslist_, tmp_local_addreslist_size_);

			/*5.7) generate and append cookie to INIT ACK*/
			write_cookie(init_cid, init_ack_cid, get_init_fixed(init_cid),
				get_init_fixed(init_ack_cid), get_cookie_lifespan(init_cid),
				/* unexpected case: existing channel found, set both NOT zero*/
				smctrl->local_tie_tag, smctrl->peer_tie_tag, last_dest_port_,
				last_src_port_,
				tmp_local_addreslist_, tmp_local_addreslist_size_, tmp_peer_addreslist_,
				tmp_peer_addreslist_size_);

			/* 5.8) check unrecognized params */
			ret = process_unrecognized_vlparams(init_cid, init_ack_cid);
			if (ret < 0 || ret == ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM)
			{
				/* 6.9) peer's init chunk has icorrect chunk length or
				stop prcess when meeting unrecognized chunk type
				both cases should not send init ack-> discard*/
				free_simple_chunk(init_ack_cid);
			}
			else
			{
				/* 5.10) MUST send INIT ACK caried unknown params to the peer
				* if he has unknown params in its init chunk
				* as we SHOULD let peer's imple to finish the
				* unnormal connection handling precedures*/

				/* send all bundled chunks to ensure init ack is the only chunk sent
				* in the whole geco packet*/
				unlock_bundle_ctrl();
				send_bundled_chunks();
				// bundle INIT ACK if full will send and empty bundle then copy init ack
				bundle_ctrl_chunk(complete_simple_chunk(init_ack_cid));
				send_bundled_chunks();  // send init ack
				free_simple_chunk(init_ack_cid);
				EVENTLOG(INTERNAL_EVENT, "event: initAck sent at state of cookie echoed");
			}
		}
		else if (channel_state == ChannelState::ShutdownAckSent)
		{
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
				FLAG_TBIT_UNSET);
			/*send all bundled chunks to ensure init ack is the only chunk sent*/
			EVENTLOG1(VERBOSE, "at line 1 process_init_chunk():CURR BUNDLE SIZE (%d)",
				get_bundle_total_size(get_bundle_controller()));
			unlock_bundle_ctrl();
			send_bundled_chunks();
			bundle_ctrl_chunk(complete_simple_chunk(shutdownackcid));
			send_bundled_chunks();  //send init ack
			free_simple_chunk(shutdownackcid);
			EVENTLOG(INTERNAL_EVENT, "event: initAck sent at state of ShutdownAckSent");
		}
		else
		{
			/* 7) see RFC 4960 - Section 5.2.2
			Unexpected INIT in States Other than CLOSED, COOKIE-ECHOED,
			COOKIE-WAIT, and SHUTDOWN-ACK-SENT
			Unless otherwise stated, upon receipt of an unexpected INIT for this
			association, the endpoint shall generate an INIT ACK with a State
			Cookie.  Before responding, the endpoint MUST check to see if the
			unexpected INIT adds new addresses to the association.*/

			//ChannelState::Connected:
			//ChannelState::ShutdownPending:
			// ChannelState::ShutdownSent:

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
			assert(curr_geco_packet_value_len_ == init->chunk_header.chunk_length);
			tmp_peer_addreslist_size_ = read_peer_addreslist(tmp_peer_addreslist_,
				(uchar*)init,
				curr_geco_packet_value_len_, my_supported_addr_types_,
				&tmp_peer_supported_types_);
			if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
			{
				EVENTLOG(NOTICE,
					"process_init_chunk():: UNSUPPOTED ADDR TYPES -> send abort with tbit unset !");
				supported_address_types_t saddrtypes;
				uint len = put_vlp_supported_addr_types((uchar*)&saddrtypes,
					my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV4,
					my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV6, false);
				chunk_id_t abort_cid = alloc_simple_chunk(CHUNK_ABORT, FLAG_TBIT_UNSET);
				enter_error_cause(abort_cid, ECC_PEER_NOT_SUPPORT_ADDR_TYPES,
					(uchar*)&saddrtypes, len);
				lock_bundle_ctrl();
				bundle_ctrl_chunk(complete_simple_chunk(abort_cid));
				free_simple_chunk(abort_cid);
				unlock_bundle_ctrl();
				send_bundled_chunks();
				return discard;
			}

			/*compare if there is new addr presenting*/
			for (uint idx = 0; idx < curr_channel_->remote_addres_size; idx++)
			{
				for (int inner = 0; inner < tmp_peer_addreslist_size_; inner++)
				{
					if (!saddr_equals(curr_channel_->remote_addres + idx,
						tmp_peer_addreslist_ + inner))
					{
						EVENTLOG(VERBOSE,
							"new addr found in received INIT at CookieEchoed state -> discard !");
						/* remove NOT free INIT CHUNK before return */
						remove_simple_chunk(init_cid);
						return STOP_PROCESS_CHUNK_FOR_FOUND_NEW_ADDR;
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
			init_tag = generate_init_tag();  // todo use safe generate_init_tag
			init_ack_cid = alloc_init_ack_chunk(init_tag,
				curr_channel_->receive_control->my_rwnd,
				curr_channel_->deliverman_control->numSendStreams,
				curr_channel_->deliverman_control->numReceiveStreams,
				smctrl->my_init_chunk->init_fixed.initial_tsn);

			/*7.4) get local addr list and append them to INIT ACK*/
			tmp_local_addreslist_size_ = get_local_addreslist(tmp_local_addreslist_,
				last_source_addr_, 1, tmp_peer_supported_types_, true);
			enter_vlp_addrlist(init_ack_cid, tmp_local_addreslist_, tmp_local_addreslist_size_);

			/*6.7) generate and append cookie to INIT ACK*/
			write_cookie(init_cid, init_ack_cid, get_init_fixed(init_cid),
				get_init_fixed(init_ack_cid), get_cookie_lifespan(init_cid),
				/* unexpected case:  channel existing, set both NOT zero*/
				smctrl->local_tie_tag, smctrl->peer_tie_tag, last_dest_port_,
				last_src_port_,
				tmp_local_addreslist_, tmp_local_addreslist_size_, tmp_peer_addreslist_,
				tmp_peer_addreslist_size_);

			/* 6.8) check unrecognized params*/
			ret = process_unrecognized_vlparams(init_cid, init_ack_cid);
			if (ret < 0 || ret == ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM)
			{
				/* 6.9) peer's init chunk has icorrect chunk length or
				stop prcess when meeting unrecognized chunk type
				both cases should not send init ack-> discard*/
				free_simple_chunk(init_ack_cid);
			}
			else
			{
				/* 6.10) MUST send INIT ACK caried unknown params to the peer
				* if he has unknown params in its init chunk
				* as we SHOULD let peer's imple to finish the
				* unnormal connection handling precedures*/

				/*send all bundled chunks to ensure init ack is the only chunk sent*/
				EVENTLOG1(VERBOSE, "at line 1674 process_init_chunk():CURR BUNDLE SIZE (%d)",
					get_bundle_total_size(get_bundle_controller()));
				assert(
					get_bundle_total_size(get_bundle_controller()) == UDP_GECO_PACKET_FIXED_SIZES);
				unlock_bundle_ctrl();
				send_bundled_chunks();
				// bundle INIT ACK if full will send and empty bundle then copy init ack
				bundle_ctrl_chunk(complete_simple_chunk(init_ack_cid));
				/* trying to send bundle to become more responsive
				* unlock bundle to send init ack as single chunk in the
				* whole geco packet */
				send_bundled_chunks(&smctrl->addr_my_init_chunk_sent_to);
				free_simple_chunk(init_ack_cid);
				EVENTLOG(INTERNAL_EVENT, "event: initAck sent at state of ShutdownSent");
			}
		}
	}// existing channel
	/*6) remove NOT free INIT CHUNK*/
	remove_simple_chunk(init_cid);
	return ret;
}
int dispatch_layer_t::process_unrecognized_vlparams(uint src_cid, uint dest_cid)
{
#ifdef _DEBUG
	EVENTLOG(VERBOSE, "- - - Enter process_unrecognized_vlparams()");
#endif

	if (simple_chunks_[src_cid] == NULL || simple_chunks_[dest_cid] == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "write_cookie()::Invalid chunk ID");
		return -1;
	}

	init_chunk_t* chunk = ((init_chunk_t*)simple_chunks_[src_cid]);
	uchar* curr_vlp_start = chunk->variableParams;
	uint total_len_vlps = chunk->chunk_header.chunk_length - INIT_CHUNK_FIXED_SIZES;

	uint read_len = 0;
	ushort pType;
	ushort pLen;
	vlparam_fixed_t* vlparam_fixed;
	int ret = 0;

	while (read_len < total_len_vlps)
	{
		if (total_len_vlps - read_len < VLPARAM_FIXED_SIZE)
		{
			EVENTLOG(WARNNING_ERROR,
				"remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !");
			return -1;
		}
		//init_ack_str = &chunk->variableParams[curr_write_pos_[dest_chunk_cid]];
		vlparam_fixed = (vlparam_fixed_t*)curr_vlp_start;
		pType = ntohs(vlparam_fixed->param_type);
		pLen = ntohs(vlparam_fixed->param_length);
		// vlp length too short or patial vlp problem
		if (pLen < VLPARAM_FIXED_SIZE || pLen + read_len > total_len_vlps) return -1;

		/* handle unrecognized params */
		else if (pType != VLPARAM_COOKIE_PRESEREASONV &&
			pType != VLPARAM_SUPPORTED_ADDR_TYPES &&
			pType != VLPARAM_IPV4_ADDRESS &&
			pType != VLPARAM_IPV6_ADDRESS &&
			pType != VLPARAM_UNRELIABILITY &&
			pType != VLPARAM_ADDIP &&
			pType != VLPARAM_COOKIE_PRESEREASONV &&
			pType != VLPARAM_COOKIE &&
			pType != VLPARAM_SET_PRIMARY &&
			pType != VLPARAM_UNRELIABILITY)
		{
			if (STOP_PROCESS_PARAM(pType))
			{
				EVENTLOG2(NOTICE, "found unknown parameter type %u len %u in message -> stop",
					pType, pLen);
				enter_error_cause(dest_cid, VLPARAM_UNRECOGNIZED_PARAM, curr_vlp_start, pLen);
				return ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM;
			}
			else if (STOP_PROCES_PARAM_REPORT_EREASON(pType))
			{
				EVENTLOG2(NOTICE,
					"found unknown parameter type %u len %u in message -> stop and report",
					pType, pLen);
				enter_error_cause(dest_cid, VLPARAM_UNRECOGNIZED_PARAM, curr_vlp_start, pLen);
				return ActionWhenUnknownVlpOrChunkType::STOP_PROCES_PARAM_REPORT_EREASON;
			}
			else if (SKIP_PARAM_REPORT_EREASON(pType))
			{
				EVENTLOG2(NOTICE,
					"found unknown parameter type %u len %u in message -> skip and report",
					pType, pLen);
				enter_error_cause(dest_cid, VLPARAM_UNRECOGNIZED_PARAM, curr_vlp_start, pLen);
				ret = ActionWhenUnknownVlpOrChunkType::SKIP_PARAM_REPORT_EREASON;
			}
			else if (SKIP_PARAM(pType))
			{
				EVENTLOG2(NOTICE, "found unknown parameter type %u len %u in message -> skip",
					pType, pLen);
				ret = ActionWhenUnknownVlpOrChunkType::SKIP_PARAM;
			}
		}
		read_len += pLen;
		while (read_len & 3)
			read_len++;
		curr_vlp_start += read_len;
	}

#ifdef _DEBUG
	if (ret == 0)
		EVENTLOG1(DEBUG, "Not find unknown parameter types (ret=%d)", ret);
	EVENTLOG(VERBOSE, "- - - Leave process_unrecognized_vlparams()");
#endif
	return ret;
}
int dispatch_layer_t::process_unrecognized_params_errs_from_initack(chunk_id_t initAckID,
	uint supportedTypes, chunk_id_t * errorchunk, sockaddrunion * preferredDest, bool * destSet,
	bool * peerSupportsIPV4, bool * peerSupportsIPV6, bool * peerSupportsPRSCTP,
	bool * peerSupportsADDIP)
{

	return 0;
}
void dispatch_layer_t::write_cookie(uint initCID, uint initAckID, init_chunk_fixed_t* peer_init,
	init_chunk_fixed_t* local_initack, uint cookieLifetime, uint local_tie_tag,
	uint peer_tie_tag, ushort last_dest_port, ushort last_src_port,
	sockaddrunion local_Addresses[], uint num_local_Addresses, sockaddrunion peer_Addresses[],
	uint num_peer_Addresses)
{
	init_chunk_t* initack = (init_chunk_t*)(simple_chunks_[initAckID]);
	if (initack == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "write_cookie()::Invalid chunk ID");
		return;
	}
	if (initack->chunk_header.chunk_id != CHUNK_INIT_ACK)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "write_cookie()::chunk type not initAck");
		return;
	}
	if (completed_chunks_[initAckID])
	{
		ERRLOG(FALTAL_ERROR_EXIT, "write_cookie()::Invalid chunk ID");
		return;
	}

	cookie_param_t* cookie =
		(cookie_param_t*)(initack->variableParams + curr_write_pos_[initAckID]);
	put_vlp_cookie_fixed(cookie, peer_init, local_initack, cookieLifetime, local_tie_tag,
		peer_tie_tag, last_dest_port, last_src_port, local_Addresses, num_local_Addresses,
		peer_Addresses, num_peer_Addresses);

	uint wr = curr_write_pos_[initAckID];
	curr_write_pos_[initAckID] += COOKIE_PARAM_SIZE;

	EVENTLOG2(VERBOSE, "Building Cookie with %u local, %u peer addresses", num_local_Addresses,
		num_peer_Addresses);
	enter_vlp_addrlist(initAckID, local_Addresses, num_local_Addresses);
	enter_vlp_addrlist(initAckID, peer_Addresses, num_peer_Addresses);

	/* append peer unre to cookie */
	int peer_support_unre = write_vlp_unreliability(initCID, initAckID);

	/* check if endpoint is ADD-IP capable, store result, and append it in cookie */
	if (write_add_ip_chunk(initAckID, initCID) > 0)
	{
		/* check for set primary chunk ? Maybe add this only after Cookie Chunk ! */
		write_set_primary_chunk(initAckID, initCID);
	}

	/* total length of cookie = vlp fixed+cookie fixed*/
	cookie->vlparam_header.param_length = htons(curr_write_pos_[initAckID] - wr);
	/* calculate and write hmac when other fields are all filled*/
	while (curr_write_pos_[initAckID] & 3)
		curr_write_pos_[initAckID]++;

	if (put_hmac(cookie) < 0)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "put_hmac() failed!");
	}

	put_ecn(initAckID, initCID);

	/* if both support PRSCTP, enter our PRSCTP parameter to INIT ACK chunk */
	if ((peer_support_unre >= 0) && support_unreliability())
	{
		/* this is variable-length-data, this fuction will internally do alignment */
		curr_write_pos_[initAckID] +=
			put_init_vlp(&initack->variableParams[curr_write_pos_[initAckID]],
				VLPARAM_UNRELIABILITY);
	}

	/* cookie params is all filledup and now let us align it to 4 by default
	 * the rest of ecn and unre will have a aligned start writing pos  they may need do align internally
	 * here we just confirm it*/
	assert((curr_write_pos_[initAckID] & 3) == 0);
}

ushort dispatch_layer_t::get_local_inbound_stream(uint * geco_inst_id)
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
ushort dispatch_layer_t::get_local_outbound_stream(uint * geco_inst_id)
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

int dispatch_layer_t::get_local_addreslist(sockaddrunion* local_addrlist,
	sockaddrunion *peerAddress, uint numPeerAddresses, uint peer_supported_types,
	bool receivedFromPeer)
{
	EVENTLOG(VERBOSE, "- - - Enter get_local_addreslist()");

	/*1) make sure either curr channel or curr geco instance presents */
	if (curr_channel_ == NULL && curr_geco_instance_ == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT,
			"dispatch_layer_t::get_local_addreslist()::neither assoc nor instance set - error !");
		return -1;
	}

	if (curr_geco_instance_ == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT,
			"get_local_addreslist():: curr_geco_instance_ not set - program error");
		return -1;
	}

	/* 2) Determine address type of peer addres
	 * localHostFound == false:
	 * localhost not found means we are NOT sending msg to ourselves
	 * this is from a normal address, so we need filter out except loopback and cast addres
	 * localHostFound == true:
	 * localhost Found means we are sending msg to ourselves
	 * peer addr is actually our local address, so we need filter out
	 * all illegal addres */
	uint count, tmp;
	IPAddrType filterFlags = (IPAddrType)0;
	bool localHostFound = false, linkLocalFound = false, siteLocalFound = false;
	for (count = 0; count < numPeerAddresses; count++)
	{
		localHostFound = contain_local_addr(peerAddress + count, 1);
		linkLocalFound = transport_layer_->typeofaddr(peerAddress + count, LinkLocalAddrType);
		siteLocalFound = transport_layer_->typeofaddr(peerAddress + count, SiteLocalAddrType);
	}

	/* 3) Should we add @param peerAddress to @param local_addrlist ?
	 * receivedFromPeer == FALSE: I send an INIT with my addresses to the peer
	 * receivedFromPeer == TRUE: I got an INIT with addresses from the peer */
	if (receivedFromPeer == false && localHostFound == true)
	{
		/* 3.1) this means:
		 * I sent an INIT with my addresses to myself
		 * should filter out all illgal-formate addres from my local addr list
		 * and use the rest ones. It is ok if the rest addres include my loopback addr
		 * as i am sending to myself i should use all my local addres
		 */
		filterFlags = AllCastAddrTypes;
#ifdef _DEBUG
		EVENTLOG(DEBUG,
			"get_local_addreslist():: 3.1) I sent an INIT with my addresses to myself ->  filterFlags = AllCastAddrTypes;");
#endif
	}
	else if (receivedFromPeer == false && localHostFound == false)
	{
		/* 3.2) this means:
		 * I sent an INIT with my addresses to peer hosts other than myself
		 * so I should filter out all illegal-formate addres and loopback addres from my localaddrlist
		 * and only use the rest ones (only refers to addres like lan ip 192.168.1.168 or wan ip 220.123.22.21)
		 */
		filterFlags = (IPAddrType)(AllCastAddrTypes | LoopBackAddrType);
#ifdef _DEBUG
		EVENTLOG(DEBUG,
			"get_local_addreslist()::  3.2) I sent an INIT with my addresses to peer hosts other than myself - >  filterFlags = (IPAddrType) ( AllCastAddrTypes | LoopBackAddrType )");
#endif
	}
	else if (receivedFromPeer == true && localHostFound == false)
	{
		/* 3.3) this means:
		 * I received an INIT with addresses from others which is a normal case.
		 * should filter out all illegal-formate addres and loopback addres from my  local addr list
		 * and only use the rest ones (only refers to addres like lan ip 192.168.1.168 or wan ip 220.123.22.21) */
		if (linkLocalFound)
		{
			filterFlags = (IPAddrType)(AllCastAddrTypes | LoopBackAddrType);
		}
		else if (siteLocalFound)
		{
			filterFlags = (IPAddrType)(AllCastAddrTypes | LinkLocalAddrType | LoopBackAddrType);
		}
		else
		{
			filterFlags = (IPAddrType)(AllCastAddrTypes | AllLocalAddrTypes);
		}
#ifdef _DEBUG
		EVENTLOG(DEBUG,
			"get_local_addreslist():: 3.3) I received an INIT with addresses from others which is a normal case. -> unknwn");
#endif
	}
	else  // (receivedFromPeer == true && localHostFound == true)
	{
		/* 3.4) this means:
		 * I received an INIT with addresses from myself
		 * should filter out all  illegal-formate addres from geco instance's local addr list
		 * and use the rest ones. It is ok if the rest addres include my loopback addr
		 * as i am sending init ack to myself i should use all my local addres */
		filterFlags = AllCastAddrTypes;
#ifdef _DEBUG
		EVENTLOG(DEBUG,
			"get_local_addreslist():: 3.4) I received an INIT with addresses from myself -> filterFlags = AllCastAddrTypes");
#endif
	}
#ifdef _DEBUG
	uint ip4count = 0;
#endif
	count = 0;
	bool anyaddr = false;
	/* 4.1) if geco instance has any addr 4 setup, we use default local addr list_*/
	if (curr_geco_instance_->is_inaddr_any)
	{
		anyaddr = true;
		for (tmp = 0; tmp < defaultlocaladdrlistsize_; tmp++)
		{
			if (saddr_family(&(defaultlocaladdrlist_[tmp])) == AF_INET)
			{
				if (peer_supported_types & SUPPORT_ADDRESS_TYPE_IPV4)
				{
					// filter out unwanted local addres and copy the rest ones
					if (!transport_layer_->typeofaddr(&(defaultlocaladdrlist_[tmp]), filterFlags))
					{
						// addr looks good, copy it
						memcpy(&(local_addrlist[count]), &(defaultlocaladdrlist_[tmp]),
							sizeof(sockaddrunion));
						count++;
					}
				}
			}
		}
#ifdef _DEBUG
		ip4count = count;
		EVENTLOG2(DEBUG,
			"get_local_addreslist(): picked up and copied %u local ip4 addresses from INADDR_ANY (defaultlocaladdrlistsize_ %u)",
			ip4count,
			defaultlocaladdrlistsize_);
#endif
	}

	/* 4.2) if geco instance has any addr 6 setup, we use @param defaultlocaladdrlist_*/
	if (curr_geco_instance_->is_in6addr_any)
	{
		anyaddr = true;
		for (tmp = 0; tmp < defaultlocaladdrlistsize_; tmp++)
		{
			if (saddr_family(&(defaultlocaladdrlist_[tmp])) == AF_INET6)
			{
				if (peer_supported_types & SUPPORT_ADDRESS_TYPE_IPV6)
				{
					// filter out unwanted local addres and copy the rest ones
					if (!transport_layer_->typeofaddr(&(defaultlocaladdrlist_[tmp]), filterFlags))
					{
						// addr looks good copy it
						memcpy(&(local_addrlist[count]), &(defaultlocaladdrlist_[tmp]),
							sizeof(sockaddrunion));
						count++;
					}
				}
			}
		}
#ifdef _DEBUG
		EVENTLOG2(DEBUG,
			"get_local_addreslist(): picked up and copied %u local ip6 addresses from INADDR6_ANY (defaultlocaladdrlistsize_ %u)",
			count - ip4count,
			defaultlocaladdrlistsize_);
#endif
	}

	if (anyaddr == false)
	{
		/* 4.3) geco instance has NO any addr (6) setup,
		 * search from local addr list of geco instance*/
		for (tmp = 0; tmp < curr_geco_instance_->local_addres_size; tmp++)
		{
			ushort af = saddr_family(&(curr_geco_instance_->local_addres_list[tmp]));
			if (af == AF_INET)
			{
				if (peer_supported_types & SUPPORT_ADDRESS_TYPE_IPV4)
				{
					if (!transport_layer_->typeofaddr(
						&(curr_geco_instance_->local_addres_list[tmp]), filterFlags))
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
				if (peer_supported_types & SUPPORT_ADDRESS_TYPE_IPV6)
				{
					if (!transport_layer_->typeofaddr(
						&(curr_geco_instance_->local_addres_list[tmp]), filterFlags))
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
				ERRLOG(FALTAL_ERROR_EXIT, "get_local_addreslist(): no such af !");
			}
		}
#ifdef _DEBUG
		EVENTLOG2(DEBUG,
			"get_local_addreslist(): found %u local addresses from inst local addr list (from %u)",
			count, curr_geco_instance_->local_addres_size);
#endif
	}

	if (count == 0)
		ERRLOG(FALTAL_ERROR_EXIT, "get_local_addreslist(): found no addres!");

	EVENTLOG(VERBOSE, "- - - Leave get_local_addreslist()");
	return count;
}

void dispatch_layer_t::delete_curr_channel(void)
{
	uint path_id;
	if (curr_channel_ != NULL)
	{
		for (path_id = 0; path_id < curr_channel_->remote_addres_size; path_id++)
		{
			stop_heart_beat_timer(path_id);
		}
		// fc_stop_timers();         // TODO
		stop_sack_timer();

		/* mark channel as deleted, it will be deleted
		 when get_channel(..) encounters a "deleted" channel*/
		curr_channel_->deleted = true;
		EVENTLOG1(DEBUG, "channel ID %u marked for deletion", curr_channel_->channel_id);
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
		if (curr_geco_instance_->applicaton_layer_cbs.communicationLostNotif != NULL)
		{
			//ENTER_CALLBACK("communicationLostNotif");
			curr_geco_instance_->applicaton_layer_cbs.communicationLostNotif(
				curr_channel_->channel_id, status, curr_channel_->application_layer_dataptr);
			//LEAVE_CALLBACK("communicationLostNotif");
		}
	}
	curr_geco_instance_ = old_ginst;
	curr_channel_ = old_channel;
}

void dispatch_layer_t::on_connection_up(uint status)
{
	//@TODO
}

void dispatch_layer_t::on_peer_restart(void)
{
	assert(curr_geco_instance_ != NULL);
	assert(curr_channel_ != NULL);
	assert(curr_geco_instance_->applicaton_layer_cbs.restartNotif != NULL);
	curr_geco_instance_->applicaton_layer_cbs.restartNotif(
		curr_channel_->channel_id,
		curr_channel_->application_layer_dataptr);
}

void dispatch_layer_t::abort_channel(short error_type, uchar* errordata,
	ushort errordattalen)
{
	assert(curr_channel_->state_machine_control != NULL);
	bool removed = false;
	chunk_id_t abortcid;
	switch (curr_channel_->state_machine_control->channel_state)
	{
	case ChannelState::Closed:
		EVENTLOG(DEBUG, "event: abort in state CLOSED");
		delete_curr_channel();
		clear_current_channel();
		break;
	case ChannelState::CookieWait:
	case ChannelState::CookieEchoed:
	case ChannelState::ShutdownSent:
	case ChannelState::ShutdownAckSent:
		EVENTLOG(DEBUG, "event: abort in ShutdownAckSent --> send abort");
		abortcid = alloc_simple_chunk(CHUNK_ABORT, FLAG_TBIT_UNSET);
		if (error_type > 0)
		{
			enter_error_cause(abortcid, error_type, errordata, errordattalen);
		}
		bundle_ctrl_chunk(complete_simple_chunk(abortcid));
		free_simple_chunk(abortcid);
		unlock_bundle_ctrl();
		send_bundled_chunks();
		//stop init timer
		if (curr_channel_->state_machine_control->init_timer_id !=
			timer_mgr_.timers.end())
		{
			timer_mgr_.delete_timer(curr_channel_->state_machine_control->init_timer_id);
			curr_channel_->state_machine_control->init_timer_id = timer_mgr_.timers.end();
		}
		// delete all data of channel
		delete_curr_channel();
		removed = true;
		break;
	case ChannelState::ShutdownPending:
	case ChannelState::Connected:
	case ChannelState::ShutdownReceived:
		EVENTLOG(DEBUG, "event: abort in ShutdownReceived --> send abort");
		abortcid = alloc_simple_chunk(CHUNK_ABORT, FLAG_TBIT_UNSET);
		if (error_type > 0)
		{
			enter_error_cause(abortcid, error_type, errordata, errordattalen);
		}
		bundle_ctrl_chunk(complete_simple_chunk(abortcid));
		free_simple_chunk(abortcid);
		unlock_bundle_ctrl();
		send_bundled_chunks();
		// delete all data of channel
		delete_curr_channel();
		removed = true;
		break;
	default:
		/* error logging */
		EVENTLOG1(NOTICE,
			"dispatch_layer_t:: abort() in state %02d: unexpected event",
			curr_channel_->state_machine_control->channel_state);
		break;
	}

	if (removed)
	{
		on_connection_lost(ConnectionLostReason::PeerAbortConnection);
		clear_current_channel();
	}
}

/**
 * Defines the callback function that is called when an (INIT, COOKIE, SHUTDOWN etc.) timer expires.
 * @param timerID               ID of timer
 * @param associationIDvoid     pointer to param1, here to an Association ID value, it may be used
 *                              to identify the association, to which the timer function belongs
 * @param unused                pointer to param2 - timers have two params, by default. Not needed here.
 */
static bool sci_timer_expired(timer_id_t& timerID, void* associationIDvoid, void* unused)
{
	return false;
}
ChunkProcessResult dispatch_layer_t::process_init_ack_chunk(init_chunk_t * initAck)
{
	assert(initAck->chunk_header.chunk_id == CHUNK_INIT_ACK);
	ChunkProcessResult return_state = ChunkProcessResult::Good;
	smctrl_t* smctrl = get_state_machine_controller();

	//1) alloc chunk id for the received init ack
	chunk_id_t initAckCID = alloc_simple_chunk((simple_chunk_t*)initAck);
	if (smctrl == NULL)
	{
		remove_simple_chunk(initAckCID);
		ERRLOG(MINOR_ERROR,
			"process_init_ack_chunk(): get_state_machine_controller() returned NULL!");
		return return_state;
	}

	int result;
	int process_further = 0;
	uint state, idx;
	ushort inbound_stream, outbound_stream;
	chunk_id_t errorCID;
	bool preferredSet = false,
		peerSupportsADDIP = false, peerSupportsIPV4 = false,
		peerSupportsIPV6 = false;
	short preferredPath;
	sockaddrunion prefered_primary_addr;
	unsigned int peerSupportedTypes = 0, supportedTypes = 0;

	ChannelState channel_state = smctrl->channel_state;
	if (channel_state == ChannelState::CookieWait)
	{  //2) discard init ack recived in state other than cookie wait

		EVENTLOG(INFO, "event:received init ack in cookie wait state");
		ushort initchunklen = ntohs(smctrl->my_init_chunk->chunk_header.chunk_length);
		if (!read_outbound_stream(initAckCID) || !read_inbound_stream(initAckCID)
			|| !read_init_tag(initAckCID))
		{
			EVENTLOG(DEBUG,
				"2) validate init params [zero streams  or zero init TAG] -> send abort ");

			/*2.1) make and send ABORT with ecc*/
			chunk_id_t abortcid = alloc_simple_chunk(CHUNK_ABORT, FLAG_TBIT_UNSET);
			enter_error_cause(abortcid, ECC_INVALID_MANDATORY_PARAM);

			bundle_ctrl_chunk(complete_simple_chunk(abortcid));
			free_simple_chunk(abortcid);

			unlock_bundle_ctrl();
			send_bundled_chunks();

			/*2.2) delete all data of this channel,
			 * smctrl != NULL means current channel MUST exist at this moment */
			if (smctrl != NULL)
			{
				delete_curr_channel();
				on_connection_lost(ConnectionLostReason::invalid_param);
				clear_current_channel();
			}
			return_state = ChunkProcessResult::StopAndDeleteChannel_ValidateInitParamFailedError;
			return return_state;
		}

		if (last_source_addr_ == NULL)
		{
			/* delete all data of this channel,
			 smctrl != NULL means current channel MUST exist at this moment */
			if (smctrl == NULL)
			{
				clear_current_channel();
				return_state = ChunkProcessResult::StopAndDeleteChannel_LastSrcPortNullError;
				return return_state;
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
				return_state = ChunkProcessResult::StopAndDeleteChannel_LastSrcPortNullError;
				return return_state;
			}
		}
		else
		{
			memcpy(&tmp_addr_, last_source_addr_, sizeof(sockaddrunion));
		}

		/*get in out stream number*/
		inbound_stream = std::min(read_outbound_stream(initAckCID), get_local_inbound_stream());
		outbound_stream = std::min(read_inbound_stream(initAckCID), get_local_outbound_stream());

		/* read and validate peer addrlist carried in the received initack chunk */
		assert(my_supported_addr_types_ != 0);
		assert(curr_geco_packet_value_len_ == initAck->chunk_header.chunk_length);
		tmp_peer_addreslist_size_ = read_peer_addreslist(tmp_peer_addreslist_, (uchar*)initAck,
			curr_geco_packet_value_len_, my_supported_addr_types_, &tmp_peer_supported_types_);
		if ((my_supported_addr_types_ & tmp_peer_supported_types_) == 0)
		{
			supported_address_types_t saddrtypes;
			uint len = put_vlp_supported_addr_types((uchar*)&saddrtypes,
				my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV4,
				my_supported_addr_types_ & SUPPORT_ADDRESS_TYPE_IPV6, false);
			abort_channel(ECC_PEER_NOT_SUPPORT_ADDR_TYPES, (uchar*)&saddrtypes, len);
		}
		ERRLOG(FALTAL_ERROR_EXIT,
			"BAKEOFF: Program error, no common address types in process_init_chunk()");
		set_channel_remote_addrlist(tmp_peer_addreslist_, tmp_peer_addreslist_size_);

		/* initialize channel with infos in init ack*/
		bool peerSupportsPRSCTP = peer_supports_particial_reliability(initAck);
		bool assocSupportsADDIP = false;  // todo

		init_channel(get_rwnd(initAckCID), inbound_stream, outbound_stream,
			get_init_tsn(initAckCID),
			read_init_tag(initAckCID), ntohl(smctrl->my_init_chunk->init_fixed.initial_tsn),
			peerSupportsPRSCTP,
			assocSupportsADDIP);

		EVENTLOG2(VERBOSE,
			"process_init_ack_chunk()::called init_channel(in-streams=%u, out-streams=%u)",
			inbound_stream, outbound_stream);

		// make cookie echo to en to peer
		chunk_id_t cookieecho_cid = alloc_cookie_echo(get_state_cookie_from_init_ack(initAck));
		if (cookieecho_cid < 0)
		{
			EVENTLOG(INFO, "received a initAck without cookie");
			// stop shutdown timer
			if (smctrl->init_timer_id != timer_mgr_.timers.end())
			{
				timer_mgr_.delete_timer(smctrl->init_timer_id);
				smctrl->init_timer_id = timer_mgr_.timers.end();
			}
			missing_mandaory_params_err_t missing_mandaory_params_err;
			missing_mandaory_params_err.numberOfParams = htonl(1);
			missing_mandaory_params_err.params[0] = htons(VLPARAM_COOKIE);
			abort_channel(ECC_MISSING_MANDATORY_PARAM, (uchar*)&missing_mandaory_params_err,
				1 * (sizeof(ushort) + sizeof(uint)));

			unlock_bundle_ctrl();
			smctrl->channel_state = ChannelState::Closed;
			return_state = ChunkProcessResult::StopProcessAndDeleteChannel;
			return return_state;
		}

		chunk_id_t errorCID = alloc_simple_chunk(CHUNK_ERROR, FLAG_TBIT_UNSET);
		process_further = process_unrecognized_vlparams(initAckCID, errorCID);
		if (process_further == -1
			|| process_further == ActionWhenUnknownVlpOrChunkType::STOP_PROCESS_PARAM)
		{
			remove_simple_chunk(initAckCID);
			free_simple_chunk(cookieecho_cid);
			if (errorCID > 0) free_simple_chunk(errorCID);
			// stop shutdown timer
			if (smctrl->init_timer_id != timer_mgr_.timers.end())
			{
				timer_mgr_.delete_timer(smctrl->init_timer_id);
				smctrl->init_timer_id = timer_mgr_.timers.end();
			}
			unlock_bundle_ctrl();
			delete_curr_channel();
			on_connection_lost(ConnectionLostReason::unknown_param);
			clear_current_channel();
			smctrl->channel_state = ChannelState::Closed;
			return_state = ChunkProcessResult::StopProcessAndDeleteChannel;
			return return_state;
		}

		if (process_further == ActionWhenUnknownVlpOrChunkType::STOP_PROCES_PARAM_REPORT_EREASON)
		{
			return_state = ChunkProcessResult::Stop;
		}

		smctrl->cookieChunk = (cookie_echo_chunk_t *)complete_simple_chunk(cookieecho_cid);
		smctrl->local_tie_tag = curr_channel_ == NULL ? 0 : curr_channel_->local_tag;
		smctrl->peer_tie_tag = read_init_tag(initAckCID);
		smctrl->inbound_stream = inbound_stream;
		smctrl->outbound_stream = outbound_stream;
		remove_simple_chunk(cookieecho_cid);
		remove_simple_chunk(initAckCID);

		/* send cookie echo back to peer */
		bundle_ctrl_chunk((simple_chunk_t*)smctrl->cookieChunk);  // not free cookie echo
		if (errorCID != 0)
		{
			bundle_ctrl_chunk(complete_simple_chunk(errorCID));
			free_simple_chunk(errorCID);
		}
		unlock_bundle_ctrl();
		send_bundled_chunks();

		// stop init timer
		if (smctrl->init_timer_id != timer_mgr_.timers.end())
		{
			timer_mgr_.delete_timer(smctrl->init_timer_id);
			smctrl->init_timer_id = timer_mgr_.timers.end();
		}

		//start cookie timer
		channel_state = ChannelState::CookieEchoed;
		smctrl->init_timer_id = timer_mgr_.add_timer(TIMER_TYPE_INIT,
			smctrl->init_timer_interval, &sci_timer_expired, (void *)&smctrl->channel_id,
			NULL);
		EVENTLOG(INFO,
			"event: sent cookie echo to last src addr, stop init timer, starts cookie timer!");
	}
	else if (channel_state == ChannelState::CookieEchoed)
	{
		/* Duplicated initAck, ignore */
		EVENTLOG(NOTICE, "event: duplicatied sctlr_initAck in state CookieEchoed ->discard!");
	}
	else if (channel_state == ChannelState::ShutdownSent)
	{
		/* In this states the initAck is unexpected event. */
		EVENTLOG(NOTICE, "event: received init ack in state ShutdownSent ->discard!");
	}

	smctrl->channel_state = channel_state;
	return return_state;
}

int dispatch_layer_t::process_sack_chunk(uint adr_index, void *sack_chunk, uint totalLen)
{
	EVENTLOG(VERBOSE, "Enter process_sack_chunk()");
	int ret = 0;

leave:
	EVENTLOG(VERBOSE, "Leave process_sack_chunk()");
	return ret;
}

bool dispatch_layer_t::alloc_new_channel(geco_instance_t* instance,
	ushort local_port,
	ushort remote_port,
	uint tagLocal,
	short primaryDestinitionAddress,
	ushort noOfDestinationAddresses,
	sockaddrunion *destinationAddressList)
{
	assert(instance != NULL);
	assert(noOfDestinationAddresses > 0);
	assert(destinationAddressList != NULL);
	assert(primaryDestinitionAddress >= 0);
	assert(primaryDestinitionAddress < noOfDestinationAddresses);

	EVENTLOG5(VERBOSE,
		" alloc_new_channel()::Instance: %u, local port %u, rem.port: %u, local tag: %u, primary: %d",
		instance->dispatcher_name, local_port, remote_port, tagLocal,
		primaryDestinitionAddress);

	curr_channel_ = (channel_t*)geco_malloc_ext(sizeof(channel_t), __FILE__, __LINE__);
	assert(curr_channel_ != NULL);
	curr_channel_->geco_inst = instance;
	curr_channel_->local_port = local_port;
	curr_channel_->remote_port = remote_port;
	curr_channel_->local_tag = tagLocal;
	//curr_channel_->channel_id = mdi_getUnusedAssocId();
	curr_channel_->remote_tag = 0;
	curr_channel_->deleted = false;
	curr_channel_->application_layer_dataptr = NULL;
	curr_channel_->ipTos = instance->default_ipTos;
	curr_channel_->maxSendQueue = instance->default_maxSendQueue;

	// init local addrlist
	int maxMTU;
	if (defaultlocaladdrlistsize_ == 0)
	{//expensicve call, only call it one time
		transport_layer_->get_local_addresses(&defaultlocaladdrlist_, &defaultlocaladdrlistsize_,
			transport_layer_->ip4_socket_despt_ == 0 ?
			transport_layer_->ip6_socket_despt_ :
			transport_layer_->ip4_socket_despt_,
			true, &maxMTU, IPAddrType::AllCastAddrTypes);
	}
	int ii;
	if (instance->is_inaddr_any && instance->is_in6addr_any)
	{
		//use all addrlist
		curr_channel_->local_addres_size = defaultlocaladdrlistsize_;
		curr_channel_->local_addres = defaultlocaladdrlist_;
		EVENTLOG1(VERBOSE,
			"gec inst  is_in6addr_any and is_inaddr_any both true, use defaultlocaladdrlistsize_%d",
			defaultlocaladdrlistsize_);
	}
	else
	{
		curr_channel_->local_addres_size = 0;  //ip6size
		curr_channel_->remote_addres_size = 0;  //ip4size
		for (ii = 0; ii < defaultlocaladdrlistsize_; ii++)
		{
			if (saddr_family(&(defaultlocaladdrlist_[ii])) == AF_INET6)
				curr_channel_->local_addres_size++;
			else if (saddr_family(&(defaultlocaladdrlist_[ii])) == AF_INET)
				curr_channel_->remote_addres_size++;
			else
				ERRLOG(FALTAL_ERROR_EXIT, "no such af !");
		}
		if (instance->is_inaddr_any)
		{
			// only use ip4 addrlist
			curr_channel_->local_addres_size = curr_channel_->remote_addres_size;
			curr_channel_->local_addres = defaultlocaladdrlist_;
			EVENTLOG1(VERBOSE, "gec inst  is_inaddr_any  true, use addres size=%d",
				curr_channel_->local_addres_size);
		}
		else if (instance->is_in6addr_any)  // get all IPv4 addresses
		{
			//only use ip6 addrlist
			curr_channel_->local_addres = defaultlocaladdrlist_ + curr_channel_->remote_addres_size;
			EVENTLOG1(VERBOSE, "gec inst  is_in6addr_any  true, use addres size=%d",
				curr_channel_->local_addres_size);
		}
		else
		{
			// no any is set, use localaddrlist in geco inst
			curr_channel_->local_addres_size = instance->local_addres_size;
			curr_channel_->local_addres = instance->local_addres_list;
			EVENTLOG1(VERBOSE,
				"gec inst  is_inaddr_any false, is_in6addr_any  false, use use localaddrlist in geco inst, addrsize=%d",
				curr_channel_->local_addres_size);
		}
	}
	curr_channel_->is_IN6ADDR_ANY = instance->is_in6addr_any;
	curr_channel_->is_INADDR_ANY = instance->is_inaddr_any;
	curr_channel_->remote_addres_size = noOfDestinationAddresses;
	curr_channel_->remote_addres = destinationAddressList;
	for (auto channelptr : this->channels_)
	{
		if (cmp_channel(*curr_channel_, *channelptr))
		{
			EVENTLOG(NOTICE, "alloc_new_channel()::tried to alloc an existing channel -> return false !");
			geco_free_ext(curr_channel_, __FILE__, __LINE__);
			curr_channel_ = NULL;
			return false;
		}
	}
	curr_channel_->remote_addres =
		(sockaddrunion*)geco_malloc_ext(noOfDestinationAddresses * sizeof(sockaddrunion),
			__FILE__, __LINE__);
	memcpy(curr_channel_->remote_addres, destinationAddressList, noOfDestinationAddresses);

	curr_channel_->flow_control = NULL;
	curr_channel_->reliable_transfer_control = NULL;
	curr_channel_->receive_control = NULL;
	curr_channel_->deliverman_control = NULL;

	/* only pathman, bundling and sctp-control are created at this point, the rest is created
	with mdi_initAssociation */
	curr_channel_->bundle_control = bu_new();
	curr_channel_->path_control = pm_new(noOfDestinationAddresses, primaryDestinitionAddress);
	curr_channel_->state_machine_control = sm_new();
	curr_channel_->locally_supported_PRDCTP = instance->supportsPRSCTP;
	curr_channel_->remotely_supported_PRSCTP = instance->supportsPRSCTP;
	curr_channel_->locally_supported_ADDIP = instance->supportsADDIP;
	curr_channel_->remotely_supported_ADDIP = instance->supportsADDIP;
	channels_.push_back(curr_channel_);
	return true;
}

int dispatch_layer_t::read_addrlist_from_cookie(cookie_echo_chunk_t* cookiechunk,
	uint mySupportedTypes,
	sockaddrunion addresses[MAX_NUM_ADDRESSES],
	uint*peerSupportedAddressTypes,
	sockaddrunion* lastSource)
{
#ifdef _DEBUG
	EVENTLOG(VERBOSE, "Enter read_addrlist_from_cookie()");
#endif

	assert(cookiechunk != NULL);
	assert(cookiechunk->chunk_header.chunk_id == CHUNK_COOKIE_ECHO);
	static int nAddresses;
	static int vl_param_total_length;
	static ushort no_loc_ipv4_addresses, no_remote_ipv4_addresses;
	static ushort no_loc_ipv6_addresses, no_remote_ipv6_addresses;
	static sockaddrunion temp_addresses[MAX_NUM_ADDRESSES];

	no_loc_ipv4_addresses = ntohs(cookiechunk->cookie.no_local_ipv4_addresses);
	no_remote_ipv4_addresses = ntohs(cookiechunk->cookie.no_remote_ipv4_addresses);
	no_loc_ipv6_addresses = ntohs(cookiechunk->cookie.no_local_ipv6_addresses);
	no_remote_ipv6_addresses = ntohs(cookiechunk->cookie.no_remote_ipv6_addresses);
	vl_param_total_length = cookiechunk->chunk_header.chunk_length - CHUNK_FIXED_SIZE
		- COOKIE_FIXED_SIZE;

#ifdef _DEBUG
	EVENTLOG1(VVERBOSE, " Computed total length of vparams : %d",
		vl_param_total_length);
	EVENTLOG2(VVERBOSE, " Num of local/remote IPv4 addresses %u / %u",
		no_loc_ipv4_addresses, no_remote_ipv4_addresses);
	EVENTLOG2(VVERBOSE, " Num of local/remote IPv6 addresses %u / %u",
		no_loc_ipv6_addresses, no_remote_ipv6_addresses);
#endif

	nAddresses = read_peer_addreslist(temp_addresses,
		(uchar*)cookiechunk,
		cookiechunk->chunk_header.chunk_length,
		curr_geco_instance_->supportedAddressTypes,
		peerSupportedAddressTypes,
		false/*ignore dups*/, true/*ignore last src addr*/);

	if ((nAddresses != (no_loc_ipv4_addresses + no_remote_ipv4_addresses +
		no_loc_ipv6_addresses + no_remote_ipv6_addresses)) ||
		(!(*peerSupportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV4) &&
			!(*peerSupportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV6)) ||
			(no_remote_ipv4_addresses > 0
				&& !(*peerSupportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV4)) ||
				(no_remote_ipv6_addresses > 0
					&& !(*peerSupportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV6)) ||
					(no_loc_ipv4_addresses > 0
						&& !(mySupportedTypes & SUPPORT_ADDRESS_TYPE_IPV4)) ||
						(no_loc_ipv6_addresses > 0
							&& !(mySupportedTypes & SUPPORT_ADDRESS_TYPE_IPV6))
		)
	{
		ERRLOG(FALTAL_ERROR_EXIT, "read_addrlist_from_cookie() invalidate addres");
		return -1;
	}

	//copy remote ip4 addrlist
	memcpy(addresses, &temp_addresses[no_loc_ipv4_addresses],
		no_remote_ipv4_addresses * sizeof(sockaddrunion));
	if (no_remote_ipv6_addresses > 0)
		memcpy(&addresses[no_remote_ipv4_addresses],
			&temp_addresses[no_loc_ipv4_addresses + no_remote_ipv4_addresses + no_loc_ipv6_addresses],
			no_remote_ipv6_addresses * sizeof(sockaddrunion));

#ifdef _DEBUG
	EVENTLOG1(VERBOSE, "Leave read_addrlist_from_cookie(remote affrlist size=%d)",
		no_remote_ipv4_addresses + no_remote_ipv6_addresses);
#endif
	return (no_remote_ipv4_addresses + no_remote_ipv6_addresses);
}
void dispatch_layer_t::set_channel_addrlist(sockaddrunion addresses[MAX_NUM_ADDRESSES],
	int noOfAddresses)
{
#ifdef _DEBUG
	EVENTLOG1(VERBOSE,
		"- - - - - Enter set_channel_addrlist(noOfAddresses =%d)", noOfAddresses);
#endif

	assert(curr_channel_ != NULL);
	if (curr_channel_->remote_addres_size > 0 && curr_channel_->remote_addres != NULL)
	{
		geco_free_ext(curr_channel_->remote_addres, __FILE__, __LINE__);
	}
	curr_channel_->remote_addres = (sockaddrunion*)geco_malloc_ext(
		noOfAddresses * sizeof(sockaddrunion), __FILE__, __LINE__);
	assert(curr_channel_->remote_addres != NULL);
	memcpy(curr_channel_->remote_addres, addresses, noOfAddresses * sizeof(sockaddrunion));
	curr_channel_->remote_addres_size = noOfAddresses;

#ifdef _DEBUG
	EVENTLOG1(VERBOSE,
		"- - - - - Leave set_channel_addrlist(curr_channel_->remote_addres_size =%d)",
		curr_channel_->remote_addres_size);
#endif
}
void dispatch_layer_t::process_cookie_echo_chunk(cookie_echo_chunk_t * cookie_echo)
{
	EVENTLOG(VERBOSE, "Enter process_cookie_echo_chunk()");

	/*
	@rememberme:
	cookie_echo_chunk received with channel exists
	or not can shoare the same authentication prodecures
	except of cookie life time handle
	5.1.5 State Cookie Authentication &&
	5.2.4 Hnadle a cookie echo when a TCB exists*/

	/* 5.1.5.1)
	 * Compute a MAC using the TCB data carried in the State Cookie and
	 * the secret key (note the timestamp in the State Cookie MAY be
	 * used to determine which secret key to use).*/
	chunk_id_t cookie_echo_cid = alloc_simple_chunk((simple_chunk_t*)cookie_echo);
	if (cookie_echo->chunk_header.chunk_id != CHUNK_COOKIE_ECHO)
	{
		remove_simple_chunk(cookie_echo_cid);
		EVENTLOG(NOTICE, "cookie_echo->chunk_header.chunk_id != CHUNK_COOKIE_ECHO -> return");
		return;
	}

	/* 5.1.5.2)
	 * Authenticate the State Cookie as one that it previously generated
	 * by comparing the computed MAC against the one carried in the
	 * State Cookie.  If this comparison fails, the SCTP packet,
	 * including the COOKIE ECHO and any DATA chunks, should be silently discarded*/
	if (!verify_hmac(cookie_echo))
	{
		remove_simple_chunk(cookie_echo_cid);
		EVENTLOG(NOTICE, "verify_hmac() failed ! -> return");
		return;
	}

	/* 5.1.5.3)
	 * Compare the port numbers and the Verification Tag contained
	 * within the COOKIE ECHO chunk to the actual port numbers and the
	 * Verification Tag within the SCTP common header of the received
	 * packet.  If these values do not match, the packet MUST be silently discarded.*/
	chunk_id_t initCID = build_init_chunk_from_cookie(cookie_echo);
	chunk_id_t initAckCID = build_init_ack_chunk_from_cookie(cookie_echo);
	uint cookie_remote_tag = read_init_tag(initCID);
	uint cookie_local_tag = read_init_tag(initAckCID);
	uint local_tag = get_local_tag();
	uint remote_tag = get_remote_tag();
	bool valid = true;
	if (last_veri_tag_ != cookie_local_tag)
	{
		EVENTLOG(NOTICE, "validate cookie echo failed as last_veri_tag_ != cookie_local_tag! -> return");
		valid = false;
	}
	if(last_dest_port_ != ntohs(cookie_echo->cookie.dest_port))
	{
		EVENTLOG(NOTICE, "validate cookie echo failed as last_dest_port_ != cookie.dest_port -> return");
		valid = false;
	}
	if(last_src_port_ != ntohs(cookie_echo->cookie.src_port)
	{
		EVENTLOG(NOTICE, "validate cookie echo failed as last_src_port_ != cookie.src_port -> return");
		valid = false;
	}
	if(valid == false)
	{
		remove_simple_chunk(cookie_echo_cid);
		free_simple_chunk(initCID);
		free_simple_chunk(initAckCID);
		EVENTLOG(NOTICE, "validate cookie echo failed ! -> return");
		return;
	}

	/* 5.1.5.4)
	 * Compare the creation timestamp in the State Cookie to the current
	 * local time.If the elapsed time is longer than the lifespan
	 * carried in the State Cookie, then the packet, including the
	 *	COOKIE ECHO and any attached DATA chunks, SHOULD be discarded,
	 *	and the endpoint MUST transmit an ERROR chunk with a "Stale
	 *	Cookie" error cause to the peer endpoint.*/
	chunk_id_t errorCID;
	cookiesendtime_ = ntohl(cookie_echo->cookie.sendingTime);
	currtime_ = get_safe_time_ms();
	cookielifetime_ = cookiesendtime_ - currtime_;
	if (cookielifetime_ > ntohl(cookie_echo->cookie.cookieLifetime))
	{
		bool senderror = true;
		if (curr_channel_ != NULL && local_tag == cookie_local_tag && remote_tag == cookie_remote_tag)
		{
			senderror = false;
		}
		if (senderror == true)
		{
			EVENTLOG2(NOTICE, curr_channel_ == NULL ?
				"process_cookie_echo_chunk()::curr_channel_ == NULL and actual cookielifetime_ %u ms > cookie cookielifetime_ %u -> send error chunk of stale cookie! -> discard packet!" :
				"process_cookie_echo_chunk()::curr_channel_ != NULL and actual cookielifetime_ %u ms > cookie cookielifetime_ %u"
				"and veri tags not matched (local_tag %u : cookie_local_tag %u, remote_tag %u : cookie_remote_tag %u)->"
				"send error chunk of stale cookie! -> discard packet!",
				cookie_echo->cookie.cookieLifetime, cookielifetime_);

			last_init_tag_ = cookie_remote_tag; // peer's init tag in previously sent INIT chunk to us
			uint staleness = htonl(cookielifetime_);
			errorCID = alloc_simple_chunk(CHUNK_ERROR, FLAG_TBIT_UNSET);
			enter_error_cause(errorCID, ECC_STALE_COOKIE_ERROR, (uchar*)&staleness, sizeof(uint));
			bundle_ctrl_chunk(complete_simple_chunk(errorCID));
			free_simple_chunk(errorCID);
			remove_simple_chunk(cookie_echo_cid);
			free_simple_chunk(initCID);
			free_simple_chunk(initAckCID);
			unlock_bundle_ctrl();
			send_bundled_chunks();
			return;
		}
	}

	assert(last_source_addr_ != NULL);
	smctrl_t* smctrl = get_state_machine_controller();
	if (smctrl == NULL)
	{
		EVENTLOG(NOTICE,
			"process_cookie_echo_chunk(): get_state_machine_controller() returned NULL -> call alloc_new_channel() !");
		if (alloc_new_channel(curr_geco_instance_,
			last_dest_port_,
			last_src_port_,
			cookie_local_tag,/*local tag*/
			0,/*primaryDestinationAddress*/
			1, /*noOfDestinationAddresses*/
			last_source_addr_) == false)
		{
			EVENTLOG(NOTICE, "alloc_new_channel() failed ! -> discard!");
			remove_simple_chunk(cookie_echo_cid);
			free_simple_chunk(initCID);
			free_simple_chunk(initAckCID);
			return;
		}
		smctrl = get_state_machine_controller();
		assert(smctrl == NULL);
	}

	ChannelState newstate = UnknownChannelState;
	ChannelState state = smctrl->channel_state;
	EVENTLOG5(DEBUG,
		"State: %u, cookie_remote_tag: %u , cookie_local_tag: %u, remote_tag: %u , local_tag : %u",
		state, cookie_remote_tag, cookie_local_tag, remote_tag, local_tag);

	int SendCommUpNotification = 0;

	//============== Normal Case ============
	if (smctrl->channel_state == Closed)
	{
		EVENTLOG(DEBUG,"event: process_cookie_echo_chunk in state CLOSED -> Normal Case");
		tmp_peer_addreslist_size_ = read_addrlist_from_cookie(cookie_echo,
			curr_geco_instance_->supportedAddressTypes,
			tmp_peer_addreslist_,
			&tmp_peer_supported_types_,
			last_source_addr_);
		if (tmp_peer_addreslist_size_ > 0)
		{
			set_channel_addrlist(tmp_peer_addreslist_, tmp_peer_addreslist_size_);
		}

		init_channel(get_rwnd(initCID),
			read_inbound_stream(initAckCID),
			read_outbound_stream(initAckCID),
			get_init_tsn(initCID),
			cookie_remote_tag,
			get_init_tsn(initAckCID),
			peer_supports_particial_reliability(cookie_echo),
			peer_supports_addip(cookie_echo));
		smctrl->outbound_stream = read_outbound_stream(initAckCID);
		smctrl->inbound_stream = read_inbound_stream(initAckCID);
		EVENTLOG2(VERBOSE, "Set Outbound Stream to %u, Inbound Streams to %u",
			smctrl->outbound_stream, smctrl->inbound_stream);

		//bundle and send cookie ack
		cookie_ack_cid_ = alloc_simple_chunk(CHUNK_COOKIE_ACK, FLAG_TBIT_UNSET);
		bundle_ctrl_chunk(complete_simple_chunk(cookie_ack_cid_));
		free_simple_chunk(cookie_ack_cid_);
		unlock_bundle_ctrl();
		send_bundled_chunks();

		// notification to ULP
		SendCommUpNotification = COMM_UP_RECEIVED_VALID_COOKIE;
		newstate = ChannelState::Connected;
	}
	//============== Sick Cases ============
	else
	{
		//case COOKIE_WAIT:
		//case COOKIE_ECHOED:
		//case ESTABLISHED:
		//case SHUTDOWNPENDING:
		//case SHUTDOWNSENT:
		//case SHUTDOWNRECEIVED:
		//case SHUTDOWNACKSENT:
		EVENTLOG(DEBUG,"event: process_cookie_echo_chunk in state other than CLOSED -> Sick Case");

		cookie_local_tie_tag_ = ntohl(cookie_echo->cookie.local_tie_tag);
		cookie_remote_tie_tag_ = ntohl(cookie_echo->cookie.peer_tie_tag);
		EVENTLOG2(VERBOSE, "cookie_remote_tie_tag ; %u , cookie_local_tie_tag : %u,"
			"remote_tag ; %u , local_tag : %u ",
			cookie_remote_tie_tag_, cookie_local_tie_tag_,
			remote_tag, local_tag);

		if (local_tag == cookie_local_tag)
		{ //ACTION 5.2.4.B OR 5.2.4.D
			if (remote_tag != cookie_remote_tag)
			{//ACTION 5.2.4.B - CONNECTION COLLISION
				EVENTLOG(INFO, "event: recv COOKIE-ECHO, it is sick case of connection collision, take action 5.2.4.B -> go to connected state !");
				newstate = ChannelState::Connected;
				if (state != ChannelState::Connected)
				{
					//we must be at COOKIE_WAIT or COOKIE_ECHOED state at this moment
					// at such case, we must update remote tag
					//TODO
				}
			}
			else
			{//ACTION 5.2.4.D
				//todo
			}
		}
		else
		{//ACTION 5.2.4.A OR 5.2.4.C
			if (remote_tag != cookie_remote_tag && 
				cookie_local_tie_tag_ == smctrl->local_tie_tag &&
				cookie_remote_tie_tag_ == smctrl->peer_tie_tag)
			{//ACTION 5.2.4.A
			 //todo
			}
			else if (remote_tag != cookie_remote_tag &&				
				cookie_local_tie_tag_ == 0 &&
				cookie_remote_tie_tag_ == 0)
			{//ACTION 5.2.4.C
				//todo
			}
			else
			{
				// silently discard
				EVENTLOG(NOTICE, "event: recv COOKIE-ECHO, it is sick case with no matched case -> discard !");
				//todo
			}
		}
	}

	remove_simple_chunk(cookie_echo_cid);
	free_simple_chunk(initCID);
	free_simple_chunk(initAckCID);
	if (newstate != UnknownChannelState)
		smctrl->channel_state = newstate;
	if (SendCommUpNotification == COMM_UP_RECEIVED_VALID_COOKIE)
		on_connection_up(SendCommUpNotification);  //@TODO
	else if (SendCommUpNotification == COMM_UP_RECEIVED_COOKIE_RESTART)
		on_peer_restart();

	EVENTLOG(VERBOSE, "Leave process_cookie_echo_chunk()");
}

uchar* dispatch_layer_t::find_vlparam_from_setup_chunk(uchar * setup_chunk, uint chunk_len,
	ushort param_type)
{
	/*1) validate packet length*/
	uint read_len = CHUNK_FIXED_SIZE + INIT_CHUNK_FIXED_SIZE;
	if (setup_chunk == NULL || chunk_len < read_len)
	{
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
	uchar* curr_pos = setup_chunk + read_len;

	ushort vlp_len;
	uint padding_len;
	vlparam_fixed_t* vlp;

	/*3) parse all vlparams in this chunk*/
	while (read_len < len)
	{
		EVENTLOG2(VVERBOSE, "find_params_from_setup_chunk() : len==%u, processed_len == %u", len,
			read_len);

		if (len - read_len < VLPARAM_FIXED_SIZE)
		{
			return NULL;
		}

		vlp = (vlparam_fixed_t*)(curr_pos);
		vlp_len = ntohs(vlp->param_length);
		if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len)
		{
			return NULL;
		}

		/*4) find param in this chunk*/
		if (ntohs(vlp->param_type) == param_type)
		{
			EVENTLOG1(VERBOSE, "find_params_from_setup_chunk() : Founf chunk type %d-> return",
				param_type);
			return curr_pos;
		}

		read_len += vlp_len;
		padding_len = ((read_len & 3) == 0) ? 0 : (4 - (read_len & 3));
		read_len += padding_len;
		curr_pos = setup_chunk + read_len;
	}  // while

	return NULL;
	}

int dispatch_layer_t::send_geco_packet(char* geco_packet, uint length, short destAddressIndex)
{
#ifdef _DEBUG
	EVENTLOG(VERBOSE, "- - - - Enter send_geco_packet()");
#endif

#if enable_mock_dispatch_send_geco_packet
	EVENTLOG(DEBUG, "Mock::dispatch_layer_t::send_geco_packet() is called");
	return 0;
#endif

	int len = 0;

	assert(geco_packet != NULL);
	assert(length != 0);

	//if( geco_packet == NULL || length == 0 )
	//{
	//	EVENTLOG(DEBUG, "dispatch_layer::send_geco_packet(): no message to send !!!");
	//	len = -1;
	//	goto leave;
	//}

	geco_packet_t* geco_packet_ptr = (geco_packet_t*)(geco_packet + UDP_PACKET_FIXED_SIZE);
	simple_chunk_t* chunk = ((simple_chunk_t*)(geco_packet_ptr->chunk));

	/*1)
	 * when sending OOB chunk without channel found, we use last_source_addr_
	 * carried in OOB packet as the sending dest addr
	 * see recv_geco_packet() for details*/
	sockaddrunion dest_addr;
	sockaddrunion* dest_addr_ptr;
	uchar tos;
	int primary_path;

	if (curr_channel_ == NULL)
	{
		assert(last_source_addr_ != NULL);
		assert(last_init_tag_ != 0);
		assert(last_dest_port_ != 0);
		assert(last_src_port_ != 0);

		//if( last_source_addr_ == NULL || last_init_tag_ == 0 || last_dest_port_ == 0
		//	|| last_src_port_ == 0 )
		//{
		//EVENTLOG(NOTICE, "dispatch_layer::send_geco_packet(): invalid params ");
		//len = -1;
		//goto leave;
		//}

		memcpy(&dest_addr, last_source_addr_, sizeof(sockaddrunion));
		dest_addr_ptr = &dest_addr;
		geco_packet_ptr->pk_comm_hdr.verification_tag = htonl(last_init_tag_);
		last_init_tag_ = 0;  //reset it
		// swap port number
		geco_packet_ptr->pk_comm_hdr.src_port = htons(last_dest_port_);
		geco_packet_ptr->pk_comm_hdr.dest_port = htons(last_src_port_);
		curr_geco_instance_ == NULL ?
			tos = (uchar)IPTOS_DEFAULT :
			tos = curr_geco_instance_->default_ipTos;
		EVENTLOG4(VERBOSE,
			"send_geco_packet() : currchannel is null, use last src addr as dest addr, tos = %u, tag = %x, src_port = %u , dest_port = %u",
			tos, last_init_tag_, last_dest_port_, last_src_port_);
	}  // curr_channel_ == NULL
	else  // curr_channel_ != NULL
	{
		/*2) normal send with channel found*/
		if (destAddressIndex < -1 || destAddressIndex >= (int)curr_channel_->remote_addres_size)
		{
			EVENTLOG1(NOTICE,
				"dispatch_layer::send_geco_packet(): invalid destAddressIndex (%d)!!!",
				destAddressIndex);
			len = -1;
			goto leave;
		}

		if (destAddressIndex != -1)  // 0<=destAddressIndex<remote_addres_size
		{
			/* 3) Use given destination address from current association */
			dest_addr_ptr = curr_channel_->remote_addres + destAddressIndex;
		}
		else
		{
			if (last_source_addr_ == NULL)
			{
				/*5) last src addr is NUll, we use primary path*/
				primary_path = get_primary_path();
				EVENTLOG2(VERBOSE,
					"dispatch_layer::send_geco_packet():sending to primary with index %u (with %u paths)",
					primary_path, curr_channel_->remote_addres_size);
				if (primary_path < 0 || primary_path >= (int)(curr_channel_->remote_addres_size))
				{
					EVENTLOG1(NOTICE,
						"dispatch_layer::send_geco_packet(): could not get primary address (%d)",
						primary_path);
					len = -1;
					goto leave;
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
			assert(last_init_tag_ != 0);
			//if( last_init_tag_ == 0 )
			//{
			//	EVENTLOG(NOTICE,
			//		"dispatch_layer_t::send_geco_packet(): invalid last_init_tag_ 0 !");
			//	len = -1;
			//	goto leave;
			//}
			geco_packet_ptr->pk_comm_hdr.verification_tag = htonl(last_init_tag_);
		}
		/*8) use normal tag stored in curr channel*/
		else
		{
			geco_packet_ptr->pk_comm_hdr.verification_tag = htonl(curr_channel_->remote_tag);
		}

		geco_packet_ptr->pk_comm_hdr.src_port = htons(curr_channel_->local_port);
		geco_packet_ptr->pk_comm_hdr.dest_port = htons(curr_channel_->remote_port);
		tos = curr_channel_->ipTos;
		EVENTLOG4(VERBOSE,
			"dispatch_layer_t::send_geco_packet() : tos = %u, tag = %x, src_port = %u , dest_port = %u",
			tos, curr_channel_->remote_tag, curr_channel_->local_port,
			curr_channel_->remote_port);
	}  // curr_channel_ != NULL

	/*9) calc checksum and insert it MD5*/
	gset_checksum((geco_packet + UDP_PACKET_FIXED_SIZE), length - UDP_PACKET_FIXED_SIZE);

	switch (saddr_family(dest_addr_ptr))
	{
	case AF_INET:
		len = transport_layer_->send_ip_packet(transport_layer_->ip4_socket_despt_, geco_packet,
			length, dest_addr_ptr, tos);
		break;
	case AF_INET6:
		len = transport_layer_->send_ip_packet(transport_layer_->ip6_socket_despt_, geco_packet,
			length, dest_addr_ptr, tos);
		break;
	default:
		ERRLOG(MAJOR_ERROR, "dispatch_layer_t::send_geco_packet() : Unsupported AF_TYPE");
		break;
	}

#ifdef _DEBUG
	ushort port;
	saddr2str(dest_addr_ptr, hoststr_, MAX_IPADDR_STR_LEN, &port);
	EVENTLOG4(VERBOSE, "send_geco_packet()::sent geco packet of %d bytes to %s:%u, sent bytes %d",
		length, hoststr_, ntohs(geco_packet_ptr->pk_comm_hdr.dest_port), len);
#endif

leave:
#ifdef _DEBUG
	EVENTLOG1(VERBOSE, "- - - - Leave send_geco_packet(ret = %d)", len);
#endif

	return (len == (int)length) ? 0 : -1;
}

int dispatch_layer_t::send_bundled_chunks(int * ad_idx /*= NULL*/)
{
#ifdef _DEBUG
	EVENTLOG1(VERBOSE, "- -  - Enter send_bundled_chunks (%d)", ad_idx);
#endif

	int ret = 0;
	bundle_controller_t* bundle_ctrl = (bundle_controller_t*)get_bundle_controller(curr_channel_);

	// no channel exists, so we take the global bundling buffer
	if (bundle_ctrl == NULL)
	{
		EVENTLOG(VERBOSE, "use global bundling buffer");
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
		EVENTLOG(VERBOSE, "sender is LOCKED ---> return");
		ret = 1;
		goto leave;
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
			ret = -1;
			goto leave;
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
			path_param_id = -1;  // use last src path OR primary path
		}
	}
	EVENTLOG1(VERBOSE, "send to path %d ", path_param_id);

	/* try to bundle ctrl or/and sack chunks with data chunks in an packet*/
	char* send_buffer;
	int send_len;
	if (bundle_ctrl->sack_in_buffer)
	{
		stop_sack_timer();

		/* send sacks, by default they go to the last active address,
		 * from which data arrived */
		send_buffer = bundle_ctrl->sack_buf;

		/*
		 * at least sizeof(geco_packet_fixed_t)
		 * at most pointing to the end of SACK chunk */
		send_len = bundle_ctrl->sack_position;
		EVENTLOG1(VERBOSE, "send_bundled_chunks(sack) : send_len == %d ", send_len);

		if (bundle_ctrl->ctrl_chunk_in_buffer)
		{
			ret = bundle_ctrl->ctrl_position - UDP_GECO_PACKET_FIXED_SIZES;
			memcpy(&(send_buffer[send_len]), &(bundle_ctrl->ctrl_buf[UDP_GECO_PACKET_FIXED_SIZES]),
				ret);
			send_len += ret;
			EVENTLOG1(VERBOSE, "send_bundled_chunks(sack+ctrl) : send_len == %d ", send_len);
		}
		if (bundle_ctrl->data_in_buffer)
		{
			ret = bundle_ctrl->data_position - UDP_GECO_PACKET_FIXED_SIZES;
			memcpy(&(send_buffer[send_len]), &(bundle_ctrl->data_buf[UDP_GECO_PACKET_FIXED_SIZES]),
				ret);
			send_len += ret;
			EVENTLOG1(VERBOSE,
				ret == 0 ?
				"send_bundled_chunks(sack+data) : send_len == %d " :
				"send_bundled_chunks(sack+ctrl+data) : send_len == %d ", send_len);
		}
	}
	else if (bundle_ctrl->ctrl_chunk_in_buffer)
	{
		send_buffer = bundle_ctrl->ctrl_buf;
		send_len = bundle_ctrl->ctrl_position;
		EVENTLOG1(VERBOSE, "send_bundled_chunks(ctrl) : send_len == %d ", send_len);
		if (bundle_ctrl->data_in_buffer)
		{
			ret = bundle_ctrl->data_position - UDP_GECO_PACKET_FIXED_SIZES;
			memcpy(&send_buffer[send_len], &(bundle_ctrl->data_buf[UDP_GECO_PACKET_FIXED_SIZES]),
				ret);
			send_len += ret;
			EVENTLOG1(VERBOSE, "send_bundled_chunks(ctrl+data) : send_len == %d ", send_len);
		}
	}
	else if (bundle_ctrl->data_in_buffer)
	{
		send_buffer = bundle_ctrl->data_buf;
		send_len = bundle_ctrl->data_position;
		EVENTLOG1(VERBOSE, "send_bundled_chunks(data) : send_len == %d ", send_len);
	}
	else
	{
		EVENTLOG(VERBOSE, "Nothing to send");
		ret = 1;
		goto leave;
	}
	EVENTLOG1(VERBOSE, "send_len == %d ", send_len);

	/*this should not happen as bundle_xxx_chunk() internally detects
	 * if exceeds MAX_GECO_PACKET_SIZE, if so, it will call */
	if (send_len > MAX_GECO_PACKET_SIZE)
	{
		EVENTLOG5(FALTAL_ERROR_EXIT,
			"send len (%u)  exceeded (%u) - aborting\nsack_position: %u, ctrl_position: %u, data_position: %u",
			send_len, MAX_GECO_PACKET_SIZE, bundle_ctrl->sack_position,
			bundle_ctrl->ctrl_position, bundle_ctrl->data_position);
		ret = -1;
		goto leave;
	}

	if (bundle_ctrl->data_in_buffer && path_param_id > 0)
	{
		set_data_chunk_sent_flag(path_param_id);
	}

	EVENTLOG2(VERBOSE, "sending message len==%u to adress idx=%d", send_len,
		path_param_id);

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

#ifdef _DEBUG
	EVENTLOG(VERBOSE, "- - - Leave send_bundled_chunks()");
#endif

leave:
	return ret;
}

void dispatch_layer_t::bundle_ctrl_chunk(simple_chunk_t * chunk, int * dest_index /*= NULL*/)
{
	EVENTLOG(VERBOSE, "- -  Enter bundle_ctrl_chunk()");
	bundle_controller_t* bundle_ctrl = (bundle_controller_t*)get_bundle_controller(curr_channel_);

	/*1) no channel exists, so we take the global bundling buffer */
	if (bundle_ctrl == NULL)
	{
		EVENTLOG(VERBOSE, "bundle_ctrl_chunk()::use global bundle_ctrl");
		bundle_ctrl = &default_bundle_ctrl_;
	}

	ushort chunk_len = get_chunk_length((chunk_fixed_t*)chunk);
	uint bundle_size = get_bundle_total_size(bundle_ctrl);

	if ((bundle_size + chunk_len) > MAX_GECO_PACKET_SIZE)
	{
		/*2) an packet CANNOT hold all data, we send chunks and get bundle empty*/
		EVENTLOG5(VERBOSE, "bundle_ctrl_chunk()::Chunk Length(bundlesize %u+chunk_len %u = %u),"
			"exceeded MAX_NETWORK_PACKET_VALUE_SIZE(%u) : sending chunk to address %u !",
			bundle_size, chunk_len, bundle_size + chunk_len, MAX_GECO_PACKET_SIZE,
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
	memcpy(&bundle_ctrl->ctrl_buf[bundle_ctrl->ctrl_position], chunk, chunk_len);
	bundle_ctrl->ctrl_position += chunk_len;
	bundle_ctrl->ctrl_chunk_in_buffer = true;
	while (bundle_ctrl->ctrl_position & 3)
		bundle_ctrl->ctrl_position++;

	EVENTLOG3(VERBOSE,
		"bundle_ctrl_chunk():chunklen %u + UDP_GECO_PACKET_FIXED_SIZES(%u) = Total buffer size now (includes pad): %u",
		get_chunk_length((chunk_fixed_t *)chunk), UDP_GECO_PACKET_FIXED_SIZES,
		get_bundle_total_size(bundle_ctrl));

	EVENTLOG(VERBOSE, "- -  Leave bundle_ctrl_chunk()");
}

int dispatch_layer_t::enter_vlp_addrlist(uint chunkid,
	sockaddrunion local_addreslist[MAX_NUM_ADDRESSES], uint local_addreslist_size)
{
	EVENTLOG(DEBUG, "- - - Enter enter_vlp_addrlist()");

	if (local_addreslist_size <= 0)
	{
		ERRLOG(MAJOR_ERROR, "enter_vlp_addrlist()::Invalid local_addreslist_size !");
		return -1;
	}
	if (simple_chunks_[chunkid] == NULL)
	{
		ERRLOG(MAJOR_ERROR, "enter_vlp_addrlist()::Invalid chunk ID!");
		return -1;
	}
	if (completed_chunks_[chunkid])
	{
		ERRLOG(MAJOR_ERROR, "enter_vlp_addrlist()::chunk already completed !");
		return -1;
	}

	uchar* vlp;
	if (simple_chunks_[chunkid]->chunk_header.chunk_id != CHUNK_ASCONF)
	{
		vlp = &((init_chunk_t *)simple_chunks_[chunkid])->variableParams[curr_write_pos_[chunkid]];
	}
	else
	{
		vlp =
			&((asconfig_chunk_t*)simple_chunks_[chunkid])->variableParams[curr_write_pos_[chunkid]];
	}
	curr_write_pos_[chunkid] += put_vlp_addrlist(vlp, local_addreslist, local_addreslist_size);

	EVENTLOG(DEBUG, "- - - Leave enter_vlp_addrlist()");
	return 0;
}

int dispatch_layer_t::read_peer_addreslist(sockaddrunion peer_addreslist[MAX_NUM_ADDRESSES],
	uchar * chunk, uint len, uint my_supported_addr_types,
	uint* peer_supported_addr_types, bool ignore_dups, bool ignore_last_src_addr)
{
	EVENTLOG(DEBUG, "- - - Enter read_peer_addreslist()");

	/*1) validate method input params*/
	static uint read_len;
	static int found_addr_number;
	found_addr_number = 0;
	if (chunk == NULL || peer_addreslist == NULL || len < read_len)
	{
		found_addr_number = -1;
		EVENTLOG(DEBUG, "- - - Leave read_peer_addreslist()");
		return found_addr_number;
	}

	/*2) validate chunk id inside this chunk*/
	simple_chunk_t* init_chunk = (simple_chunk_t*)chunk;
	if (init_chunk->chunk_header.chunk_id == CHUNK_INIT
		|| init_chunk->chunk_header.chunk_id == CHUNK_INIT_ACK)
	{
		read_len = INIT_CHUNK_FIXED_SIZES;
	}
	else if (init_chunk->chunk_header.chunk_id == CHUNK_COOKIE_ECHO)
	{
		read_len = CHUNK_FIXED_SIZE + COOKIE_FIXED_SIZE;
	}
	else
	{
		found_addr_number = -1;
		EVENTLOG(DEBUG, "- - - Leave read_peer_addreslist()");
		return found_addr_number;
	}

	static uchar* curr_pos;
	curr_pos = chunk + read_len;

	static uint vlp_len;
	static vlparam_fixed_t* vlp;
	static ip_address_t* addres;
	static bool is_new_addr;
	static int idx;
	static IPAddrType flags;

	/*3) parse all vlparams in this chunk*/
	while (read_len < len)
	{
		EVENTLOG2(VVERBOSE, "read_peer_addreslist() : len==%u, processed_len == %u", len, read_len);

		if (len - read_len < VLPARAM_FIXED_SIZE)
		{
			EVENTLOG(WARNNING_ERROR,
				"remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !");
			found_addr_number = -1;
			EVENTLOG(DEBUG, "- - - Leave read_peer_addreslist()");
			return found_addr_number;
		}

		vlp = (vlparam_fixed_t*)curr_pos;
		vlp_len = ntohs(vlp->param_length);
		// vlp length too short or patial vlp problem
		if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len)
		{
			found_addr_number = -1;
			EVENTLOG(DEBUG, "- - - Leave read_peer_addreslist()");
			return found_addr_number;
		}

		ushort paratype = ntohs(vlp->param_type);
		/* determine the falgs from last source addr
		 * then this falg will be used to validate other found addres*/
		if (paratype == VLPARAM_IPV4_ADDRESS || paratype == VLPARAM_IPV6_ADDRESS)
		{
			bool b1, b2, b3;
			if (!(b1 = contain_local_addr(last_source_addr_, 1)))
			{
				/* this is from a normal address,
				 * furtherly filter out except loopbacks */
				if ((b2 = transport_layer_->typeofaddr(last_source_addr_, LinkLocalAddrType)))  //
				{
					flags = (IPAddrType)(AllCastAddrTypes | LoopBackAddrType);
				}
				else if ((b3 = transport_layer_->typeofaddr(last_source_addr_, SiteLocalAddrType)))  // filtered
				{
					flags = (IPAddrType)(AllCastAddrTypes | LoopBackAddrType | LinkLocalAddrType);
				}
				else
				{
					flags = (IPAddrType)(AllCastAddrTypes | AllLocalAddrTypes);
				}
			}
			else
			{
				/* this is from a loopback, use default flag*/
				flags = AllCastAddrTypes;
			}
			EVENTLOG3(DEBUG, "localHostFound: %d,  linkLocalFound: %d, siteLocalFound: %d", b1, b2,
				b3);
		}

		/*4) validate received addresses in this chunk*/
		switch (paratype)
		{
		case VLPARAM_IPV4_ADDRESS:
			if ((my_supported_addr_types & SUPPORT_ADDRESS_TYPE_IPV4))
			{  // use peer addrlist that we can support, ignoring unsupported addres
			   // validate if exceed max num addres allowed
				if (found_addr_number < MAX_NUM_ADDRESSES)
				{
					addres = (ip_address_t*)curr_pos;
					// validate vlp type and length
					if (IS_IPV4_ADDRESS_PTR_NBO(addres))
					{
						uint ip4_saddr = ntohl(addres->dest_addr_un.ipv4_addr);
						// validate addr itself
						if (!IN_CLASSD(ip4_saddr) && !IN_EXPERIMENTAL(ip4_saddr)
							&& !IN_BADCLASS(ip4_saddr) && INADDR_ANY != ip4_saddr
							&& INADDR_BROADCAST != ip4_saddr)
						{
							peer_addreslist[found_addr_number].sa.sa_family =
								AF_INET;
							peer_addreslist[found_addr_number].sin.sin_port = 0;
							peer_addreslist[found_addr_number].sin.sin_addr.s_addr =
								addres->dest_addr_un.ipv4_addr;

							if (!transport_layer_->typeofaddr(
								&peer_addreslist[found_addr_number],
								flags))  // NOT contains the addr type of [flags]
							{
								//current addr duplicated with a previous found addr?
								is_new_addr = true;  // default as new addr
								if (ignore_dups)
								{
									for (idx = 0; idx < found_addr_number; idx++)
									{
										if (saddr_equals(&peer_addreslist[found_addr_number], &peer_addreslist[idx], true))
										{
											is_new_addr = false;
										}
									}
								}

								if (is_new_addr)
								{
									found_addr_number++;
									if (peer_supported_addr_types != NULL) (*peer_supported_addr_types) |=
										SUPPORT_ADDRESS_TYPE_IPV4;
#ifdef _DEBUG
									saddr2str(&peer_addreslist[found_addr_number - 1], hoststr_,
										sizeof(hoststr_), 0);
									EVENTLOG1(VERBOSE, "Found NEW IPv4 Address = %s", hoststr_);
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
					else  // IS_IPV4_ADDRESS_PTR_HBO(addres) == false
					{
						ERRLOG(MAJOR_ERROR, "ip4 vlp has problem, stop read addresses");
						break;
					}
				}
			}
			break;
		case VLPARAM_IPV6_ADDRESS:
			if ((my_supported_addr_types & SUPPORT_ADDRESS_TYPE_IPV6))
			{  // use peer addrlist that we can support, ignoring unsupported addres
				/*6) pass by other validates*/
				if (found_addr_number < MAX_NUM_ADDRESSES)
				{
					addres = (ip_address_t*)curr_pos;
					if (IS_IPV6_ADDRESS_PTR_NBO(addres))
					{
#ifdef WIN32
						if (!IN6_IS_ADDR_UNSPECIFIED(
							&addres->dest_addr_un.ipv6_addr) && !IN6_IS_ADDR_MULTICAST(&addres->dest_addr_un.ipv6_addr)
							&& !IN6_IS_ADDR_V4COMPAT(&addres->dest_addr_un.ipv6_addr))
#else
						if (!IN6_IS_ADDR_UNSPECIFIED(
							addres->dest_addr_un.ipv6_addr.s6_addr) && !IN6_IS_ADDR_MULTICAST(addres->dest_addr_un.ipv6_addr.s6_addr)
							&& !IN6_IS_ADDR_V4COMPAT(addres->dest_addr_un.ipv6_addr.s6_addr))
#endif
						{

							// fillup addrr
							peer_addreslist[found_addr_number].sa.sa_family =
								AF_INET6;
							peer_addreslist[found_addr_number].sin6.sin6_port = 0;
							peer_addreslist[found_addr_number].sin6.sin6_flowinfo = 0;
#ifdef HAVE_SIN6_SCOPE_ID
							foundAddress[found_addr_number].sin6.sin6_scope_id = 0;
#endif
							memcpy(peer_addreslist[found_addr_number].sin6.sin6_addr.s6_addr,
								&(addres->dest_addr_un.ipv6_addr), sizeof(struct in6_addr));

							if (!transport_layer_->typeofaddr(
								&peer_addreslist[found_addr_number],
								flags))  // NOT contains the addr type of [flags]
							{
								// current addr duplicated with a previous found addr?
								is_new_addr = true;  // default as new addr
								if (ignore_dups)
								{
									for (idx = 0; idx < found_addr_number; idx++)
									{
										if (saddr_equals(&peer_addreslist[found_addr_number], &peer_addreslist[idx], true))
										{
											is_new_addr = false;
										}
									}
								}

								if (is_new_addr)
								{
									found_addr_number++;
									if (peer_supported_addr_types != NULL) (*peer_supported_addr_types) |=
										SUPPORT_ADDRESS_TYPE_IPV6;
#ifdef _DEBUG
									saddr2str(&peer_addreslist[found_addr_number - 1], hoststr_,
										sizeof(hoststr_), 0);
									EVENTLOG1(VERBOSE, "Found NEW IPv6 Address = %s", hoststr_);
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
					ERRLOG(WARNNING_ERROR, "Too many addresses found during IPv4 reading");
				}
		}
			break;
		case VLPARAM_SUPPORTED_ADDR_TYPES:
			if (peer_supported_addr_types != NULL)
			{
				supported_address_types_t* sat = (supported_address_types_t*)curr_pos;
				int size = ((vlp_len - VLPARAM_FIXED_SIZE) / sizeof(ushort)) - 1;
				while (size >= 0)
				{
					*peer_supported_addr_types |=
						ntohs(sat->address_type[size]) == VLPARAM_IPV4_ADDRESS ?
						SUPPORT_ADDRESS_TYPE_IPV4 : SUPPORT_ADDRESS_TYPE_IPV6;
					size--;
				}
				EVENTLOG1(VERBOSE,
					"Found VLPARAM_SUPPORTED_ADDR_TYPES, update peer_supported_addr_types now it is (%d)",
					*peer_supported_addr_types);
			}
			break;
	}
		read_len += vlp_len;
		while (read_len & 3)
			++read_len;
		curr_pos = chunk + read_len;
}  // while

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
			if ((last_source_addr_->sa.sa_family == AF_INET ?
				SUPPORT_ADDRESS_TYPE_IPV4 :
				SUPPORT_ADDRESS_TYPE_IPV6)
				& my_supported_addr_types)
			{
				memcpy(&peer_addreslist[found_addr_number], last_source_addr_,
					sizeof(sockaddrunion));
				EVENTLOG2(VERBOSE,
					"Added also last_source_addr_ to the addresslist at index %u,found_addr_number = %u!",
					found_addr_number, found_addr_number + 1);
				found_addr_number++;
			}
		}
	}

	EVENTLOG(DEBUG, "- - - Leave read_peer_addreslist()");
	return found_addr_number;
}

inline bool dispatch_layer_t::contain_local_addr(sockaddrunion* addr_list, uint addr_list_num)
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
				EVENTLOG1(VERBOSE,
					"contains_local_host_addr():Found IPv4 loopback address ! Num: %u",
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
				EVENTLOG1(VERBOSE,
					"contains_local_host_addr():Found IPv6 loopback address ! Num: %u",
					addr_list_num);
				ret = true;
			}
			break;
		default:
			ERRLOG(MAJOR_ERROR, "contains_local_host_addr():no such addr family!");
			ret = false;
			}
	}

	/*2) otherwise try to find from local addr list stored in curr geco instance*/
	if (curr_geco_instance_ != NULL)
	{
		if (curr_geco_instance_->local_addres_size > 0)
		{
			for (idx = 0; idx < curr_geco_instance_->local_addres_size; ++idx)
			{
				for (ii = 0; ii < addr_list_num; ++ii)
				{
					if (saddr_equals(addr_list + ii, curr_geco_instance_->local_addres_list + idx))
					{
						ret = true;
						EVENTLOG(VERBOSE,
							"contains_local_host_addr():Found same address from curr_geco_instance_");
					}
				}
			}
		}
		else
		{ /*3 otherwise try to find from global local host addres list if geco instace local_addres_size is 0*/
			for (idx = 0; idx < defaultlocaladdrlistsize_; idx++)
			{
				for (ii = 0; ii < addr_list_num; ++ii)
				{
					if (saddr_equals(addr_list + ii, defaultlocaladdrlist_ + idx))
					{
						ret = true;
						EVENTLOG(VERBOSE,
							"contains_local_host_addr():Found same address from defaultlocaladdrlist_");
					}
				}
			}
		}
	}
	/*4 find from global local host addres list if geco instance NULL*/
	else
	{
		for (idx = 0; idx < defaultlocaladdrlistsize_; idx++)
		{
			for (ii = 0; ii < addr_list_num; ++ii)
			{
				if (saddr_equals(addr_list + ii, defaultlocaladdrlist_ + idx))
				{
					ret = true;
					EVENTLOG(VERBOSE,
						"contains_local_host_addr():Found same address from defaultlocaladdrlist_");
				}
			}
		}
	}
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
			"remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !");
		return -1;
	}

	if (foundAddress == NULL || n < 1 || n > MAX_NUM_ADDRESSES)
	{
		EVENTLOG(FALTAL_ERROR_EXIT,
			"remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !");
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
		EVENTLOG2(VERBOSE, "read_peer_addreslist() : len==%u, processed_len == %u", len, read_len);

		if (len - read_len < VLPARAM_FIXED_SIZE)
		{
			EVENTLOG(WARNNING_ERROR,
				"remainning bytes not enough for VLPARAM_FIXED_SIZE(4 bytes) invalid !");
			return -1;
		}

		vlp = (vlparam_fixed_t*)curr_pos;
		vlp_len = ntohs(vlp->param_length);
		if (vlp_len < VLPARAM_FIXED_SIZE || vlp_len + read_len > len) return -1;

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
					foundAddress->sin.sin_addr.s_addr = addres->dest_addr_un.ipv4_addr;
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
		while (read_len & 3)
			++read_len;
		curr_pos = init_chunk->variableParams + read_len;
			}  // while
	return 1;
		}
uchar* dispatch_layer_t::find_first_chunk_of(uchar * packet_value, uint packet_val_len,
	uint chunk_type)
{
	uint chunk_len = 0;
	uint read_len = 0;
	uint padding_len;
	chunk_fixed_t* chunk;
	uchar* curr_pos = packet_value;

	while (read_len < packet_val_len)
	{
		EVENTLOG3(VVERBOSE, "find_first_chunk_of(%u)::packet_val_len=%d, read_len=%d", chunk_type,
			packet_val_len, read_len);

		if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
		{
			ERRLOG(MINOR_ERROR,
				"find_first_chunk_of():not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !");
			return NULL;
		}

		chunk = (chunk_fixed_t*)curr_pos;
		chunk_len = get_chunk_length(chunk);

		if (chunk_len < CHUNK_FIXED_SIZE)
		{
			ERRLOG1(MINOR_ERROR,
				"find_first_chunk_of():chunk_len (%u) < CHUNK_FIXED_SIZE(4 bytes)!", chunk_len);
			return NULL;
		}
		if (chunk_len + read_len > packet_val_len)
		{
			ERRLOG3(MINOR_ERROR,
				"find_first_chunk_of():chunk_len(%u) + read_len(%u) < packet_val_len(%u)!",
				chunk_len, read_len, packet_val_len);
			return NULL;
		}

		if (chunk->chunk_id == chunk_type) return curr_pos;

		read_len += chunk_len;
		while (read_len & 3)
			++read_len;
		curr_pos = packet_value + read_len;
	}
	return NULL;
}

bool dispatch_layer_t::contains_error_chunk(uchar * packet_value, uint packet_val_len,
	ushort error_cause)
{
	uint chunk_len = 0;
	uint read_len = 0;
	uint padding_len;
	chunk_fixed_t* chunk;
	uchar* curr_pos = packet_value;
	vlparam_fixed_t* err_chunk;

	while (read_len < packet_val_len)
	{
		EVENTLOG3(VVERBOSE, "contains_error_chunk(error_cause %u)::packet_val_len=%d, read_len=%d",
			error_cause, packet_val_len, read_len);

		if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
		{
			EVENTLOG(MINOR_ERROR,
				"remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !");
			return false;
		}

		chunk = (chunk_fixed_t*)curr_pos;
		chunk_len = get_chunk_length(chunk);
		if (chunk_len < CHUNK_FIXED_SIZE || chunk_len + read_len > packet_val_len) return false;

		if (chunk->chunk_id == CHUNK_ERROR)
		{
			EVENTLOG(VERBOSE, "contains_error_chunk()::Error Chunk Found");
			uint err_param_len = 0;
			uchar* simple_chunk;
			uint param_len = 0;
			// search for target error param
			while (err_param_len < chunk_len - CHUNK_FIXED_SIZE)
			{
				if (chunk_len - CHUNK_FIXED_SIZE - err_param_len < VLPARAM_FIXED_SIZE)
				{
					EVENTLOG(MINOR_ERROR,
						"remainning bytes not enough for CHUNK_FIXED_SIZE(4 bytes) invalid !");
					return false;
				}

				simple_chunk = &((simple_chunk_t*)chunk)->chunk_value[err_param_len];
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
		while (read_len & 3)
			++read_len;
		curr_pos = packet_value + read_len;
	}
	return false;
}

uint dispatch_layer_t::find_chunk_types(uchar* packet_value, uint packet_val_len,
	uint* total_chunk_count)
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
		EVENTLOG2(VVERBOSE, "find_chunk_types()::packet_val_len=%d, read_len=%d", packet_val_len,
			read_len);

		if (packet_val_len - read_len < CHUNK_FIXED_SIZE)
		{
			ERRLOG(MINOR_ERROR,
				"find_chunk_types()::INCOMPLETE CHUNK_FIXED_SIZE(4 bytes) invalid !");
			return result;
		}

		chunk = (chunk_fixed_t*)curr_pos;
		chunk_len = get_chunk_length(chunk);

		if (chunk_len < CHUNK_FIXED_SIZE)
		{
			ERRLOG1(MINOR_ERROR, "find_chunk_types():chunk_len (%u) < CHUNK_FIXED_SIZE(4 bytes)!",
				chunk_len);
			return result;
		}
		if (chunk_len + read_len > packet_val_len)
		{
			ERRLOG3(MINOR_ERROR,
				"find_chunk_types():chunk_len(%u) + read_len(%u) < packet_val_len(%u)!",
				chunk_len, read_len, packet_val_len);
			return result;
		}

		if (chunk->chunk_id <= 30)
		{
			result |= (1 << chunk->chunk_id);
			EVENTLOG2(VERBOSE, "find_chunk_types()::Chunktype %u,result:%s", chunk->chunk_id,
				Bitify(sizeof(result) * 8, (char*)&result));
		}
		else
		{
			result |= (1 << 31);
			EVENTLOG2(VERBOSE, "find_chunk_types()::Chunktype %u,setting bit 31,result %s",
				chunk->chunk_id, Bitify(sizeof(result) * 8, (char*)&result));
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

bool dispatch_layer_t::cmp_geco_instance(const geco_instance_t& a, const geco_instance_t& b)
{
	/* compare local port*/
	if (a.local_port != b.local_port)
	{
		return false;
	}
	else
	{
		is_there_at_least_one_equal_dest_port_ = true;
	}

	if (!a.is_in6addr_any && !b.is_in6addr_any && !a.is_inaddr_any && !b.is_inaddr_any)
	{
		int i, j;
		/*find if at least there is an ip addr thate quals*/
		for (i = 0; i < a.local_addres_size; i++)
		{
			for (j = 0; j < b.local_addres_size; j++)
			{
				if (saddr_equals(&(a.local_addres_list[i]), &(b.local_addres_list[j]), true))
				{
					return true;
				}
			}
		}
		return false;
	}
	else
	{
		/* one has IN_ADDR_ANY OR IN6_ADDR_ANY : return equal ! */
		return true;
	}
}

geco_instance_t* dispatch_layer_t::find_geco_instance_by_transport_addr(sockaddrunion* dest_addr,
	ushort dest_port)
{
	if (geco_instances_.size() == 0)
	{
		ERRLOG(MAJOR_ERROR,
			"dispatch_layer_t::find_geco_instance_by_transport_addr()::geco_instances_.size() == 0");
		return NULL;
	}

	/* search for this endpoint from list*/
	tmp_geco_instance_.local_port = dest_port;
	tmp_geco_instance_.local_addres_size = 1;
	tmp_geco_instance_.local_addres_list = dest_addr;
	tmp_geco_instance_.is_in6addr_any = false;
	tmp_geco_instance_.is_inaddr_any = false;
	// as we use saddr_equals() to compare addr which internally compares addr type
	// so it is not required actually can removed
	//tmp_geco_instance_.supportedAddressTypes = address_type;

	is_there_at_least_one_equal_dest_port_ = false;
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

channel_t* dispatch_layer_t::find_channel_by_transport_addr(sockaddrunion * src_addr,
	ushort src_port, ushort dest_port)
{
	tmp_channel_.remote_addres_size = 1;
	tmp_channel_.remote_addres = &tmp_addr_;

	switch (saddr_family(src_addr))
	{
	case AF_INET:
		tmp_channel_.remote_addres[0].sa.sa_family = AF_INET;
		tmp_channel_.remote_addres[0].sin.sin_addr.s_addr = s4addr(src_addr);
		tmp_channel_.remote_addres[0].sin.sin_port = src_addr->sin.sin_port;
		tmp_channel_.remote_port = src_port;
		tmp_channel_.local_port = dest_port;
		tmp_channel_.deleted = false;
		break;
	case AF_INET6:
		tmp_channel_.remote_addres[0].sa.sa_family = AF_INET6;
		memcpy(&(tmp_channel_.remote_addres[0].sin6.sin6_addr.s6_addr), (s6addr(src_addr)),
			sizeof(struct in6_addr));
		tmp_channel_.remote_addres[0].sin6.sin6_port = src_addr->sin6.sin6_port;
		tmp_channel_.remote_port = src_port;
		tmp_channel_.local_port = dest_port;
		tmp_channel_.deleted = false;
		break;
	default:
		EVENTLOG1(FALTAL_ERROR_EXIT,
			"find_channel_by_transport_addr():Unsupported Address Family %d in find_channel_by_transport_addr()",
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
				"find_channel_by_transport_addr():Found channel that should be deleted, with id %u",
				result->channel_id);
			result = NULL;
		}
		else
		{
			EVENTLOG1(VERBOSE, "find_channel_by_transport_addr():Found valid channel with id %u",
				result->channel_id);
		}
	}
	else
	{
		EVENTLOG(VERBOSE,
			"find_channel_by_transport_addr()::channel indexed by transport address not in list");
	}

	return result;
}

bool dispatch_layer_t::cmp_channel(const channel_t& tmp_channel, const channel_t& b)
{
	EVENTLOG2(VERBOSE, "cmp_endpoint_by_addr_port(): checking ep A[id=%d] and ep B[id=%d]",
		tmp_channel.channel_id, b.channel_id);
	if (tmp_channel.remote_port == b.remote_port && tmp_channel.local_port == b.local_port)
	{
		uint i, j;
		/*find if at least there is an ip addr thate quals*/
		for (i = 0; i < tmp_channel.remote_addres_size; i++)
		{
#ifdef _DEBUG
			char buf[MAX_IPADDR_STR_LEN];
			saddr2str(&tmp_channel.remote_addres[i], buf, MAX_IPADDR_STR_LEN,
				NULL);
			EVENTLOG2(VERBOSE, "temp.remote_addres[%d]::%s", i, buf);
#endif
			for (j = 0; j < b.remote_addres_size; j++)
			{
#ifdef _DEBUG
				saddr2str(&(b.remote_addres[j]), buf, MAX_IPADDR_STR_LEN, NULL);
				EVENTLOG2(VERBOSE, "b.remote_addres[%d]::%s", j, buf);
#endif
				if (saddr_equals(&(tmp_channel.remote_addres[i]), &(b.remote_addres[j]), true))
				{
					if (!tmp_channel.deleted && !b.deleted)
					{
#ifdef _DEBUG
						saddr2str(&(b.remote_addres[j]), buf,
							MAX_IPADDR_STR_LEN, NULL);
						EVENTLOG2(VERBOSE, "cmp_endpoint_by_addr_port():found equal channel"
							"set last_src_path_ to index %u, addr %s", j, buf);
#endif
						last_src_path_ = j;
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
	 * we can receive this packet means that dest addr is good no matter it is
	 * ip4 or ip6, it maybe different addr type from the one in inst, which cause null inst found.
	 *
	 * this case will be specially treated after the call to validate_dest_addr()
	 * reason is there is a special case that when channel not found as src addr unequals
	 * and inst not found as dest addr type(ip4 vs ip6 for example, see explaination above)  unequals,
	 * if this packet is setup chunk, we probably
	 * stil can find a previous channel with the a new src addr found in init chunk address parameters,
	 * old src port and old dest port, and this precious channel must have a non-null inst;
	 * so here we return true to let the follwoing codes to handle this case.
	 */
	if (curr_geco_instance_ == NULL && curr_channel_ == NULL) return true;

	// either channel or inst is NULL
	// or both are not null

	// here we have checked src addr in find channel mtd now
	// we need make sure dst src is also presenting in channel's
	// local_addr_list. if not, just discard it.
	if (curr_channel_ != NULL)
	{
		/* 2) check if dest saadr and type in curr_channel_'s local addresses list*/
		for (uint j = 0; j < curr_channel_->local_addres_size; j++)
		{
			// all channels' addr unions MUST have the port setup same to the individual one
			// channel->remote port = all remote ports in remote addr list
			// channel->local port = all local port pports in local addt list = geco instance locla port
			// so dest port  must be equal to the one found in local addres list
			if (saddr_equals(&curr_channel_->local_addres[j], dest_addr))
			{
				EVENTLOG(VVERBOSE, "dispatch_layer_t::validate_dest_addr()::found equal dest addr");
				return true;
			}
		}
	}

	if (curr_geco_instance_ != NULL)
	{
		ushort af = saddr_family(dest_addr);
		if (curr_geco_instance_->is_inaddr_any && curr_geco_instance_->is_in6addr_any)
		{            //we supports both of ip4and6
			if (af == AF_INET || af == AF_INET6)
				return true;
			else
				*curr_ecc_reason_ = AF_INET | AF_INET6;
		}
		else if (curr_geco_instance_->is_in6addr_any && !curr_geco_instance_->is_inaddr_any)
		{            //we only supports ip6
			if (af == AF_INET6)
				return true;
			else
				*curr_ecc_reason_ = AF_INET6;
		}
		else if (!curr_geco_instance_->is_in6addr_any && curr_geco_instance_->is_inaddr_any)
		{            //we only supports ip4
			if (af == AF_INET) return true;
			else
				*curr_ecc_reason_ = AF_INET;
		}
		else  //!curr_geco_instance_->is_inaddr_any && !curr_geco_instance_->is_in6addr_any
		{  // we found inst in compare_geco_instance(), here return true
			return true;
		}
	}
	return false;
}

