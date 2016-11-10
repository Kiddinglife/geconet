#include <iostream>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "geco-net-common.h"
#include "geco-net-dispatch.h"
#include "geco-net.h"

TEST(MULP, test_initialize_and_free_library)
{
	initialize_library();
	free_library();
}

TEST(MULP, test_mulp_get_lib_params)
{
	//precondition lib has been inited
	initialize_library();

	lib_params_t lib_infos;
	mulp_get_lib_params(&lib_infos);
	ASSERT_EQ(lib_infos.checksum_algorithm, MULP_CHECKSUM_ALGORITHM_MD5);
	ASSERT_EQ(lib_infos.delayed_ack_interval, 200);
	ASSERT_EQ(lib_infos.send_ootb_aborts, true);
	ASSERT_EQ(lib_infos.support_dynamic_addr_config, true);
	ASSERT_EQ(lib_infos.support_particial_reliability, true);

	free_library();
}

TEST(MULP, test_mulp_set_lib_params)
{
	//precondition lib has been inited
	initialize_library();

	lib_params_t lib_infos;
	mulp_get_lib_params(&lib_infos);

	lib_infos.checksum_algorithm = MULP_CHECKSUM_ALGORITHM_CRC32C;
	lib_infos.delayed_ack_interval = 50; // must be smaller than 500ms
	lib_infos.send_ootb_aborts = false;
	lib_infos.support_dynamic_addr_config = false;
	lib_infos.support_particial_reliability = false;
	mulp_set_lib_params(&lib_infos);

	mulp_get_lib_params(&lib_infos);
	ASSERT_EQ(lib_infos.checksum_algorithm, MULP_CHECKSUM_ALGORITHM_CRC32C);
	ASSERT_EQ(lib_infos.delayed_ack_interval, 50);
	ASSERT_EQ(lib_infos.send_ootb_aborts, false);
	ASSERT_EQ(lib_infos.support_dynamic_addr_config, false);
	ASSERT_EQ(lib_infos.support_particial_reliability, false);

	free_library();
}

/**
 * allocatePort Allocate a given port.
 * @return usable port otherwise 0 if port is occupied.
 */
extern unsigned char portsSeized[65536];
extern unsigned int numberOfSeizedPorts;
extern unsigned short
unused(unsigned short port);
TEST(MULP, test_unused_port)
{
	//test initial values
	ASSERT_EQ(numberOfSeizedPorts, 0);
	for (int i = 0; i < 65536; i++)
	{
		ASSERT_EQ(portsSeized[i], 0);
	}

	//test unoccupied port
	ASSERT_EQ(unused(1234), 1234);
	ASSERT_EQ(numberOfSeizedPorts, 1);

	//test occupied port
	ASSERT_EQ(unused(1234), 0);
	ASSERT_EQ(numberOfSeizedPorts, 1);

	//should exit if port value > UINT16_MAX, which is overflowed uint16
	//ASSERT_EQ(unused(655355),123456);
}

/**
 * seizePort return a free port number.
 * @return free port.
 */
extern unsigned short
allocport(void);
/**
 * releasePort frees a previously used port.
 * @param portSeized port that is to be freed.
 */
extern void
freeport(unsigned short portSeized);
TEST(MULP, test_alloc_and_free_port)
{
	ushort port = allocport();
	ASSERT_EQ(numberOfSeizedPorts, 1);
	freeport(port);
	ASSERT_EQ(numberOfSeizedPorts, 0);
	numberOfSeizedPorts = 65535;
	port = allocport();
	ASSERT_EQ(port, 0);
}

extern int myRWND;
extern uint ipv4_sockets_geco_instance_users;
extern uint ipv6_sockets_geco_instance_users;
extern int defaultlocaladdrlistsize_;
extern sockaddrunion* defaultlocaladdrlist_;
extern std::vector<geco_instance_t*> geco_instances_;
TEST(MULP, test_mulp_mulp_new_and_delete_geco_instnce)
{
	//precondition lib has been inited
	initialize_library();
	lib_params_t lib_infos;
	mulp_get_lib_params(&lib_infos);
	geco_instance_t* curr_geco_instance_;
	int instid;
	bool fip4 = false, fip6 = false;
	char ip4addrstr[MAX_IPADDR_STR_LEN];
	char ip6addrstr[MAX_IPADDR_STR_LEN];
	for (int i = 0; i < defaultlocaladdrlistsize_; i++)
	{
		if (!fip4 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET)
		{
			fip4 = true;
			saddr2str(&defaultlocaladdrlist_[i], ip4addrstr, MAX_IPADDR_STR_LEN);
			if (fip6)
				break;
		}
		if (!fip6 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET6)
		{
			fip6 = true;
			saddr2str(&defaultlocaladdrlist_[i], ip6addrstr, MAX_IPADDR_STR_LEN);
			if (fip4)
				break;
		}
	}
	unsigned short localPort;
	unsigned short noOfInStreams;
	unsigned short noOfOutStreams;
	unsigned int noOfLocalAddresses;
	unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN];
	ulp_cbs_t ULPcallbackFunctions;

	//ip6 any and ip4 any
	localPort = 123;
	noOfInStreams = 32;
	noOfOutStreams = 32;
	noOfLocalAddresses = 2;
	strcpy((char*)localAddressList[0], "0.0.0.0");
	strcpy((char*)localAddressList[1], "::0");
	ULPcallbackFunctions =
	{ 0 };
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];
	ASSERT_EQ(curr_geco_instance_->local_port, localPort);
	ASSERT_EQ(curr_geco_instance_->noOfInStreams, noOfInStreams);
	ASSERT_EQ(curr_geco_instance_->noOfOutStreams, noOfOutStreams);
	ASSERT_EQ(curr_geco_instance_->is_inaddr_any, true);
	ASSERT_EQ(curr_geco_instance_->is_in6addr_any, true);
	ASSERT_EQ(curr_geco_instance_->use_ip4, true);
	ASSERT_EQ(curr_geco_instance_->use_ip6, true);
	ASSERT_EQ(curr_geco_instance_->use_ip6, true);
	ASSERT_EQ(curr_geco_instance_->supportedAddressTypes,
		SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 1);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 1);
	mulp_delete_geco_instance(instid);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

	//ip6 not any and ip4 any
	localPort = 124;
	strcpy((char*)localAddressList[0], "0.0.0.0");
	strcpy((char*)localAddressList[1], ip6addrstr);
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];
	ASSERT_EQ(curr_geco_instance_->local_port, localPort);
	ASSERT_EQ(curr_geco_instance_->is_inaddr_any, true);
	ASSERT_EQ(curr_geco_instance_->is_in6addr_any, false);
	ASSERT_EQ(curr_geco_instance_->use_ip4, true);
	ASSERT_EQ(curr_geco_instance_->use_ip6, true);
	ASSERT_EQ(curr_geco_instance_->supportedAddressTypes,
		SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 1);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 1);
	mulp_delete_geco_instance(instid);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

	//ip6 any and ip4 not any
	localPort = 125;
	strcpy((char*)localAddressList[0], "127.0.0.1");
	strcpy((char*)localAddressList[1], "::0");
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	int lastinstid = instid;
	curr_geco_instance_ = geco_instances_[instid];
	ASSERT_EQ(curr_geco_instance_->local_port, localPort);
	ASSERT_EQ(curr_geco_instance_->is_inaddr_any, false);
	ASSERT_EQ(curr_geco_instance_->is_in6addr_any, true);
	ASSERT_EQ(curr_geco_instance_->use_ip4, true);
	ASSERT_EQ(curr_geco_instance_->use_ip6, true);
	ASSERT_EQ(curr_geco_instance_->supportedAddressTypes,
		SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 1);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 1);

	//ip6 not any and ip4 not any
	localPort = 126;
	strcpy((char*)localAddressList[0], "127.0.0.1");
	strcpy((char*)localAddressList[1], "::1");
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];
	ASSERT_EQ(curr_geco_instance_->local_port, localPort);
	ASSERT_EQ(curr_geco_instance_->is_inaddr_any, false);
	ASSERT_EQ(curr_geco_instance_->is_in6addr_any, false);
	ASSERT_EQ(curr_geco_instance_->use_ip4, true);
	ASSERT_EQ(curr_geco_instance_->use_ip6, true);
	ASSERT_EQ(curr_geco_instance_->supportedAddressTypes,
		SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 2);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 2);
	mulp_delete_geco_instance(lastinstid);
	mulp_delete_geco_instance(instid);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

	//ip6 any
	localPort = 127;
	noOfLocalAddresses = 1;
	strcpy((char*)localAddressList[0], "::0");
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];
	ASSERT_EQ(curr_geco_instance_->local_port, localPort);
	ASSERT_EQ(curr_geco_instance_->is_inaddr_any, false);
	ASSERT_EQ(curr_geco_instance_->is_in6addr_any, true);
	ASSERT_EQ(curr_geco_instance_->use_ip4, false);
	ASSERT_EQ(curr_geco_instance_->use_ip6, true);
	ASSERT_EQ(curr_geco_instance_->supportedAddressTypes,
		SUPPORT_ADDRESS_TYPE_IPV6);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 1);
	mulp_delete_geco_instance(instid);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

	//ip4 any
	localPort = 128;
	noOfLocalAddresses = 1;
	strcpy((char*)localAddressList[0], "0.0.0.0");
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];
	ASSERT_EQ(curr_geco_instance_->local_port, localPort);
	ASSERT_EQ(curr_geco_instance_->is_inaddr_any, true);
	ASSERT_EQ(curr_geco_instance_->is_in6addr_any, false);
	ASSERT_EQ(curr_geco_instance_->use_ip4, true);
	ASSERT_EQ(curr_geco_instance_->use_ip6, false);
	ASSERT_EQ(curr_geco_instance_->supportedAddressTypes,
		SUPPORT_ADDRESS_TYPE_IPV4);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 1);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);
	mulp_delete_geco_instance(instid);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

	//ip6
	localPort = 129;
	noOfLocalAddresses = 1;
	strcpy((char*)localAddressList[0], ip6addrstr);
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];
	ASSERT_EQ(curr_geco_instance_->local_port, localPort);
	ASSERT_EQ(curr_geco_instance_->is_inaddr_any, false);
	ASSERT_EQ(curr_geco_instance_->is_in6addr_any, false);
	ASSERT_EQ(curr_geco_instance_->use_ip4, false);
	ASSERT_EQ(curr_geco_instance_->use_ip6, true);
	ASSERT_EQ(curr_geco_instance_->supportedAddressTypes,
		SUPPORT_ADDRESS_TYPE_IPV6);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 1);
	mulp_delete_geco_instance(instid);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

	//ip4
	localPort = 130;
	noOfLocalAddresses = 1;
	strcpy((char*)localAddressList[0], ip4addrstr);
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];
	ASSERT_EQ(curr_geco_instance_->local_port, localPort);
	ASSERT_EQ(curr_geco_instance_->is_inaddr_any, false);
	ASSERT_EQ(curr_geco_instance_->is_in6addr_any, false);
	ASSERT_EQ(curr_geco_instance_->use_ip4, true);
	ASSERT_EQ(curr_geco_instance_->use_ip6, false);
	ASSERT_EQ(curr_geco_instance_->supportedAddressTypes,
		SUPPORT_ADDRESS_TYPE_IPV4);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 1);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

	//ip4 and ip6 that are not found in local addr list, should cause fatal error exits
	//localPort = 131;
	//noOfLocalAddresses = 2;
	//strcpy((char*)localAddressList[0], "10.0.0.113");
	//strcpy((char*)localAddressList[1], "fe80::e5e2:146e:25a2:4015");
	//instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams, noOfLocalAddresses, localAddressList, ULPcallbackFunctions);

	//ip4 and ip6  one of them  is not found in local addr list, should cause fatal error exits
	//localPort = 132;
	//noOfLocalAddresses = 2;
	//strcpy((char*)localAddressList[0], "10.0.0.114");
	//strcpy((char*)localAddressList[1], "fe80::e5e2:146e:25a2:4015");
	//instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams, noOfLocalAddresses, localAddressList, ULPcallbackFunctions);

	//commons
	ASSERT_EQ(curr_geco_instance_->supportsPRSCTP,
		lib_infos.support_particial_reliability);
	ASSERT_EQ(curr_geco_instance_->supportsADDIP,
		lib_infos.support_dynamic_addr_config);
	ASSERT_EQ(curr_geco_instance_->default_rtoInitial, RTO_INITIAL);
	ASSERT_EQ(curr_geco_instance_->default_validCookieLife,
		VALID_COOKIE_LIFE_TIME);
	ASSERT_EQ(curr_geco_instance_->default_validCookieLife,
		VALID_COOKIE_LIFE_TIME);
	ASSERT_EQ(curr_geco_instance_->default_assocMaxRetransmits,
		ASSOCIATION_MAX_RETRANS_ATTEMPTS);
	ASSERT_EQ(curr_geco_instance_->default_pathMaxRetransmits,
		MAX_PATH_RETRANS_TIMES);
	ASSERT_EQ(curr_geco_instance_->default_maxInitRetransmits,
		MAX_INIT_RETRANS_ATTEMPTS);
	ASSERT_EQ(curr_geco_instance_->default_myRwnd, myRWND / 2);
	ASSERT_EQ(curr_geco_instance_->default_delay, lib_infos.delayed_ack_interval);
	ASSERT_EQ(curr_geco_instance_->default_ipTos, (uchar)IPTOS_DEFAULT);
	ASSERT_EQ(curr_geco_instance_->default_rtoMin, (int)RTO_MIN);
	ASSERT_EQ(curr_geco_instance_->default_rtoMax, (int)RTO_MAX);
	ASSERT_EQ(curr_geco_instance_->default_maxSendQueue,
		(int)DEFAULT_MAX_SENDQUEUE);
	ASSERT_EQ(curr_geco_instance_->default_maxRecvQueue,
		(int)DEFAULT_MAX_RECVQUEUE);
	ASSERT_EQ(curr_geco_instance_->default_maxBurst, (int)DEFAULT_MAX_BURST);

	//delete last instance after testing commons
	mulp_delete_geco_instance(instid);
	ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
	ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

	free_library();
}

extern bool mdi_new_channel(geco_instance_t* instance, ushort local_port, ushort remote_port, uint tagLocal,
	short primaryDestinitionAddress, ushort noOfDestinationAddresses, sockaddrunion *destinationAddressLis);
extern int mtra_poll(void(*lock)(void* data) = NULL,
	void(*unlock)(void* data) = NULL, void* data = NULL);
extern void msm_abort_channel(short error_type = 0, uchar* errordata = 0, ushort errordattalen = 0);
extern channel_t** channels_; /*store all channels, channel id as key*/
extern uint channels_size_;
extern uint* available_channel_ids_; /*store all frred channel ids, can be reused when creatng a new channel*/
extern uint available_channel_ids_size_;
extern geco_instance_t *curr_geco_instance_;
extern channel_t *curr_channel_;
extern timer_mgr mtra_timer_mgr_;
TEST(MULP, test_mdi_new_and_delete_channel)
{
	//precondition lib has been inited
	initialize_library();

	lib_params_t lib_infos;
	mulp_get_lib_params(&lib_infos);

	int instid;
	bool fip4 = false, fip6 = false;
	char ip4addrstr[MAX_IPADDR_STR_LEN];
	char ip6addrstr[MAX_IPADDR_STR_LEN];

	for (int i = 0; i < defaultlocaladdrlistsize_; i++)
	{
		if (!fip4 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET)
		{
			fip4 = true;
			saddr2str(&defaultlocaladdrlist_[i], ip4addrstr, MAX_IPADDR_STR_LEN);
			if (fip6)
				break;
		}
		if (!fip6 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET6)
		{
			fip6 = true;
			saddr2str(&defaultlocaladdrlist_[i], ip6addrstr, MAX_IPADDR_STR_LEN);
			if (fip4)
				break;
		}
	}

	unsigned short localPort;
	unsigned short noOfInStreams;
	unsigned short noOfOutStreams;
	unsigned int noOfLocalAddresses;
	unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN];
	ulp_cbs_t ULPcallbackFunctions;

	//test normal flows: given ip6 any and ip4 any
	localPort = 123;
	noOfInStreams = 32;
	noOfOutStreams = 32;
	noOfLocalAddresses = 2;
	strcpy((char*)localAddressList[0], "0.0.0.0");
	strcpy((char*)localAddressList[1], "::0");
	ULPcallbackFunctions =
	{ 0 };
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];

	sockaddrunion dest_su[3];
	str2saddr(dest_su, "127.0.0.1");
	str2saddr(dest_su + 1, "192.168.1.1");
	str2saddr(dest_su + 2, "192.168.1.2");
	ushort noOfDestinationAddresses = sizeof(dest_su) / sizeof(sockaddrunion);
	ushort destinationPort = 456;
	ushort ppath = 0;
	uint itag = 1234567;
	ASSERT_EQ(mdi_new_channel(curr_geco_instance_, localPort, destinationPort, itag, ppath, noOfDestinationAddresses, dest_su), true);
	curr_channel_ = channels_[0];

	ASSERT_EQ(curr_channel_->channel_id, 0);
	ASSERT_EQ(curr_channel_->deleted, false);
	ASSERT_EQ(curr_channel_->geco_inst, curr_geco_instance_);
	ASSERT_EQ(curr_channel_->local_port, localPort);
	ASSERT_EQ(curr_channel_->local_tag, itag);
	ASSERT_EQ(curr_channel_->remote_port, destinationPort);
	ASSERT_EQ(curr_channel_->remote_tag, 0);//must be zero at this moment
	ASSERT_EQ(curr_channel_->local_addres_size, defaultlocaladdrlistsize_);
	ASSERT_EQ(curr_channel_->remote_addres_size, noOfDestinationAddresses);
	ASSERT_EQ(curr_channel_->remotely_supported_PRSCTP, false);
	ASSERT_EQ(curr_channel_->remotely_supported_ADDIP, false);
	ASSERT_EQ(curr_channel_->locally_supported_PRDCTP,
		lib_infos.support_particial_reliability);
	ASSERT_EQ(curr_channel_->locally_supported_ADDIP,
		lib_infos.support_dynamic_addr_config);
	ASSERT_EQ(curr_channel_->ipTos, curr_geco_instance_->default_ipTos);
	ASSERT_EQ(curr_channel_->is_IN6ADDR_ANY, curr_geco_instance_->is_in6addr_any);
	ASSERT_EQ(curr_channel_->is_INADDR_ANY, curr_geco_instance_->is_inaddr_any);
	ASSERT_EQ(curr_channel_->maxRecvQueue, curr_geco_instance_->default_maxRecvQueue);
	ASSERT_EQ(curr_channel_->maxSendQueue, curr_geco_instance_->default_maxSendQueue);
	ASSERT_EQ(curr_channel_->maxRecvQueue, 0);
	ASSERT_EQ(curr_channel_->maxSendQueue, 0);

	ASSERT_EQ(curr_channel_->flow_control, (flow_controller_t*)NULL);
	ASSERT_EQ(curr_channel_->reliable_transfer_control, (reltransfer_controller_t*)NULL);
	ASSERT_EQ(curr_channel_->receive_control, (recv_controller_t*)NULL);
	ASSERT_EQ(curr_channel_->deliverman_control, (deliverman_controller_t*)NULL);

	path_controller_t* pmData = curr_channel_->path_control;
	ASSERT_EQ(pmData->path_params, (path_params_t*)NULL);
	ASSERT_EQ(pmData->primary_path, ppath);
	ASSERT_EQ(pmData->path_num, noOfDestinationAddresses);
	ASSERT_EQ(pmData->channel_id, curr_channel_->channel_id);
	ASSERT_EQ(pmData->channel_ptr, curr_channel_);
	ASSERT_EQ(pmData->max_retrans_per_path, curr_geco_instance_->default_pathMaxRetransmits);
	ASSERT_EQ(pmData->rto_initial, curr_geco_instance_->default_rtoInitial);
	ASSERT_EQ(pmData->rto_min, curr_geco_instance_->default_rtoMin);
	ASSERT_EQ(pmData->rto_max, curr_geco_instance_->default_rtoMax);

	bundle_controller_t* mbu = curr_channel_->bundle_control;
	ASSERT_EQ(mbu->ctrl_chunk_in_buffer, false);
	ASSERT_EQ(mbu->ctrl_position, GECO_PACKET_FIXED_SIZE);
	ASSERT_EQ(mbu->data_in_buffer, false);
	ASSERT_EQ(mbu->data_position, GECO_PACKET_FIXED_SIZE);
	ASSERT_EQ(mbu->sack_in_buffer, false);
	ASSERT_EQ(mbu->sack_position, GECO_PACKET_FIXED_SIZE);
	ASSERT_EQ(mbu->got_send_address, false);
	ASSERT_EQ(mbu->got_send_request, false);
	ASSERT_EQ(mbu->got_shutdown, false);
	ASSERT_EQ(mbu->locked, false);
	ASSERT_EQ(mbu->requested_destination, 0);

	smctrl_t* msm = curr_channel_->state_machine_control;
	ASSERT_EQ(msm->channel_state, ChannelState::Closed);
	ASSERT_EQ(msm->init_timer_id, mtra_timer_mgr_.timers.end());
	ASSERT_EQ(msm->init_timer_interval, RTO_INITIAL);
	ASSERT_EQ(msm->init_retrans_count, 0);
	ASSERT_EQ(msm->channel_id, curr_channel_->channel_id);
	ASSERT_EQ(msm->my_init_chunk, (init_chunk_t*)NULL);
	ASSERT_EQ(msm->peer_cookie_chunk, (cookie_echo_chunk_t*)NULL);
	ASSERT_EQ(msm->outbound_stream, curr_geco_instance_->noOfOutStreams);
	ASSERT_EQ(msm->inbound_stream, curr_geco_instance_->noOfInStreams);
	ASSERT_EQ(msm->local_tie_tag, 0);
	ASSERT_EQ(msm->peer_tie_tag, 0);
	ASSERT_EQ(msm->max_init_retrans_count, curr_geco_instance_->default_maxInitRetransmits);
	ASSERT_EQ(msm->max_assoc_retrans_count, curr_geco_instance_->default_assocMaxRetransmits);
	ASSERT_EQ(msm->cookie_lifetime, curr_geco_instance_->default_validCookieLife);
	ASSERT_EQ(msm->instance, curr_geco_instance_);
	ASSERT_EQ(msm->channel, curr_channel_);


	//test error flow: when create an existing channel, should return false
	ASSERT_EQ(mdi_new_channel(curr_geco_instance_, localPort, destinationPort, itag, ppath, noOfDestinationAddresses, dest_su), false);

	//test channel id generating mechnics
	destinationPort = 4567;
	ppath = 1;
	itag = 1234567;
	ASSERT_EQ(mdi_new_channel(curr_geco_instance_, localPort, destinationPort, itag, ppath, noOfDestinationAddresses, dest_su), true);
	curr_channel_ = channels_[1];
	ASSERT_EQ(curr_channel_->channel_id, 1);
	ASSERT_EQ(curr_channel_->geco_inst, curr_geco_instance_);

	destinationPort = 4568;
	ASSERT_EQ(mdi_new_channel(curr_geco_instance_, localPort, destinationPort, itag, ppath, noOfDestinationAddresses, dest_su), true);
	curr_channel_ = channels_[2];
	ASSERT_EQ(curr_channel_->channel_id, 2);
	ASSERT_EQ(channels_size_, 3);

	// let us delete channel with id 2
	msm_abort_channel();

	// need reassign curr_geco_instance_  as it is set to NULL in msm_abort_channel();this is not error
	curr_geco_instance_ = geco_instances_[instid];

	destinationPort = 4569;
	ASSERT_EQ(mdi_new_channel(curr_geco_instance_, localPort, destinationPort, itag, ppath, noOfDestinationAddresses, dest_su), true);
	curr_channel_ = channels_[2];
	ASSERT_EQ(curr_channel_->channel_id, 2);
	ASSERT_EQ(channels_size_, 3);
	ASSERT_EQ(available_channel_ids_size_, 0);
	msm_abort_channel();
	assert(channels_[2] == NULL);
	assert(channels_size_ == 3);
	ASSERT_EQ(available_channel_ids_size_, 1);

	// need reassign curr_geco_instance_  as it is set to NULL in msm_abort_channel();this is not error
	curr_geco_instance_ = geco_instances_[instid];
	curr_channel_ = channels_[0];
	assert(curr_channel_ != NULL);
	msm_abort_channel();

	// need reassign curr_geco_instance_  as it is set to NULL in msm_abort_channel();this is not error
	curr_geco_instance_ = geco_instances_[instid];
	curr_channel_ = channels_[1];
	assert(curr_channel_ != NULL);
	msm_abort_channel();

	// need reassign curr_geco_instance_  as it is set to NULL in msm_abort_channel();this is not error
	curr_geco_instance_ = geco_instances_[instid];
	mulp_delete_geco_instance(instid);
	free_library();

}

TEST(MULP, test_mulp_connect)
{
	//precondition lib has been inited
	initialize_library();

	lib_params_t lib_infos;
	mulp_get_lib_params(&lib_infos);

	geco_instance_t* curr_geco_instance_;
	int instid;
	bool fip4 = false, fip6 = false;
	char ip4addrstr[MAX_IPADDR_STR_LEN];
	char ip6addrstr[MAX_IPADDR_STR_LEN];

	for (int i = 0; i < defaultlocaladdrlistsize_; i++)
	{
		if (!fip4 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET)
		{
			fip4 = true;
			saddr2str(&defaultlocaladdrlist_[i], ip4addrstr, MAX_IPADDR_STR_LEN);
			if (fip6)
				break;
		}
		if (!fip6 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET6)
		{
			fip6 = true;
			saddr2str(&defaultlocaladdrlist_[i], ip6addrstr, MAX_IPADDR_STR_LEN);
			if (fip4)
				break;
		}
	}
	EVENTLOG2(DEBUG, "used ip4 addr %s, ip6 addr %s", ip4addrstr, ip6addrstr);

	unsigned short localPort;
	unsigned short noOfInStreams;
	unsigned short noOfOutStreams;
	unsigned int noOfLocalAddresses;
	unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN];
	ulp_cbs_t ULPcallbackFunctions;

	//ip6 any and ip4 any
	localPort = 123;
	noOfInStreams = 32;
	noOfOutStreams = 32;
	noOfLocalAddresses = 2;
	strcpy((char*)localAddressList[0], "0.0.0.0");
	strcpy((char*)localAddressList[1], "::0");
	ULPcallbackFunctions =
	{ 0 };
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];

	noOfOutStreams = 12;
	mulp_connect(instid, noOfOutStreams, "::1", localPort,
		&ULPcallbackFunctions);
	channel_t* curr_channel_ = channels_[0];

	ASSERT_EQ(curr_channel_->channel_id, 0);
	ASSERT_EQ(curr_channel_->deleted, false);
	ASSERT_EQ(curr_channel_->remotely_supported_PRSCTP, false);
	ASSERT_EQ(curr_channel_->remotely_supported_ADDIP, false);
	ASSERT_EQ(curr_channel_->locally_supported_PRDCTP,
		lib_infos.support_particial_reliability);
	ASSERT_EQ(curr_channel_->locally_supported_ADDIP,
		lib_infos.support_dynamic_addr_config);
	ASSERT_EQ(curr_channel_->ipTos, curr_geco_instance_->default_ipTos);
	ASSERT_EQ(curr_channel_->is_IN6ADDR_ANY, curr_geco_instance_->is_in6addr_any);
	ASSERT_EQ(curr_channel_->is_INADDR_ANY, curr_geco_instance_->is_inaddr_any);
	//ASSERT_EQ(curr_channel_->local_addres,false);
	bundle_controller_t* mbu = curr_channel_->bundle_control;
	EXPECT_EQ(mbu->ctrl_chunk_in_buffer, false);
	EXPECT_EQ(mbu->ctrl_position, GECO_PACKET_FIXED_SIZE);
	EXPECT_EQ(mbu->data_in_buffer, false);
	EXPECT_EQ(mbu->data_position, GECO_PACKET_FIXED_SIZE);
	EXPECT_EQ(mbu->sack_in_buffer, false);
	EXPECT_EQ(mbu->sack_position, GECO_PACKET_FIXED_SIZE);
	EXPECT_EQ(mbu->got_send_address, false);
	EXPECT_EQ(mbu->got_send_request, false);
	EXPECT_EQ(mbu->got_shutdown, false);
	EXPECT_EQ(mbu->locked, false);
	EXPECT_EQ(mbu->requested_destination, 0);

	channels_size_ = 0; // clear channel
	mulp_delete_geco_instance(instid);
	free_library();
}


static bool flag = true;
static void stdin_cb(char* data, size_t datalen)
{
	EVENTLOG2(DEBUG, "stdin_cb()::%d bytes : %s", datalen, data);
	if (strcmp(data, "q") == 0)
	{
		flag = false;
		return;
	}
}
static void communicationLostNotif(unsigned int, unsigned short, void*)
{
	EVENTLOG(INFO, "connection lost !");
}
#include "geco-net-transport.h"
TEST(MULP, test_connection_pharse)
{
	//precondition lib has been inited
	initialize_library();
	mtra_add_stdin_cb(stdin_cb);

	lib_params_t lib_infos;
	mulp_get_lib_params(&lib_infos);

	geco_instance_t* curr_geco_instance_;
	int instid;
	bool fip4 = false, fip6 = false;
	char ip4addrstr[MAX_IPADDR_STR_LEN];
	char ip6addrstr[MAX_IPADDR_STR_LEN];

	for (int i = 0; i < defaultlocaladdrlistsize_; i++)
	{
		if (!fip4 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET)
		{
			fip4 = true;
			saddr2str(&defaultlocaladdrlist_[i], ip4addrstr, MAX_IPADDR_STR_LEN);
			if (fip6)
				break;
		}
		if (!fip6 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET6)
		{
			fip6 = true;
			saddr2str(&defaultlocaladdrlist_[i], ip6addrstr, MAX_IPADDR_STR_LEN);
			if (fip4)
				break;
		}
	}
	EVENTLOG2(DEBUG, "used ip4 addr %s, ip6 addr %s", ip4addrstr, ip6addrstr);

	unsigned short localPort;
	unsigned short noOfInStreams;
	unsigned short noOfOutStreams;
	unsigned int noOfLocalAddresses;
	unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN];
	ulp_cbs_t ULPcallbackFunctions;

	//ip6 any and ip4 any
	localPort = USED_UDP_PORT;
	noOfInStreams = 32;
	noOfOutStreams = 32;
	noOfLocalAddresses = 2;
	strcpy((char*)localAddressList[0], "0.0.0.0");
	strcpy((char*)localAddressList[1], "::0");
	ULPcallbackFunctions =
	{ 0 };
	ULPcallbackFunctions.communicationLostNotif = communicationLostNotif;
	instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams,
		noOfLocalAddresses, localAddressList,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];

	// cline code
	noOfOutStreams = 12;
	mulp_connect(instid, noOfOutStreams, "10.0.0.107", localPort, &ULPcallbackFunctions);

	//poll to receive the init, send initack
	while(flag)
		mtra_poll(0, 0, 0);

	// client code
	msm_abort_channel();

	mulp_delete_geco_instance(instid);
	free_library();
}
