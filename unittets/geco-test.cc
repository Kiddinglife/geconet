/*
 * geco-test.cc
 *
 *  Created on: 22Feb.,2017
 *      Author: jackiez
 */

#include "geco-test.h"

static const ushort UT_LOCAL_PORT = 123;
static const ushort UT_PEER_PORT = 456;
static const ushort UT_ORDER_STREAM = 32;
static const ushort UT_SEQ_STREAM = 32;
static const uint UT_ITAG = 1;
static const uint UT_ITSN = 1;
static const short UT_PRI_PATH_ID = 0;
static const uint UT_ARWND = 65535;
static const bool ADDIP = true;
static const bool PR = true;

static int instid = -1;
static int channelid = -1;
static uint UT_LOCAL_ADDR_LIST_SIZE = 0;
static uchar UT_LOCAL_ADDR_LIST[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN] =
{ 0 };
static ulp_cbs_t ULPcallbackFunctions =
{ 0 };

extern int
mulp_new_geco_instance(unsigned short localPort,
	unsigned short noOfOrderStreams,
	unsigned short noOfSeqStreams,
	unsigned int noOfLocalAddresses,
	unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN],
	ulp_cbs_t ULPcallbackFunctions);
void alloc_geco_instance()
{
	bool fip4 = false, fip6 = false;
	char ip4addrstr[MAX_IPADDR_STR_LEN];
	char ip6addrstr[MAX_IPADDR_STR_LEN];
	for (uint i = 0; i < defaultlocaladdrlistsize_; i++)
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
	//use ip6 any and ip4 any
	UT_LOCAL_ADDR_LIST_SIZE = 2;
	strcpy((char*)UT_LOCAL_ADDR_LIST[0], "0.0.0.0");
	strcpy((char*)UT_LOCAL_ADDR_LIST[1], "::0");
	initialize_library();
	lib_params_t lib_infos;
	mulp_get_lib_params(&lib_infos);
	instid = mulp_new_geco_instance(UT_LOCAL_PORT, UT_ORDER_STREAM, UT_SEQ_STREAM,
		UT_LOCAL_ADDR_LIST_SIZE, UT_LOCAL_ADDR_LIST,
		ULPcallbackFunctions);
	curr_geco_instance_ = geco_instances_[instid];
}
void
free_geco_instance()
{
	if (instid > -1)
	{
		mulp_delete_geco_instance(instid);
		free_library();
		instid = -1;
	}
	curr_geco_instance_ = NULL;
}

extern bool
mdi_new_channel(geco_instance_t* instance, ushort local_port,
	ushort remote_port, uint tagLocal,
	short primaryDestinitionAddress,
	ushort noOfDestinationAddresses,
	sockaddrunion *destinationAddressLis);
extern ushort mdi_init_channel(uint remoteSideReceiverWindow, ushort noOfOrderStreams,
	ushort noOfSeqStreams, uint remoteInitialTSN, uint tagRemote,
	uint localInitialTSN, bool assocSupportsPRSCTP, bool assocSupportsADDIP);
extern void set_channel_remote_addrlist(sockaddrunion destaddrlist[MAX_NUM_ADDRESSES],
	int noOfAddresses);
extern void mdi_delete_curr_channel();
void alloc_geco_channel()
{
	sockaddrunion dest_su[2];
	str2saddr(dest_su, "192.168.1.1",UT_PEER_PORT);
	str2saddr(dest_su + 1, "192.168.1.2", UT_PEER_PORT);
	alloc_geco_instance();
	mdi_new_channel(curr_geco_instance_, UT_LOCAL_PORT, UT_PEER_PORT, UT_ITAG, UT_PRI_PATH_ID, sizeof(dest_su) / sizeof(sockaddrunion), dest_su);
	mdi_init_channel(UT_ARWND, UT_ORDER_STREAM, UT_SEQ_STREAM, UT_ITSN, UT_ITAG, UT_ITSN, PR, ADDIP);
	set_channel_remote_addrlist(dest_su, sizeof(dest_su)/sizeof(sockaddrunion));
	channelid = channels_size_ - 1;
	curr_channel_ = channels_[0];
	curr_channel_->geco_inst = curr_geco_instance_;
}

void
free_geco_channel()
{
	if (channelid > -1)
	{
		mdi_delete_curr_channel();
		free_geco_instance();
		channelid = -1;
	}

	curr_geco_instance_ = NULL;
	curr_channel_ = NULL;
}

TEST(UT_HELPER, test_make_geco_instance)
{
	alloc_geco_instance();
	free_geco_instance();
}

TEST(UT_HELPER, test_make_geco_channel)
{
	alloc_geco_channel();
	free_geco_channel();
}
