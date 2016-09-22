#include "gtest/gtest.h"
#include "gmock/gmock.h"
// @caution because geco-ds-malloc includes geco-thread.h that includes window.h
// but transport_layer.h includes wsock2.h, as we know, it must include before windows.h
// so if you uncomment this line, will cause error
//#include "geco-ds-malloc.h"
#include "transport_layer.h"
#include "dispatch_layer.h"
#include "geco-ds-malloc.h"
#include "geco-malloc.h"
using namespace geco::ds;

#define reset_geco_packet_fixed() \
        geco_packet.pk_comm_hdr.checksum = 0;\
        geco_packet.pk_comm_hdr.dest_port = htons(sender_dest_port);  \
        geco_packet.pk_comm_hdr.src_port = htons(sender_src_port);  \
        geco_packet.pk_comm_hdr.verification_tag = 0

#define init() \
            int i;\
           const int srcaddr4_size = 3;const int srcaddr6_size = 2;\
           const char* srcaddr4_ipstrs[srcaddr4_size] =\
               { "192.168.1.121", "192.168.1.132", "192.168.34.2" };\
           const char* srcaddr6_ipstrs[srcaddr6_size] =\
               { "2001:0db8:0a0b:12f0:0000:0000:0000:0001", "2607:f0d0:1002:0051:0000:0000:0000:0004" };\
           const int destaddr4_size = 3;\
           const int destaddr6_size = 2;\
           const char* destaddr4_ipstrs[destaddr4_size] =\
               { "192.168.1.122", "192.168.1.131", "192.168.34.1" };\
           const char* destaddr6_ipstrs[destaddr6_size] =\
               { "2001:0db8:0a0b:12f0:0000:0000:0000:0002", "2607:f0d0:1002:0051:0000:0000:0000:0005" };\
           const int cannot_found_ips4_size = 3;const int cannot_found_ips6_size = 2;\
           const char* cannot_found_ips4[cannot_found_ips4_size] =\
               { "192.168.1.123", "192.168.1.101", "192.168.34.5" };\
           const char* cannot_found_ips6[cannot_found_ips6_size] =\
               { "2001:0db8:0a0b:12f0:0000:0000:0000:0020", "2607:f0d0:1002:0051:0000:0000:0000:0100" };\
           sockaddrunion src_addres[srcaddr4_size]; \
           sockaddrunion src_addres6[srcaddr6_size]; \
           sockaddrunion dest_addres[destaddr4_size];\
           sockaddrunion dest_addres6[destaddr6_size]; \
           sockaddrunion cannot_found_addres4[cannot_found_ips4_size]; \
           sockaddrunion cannot_found_addres6[cannot_found_ips6_size]; \
           init_addrlist(true, 0, cannot_found_ips4, cannot_found_ips4_size, cannot_found_addres4);\
           init_addrlist(false, 0, cannot_found_ips6, cannot_found_ips6_size, cannot_found_addres6);\
           init_addrlist(true, 0, srcaddr4_ipstrs, srcaddr4_size, src_addres);\
           init_addrlist(false, 0, srcaddr6_ipstrs, srcaddr6_size, src_addres6);\
           init_addrlist(true, 0, destaddr4_ipstrs, destaddr4_size, dest_addres);\
           init_addrlist(false, 0, destaddr6_ipstrs, destaddr6_size, dest_addres6);\
           sockaddrunion local_addres[destaddr4_size + destaddr6_size];\
           sockaddrunion remote_addres[srcaddr4_size + srcaddr6_size];\
           for (i = 0; i < destaddr4_size; i++)\
           {\
               local_addres[i] = dest_addres[i];\
               remote_addres[i] = src_addres[i];\
           }\
           for (int j = 0; j < destaddr6_size; j++)\
           {\
               local_addres[i + j] = dest_addres6[j];\
               remote_addres[i + j] = src_addres6[j];\
           }\
           const int all_cannot_found_size = cannot_found_ips4_size + cannot_found_ips6_size;\
           sockaddrunion all_cannot_found_addres[all_cannot_found_size];\
           for (i = 0; i < cannot_found_ips4_size; i++)\
           {\
               all_cannot_found_addres[i] = cannot_found_addres4[i];\
           }\
           for (int j = 0; j < cannot_found_ips6_size; j++)\
           {\
               all_cannot_found_addres[i + j] = cannot_found_addres6[j];\
           }\
           ushort sender_src_port = 123;\
           ushort sender_dest_port = 456;\
           geco_packet_t geco_packet;\
           geco_packet_t* dctp_packet = &geco_packet;\
           geco_packet.pk_comm_hdr.checksum = 0;\
           geco_packet.pk_comm_hdr.dest_port = htons(sender_dest_port);  \
           geco_packet.pk_comm_hdr.src_port = htons(sender_src_port);  \
           geco_packet.pk_comm_hdr.verification_tag = 0;\
           dispatch_layer_t dlt;\
           channel_t channel;\
           geco_instance_t inst;\
           network_interface_t init;\
           dlt.transport_layer_ = &init;\
           dlt.channels_.push_back(&channel);\
           dlt.geco_instances_.push_back(&inst);\
           int rwnd = 512;\
           inst.supportedAddressTypes = SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6;\
           inst.is_inaddr_any = false;\
           inst.is_in6addr_any = false;\
           inst.noOfInStreams = 6;\
           inst.noOfOutStreams = 6;\
           inst.local_port = sender_dest_port;\
           inst.local_addres_list = local_addres;\
           inst.local_addres_size = destaddr4_size + destaddr6_size;\
           channel.channel_id = 123;\
           channel.remote_addres = remote_addres;\
           channel.remote_addres_size = srcaddr4_size + srcaddr6_size;\
           channel.local_addres = local_addres;\
           channel.local_addres_size = destaddr4_size + destaddr6_size;\
           channel.remote_port = sender_src_port;\
           channel.local_port = sender_dest_port;\
           channel.remote_tag = 123;\
           channel.local_tag = 456;\
           channel.deleted = false;\
           channel.geco_inst = &inst;\
           smctrl_t smt;\
           channel.state_machine_control = &smt;\
           bundle_controller_t bctrl;\
           channel.bundle_control = &bctrl;\
           sockaddrunion* last_src_addr;\
           sockaddrunion* last_dest_addr;\
           uint written = 0;\
           uint dctp_packet_len = 0; int ret = good

static void
init_inst(dispatch_layer_t& dlt, geco_instance_t& inst, ushort destport,
	const char** src_ips, uint src_ips_len, sockaddrunion* dest)
{
	for (uint i = 0; i < src_ips_len; i++)
	{
		str2saddr(&dest[i], src_ips[i], destport, true);
	}
	inst.local_addres_size = src_ips_len;
	inst.local_addres_list = dest;
	inst.local_port = destport;
	dlt.geco_instances_.push_back(&inst);
}
static void
init_channel(dispatch_layer_t& dlt, channel_t& channel, ushort srcport,
	ushort destport, const char** src_ips, uint src_ips_len,
	const char** dest_ips, uint dest_ips_len, sockaddrunion* src,
	sockaddrunion* dest)
{
	for (uint i = 0; i < src_ips_len; i++)
	{
		str2saddr(&src[i], src_ips[i], srcport, true);
	}
	for (uint i = 0; i < dest_ips_len; i++)
	{
		str2saddr(&dest[i], dest_ips[i], destport, true);
	}
	channel.remote_addres = src;
	channel.local_addres = dest;
	channel.remote_port = srcport;
	channel.local_port = destport;
	channel.remote_addres_size = src_ips_len;
	channel.local_addres_size = dest_ips_len;
	channel.deleted = false;
	channel.is_IN6ADDR_ANY = false;
	channel.is_INADDR_ANY = false;
	dlt.channels_.push_back(&channel);
}
static void
init_addrlist(bool isip4, ushort port, const char** ipstrs, uint len,
	sockaddrunion* addrlist)
{
	for (uint i = 0; i < len; i++)
	{
		str2saddr(&addrlist[i], ipstrs[i], port, isip4);
	}
}

// last run and passed on 21 Agu 2016
TEST(DISPATCHER_MODULE, test_find_geco_instance_by_transport_addr)
{
	/* 6) find dctp instancefor this packet
	 *  if this packet is for a server dctp instance,
	 *  we will find that dctp instance and let it handle this packet
	 *  (i.e. we have the dctp instance's localPort set and
	 *  it matches the packet's destination port)*/

	dispatch_layer_t dlt;
	geco_instance_t inst;
	const int destaddrsize = 6;
	const char* destipstrs[destaddrsize] =
	{ "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4",
		"192.168.1.5" };
	const ushort destport = 9989;
	sockaddrunion dest_addrs[destaddrsize];
	init_inst(dlt, inst, destport, destipstrs, destaddrsize, dest_addrs);

	sockaddrunion* last_dest_addr;
	ushort last_dest_port;
	geco_instance_t* ret = 0;

	// 1)  if is_in6addr_any and is_inaddr_any are both false
	inst.is_in6addr_any = inst.is_inaddr_any = false;
	// 1.1) if last_dest_port, last_dest_addr and addr family both matches
	last_dest_port = inst.local_port;
	for (uint i = 0; i < inst.local_addres_size; i++)
	{
		last_dest_addr = &inst.local_addres_list[i];
		ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr,
			last_dest_port);
		//  1.1.1) should found this inst
		EXPECT_EQ(ret, &inst);
	}
	// 1.2) if last_dest_port NOT mathces
	last_dest_port = inst.local_port - 1;
	for (uint i = 0; i < inst.local_addres_size; i++)
	{
		last_dest_addr = &inst.local_addres_list[i];
		ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr,
			last_dest_port);
		//  1.2.1) should NOT found this inst
		EXPECT_EQ(ret, nullptr);
	}
	// 1.3) if last_dest_addr NOT matches
	last_dest_port = inst.local_port;
	for (uint i = 0; i < inst.local_addres_size; i++)
	{
		sockaddrunion tmp = inst.local_addres_list[i];
		s4addr(&tmp) -= 1;  // just minus to make it different
		last_dest_addr = &tmp;
		ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr,
			last_dest_port);
		//  1.3.1) should NOT found this inst
		EXPECT_EQ(ret, nullptr);
	}
	// 1.4) if addr family NOT matches
	last_dest_port = inst.local_port;
	for (uint i = 0; i < inst.local_addres_size; i++)
	{
		sockaddrunion tmp = inst.local_addres_list[i];
		saddr_family(&tmp) == AF_INET ?
			saddr_family(&tmp) = AF_INET6 :
			saddr_family(&tmp) = AF_INET;
		last_dest_addr = &tmp;
		ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr,
			last_dest_port);
		//  1.4.1) should NOT found this inst
		EXPECT_EQ(ret, nullptr);
	}
	// 2)  if is_in6addr_any is true
	inst.is_in6addr_any = true;
	// 2.1) last_dest_addr and addr family ALL NOT match, but last_dest_port_matches
	for (uint i = 0; i < inst.local_addres_size; i++)
	{
		sockaddrunion tmp = inst.local_addres_list[i];
		s4addr(&tmp) -= 1;  // just minus to make it different
		saddr_family(&tmp) == AF_INET ?
			saddr_family(&tmp) = AF_INET6 :
			saddr_family(&tmp) = AF_INET;
		last_dest_addr = &tmp;
		ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr,
			last_dest_port);
		//  2.1.1) should still found this inst
		EXPECT_EQ(ret, &inst);
	}
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_find_channel_by_transport_addr)
{
	const int src_ips_size = 3;
	const char* src_ips[src_ips_size] =
	{ "192.168.1.0", "192.168.1.1", "192.168.1.2" };
	const int dest_ips_size = 3;
	const char* dest_ips[dest_ips_size] =
	{ "192.168.1.3", "192.168.1.4", "192.168.1.5" };
	const ushort ports[] =
	{ 100, 101 };  // src-dest
	sockaddrunion remote_addres[src_ips_size];
	sockaddrunion local_addres[dest_ips_size];

	channel_t channel;
	dispatch_layer_t dlt;
	init_channel(dlt, channel, ports[0], ports[1], src_ips, src_ips_size,
		dest_ips, dest_ips_size, remote_addres, local_addres);

	//temps
	channel_t* found;
	sockaddrunion* last_src_addr;
	sockaddrunion* last_dest_addr;
	ushort last_src_port = channel.remote_port;
	ushort last_dest_port = channel.local_port;
	sockaddrunion tmp_addr;

	//1) if src port not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		last_dest_addr = &channel.local_addres[i];
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			last_src_addr = &channel.remote_addres[j];
			last_src_port -= 1;  //just make it not equal to the one stored in channel
			//1.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
	//2) if dest port not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		last_dest_addr = &channel.local_addres[i];
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			last_src_addr = &channel.remote_addres[j];
			last_dest_port -= 1; //just make it not equal to the one stored in channel
			//2.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
	//2) if dest port not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		last_dest_addr = &channel.local_addres[i];
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			last_src_addr = &channel.remote_addres[j];
			last_dest_port -= 1; //just make it not equal to the one stored in channel
			//2.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
	//3) if dest and src port not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		last_dest_addr = &channel.local_addres[i];
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			last_src_addr = &channel.remote_addres[j];
			last_dest_port -= 1; //just make it not equal to the one stored in channel
			last_src_port -= 1;  //just make it not equal to the one stored in channel
			//3.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
	//4) if dest addr not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		tmp_addr = channel.local_addres[i];
		s4addr(&tmp_addr) -= 1;  // just minus to make it different
		last_dest_addr = &tmp_addr;
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			last_src_addr = &channel.remote_addres[j];
			//3.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
	//5) if  src addr not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		last_dest_addr = &channel.local_addres[i];
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			tmp_addr = channel.remote_addres[i];
			s4addr(&tmp_addr) -= 1;  // just minus to make it different
			last_src_addr = &tmp_addr;
			//5.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
	//6) if  dest and addr not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		tmp_addr = channel.local_addres[i];
		s4addr(&tmp_addr) -= 1;  // just minus to make it different
		last_dest_addr = &tmp_addr;
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			sockaddrunion tmp_addr2;
			tmp_addr2 = channel.remote_addres[i];
			s4addr(&tmp_addr2) -= 1;  // just minus to make it different
			last_src_addr = &tmp_addr2;
			//6.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
	//7) if dest addr family not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		tmp_addr = channel.local_addres[i];
		saddr_family(&tmp_addr) == AF_INET ?
			saddr_family(&tmp_addr) = AF_INET6 :
			saddr_family(&tmp_addr) = AF_INET;
		last_dest_addr = &tmp_addr;
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			last_src_addr = &channel.remote_addres[j];
			//7.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
	//8) if src addr family not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		last_dest_addr = &channel.local_addres[i];
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			tmp_addr = channel.remote_addres[i];
			saddr_family(&tmp_addr) == AF_INET ?
				saddr_family(&tmp_addr) = AF_INET6 :
				saddr_family(&tmp_addr) =
				AF_INET;
			last_src_addr = &tmp_addr;
			//5.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
	//6) if  dest and addr not equal
	for (uint i = 0; i < channel.local_addres_size; i++)
	{
		tmp_addr = channel.local_addres[i];
		saddr_family(&tmp_addr) == AF_INET ?
			saddr_family(&tmp_addr) = AF_INET6 :
			saddr_family(&tmp_addr) = AF_INET;
		last_dest_addr = &tmp_addr;
		for (uint j = 0; j < channel.remote_addres_size; j++)
		{
			sockaddrunion tmp_addr2;
			tmp_addr2 = channel.remote_addres[i];
			saddr_family(&tmp_addr2) == AF_INET ?
				saddr_family(&tmp_addr2) = AF_INET6 :
				saddr_family(&tmp_addr2) =
				AF_INET;
			last_src_addr = &tmp_addr2;
			//6.1) should not find channel
			found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
				last_dest_port);
			EXPECT_EQ(found, (channel_t*)NULL);
		}
	}
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_validate_dest_addr)
{
	/*8)
	 * now we can validate if dest_addr in localaddress
	 * this method internally uses curr_geco_instance_ and curr_channel_
	 * so we must call it right here
	 */
	int i;
	const char* addres[6] =
	{ "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4",
		"192.168.1.5" };
	const int addres_cnt = 6;
	const ushort ports[addres_cnt] =
	{ 100, 101 };  // src-dest
	sockaddrunion remote_addres[addres_cnt / 2];
	sockaddrunion local_addres[addres_cnt / 2];

	for (i = 0; i < addres_cnt; i++)
	{
		if (i < addres_cnt / 2)
		{
			str2saddr(&remote_addres[i], addres[i], ports[0], true);
		}
		else
		{
			int idx = i % (addres_cnt / 2);
			str2saddr(&local_addres[idx], addres[i], ports[1], true);
		}
	}

	channel_t channel;
	channel.remote_addres = remote_addres;
	channel.local_addres = local_addres;
	channel.remote_port = ports[0];
	channel.local_port = ports[1];
	channel.remote_addres_size = addres_cnt / 2;
	channel.local_addres_size = addres_cnt / 2;
	channel.deleted = false;

	geco_instance_t inst;
	inst.local_addres_size = addres_cnt / 2;
	inst.local_addres_list = local_addres;
	inst.local_port = ports[1];
	channel.geco_inst = &inst;

	dispatch_layer_t dlt;
	dlt.channels_.push_back(&channel);
	dlt.geco_instances_.push_back(&inst);
	sockaddrunion* last_dest_addr;
	bool ret;

	//1) test return true when both of channel and inst are NULL
	dlt.curr_channel_ = NULL;
	dlt.curr_geco_instance_ = NULL;
	last_dest_addr = local_addres + 2;
	ret = dlt.validate_dest_addr(last_dest_addr);
	EXPECT_EQ(ret, true);

	//2) test return true when curr_channel_ NOT NULL
	dlt.curr_channel_ = &channel;
	dlt.curr_geco_instance_ = &inst;
	last_dest_addr = local_addres + 2;
	ret = dlt.validate_dest_addr(last_dest_addr);
	EXPECT_EQ(ret, true);

	//2) test return true when curr_channel_  NULL,
	// inst NOT NULL, is_inaddr_any false, is_in6addr_any false;
	dlt.curr_channel_ = NULL;
	dlt.curr_geco_instance_ = &inst;
	inst.is_inaddr_any = false;
	inst.is_in6addr_any = false;
	last_dest_addr = local_addres + 2;
	ret = dlt.validate_dest_addr(last_dest_addr);
	EXPECT_EQ(ret, true);

	//3) test return true when curr_channel_  NULL inst NOT NULL, is_inaddr_any true, is_in6addr_any false;
	dlt.curr_channel_ = NULL;
	dlt.curr_geco_instance_ = &inst;
	inst.is_inaddr_any = true;
	inst.is_in6addr_any = false;
	last_dest_addr = local_addres + 2;
	ret = dlt.validate_dest_addr(last_dest_addr);
	EXPECT_EQ(ret, true);

	//3) test return true when curr_channel_  NULL inst NOT NULL, is_inaddr_any false, is_in6addr_any true;
	dlt.curr_channel_ = NULL;
	dlt.curr_geco_instance_ = &inst;
	inst.is_inaddr_any = false;
	inst.is_in6addr_any = true;
	last_dest_addr = local_addres + 2;
	ret = dlt.validate_dest_addr(last_dest_addr);
	EXPECT_EQ(ret, false);

	//3) test return false when curr_channel_  NULL inst NOT NULL, is_inaddr_any false, is_in6addr_any false;
	dlt.curr_channel_ = NULL;
	dlt.curr_geco_instance_ = &inst;
	inst.is_inaddr_any = false;
	inst.is_in6addr_any = false;
	last_dest_addr = remote_addres + 2; // we use remote addr as local addr that will not be found
	ret = dlt.validate_dest_addr(last_dest_addr);
	EXPECT_EQ(ret, true);

	//3) test return false when curr_channel_  NOT NULL,  is_inaddr_any false, is_in6addr_any false;
	dlt.curr_channel_ = &channel;
	dlt.curr_geco_instance_ = &inst;
	inst.is_inaddr_any = false;
	inst.is_in6addr_any = false;
	last_dest_addr = remote_addres + 2; // we use remote addr as local addr that will not be found
	ret = dlt.validate_dest_addr(last_dest_addr);
	//should return true
	EXPECT_EQ(ret, true);

}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_find_chunk_types)
{
	/*9)
	 *fetch all chunk types contained in this packet value field
	 *fetch for use in the folowing curr_geco_packet_value_len_
	 *fetch = dctp_packet_len - GECO_PACKET_FIXED_SIZE;
	 *fetch chunk_types_arr_ = find_chunk_types(curr_geco_packet_->chunk,
	 *fetch curr_geco_packet_value_len_, &total_chunks_count_);
	 */
	geco_packet_t geco_packet;
	geco_packet.pk_comm_hdr.checksum = 0;
	geco_packet.pk_comm_hdr.dest_port = htons(
		(generate_random_uint32() % USHRT_MAX));
	geco_packet.pk_comm_hdr.src_port = htons(
		(generate_random_uint32() % USHRT_MAX));
	geco_packet.pk_comm_hdr.verification_tag = htons(
		(generate_random_uint32()));

	// one data chunk
	uint offset = 0;
	uint chunklen = 0;
	uchar* wt = geco_packet.chunk;
	uint datalen = 101;
	chunklen = DATA_CHUNK_FIXED_SIZES + datalen;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_DATA;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	offset += chunklen;
	EXPECT_EQ(offset, 116);
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_DATA);
	wt += chunklen;

	//one sack chunk
	datalen = 31;
	chunklen = datalen + SACK_CHUNK_FIXED_SIZE + CHUNK_FIXED_SIZE;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_SACK;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	//116+4+12+31 = 132+31 = 163
	while (chunklen % 4)
	{
		chunklen++;
	}
	EXPECT_EQ(((chunk_fixed_t*)(geco_packet.chunk + offset))->chunk_id,
		CHUNK_SACK);
	offset += chunklen;
	EXPECT_EQ(offset, 164);
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_SACK);
	wt += chunklen;

	//one init chunk
	datalen = 21;
	chunklen = datalen + INIT_CHUNK_FIXED_SIZES;  //21+20=41
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_INIT;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	EXPECT_EQ(geco_packet.chunk + offset, wt);
	EXPECT_EQ(((chunk_fixed_t*)(geco_packet.chunk + offset))->chunk_id,
		CHUNK_INIT);
	offset += chunklen;
	EXPECT_EQ(offset, 208);  // 164+4+16+21= 205
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_INIT);
	wt += chunklen;

	//one init ack chunk
	datalen = 21;
	chunklen = datalen + INIT_CHUNK_FIXED_SIZES;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_INIT_ACK;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	EXPECT_EQ(((chunk_fixed_t*)(geco_packet.chunk + offset))->chunk_id,
		CHUNK_INIT_ACK);
	offset += chunklen;
	EXPECT_EQ(offset, 252);  // 208+20+21 = 228+21=249
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_INIT_ACK);
	wt += chunklen;

	//CHUNK_SHUTDOWN
	chunklen = 4 + CHUNK_FIXED_SIZE;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_SHUTDOWN;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	offset += chunklen;
	EXPECT_EQ(offset, 260);  // 252+8 = 260
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_SHUTDOWN);
	wt += chunklen;

	//CHUNK_SHUTDOWN_ACK
	chunklen = CHUNK_FIXED_SIZE;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_SHUTDOWN_ACK;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	offset += chunklen;
	EXPECT_EQ(offset, 264);  // 260+4 = 264
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_SHUTDOWN_ACK);
	wt += chunklen;

	//1) test good chunks
	dispatch_layer_t dlt;
	uint total_chunks_count;
	uint chunk_types = dlt.find_chunk_types(geco_packet.chunk, offset,
		&total_chunks_count);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 2);
	EXPECT_EQ(total_chunks_count, 6);

	//2) test bad chunks whose chun len < CHUNK_FIXED_SIZE
	// this will give us all legal chunks
	//CHUNK_SHUTDOWN_COMPLETE
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_SHUTDOWN_COMPLETE;
	((chunk_fixed_t*)wt)->chunk_length = htons(3);
	offset += 4;
	EXPECT_EQ(offset, 268);  // 264+4 = 268
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_SHUTDOWN_COMPLETE);
	wt += 4;
	chunk_types = dlt.find_chunk_types(geco_packet.chunk, offset,
		&total_chunks_count);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types), 0);
	EXPECT_EQ(total_chunks_count, 6);

	//3) test branch chunk_len + read_len > packet_val_len line 3395
	chunk_types = dlt.find_chunk_types(geco_packet.chunk, offset - 4,
		&total_chunks_count);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types), 0);
	EXPECT_EQ(total_chunks_count, 6);

	//4) one CHUNK_SHUTDOWN_ACK
	chunk_types = dlt.find_chunk_types(wt - 8, offset - 8, &total_chunks_count);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 1);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types), 0);
	EXPECT_EQ(total_chunks_count, 1);

	//5) two repeated CHUNK_SHUTDOWN_ACK contains_chunk returns 1
	// but total_chunks_count is 2
	chunklen = CHUNK_FIXED_SIZE;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_SHUTDOWN_ACK;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	offset += chunklen;
	EXPECT_EQ(offset, 272);  // 260+4 = 264
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_SHUTDOWN_ACK);
	wt += chunklen;

	chunklen = CHUNK_FIXED_SIZE;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_SHUTDOWN_ACK;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	offset += chunklen;
	EXPECT_EQ(offset, 276);  // 260+4 = 264
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_SHUTDOWN_ACK);
	wt += chunklen;
	chunk_types = dlt.find_chunk_types(wt - 8, offset - 8, &total_chunks_count);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 1);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types), 0);
	EXPECT_EQ(total_chunks_count, 2);
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_find_first_chunk_of)
{
	geco_packet_t geco_packet;
	geco_packet.pk_comm_hdr.checksum = 0;
	geco_packet.pk_comm_hdr.dest_port = htons(
		(generate_random_uint32() % USHRT_MAX));
	geco_packet.pk_comm_hdr.src_port = htons(
		(generate_random_uint32() % USHRT_MAX));
	geco_packet.pk_comm_hdr.verification_tag = htons(
		(generate_random_uint32()));

	// put one data chunk
	uint offset = 0;
	uint chunklen = 0;
	uchar* wt = geco_packet.chunk;
	uint datalen = 101;
	chunklen = DATA_CHUNK_FIXED_SIZES + datalen;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_DATA;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	offset += chunklen;
	EXPECT_EQ(offset, 116);
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_DATA);
	wt += chunklen;

	//put another data chunk
	datalen = 35;
	chunklen = DATA_CHUNK_FIXED_SIZES + datalen;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_DATA;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	offset += chunklen;
	EXPECT_EQ(offset, 164);
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_DATA);
	wt += chunklen;

	//put one sack chunk
	datalen = 31;
	chunklen = datalen + SACK_CHUNK_FIXED_SIZE + CHUNK_FIXED_SIZE;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_SACK;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	//116+4+12+31 = 132+31 = 163
	while (chunklen % 4)
	{
		chunklen++;
	}
	EXPECT_EQ(((chunk_fixed_t*)(geco_packet.chunk + offset))->chunk_id,
		CHUNK_SACK);
	offset += chunklen;
	EXPECT_EQ(offset, 212);
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_SACK);
	wt += chunklen;

	dispatch_layer_t dlt;
	EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_DATA),
		geco_packet.chunk);
	EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_SACK),
		wt - chunklen);
	EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_INIT),
		(uchar*)NULL);
	EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset - 45, CHUNK_SACK),
		(uchar*)NULL);

	//　branchtest:  chunk_len < CHUNK_FIXED_SIZE
	chunklen = 3;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_SHUTDOWN_ACK;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen);
	while (chunklen % 4)
	{
		chunklen++;
	}
	offset += chunklen;
	EXPECT_EQ(offset, 216);
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_SHUTDOWN_ACK);
	wt += chunklen;
	EXPECT_EQ(
		dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_SHUTDOWN_ACK),
		(uchar*)NULL);

	// branchtest: chunk_len + read_len > packet_val_len
	offset -= chunklen;
	wt -= chunklen;

	chunklen = 4;
	((chunk_fixed_t*)wt)->chunk_id = CHUNK_INIT_ACK;
	((chunk_fixed_t*)wt)->chunk_length = htons(chunklen + 1);
	while (chunklen % 4)
	{
		chunklen++;
	}
	offset += chunklen;
	EXPECT_EQ(offset, 216);
	EXPECT_EQ(((chunk_fixed_t*)wt)->chunk_id, CHUNK_INIT_ACK);
	wt += chunklen;
	EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_INIT_ACK),
		(uchar*)NULL);
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_read_peer_addreslist)
{
	EXPECT_EQ(sizeof(in_addr), 4);
	EXPECT_EQ(sizeof(in6_addr), 16);
	//////////////////////////////////////////////////////////////////////////////
	geco_packet_t geco_packet;
	geco_packet.pk_comm_hdr.checksum = 0;
	geco_packet.pk_comm_hdr.dest_port = htons(
		(generate_random_uint32() % USHRT_MAX));
	geco_packet.pk_comm_hdr.src_port = htons(
		(generate_random_uint32() % USHRT_MAX));
	geco_packet.pk_comm_hdr.verification_tag = htons(
		(generate_random_uint32()));
	//////////////////////////////////////////////////////////////////////////////
	init_chunk_t* init_chunk = (init_chunk_t*)(geco_packet.chunk);
	init_chunk->chunk_header.chunk_id = CHUNK_INIT;
	init_chunk->chunk_header.chunk_flags = 0;
	//////////////////////////////////////////////////////////////////////////////
	int i;
	const char* addres[] =
	{ "192.168.1.121", "192.168.1.132", "192.168.34.2" };
	const char* addres6[] =
	{ "2001:0db8:0a0b:12f0:0000:0000:0000:0001",
		"2607:f0d0:1002:0051:0000:0000:0000:0004" };
	sockaddrunion local_addres[3];
	sockaddrunion local_addres6[2];
	init_addrlist(true, 0, addres, 3, local_addres);
	init_addrlist(false, 0, addres6, 2, local_addres6);
	//////////////////////////////////////////////////////////////////////////////
	uint offset = 0;
	offset += put_vlp_supported_addr_types(init_chunk->variableParams, true,
		false, false);
	offset += put_vlp_addrlist(init_chunk->variableParams + offset, local_addres,
		3);
	offset += put_vlp_addrlist(init_chunk->variableParams + offset,
		local_addres6, 2);
	//////////////////////////////////////////////////////////////////////////////
	EXPECT_EQ(offset, 72);
	init_chunk->chunk_header.chunk_length = htons(
		INIT_CHUNK_FIXED_SIZES + offset);
	//////////////////////////////////////////////////////////////////////////////
	sockaddrunion peer_addreslist[MAX_NUM_ADDRESSES];
	dispatch_layer_t dlt;
	dlt.defaultlocaladdrlistsize_ = 0;
	//////////////////////////////////////////////////////////////////////////////
	char buf[MAX_IPADDR_STR_LEN];
	ushort port;
	//////////////////////////////////////////////////////////////////////////////
	sockaddrunion last_source_addr;
	dlt.last_source_addr_ = &last_source_addr;
	int ret;
	//////////////////////////////////////////////////////////////////////////////
	uint peersupportedtypes = 0;
	str2saddr(&last_source_addr, "2607:f0d0:1002:0051:0000:0000:0000:0005", 0,
		false);
	ret = dlt.read_peer_addreslist(peer_addreslist, geco_packet.chunk,
		offset + INIT_CHUNK_FIXED_SIZES,
		SUPPORT_ADDRESS_TYPE_IPV4,
		&peersupportedtypes);
	EXPECT_EQ(ret, 3); //3 ip4 addrs  but last src addr ths is ip6 not supported by us
	//ip4 addrs  plus last src addr is ip6
	EXPECT_EQ(peersupportedtypes,
		SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6);
	//////////////////////////////////////////////////////////////////////////////
	for (i = 0; i < 3; ++i)
	{
		saddr2str(&peer_addreslist[i], buf, MAX_IPADDR_STR_LEN, &port);
		EVENTLOG1(VERBOSE, "peer ip4addr: %s\n", buf);
		saddr2str(&local_addres[i], buf, MAX_IPADDR_STR_LEN, &port);
		EVENTLOG1(VERBOSE, "record ip4addr: %s\n", buf);
		EXPECT_TRUE(saddr_equals(&peer_addreslist[i], &local_addres[i], true));
	}
	//////////////////////////////////////////////////////////////////////////////
	str2saddr(&last_source_addr, "192.168.5.123", 0, true);
	ret = dlt.read_peer_addreslist(
		peer_addreslist, geco_packet.chunk, offset + INIT_CHUNK_FIXED_SIZES,
		SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6);
	EXPECT_EQ(ret, 6);
	for (i = 0; i < 3; ++i)
	{
		EXPECT_TRUE(saddr_equals(&peer_addreslist[i], &local_addres[i], true));
	}
	for (i = 3; i < 5; ++i)
	{
		EXPECT_TRUE(
			saddr_equals(&peer_addreslist[i], &local_addres6[i - 3], true));
	}
	EXPECT_TRUE(saddr_equals(&peer_addreslist[5], &last_source_addr, true));
	str2saddr(&last_source_addr, "2607:f0d0:1002:0051:0000:0000:0000:0005", 0,
		false);
	ret = dlt.read_peer_addreslist(peer_addreslist, geco_packet.chunk,
		offset + INIT_CHUNK_FIXED_SIZES,
		SUPPORT_ADDRESS_TYPE_IPV6);
	EXPECT_EQ(ret, 3);  //2 + last_source_addr_ = 3
	for (i = 0; i < 2; ++i)
	{
		saddr2str(&peer_addreslist[i], buf, MAX_IPADDR_STR_LEN, &port);
		EVENTLOG1(VERBOSE, "peer ip6addr: %s\n", buf);
		saddr2str(&local_addres6[i], buf, MAX_IPADDR_STR_LEN, &port);
		EVENTLOG1(VERBOSE, "record ip6addr: %s\n", buf);
		EXPECT_TRUE(saddr_equals(&peer_addreslist[i], &local_addres6[i], true));
	}
	EXPECT_TRUE(saddr_equals(&peer_addreslist[2], &last_source_addr, true));
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_contain_local_addr)
{
	/**
	 * check if local addr is found
	 * eg. ip4 loopback 127.0.0.1 or ip4  ethernet local addr 192.168.1.107 or public ip4 addr
	 * containslocaladdr(sockaddrunion* addr_list,uint addr_list_num);*/
	int i;
	const char* addres[] =
	{ "192.168.1.121", "192.168.1.132", "192.168.34.2" };
	const char* addres6[] =
	{ "2001:0db8:0a0b:12f0:0000:0000:0000:0001",
		"2607:f0d0:1002:0051:0000:0000:0000:0004" };
	sockaddrunion local_addres[3];
	sockaddrunion local_addres6[2];
	for (i = 0; i < 3; i++)
	{
		str2saddr(&local_addres[i], addres[i], 0, true);
	}
	for (i = 0; i < 2; i++)
	{
		str2saddr(&local_addres6[i], addres6[i], 0, false);
	}
	geco_instance_t inst;
	inst.supportedAddressTypes = SUPPORT_ADDRESS_TYPE_IPV4;
	inst.local_addres_size = 3;
	inst.local_addres_list = local_addres;
	//////////////////////////////////////////////////////////////////////////////
	dispatch_layer_t dlt;
	dlt.geco_instances_.push_back(&inst);
	sockaddrunion tmpaddr;
	//////////////////////////////////////////////////////////////////////////////
	//1) test branch 1 curr geco_inst and curr channel both NULL
	//1.1) test no local addr presents
	EXPECT_FALSE(dlt.contain_local_addr(local_addres, 3));
	EXPECT_FALSE(dlt.contain_local_addr(local_addres6, 2));
	//1.2) test  local addr presents
	tmpaddr = local_addres[1];
	str2saddr(&local_addres[1], "127.0.0.1", 0, true);
	EXPECT_TRUE(dlt.contain_local_addr(local_addres, 3));
	local_addres[1] = tmpaddr;
	tmpaddr = local_addres6[1];
	str2saddr(&local_addres6[1], "::1", 0, false);
	EXPECT_TRUE(dlt.contain_local_addr(local_addres6, 2));
	local_addres6[1] = tmpaddr;
	//////////////////////////////////////////////////////////////////////////////
	//2) test branch 2 curr_geco_instance_ NOT NULL
	dlt.curr_geco_instance_ = &inst;
	//2.1) test local addr in curr gecio inst local addres list
	tmpaddr = local_addres[1];
	EXPECT_TRUE(dlt.contain_local_addr(&tmpaddr, 1));
	//2.1) test no local addr in curr gecio inst local addres list
	str2saddr(&tmpaddr, "221.123.45.12", 0, true);
	EXPECT_FALSE(dlt.contain_local_addr(&tmpaddr, 1));
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_find_vlparam_from_setup_chunk)
{
	geco_packet_t geco_packet;
	geco_packet.pk_comm_hdr.checksum = 0;
	geco_packet.pk_comm_hdr.dest_port = htons(
		(generate_random_uint32() % USHRT_MAX));
	geco_packet.pk_comm_hdr.src_port = htons(
		(generate_random_uint32() % USHRT_MAX));
	geco_packet.pk_comm_hdr.verification_tag = htons(
		(generate_random_uint32()));
	//////////////////////////////////////////////////////////////////////////////
	init_chunk_t* init_chunk = (init_chunk_t*)(geco_packet.chunk);
	init_chunk->chunk_header.chunk_id = CHUNK_INIT;
	init_chunk->chunk_header.chunk_flags = 0;
	//////////////////////////////////////////////////////////////////////////////
	const char* hn = "www.baidu.com";
	((vlparam_fixed_t*)init_chunk->variableParams)->param_type = htons(
		VLPARAM_HOST_NAME_ADDR);
	((vlparam_fixed_t*)init_chunk->variableParams)->param_length = htons(
		4 + strlen(hn));
	strcpy((char*)(init_chunk->variableParams + 4), hn);
	//////////////////////////////////////////////////////////////////////////////
	uint len = 4 + strlen(hn) + INIT_CHUNK_FIXED_SIZES;
	init_chunk->chunk_header.chunk_length = htons(len);
	while (len % 4)
		++len;
	dispatch_layer_t dlt;
	uchar* ret = dlt.find_vlparam_from_setup_chunk(geco_packet.chunk, len,
		VLPARAM_HOST_NAME_ADDR);
	EXPECT_EQ(ret, init_chunk->variableParams);
	//////////////////////////////////////////////////////////////////////////////
	ret = dlt.find_vlparam_from_setup_chunk(geco_packet.chunk, len,
		VLPARAM_COOKIE);
	EXPECT_EQ(ret, (uchar*)NULL);
	ret = dlt.find_vlparam_from_setup_chunk(geco_packet.chunk, len,
		VLPARAM_SUPPORTED_ADDR_TYPES);
	EXPECT_EQ(ret, (uchar*)NULL);

}
// last run and passed on 29 Agu 2016
TEST(DISPATCHER_MODULE, test_bundle_ctrl_chunk)
{
	dispatch_layer_t dlt;
	int rcwnd = 512;
	network_interface_t nit;
	//nit.init(&rcwnd, true);
	dlt.transport_layer_ = &nit;
	sockaddrunion last_drc_addr;
	str2saddr(&last_drc_addr, "127.0.0.1", 456);
	dlt.last_source_addr_ = &last_drc_addr;
	dlt.last_dest_port_ = 123;
	dlt.last_src_port_ = 456;
	dlt.last_init_tag_ = 12345;
	//////////////////////////////////////////////////////////////////////////////
	uint cid = dlt.alloc_simple_chunk(CHUNK_SHUTDOWN_COMPLETE,
		FLAG_TBIT_SET);
	EXPECT_EQ(dlt.simple_chunks_[cid]->chunk_header.chunk_flags, 0x01);
	dlt.curr_write_pos_[cid] += 24;
	simple_chunk_t* simple_chunk_t_ptr_ = dlt.complete_simple_chunk(cid);
	EXPECT_EQ(dlt.simple_chunks_[cid]->chunk_header.chunk_length, htons(28));
	EXPECT_EQ(dlt.completed_chunks_[cid], true);
	dlt.free_simple_chunk(cid);
	dlt.default_bundle_ctrl_.reset();

	cid = dlt.alloc_simple_chunk(CHUNK_SHUTDOWN_COMPLETE,
		FLAG_TBIT_UNSET);
	EXPECT_EQ(dlt.simple_chunks_[cid]->chunk_header.chunk_flags, 0);
	simple_chunk_t_ptr_ = dlt.complete_simple_chunk(cid);
	EXPECT_EQ(dlt.simple_chunks_[cid]->chunk_header.chunk_length, htons(4));
	EXPECT_EQ(dlt.completed_chunks_[cid], true);
	dlt.free_simple_chunk(cid);
	dlt.default_bundle_ctrl_.reset();
	//////////////////////////////////////////////////////////////////////////////
	//1) if packet length < max_geco_
	cid = dlt.alloc_simple_chunk(CHUNK_SHUTDOWN_COMPLETE,
		FLAG_TBIT_UNSET);
	simple_chunk_t_ptr_ = dlt.complete_simple_chunk(cid);
	//  1.1) if dest_index == NULL
	dlt.bundle_ctrl_chunk(simple_chunk_t_ptr_, NULL);
	//      1.1.1) got_send_address shoul be false && requested_destination should be zero
	EXPECT_FALSE(dlt.default_bundle_ctrl_.got_send_address);
	EXPECT_EQ(dlt.default_bundle_ctrl_.requested_destination, 0);
	dlt.free_simple_chunk(cid);
	dlt.default_bundle_ctrl_.reset();
	//  1.2)if dest_index != NULL
	int path = 6;
	cid = dlt.alloc_simple_chunk(CHUNK_SHUTDOWN_COMPLETE,
		FLAG_TBIT_UNSET);
	simple_chunk_t_ptr_ = dlt.complete_simple_chunk(cid);
	dlt.bundle_ctrl_chunk(simple_chunk_t_ptr_, &path);
	//      1.2.1) got_send_address shoul be true && requested_destination should be 6
	EXPECT_TRUE(dlt.default_bundle_ctrl_.got_send_address);
	EXPECT_EQ(dlt.default_bundle_ctrl_.requested_destination, path);
	dlt.free_simple_chunk(cid);
	dlt.default_bundle_ctrl_.reset();
	//////////////////////////////////////////////////////////////////////////////
	//2) if packet length == max_geco_packet_length
	cid = dlt.alloc_simple_chunk(CHUNK_SHUTDOWN_COMPLETE,
		FLAG_TBIT_SET);
	dlt.curr_write_pos_[cid] += MAX_NETWORK_PACKET_VALUE_SIZE - 4;
	simple_chunk_t_ptr_ = dlt.complete_simple_chunk(cid);
	EXPECT_EQ(ntohs(simple_chunk_t_ptr_->chunk_header.chunk_length),
		MAX_NETWORK_PACKET_VALUE_SIZE);
	EXPECT_EQ(dlt.get_bundle_total_size(&dlt.default_bundle_ctrl_),
		UDP_GECO_PACKET_FIXED_SIZES);
	//  2.1 should not force send
	dlt.bundle_ctrl_chunk(simple_chunk_t_ptr_, &path);
	EXPECT_EQ(dlt.get_bundle_total_size(&dlt.default_bundle_ctrl_),
		MAX_GECO_PACKET_SIZE);
	dlt.free_simple_chunk(cid);
	//3) if packet length > max_geco_packet_length
	cid = dlt.alloc_simple_chunk(CHUNK_SHUTDOWN_COMPLETE,
		FLAG_TBIT_SET);
	dlt.curr_write_pos_[cid] += 4;
	simple_chunk_t_ptr_ = dlt.complete_simple_chunk(cid);
	EXPECT_EQ(ntohs(simple_chunk_t_ptr_->chunk_header.chunk_length), 8);
	EXPECT_EQ(dlt.get_bundle_total_size(&dlt.default_bundle_ctrl_), 1480);
	//  3.1 should force send && get_bundle_total_size == UDP_GECO_PACKET_FIXED_SIZES+8
	dlt.bundle_ctrl_chunk(simple_chunk_t_ptr_, &path);
	EXPECT_EQ(dlt.get_bundle_total_size(&dlt.default_bundle_ctrl_),
		UDP_GECO_PACKET_FIXED_SIZES + 8);
	dlt.free_simple_chunk(cid);
}
// last run and passed on 26 Agu 2016
TEST(DISPATCHER_MODULE, test_recv_geco_packet)
{
	bool enable_0_if_recv_invalidate_packet_addr_port_length_integritycheck_and_so_on =
		false;  // passed
	bool enable_1_ifanINITACKCHUNKisreceived = false;  // passed
	bool enable_2_if_recv_init_initack_shoutdowncomplete = false;  // passed
	bool enable_3_if_recv_ABORT_CHUNK = false;  //passed
	bool enable_4_if_recv_SHUTDOWN_ACK = false;  //passed
	bool enable_5_if_recv_SHUTDOWN_COMPLETE = false;  //passed
	bool enable_6_processinit_chunk = true; //passed
	/////////////////////////////////////////////////////////////////////////////////////
	EXPECT_EQ(sizeof(in_addr), 4);
	EXPECT_EQ(sizeof(in6_addr), 16);
	/////////////////////////////////////////////////////////////////////////////////////
	init();
	//disenable branch call  to test branch call this can reused all sample inputs to make life easier
	dlt.enable_mock_dispatcher_disassemle_curr_geco_packet_ = true;
	/////////////////////////////////////////////////////////////////////////////////////
	//0)if an invalidate packet is received
	if (enable_0_if_recv_invalidate_packet_addr_port_length_integritycheck_and_so_on)
	{
		sockaddrunion illegal_addr;
		illegal_addr.sin.sin_family = AF_INET;
		illegal_addr.sin.sin_port = 0;

		// 0.1) if it is broadcast addr
		illegal_addr.sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		//      0.1.1) should return recv_geco_packet_but_addrs_formate_check_failed
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			&illegal_addr, &inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_addrs_formate_check_failed);
		// 0.2) if it is any addr
		illegal_addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		//      0.2.1) should return recv_geco_packet_but_addrs_formate_check_failed
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			&illegal_addr, &inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_addrs_formate_check_failed);
		// 0.3) if either dest port or src port is zero,
		ushort oldport = geco_packet.pk_comm_hdr.dest_port;
		geco_packet.pk_comm_hdr.dest_port = 0;
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		//      0.3.1) should return recv_geco_packet_but_addrs_formate_check_failed
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			&illegal_addr, &inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_port_numbers_check_failed);
		geco_packet.pk_comm_hdr.dest_port = oldport;
		// 0.4) if geco packet len is not %4
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE + 1);
		//      0.4.1) should return recv_geco_packet_but_integrity_check_failed
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet,
			MIN_GECO_PACKET_SIZE + 1,
			&illegal_addr, &inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_integrity_check_failed);
		// 0.5) if geco packet len < MIN_GECO_PACKET_SIZE
		gset_checksum((char*)&geco_packet, 4);
		//      0.5.1) should return recv_geco_packet_but_integrity_check_failed
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, 4, &illegal_addr,
			&inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_integrity_check_failed);
		// 0.6) if geco packet len  > MAX_GECO_PACKET_SIZE
		gset_checksum((char*)&geco_packet, MAX_GECO_PACKET_SIZE + 1);
		//       0.6.1) should return recv_geco_packet_but_integrity_check_failed
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet,
			MAX_GECO_PACKET_SIZE + 1,
			&illegal_addr, &inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_integrity_check_failed);
		// 0.7) if VALIDATION OF checksum not equals,
		//      0.7.1) should return recv_geco_packet_but_integrity_check_failed
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			&illegal_addr, &inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_integrity_check_failed);
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	//1)if an INIT(ACK) CHUNK is received
	if (enable_1_ifanINITACKCHUNKisreceived)
	{
		// fills up init chunk hdr
		unsigned int initTag = htonl(generate_random_uint32());
		unsigned int arwnd = 512;
		unsigned short noOutStreams = 5;
		unsigned short noInStreams = 5;
		unsigned int initialTSN = initTag;
		init_chunk_t* init_chunk = build_init_chunk(initTag, rwnd, noOutStreams,
			noInStreams, initialTSN);

		for (i = 0; i < all_cannot_found_size; i++)
		{  //1.1) if channel is NOT found as src addr not matched
			last_src_addr = &all_cannot_found_addres[i];
			for (uint j = 0; j < channel.local_addres_size; j++)
			{
				last_dest_addr = &channel.local_addres[j];
				//1.2) but there is matched src addres in INIT chunk
				//1.2.1) fills up init with matched addrlist
				written = put_vlp_addrlist(init_chunk->variableParams, src_addres,
					srcaddr4_size);
				written += put_vlp_addrlist(&init_chunk->variableParams[written],
					src_addres6, srcaddr6_size);
				written += put_vlp_supported_addr_types(
					&init_chunk->variableParams[written], true, true, false);
				dctp_packet_len = written + INIT_CHUNK_FIXED_SIZES
					+ GECO_PACKET_FIXED_SIZE;
				init_chunk->chunk_header.chunk_length = htons(
					INIT_CHUNK_FIXED_SIZES + written);
				memcpy(geco_packet.chunk, init_chunk,
					dctp_packet_len - GECO_PACKET_FIXED_SIZE);
				gset_checksum((char*)&geco_packet, dctp_packet_len);
				EXPECT_EQ(INIT_CHUNK_FIXED_SIZES + written, 92);
				ret = dlt.recv_geco_packet(0, (char*)dctp_packet, dctp_packet_len,
					last_src_addr, last_dest_addr);
				//1.2.2) should find an existed channel
				ASSERT_EQ(ret, geco_return_enum::good);
				ASSERT_EQ(dlt.curr_channel_, &channel);

				//1.3) there is NO matched src addres in INIT chunk
				//  1.3.1) fills up init with unmatched addrlist
				written = 0;
				dctp_packet_len = 0;
				written += put_vlp_supported_addr_types(init_chunk->variableParams,
					true, true, false);
				dctp_packet_len = written + INIT_CHUNK_FIXED_SIZES
					+ GECO_PACKET_FIXED_SIZE;
				init_chunk->chunk_header.chunk_length = htons(
					INIT_CHUNK_FIXED_SIZES + written);
				memcpy(geco_packet.chunk, init_chunk,
					dctp_packet_len - GECO_PACKET_FIXED_SIZE);
				gset_checksum((char*)&geco_packet, dctp_packet_len);
				EXPECT_EQ(INIT_CHUNK_FIXED_SIZES + written, 28);
				ret = dlt.recv_geco_packet(0, (char*)dctp_packet, dctp_packet_len,
					last_src_addr, last_dest_addr);
				//1.3.2) should NOT find an existed channel
				ASSERT_EQ(ret, geco_return_enum::good);
				ASSERT_EQ(dlt.curr_channel_, (channel_t*)NULL);
			}
		}
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	//2) if recv init, init ack or shutdown complete chunks
	if (enable_2_if_recv_init_initack_shoutdowncomplete)
	{
		//2.1) if they are not the only one chunk in the packet
		// here we add another data chunk
		last_src_addr = &channel.remote_addres[0];
		last_dest_addr = &channel.local_addres[0];
		uchar chunktypes[3] =
		{ CHUNK_INIT_ACK, CHUNK_INIT, CHUNK_SHUTDOWN_COMPLETE };
		uint reterrnos[3] =
		{ recv_geco_packet_but_morethanone_init_ack,
			recv_geco_packet_but_morethanone_init,
			recv_geco_packet_but_morethanone_shutdown_complete };

		((chunk_fixed_t*)&geco_packet.chunk[4])->chunk_id = CHUNK_DATA;
		((chunk_fixed_t*)&geco_packet.chunk[4])->chunk_flags = 0;
		((chunk_fixed_t*)&geco_packet.chunk[4])->chunk_length = htons(4);
		dctp_packet_len = 2 * CHUNK_FIXED_SIZE + GECO_PACKET_FIXED_SIZE;

		((chunk_fixed_t*)geco_packet.chunk)->chunk_flags = 0;
		((chunk_fixed_t*)geco_packet.chunk)->chunk_length = htons(4);
		for (int i = 0; i < 3; ++i)
		{
			((chunk_fixed_t*)geco_packet.chunk)->chunk_id = chunktypes[i];
			//2.2) the packet should be discarded
			gset_checksum((char*)&geco_packet, dctp_packet_len);
			ret = dlt.recv_geco_packet(0, (char*)dctp_packet, dctp_packet_len,
				last_src_addr, last_dest_addr);
			ASSERT_EQ(ret, (uint)reterrnos[i]);
		}
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	//3) if recv ABORT CHUNK
	if (enable_3_if_recv_ABORT_CHUNK)
	{
		((chunk_fixed_t*)geco_packet.chunk)->chunk_id = CHUNK_ABORT;
		((chunk_fixed_t*)geco_packet.chunk)->chunk_flags = 0;
		((chunk_fixed_t*)geco_packet.chunk)->chunk_length = htons(4);
		//3.1 if ootb packet
		last_src_addr = &all_cannot_found_addres[0];
		//  3.1.1 should discard
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_it_is_ootb_abort_discard);
		//3.2 if non-ootb packet
		last_src_addr = &channel.remote_addres[0];
		//  3.2.1)if tbit set && last_veri_tag_ == curr_channel_->remote_tag
		((chunk_fixed_t*)geco_packet.chunk)->chunk_flags = 0x01;
		geco_packet.pk_comm_hdr.verification_tag = htonl(channel.remote_tag);
		//      3.2.1.1) should go on
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &channel.local_addres[0]);
		ASSERT_EQ(ret, good);
		ASSERT_EQ(dlt.is_found_abort_chunk_, true);
		//  3.2)if !is_tbit_set && last_veri_tag_ == curr_channel_->local_tag)
		((chunk_fixed_t*)geco_packet.chunk)->chunk_flags = 0;
		geco_packet.pk_comm_hdr.verification_tag = htonl(channel.local_tag);
		//      3.2.1) should go on
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &channel.local_addres[0]);
		ASSERT_EQ(ret, good);
		ASSERT_EQ(dlt.is_found_abort_chunk_, true);
		//  3.3)if tbit and verifi tag not matched
		((chunk_fixed_t*)geco_packet.chunk)->chunk_flags = 0;
		geco_packet.pk_comm_hdr.verification_tag = htonl(channel.remote_tag);
		//  3.3.1)should discard
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &channel.local_addres[0]);
		ASSERT_EQ(ret,
			recv_geco_packet_but_nootb_abort_chunk_has_ielegal_verifi_tag);
	}
	/////////////////////////////////////////////////////////////////////////////////////
	//4) if recv SHUTDOWN_ACK
	if (enable_4_if_recv_SHUTDOWN_ACK)
	{
		((chunk_fixed_t*)geco_packet.chunk)->chunk_id = CHUNK_SHUTDOWN_ACK;
		((chunk_fixed_t*)geco_packet.chunk)->chunk_flags = 0;
		((chunk_fixed_t*)geco_packet.chunk)->chunk_length = htons(4);
		geco_packet.pk_comm_hdr.verification_tag = htonl(channel.local_tag);

		//3.1 if ootb packet
		last_src_addr = &all_cannot_found_addres[0];
		//  3.1.1 should discard
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_it_is_ootb_sdack_send_sdc);
		//3.2 if non-ootb packet
		last_src_addr = &channel.remote_addres[0];
		//  3.2.1)if curr channel state is neither cookie echoed nor cookie wait
		channel.state_machine_control->channel_state = ChannelState::ShutdownSent;
		//      3.2.1.1) should go on
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &channel.local_addres[0]);
		ASSERT_EQ(ret, good);
		//  3.2.2)if curr channel state is either cookie echoed or cookie wait
		channel.state_machine_control->channel_state = ChannelState::CookieWait;
		//      3.2.2.1) should send shutdown complete chunk to the peer
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &channel.local_addres[0]);
		ASSERT_EQ(ret, discard);
		//  3.2.3)if veri tag unmatched channel local tag
		geco_packet.pk_comm_hdr.verification_tag = htonl(channel.local_tag - 1);
		channel.state_machine_control->channel_state = ChannelState::ShutdownSent;
		//      3.2.3.1) should discard
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &channel.local_addres[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_nootb_packet_verifitag_illegal);
	}
	/////////////////////////////////////////////////////////////////////////////////////
	//5) if recv SHUTDOWN_COMPLETE
	if (enable_5_if_recv_SHUTDOWN_COMPLETE)
	{
		((chunk_fixed_t*)geco_packet.chunk)->chunk_id =
			CHUNK_SHUTDOWN_COMPLETE;
		((chunk_fixed_t*)geco_packet.chunk)->chunk_flags = 0;
		((chunk_fixed_t*)geco_packet.chunk)->chunk_length = htons(4);
		geco_packet.pk_comm_hdr.verification_tag = htonl(channel.local_tag);

		//4.1 if ootb packet
		last_src_addr = &all_cannot_found_addres[0];
		//  4.1.1 should discard
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &inst.local_addres_list[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_it_is_ootb_sdc_discard);
		//4.2 if non-ootb packet
		last_src_addr = &channel.remote_addres[0];
		//  4.2.1)if curr channel state is not ShutdownAckSent
		channel.state_machine_control->channel_state = ChannelState::Connected;
		//      4.2.1.1) should discard
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &channel.local_addres[0]);
		ASSERT_EQ(ret,
			recv_geco_packet_but_nootb_sdc_recv_otherthan_sdc_ack_sentstate);
		//  4.2.2)if curr channel state is ShutdownAckSent
		channel.state_machine_control->channel_state =
			ChannelState::ShutdownAckSent;
		//      4.2.2.1) if verifi tag matched
		((chunk_fixed_t*)geco_packet.chunk)->chunk_flags = 0;
		geco_packet.pk_comm_hdr.verification_tag = htonl(channel.local_tag);
		//          4.2.2.2 should go on
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &channel.local_addres[0]);
		ASSERT_EQ(ret, good);
		//  3.2.3)if veri tag unmatched
		geco_packet.pk_comm_hdr.verification_tag = htonl(channel.local_tag - 1);
		//      3.2.3.1) should discard
		gset_checksum((char*)&geco_packet, MIN_GECO_PACKET_SIZE);
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, MIN_GECO_PACKET_SIZE,
			last_src_addr, &channel.local_addres[0]);
		ASSERT_EQ(ret, recv_geco_packet_but_nootb_sdc_recv_verifitag_illegal);
	}
	/////////////////////////////////////////////////////////////////////////////////////

	unsigned int initTag = htonl(generate_random_uint32());
	unsigned int arwnd = 512;
	unsigned short noOutStreams = 5;
	unsigned short noInStreams = 5;
	unsigned int initialTSN = initTag;
	init_chunk_t* init_chunk = build_init_chunk(initTag, rwnd, noOutStreams,
		noInStreams, initialTSN);

	if (enable_6_processinit_chunk)
	{
		reset_geco_packet_fixed()
			;

		dlt.enable_mock_dispatcher_disassemle_curr_geco_packet_ = false;
		dlt.enable_mock_dispatcher_process_init_chunk_ = false;

		//1.1) if channel is NOT found as src addr not matched
		last_src_addr = &all_cannot_found_addres[0];
		last_dest_addr = &channel.local_addres[0];
		//　there is NO matched src addres in INIT chunk
		//   fills up init with unmatched addrlist
		written = 0;
		dctp_packet_len = 0;
		//    written = put_vlp_addrlist(init_chunk->variableParams, all_cannot_found_addres,
		//            all_cannot_found_size);
		written += put_vlp_supported_addr_types(
			&init_chunk->variableParams[written], true, true, false);
		dctp_packet_len = written + INIT_CHUNK_FIXED_SIZES + GECO_PACKET_FIXED_SIZE;
		init_chunk->chunk_header.chunk_length = htons(
			INIT_CHUNK_FIXED_SIZES + written);
		memcpy(geco_packet.chunk, init_chunk,
			dctp_packet_len - GECO_PACKET_FIXED_SIZE);
		gset_checksum((char*)&geco_packet, dctp_packet_len);
		printf(
			"..............................................test branch call disassemble's branch call process_init_chunk()...................................\n");
		ret = dlt.recv_geco_packet(0, (char*)dctp_packet, dctp_packet_len,
			last_src_addr, last_dest_addr);
	}

}
// last run and passed on 21 Agu 2016
TEST(DISPATCHER_MODULE, test_contains_chunk)
{
	/**
	 * contains_chunk: looks for chunk_type in a newly received geco packet
	 * Should be called after find_chunk_types().
	 * The chunkArray parameter is inspected. This only really checks for chunks
	 * with an ID <= 30. For all other chunks, it just guesses...
	 * @return 0 NOT contains, 1 contains and only one, 2 contains and NOT only one
	 * @pre: need call find_chunk_types() first
	 */
	uint chunk_types;
	dispatch_layer_t dlt;
	//////////////////////////////////////////////////////////////////////////////
	chunk_types = 0;
	EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 0);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_HBREQ, chunk_types), 0);
	//////////////////////////////////////////////////////////////////////////////
	// INIT must be the only chunk in the packet
	chunk_types = 0;
	chunk_types |= 1 << CHUNK_INIT;
	EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 1);
	//////////////////////////////////////////////////////////////////////////////
	chunk_types = 0;
	chunk_types |= 1 << CHUNK_DATA;
	chunk_types |= 1 << CHUNK_SACK;
	chunk_types |= 1 << CHUNK_HBREQ;
	EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 2);
	EXPECT_EQ(dlt.contains_chunk(CHUNK_HBREQ, chunk_types), 2);
	//////////////////////////////////////////////////////////////////////////////
}



