/*
 * geco-test.h
 *
 *  Created on: 22Feb.,2017
 *      Author: jackiez
 */

#ifndef UNITTETS_GECO_TEST_H_
#define UNITTETS_GECO_TEST_H_

#include "spdlog/spdlog.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "geco-net-config.h"
#include "geco-net.h"

 // @caution because geco-ds-malloc includes geco-thread.h that includes window.h
 // but transport_layer.h includes wsock2.h, as we know, it must include before windows.h
 // so if you uncomment this line, will cause error
 //#include "geco-ds-malloc.h"
#include "geco-net-transport.h"
#include "geco-net-dispatch.h"

#include "geco-ds-malloc.h"
#include "geco-malloc.h"
using namespace geco::ds;

/**
 * ut specific defines, global variables and functions
 */
const ushort UT_LOCAL_PORT = 123;
const ushort UT_PEER_PORT = 456;
const ushort UT_ORDER_STREAM = 32;
const ushort UT_SEQ_STREAM = 32;
const uint UT_ITAG = 1;
const uint UT_ITSN = 1;
const short UT_PRI_PATH_ID = 0;
const uint UT_ARWND = 65535;
const bool ADDIP = true;
const bool PR = true;
extern int UT_INST_ID;
extern int UT_CHANNEL_ID;
const uint UT_LOCAL_ADDR_LIST_SIZE = 2;
const uint UT_REMOTE_ADDR_LIST_SIZE = 2;
extern ulp_cbs_t UT_ULPcallbackFunctions;
extern uchar UT_LOCAL_ADDR_LIST[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN];

extern void
alloc_geco_instance();
extern void
free_geco_instance();
extern void
alloc_geco_channel();
extern void
free_geco_channel();

/**
 * module specific defines, global variables and functions
 */
extern int myRWND;
extern uint ipv4_sockets_geco_instance_users;
extern uint ipv6_sockets_geco_instance_users;
extern uint defaultlocaladdrlistsize_;
extern sockaddrunion* defaultlocaladdrlist_;
/* store all instances, instance name as key*/
extern std::vector<geco_instance_t*> geco_instances_;
extern geco_channel_t** channels_;
extern uint channels_size_;
extern geco_instance_t *curr_geco_instance_;
extern geco_channel_t *curr_channel_;
extern bool is_found_abort_chunk_;
/* where is the next write starts */
extern uint curr_write_pos_[MAX_CHUNKS_SIZE];
/* simple ctrl chunks to send*/
extern simple_chunk_t* simple_chunks_[MAX_CHUNKS_SIZE];
/*if a chunk is completely constructed*/
extern bool completed_chunks_[MAX_CHUNKS_SIZE];
/* current simple chunk index */
extern uint simple_chunk_index_;
/* current simple chunk ptr */
extern simple_chunk_t* simple_chunk_t_ptr_;
extern bundle_controller_t* default_bundle_ctrl_;
//cmp_channel() will set last_src_path_ to
//the one found src's index in channel's remote addr list
extern int last_src_path_;
extern ushort last_src_port_;
extern ushort last_dest_port_;
extern uint last_init_tag_;
extern uint last_veri_tag_;
//store all usable channel ids,
//can be reused when creatng a new channel
extern uint* available_channel_ids_;
extern uint available_channel_ids_size_;
extern bool mdi_connect_udp_sfd_;
struct transportaddr_hash_functor;
struct transportaddr_cmp_functor;
#ifdef _WIN32
extern std::unordered_map<transport_addr_t, uint, transportaddr_hash_functor, transportaddr_cmp_functor> channel_map_;
#else
extern std::tr1::unordered_map<transport_addr_t, uint,
	transportaddr_hash_functor, transportaddr_cmp_functor> channel_map_;
#endif
extern transport_addr_t curr_trans_addr_;

extern int
mulp_new_geco_instance(
	unsigned short localPort, unsigned short noOfOrderStreams,
	unsigned short noOfSeqStreams, unsigned int noOfLocalAddresses,
	unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN],
	ulp_cbs_t ULPcallbackFunctions);
extern bool
mdi_new_channel(geco_instance_t* instance, ushort local_port,
	ushort remote_port, uint tagLocal,
	short primaryDestinitionAddress,
	ushort noOfDestinationAddresses,
	sockaddrunion *destinationAddressLis);
extern ushort
mdi_init_channel(uint remoteSideReceiverWindow, ushort noOfOrderStreams,
	ushort noOfSeqStreams, uint remoteInitialTSN, uint tagRemote,
	uint localInitialTSN, bool assocSupportsPRSCTP,
	bool assocSupportsADDIP);
extern void
set_channel_remote_addrlist(sockaddrunion destaddrlist[MAX_NUM_ADDRESSES],
	int noOfAddresses);
extern void
mdi_delete_curr_channel();
extern void
mdi_on_peer_connected(uint status);
extern geco_instance_t*
mdi_find_geco_instance(sockaddrunion* dest_addr, ushort dest_port);
extern geco_channel_t*
mdi_find_channel(sockaddrunion * src_addr, ushort src_port, ushort dest_port);
extern bool
validate_dest_addr(sockaddrunion * dest_addr);
extern uint
find_chunk_types(uchar* packet_value, uint packet_val_len,
	uint* total_chunk_count);
extern int
contains_chunk(uint chunk_type, uint chunk_types);
extern uchar*
mch_find_first_chunk_of(uchar * packet_value, uint packet_val_len,
	uint chunk_type);
extern uchar*
mch_read_vlparam_init_chunk(uchar * setup_chunk, uint chunk_len,
	ushort param_type);
extern int
mdi_read_peer_addreslist(sockaddrunion peer_addreslist[MAX_NUM_ADDRESSES],
	uchar * chunk, uint len, uint my_supported_addr_types,
	uint* peer_supported_addr_types, bool ignore_dups,
	bool ignore_last_src_addr);
extern bool
mdi_contains_localaddr(sockaddrunion* addr_list, uint addr_list_num);
extern inline uint
mch_make_simple_chunk(uint chunk_type, uchar flag);
extern inline simple_chunk_t *
mch_complete_simple_chunk(uint chunkID);
extern void
mch_free_simple_chunk(uint chunkID);
extern void
mdi_bundle_ctrl_chunk(simple_chunk_t * chunk, int * dest_index = NULL);
extern uint
get_bundle_total_size(bundle_controller_t* buf);
extern void
mdi_set_channel_remoteaddrlist(sockaddrunion addresses[MAX_NUM_ADDRESSES], int noOfAddresses);
extern geco_channel_t* mdi_find_channel();
extern void mch_write_vlp_supportedaddrtypes(chunk_id_t chunkID, bool with_ipv4, bool with_ipv6, bool with_dns);
void print_addrlist(sockaddrunion* list, uint nAddresses);

struct transportaddr_hash_functor
{
	size_t
		operator() (const transport_addr_t &addr) const
	{
		return transportaddr2hashcode(addr.local_saddr, addr.peer_saddr);
	}
};
struct transportaddr_cmp_functor
{
	bool
		operator() (const transport_addr_t& addr1,
			const transport_addr_t &addr2) const
	{
		return saddr_equals(addr1.local_saddr, addr2.local_saddr)
			&& saddr_equals(addr1.peer_saddr, addr2.peer_saddr);
	}
};
#endif /* UNITTETS_GECO_TEST_H_ */
