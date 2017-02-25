/*
 * geco-test.cc
 *
 *  Created on: 22Feb.,2017
 *      Author: jackiez
 */

#include "geco-test.h"

int UT_INST_ID = -1;
int UT_CHANNEL_ID = -1;
static uchar UT_LOCAL_ADDR_LIST[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN] =
  { 0 };
ulp_cbs_t UT_ULPcallbackFunctions =
  { 0 };

extern int
mulp_new_geco_instance (
    unsigned short localPort, unsigned short noOfOrderStreams,
    unsigned short noOfSeqStreams, unsigned int noOfLocalAddresses,
    unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN],
    ulp_cbs_t ULPcallbackFunctions);
void
alloc_geco_instance ()
{

  bool fip4 = false, fip6 = false;
  char ip4addrstr[MAX_IPADDR_STR_LEN];
  char ip6addrstr[MAX_IPADDR_STR_LEN];
  for (uint i = 0; i < defaultlocaladdrlistsize_; i++)
  {
    if (!fip4 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET)
    {
      fip4 = true;
      saddr2str (&defaultlocaladdrlist_[i], ip4addrstr, MAX_IPADDR_STR_LEN);
      if (fip6)
        break;
    }
    if (!fip6 && defaultlocaladdrlist_[i].sa.sa_family == AF_INET6)
    {
      fip6 = true;
      saddr2str (&defaultlocaladdrlist_[i], ip6addrstr, MAX_IPADDR_STR_LEN);
      if (fip4)
        break;
    }
  }
  //use ip6 any and ip4 any
  strcpy ((char*) UT_LOCAL_ADDR_LIST[0], "0.0.0.0");
  strcpy ((char*) UT_LOCAL_ADDR_LIST[1], "::0");
  initialize_library ();
  lib_params_t lib_infos;
  mulp_get_lib_params (&lib_infos);
  UT_INST_ID = mulp_new_geco_instance (UT_LOCAL_PORT, UT_ORDER_STREAM,
                                       UT_SEQ_STREAM, UT_LOCAL_ADDR_LIST_SIZE,
                                       UT_LOCAL_ADDR_LIST,
                                       UT_ULPcallbackFunctions);
  curr_geco_instance_ = geco_instances_[UT_INST_ID];
}
void
free_geco_instance ()
{
  if (UT_INST_ID > -1)
  {
    mulp_delete_geco_instance (UT_INST_ID);
    free_library ();
    UT_INST_ID = -1;
  }
  curr_geco_instance_ = NULL;
}

extern bool
mdi_new_channel (geco_instance_t* instance, ushort local_port,
                 ushort remote_port, uint tagLocal,
                 short primaryDestinitionAddress,
                 ushort noOfDestinationAddresses,
                 sockaddrunion *destinationAddressLis);
extern ushort
mdi_init_channel (uint remoteSideReceiverWindow, ushort noOfOrderStreams,
                  ushort noOfSeqStreams, uint remoteInitialTSN, uint tagRemote,
                  uint localInitialTSN, bool assocSupportsPRSCTP,
                  bool assocSupportsADDIP);
extern void
set_channel_remote_addrlist (sockaddrunion destaddrlist[MAX_NUM_ADDRESSES],
                             int noOfAddresses);
extern void
mdi_delete_curr_channel ();
extern void mdi_on_peer_connected(uint status);
extern bool mdi_connect_udp_sfd_;
extern bundle_controller_t* default_bundle_ctrl_;
void
alloc_geco_channel ()
{
  sockaddrunion dest_su[UT_REMOTE_ADDR_LIST_SIZE];
  str2saddr (dest_su, "192.168.1.1", UT_PEER_PORT);
  str2saddr (dest_su + 1, "192.168.1.2", UT_PEER_PORT);

  // sometimes delete_curr_channle() is called that will zero curr_geco_instance_  and so
  // UT_INST_ID can be used as flag to show if still existing. if so, reuse the existing curr_geco_instance_
  if (UT_INST_ID < 0)
    alloc_geco_instance ();
  else
    curr_geco_instance_ = geco_instances_[UT_INST_ID];

  mdi_new_channel (curr_geco_instance_, UT_LOCAL_PORT, UT_PEER_PORT, UT_ITAG,
                   UT_PRI_PATH_ID, UT_REMOTE_ADDR_LIST_SIZE, dest_su);

  mdi_init_channel (UT_ARWND, UT_ORDER_STREAM, UT_SEQ_STREAM, UT_ITSN, UT_ITAG,
                    UT_ITSN, PR, ADDIP);

  //fills channel_map
  set_channel_remote_addrlist (dest_su, UT_REMOTE_ADDR_LIST_SIZE);

  //make use of UDP socketto ease test
  mdi_connect_udp_sfd_ = true;
  default_bundle_ctrl_->geco_packet_fixed_size =
      GECO_PACKET_FIXED_SIZE_USE_UDP;
  default_bundle_ctrl_->curr_max_pdu = PMTU_LOWEST - IP_HDR_SIZE
      - UDP_HDR_SIZE;

  //make max_channel_retrans_count = 2,max_retrans_per_path = 1,fills path_map
  mdi_on_peer_connected(ChannelState::Closed);
  curr_channel_->path_control->max_retrans_per_path = 2;
  curr_channel_->state_machine_control->max_assoc_retrans_count =
      UT_REMOTE_ADDR_LIST_SIZE
          * curr_channel_->path_control->max_retrans_per_path;

  UT_CHANNEL_ID = channels_size_ - 1;
  curr_channel_ = channels_[0];
  curr_channel_->geco_inst = curr_geco_instance_;
}

void
free_geco_channel ()
{
  if (UT_CHANNEL_ID > -1)
  {
    mdi_delete_curr_channel ();
    free_geco_instance ();
    UT_CHANNEL_ID = -1;
  }
  curr_geco_instance_ = NULL;
  curr_channel_ = NULL;
}

TEST(UT_HELPER, test_make_geco_instance)
{
  alloc_geco_instance ();
  free_geco_instance ();
}

TEST(UT_HELPER, test_make_geco_channel)
{
  alloc_geco_channel ();
  free_geco_channel ();
}

extern void reset_channel()
{
	
}
