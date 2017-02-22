/*
 * geco-test.cc
 *
 *  Created on: 22Feb.,2017
 *      Author: jackiez
 */

#include "geco-test.h"

static const ushort UT_LOCAL_PORT = 123;
static const ushort UT_PEER_PORT = 456;
static const ushort UT_ISTREAM = 32;
static const ushort UT_OSTREAM = 32;
static const uint UT_ITAG = 1;
static const short UT_PRI_PATH_ID = 0;

static int instid = -1;
static int channelid = -1;
static uint UT_LOCAL_ADDR_LIST_SIZE = 0;
static uchar UT_LOCAL_ADDR_LIST[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN] =
  { 0 };
static ulp_cbs_t ULPcallbackFunctions =
  { 0 };

extern int
mulp_new_geco_instance (
    unsigned short localPort, unsigned short noOfInStreams,
    unsigned short noOfOutStreams, unsigned int noOfLocalAddresses,
    unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN],
    ulp_cbs_t ULPcallbackFunctions);
geco_instance_t*
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
  UT_LOCAL_ADDR_LIST_SIZE = 2;
  strcpy ((char*) UT_LOCAL_ADDR_LIST[0], "0.0.0.0");
  strcpy ((char*) UT_LOCAL_ADDR_LIST[1], "::0");
  initialize_library ();
  lib_params_t lib_infos;
  mulp_get_lib_params (&lib_infos);
  instid = mulp_new_geco_instance (UT_LOCAL_PORT, UT_ISTREAM, UT_OSTREAM,
                                   UT_LOCAL_ADDR_LIST_SIZE, UT_LOCAL_ADDR_LIST,
                                   ULPcallbackFunctions);
  return geco_instances_[instid];
}
void
free_geco_instance ()
{
  //delete last instance after testing commons
  if (instid > -1)
  {
    mulp_delete_geco_instance (instid);
    free_library ();
    instid = -1;
  }
}

extern bool
mdi_new_channel (geco_instance_t* instance, ushort local_port,
                 ushort remote_port, uint tagLocal,
                 short primaryDestinitionAddress,
                 ushort noOfDestinationAddresses,
                 sockaddrunion *destinationAddressLis);
geco_channel_t*
alloc_geco_channel ()
{
  sockaddrunion dest_su[2];
  str2saddr (dest_su, "192.168.1.1");
  str2saddr (dest_su + 1, "192.168.1.2");
  ushort destinationPort = 456;
  ushort ppath = 0;
  ASSERT_EQ(
      mdi_new_channel (alloc_geco_instance (), UT_LOCAL_PORT, UT_PEER_PORT,
                       UT_ITAG, UT_PRI_PATH_ID, 2, dest_su),
      true);
  channelid = channels_size_ -1;
  return channels_[0];
}

void
free_geco_channel()
{
  if(channelid > -1)
  {
    msm_abort_channel ();
    free_geco_instance();
    channelid = -1;
  }
}

TEST(mpath, test_make_geco_instance)
{
  geco_instance_t* inst = alloc_geco_instance ();
  EXPECT_EQ(inst->is_in6addr_any, true);
  free_geco_instance ();
}
