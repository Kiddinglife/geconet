#include <iostream>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "geco-net-common.h"
#include "geco-net-dispatch.h"
#include "geco-net.h"

TEST(MULP, test_initialize_and_free_library)
{
  initialize_library ();
  free_library ();
}
TEST(MULP, test_mulp_get_lib_params)
{
  //precondition lib has been inited
  initialize_library ();

  lib_params_t lib_infos;
  mulp_get_lib_params (&lib_infos);
  ASSERT_EQ(lib_infos.checksum_algorithm, MULP_CHECKSUM_ALGORITHM_MD5);
  ASSERT_EQ(lib_infos.delayed_ack_interval, 200);
  ASSERT_EQ(lib_infos.send_ootb_aborts, true);
  ASSERT_EQ(lib_infos.support_dynamic_addr_config, true);
  ASSERT_EQ(lib_infos.support_particial_reliability, true);

  free_library ();
}
TEST(MULP, test_mulp_set_lib_params)
{
  //precondition lib has been inited
  initialize_library ();

  lib_params_t lib_infos;
  mulp_get_lib_params (&lib_infos);

  lib_infos.checksum_algorithm = MULP_CHECKSUM_ALGORITHM_CRC32C;
  lib_infos.delayed_ack_interval = 50; // must be smaller than 500ms
  lib_infos.send_ootb_aborts = false;
  lib_infos.support_dynamic_addr_config = false;
  lib_infos.support_particial_reliability = false;
  mulp_set_lib_params (&lib_infos);

  mulp_get_lib_params (&lib_infos);
  ASSERT_EQ(lib_infos.checksum_algorithm, MULP_CHECKSUM_ALGORITHM_CRC32C);
  ASSERT_EQ(lib_infos.delayed_ack_interval, 50);
  ASSERT_EQ(lib_infos.send_ootb_aborts, false);
  ASSERT_EQ(lib_infos.support_dynamic_addr_config, false);
  ASSERT_EQ(lib_infos.support_particial_reliability, false);

  free_library ();
}

extern std::vector<geco_instance_t*> geco_instances_;
extern int myRWND;
extern uint ipv4_sockets_geco_instance_users;
extern uint ipv6_sockets_geco_instance_users;
extern int defaultlocaladdrlistsize_;
extern sockaddrunion* defaultlocaladdrlist_;
TEST(MULP, test_mulp_mulp_new_and_delete_geco_instnce)
{
  //precondition lib has been inited
  initialize_library ();
  lib_params_t lib_infos;
  mulp_get_lib_params (&lib_infos);
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
  strcpy ((char*) localAddressList[0], "0.0.0.0");
  strcpy ((char*) localAddressList[1], "::0");
  ULPcallbackFunctions =
  { 0};
  instid = mulp_new_geco_instance (localPort, noOfInStreams, noOfOutStreams,
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
  mulp_delete_geco_instance (instid);
  ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
  ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

  //ip6 not any and ip4 any
  localPort = 124;
  strcpy ((char*) localAddressList[0], "0.0.0.0");
  strcpy ((char*) localAddressList[1], ip6addrstr);
  instid = mulp_new_geco_instance (localPort, noOfInStreams, noOfOutStreams,
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
  mulp_delete_geco_instance (instid);
  ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
  ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

  //ip6 any and ip4 not any
  localPort = 125;
  strcpy ((char*) localAddressList[0], "127.0.0.1");
  strcpy ((char*) localAddressList[1], "::0");
  instid = mulp_new_geco_instance (localPort, noOfInStreams, noOfOutStreams,
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
  strcpy ((char*) localAddressList[0], "127.0.0.1");
  strcpy ((char*) localAddressList[1], "::1");
  instid = mulp_new_geco_instance (localPort, noOfInStreams, noOfOutStreams,
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
  mulp_delete_geco_instance (lastinstid);
  mulp_delete_geco_instance (instid);
  ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
  ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

  //ip6 any
  localPort = 127;
  noOfLocalAddresses = 1;
  strcpy ((char*) localAddressList[0], "::0");
  instid = mulp_new_geco_instance (localPort, noOfInStreams, noOfOutStreams,
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
  mulp_delete_geco_instance (instid);
  ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
  ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

  //ip4 any
  localPort = 128;
  noOfLocalAddresses = 1;
  strcpy ((char*) localAddressList[0], "0.0.0.0");
  instid = mulp_new_geco_instance (localPort, noOfInStreams, noOfOutStreams,
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
  mulp_delete_geco_instance (instid);
  ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
  ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

  //ip6
  localPort = 129;
  noOfLocalAddresses = 1;
  strcpy ((char*) localAddressList[0], ip6addrstr);
  instid = mulp_new_geco_instance (localPort, noOfInStreams, noOfOutStreams,
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
  mulp_delete_geco_instance (instid);
  ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
  ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

  //ip4
  localPort = 130;
  noOfLocalAddresses = 1;
  strcpy ((char*) localAddressList[0], ip4addrstr);
  instid = mulp_new_geco_instance (localPort, noOfInStreams, noOfOutStreams,
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
  mulp_delete_geco_instance (instid);
  ASSERT_EQ(ipv4_sockets_geco_instance_users, 0);
  ASSERT_EQ(ipv6_sockets_geco_instance_users, 0);

  free_library ();
}

extern int
mtra_poll (void
(*lock) (void* data),
           void
           (*unlock) (void* data),
           void* data);
TEST(MULP, test_mulp_connect)
{
  //precondition lib has been inited
  initialize_library ();

  lib_params_t lib_infos;
  mulp_get_lib_params (&lib_infos);

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
  strcpy ((char*) localAddressList[0], "0.0.0.0");
  strcpy ((char*) localAddressList[1], "::0");
  ULPcallbackFunctions =
  { 0};
  instid = mulp_new_geco_instance (localPort, noOfInStreams, noOfOutStreams,
                                   noOfLocalAddresses, localAddressList,
                                   ULPcallbackFunctions);
  curr_geco_instance_ = geco_instances_[instid];

  noOfOutStreams = 12;
  mulp_connect (instid, noOfOutStreams, ip6addrstr, localPort,
                &ULPcallbackFunctions);

  //poll to receive the init, send initack
  mtra_poll (0, 0, 0);

  //poll to receive the initack  send cookie echoed
  mtra_poll (0, 0, 0);

  //poll to receive the cookie echoed chunk and send cookie ack
  mtra_poll (0, 0, 0);

  //poll to receive the cookie ack
  mtra_poll (0, 0, 0);

  mulp_delete_geco_instance (instid);
  free_library ();
}
