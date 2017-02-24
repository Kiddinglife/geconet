/*
 * geco-test.h
 *
 *  Created on: 22Feb.,2017
 *      Author: jackiez
 */

#ifndef UNITTETS_GECO_TEST_H_
#define UNITTETS_GECO_TEST_H_
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "geco-net-config.h"
#include "geco-net.h"
#include "geco-net-transport.h"
#include "geco-net-dispatch.h"

#include "geco-ds-malloc.h"
#include "geco-malloc.h"
using namespace geco::ds;

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

extern int myRWND;
extern uint ipv4_sockets_geco_instance_users;
extern uint ipv6_sockets_geco_instance_users;
extern uint defaultlocaladdrlistsize_;
extern sockaddrunion* defaultlocaladdrlist_;
extern std::vector<geco_instance_t*> geco_instances_;
extern geco_channel_t** channels_; /*store all channels, channel id as key*/
extern uint channels_size_;
extern geco_instance_t *curr_geco_instance_;
extern geco_channel_t *curr_channel_;

extern void
alloc_geco_instance ();
extern void
free_geco_instance ();
extern void
alloc_geco_channel ();
extern void
free_geco_channel ();
#endif /* UNITTETS_GECO_TEST_H_ */
