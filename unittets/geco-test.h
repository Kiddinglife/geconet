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
alloc_geco_instance();
extern void
free_geco_instance();
extern void
alloc_geco_channel();
extern void
free_geco_channel();
#endif /* UNITTETS_GECO_TEST_H_ */
