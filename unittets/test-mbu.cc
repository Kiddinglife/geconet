/*
 * test-mbu.cc
 *
 *  Created on: 24Oct.,2016
 *      Author: jackiez
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"
//#include "globals.h"
#include "geco-net.h"
#include "geco-net-dispatch.h"
#include <iostream>

/**
 * Creates a new bundling instance and returns a pointer to its data.
 * @return pointer to an instance of the bundling data
 */
extern bundle_controller_t*
mbu_new (void);
TEST(MBU, test_mbu_new)
{
  bundle_controller_t* mbu = mbu_new ();
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
}

