/*
 * test-mpath.cc
 *
 *  Created on: 17Feb.,2017
 *      Author: jackiez
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "geco-net.h"
#include "geco-net-dispatch.h"
#include <iostream>

// reset the below variables in every test case
extern geco_channel_t* curr_channel_; //reference from mdi
extern geco_instance_t* curr_geco_instance_; //reference from mdi
static geco_channel_t curr_channel =
  { 0 };
static geco_instance_t curr_geco_instance =
  { 0 };
static path_params_t path_params =
  { 0 };

///////////////////// TEST(mpath, test_mpath_new_and_free) ///////////////////////////
extern path_controller_t*
mpath_new (short numberOfPaths, short primaryPath);
extern void
mpath_free (path_controller_t *pmData);
TEST(mpath, test_mpath_new_and_free)
{
  short numberOfPaths = 1;
  short primaryPath = 0;
  curr_channel_ = &curr_channel;
  curr_channel_->channel_id = 8;
  curr_geco_instance_ = &curr_geco_instance;
  path_controller_t* mpath = mpath_new (numberOfPaths, primaryPath);
  mpath->path_params = (path_params_t*) geco_malloc_ext (sizeof(path_params_t),
                                                         __FILE__, __LINE__);
  memset (mpath->path_params, 0, sizeof(path_params_t));
  EXPECT_EQ(mpath->channel_id, curr_channel_->channel_id);
  EXPECT_EQ(mpath->primary_path, primaryPath);
  mpath_free (mpath);
}


