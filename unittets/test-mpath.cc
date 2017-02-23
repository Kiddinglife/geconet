/*
 * test-mpath.cc
 *
 *  Created on: 17Feb.,2017
 *      Author: jackiez
 */

#include <iostream>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "geco-test.h"


struct mpath : public testing::Test
{
    path_controller_t* mpath_;
    virtual void
    SetUp ()
    {
      puts ("SetUp()");
      alloc_geco_channel ();
      mpath_ = curr_channel_->path_control;
    }
    virtual void
    TearDown ()
    {
      puts ("TearDown()");
      free_geco_channel ();
    }
};

TEST_F(mpath, test_new_and_free)
{
  ASSERT_EQ(mpath_->channel_id, curr_channel_->channel_id);
  ASSERT_EQ(mpath_->primary_path, UT_PRI_PATH_ID);
  ASSERT_EQ(mpath_->path_num, UT_REMOTE_ADDR_LIST_SIZE);
  ASSERT_EQ(mpath_->max_retrans_per_path,
            curr_geco_instance_->default_pathMaxRetransmits);
  ASSERT_EQ(mpath_->rto_initial, curr_geco_instance_->default_rtoInitial);
  ASSERT_EQ(mpath_->rto_min, curr_geco_instance_->default_rtoMin);
  ASSERT_EQ(mpath_->rto_max, curr_geco_instance_->default_rtoMax);
  ASSERT_EQ(mpath_->min_pmtu, PMTU_LOWEST);
  ASSERT_EQ(mpath_->path_params, nullptr);
}

extern void
mpath_verify_unconfirmed_paths (uint noOfPaths, ushort primaryPathID);
TEST_F(mpath, test_mpath_verify_unconfirmed_paths)
{
  mpath_verify_unconfirmed_paths (UT_REMOTE_ADDR_LIST_SIZE, UT_PRI_PATH_ID);
  ASSERT_EQ(mpath_->primary_path, UT_PRI_PATH_ID);
  ASSERT_EQ(mpath_->path_num, UT_REMOTE_ADDR_LIST_SIZE);
  ASSERT_EQ(mpath_->total_retrans_count, 0);
  ASSERT_EQ(mpath_->max_retrans_per_path, 5);
  ASSERT_EQ(curr_channel_->state_machine_control->max_assoc_retrans_count, 10);
  for (int i = 0; i < mpath_->path_num; i++)
  {
    ASSERT_EQ(mpath_->path_params[i].hb_enabled, true);
    ASSERT_EQ(mpath_->path_params[i].firstRTO, true);
    ASSERT_EQ(mpath_->path_params[i].retrans_count, 0);
    ASSERT_EQ(mpath_->path_params[i].rto, mpath_->rto_initial);
    ASSERT_EQ(mpath_->path_params[i].srtt, mpath_->rto_initial);
    ASSERT_EQ(mpath_->path_params[i].rttvar, 0);
    ASSERT_EQ(mpath_->path_params[i].hb_sent, false);
    ASSERT_EQ(mpath_->path_params[i].heartbeatAcked, false);
    ASSERT_EQ(mpath_->path_params[i].timer_backoff, false);
    ASSERT_EQ(mpath_->path_params[i].dchunk_acked_in_last_rto, false);
    ASSERT_EQ(mpath_->path_params[i].dchunk_sent_in_last_rto, false);
    ASSERT_EQ(mpath_->path_params[i].hb_interval, PM_INITIAL_HB_INTERVAL);
    ASSERT_EQ(mpath_->path_params[i].path_id, i);
    ASSERT_EQ(mpath_->path_params[i].eff_pmtu, PMTU_LOWEST);
    ASSERT_EQ(mpath_->path_params[i].probing_pmtu, PMTU_HIGHEST);
    if (i != mpath_->primary_path)
      ASSERT_EQ(mpath_->path_params[i].state, PM_PATH_UNCONFIRMED);
    else
      ASSERT_EQ(mpath_->path_params[i].state, PM_ACTIVE);
    ASSERT_NE(mpath_->path_params[i].hb_timer_id, nullptr);
  }
}

bool mpath_handle_chunks_retx(short pathID);
TEST_F(mpath, test_handle_chunks_retx)
{
  //given a completed mpath
  mpath_verify_unconfirmed_paths (UT_REMOTE_ADDR_LIST_SIZE, UT_PRI_PATH_ID);
  //given max_channel_retrans_count = 2,max_retrans_per_path = 1
  uint old_max_rtx_counter = curr_channel_->state_machine_control->max_assoc_retrans_count;
  uint old_max_retrans_per_path = mpath_->max_retrans_per_path;
  mpath_->max_retrans_per_path = 1;
  curr_channel_->state_machine_control->max_assoc_retrans_count = UT_REMOTE_ADDR_LIST_SIZE*mpath_->max_retrans_per_path;

  bool ret;

  //when path is unconfirmed,
  mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
  mpath_handle_chunks_retx(0);
  //then only increment path retrans counter by one
  ASSERT_EQ(mpath_->path_params[0].retrans_count,1);
  //reset to initial value
  mpath_->path_params[0].retrans_count = 0;
  mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;

  //when path is active,
  mpath_->path_params[1].state = PM_ACTIVE;
  mpath_handle_chunks_retx(1);
  //then increment both path and channel retrans counters by one
  ASSERT_EQ(mpath_->path_params[1].retrans_count,1);
  ASSERT_EQ(mpath_->total_retrans_count,1);
  //reset to initial value
  mpath_->path_params[1].retrans_count = 0;
  mpath_->path_params[1].state = PM_PATH_UNCONFIRMED;
  mpath_->total_retrans_count = 0;

  //when total_retrans_count >= max_channel_retrans_count,
  mpath_->path_params[0].state = PM_ACTIVE;
  mpath_->path_params[1].state = PM_ACTIVE;
  ret = mpath_handle_chunks_retx(0);
  ret = mpath_handle_chunks_retx(1);
  // then disconnect and delete channel -> return true
  ASSERT_EQ(curr_channel_,nullptr);
  ASSERT_EQ(ret,true);

  // as the last test exceeds max_channel_retrans_count that leads to curr_channel_ freed
  alloc_geco_channel ();
  mpath_ = curr_channel_->path_control;

  // when path is inactive, then stop -> return false
}

TEST(mpath, test_heartbeat_timer_expired)
{
  // MUST FILL PARAMS
  mpath_verify_unconfirmed_paths (UT_REMOTE_ADDR_LIST_SIZE, UT_PRI_PATH_ID);

}

