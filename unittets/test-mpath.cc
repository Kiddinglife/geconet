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
      //max_channel_retrans_count = 2,max_retrans_per_path = 1
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
  ASSERT_EQ(mpath_->max_retrans_per_path,2);
  ASSERT_EQ(mpath_->rto_initial, curr_geco_instance_->default_rtoInitial);
  ASSERT_EQ(mpath_->rto_min, curr_geco_instance_->default_rtoMin);
  ASSERT_EQ(mpath_->rto_max, curr_geco_instance_->default_rtoMax);
  ASSERT_EQ(mpath_->min_pmtu, PMTU_LOWEST);
  ASSERT_NE(mpath_->path_params, nullptr);
}

TEST_F(mpath, test_set_paths)
{
  ASSERT_EQ(mpath_->primary_path, UT_PRI_PATH_ID);
  ASSERT_EQ(mpath_->path_num, UT_REMOTE_ADDR_LIST_SIZE);
  ASSERT_EQ(mpath_->total_retrans_count, 0);
  ASSERT_EQ(mpath_->max_retrans_per_path, 2);
  ASSERT_EQ(curr_channel_->state_machine_control->max_assoc_retrans_count, mpath_->max_retrans_per_path*UT_REMOTE_ADDR_LIST_SIZE);
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

bool
mpath_handle_chunks_retx (short pathID);
TEST_F(mpath, test_handle_chunks_retx)
{
  //given max_channel_retrans_count = 2,max_retrans_per_path = 1
  bool ret;

  //1 when path is unconfirmed,
  mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
  mpath_handle_chunks_retx (0);
  //then only increment path retrans counter by one
  ASSERT_EQ(mpath_->path_params[0].retrans_count, 1);
  //reset to initial mpath value
  mpath_->path_params[0].retrans_count = 0;
  mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;

  //2 when path is active,
  mpath_->path_params[1].state = PM_ACTIVE;
  mpath_handle_chunks_retx (1);
  //then increment both path and channel retrans counters by one
  ASSERT_EQ(mpath_->path_params[1].retrans_count, 1);
  ASSERT_EQ(mpath_->total_retrans_count, 1);
  //reset to initial mpath value
  mpath_->path_params[1].retrans_count = 0;
  mpath_->path_params[1].state = PM_PATH_UNCONFIRMED;
  mpath_->total_retrans_count = 0;

  //3 when total_retrans_count >= max_channel_retrans_count,
  mpath_->path_params[0].state = PM_ACTIVE;
  mpath_->path_params[1].state = PM_ACTIVE;
  ret = mpath_handle_chunks_retx (0);
  ret = mpath_handle_chunks_retx (1);
  ret = mpath_handle_chunks_retx (0);
  ret = mpath_handle_chunks_retx (1);
  // then disconnect and delete channel -> return true
  ASSERT_EQ(curr_channel_, nullptr);
  ASSERT_EQ(curr_geco_instance_, nullptr);
  ASSERT_EQ(ret, true);

  // as the last test exceeds max_channel_retrans_count that leads to curr_channel_ freed so realloc it
  alloc_geco_channel ();
  mpath_ = curr_channel_->path_control;

  //4 when path is inactive,
  mpath_->path_params[0].state = PM_INACTIVE;
  ret = mpath_handle_chunks_retx (0);
  // then stop -> return false
  ASSERT_EQ(ret, false);
  //reset to initial mpath value
  mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;

  //5 when path max retrans  >= max_retrans_per_path
  mpath_->path_params[0].state = PM_ACTIVE;
  mpath_handle_chunks_retx (0);
  mpath_handle_chunks_retx (0);
  // then path is marked as inactive
  ASSERT_EQ(mpath_->path_params[0].state, PM_INACTIVE);
  //reset to initial mpath value
  mpath_->path_params[0].retrans_count = 0;
  mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
  mpath_->total_retrans_count = 0;

  //6 when there is active or unconfirmed path
  mpath_->path_params[1].state = PM_ACTIVE;
  mpath_handle_chunks_retx (1);
  mpath_handle_chunks_retx (1);
  mpath_handle_chunks_retx (0);
  // then channel is still active
  ASSERT_EQ(mpath_->path_params[1].state, PM_INACTIVE);
  ASSERT_EQ(mpath_->path_params[0].state, PM_PATH_UNCONFIRMED);
  ASSERT_EQ(mpath_->total_retrans_count, 2);
  //reset to initial mpath value
  mpath_->path_params[0].retrans_count = 0;
  mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
  mpath_->path_params[1].retrans_count = 0;
  mpath_->path_params[1].state = PM_PATH_UNCONFIRMED;
  mpath_->total_retrans_count = 0;

  //7 when unconfirmed paths' total_retrans_count >= max_channel_retrans_count,
  ret = mpath_handle_chunks_retx (0);
  ret = mpath_handle_chunks_retx (1);
  ret = mpath_handle_chunks_retx (0);
  ret = mpath_handle_chunks_retx (1);
  // then disconnect and delete channel -> return true
  ASSERT_EQ(curr_channel_, nullptr);
  ASSERT_EQ(curr_geco_instance_, nullptr);
  ASSERT_EQ(ret, true);

  // as the last test exceeds max_channel_retrans_count that leads to curr_channel_ freed so realloc it
  alloc_geco_channel ();
  mpath_ = curr_channel_->path_control;

  //8 when one active one unconfirmed paths' total_retrans_count >= max_channel_retrans_count,
  mpath_->path_params[0].state = PM_ACTIVE;
  ret = mpath_handle_chunks_retx (0);
  ret = mpath_handle_chunks_retx (1);
  ret = mpath_handle_chunks_retx (0);
  ret = mpath_handle_chunks_retx (1);
  // then disconnect and delete channel -> return true
  ASSERT_EQ(curr_channel_, nullptr);
  ASSERT_EQ(curr_geco_instance_, nullptr);
  ASSERT_EQ(ret, true);

  // as the last test exceeds max_channel_retrans_count that leads to curr_channel_ freed so realloc it
  alloc_geco_channel ();
  mpath_ = curr_channel_->path_control;

  //9 when primary path becomes inactive,
  mpath_->primary_path = 0;
  mpath_->path_params[0].dchunk_sent_in_last_rto = true;
  ret = mpath_handle_chunks_retx (0);
  ret = mpath_handle_chunks_retx (0);
  // then use path1 as primary path even it is unconfirmed
  ASSERT_EQ(mpath_->primary_path, 1);
  ASSERT_EQ(mpath_->path_params[0].dchunk_sent_in_last_rto, false);
  ASSERT_EQ(mpath_->path_params[1].dchunk_acked_in_last_rto, false);
  //reset to initial mpath value
  mpath_->path_params[0].dchunk_sent_in_last_rto = false;
  mpath_->path_params[0].retrans_count = 0;
  mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
  mpath_->path_params[1].retrans_count = 0;
  mpath_->path_params[1].state = PM_PATH_UNCONFIRMED;
  mpath_->total_retrans_count = 0;
}

extern int mpath_heartbeat_timer_expired(timeout* timerID);
TEST_F(mpath, test_heartbeat_timer_expired)
{
  bool ret;

  //given path0,timeouts and timerID
  timeouts* ts = mtra_read_timeouts();
  ASSERT_NE(ts, nullptr);
  path_params_t* path = mpath_->path_params[0];
  ASSERT_NE(path, nullptr);
  timeout* timerID = path->hb_timer_id;
  ASSERT_NE(timerID, nullptr);

  //1 when mtu=0,
  void* old_arg3 = timerID->callback.arg3;
  timerID->callback.arg3 = nullptr;
  //andwhen hb_sent=false,
  path->hb_sent = false;
  //then do nothing but readd timout with rto
  timeout_t old_exps = timerID->expires;
  mpath_heartbeat_timer_expired(timerID);
  ASSERT_EQ(timerID, mpath_->path_params[0].hb_timer_id);
  ASSERT_LT(old_exps,timerID->expires);
  // reset everything to init value
  timerID->callback.arg3 = old_arg3;
  path->hb_sent = false;
  timerID->expires = old_exps;

  //TODO
}

