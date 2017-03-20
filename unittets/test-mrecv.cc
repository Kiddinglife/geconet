/*
 * test-mrecv.cc
 *
 *  Created on: Mar 19, 2017
 *      Author: jakez
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "geco-test.h"
#include "geco-net-chunk.h"

struct mrecv : public testing::Test
{
    recv_controller_t* mrecv_;
    geco_channel_t* old_channel;

    uint highest_duplicate_tsn;
    virtual void
    SetUp ()
    {
      alloc_geco_channel ();
      old_channel = curr_channel_;
      mrecv_ = old_channel->receive_control;
    }
    virtual void
    TearDown ()
    {
      free_geco_channel ();
    }
    void
    reset ()
    {
      //reset everything to its init valuess
      curr_channel_ = old_channel;
      curr_geco_instance_ = curr_channel_->geco_inst;
    }
};

/// insert chunk_tsn in the list of duplicates from small to big if it is not in list
/// @param chunk_tsn    tsn we just received
extern void
mrecv_update_duplicates (recv_controller_t* mrecv, uint chunk_tsn);
TEST_F(mrecv, test_mrecv_update_duplicates)
{
}

extern bool
mrecv_before_lowest_duptsn (recv_controller_t* mrecv, uint chunk_tsn);
TEST_F(mrecv, test_mrecv_before_lowest_duptsn)
{

}

extern bool
mrecv_after_highest_tsn (recv_controller_t* mrecv, uint chunk_tsn);
TEST_F(mrecv, test_mrecv_after_highest_tsn)
{
  bool ret;
  //given chunk tsn 123, mrecv->highest_duplicate_tsn 124
  uint chunk_tsn = 124;
  mrecv_->highest_duplicate_tsn = 124;
  ret = mrecv_after_highest_tsn(mrecv_, chunk_tsn);
  //should not update dup
  ASSERT_EQ(mrecv_->highest_duplicate_tsn, 124);
  ASSERT_FALSE(ret);
}

extern bool
mrecv_chunk_is_duplicate (recv_controller_t* mrecv, uint chunk_tsn);
TEST_F(mrecv, test_mrecv_chunk_is_duplicate)
{
}
