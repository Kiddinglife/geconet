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
    recv_controller_t init_mrecv_;
    geco_channel_t* init_channel_;

    uint highest_duplicate_tsn;
    virtual void
    SetUp ()
    {
      alloc_geco_channel ();
      init_channel_ = curr_channel_;
      mrecv_ = init_channel_->receive_control;
      init_mrecv_ = *mrecv_;
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
      curr_channel_ = init_channel_;
      curr_geco_instance_ = curr_channel_->geco_inst;
      mrecv_ = init_channel_->receive_control;
      *mrecv_ = init_mrecv_;
    }
};

extern bool
mrecv_before_lowest_duptsn (recv_controller_t* mrecv, uint chunk_tsn);
TEST_F(mrecv, test_mrecv_before_lowest_duptsn)
{
  bool ret;
  //when chunk tsn equals to mrecv->lowest_duplicated_tsn
  uint chunk_tsn = 124;
  mrecv_->lowest_duplicated_tsn = 124;
  ret = mrecv_before_lowest_duptsn(mrecv_, chunk_tsn);
  //then should not update lowest_duplicated_tsn
  ASSERT_EQ(mrecv_->lowest_duplicated_tsn, 124);
  ASSERT_FALSE(ret);

  //when chunk tsn is after mrecv->lowest_duplicate_tsn
  chunk_tsn = 125;
  mrecv_->lowest_duplicated_tsn = 124;
  ret = mrecv_before_lowest_duptsn(mrecv_, chunk_tsn);
  //then should not update lowest_duplicated_tsn
  ASSERT_EQ(mrecv_->lowest_duplicated_tsn, 124);
  ASSERT_FALSE(ret);

  //when chunk tsn is before mrecv->lowest_duplicated_tsn
  chunk_tsn = 123;
  mrecv_->lowest_duplicated_tsn = 124;
  ret = mrecv_before_lowest_duptsn(mrecv_, chunk_tsn);
  //then should update lowest_duplicate_tsn must be dup
  ASSERT_EQ(mrecv_->lowest_duplicated_tsn, 123);
  ASSERT_TRUE(ret);
  reset();
}

extern bool
mrecv_after_highest_tsn (recv_controller_t* mrecv, uint chunk_tsn);
TEST_F(mrecv, test_mrecv_after_highest_tsn)
{
  bool ret;
  //when chunk tsn equals to mrecv->highest_duplicate_tsn
  uint chunk_tsn = 124;
  mrecv_->highest_duplicate_tsn = 124;
  ret = mrecv_after_highest_tsn(mrecv_, chunk_tsn);
  //then should not update dup
  ASSERT_EQ(mrecv_->highest_duplicate_tsn, 124);
  ASSERT_FALSE(ret);

  //when chunk tsn is before mrecv->highest_duplicate_tsn
  chunk_tsn = 123;
  mrecv_->highest_duplicate_tsn = 124;
  ret = mrecv_after_highest_tsn(mrecv_, chunk_tsn);
  //then should not update dup
  ASSERT_EQ(mrecv_->highest_duplicate_tsn, 124);
  ASSERT_FALSE(ret);

  //when chunk tsn is after mrecv->highest_duplicate_tsn
  chunk_tsn = 125;
  mrecv_->highest_duplicate_tsn = 124;
  ret = mrecv_after_highest_tsn(mrecv_, chunk_tsn);
  //then should not update dup
  ASSERT_EQ(mrecv_->highest_duplicate_tsn, chunk_tsn);
  ASSERT_TRUE(ret);

  reset();
}

extern bool
mrecv_chunk_is_duplicate (recv_controller_t* mrecv, uint chunk_tsn);
TEST_F(mrecv, test_mrecv_chunk_is_duplicate)
{
  bool ret;

  //given
  mrecv_->lowest_duplicated_tsn = 124;
  mrecv_->cumulative_tsn = 150;
  mrecv_->highest_duplicate_tsn = 180;

  //when chunk tsn == mrecv->highest_duplicate_tsn
  uint chunk_tsn = mrecv_->highest_duplicate_tsn;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //then should be dup
  ASSERT_TRUE(ret);
  //when chunk tsn is mrecv_->cumulative_tsn
  chunk_tsn = mrecv_->cumulative_tsn;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //then should be dup
  ASSERT_TRUE(ret);
  //when chunk tsn is between (lowest_duplicated_tsn,cumulative_tsn)
  chunk_tsn = mrecv_->cumulative_tsn-1;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //then should be dup
  ASSERT_TRUE(ret);

  //when chunk tsn > highest_duplicate_tsn
  chunk_tsn = mrecv_->highest_duplicate_tsn+1;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //then should NOT be dup
  ASSERT_FALSE(ret);

  //when mrecv->fragmented_data_chunks_list.empty()
  chunk_tsn = mrecv_->highest_duplicate_tsn-1;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //then should NOT be dup
  ASSERT_FALSE(ret);

  //when chunk tsn is between (cumulative_tsn, highest_duplicate_tsn)
  // and when mrecv->fragmented_data_chunks_list not empty()
  // ...[140-150] gap1 [154-156] gap2 180
  mrecv_->fragmented_data_chunks_list.push_back({mrecv_->cumulative_tsn+4, mrecv_->cumulative_tsn+6});
  //  and when chunk tsn is not contained in list as in gap2
  chunk_tsn = mrecv_->highest_duplicate_tsn-1;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //  then should NOT be dup
  ASSERT_FALSE(ret);
  //  and when chunk tsn is not contained in list as in gap1
  chunk_tsn = mrecv_->cumulative_tsn+2;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //  then should be dup
  ASSERT_FALSE(ret);

  //  and when chunk tsn is contained in list in left seg bundary
  chunk_tsn = mrecv_->cumulative_tsn+4;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //  then should be dup
  ASSERT_TRUE(ret);
  //  and when chunk tsn is contained in list in right seg bundary
  chunk_tsn = mrecv_->cumulative_tsn+6;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //  then should be dup
  ASSERT_TRUE(ret);
  //  and when chunk tsn is contained in list in seg bundary
  chunk_tsn = mrecv_->cumulative_tsn+5;
  ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
  //  then should be dup
  ASSERT_TRUE(ret);

  reset();
}

extern void
mrecv_update_duplicates (recv_controller_t* mrecv, uint chunk_tsn);
TEST_F(mrecv, test_mrecv_update_duplicates)
{
  //given duplicated_data_chunks_list 123,125
  mrecv_->duplicated_data_chunks_list.push_back(123);
  mrecv_->duplicated_data_chunks_list.push_back(125);

  //when duplicate_tsn in list
  duplicate_tsn_t duplicate_tsn = 123;
  mrecv_update_duplicates(mrecv_, duplicate_tsn);
  //then not insert it to list
  int count = 0;
  for(auto tsn : mrecv_->duplicated_data_chunks_list)
  {
    if(tsn == duplicate_tsn)
      count++;
  }
  ASSERT_EQ(count, 1);
  ASSERT_EQ(mrecv_->duplicated_data_chunks_list.front(),123);
  mrecv_->duplicated_data_chunks_list.pop_front();
  ASSERT_EQ(mrecv_->duplicated_data_chunks_list.front(),125);

  //when duplicate_tsn not in list
  duplicate_tsn = 100;
  mrecv_update_duplicates(mrecv_, duplicate_tsn);
  //then insert it to list
  auto ret = std::find(mrecv_->duplicated_data_chunks_list.begin(), mrecv_->duplicated_data_chunks_list.end(),duplicate_tsn);
  ASSERT_TRUE(*ret == duplicate_tsn);
  ASSERT_EQ(mrecv_->duplicated_data_chunks_list.front(),100);
  mrecv_->duplicated_data_chunks_list.pop_front();
  ASSERT_EQ(mrecv_->duplicated_data_chunks_list.front(),123);
  mrecv_->duplicated_data_chunks_list.pop_front();
  ASSERT_EQ(mrecv_->duplicated_data_chunks_list.front(),125);
}
