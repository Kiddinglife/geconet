/*
 * test-mrecv.cc
 *
 *  Created on: Mar 19, 2017
 *      Author: jakez
 */

#include "spdlog/spdlog.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "geco-net-chunk.h"
#include "geco-test.h"

struct mrecv : public testing::Test
{
	recv_controller_t* mrecv_;
	recv_controller_t init_mrecv_;
	geco_channel_t* init_channel_;

	uint highest_duplicate_tsn;
	virtual void
		SetUp()
	{
		alloc_geco_channel();
		init_channel_ = curr_channel_;
		mrecv_ = init_channel_->receive_control;
		init_mrecv_ = *mrecv_;
	}
	virtual void
		TearDown()
	{
		free_geco_channel();
	}
	void
		reset()
	{
		//reset everything to its init valuess
		curr_channel_ = init_channel_;
		curr_geco_instance_ = curr_channel_->geco_inst;
		mrecv_ = init_channel_->receive_control;
		*mrecv_ = init_mrecv_;
	}
};

extern bool
mrecv_chunk_is_duplicate(recv_controller_t* mrecv, uint chunk_tsn);
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

	//when chunk tsn is brfore lowest_duplicated_tsn
	chunk_tsn = mrecv_->lowest_duplicated_tsn - 1;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
	//then should be dup
	ASSERT_TRUE(ret);
	//then should update lowest_duplicated_tsn
	ASSERT_EQ(mrecv_->lowest_duplicated_tsn, chunk_tsn);

	mrecv_->lowest_duplicated_tsn++; //set it back to 124

	//when chunk tsn is mrecv_->cumulative_tsn
	chunk_tsn = mrecv_->cumulative_tsn;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
	//then should be dup
	ASSERT_TRUE(ret);

	//when chunk tsn is between (lowest_duplicated_tsn,cumulative_tsn)
	chunk_tsn = mrecv_->cumulative_tsn - 1;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
	//then should be dup
	ASSERT_TRUE(ret);

	//when chunk tsn > highest_duplicate_tsn
	chunk_tsn = mrecv_->highest_duplicate_tsn + 1;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
	//then should NOT be dup
	ASSERT_FALSE(ret);
	//then should update dup
	ASSERT_EQ(mrecv_->highest_duplicate_tsn, chunk_tsn);

	mrecv_->highest_duplicate_tsn--; //set it back to 180

	//when mrecv->fragmented_data_chunks_list.empty()
	chunk_tsn = mrecv_->highest_duplicate_tsn - 1;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
	//then should NOT be dup
	ASSERT_FALSE(ret);

	//when chunk tsn is between (cumulative_tsn, highest_duplicate_tsn)
	// and when mrecv->fragmented_data_chunks_list not empty()
	// ...[140-150] gap1 [154-156] gap2 180
	mrecv_->fragmented_data_chunks_list.push_back(
	{ mrecv_->cumulative_tsn + 4, mrecv_->cumulative_tsn + 6 });

	//  and when chunk tsn is not contained in list as in gap2
	chunk_tsn = mrecv_->highest_duplicate_tsn - 1;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
	//  then should NOT be dup
	ASSERT_FALSE(ret);

	//  and when chunk tsn is not contained in list as in gap1
	chunk_tsn = mrecv_->cumulative_tsn + 2;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
	//  then should be dup
	ASSERT_FALSE(ret);

	//  and when chunk tsn is contained in list in left seg bundary
	chunk_tsn = mrecv_->cumulative_tsn + 4;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);

	//  then should be dup
	ASSERT_TRUE(ret);

	//  and when chunk tsn is contained in list in right seg bundary
	chunk_tsn = mrecv_->cumulative_tsn + 6;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
	//  then should be dup
	ASSERT_TRUE(ret);

	//  and when chunk tsn is contained in list in seg bundary
	chunk_tsn = mrecv_->cumulative_tsn + 5;
	ret = mrecv_chunk_is_duplicate(mrecv_, chunk_tsn);
	//  then should be dup
	ASSERT_TRUE(ret);

	reset();
}

extern void
mrecv_update_duplicates(recv_controller_t* mrecv, uint chunk_tsn);
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
	for (auto tsn : mrecv_->duplicated_data_chunks_list)
	{
		if (tsn == duplicate_tsn)
			count++;
	}
	ASSERT_EQ(count, 1);
	auto itr = mrecv_->duplicated_data_chunks_list.begin();
	ASSERT_EQ(*(itr), 123);
	std::advance(itr, 1);
	ASSERT_EQ(*(itr), 125);

	//when duplicate_tsn not in list
	duplicate_tsn = 100;
	mrecv_update_duplicates(mrecv_, duplicate_tsn);
	//then insert it to list
	auto ret = std::find(mrecv_->duplicated_data_chunks_list.begin(),
		mrecv_->duplicated_data_chunks_list.end(),
		duplicate_tsn);
	ASSERT_TRUE(*ret == duplicate_tsn);
	itr = mrecv_->duplicated_data_chunks_list.begin();
	ASSERT_EQ(*(itr), 100);
	std::advance(itr, 1);
	ASSERT_EQ(*(itr), 123);
	std::advance(itr, 1);
	ASSERT_EQ(*(itr), 125);

	reset();
}

extern void
mrecv_update_fragments(recv_controller_t* mrecv, uint chunk_tsn);
TEST_F(mrecv, test_mrecv_update_fragments)
{
	// Given cstna=2, frags = {4-5,7-7,13-15}
	// 2 (3) 4-5 (6) 7-7 (89) 13-15
	mrecv_->cumulative_tsn = 2;
	mrecv_->fragmented_data_chunks_list.push_back(
	{ 4, 5 });
	mrecv_->fragmented_data_chunks_list.push_back(
	{ 7, 7 });
	mrecv_->fragmented_data_chunks_list.push_back(
	{ 13, 15 });
	auto init_list = mrecv_->fragmented_data_chunks_list;
	auto init_ctsn = mrecv_->cumulative_tsn;
	bool can_bubbleup_ctsn = false;
	bool found = false;
	uint chunktsn;

	//when chunk_tsn=3
	chunktsn = 3;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then cstna should be 5
	ASSERT_EQ(mrecv_->cumulative_tsn, 5);
	//then frag 4-5 shoul be removed from list
	ASSERT_EQ(
		mrecv_->fragmented_data_chunks_list.end(),
		std::find_if(mrecv_->fragmented_data_chunks_list.begin(),
			mrecv_->fragmented_data_chunks_list.end(),
			[](const segment32_t& obj)
	{
		return obj.start_tsn == 4 && obj.stop_tsn == 5;
	}));
	//set back for next test
	mrecv_->cumulative_tsn = init_ctsn;
	mrecv_->fragmented_data_chunks_list = init_list;

	//when chunk_tsn=6
	chunktsn = 6;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then cstna should remain unchanged
	ASSERT_EQ(mrecv_->cumulative_tsn, init_ctsn);
	//then frag 4-5 shoul be removed from list
	ASSERT_EQ(
		mrecv_->fragmented_data_chunks_list.end(),
		std::find_if(mrecv_->fragmented_data_chunks_list.begin(),
			mrecv_->fragmented_data_chunks_list.end(),
			[](const segment32_t& obj)
	{
		return obj.start_tsn == 4 && obj.stop_tsn == 5;
	}));
	//then frag 4-7 shoul be added to list
	ASSERT_NE(
		mrecv_->fragmented_data_chunks_list.end(),
		std::find_if(mrecv_->fragmented_data_chunks_list.begin(),
			mrecv_->fragmented_data_chunks_list.end(),
			[](const segment32_t& obj)
	{
		return obj.start_tsn == 4 && obj.stop_tsn == 7;
	}));
	//set back for next test
	mrecv_->cumulative_tsn = init_ctsn;
	mrecv_->fragmented_data_chunks_list = init_list;

	//when chunk_tsn=8
	chunktsn = 8;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then cstna should remain unchanged
	ASSERT_EQ(mrecv_->cumulative_tsn, init_ctsn);
	//then frag 7-7 shoul be updated to 7-8 that should be added to list too
	ASSERT_NE(
		mrecv_->fragmented_data_chunks_list.end(),
		std::find_if(mrecv_->fragmented_data_chunks_list.begin(),
			mrecv_->fragmented_data_chunks_list.end(),
			[](const segment32_t& obj)
	{
		return obj.start_tsn == 7 && obj.stop_tsn == 8;
	}));
	ASSERT_EQ(
		mrecv_->fragmented_data_chunks_list.end(),
		std::find_if(mrecv_->fragmented_data_chunks_list.begin(),
			mrecv_->fragmented_data_chunks_list.end(),
			[](const segment32_t& obj)
	{
		return obj.start_tsn == 7 && obj.stop_tsn == 7;
	}));
	//set back for next test
	mrecv_->cumulative_tsn = init_ctsn;
	mrecv_->fragmented_data_chunks_list = init_list;

	// Given cstna=1, frags = {4-5,8-9}
	// 1 4-5 8-9
	mrecv_->cumulative_tsn = init_ctsn = 1;
	mrecv_->fragmented_data_chunks_list.clear();
	mrecv_->fragmented_data_chunks_list.push_back({ 4,5 });
	mrecv_->fragmented_data_chunks_list.push_back({ 8,9 });

	//when chunk_tsn=2
	chunktsn = 2;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then cstna should changed
	ASSERT_EQ(mrecv_->cumulative_tsn, 2);
	//then frag45 and 89 should not change
	ASSERT_NE(
		mrecv_->fragmented_data_chunks_list.end(),
		std::find_if(mrecv_->fragmented_data_chunks_list.begin(),
			mrecv_->fragmented_data_chunks_list.end(),
			[](const segment32_t& obj)
	{
		return (obj.start_tsn == 4 && obj.stop_tsn == 5);
	}));
	ASSERT_NE(
		mrecv_->fragmented_data_chunks_list.end(),
		std::find_if(mrecv_->fragmented_data_chunks_list.begin(),
			mrecv_->fragmented_data_chunks_list.end(),
			[](const segment32_t& obj)
	{
		return  (obj.start_tsn == 8 && obj.stop_tsn == 9);
	}));
	//set back for next test
	mrecv_->cumulative_tsn = init_ctsn;
	mrecv_->fragmented_data_chunks_list = init_list;

	//when chunk_tsn=3
	chunktsn = 3;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then cstna should changed
	ASSERT_EQ(mrecv_->cumulative_tsn, 1);
	//then frag45 should be updated to frag35
	ASSERT_NE(
		mrecv_->fragmented_data_chunks_list.end(),
		std::find_if(mrecv_->fragmented_data_chunks_list.begin(),
			mrecv_->fragmented_data_chunks_list.end(),
			[](const segment32_t& obj)
	{
		return (obj.start_tsn == 3 && obj.stop_tsn == 5);
	}));
	ASSERT_EQ(
		mrecv_->fragmented_data_chunks_list.end(),
		std::find_if(mrecv_->fragmented_data_chunks_list.begin(),
			mrecv_->fragmented_data_chunks_list.end(),
			[](const segment32_t& obj)
	{
		return (obj.start_tsn == 4 && obj.stop_tsn == 5);
	}));

	reset();
}
