/*
 * test-mrecv.cc
 *
 *  Created on: Mar 19, 2017
 *      Author: jakez
 */

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
		GLOBAL_CURR_EVENT_LOG_LEVEL = INFO;
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
	// Given cstna=2, frags = {4-5,7-7,13-15}, 2 (3) 4-5 (6) 7-7 (89) 13-15
	mrecv_->cumulative_tsn = 2;
	mrecv_->fragmented_data_chunks_list.push_back(
	{ 4, 5 });
	mrecv_->fragmented_data_chunks_list.push_back(
	{ 7, 7 });
	mrecv_->fragmented_data_chunks_list.push_back(
	{ 13, 15 });
	auto init_list = mrecv_->fragmented_data_chunks_list;
	auto init_ctsn = mrecv_->cumulative_tsn;
	uint chunktsn;

	//when chunk_tsn=3
	chunktsn = 3;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then sequence should change from 2 (3) 4-5 (6) 7-7 (89) 13-15 to 5 (6) 7-7 (89) 13-15
	ASSERT_EQ(mrecv_->cumulative_tsn, 5);
	segment32_t& seg77_ = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg77_.start_tsn, 7);
	ASSERT_EQ(seg77_.stop_tsn, 7);
	mrecv_->fragmented_data_chunks_list.pop_front();
	segment32_t& seg13_15_ = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg13_15_.start_tsn, 13);
	ASSERT_EQ(seg13_15_.stop_tsn, 15);
	mrecv_->fragmented_data_chunks_list.pop_front();
	ASSERT_TRUE(mrecv_->fragmented_data_chunks_list.empty());

	//set back for next test
	mrecv_->cumulative_tsn = init_ctsn;
	mrecv_->fragmented_data_chunks_list = init_list;

	//when chunk_tsn=6
	chunktsn = 6;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then sequence should change from 2 (3) 4-5 (6) 7-7 (89) 13-15 to 2 (3) 4-7 (89) 13-15
	ASSERT_EQ(mrecv_->cumulative_tsn, 2);
	segment32_t& seg47 = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg47.start_tsn, 4);
	ASSERT_EQ(seg47.stop_tsn, 7);
	mrecv_->fragmented_data_chunks_list.pop_front();
	segment32_t& seg13_15__ = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg13_15__.start_tsn, 13);
	ASSERT_EQ(seg13_15__.stop_tsn, 15);
	mrecv_->fragmented_data_chunks_list.pop_front();
	ASSERT_TRUE(mrecv_->fragmented_data_chunks_list.empty());

	//set back for next test
	mrecv_->cumulative_tsn = init_ctsn;
	mrecv_->fragmented_data_chunks_list = init_list;

	//when chunk_tsn=8
	chunktsn = 8;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then sequence should change from 2 (3) 4-5 (6) 7-7 (89) 13-15 to 2 (3) 7-8 (9) 13-15
	ASSERT_EQ(mrecv_->cumulative_tsn, 2);
	segment32_t& seg45___ = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg45___.start_tsn, 4);
	ASSERT_EQ(seg45___.stop_tsn, 5);
	mrecv_->fragmented_data_chunks_list.pop_front();
	segment32_t& seg78 = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg78.start_tsn, 7);
	ASSERT_EQ(seg78.stop_tsn, 8);
	mrecv_->fragmented_data_chunks_list.pop_front();
	segment32_t& seg13_15___ = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg13_15___.start_tsn, 13);
	ASSERT_EQ(seg13_15___.stop_tsn, 15);
	mrecv_->fragmented_data_chunks_list.pop_front();
	ASSERT_TRUE(mrecv_->fragmented_data_chunks_list.empty());

	//set back for next test
	mrecv_->cumulative_tsn = init_ctsn;
	mrecv_->fragmented_data_chunks_list = init_list;

	//when chunk_tsn=10
	chunktsn = 10;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then sequence should change from
	//2 (3) 4-5 (6) 7-7 (89) to 2 (3) 4-5 7-7 10-10 (11-12) 13-15
	ASSERT_EQ(mrecv_->cumulative_tsn, init_ctsn);
	segment32_t& seg45 = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg45.start_tsn, 4);
	ASSERT_EQ(seg45.stop_tsn, 5);
	mrecv_->fragmented_data_chunks_list.pop_front();
	segment32_t& seg77 = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg77.start_tsn, 7);
	ASSERT_EQ(seg77.stop_tsn, 7);
	mrecv_->fragmented_data_chunks_list.pop_front();
	segment32_t& seg10_10 = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg10_10.start_tsn, 10);
	ASSERT_EQ(seg10_10.stop_tsn, 10);
	mrecv_->fragmented_data_chunks_list.pop_front();
	segment32_t& seg13_15 = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg13_15.start_tsn, 13);
	ASSERT_EQ(seg13_15.stop_tsn, 15);
	mrecv_->fragmented_data_chunks_list.pop_front();
	ASSERT_TRUE(mrecv_->fragmented_data_chunks_list.empty());

	// Given cstna=1, frags = {4-5,8-9}, 1 (2-3) 4-5 (6-7) 8-9
	mrecv_->cumulative_tsn = init_ctsn = 1;
	mrecv_->fragmented_data_chunks_list.clear();
	mrecv_->fragmented_data_chunks_list.push_back(
	{ 4, 5 });
	mrecv_->fragmented_data_chunks_list.push_back(
	{ 8, 9 });
	init_list = mrecv_->fragmented_data_chunks_list;

	//when chunk_tsn=2
	chunktsn = 2;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then sequence should change from
	// 1 (2-3) 4-5 (6-7) 8-9 to 2 (3) 4-5 (6-7) 8-9
	ASSERT_EQ(mrecv_->cumulative_tsn, 2);
	segment32_t& seg45____ = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg45____.start_tsn, 4);
	ASSERT_EQ(seg45____.stop_tsn, 5);
	mrecv_->fragmented_data_chunks_list.pop_front();
	segment32_t& seg89 = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg89.start_tsn, 8);
	ASSERT_EQ(seg89.stop_tsn, 9);
	mrecv_->fragmented_data_chunks_list.pop_front();
	ASSERT_TRUE(mrecv_->fragmented_data_chunks_list.empty());
	//set back for next test
	mrecv_->cumulative_tsn = init_ctsn;
	mrecv_->fragmented_data_chunks_list = init_list;

	//when chunk_tsn=3
	chunktsn = 3;
	mrecv_update_fragments(mrecv_, chunktsn);
	//then sequence should change from
	//1 (2-3) 4-5 (6-7) 8-9 to 1 (2) 3-5 (6-7) 8-9
	ASSERT_EQ(mrecv_->cumulative_tsn, 1);
	segment32_t& seg35 = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg35.start_tsn, 3);
	ASSERT_EQ(seg35.stop_tsn, 5);
	mrecv_->fragmented_data_chunks_list.pop_front();
	segment32_t& seg89_____ = mrecv_->fragmented_data_chunks_list.front();
	ASSERT_EQ(seg89_____.start_tsn, 8);
	ASSERT_EQ(seg89_____.stop_tsn, 9);
	mrecv_->fragmented_data_chunks_list.pop_front();
	ASSERT_TRUE(mrecv_->fragmented_data_chunks_list.empty());

	reset();
}

extern int
mrecv_receive_dchunk(dchunk_r_o_s_t* data_chunk, uint remote_addr_idx);
TEST_F(mrecv, test_mrecv_receive_dchunk)
{
	// given remote addr index 0, sid 0,  pdu = 32
	ushort addr_idx = 0;
	ushort sid = 0;
	ushort ssn = 0;
	uint tsn = UT_ITSN;
	uint pdulen = 32;

	// and given an unfragmented dchunk_ur_uo_us
	uchar chunkflag = FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_UNSEQ
		| DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
	chunk_id_t dchunk_ur_uo_us_id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[dchunk_ur_uo_us_id] = DCHUNK_UR_US_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[dchunk_ur_uo_us_id] += pdulen;
	dchunk_ur_us_t* dchunk_ur_us = (dchunk_ur_us_t*)mch_complete_simple_chunk(
		dchunk_ur_uo_us_id);

	// and given an unfragmented dchunk_ur_s
	chunkflag =
		FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_SEQ
		| DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
	chunk_id_t dchunk_ur_s_id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[dchunk_ur_s_id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[dchunk_ur_s_id] += pdulen;
	dchunk_ur_s_t* dchunk_ur_s = (dchunk_ur_s_t*)mch_complete_simple_chunk(
		dchunk_ur_s_id);
	dchunk_ur_s->data_chunk_hdr.stream_identity = htons(sid);
	dchunk_ur_s->data_chunk_hdr.stream_seq_num = htons(ssn);
	ssn++;

	// and given an unfragmented dchunk_r_uo_us
	chunkflag =
		FLAG_TBIT_UNSET | DCHUNK_FLAG_RELIABLE | DCHUNK_FLAG_UNSEQ
		| DCHUNK_FLAG_UNORDER | DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
	chunk_id_t dchunk_r_uo_us_id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[dchunk_r_uo_us_id] = DCHUNK_R_UO_US_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[dchunk_r_uo_us_id] += pdulen;
	dchunk_r_uo_us_t* dchunk_r_uo_us =
		(dchunk_r_uo_us_t*)mch_complete_simple_chunk(dchunk_r_uo_us_id);
	dchunk_r_uo_us->data_chunk_hdr.trans_seq_num = htonl(tsn);
	tsn++;

	// and given an unfragmented dchunk_r_o
	chunkflag =
		FLAG_TBIT_UNSET | DCHUNK_FLAG_RELIABLE | DCHUNK_FLAG_ORDER
		| DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
	chunk_id_t dchunk_r_o_s_id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[dchunk_r_o_s_id] = DCHUNK_R_O_S_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[dchunk_r_o_s_id] += pdulen;
	dchunk_r_o_s_t* dchunk_r_o_s = (dchunk_r_o_s_t*)mch_complete_simple_chunk(dchunk_r_o_s_id);
	dchunk_r_o_s->data_chunk_hdr.stream_identity = htons(sid);
	dchunk_r_o_s->data_chunk_hdr.stream_seq_num = htons(ssn);
	dchunk_r_o_s->data_chunk_hdr.trans_seq_num = htonl(tsn);

	// when receiving a ro-dchunk
	mrecv_receive_dchunk(dchunk_r_o_s, addr_idx);
	ASSERT_TRUE(mrecv_->datagram_has_reliable_dchunk);
	ASSERT_EQ(mrecv_->duplicated_data_chunks_list.size(), 0);
	ASSERT_EQ(mrecv_->highest_duplicate_tsn, tsn);
}
