/*
* test-mrecv.cc
*
*  Created on: Mar 25, 2017
*      Author: jakez
*/

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "geco-net-chunk.h"
#include "geco-test.h"

#include "geco-net-chunk.h"
#include "geco-net.h"

struct mdlm : public testing::Test
{
	deliverman_controller_t* mdlm_;
	deliverman_controller_t init_mrecv_;
	geco_channel_t* init_channel_;

	virtual void
		SetUp()
	{
		GLOBAL_CURR_EVENT_LOG_LEVEL = INFO;
		alloc_geco_channel();
		init_channel_ = curr_channel_;
		mdlm_ = init_channel_->deliverman_control;
		init_mrecv_ = *mdlm_;
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
		mdlm_ = init_channel_->deliverman_control;
		*mdlm_ = init_mrecv_;
	}
};

extern int
mdlm_receive_dchunk(deliverman_controller_t* mdlm, dchunk_ur_us_t* dataChunk, ushort address_index);
TEST_F(mdlm, test_mdlm_process_dchunk_ur_us_t)
{
	// given dchunk_ur_s_t, addr_idx 0, pdu 32
	uchar chunkflag = FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_UNSEQ | DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
	chunk_id_t id;
	uint pdu_len;
	dchunk_ur_us_t* chunk;
	ushort addr_idx = 0;

	//when pdu_len = 32 >0 
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	pdu_len = 32;
	curr_write_pos_[id] = pdu_len;
	chunk = (dchunk_ur_us_t*)mch_complete_simple_chunk(id);
	int ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should create a delivery_pdu and add it to mdlm->ur_pduList 
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(mdlm_->queuedBytes, 32);
	const auto& found = std::find_if(mdlm_->ur_pduList.begin(), mdlm_->ur_pduList.end(), 
		[](const delivery_pdu_t* const val) 
	{
		return val->number_of_chunks == 1 &&
			val->read_position == 0 &&
			val->read_chunk == 0 &&
			val->chunk_position == 0 &&
			val->total_length == 32 &&
			val->data->chunk_flags == FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE |
			DCHUNK_FLAG_UNSEQ | DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG &&
			val->data->from_addr_index == 0 &&
			val->data->data_length == 32;
	});
	ASSERT_NE(found, mdlm_->ur_pduList.end());
	mch_free_simple_chunk(id);
	reset();

	//when pdu_len = 0 
	pdu_len = 0;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[id] = pdu_len;
	chunk = (dchunk_ur_us_t*)mch_complete_simple_chunk(id);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should abort current channel
	ASSERT_EQ(ret, -18); // MULP_NO_USER_DATA=-18
	ASSERT_EQ(curr_channel_, nullptr);
	this->SetUp();

	//when dchunk_ur_s is segmented and pdu not zero
	chunkflag = FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_UNSEQ | DCHUNK_FLAG_FIRST_FRAG;
	pdu_len = 32;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[id] = pdu_len;
	chunk = (dchunk_ur_us_t*)mch_complete_simple_chunk(id);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should abort current channel
	ASSERT_EQ(ret, -19); // MULP_PROTOCOL_VIOLATION=-19
	ASSERT_EQ(curr_channel_, nullptr);
	this->SetUp();
}