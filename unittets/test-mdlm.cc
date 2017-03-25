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
	chunk_id_t id = mch_make_simple_chunk(CHUNK_DATA, DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_UNSEQ);
	uint pdu_len = 32;
	curr_write_pos_[id] = pdu_len;
	dchunk_ur_us_t* chunk = (dchunk_ur_us_t*)mch_complete_simple_chunk(id);
	ushort addr_idx = 0;
	mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
}