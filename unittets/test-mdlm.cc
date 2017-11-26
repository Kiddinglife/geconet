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
	deliverman_controller_t init_mdlm_;
	geco_channel_t* init_channel_;
	recv_controller_t* mrecv_;
	recv_controller_t init_mrecv_;

	virtual void
		SetUp()
	{
		GLOBAL_CURR_EVENT_LOG_LEVEL = INFO;
		alloc_geco_channel();
		init_channel_ = curr_channel_;
		mdlm_ = init_channel_->deliverman_control;
		init_mdlm_ = *mdlm_;
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
		mdlm_ = init_channel_->deliverman_control;
		*mdlm_ = init_mdlm_;
		mrecv_ = init_channel_->receive_control;
		*mrecv_ = init_mrecv_;
	}
};

extern int
mdlm_receive_dchunk(deliverman_controller_t* mdlm, dchunk_ur_us_t* dataChunk,
	ushort address_index);
TEST_F(mdlm, test_mdlm_process_dchunk_ur_us_t)
{
	// given dchunk_ur_s_t, addr_idx 0, pdu 32
	uchar chunkflag = FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_UNSEQ
		| DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
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
	ASSERT_EQ(mdlm_->queued_bytes, 32);
	const auto& found = std::find_if(
		mdlm_->ur_pduList.begin(), mdlm_->ur_pduList.end(),
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
	chunkflag = FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_UNSEQ
		| DCHUNK_FLAG_FIRST_FRAG;
	pdu_len = 32;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[id] = pdu_len;
	chunk = (dchunk_ur_us_t*)mch_complete_simple_chunk(id);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should abort current channel
	ASSERT_EQ(ret, -19); // MULP_PROTOCOL_VIOLATION=-19
	ASSERT_EQ(curr_channel_, nullptr);
	mch_free_simple_chunk(id);
	this->SetUp();
}

extern int
mdlm_receive_dchunk(deliverman_controller_t* mdlm, dchunk_ur_s_t* dataChunk,
	ushort address_index);
TEST_F(mdlm, test_mdlm_process_dchunk_ur_s_t)
{
	// given dchunk_ur_s_t, addr_idx 0 numSequencedStreams 12
	uchar chunkflag = FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_SEQ
		| DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
	ushort addr_idx = 0;

	chunk_id_t id;
	uint pdu_len;
	dchunk_ur_s_t* chunk;

	//when pdu_len = 32 >0, sid == mdlm->numSequencedStreams
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	pdu_len = 32;
	chunk = (dchunk_ur_s_t*)mch_complete_simple_chunk(id);
	chunk->data_chunk_hdr.stream_identity = htons(mdlm_->numSequencedStreams);
	curr_write_pos_[id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[id] += pdu_len;
	int ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should create a delivery_pdu and add it to mdlm->ur_pduList
	ASSERT_EQ(ret, -17); //MULP_INVALID_STREAM_ID=-17
	ASSERT_EQ(curr_channel_, nullptr);

	mch_free_simple_chunk(id);
	this->SetUp();

	//when pdu_len = 0 and stream_identity<numSequencedStreams
	pdu_len = 0;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	chunk->data_chunk_hdr.stream_identity = htons(
		mdlm_->numSequencedStreams - 1);
	curr_write_pos_[id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[id] += pdu_len;
	chunk = (dchunk_ur_s_t*)mch_complete_simple_chunk(id);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should abort current channel
	ASSERT_EQ(ret, -18); // MULP_NO_USER_DATA=-18
	ASSERT_EQ(curr_channel_, nullptr);
	mch_free_simple_chunk(id);
	this->SetUp();

	//when dchunk_ur_s is segmented, pdu not zero, sid < mdlm_->numSequencedStreams
	chunkflag = FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_UNSEQ
		| DCHUNK_FLAG_FIRST_FRAG;
	pdu_len = 32;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[id] += pdu_len;
	chunk = (dchunk_ur_s_t*)mch_complete_simple_chunk(id);
	chunk->data_chunk_hdr.stream_identity = htons(mdlm_->numSequencedStreams - 1);
	chunk->data_chunk_hdr.stream_seq_num = htons(3);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should abort current channel
	ASSERT_EQ(ret, -19); // MULP_PROTOCOL_VIOLATION=-19
	ASSERT_EQ(curr_channel_, nullptr);
	mch_free_simple_chunk(id);
	this->SetUp();

	ushort ssn;

	//when dchunk_ur_s is completed, pdu not zero, sid < mdlm_->numSequencedStreams
	ushort sid = 0;
	recv_stream_t* recv_stream = &mdlm_->recv_seq_streams[sid];
	chunkflag = FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_SEQ
		| DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
	pdu_len = 32;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	chunk->data_chunk_hdr.stream_identity = htons(sid);
	curr_write_pos_[id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[id] += pdu_len;
	chunk = (dchunk_ur_s_t*)mch_complete_simple_chunk(id);

	//and when last_ssn_used=true,recv_stream->last_ssn=0,ssn=2 != 0+1
	recv_stream->last_ssn_used = true;
	recv_stream->last_ssn = 0;
	chunk->data_chunk_hdr.stream_seq_num = htons(2);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should discard the chunk
	ASSERT_EQ(ret, -19); // MULP_PROTOCOL_VIOLATION=-19
	ASSERT_EQ(curr_channel_, nullptr);
	mch_free_simple_chunk(id);
	this->SetUp();

	//and when last_ssn_used=false,sbefore(ssn=2,next_expected_ssn=3)
	recv_stream = &mdlm_->recv_seq_streams[sid];
	recv_stream->last_ssn_used = false;
	recv_stream->next_expected_ssn = 3;
	pdu_len = 32;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	chunk->data_chunk_hdr.stream_identity = htons(sid);
	chunk->data_chunk_hdr.stream_seq_num = htons(2);
	curr_write_pos_[id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[id] += pdu_len;
	chunk = (dchunk_ur_s_t*)mch_complete_simple_chunk(id);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should discard the chunk
	ASSERT_EQ(ret, 0); // MULP_SUCCESS=0
	mch_free_simple_chunk(id);
	reset();

	//and when last_ssn_used=false,ssn=0,next_expected_ssn=0,sid=0
	ssn = 0;
	recv_stream = &mdlm_->recv_seq_streams[sid];
	recv_stream->next_expected_ssn = 0;
	pdu_len = 32;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	chunk->data_chunk_hdr.stream_identity = sid;
	chunk->data_chunk_hdr.stream_seq_num = htons(ssn);
	curr_write_pos_[id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[id] += pdu_len;
	chunk = (dchunk_ur_s_t*)mch_complete_simple_chunk(id);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should add the chunk
	ASSERT_EQ(ret, 0); // MULP_SUCCESS=0
	ASSERT_EQ(recv_stream->next_expected_ssn, ssn + 1);
	ASSERT_EQ(recv_stream->last_ssn, ssn);
	ASSERT_EQ(recv_stream->last_ssn_used, true);
	mch_free_simple_chunk(id);
	//g_ut_console->debug("hello man");

	//and and when ssn(1) == recv_stream->last_ssn(0)+1
	ssn = 1;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	chunk->data_chunk_hdr.stream_identity = sid;
	chunk->data_chunk_hdr.stream_seq_num = htons(ssn);
	curr_write_pos_[id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[id] += pdu_len;
	chunk = (dchunk_ur_s_t*)mch_complete_simple_chunk(id);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should add the chunk
	ASSERT_EQ(ret, 0); // MULP_SUCCESS=0
	ASSERT_EQ(recv_stream->next_expected_ssn, ssn + 1);
	ASSERT_EQ(recv_stream->last_ssn, ssn);
	ASSERT_EQ(recv_stream->last_ssn_used, true);
	mch_free_simple_chunk(id);

	ASSERT_EQ(recv_stream->prePduList.front()->data->stream_sn, 0);
	recv_stream->prePduList.pop_front();
	ASSERT_EQ(recv_stream->prePduList.front()->data->stream_sn, 1);
	recv_stream->prePduList.pop_front();
	ASSERT_TRUE(recv_stream->prePduList.empty());

	//and and when ssn(3) != recv_stream->last_ssn(1)+1=2
	ssn = 3;
	id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	chunk->data_chunk_hdr.stream_identity = sid;
	chunk->data_chunk_hdr.stream_seq_num = htons(ssn);
	curr_write_pos_[id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[id] += pdu_len;
	chunk = (dchunk_ur_s_t*)mch_complete_simple_chunk(id);
	ret = mdlm_receive_dchunk(mdlm_, chunk, addr_idx);
	//then should abort connection
	ASSERT_EQ(ret, -19); // MULP_PROTOCOL_VIOLATION=-19
	ASSERT_EQ(curr_channel_, nullptr);
	mch_free_simple_chunk(id);
	this->SetUp();
}

extern int mdlm_reassemble_pdu_frags(deliverman_controller_t* mdlm);
extern int mrecv_receive_dchunk(dchunk_r_o_s_t* data_chunk, uint remote_addr_idx);
TEST_F(mdlm, test_mdlm_reassemble_pdu_frags)
{
	// test search complete pdu from reliable-ordered chunklist
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
	dchunk_r_o_s_t* dchunk_ur_us = (dchunk_r_o_s_t*)mch_complete_simple_chunk(
		dchunk_ur_uo_us_id);

	// and given an unfragmented dchunk_ur_s
	chunkflag = FLAG_TBIT_UNSET | DCHUNK_FLAG_UNRELIABLE | DCHUNK_FLAG_SEQ |
		DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
	chunk_id_t dchunk_ur_s_id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[dchunk_ur_s_id] = DCHUNK_UR_SEQ_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[dchunk_ur_s_id] += pdulen;
	dchunk_r_o_s_t* dchunk_ur_s = (dchunk_r_o_s_t*)mch_complete_simple_chunk(
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
	dchunk_r_o_s_t* dchunk_r_uo_us = (dchunk_r_o_s_t*)mch_complete_simple_chunk(
		dchunk_r_uo_us_id);
	dchunk_r_uo_us->data_chunk_hdr.trans_seq_num = htonl(tsn);
	tsn++;

	// and given an unfragmented dchunk_r_o
	chunkflag =
		FLAG_TBIT_UNSET | DCHUNK_FLAG_RELIABLE | DCHUNK_FLAG_ORDER
		| DCHUNK_FLAG_FIRST_FRAG | DCHUNK_FLAG_LAST_FRG;
	chunk_id_t dchunk_r_o_s_id = mch_make_simple_chunk(CHUNK_DATA, chunkflag);
	curr_write_pos_[dchunk_r_o_s_id] = DCHUNK_R_O_S_FIXED_SIZE; // write dchunk_ur fixed size
	curr_write_pos_[dchunk_r_o_s_id] += pdulen;
	dchunk_r_o_s_t* dchunk_r_o_s = (dchunk_r_o_s_t*)mch_complete_simple_chunk(
		dchunk_r_o_s_id);
	dchunk_r_o_s->data_chunk_hdr.stream_identity = htons(sid);
	dchunk_r_o_s->data_chunk_hdr.stream_seq_num = htons(ssn);
	dchunk_r_o_s->data_chunk_hdr.trans_seq_num = htonl(tsn);

	// when receiving a ro-dchunk
	mrecv_receive_dchunk(dchunk_r_o_s, addr_idx);
	ASSERT_TRUE(mrecv_->datagram_has_reliable_dchunk);
	ASSERT_EQ(mrecv_->duplicated_data_chunks_list.size(), 0);
	ASSERT_EQ(mrecv_->highest_duplicate_tsn, tsn);

	// when receiving a r-uo-us-dchunk
	mrecv_receive_dchunk(dchunk_r_uo_us, addr_idx);
	ASSERT_TRUE(mrecv_->datagram_has_reliable_dchunk);
	ASSERT_EQ(mrecv_->duplicated_data_chunks_list.size(), 0);
	ASSERT_EQ(mrecv_->highest_duplicate_tsn, tsn);

	// when receiving a dchunk_ur_s
	mrecv_receive_dchunk(dchunk_ur_s, addr_idx);
	ASSERT_TRUE(mrecv_->datagram_has_reliable_dchunk);
	ASSERT_EQ(mrecv_->duplicated_data_chunks_list.size(), 0);
	ASSERT_EQ(mrecv_->highest_duplicate_tsn, tsn);

	// when receiving a dchunk_ur_s
	mrecv_receive_dchunk(dchunk_ur_us, addr_idx);
	ASSERT_TRUE(mrecv_->datagram_has_reliable_dchunk);
	ASSERT_EQ(mrecv_->duplicated_data_chunks_list.size(), 0);
	ASSERT_EQ(mrecv_->highest_duplicate_tsn, tsn);
}