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
#include "geco-net-chunk.h"

struct mpath : public testing::Test
{
	path_controller_t* mpath_;
	void* old_arg3;
	timeout_t old_exps;
	uint old_retrans_count;
	bool old_hb_sent;
	geco_channel_t* old_channel;
	timeout* timerID;
	path_params_t* path;
	bool old_hb_acked;
	uint old_total_retrans_count;
	uint old_srtt;
	uint old_rttvar;
	uint old_rto;
	uint old_first_rto;
	uint64 old_rtt_update_time;
	uint old_state;

	virtual void
		SetUp()
	{
		alloc_geco_channel();
		mpath_ = curr_channel_->path_control;
		path = &mpath_->path_params[0];
		timerID = path->hb_timer_id;
		old_arg3 = timerID->callback.arg3;
		old_exps = timerID->expires;
		old_retrans_count = path->retrans_count;
		old_hb_sent = path->hb_sent;
		old_hb_acked = path->hb_acked;
		old_channel = curr_channel_;
		old_total_retrans_count = mpath_->total_retrans_count;
		old_srtt = path->srtt;
		old_rttvar = path->rttvar;
		old_rto = path->rto;
		old_first_rto = path->firstRTO;
		old_rtt_update_time = path->rtt_update_time;
		old_state = path->state;
	}
	virtual void
		TearDown()
	{
		free_geco_channel();
	}

	void
		reset()
	{
		//reset everything of 'path' to its init valuess
		mpath_->total_retrans_count = old_total_retrans_count;
		path->hb_sent = old_hb_sent;
		timerID->callback.arg3 = old_arg3;
		path->retrans_count = old_retrans_count;
		timerID->expires = old_exps;
		path->hb_sent = old_hb_sent;
		path->hb_acked = old_hb_acked;
		curr_channel_ = old_channel;
		curr_geco_instance_ = curr_channel_->geco_inst;
		path->srtt = old_srtt;
		path->rttvar = old_rttvar;
		path->rto = old_rto;
		path->firstRTO = old_first_rto;
		path->rtt_update_time = old_rtt_update_time;
		path->state = old_state;
	}
};

TEST_F(mpath, test_new_and_free)
{
	ASSERT_EQ(mpath_->channel_id, curr_channel_->channel_id);
	ASSERT_EQ(mpath_->primary_path, UT_PRI_PATH_ID);
	ASSERT_EQ(mpath_->path_num, UT_REMOTE_ADDR_LIST_SIZE);
	ASSERT_EQ(mpath_->max_retrans_per_path, 2);
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
	ASSERT_EQ(curr_channel_->state_machine_control->max_assoc_retrans_count,
		mpath_->max_retrans_per_path * UT_REMOTE_ADDR_LIST_SIZE);
	for (int i = 0; i < mpath_->path_num; i++)
	{
		ASSERT_EQ(mpath_->path_params[i].hb_enabled, true);
		ASSERT_EQ(mpath_->path_params[i].firstRTO, true);
		ASSERT_EQ(mpath_->path_params[i].retrans_count, 0);
		ASSERT_EQ(mpath_->path_params[i].rto, mpath_->rto_initial);
		ASSERT_EQ(mpath_->path_params[i].srtt, mpath_->rto_initial);
		ASSERT_EQ(mpath_->path_params[i].rttvar, 0);
		ASSERT_EQ(mpath_->path_params[i].hb_sent, false);
		ASSERT_EQ(mpath_->path_params[i].hb_acked, false);
		ASSERT_EQ(mpath_->path_params[i].timer_backoff, false);
		ASSERT_EQ(mpath_->path_params[i].data_chunk_acked, false);
		ASSERT_EQ(mpath_->path_params[i].data_chunk_sent, false);
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

extern bool
mpath_handle_chunks_rtx(short pathID);
TEST_F(mpath, test_handle_chunks_retx)
{
	//given max_channel_retrans_count = 2,max_retrans_per_path = 1
	bool ret;
	//1 when path is unconfirmed,
	mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
	mpath_handle_chunks_rtx(0);
	//then only increment path retrans counter by one
	ASSERT_EQ(mpath_->path_params[0].retrans_count, 1);
	//reset to initial mpath value
	mpath_->path_params[0].retrans_count = 0;
	mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
	//2 when path is active,
	mpath_->path_params[1].state = PM_ACTIVE;
	mpath_handle_chunks_rtx(1);
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
	ret = mpath_handle_chunks_rtx(0);
	ret = mpath_handle_chunks_rtx(1);
	ret = mpath_handle_chunks_rtx(0);
	ret = mpath_handle_chunks_rtx(1);
	// then disconnect and delete channel -> return true
	ASSERT_EQ(curr_channel_, nullptr);
	ASSERT_EQ(curr_geco_instance_, nullptr);
	ASSERT_EQ(ret, true);
	// as the last test exceeds max_channel_retrans_count that leads to curr_channel_ freed so realloc it
	alloc_geco_channel();
	mpath_ = curr_channel_->path_control;
	//4 when path is inactive,
	mpath_->path_params[0].state = PM_INACTIVE;
	ret = mpath_handle_chunks_rtx(0);
	// then stop -> return false
	ASSERT_EQ(ret, false);
	//reset to initial mpath value
	mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
	//5 when path max retrans  >= max_retrans_per_path
	mpath_->path_params[0].state = PM_ACTIVE;
	mpath_handle_chunks_rtx(0);
	mpath_handle_chunks_rtx(0);
	// then path is marked as inactive
	ASSERT_EQ(mpath_->path_params[0].state, PM_INACTIVE);
	//reset to initial mpath value
	mpath_->path_params[0].retrans_count = 0;
	mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
	mpath_->total_retrans_count = 0;
	//6 when there is active or unconfirmed path
	mpath_->path_params[1].state = PM_ACTIVE;
	mpath_handle_chunks_rtx(1);
	mpath_handle_chunks_rtx(1);
	mpath_handle_chunks_rtx(0);
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
	//7 when all paths are unconfirmed and total_retrans_count >= max_channel_retrans_count,
	ret = mpath_handle_chunks_rtx(0);
	ret = mpath_handle_chunks_rtx(1);
	ret = mpath_handle_chunks_rtx(0);
	ret = mpath_handle_chunks_rtx(1);
	// then disconnect and delete channel -> return true
	ASSERT_EQ(curr_channel_, nullptr);
	ASSERT_EQ(curr_geco_instance_, nullptr);
	ASSERT_EQ(ret, true);
	// as the last test exceeds max_channel_retrans_count that leads to curr_channel_ freed so realloc it
	alloc_geco_channel();
	mpath_ = curr_channel_->path_control;
	//8 when one active one unconfirmed paths' total_retrans_count >= max_channel_retrans_count,
	mpath_->path_params[0].state = PM_ACTIVE;
	ret = mpath_handle_chunks_rtx(0);
	ret = mpath_handle_chunks_rtx(1);
	ret = mpath_handle_chunks_rtx(0);
	ret = mpath_handle_chunks_rtx(1);
	// then disconnect and delete channel -> return true
	ASSERT_EQ(curr_channel_, nullptr);
	ASSERT_EQ(curr_geco_instance_, nullptr);
	ASSERT_EQ(ret, true);
	// as the last test exceeds max_channel_retrans_count that leads to curr_channel_ freed so realloc it
	alloc_geco_channel();
	mpath_ = curr_channel_->path_control;
	//9 when primary path becomes inactive,
	mpath_->primary_path = 0;
	mpath_->path_params[0].data_chunk_sent = true;
	ret = mpath_handle_chunks_rtx(0);
	ret = mpath_handle_chunks_rtx(0);
	// then use path1 as primary path even it is unconfirmed
	ASSERT_EQ(mpath_->primary_path, 1);
	ASSERT_EQ(mpath_->path_params[0].data_chunk_sent, false);
	ASSERT_EQ(mpath_->path_params[1].data_chunk_acked, false);
	//reset to initial mpath value
	mpath_->path_params[0].data_chunk_sent = false;
	mpath_->path_params[0].retrans_count = 0;
	mpath_->path_params[0].state = PM_PATH_UNCONFIRMED;
	mpath_->path_params[1].retrans_count = 0;
	mpath_->path_params[1].state = PM_PATH_UNCONFIRMED;
	mpath_->total_retrans_count = 0;
	reset();
}

extern int
mpath_heartbeat_timer_expired(timeout* timerID);
TEST_F(mpath, test_heartbeat_timer_expired)
{
	//1 when mtu 0, hb_sent false, hb_acked false
	timerID->callback.arg3 = nullptr;
	path->hb_sent = false;
	mpath_heartbeat_timer_expired(timerID);
	//then this is the error case that should not happen
	// in order to make it rubust, send hb probe with mtu 0 again
	ASSERT_EQ(curr_channel_, nullptr);
	ASSERT_EQ(timerID->callback.arg3, nullptr);
	ASSERT_EQ(timerID, path->hb_timer_id);
	ASSERT_EQ(false, path->data_chunk_sent);
	ASSERT_EQ(false, path->data_chunk_acked);
	ASSERT_EQ(path->retrans_count, 0);
	ASSERT_LE(
		abs(
		(timerID->expires - old_exps) / stamps_per_ms_double()
			- (double)(path->rto + path->hb_interval)),
		1.f);
	reset();

	//2 when mtu 0, hb_sent true, hb_acked false
	timerID->callback.arg3 = nullptr;
	path->hb_sent = true;
	mpath_heartbeat_timer_expired(timerID);
	//then this is case that last hb probe failed and need send hb probe with mtu 0 again
	ASSERT_EQ(curr_channel_, nullptr);
	ASSERT_EQ(timerID->callback.arg3, nullptr);
	ASSERT_EQ(path->probing_pmtu, PMTU_HIGHEST);
	ASSERT_EQ(timerID, path->hb_timer_id);
	ASSERT_EQ(false, path->data_chunk_sent);
	ASSERT_EQ(false, path->data_chunk_acked);
	ASSERT_EQ(path->retrans_count, 1);
	ASSERT_LE(
		abs(
		(timerID->expires - old_exps) / stamps_per_ms_double()
			- (double)(path->rto + path->hb_interval)),
		1.f);
	reset();

	//3 when mtu !0, hb_sent false, hb_acked false
	path->hb_sent = false;
	mpath_heartbeat_timer_expired(timerID);
	//then path verify when connected by sending hb probe with PMTU_HIGHEST
	ASSERT_EQ(curr_channel_, nullptr);
	ASSERT_EQ(*(uint*)(timerID->callback.arg3), PMTU_HIGHEST);
	ASSERT_EQ(path->probing_pmtu, PMTU_HIGHEST);
	ASSERT_EQ(timerID, path->hb_timer_id);
	ASSERT_EQ(false, path->data_chunk_sent);
	ASSERT_EQ(false, path->data_chunk_acked);
	ASSERT_EQ(path->retrans_count, 0);
	ASSERT_LE(
		abs(
		(timerID->expires - old_exps) / stamps_per_ms_double()
			- (double)(path->rto)),
		1.f);
	reset();

	//4 when mtu !0, hb_sent false, hb_acked true
	path->hb_sent = false;
	path->hb_acked = true;
	mpath_heartbeat_timer_expired(timerID);
	//then pmtu&hb probe suceeds, switch to normal hb probe by sending hb probe again
	ASSERT_EQ(curr_channel_, nullptr);
	ASSERT_EQ(timerID->callback.arg3, nullptr);
	ASSERT_EQ(path->probing_pmtu, PMTU_HIGHEST);
	ASSERT_EQ(timerID, path->hb_timer_id);
	ASSERT_EQ(false, path->data_chunk_sent);
	ASSERT_EQ(false, path->data_chunk_acked);
	ASSERT_EQ(path->retrans_count, 0);
	ASSERT_LE(
		abs(
		(timerID->expires - old_exps) / stamps_per_ms_double()
			- (double)(path->rto + path->hb_interval)),
		1.f);
	reset();

	//5 when total_retrans_count >= max_channel_retrans_count,
	mpath_->total_retrans_count = mpath_->max_retrans_per_path * mpath_->path_num;
	mpath_->path_params[1].state = PM_ACTIVE;
	path->hb_sent = true;
	path->hb_acked = false;
	mpath_heartbeat_timer_expired(timerID);
	// then disconnect and delete channel -> return true
	ASSERT_EQ(curr_channel_, nullptr);
	ASSERT_EQ(curr_geco_instance_, nullptr);
	// realloc channel and reset evenrything
	this->SetUp();
}

extern void
mpath_update_rtt(short pathID, int newRTT);
TEST_F(mpath, test_update_rtt)
{
	bool ret;
	//1 when it is retransmit acked
	mpath_update_rtt(path->path_id, 0);
	//then should not update rtt  pmData->path_params[pathID].firstRTO
	ASSERT_EQ(path->firstRTO, true);
	reset();
	//2 when it is Not retransmit acked
	mpath_update_rtt(path->path_id, 50);
	//then should update rtt
	ASSERT_EQ(path->firstRTO, false);
	ASSERT_EQ(path->srtt, 50);
	ASSERT_EQ(path->rttvar, 25);
	ASSERT_EQ(path->rto, mpath_->rto_min);
	mpath_update_rtt(path->path_id, 50);
	//then should update rtt
	ASSERT_EQ(path->firstRTO, false);
	ASSERT_EQ(path->srtt, 50);
	ASSERT_EQ(path->rttvar, 18);
	ASSERT_EQ(path->rto, mpath_->rto_min);
	reset();
}

extern void
mpath_data_chunk_acked(short pathID, int newRTT);
TEST_F(mpath, test_data_chunk_acked)
{
	//1 when newrtt >= rto_max
	mpath_data_chunk_acked(path->path_id, mpath_->rto_max + 1);
	//then should use rto_max to update rtt
	ASSERT_EQ(path->srtt, mpath_->rto_max);
	reset();

	//2 when  newrtt  0, path inactive
	mpath_data_chunk_acked(path->path_id, 0);
	path->state = PM_INACTIVE;
	//then do nothing but just return
	ASSERT_EQ(path->srtt, old_srtt);
	reset();

	//3 when  0 < newrtt < rto_max, path inactive
	mpath_data_chunk_acked(path->path_id, mpath_->rto_min / 2);
	path->state = PM_INACTIVE;
	//then do nothing but just return
	ASSERT_EQ(path->srtt, mpath_->rto_min / 2);
	reset();

	//3 when  newrtt 0, path active
	mpath_data_chunk_acked(path->path_id, 0);
	path->state = PM_ACTIVE;
	//then update path error counter
	ASSERT_EQ(path->retrans_count, 0);
	ASSERT_EQ(mpath_->total_retrans_count, 0);
	ASSERT_EQ(path->data_chunk_acked, true);
	reset();

	//4 when  0 < newrtt < rto_max, path active
	mpath_data_chunk_acked(path->path_id, 50);
	path->state = PM_ACTIVE;
	//then update path error counter, rto_update_time
	ASSERT_EQ(path->retrans_count, 0);
	ASSERT_EQ(mpath_->total_retrans_count, 0);
	ASSERT_EQ(path->data_chunk_acked, true);
	ASSERT_GT(
		(path->rtt_update_time - old_rtt_update_time) / stamps_per_ms_double(),
		(double)path->srtt);  // SRTT 50MS + SYTEM INTERVAL 8.7MS
	reset();
}

extern void
mpath_hb_ack_received(heartbeat_chunk_t* heartbeatChunk);
TEST_F(mpath, test_hb_ack_received)
{
	chunk_id_t hbid;
	heartbeat_chunk_t* hback;

	//1 when path id is illegal
	hbid = mch_make_hb_chunk(get_safe_time_ms() - 50, mpath_->path_num, 0);
	hback = (heartbeat_chunk_t*)mch_complete_simple_chunk(hbid);
	hback->chunk_header.chunk_id = CHUNK_HBACK;
	hback->chunk_header.chunk_length = htons(20 + ntohs(hback->hmaclen));
	mpath_hb_ack_received(hback);
	//then do nothing but just return
	mch_free_simple_chunk(hbid);
	reset();

	//2 when hmac illegal
	hbid = mch_make_hb_chunk(get_safe_time_ms() - 50, mpath_->path_num, 0);
	hback = (heartbeat_chunk_t*)mch_complete_simple_chunk(hbid);
	hback->chunk_header.chunk_id = CHUNK_HBACK;
	hback->chunk_header.chunk_length = htons(20 + ntohs(hback->hmaclen));
	hback->mtu = 1; // make it illegal hmac by changing mtu to non-zero
	mpath_hb_ack_received(hback);
	//then do nothing but just return
	mch_free_simple_chunk(hbid);
	reset();

	//3 when path id good hmac good path inactive
	path->state = PM_INACTIVE;
	mpath_->path_params[1].eff_pmtu = 1500;
	hbid = mch_make_hb_chunk(get_safe_time_ms() - 50, path->path_id, 1024);
	hback = (heartbeat_chunk_t*)mch_complete_simple_chunk(hbid);
	hback->chunk_header.chunk_id = CHUNK_HBACK;
	hback->chunk_header.chunk_length = htons(20 + ntohs(hback->hmaclen));
	mpath_hb_ack_received(hback);
	//then should update rtt pmtu, active path, readd timer
	ASSERT_EQ(path->state, PM_ACTIVE);
	ASSERT_EQ(path->hb_acked, true);
	ASSERT_EQ(path->hb_timer_id->callback.arg3, nullptr);
	ASSERT_GT(path->cached_eff_pmtu_start_time, 0);
	ASSERT_EQ(path->eff_pmtu, 1024);
	ASSERT_EQ(mpath_->min_pmtu, 1024);
	ASSERT_EQ(curr_channel_->bundle_control->curr_max_pdu,
		1024 - IP_HDR_SIZE - UDP_HDR_SIZE);
	ASSERT_EQ(curr_channel_->flow_control->cparams->mtu, 1024 - IP_HDR_SIZE - 12);
	mch_free_simple_chunk(hbid);
	reset();
}

//在一个二维数组中，每一行都按照从左到右递增的顺序排序，
//每一列都按照从上到下递增的顺序排序。
//请完成一个函数，输入这样的一个二维数组和一个整数，
//判断数组中是否含有该整数
#include <vector>
static bool alg0_find(int target, std::vector<std::vector<int>>& array);
TEST_F(mpath, test_alg0)
{
	int a[][2] = { {1,2},{3,4} };
	//int** pp = a; //cannot compile
	//int* p = a; //cannot compile
	//int (*ptr)[2]=a -> addr of [first array -> addr of first ele (int)] => int**
	//so int (*ptr)[2] should equvient to int** ptr
	//but int** pp = a will not cannot compile as they are different types
	// but you can dereference int** ptr to get any ele value as array is  memory block
	int* first_array_ptr = a[0];
	int(*ptr)[2] = a;
	int** a_ptr = (int**)a; // **a_ptr is crshing
	// ptr val = 4, sizeof = 8
	printf("ptr val = %d, val = %d,,sizeof = %zu\n", (*ptr)[3], first_array_ptr[2], sizeof(ptr));
	std::vector<std::vector<int>> arrary =
	{
	  { 0, 1, 3, 4, 5, 7, 8, 11, 13, 15, 18, 21, 24, 27, 30 },
	  { 1, 4, 6, 8, 11, 12, 15, 17, 18, 20, 23, 24, 27, 30 },
	  { 4, 7, 8, 11, 14, 16, 18, 20, 21, 24, 27, 29, 32, 35, 89, 91, 93, 96 },
	  { 5, 8, 10, 13, 15, 19, 21, 23, 24, 27, 29, 31 },
	  { 6, 11, 14, 16, 18, 22, 24, 27, 29, 32, 33, 35,  94, 97, 99, 101, 102 },
	  { 9, 13, 16, 19, 21, 23, 25, 29, 31, 35, 38, 39, 42, 45, 48, 51, 54, 56 }
	};

	bool find = alg0_find(22, arrary);
	ASSERT_TRUE(find);
}

bool alg0_find(int target, std::vector<std::vector<int>>& array)
{
	if (array.empty())
		return false;
	int row = 0, col = 0, rows = array.size();
	for (; row < rows; row++)
	{
		if(array[row].empty())
			continue;
		int cols = array[row].size();
		int max = array[row][cols - 1];
		int min = array[row][0];
		if (target == min || target == max)
			return true;
		if (target < min)
			return false;
		if (target > max)
			continue;
		if (array[row][col] == target)
			return true;
		if (array[row][col] > target)
		{
			col = 0;
			cols--;
		}
		else
			col++;

		for (; col < cols; col++)
		{
			int v = array[row][col];
			if (v == target)
				return true;
			if (target > v)
				continue;
			if (target < v)
			{
				col--;
				break;
			}
		}
	}
	return false;
}