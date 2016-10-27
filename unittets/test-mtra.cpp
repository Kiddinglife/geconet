#include "gtest/gtest.h"
#include "gmock/gmock.h"
// @caution because geco-ds-malloc includes geco-thread.h that includes window.h but transport_layer.h includes wsock2.h, as we know, it must include before windows.h so if you uncomment this line, will cause error
//#include "geco-ds-malloc.h"
#include "transport_layer.h"
#include "geco-ds-malloc.h"
#include "geco-malloc.h"
using namespace geco::ds;

#ifdef _WIN32
#define mysleep Sleep
#else
#define mysleep sleep
#endif

extern timer_mgr mtra_timer_mgr_;
extern int mtra_icmp_socket_despt_; /* socket fd for ICMP messages */
extern int socket_despts_size_;
extern socket_despt_t socket_despts[MAX_FD_SIZE];
extern event_handler_t event_callbacks[MAX_FD_SIZE];

extern void mtra_set_expected_event_on_fd(int fd_index, int sfd, int event_mask);
extern void mtra_set_expected_event_on_fd(int sfd, int eventcb_type,
	int event_mask, cbunion_t action, void* userData);
extern void mtra_add_stdin_cb(stdin_data_t::stdin_cb_func_t stdincb);
extern int mtra_poll(void(*lock)(void* data), void(*unlock)(void* data), void* data);
extern int mtra_remove_stdin_cb();
extern int mtra_remove_event_handler(int sfd);
extern int mtra_read_ip4_socket();
extern int mtra_read_ip6_socket();
extern int mtra_read_icmp_socket();
extern int mtra_init(int * myRwnd);

struct alloc_t
{
	void* ptr;
	size_t allocsize;
};

TEST(test_case_logging, test_read_trace_levels)
{
	read_trace_levels();
}

static bool
action(timer_id_t& id, void*, void*)
{
	EVENTLOG(VERBOSE, "timer triggered\n");
	return NOT_RESET_TIMER_FROM_CB;
}

TEST(TIMER_MODULE, test_timer_mgr)
{
	timer_mgr tm;
	timer_id_t ret1 = tm.add_timer(TIMER_TYPE_INIT, 1000, action);
	timer_id_t ret3 = tm.add_timer(TIMER_TYPE_SACK, 15, action);
	timer_id_t ret2 = tm.add_timer(TIMER_TYPE_SACK, 1, action);
	tm.print(VERBOSE);

	mysleep(20);
	EVENTLOG1(VERBOSE, "timeouts %d", tm.timeouts());
	tm.delete_timer(ret3);
	tm.delete_timer(ret2);
	tm.delete_timer(ret1);
	EVENTLOG1(VERBOSE, "timeouts %d", tm.timeouts());

	tm.print(VERBOSE);
}
TEST(TIMER_MODULE, test_operations_on_time)
{
	timeval tv;
	fills_timeval(&tv, 1000);
	EXPECT_TRUE(tv.tv_sec == 1);
	EXPECT_TRUE(tv.tv_usec == 0);

	timeval result;
	sum_time(&tv, (time_t)200, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 1);
	EXPECT_TRUE(result.tv_usec == 200000);

	sum_time(&result, (time_t)0, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 1);
	EXPECT_TRUE(result.tv_usec == 200000);

	sum_time(&result, (time_t)1, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 1);
	EXPECT_TRUE(result.tv_usec == 201000);

	sum_time(&result, (time_t)1000, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 2);
	EXPECT_TRUE(result.tv_usec == 201000);

	sum_time(&result, (time_t)800, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 3);
	EXPECT_TRUE(result.tv_usec == 1000);

	subtract_time(&result, (time_t)800, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 2);
	EXPECT_TRUE(result.tv_usec == 201000);

	subtract_time(&result, (time_t)201, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 2);
	EXPECT_TRUE(result.tv_usec == 0);

	subtract_time(&result, (time_t)0, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 2);
	EXPECT_TRUE(result.tv_usec == 0);

	subtract_time(&result, 2000, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 0);
	EXPECT_TRUE(result.tv_usec == 0);
}
// last run on 21 Agu 2016 and passed
TEST(GLOBAL_MODULE, test_saddr_str)
{
	sockaddrunion saddr;
	str2saddr(&saddr, "192.168.1.107", 38000);

	char ret[MAX_IPADDR_STR_LEN];
	ushort port = 0;
	saddr2str(&saddr, ret, sizeof(ret), &port);
	EVENTLOG1(VERBOSE, "saddr {%s}\n", ret);
	EXPECT_EQ(saddr.sa.sa_family, AF_INET);
	EXPECT_EQ(strcmp(ret, "192.168.1.107"), 0);
	EXPECT_EQ(port, 38000);

	sockaddrunion saddr1;
	str2saddr(&saddr1, "192.168.1.107", 38000);
	sockaddrunion saddr2;
	str2saddr(&saddr2, "192.168.1.107", 38000);
	EXPECT_EQ(saddr_equals(&saddr1, &saddr2), true);

	str2saddr(&saddr1, "192.167.1.125", 38000);
	str2saddr(&saddr2, "192.168.1.107", 38000);
	EXPECT_EQ(saddr_equals(&saddr1, &saddr2), false);

	str2saddr(&saddr1, "192.168.1.107", 3800);
	str2saddr(&saddr2, "192.168.1.107", 38000);
	EXPECT_EQ(saddr_equals(&saddr1, &saddr2), false);

	str2saddr(&saddr1, "192.168.1.125", 3800);
	str2saddr(&saddr2, "192.168.1.107", 38000);
	EXPECT_EQ(saddr_equals(&saddr1, &saddr2), false);
}

// last run on 27 Agu 2016 and passed
TEST(MALLOC_MODULE, test_geco_new_delete)
{
	int j;
	int total = 1000000;
	/*max is 5120 we use 5121 to have the max*/
	size_t allocsize;
	size_t dealloc_idx;
	std::list<alloc_t*> allos;
	std::list<alloc_t*>::iterator it;

	int alloccnt = 0;
	int deallcnt = 0;
	alloc_t* at;
	for (j = 0; j < total; j++)
	{
		if (rand() % 2)
		{

			uint s = ((rand() * UINT32_MAX) % 1024) + 1;
			at = geco_new_array<alloc_t>(s, __FILE__, __LINE__);
			at->allocsize = s;
			allos.push_back(at);
			alloccnt += s;
		}
		else
		{
			size_t s = allos.size();
			if (s > 0)
			{
				dealloc_idx = (rand() % s);
				it = allos.begin();
				std::advance(it, dealloc_idx);
				deallcnt += (*it)->allocsize;
				geco_delete_array<alloc_t>(*it, __FILE__, __LINE__);
				allos.erase(it);
			}
		}
	}
	for (auto& p : allos)
	{
		deallcnt += p->allocsize;
		geco_delete_array<alloc_t>(p, __FILE__, __LINE__);
	}
	allos.clear();
	EXPECT_EQ(alloccnt, deallcnt);
	EXPECT_EQ(allos.size(), 0);
}
TEST(MALLOC_MODULE, test_geco_alloc_dealloc)
{
	int j;
	int total = 1000000;
	/*max is 5120 we use 5121 to have the max*/
	size_t allocsize;
	size_t dealloc_idx;
	std::list<alloc_t> allos;
	std::list<alloc_t>::iterator it;

	int alloccnt = 0;
	int deallcnt = 0;
	int less_than_max_byte_cnt = 0;
	int zero_alloc_cnt = 0;
	alloc_t at;
	for (j = 0; j < total; j++)
	{
		if (rand() % 2)
		{
			allocsize = (rand() * UINT32_MAX) % 2049;
			if (allocsize <= 1512)
				++less_than_max_byte_cnt;
			if (allocsize == 0)
				++zero_alloc_cnt;
			at.ptr = geco_malloc_ext(allocsize, __FILE__, __LINE__);
			at.allocsize = allocsize;
			allos.push_back(at);
			alloccnt++;
		}
		else
		{
			size_t s = allos.size();
			if (s > 0)
			{
				dealloc_idx = rand() % s;
				it = allos.begin();
				std::advance(it, dealloc_idx);
				geco_free_ext(it->ptr, __FILE__, __LINE__);
				allos.erase(it);
				deallcnt++;
			}
		}
	}
	for (auto& p : allos)
	{
		geco_free_ext(p.ptr, __FILE__, __LINE__);
		deallcnt++;
	}
	allos.clear();
	EXPECT_EQ(alloccnt, deallcnt);
	EXPECT_EQ(allos.size(), 0);
	EVENTLOG5(VERBOSE,
		"alloccnt %d, dealloccnt %d, < 1512 cnt %d, %d, zer alloc cnt %d\n",
		alloccnt, deallcnt, less_than_max_byte_cnt,
		alloccnt - less_than_max_byte_cnt, zero_alloc_cnt);
}
// last run on 21 Agu 2016 and passed
TEST(MALLOC_MODULE, test_alloc_dealloc)
{
	single_client_alloc allocator;
	int j;
	int total = 1000000;
	/*max is 5120 we use 5121 to have the max*/
	size_t allocsize;
	size_t dealloc_idx;
	std::list<alloc_t> allos;
	std::list<alloc_t>::iterator it;

	int alloccnt = 0;
	int deallcnt = 0;
	int less_than_max_byte_cnt = 0;
	int zero_alloc_cnt = 0;
	alloc_t at;
	for (j = 0; j < total; j++)
	{
		if (rand() % 2)
		{
			allocsize = (rand() * UINT32_MAX) % 2049;
			if (allocsize <= 1512)
				++less_than_max_byte_cnt;
			if (allocsize == 0)
				++zero_alloc_cnt;
			at.ptr = allocator.allocate(allocsize);
			at.allocsize = allocsize;
			allos.push_back(at);
			alloccnt++;
		}
		else
		{
			size_t s = allos.size();
			if (s > 0)
			{
				dealloc_idx = rand() % s;
				it = allos.begin();
				std::advance(it, dealloc_idx);
				allocator.deallocate(it->ptr, it->allocsize);
				allos.erase(it);
				deallcnt++;
			}
		}
	}
	for (auto& p : allos)
	{
		allocator.deallocate(p.ptr, p.allocsize);
		deallcnt++;
	}
	allos.clear();
	allocator.destroy();
	EXPECT_EQ(alloccnt, deallcnt);
	EXPECT_EQ(allos.size(), 0);
	EVENTLOG5(VERBOSE,
		"alloccnt %d, dealloccnt %d, < 1512 cnt %d, %d, zer alloc cnt %d\n",
		alloccnt, deallcnt, less_than_max_byte_cnt,
		alloccnt - less_than_max_byte_cnt, zero_alloc_cnt);
}

// last pass on 26 Oct 2016
TEST(AUTH_MODULE, test_md5)
{
	unsigned char digest[HMAC_LEN];
	MD5_CTX ctx;

	const char* testdata = "202cb962ac59075b964b07152d234b70";
	const char* result = "d9b1d7db4cd6e70935368a1efb10e377";
	MD5Init(&ctx);
	MD5Update(&ctx, (uchar*)testdata, strlen(testdata));
	MD5Final(digest, &ctx);
	EVENTLOG1(VERBOSE, "Computed MD5 signature : %s",
		hexdigest(digest, HMAC_LEN));
	EXPECT_STREQ(hexdigest(digest, 16), result);

	testdata = "d9b1d7db4cd6e70935368a1efb10e377";
	result = "7363a0d0604902af7b70b271a0b96480";
	MD5Init(&ctx);
	MD5Update(&ctx, (uchar*)testdata, strlen(testdata));
	MD5Final(digest, &ctx);
	EVENTLOG1(VERBOSE, "Computed MD5 signature : %s",
		hexdigest(digest, HMAC_LEN));
	EXPECT_STREQ(hexdigest(digest, 16), result);
}
TEST(AUTH_MODULE, test_sockaddr2hashcode)
{
	uint ret;
	sockaddrunion localsu;
	str2saddr(&localsu, "192.168.1.107", 36000);
	sockaddrunion peersu;
	str2saddr(&peersu, "192.168.1.107", 36000);
	ret = transportaddr2hashcode(&localsu, &peersu);
	EVENTLOG2(
		VERBOSE,
		"hash(addr pair { localsu: 192.168.1.107:36001 peersu: 192.168.1.107:36000 }) = %u, %u",
		ret, ret % 100000);

	str2saddr(&localsu, "192.168.1.107", 1234);
	str2saddr(&peersu, "192.168.1.107", 360);
	ret = transportaddr2hashcode(&localsu, &peersu);
	EVENTLOG2(
		VERBOSE,
		"hash(addr pair { localsu: 192.168.1.107:36001 peersu: 192.168.1.107:36000 }) = %u, %u",
		ret, ret % 100000);
}
TEST(AUTH_MODULE, test_crc32_checksum)
{
	for (int ii = 0; ii < 100; ii++)
	{
		geco_packet_t geco_packet;
		geco_packet.pk_comm_hdr.checksum = 0;
		geco_packet.pk_comm_hdr.dest_port = htons(
			(generate_random_uint32() % USHRT_MAX));
		geco_packet.pk_comm_hdr.src_port = htons(
			(generate_random_uint32() % USHRT_MAX));
		geco_packet.pk_comm_hdr.verification_tag = htons(
			(generate_random_uint32()));
		((chunk_fixed_t*)geco_packet.chunk)->chunk_id = CHUNK_DATA;
		((chunk_fixed_t*)geco_packet.chunk)->chunk_length = htons(100);
		((chunk_fixed_t*)geco_packet.chunk)->chunk_flags =
			DCHUNK_FLAG_UNORDER | DCHUNK_FLAG_FL_FRG;
		for (int i = 0; i < 100; i++)
		{
			uchar* wt = geco_packet.chunk + CHUNK_FIXED_SIZE;
			wt[i] = generate_random_uint32() % UCHAR_MAX;
		}
		set_crc32_checksum((char*)&geco_packet, DATA_CHUNK_FIXED_SIZES + 100);
		bool ret = validate_crc32_checksum((char*)&geco_packet,
			DATA_CHUNK_FIXED_SIZES + 100);
		EXPECT_TRUE(ret);
	}
}


static bool flag = true;
static timer_id_t tid;
static void
process_stdin(char* data, size_t datalen)
{
	EVENTLOG2(DEBUG, "process_stdin()::%d bytes : %s", datalen, data);

	if (strcmp(data, "q") == 0)
	{
		flag = false;
		return;
	}

	mtra_timer_mgr_.reset_timer(tid, 1000000);

	sockaddrunion saddr;
	str2saddr(&saddr, "::1", USED_UDP_PORT);
	uchar tos = IPTOS_DEFAULT;
	int sentsize;

	sentsize = mtra_send_ip_packet(mtra_read_ip6_socket(), data, datalen, &saddr, tos);
	assert(sentsize == datalen);

	str2saddr(&saddr, "127.0.0.1", USED_UDP_PORT);
	sentsize = mtra_send_ip_packet(mtra_read_ip4_socket(), data, datalen, &saddr, tos);
	assert(sentsize == datalen);
}
static void
socket_cb(int sfd, char* data, int datalen, const char* addr, ushort port)
{
	EVENTLOG4(DEBUG, "socket_cb(ip%d fd=%d)::%d bytes : %s", mtra_read_ip4_socket() == sfd ? 4 : 6, sfd, datalen, data);
}
static bool
timer_cb(timer_id_t& tid, void* a1, void* a2)
{
	EVENTLOG2(DEBUG, "timeouts, BYE!", tid->timer_id, tid->timer_type);
	flag = false;
	return true;
}

TEST(TRANSPORT_MODULE, test_process_stdin)
{
	int rcwnd = 512;
	mtra_init(&rcwnd);
	cbunion_t cbunion;
	cbunion.socket_cb_fun = socket_cb;
	mtra_set_expected_event_on_fd(mtra_read_ip4_socket(),
		EVENTCB_TYPE_SCTP, POLLIN | POLLPRI, cbunion, 0);
	mtra_set_expected_event_on_fd(mtra_read_ip6_socket(),
		EVENTCB_TYPE_SCTP, POLLIN | POLLPRI, cbunion, 0);
	// you have to put stdin as last because we test it
	mtra_add_stdin_cb(process_stdin);
	tid = mtra_timer_mgr_.add_timer(TIMER_TYPE_INIT, 30000, timer_cb, 0, 0);
	while (flag) mtra_poll(0, 0, 0);
	mtra_destroy();
}
static void
fd_action_sctp(int sfd, char* data, int datalen, const char* addr, ushort port)
{
}
static void
fd_action_udp(int sfd, char* data, int datalen, const char* addr, ushort port)
{
}
static void
fd_action_rounting(int sfd, char* data, int datalen, const char* addr,
	ushort port)
{
}
TEST(TRANSPORT_MODULE, test_add_remove_fd)
{
	// !!! comment wsaselect() in poller::set_event_on_win32_sdespt()
	// if you run this unit test
	cbunion_t cbunion_;
	cbunion_.socket_cb_fun = fd_action_sctp;
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, cbunion_, (void*)1);
	cbunion_.socket_cb_fun = fd_action_udp;
	mtra_set_expected_event_on_fd(2, EVENTCB_TYPE_UDP, POLLIN, cbunion_, (void*)2);
	cbunion_.socket_cb_fun = fd_action_rounting;
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN, cbunion_, (void*)1);

	int size = mtra_remove_event_handler(1);
	assert(size == 2);
	size = mtra_remove_event_handler(200);
	assert(size == 0);
	size = mtra_remove_event_handler(200);
	assert(size == 0);
	size = mtra_remove_event_handler(2);
	assert(size == 1);
	assert(socket_despts_size_ == 0);
	cbunion_.socket_cb_fun = fd_action_rounting;
	mtra_set_expected_event_on_fd(3, EVENTCB_TYPE_ROUTING, POLLIN,
		cbunion_, (void*)1);
	assert(socket_despts_size_ == 1);
	assert(
		socket_despts[socket_despts_size_].event_handler_index
		== 0);
	assert(
		event_callbacks[socket_despts[socket_despts_size_].event_handler_index].action.socket_cb_fun
		== fd_action_rounting);

	size = mtra_remove_event_handler(3);
	assert(size == 1);
	assert(socket_despts_size_ == 0);

	size = mtra_remove_event_handler(200);
	assert(size == 0);
	assert(socket_despts_size_ == 0);
	for (int i = 0; i < MAX_FD_SIZE; i++)
	{
		assert(socket_despts[i].fd == -1);
	}

	memset(&cbunion_, 0, sizeof(cbunion_t));
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_UDP, POLLIN, cbunion_,
		(void*)2);
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN,
		cbunion_, (void*)1);
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN,
		cbunion_, (void*)1);
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN,
		cbunion_, (void*)1);
	size = mtra_remove_event_handler(1);
	assert(size == 5);
	assert(socket_despts_size_ == 0);

	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	size = mtra_remove_event_handler(1);
	assert(size == 1);
	assert(socket_despts_size_ == 0);

	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	size = mtra_remove_event_handler(1);
	assert(size == 2);
	assert(socket_despts_size_ == 0);

	mtra_set_expected_event_on_fd(2, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	size = mtra_remove_event_handler(1);
	assert(size == 2);
	assert(socket_despts_size_ == 1);
	assert(
		event_callbacks[socket_despts[0].event_handler_index].action.socket_cb_fun
		== fd_action_sctp);
	assert(
		event_callbacks[socket_despts[0].event_handler_index].sfd
		== 2);

	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	mtra_set_expected_event_on_fd(2, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	mtra_set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	mtra_set_expected_event_on_fd(2, EVENTCB_TYPE_SCTP, POLLIN,
		cbunion_, (void*)1);
	size = mtra_remove_event_handler(1);
	assert(size == 2);
	assert(socket_despts_size_ == 3);
	assert(
		event_callbacks[socket_despts[0].event_handler_index].action.socket_cb_fun
		== fd_action_sctp);
	assert(
		event_callbacks[socket_despts[1].event_handler_index].action.socket_cb_fun
		== fd_action_sctp);
	printf("ALl Done\n");
}

TEST(TEST_SWITCH, SWITCH)
{
	int a = 6;
	switch (a)
	{
	case 1:
		EVENTLOG(VERBOSE, "1");
	case 4:
	case 5:
	case 6:
		EVENTLOG(VERBOSE, "6");
		break;
	case 7:
		EVENTLOG(VERBOSE, "2");
		break;
	default:
		break;
	}
}

