#include "gtest/gtest.h"
#include "gmock/gmock.h"
// @caution because geco-ds-malloc includes geco-thread.h that includes window.h but transport_layer.h includes wsock2.h, as we know, it must include before windows.h so if you uncomment this line, will cause error
//#include "geco-ds-malloc.h"
#include "transport_layer.h"
#include "dispatch_layer.h"
#include "geco-ds-malloc.h"
#include "geco-malloc.h"
using namespace geco::ds;

struct alloc_t
{
	void* ptr;
	size_t allocsize;
};

TEST(test_case_logging, test_read_trace_levels)
{
	read_trace_levels();
}

static bool action(timer_id_t& id, void*, void*)
{
	EVENTLOG(VERBOSE, "timer triggered\n");
	return NOT_RESET_TIMER_FROM_CB;
}
TEST(TIMER_MODULE, test_timer_mgr)
{
	timer_mgr tm;
	timer_id_t ret1 = tm.add_timer(TIMER_TYPE_INIT, 1000, action);
	timer_id_t ret2 = tm.add_timer(TIMER_TYPE_SACK, 1, action);
	timer_id_t ret3 = tm.add_timer(TIMER_TYPE_SACK, 15, action);
	tm.print(VERBOSE);
	tm.delete_timer(ret1);
	tm.delete_timer(ret2);
	tm.print(VERBOSE);
}
TEST(TIMER_MODULE, test_operations_on_time)
{
	timeval tv;
	fills_timeval(&tv, 1000);
	EXPECT_TRUE(tv.tv_sec == 1);
	EXPECT_TRUE(tv.tv_usec == 0);

	timeval result;
	sum_time(&tv, (time_t) 200, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 1);
	EXPECT_TRUE(result.tv_usec == 200000);

	sum_time(&result, (time_t) 0, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 1);
	EXPECT_TRUE(result.tv_usec == 200000);

	sum_time(&result, (time_t) 1, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 1);
	EXPECT_TRUE(result.tv_usec == 201000);

	sum_time(&result, (time_t) 1000, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 2);
	EXPECT_TRUE(result.tv_usec == 201000);

	sum_time(&result, (time_t) 800, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 3);
	EXPECT_TRUE(result.tv_usec == 1000);

	subtract_time(&result, (time_t) 800, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 2);
	EXPECT_TRUE(result.tv_usec == 201000);

	subtract_time(&result, (time_t) 201, &result);
	//print_timeval(&result);
	EXPECT_TRUE(result.tv_sec == 2);
	EXPECT_TRUE(result.tv_usec == 0);

	subtract_time(&result, (time_t) 0, &result);
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
// last run on 21 Agu 2016 and passed
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

// AUTH_MODULE.* -> last run on 21 Agu 2016 and all passed
TEST(AUTH_MODULE, test_md5)
{
	unsigned char digest[HMAC_LEN];
	MD5_CTX ctx;

	const char* testdata = "202cb962ac59075b964b07152d234b70";
	const char* result = "d9b1d7db4cd6e70935368a1efb10e377";
	MD5Init(&ctx);
	MD5Update(&ctx, (uchar*) testdata, strlen(testdata));
	MD5Final(digest, &ctx);
	EVENTLOG1(VERBOSE, "Computed MD5 signature : %s",
			hexdigest(digest, HMAC_LEN));
	EXPECT_STREQ(hexdigest(digest, 16), result);

	testdata = "d9b1d7db4cd6e70935368a1efb10e377";
	result = "7363a0d0604902af7b70b271a0b96480";
	MD5Init(&ctx);
	MD5Update(&ctx, (uchar*) testdata, strlen(testdata));
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
	EVENTLOG2(VERBOSE,
			"hash(addr pair { localsu: 192.168.1.107:36001 peersu: 192.168.1.107:36000 }) = %u, %u",
			ret, ret % 100000);

	str2saddr(&localsu, "192.168.1.107", 1234);
	str2saddr(&peersu, "192.168.1.107", 360);
	ret = transportaddr2hashcode(&localsu, &peersu);
	EVENTLOG2(VERBOSE,
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
		((chunk_fixed_t*) geco_packet.chunk)->chunk_id = CHUNK_DATA;
		((chunk_fixed_t*) geco_packet.chunk)->chunk_length = htons(100);
		((chunk_fixed_t*) geco_packet.chunk)->chunk_flags =
		DCHUNK_FLAG_UNORDER | DCHUNK_FLAG_FL_FRG;
		for (int i = 0; i < 100; i++)
		{
			uchar* wt = geco_packet.chunk + CHUNK_FIXED_SIZE;
			wt[i] = generate_random_uint32() % UCHAR_MAX;
		}
		set_crc32_checksum((char*) &geco_packet, DATA_CHUNK_FIXED_SIZES + 100);
		bool ret = validate_crc32_checksum((char*) &geco_packet,
		DATA_CHUNK_FIXED_SIZES + 100);
		EXPECT_TRUE(ret);
	}
}

#include "transport_layer.h"
TEST(TRANSPORT_MODULE, test_get_local_addr)
{
	int rcwnd = 512;
	network_interface_t nit;
	nit.init(&rcwnd, true);

	sockaddrunion* saddr = 0;
	int num = 0;
	int maxmtu = 0;
	ushort port = 0;
	char addr[MAX_IPADDR_STR_LEN];
	IPAddrType t = (IPAddrType) (AllLocalAddrTypes | AllCastAddrTypes);
	nit.get_local_addresses(&saddr, &num, nit.ip4_socket_despt_, true, &maxmtu,
			t);

	EVENTLOG1(VERBOSE, "max mtu  %d\n", maxmtu);

	if (saddr != NULL)
		for (int i = 0; i < num; i++)
		{
			saddr2str(saddr + i, addr, MAX_IPADDR_STR_LEN, &port);
			EVENTLOG2(VERBOSE, "ip address %s port %d\n", addr, port);
		}
}

static network_interface_t nit;
static bool flag = true;
static void process_stdin(char* data, size_t datalen)
{
	EVENTLOG2(VERBOSE,
			"process_stdin()::recvied %d bytes of %s data  from stdin", datalen,
			data);

	if (strcmp(data, "q") == 0)
	{
		flag = false;
		return;
	}

	sockaddrunion saddr;
	str2saddr(&saddr, "127.0.0.1", USED_UDP_PORT);
	int sampledata = 27;
	uchar tos = IPTOS_DEFAULT;
	int sentsize = nit.send_ip_packet(nit.ip4_socket_despt_, data, datalen,
			&saddr, tos);
	assert(sentsize == datalen);
}
static void socket_cb(int sfd, char* data, int datalen, const char* addr,
		ushort port)
{
	EVENTLOG3(VERBOSE,
			"socket_cb()::recvied  %d bytes of data %s from dctp fd %d\n",
			datalen, data, sfd);
}
static int timercb_cnt = 0;
static bool timer_cb(timer_id_t& tid, void* a1, void* a2)
{
	EVENTLOG2(VERBOSE, "timer_cb(id %d, type->%d)::\n", tid->timer_id,
			tid->timer_type);
	if (timercb_cnt < 5)
		nit.restart_timer(tid, 10000);
	else
		flag = false;
	timercb_cnt++;
	return true;
}
TEST(TRANSPORT_MODULE, test_process_stdin)
{
	int rcwnd = 512;
	nit.init(&rcwnd, true);

	nit.cbunion_.socket_cb_fun = socket_cb;
	nit.poller_.set_expected_event_on_fd(nit.ip4_socket_despt_,
	EVENTCB_TYPE_SCTP, POLLIN | POLLPRI, nit.cbunion_, 0);
	// you have to put stdin as last because we test it
	nit.poller_.add_stdin_cb(process_stdin);
	nit.start_timer(10000, timer_cb, TIMER_TYPE_INIT, 0, 0);
	while (flag)
		nit.poller_.poll();
	nit.poller_.timer_mgr_.timers.clear();
	nit.poller_.remove_stdin_cb();
	nit.poller_.remove_event_handler(nit.ip4_socket_despt_);
}
static void fd_action_sctp(int sfd, char* data, int datalen, const char* addr,
		ushort port)
{
}
static void fd_action_udp(int sfd, char* data, int datalen, const char* addr,
		ushort port)
{
}
static void fd_action_rounting(int sfd, char* data, int datalen,
		const char* addr, ushort port)
{
}
TEST(TRANSPORT_MODULE, test_add_remove_fd)
{
	// !!! comment wsaselect() in poller::set_event_on_win32_sdespt()
	// if you run this unit test
	selector poller;
	poller.cbunion_.socket_cb_fun = fd_action_sctp;
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.cbunion_.socket_cb_fun = fd_action_udp;
	poller.set_expected_event_on_fd(2, EVENTCB_TYPE_UDP, POLLIN,
			poller.cbunion_, (void*) 2);
	poller.cbunion_.socket_cb_fun = fd_action_rounting;
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN,
			poller.cbunion_, (void*) 1);

	int size = poller.remove_event_handler(1);
	assert(size == 2);
	size = poller.remove_event_handler(200);
	assert(size == 0);
	size = poller.remove_event_handler(200);
	assert(size == 0);
	size = poller.remove_event_handler(2);
	assert(size == 1);
	assert(poller.socket_despts_size_ == 0);
	poller.cbunion_.socket_cb_fun = fd_action_rounting;
	poller.set_expected_event_on_fd(3, EVENTCB_TYPE_ROUTING, POLLIN,
			poller.cbunion_, (void*) 1);
	assert(poller.socket_despts_size_ == 1);
	assert(
			poller.socket_despts[poller.socket_despts_size_].event_handler_index
					== 0);
	assert(
			poller.event_callbacks[poller.socket_despts[poller.socket_despts_size_].event_handler_index].action.socket_cb_fun
					== fd_action_rounting);

	size = poller.remove_event_handler(3);
	assert(size == 1);
	assert(poller.socket_despts_size_ == 0);

	size = poller.remove_event_handler(200);
	assert(size == 0);
	assert(poller.socket_despts_size_ == 0);
	for (int i = 0; i < MAX_FD_SIZE; i++)
	{
		assert(poller.socket_despts[i].fd == -1);
	}

	memset(&poller.cbunion_, 0, sizeof(cbunion_t));
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_UDP, POLLIN,
			poller.cbunion_, (void*) 2);
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN,
			poller.cbunion_, (void*) 1);
	size = poller.remove_event_handler(1);
	assert(size == 5);
	assert(poller.socket_despts_size_ == 0);

	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	size = poller.remove_event_handler(1);
	assert(size == 1);
	assert(poller.socket_despts_size_ == 0);

	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	size = poller.remove_event_handler(1);
	assert(size == 2);
	assert(poller.socket_despts_size_ == 0);

	poller.set_expected_event_on_fd(2, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	size = poller.remove_event_handler(1);
	assert(size == 2);
	assert(poller.socket_despts_size_ == 1);
	assert(
			poller.event_callbacks[poller.socket_despts[0].event_handler_index].action.socket_cb_fun
					== fd_action_sctp);
	assert(
			poller.event_callbacks[poller.socket_despts[0].event_handler_index].sfd
					== 2);

	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.set_expected_event_on_fd(2, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	poller.set_expected_event_on_fd(2, EVENTCB_TYPE_SCTP, POLLIN,
			poller.cbunion_, (void*) 1);
	size = poller.remove_event_handler(1);
	assert(size == 2);
	assert(poller.socket_despts_size_ == 3);
	assert(
			poller.event_callbacks[poller.socket_despts[0].event_handler_index].action.socket_cb_fun
					== fd_action_sctp);
	assert(
			poller.event_callbacks[poller.socket_despts[1].event_handler_index].action.socket_cb_fun
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

