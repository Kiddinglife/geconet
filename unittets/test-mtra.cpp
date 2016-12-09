#include "gtest/gtest.h"
#include "gmock/gmock.h"
// @caution because geco-ds-malloc includes geco-thread.h that includes window.h but transport_layer.h includes wsock2.h, as we know, it must include before windows.h so if you uncomment this line, will cause error
//#include "geco-ds-malloc.h"
#include "geco-net-transport.h"
#include "geco-net-common.h"
#include "geco-ds-malloc.h"
#include "geco-malloc.h"
using namespace geco::ds;

#include "geco-net-config.h"
#include "geco-net.h"
//#include "timeout-debug.h"
#include "wheel-timer.h"

#ifdef _WIN32
#define mysleep Sleep
#else
#define mysleep sleep
#endif

extern timer_mgr mtra_timer_mgr_;
extern int mtra_icmp_rawsock_; /* socket fd for ICMP messages */
extern int socket_despts_size_;
extern socket_despt_t socket_despts[MAX_FD_SIZE];
extern event_handler_t event_callbacks[MAX_FD_SIZE];

extern void
mtra_set_expected_event_on_fd (int fd_index, int sfd, int event_mask);
extern void
mtra_set_expected_event_on_fd (int sfd, int eventcb_type, int event_mask,
                               cbunion_t action, void* userData);
extern void
mtra_add_stdin_cb (stdin_data_t::stdin_cb_func_t stdincb);
extern int
mtra_poll (int maxwait = -1);
extern int
mtra_remove_stdin_cb ();
extern int
mtra_remove_event_handler (int sfd);
extern int
mtra_read_ip4rawsock ();
extern int
mtra_read_ip6rawsock ();
extern int
mtra_read_icmp_socket ();
extern int
mtra_init (int * myRwnd);

struct alloc_t
{
    void* ptr;
    size_t allocsize;
};

TEST(test_case_logging, test_read_trace_levels)
{
  read_trace_levels ();
}

static bool
action (timer_id_t& id, void*, void*)
{
  EVENTLOG(VERBOSE, "timer triggered\n");
  return NOT_RESET_TIMER_FROM_CB;
}

TEST(TIMER_MODULE, test_timer_mgr)
{
  timer_mgr tm;
  timer_id_t ret1 = tm.add_timer (TIMER_TYPE_INIT, 1000, action);
  timer_id_t ret3 = tm.add_timer (TIMER_TYPE_SACK, 15, action);
  timer_id_t ret2 = tm.add_timer (TIMER_TYPE_SACK, 1, action);
  tm.print (VERBOSE);

  mysleep (20);
  EVENTLOG1(VERBOSE, "timeouts %d", tm.timeouts ());
  tm.delete_timer (ret3);
  tm.delete_timer (ret2);
  tm.delete_timer (ret1);
  EVENTLOG1(VERBOSE, "timeouts %d", tm.timeouts ());

  tm.print (VERBOSE);

  int err = 0;
  struct timeouts *tos = timeouts_open (0, &err);
}
TEST(TIMER_MODULE, test_operations_on_time)
{
  timeval tv;
  fills_timeval(&tv, 1000);
  EXPECT_TRUE(tv.tv_sec == 1);
  EXPECT_TRUE(tv.tv_usec == 0);

  timeval result;
  sum_time (&tv, (time_t) 200, &result);
  //print_timeval(&result);
  EXPECT_TRUE(result.tv_sec == 1);
  EXPECT_TRUE(result.tv_usec == 200000);

  sum_time (&result, (time_t) 0, &result);
  //print_timeval(&result);
  EXPECT_TRUE(result.tv_sec == 1);
  EXPECT_TRUE(result.tv_usec == 200000);

  sum_time (&result, (time_t) 1, &result);
  //print_timeval(&result);
  EXPECT_TRUE(result.tv_sec == 1);
  EXPECT_TRUE(result.tv_usec == 201000);

  sum_time (&result, (time_t) 1000, &result);
  //print_timeval(&result);
  EXPECT_TRUE(result.tv_sec == 2);
  EXPECT_TRUE(result.tv_usec == 201000);

  sum_time (&result, (time_t) 800, &result);
  //print_timeval(&result);
  EXPECT_TRUE(result.tv_sec == 3);
  EXPECT_TRUE(result.tv_usec == 1000);

  subtract_time (&result, (time_t) 800, &result);
  //print_timeval(&result);
  EXPECT_TRUE(result.tv_sec == 2);
  EXPECT_TRUE(result.tv_usec == 201000);

  subtract_time (&result, (time_t) 201, &result);
  //print_timeval(&result);
  EXPECT_TRUE(result.tv_sec == 2);
  EXPECT_TRUE(result.tv_usec == 0);

  subtract_time (&result, (time_t) 0, &result);
  //print_timeval(&result);
  EXPECT_TRUE(result.tv_sec == 2);
  EXPECT_TRUE(result.tv_usec == 0);

  subtract_time (&result, 2000, &result);
  //print_timeval(&result);
  EXPECT_TRUE(result.tv_sec == 0);
  EXPECT_TRUE(result.tv_usec == 0);
}
// last run on 21 Agu 2016 and passed
TEST(GLOBAL_MODULE, test_saddr_str)
{
  sockaddrunion saddr;
  str2saddr (&saddr, "192.168.1.107", 38000);

  char ret[MAX_IPADDR_STR_LEN];
  ushort port = 0;
  saddr2str (&saddr, ret, sizeof(ret), &port);
  EVENTLOG1(VERBOSE, "saddr {%s}\n", ret);
  EXPECT_EQ(saddr.sa.sa_family, AF_INET);
  EXPECT_EQ(strcmp (ret, "192.168.1.107"), 0);
  EXPECT_EQ(port, 38000);

  sockaddrunion saddr1;
  str2saddr (&saddr1, "192.168.1.107", 38000);
  sockaddrunion saddr2;
  str2saddr (&saddr2, "192.168.1.107", 38000);
  EXPECT_EQ(saddr_equals (&saddr1, &saddr2), true);

  str2saddr (&saddr1, "192.167.1.125", 38000);
  str2saddr (&saddr2, "192.168.1.107", 38000);
  EXPECT_EQ(saddr_equals (&saddr1, &saddr2), false);

  str2saddr (&saddr1, "192.168.1.107", 3800);
  str2saddr (&saddr2, "192.168.1.107", 38000);
  EXPECT_EQ(saddr_equals (&saddr1, &saddr2), false);

  str2saddr (&saddr1, "192.168.1.125", 3800);
  str2saddr (&saddr2, "192.168.1.107", 38000);
  EXPECT_EQ(saddr_equals (&saddr1, &saddr2), false);
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
    if (rand () % 2)
    {

      uint s = ((rand () * UINT32_MAX) % 1024) + 1;
      at = geco_new_array<alloc_t> (s, __FILE__, __LINE__);
      at->allocsize = s;
      allos.push_back (at);
      alloccnt += s;
    }
    else
    {
      size_t s = allos.size ();
      if (s > 0)
      {
        dealloc_idx = (rand () % s);
        it = allos.begin ();
        std::advance (it, dealloc_idx);
        deallcnt += (*it)->allocsize;
        geco_delete_array<alloc_t> (*it, __FILE__, __LINE__);
        allos.erase (it);
      }
    }
  }
  for (auto& p : allos)
  {
    deallcnt += p->allocsize;
    geco_delete_array<alloc_t> (p, __FILE__, __LINE__);
  }
  allos.clear ();
  EXPECT_EQ(alloccnt, deallcnt);
  EXPECT_EQ(allos.size (), 0);
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
    if (rand () % 2)
    {
      allocsize = (rand () * UINT32_MAX) % 2049;
      if (allocsize <= 1512)
        ++less_than_max_byte_cnt;
      if (allocsize == 0)
        ++zero_alloc_cnt;
      at.ptr = geco_malloc_ext (allocsize, __FILE__, __LINE__);
      at.allocsize = allocsize;
      allos.push_back (at);
      alloccnt++;
    }
    else
    {
      size_t s = allos.size ();
      if (s > 0)
      {
        dealloc_idx = rand () % s;
        it = allos.begin ();
        std::advance (it, dealloc_idx);
        geco_free_ext (it->ptr, __FILE__, __LINE__);
        allos.erase (it);
        deallcnt++;
      }
    }
  }
  for (auto& p : allos)
  {
    geco_free_ext (p.ptr, __FILE__, __LINE__);
    deallcnt++;
  }
  allos.clear ();
  EXPECT_EQ(alloccnt, deallcnt);
  EXPECT_EQ(allos.size (), 0);
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
    if (rand () % 2)
    {
      allocsize = (rand () * UINT32_MAX) % 2049;
      if (allocsize <= 1512)
        ++less_than_max_byte_cnt;
      if (allocsize == 0)
        ++zero_alloc_cnt;
      at.ptr = allocator.allocate (allocsize);
      at.allocsize = allocsize;
      allos.push_back (at);
      alloccnt++;
    }
    else
    {
      size_t s = allos.size ();
      if (s > 0)
      {
        dealloc_idx = rand () % s;
        it = allos.begin ();
        std::advance (it, dealloc_idx);
        allocator.deallocate (it->ptr, it->allocsize);
        allos.erase (it);
        deallcnt++;
      }
    }
  }
  for (auto& p : allos)
  {
    allocator.deallocate (p.ptr, p.allocsize);
    deallcnt++;
  }
  allos.clear ();
  allocator.destroy ();
  EXPECT_EQ(alloccnt, deallcnt);
  EXPECT_EQ(allos.size (), 0);
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
  MD5Init (&ctx);
  MD5Update (&ctx, (uchar*) testdata, strlen (testdata));
  MD5Final (digest, &ctx);
  EVENTLOG1(VERBOSE, "Computed MD5 signature : %s",
            hexdigest(digest, HMAC_LEN));
  EXPECT_STREQ(hexdigest (digest, 16), result);

  testdata = "d9b1d7db4cd6e70935368a1efb10e377";
  result = "7363a0d0604902af7b70b271a0b96480";
  MD5Init (&ctx);
  MD5Update (&ctx, (uchar*) testdata, strlen (testdata));
  MD5Final (digest, &ctx);
  EVENTLOG1(VERBOSE, "Computed MD5 signature : %s",
            hexdigest(digest, HMAC_LEN));
  EXPECT_STREQ(hexdigest (digest, 16), result);
}
TEST(AUTH_MODULE, test_sockaddr2hashcode)
{
  uint ret;
  sockaddrunion localsu;
  str2saddr (&localsu, "192.168.1.107", 36000);
  sockaddrunion peersu;
  str2saddr (&peersu, "192.168.1.107", 36000);
  ret = transportaddr2hashcode (&localsu, &peersu);
  EVENTLOG2(
      VERBOSE,
      "hash(addr pair { localsu: 192.168.1.107:36001 peersu: 192.168.1.107:36000 }) = %u, %u",
      ret, ret % 100000);

  str2saddr (&localsu, "192.168.1.107", 1234);
  str2saddr (&peersu, "192.168.1.107", 360);
  ret = transportaddr2hashcode (&localsu, &peersu);
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
    geco_packet.pk_comm_hdr.dest_port = htons (
        (generate_random_uint32 () % USHRT_MAX));
    geco_packet.pk_comm_hdr.src_port = htons (
        (generate_random_uint32 () % USHRT_MAX));
    geco_packet.pk_comm_hdr.verification_tag = htons (
        (generate_random_uint32 ()));
    ((chunk_fixed_t*) geco_packet.chunk)->chunk_id = CHUNK_DATA;
    ((chunk_fixed_t*) geco_packet.chunk)->chunk_length = htons (100);
    ((chunk_fixed_t*) geco_packet.chunk)->chunk_flags =
    DCHUNK_FLAG_UNORDER | DCHUNK_FLAG_FL_FRG;
    for (int i = 0; i < 100; i++)
    {
      uchar* wt = geco_packet.chunk + CHUNK_FIXED_SIZE;
      wt[i] = generate_random_uint32 () % UCHAR_MAX;
    }
    set_crc32_checksum ((char*) &geco_packet, DATA_CHUNK_FIXED_SIZES + 100);
    bool ret = validate_crc32_checksum ((char*) &geco_packet,
    DATA_CHUNK_FIXED_SIZES + 100);
    EXPECT_TRUE(ret);
  }
}

static bool flag = true;
static timer_id_t tid;
static char inputs[1024];
static int len;
static void
stdin_cb (char* data, size_t datalen)
{
  EVENTLOG2(DEBUG, "stdin_cb()::%d bytes : %s", datalen, inputs);

  memcpy (inputs, data, datalen);
  if (strcmp (data, "q") == 0)
  {
    flag = false;
    return;
  }

  mtra_timer_mgr_.reset_timer (tid, 1000000);

  int sentsize;
  uchar tos = IPTOS_DEFAULT;
  sockaddrunion saddr;

  str2saddr (&saddr, "::1", USED_UDP_PORT);
  sentsize = mtra_send_rawsocks (mtra_read_ip6rawsock (), inputs, datalen,
                                 &saddr, tos);
  assert(sentsize == datalen);
  EXPECT_STRCASEEQ(data, inputs);

  str2saddr (&saddr, "127.0.0.1", USED_UDP_PORT);
  sentsize = mtra_send_rawsocks (mtra_read_ip4rawsock (), inputs, datalen,
                                 &saddr, tos);
  assert(sentsize == datalen);
  EXPECT_STRCASEEQ(data, inputs);

  str2saddr (&saddr, "::1", USED_UDP_PORT);
  sentsize = mtra_send_udpscoks (mtra_read_ip6udpsock (), inputs, datalen,
                                 &saddr, tos);
  assert(sentsize == datalen);
  EXPECT_STRCASEEQ(data, inputs);

  str2saddr (&saddr, "127.0.0.1", USED_UDP_PORT);
  sentsize = mtra_send_udpscoks (mtra_read_ip4udpsock (), inputs, datalen,
                                 &saddr, tos);
  assert(sentsize == datalen);
  EXPECT_STRCASEEQ(data, inputs);
}
static void
socket_cb (int sfd, char* data, int datalen, sockaddrunion* from,
           sockaddrunion* to)
{
  EXPECT_STRCASEEQ(data, inputs);

  static char fromstr[MAX_IPADDR_STR_LEN];
  static char tostr[MAX_IPADDR_STR_LEN];
  ushort fport;
  ushort tport;
  saddr2str (from, fromstr, MAX_IPADDR_STR_LEN, &fport);
  saddr2str (to, tostr, MAX_IPADDR_STR_LEN, &tport);

  if (sfd == mtra_read_ip4rawsock ())
  {
    EVENTLOG8(
        DEBUG,
        "socket_cb(ip%d raw fd=%d)::receive (%d) bytes  of data(%s) from addr (%s:%d) to addr (%s:%d)",
        4, sfd, datalen, data, fromstr, fport, tostr, tport);
  }
  else if (sfd == mtra_read_ip6rawsock ())
  {
    EVENTLOG8(
        DEBUG,
        "socket_cb(ip%d raw fd=%d)::receive (%d) bytes  of data(%s) from addr (%s:%d) to addr (%s:%d)",
        6, sfd, datalen, data, fromstr, fport, tostr, tport);
  }
  else if (sfd == mtra_read_ip6udpsock ())
  {
    EVENTLOG8(
        DEBUG,
        "socket_cb(ip%d udp fd=%d)::receive (%d) bytes  of data(%s) from addr (%s:%d) to addr (%s:%d)",
        6, sfd, datalen, data, fromstr, fport, tostr, tport);
  }
  else if (sfd == mtra_read_ip4udpsock ())
  {
    EVENTLOG8(
        DEBUG,
        "socket_cb(ip%d udp fd=%d)::receive (%d) bytes  of data(%s) from addr (%s:%d) to addr (%s:%d)",
        4, sfd, datalen, data, fromstr, fport, tostr, tport);
  }
  else
  {
    EVENTLOG(DEBUG, "NO SUCH SFD");
  }
}

static bool
timer_cb (timer_id_t& tid, void* a1, void* a2)
{
  EVENTLOG2(DEBUG, "timeouts, BYE!", tid->timer_id, tid->timer_type);
  flag = false;
  return true;
}
static void
task_cb (void* userdata)
{
  static int counter = 0;
  counter++;
  if (counter > 300)
  {
    EVENTLOG1(DEBUG,
              "task_cb called 300 times with tick of 10ms(userdata = %s)",
              (char* )userdata);
    counter = 0;
  }
}

int
socket_read_start (void* user_data)
{
  printf ("socket read starts\n");
}
int
socket_read_end (int sfd, bool isudpsocket, char* data, int datalen,
                 sockaddrunion* from, sockaddrunion* to, void* user_data)
{
  printf ("socket read end sfd=%d,isudpsocket=%d,datalen=%d ... \n", sfd,
          isudpsocket, datalen);
}
int
select_start (void* user_data)
{
  printf ("select_start\n");
}
int
select_end (void* user_data)
{
  printf ("select_end\n");
  mulp_disable_mtra_select_handler();
}
TEST(TRANSPORT_MODULE, test_process_stdin)
{
  int rcwnd = 512;
  mtra_init (&rcwnd);

  cbunion_t cbunion;
  cbunion.socket_cb_fun = socket_cb;
  mtra_set_expected_event_on_fd (mtra_read_ip4rawsock (),
  EVENTCB_TYPE_SCTP,
                                 POLLIN | POLLPRI, cbunion, 0);
  mtra_set_expected_event_on_fd (mtra_read_ip4udpsock (),
  EVENTCB_TYPE_UDP,
                                 POLLIN | POLLPRI, cbunion, 0);
  mtra_set_expected_event_on_fd (mtra_read_ip6rawsock (),
  EVENTCB_TYPE_SCTP,
                                 POLLIN | POLLPRI, cbunion, 0);
  mtra_set_expected_event_on_fd (mtra_read_ip6udpsock (),
  EVENTCB_TYPE_UDP,
                                 POLLIN | POLLPRI, cbunion, 0);

  //you have to put stdin as last because we test it
  mtra_add_stdin_cb (stdin_cb);

  mtra_set_tick_task_cb (task_cb, (void*) "this is user datta");

  //mulp_set_mtra_select_handler();
  tid = mtra_timer_mgr_.add_timer (TIMER_TYPE_INIT, 300000, timer_cb, 0, 0);

  socket_read_start_cb_t mtra_socket_read_start = socket_read_start;
  socket_read_end_cb_t mtra_socket_read_end = socket_read_end;
  mulp_set_socket_read_handler (mtra_socket_read_start, mtra_socket_read_end);
  mulp_enable_socket_read_handler ();

  select_cb_t mtra_select_start = select_start;
  select_cb_t mtra_select_end = select_end;
  mulp_set_mtra_select_handler (mtra_select_start, mtra_select_end);
  mulp_enable_mtra_select_handler ();

  while (flag)
    mtra_poll ();
  mtra_destroy ();
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <wheel-timer.h>

#define THE_END_OF_TIME ((timeout_t)-1)

static int
check_misc (void)
{
  if (TIMEOUT_VERSION != timeout_version ())
    return 1;
  if (TIMEOUT_V_REL != timeout_v_rel ())
    return 1;
  if (TIMEOUT_V_API != timeout_v_api ())
    return 1;
  if (TIMEOUT_V_ABI != timeout_v_abi ())
    return 1;
  if (strcmp (timeout_vendor (), TIMEOUT_VENDOR))
    return 1;
  return 0;
}

static int
check_open_close (timeout_t hz_set, timeout_t hz_expect)
{
  int err = 0;
  struct timeouts *tos = timeouts_open (hz_set, &err);
  if (!tos)
    return 1;
  if (err)
    return 1;
  if (hz_expect != timeouts_hz (tos))
    return 1;
  timeouts_close (tos);
  return 0;
}

/* Not very random */
static timeout_t
random_to (timeout_t min, timeout_t max)
{
  if (max <= min)
    return min;
  /* Not actually all that random, but should exercise the code. */
  timeout_t rand64 = rand () * (timeout_t) INT_MAX + rand ();
  return min + (rand64 % (max - min));
}

/* configuration for check_randomized */
struct rand_cfg
{
    /* When creating timeouts, smallest possible delay */
    timeout_t min_timeout;
    /* When creating timeouts, largest possible delay */
    timeout_t max_timeout;
    /* First time to start the clock at. */
    timeout_t start_at;
    /* Do not advance the clock past this time. */
    timeout_t end_at;
    /* Number of timeouts to create and monitor. */
    int n_timeouts;
    /* Advance the clock by no more than this each step. */
    timeout_t max_step;
    /* Use relative timers and stepping */
    int relative;
    /* Every time the clock ticks, try removing this many timeouts at
     * random. */
    int try_removing;
    /* When we're done, advance the clock to the end of time. */
    int finalize;
};

#define MFAIL0() do {printf("Failure on line %d\n", __LINE__);goto done;} while (0)
//#define MFAIL()
static int
check_randomized (const struct rand_cfg *cfg)
{

  int i, err;
  int rv = 1;
  struct timeout *t = (timeout*) calloc (cfg->n_timeouts,
                                         sizeof(struct timeout));
  timeout_t *timeouts = (timeout_t*) calloc (cfg->n_timeouts,
                                             sizeof(timeout_t));
  uint8_t *fired = (uint8_t*) calloc (cfg->n_timeouts, sizeof(uint8_t));
  uint8_t *found = (uint8_t*) calloc (cfg->n_timeouts, sizeof(uint8_t));
  uint8_t *deleted = (uint8_t*) calloc (cfg->n_timeouts, sizeof(uint8_t));
  struct timeouts *tos = timeouts_open (0, &err);
  timeout_t now = cfg->start_at;
  int n_added_pending = 0, cnt_added_pending = 0;
  int n_added_expired = 0, cnt_added_expired = 0;
  struct timeouts_it it_p, it_e, it_all;
  int p_done = 0, e_done = 0, all_done = 0;
  struct timeout *to = NULL;
  const int rel = cfg->relative;

  if (!t || !timeouts || !tos || !fired || !found || !deleted)
    MFAIL0()
    ;
  timeouts_update (tos, cfg->start_at);

  for (i = 0; i < cfg->n_timeouts; ++i)
  {
    if (&t[i] != timeout_init (&t[i], rel ? 0 : TIMEOUT_ABS))
      MFAIL0()
      ;
    if (timeout_pending (&t[i]))
      MFAIL0()
      ;
    if (timeout_expired (&t[i]))
      MFAIL0()
      ;

    timeouts[i] = random_to (cfg->min_timeout, cfg->max_timeout);

    timeouts_add (tos, &t[i], timeouts[i] - (rel ? now : 0));
    if (timeouts[i] <= cfg->start_at)
    {
      if (timeout_pending (&t[i]))
        MFAIL0()
        ;
      if (!timeout_expired (&t[i]))
        MFAIL0()
        ;
      ++n_added_expired;
    }
    else
    {
      if (!timeout_pending (&t[i]))
        MFAIL0()
        ;
      if (timeout_expired (&t[i]))
        MFAIL0()
        ;
      ++n_added_pending;
    }
  }

  if (!!n_added_pending != timeouts_pending (tos))
    MFAIL0()
    ;
  if (!!n_added_expired != timeouts_expired (tos))
    MFAIL0()
    ;

  /* Test foreach, interleaving a few iterators. */
  TIMEOUTS_IT_INIT(&it_p, TIMEOUTS_PENDING);
  TIMEOUTS_IT_INIT(&it_e, TIMEOUTS_EXPIRED);
  TIMEOUTS_IT_INIT(&it_all, TIMEOUTS_ALL);
  while (!(p_done && e_done && all_done))
  {
    if (!p_done)
    {
      to = timeouts_next (tos, &it_p);
      if (to)
      {
        i = to - &t[0];
        ++found[i];
        ++cnt_added_pending;
      }
      else
      {
        p_done = 1;
      }
    }
    if (!e_done)
    {
      to = timeouts_next (tos, &it_e);
      if (to)
      {
        i = to - &t[0];
        ++found[i];
        ++cnt_added_expired;
      }
      else
      {
        e_done = 1;
      }
    }
    if (!all_done)
    {
      to = timeouts_next (tos, &it_all);
      if (to)
      {
        i = to - &t[0];
        ++found[i];
      }
      else
      {
        all_done = 1;
      }
    }
  }

  for (i = 0; i < cfg->n_timeouts; ++i)
  {
    if (found[i] != 2)
      MFAIL0()
      ;
  }
  if (cnt_added_expired != n_added_expired)
    MFAIL0()
    ;
  if (cnt_added_pending != n_added_pending)
    MFAIL0()
    ;

  while (NULL != (to = timeouts_get (tos)))
  {
    i = to - &t[0];
    assert(&t[i] == to);
    if (timeouts[i] > cfg->start_at)
      MFAIL0()
      ; /* shouldn't have happened yet */

    --n_added_expired; /* drop expired timeouts. */
    ++fired[i];
  }

  if (n_added_expired != 0)
    MFAIL0()
    ;

  while (now < cfg->end_at)
  {
    int n_fired_this_time = 0;
    timeout_t first_at = timeouts_timeout (tos) + now;

    timeout_t oldtime = now;
    timeout_t step = random_to (1, cfg->max_step);
    int another;
    now += step;
    if (rel)
      timeouts_step (tos, step);
    else
      timeouts_update (tos, now);

    for (i = 0; i < cfg->try_removing; ++i)
    {
      int idx = rand () % cfg->n_timeouts;
      if (!fired[idx])
      {
        timeout_del (&t[idx]);
        ++deleted[idx];
      }
    }

    another = (timeouts_timeout (tos) == 0);

    while (NULL != (to = timeouts_get (tos)))
    {
      if (!another)
        MFAIL0()
        ; /* Thought we saw the last one! */
      i = to - &t[0];
      assert(&t[i] == to);
      if (timeouts[i] > now)
        MFAIL0()
        ; /* shouldn't have happened yet */
      if (timeouts[i] <= oldtime)
        MFAIL0()
        ; /* should have happened already */
      if (timeouts[i] < first_at)
        MFAIL0()
        ; /* first_at should've been earlier */
      fired[i]++;
      n_fired_this_time++;
      another = (timeouts_timeout (tos) == 0);
    }
    if (n_fired_this_time && first_at > now)
      MFAIL0()
      ; /* first_at should've been earlier */
    if (another)
      MFAIL0()
      ; /* Huh? We think there are more? */
    if (!timeouts_check (tos, stderr))
      MFAIL0()
      ;
  }

  for (i = 0; i < cfg->n_timeouts; ++i)
  {
    if (fired[i] > 1)
      MFAIL0()
      ; /* Nothing fired twice. */
    if (timeouts[i] <= now)
    {
      if (!(fired[i] || deleted[i]))
        MFAIL0()
        ;
    }
    else
    {
      if (fired[i])
        MFAIL0()
        ;
    }
    if (fired[i] && deleted[i])
      MFAIL0()
      ;
    if (cfg->finalize > 1)
    {
      if (!fired[i])
        timeout_del (&t[i]);
    }
  }

  /* Now nothing more should fire between now and the end of time. */
  if (cfg->finalize)
  {
    timeouts_update (tos, THE_END_OF_TIME);
    if (cfg->finalize > 1)
    {
      if (timeouts_get (tos))
        MFAIL0()
        ;
      TIMEOUTS_FOREACH(to, tos, TIMEOUTS_ALL)
MFAIL0      ();
    }
  }
  rv = 0;

  done: if (tos)
    timeouts_close (tos);
  if (t)
    free (t);
  if (timeouts)
    free (timeouts);
  if (fired)
    free (fired);
  if (found)
    free (found);
  if (deleted)
    free (deleted);
  return rv;
}

struct intervals_cfg
{
    const timeout_t *timeouts;
    int n_timeouts;
    timeout_t start_at;
    timeout_t end_at;
    timeout_t skip;
};

#define MFAIL() {if (tos) timeouts_close(tos);if (t) free(t);if (fired) free(fired);return rv;}

int
check_intervals (struct intervals_cfg *cfg)
{
  int i, err;
  int rv = 1;
  struct timeout *to;
  struct timeout *t = (timeout*) calloc (cfg->n_timeouts,
                                         sizeof(struct timeout));
  unsigned *fired = (unsigned*) calloc (cfg->n_timeouts, sizeof(unsigned));
  struct timeouts *tos = timeouts_open (0, &err);

  timeout_t now = cfg->start_at;
  if (!t || !tos || !fired)
    MFAIL();

  timeouts_update (tos, now);

  for (i = 0; i < cfg->n_timeouts; ++i)
  {
    if (&t[i] != timeout_init (&t[i], TIMEOUT_INT))
      MFAIL();
    if (timeout_pending (&t[i]))
      MFAIL();
    if (timeout_expired (&t[i]))
      MFAIL();

    timeouts_add (tos, &t[i], cfg->timeouts[i]);
    if (!timeout_pending (&t[i]))
      MFAIL();
    if (timeout_expired (&t[i]))
      MFAIL();
  }

  while (now < cfg->end_at)
  {
    timeout_t delay = timeouts_timeout (tos);
    if (cfg->skip && delay < cfg->skip)
      delay = cfg->skip;
    timeouts_step (tos, delay);
    now += delay;

    while (NULL != (to = timeouts_get (tos)))
    {
      i = to - &t[0];
      assert(&t[i] == to);
      fired[i]++;
      if (0 != (to->expires - cfg->start_at) % cfg->timeouts[i])
        MFAIL();
      if (to->expires <= now)
        MFAIL();
      if (to->expires > now + cfg->timeouts[i])
        MFAIL();
    }
    if (!timeouts_check (tos, stderr))
      MFAIL();
  }

  timeout_t duration = now - cfg->start_at;
  for (i = 0; i < cfg->n_timeouts; ++i)
  {
    if (cfg->skip)
    {
      if (fired[i] > duration / cfg->timeouts[i])
        MFAIL();
    }
    else
    {
      if (fired[i] != duration / cfg->timeouts[i])
        MFAIL();
    }
    if (!timeout_pending (&t[i]))
      MFAIL();
  }

  rv = 0;
  if (tos)
    timeouts_close (tos);
  if (t)
    free (t);
  if (fired)
    free (fired);
  return rv;
}

TEST(TIMER_MODULE, test_wheel_timer)
{
  int j;
  int n_failed = 0;
#define DO(fn) do {                             \
                 printf("."); fflush(stdout);    \
                 if (fn) {                       \
                         ++n_failed;             \
                         printf("%s failed\n", #fn);     \
                 }                                       \
         } while (0)

#define DO_N(n, fn) do {                        \
                 for (j = 0; j < (n); ++j) {     \
                         DO(fn);                 \
                 }                               \
         } while (0)

  DO(check_misc ());
  DO(check_open_close (1000, 1000));
  DO(check_open_close(0, TIMEOUT_mHZ));

  struct rand_cfg cfg1;
  cfg1.min_timeout = 1;
  cfg1.max_timeout = 100;
  cfg1.start_at = 5;
  cfg1.end_at = 1000;
  cfg1.n_timeouts = 1000;
  cfg1.max_step = 10;
  cfg1.relative = 0;
  cfg1.try_removing = 0;
  cfg1.finalize = 2;
  DO_N(300, check_randomized (&cfg1));

  struct rand_cfg cfg2;
  cfg2.min_timeout = 20;
  cfg2.max_timeout = 1000;
  cfg2.start_at = 10;
  cfg2.end_at = 100;
  cfg2.n_timeouts = 1000;
  cfg2.max_step = 5;
  cfg2.relative = 1;
  cfg2.try_removing = 0;
  cfg2.finalize = 2;
  DO_N(300, check_randomized (&cfg2));

  struct rand_cfg cfg2b;
  cfg2b.min_timeout = 20;
  cfg2b.max_timeout = 1000;
  cfg2b.start_at = 10;
  cfg2b.end_at = 100;
  cfg2b.n_timeouts = 1000;
  cfg2b.max_step = 5;
  cfg2b.relative = 1;
  cfg2b.try_removing = 0;
  cfg2b.finalize = 1;
  DO_N(300, check_randomized (&cfg2b));

  struct rand_cfg cfg2c;
  cfg2c.min_timeout = 20;
  cfg2c.max_timeout = 1000;
  cfg2c.start_at = 10;
  cfg2c.end_at = 100;
  cfg2c.n_timeouts = 1000;
  cfg2c.max_step = 5;
  cfg2c.relative = 1;
  cfg2c.try_removing = 0;
  cfg2c.finalize = 0;
  DO_N(300, check_randomized (&cfg2c));

  struct rand_cfg cfg3;
  cfg3.min_timeout = 2000;
  cfg3.max_timeout = ((uint64_t) 1) << 50;
  cfg3.start_at = 100;
  cfg3.end_at = ((uint64_t) 1) << 49;
  cfg3.n_timeouts = 1000;
  cfg3.max_step = ((uint64_t) 1) << 31;
  cfg3.relative = 0;
  cfg3.try_removing = 0;
  cfg3.finalize = 2;
  DO_N(10, check_randomized (&cfg3));

  struct rand_cfg cfg3b;
  cfg3b.min_timeout = ((uint64_t) 1) << 50;
  cfg3b.max_timeout = ((uint64_t) 1) << 52;
  cfg3b.start_at = 100;
  cfg3b.end_at = ((uint64_t) 1) << 53;
  cfg3b.n_timeouts = 1000;
  cfg3b.max_step = ((uint64_t) 1) << 48;
  cfg3b.relative = 0;
  cfg3b.try_removing = 0;
  cfg3b.finalize = 2;
  DO_N(10, check_randomized (&cfg3b));

  struct rand_cfg cfg4;
  cfg4.min_timeout = 2000;
  cfg4.max_timeout = ((uint64_t) 1) << 30;
  cfg4.start_at = 100;
  cfg4.end_at = ((uint64_t) 1) << 26;
  cfg4.n_timeouts = 10000;
  cfg4.max_step = 1 << 16;
  cfg4.relative = 0;
  cfg4.try_removing = 3;
  cfg4.finalize = 2;
  DO_N(10, check_randomized (&cfg4));

  const timeout_t primes[] =
    { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97 };
  const timeout_t factors_of_1337[] =
    { 1, 7, 191, 1337 };
  const timeout_t multiples_of_five[] =
    { 5, 10, 15, 20, 25, 30, 35, 40, 45, 50 };

  struct intervals_cfg icfg1;
  icfg1.timeouts = primes;
  icfg1.n_timeouts = sizeof(primes) / sizeof(timeout_t);
  icfg1.start_at = 50;
  icfg1.end_at = 5322;
  icfg1.skip = 0;
  DO(check_intervals (&icfg1));

  struct intervals_cfg icfg2;
  icfg2.timeouts = factors_of_1337;
  icfg2.n_timeouts = sizeof(factors_of_1337) / sizeof(timeout_t);
  icfg2.start_at = 50;
  icfg2.end_at = 50000;
  icfg2.skip = 0;
  DO(check_intervals (&icfg2));

  struct intervals_cfg icfg3;
  icfg3.timeouts = multiples_of_five;
  icfg3.n_timeouts = sizeof(multiples_of_five) / sizeof(timeout_t);
  icfg3.start_at = 49;
  icfg3.end_at = 5333;
  icfg3.skip = 0;
  DO(check_intervals (&icfg3));

  struct intervals_cfg icfg4;
  icfg4.timeouts = primes;
  icfg4.n_timeouts = sizeof(primes) / sizeof(timeout_t);
  icfg4.start_at = 50;
  icfg4.end_at = 5322;
  icfg4.skip = 16;
  DO(check_intervals (&icfg4));

  if (n_failed)
  {
    puts ("\nFAIL");
  }
  else
  {
    puts ("\nOK");
  }
}

