#include "gtest/gtest.h"
#include "gmock/gmock.h"

// @caution because geco-ds-malloc includes geco-thread.h that includes window.h but transport_layer.h includes wsock2.h, as we know, it must include before windows.h so if you uncomment this line, will cause error
//#include "geco-ds-malloc.h"
#include "geco-net.h"
//#include "timeout-debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include "wheel-timer.h"
#include "wheel-timer-bitops.cc"
#include "geco-net-transport.h"

static uint64_t testcases[] =
  { 13371337 * 10, 100, 385789752, 82574, (((uint64_t) 1) << 63)
      + (((uint64_t) 1) << 31) + 10101 };

static int
naive_clz (int bits, uint64_t v)
{
  int r = 0;
  uint64_t bit = ((uint64_t) 1) << (bits - 1);
  while (bit && 0 == (v & bit))
  {
    r++;
    bit >>= 1;
  }
  printf ("clz(%d,%lx) -> %d\n", bits, v, r);
  return r;
}

static int
naive_ctz (int bits, uint64_t v)
{
  int r = 0;
  uint64_t bit = 1;
  while (bit && 0 == (v & bit))
  {
    r++;
    bit <<= 1;
    if (r == bits)
      break;
  }
  printf ("ctz(%d,%lx) -> %d\n", bits, v, r);
  return r;
}

static int
check (uint64_t vv)
{
  uint32_t v32 = (uint32_t) vv;

  if (vv == 0)
    return 1; /* c[tl]z64(0) is undefined. */

  if (ctz64 (vv) != naive_ctz (64, vv))
  {
    printf ("mismatch with ctz64: %d\n", ctz64 (vv));
    exit (1);
    return 0;
  }
  if (clz64 (vv) != naive_clz (64, vv))
  {
    printf ("mismatch with clz64: %d\n", clz64 (vv));
    exit (1);
    return 0;
  }

  if (v32 == 0)
    return 1; /* c[lt]z(0) is undefined. */

  if (ctz32 (v32) != naive_ctz (32, v32))
  {
    printf ("mismatch with ctz32: %d\n", ctz32 (v32));
    exit (1);
    return 0;
  }
  if (clz32 (v32) != naive_clz (32, v32))
  {
    printf ("mismatch with clz32: %d\n", clz32 (v32));
    exit (1);
    return 0;
  }
  return 1;
}

TEST(TIMER_MODULE, test_bitops)
{
  unsigned int i;
  const unsigned int n = sizeof(testcases) / sizeof(testcases[0]);
  int result = 0;

  for (i = 0; i <= 63; ++i)
  {
    uint64_t x = 1 << i;
    if (!check (x))
      result = 1;
    --x;
    if (!check (x))
      result = 1;
  }

  for (i = 0; i < n; ++i)
  {
    if (!check (testcases[i]))
      result = 1;
  }
  if (result)
  {
    puts ("FAIL");
  }
  else
  {
    puts ("OK");
  }
}

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
