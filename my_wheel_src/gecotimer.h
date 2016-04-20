/*
 * gecotimer.h
 *
 *  Created on: 20 Apr 2016
 *      Author: jakez
 */

#ifndef MY_WHEEL_SRC_GECOTIMER_H_
#define MY_WHEEL_SRC_GECOTIMER_H_

#if (defined (SOLARIS) || defined (WIN32))
#define timeradd(a, b, result) \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                          \
    if ((result)->tv_usec >= 1000000)                                         \
      {                                                                       \
        ++(result)->tv_sec;                                                   \
        (result)->tv_usec -= 1000000;                                         \
      }                                                                       \
  } while (0)
#define timersub(a, b, result)                                                \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)
#endif

#include "globals.h"
#include <list>
namespace geco
{
namespace ultils
{
/**
 *  A singly linked list for timer events
 */
struct timer
{
    typedef void (*Action)(TimerID, void *, void *);
    uint timer_id;
    int timer_type;
    ulonglong action_time; /* the time when it is to go off */
    void *arg1; /* pointer to possible arguments */
    void *arg2;
    Action action;/*the callback function, arranged in a sorted, linked list*/
};

class timer_mgr
{
private:
    std::list<timer> timers;
    uint tid;

public:
    timer_mgr();
    ~timer_mgr();

    /**
     *  this function inserts a timer_item into the list. Keeps it ordered,
     *  and updates length, and possibly one timeval entry. Checks whether
     *  we insert at beginning/end first. timer_item must have been alloc'ed
     *  first by the application, this is not done by this function !
     *  @param  tlist       pointer to the timer_list instance
     *  @param  item    pointer to the event item that is to be added
     *  @param  timeouts   ms time to trigger the action
     *  @return timer id
     */
    uint add_timer( uint timer_type, uint timeouts, timer::Action action,
            void *arg1=0, void *arg2=0);
    void print(short event_log_level);

private:
    void print_timer(short event_log_level, const timer& item);
    static bool cmp_timer_action_time(const timer& t1, const timer& t2)
    {
        return t1.action_time < t2.action_time;
    }
    static bool cmp_timer_id(const timer& t1, const timer& t2)
    {
        return t1.timer_id < t2.timer_id;
    }
};

}
}
#endif /* MY_WHEEL_SRC_GECOTIMER_H_ */
