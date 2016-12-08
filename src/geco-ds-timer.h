/*
 * gecotimer.h
 *
 *  Created on: 20 Apr 2016
 *      Author: jakez
 */

#ifndef MY_WHEEL_SRC_GECOTIMER_H_
#define MY_WHEEL_SRC_GECOTIMER_H_

#include <list>
#include <algorithm>
#include "geco-net-common.h"

/**
 *  A singly linked list for timer events
 */

#define RESET_TIMER_FROM_CB true
#define NOT_RESET_TIMER_FROM_CB false

struct timer;
typedef std::list<timer>::iterator timer_id_t;
struct timer
{
	// ifyou resettimer 0 in side the cb, return true
	// therwise, return false
	typedef bool (*Action)(timer_id_t& tid, void *, void *);
	uint timer_id;
	timeval action_time; /* the time when it is to go off*/
	int timer_type;
	void *arg1; /* pointer to possible arguments */
	void *arg2;
	Action action;/*the callback function, arranged in a sorted, linked listuser specify*/
};

struct timer_mgr
{
	std::list<timer> timers;
	uint tid;
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
	 *  @return -1 fail, >0 is timer id successful
	 */
	timer_id_t add_timer(uint timer_type, time_t timeouts, timer::Action action,
			void *arg1 = 0, void *arg2 = 0);

	/**
	 *  a function to remove a certain action item, first checks current_item,
	 *  then traverses the list from the start, updates length etc.
	 *  @param  tlist       pointer to the timer_list instance
	 *  @param  timer_id    id of the timer to be removed
	 *  @param  item    pointer to where deleted data is to be copied !
	 *  @return 0 on success, -1 if a pointer was NULL or other error, 1 if not found
	 */
	void delete_timer(timer_id_t& timerptr);
	/**
	 *      function to be called, when a timer is reset. Basically calls get_item(),
	 *    saves the function pointer, updates the execution time (msecs milliseconds
	 *      from now) and removes the item from the list. Then calls insert_item
	 *      with the updated timer_item struct.
	 *      @param  tlist           pointer to the timer_list instance
	 *      @param  timerptr        id of the timer to be updated
	 *      @param timouts
	 *      @ret 0  successful, -1 for fail reason no timer stored
	 */
	int reset_timer(timer_id_t& timerptr, uint timeouts);
	/**
	 * @return -1 if no timer in list, 0 if timeout and action must be taken,
	 * else interval before the timeouts
	 */
	int timeouts();
	timer_id_t get_front_timer()
	{
		return this->timers.begin();
	}
	bool empty()
	{
		return this->timers.empty();
	}
	void print(short event_log_level);
	void addition(const timer& t1, const timer& t2);
private:
	void print_timer(short event_log_level, const timer& item);
	static bool cmp_timer_action_time(const timer& t1, const timer& t2)
	{
		if (t1.action_time.tv_sec < t2.action_time.tv_sec)
			return true;
		else if (t1.action_time.tv_sec == t2.action_time.tv_sec)
		{
			return t1.action_time.tv_usec < t2.action_time.tv_usec;
		}
		else
			return false;

	}
	static bool cmp_timer_id(const timer& t1, const timer& t2)
	{
		return t1.timer_id < t2.timer_id;
	}
};


#endif /* MY_WHEEL_SRC_GECOTIMER_H_ */
