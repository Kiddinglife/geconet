/*
 * gecotimer.cpp
 *
 *  Created on: 20 Apr 2016
 *      Author: jakez
 */

#include "geco-ds-timer.h"

timer_mgr::timer_mgr()
{
    this->tid = 1;
}
timer_mgr::~timer_mgr()
{
}
timer_id_t timer_mgr::add_timer(uint timer_type,
    time_t timeouts/*ms*/, timer::Action action, void *arg1, void *arg2)
{
    timer item;
    if (gettimenow(&item.action_time) < 0)
        return this->timers.end();

    item.timer_id = this->tid++;
    item.timer_type = timer_type;
    sum_time(&item.action_time, timeouts, &item.action_time);
    item.action = action;
    item.arg1 = arg1;
    item.arg2 = arg2;

    if (item.timer_id == 0)
    {
        this->tid = 2;
        item.timer_id = 1;
    }

    auto insert_pos = upper_bound(this->timers.begin(), this->timers.end(),
        item, timer_mgr::cmp_timer_action_time);
    this->timers.insert(insert_pos, item);
    --insert_pos;
    return insert_pos;
}

void timer_mgr::delete_timer(timer_id_t& timerptr)
{
    if (this->timers.empty())
        return;
    timerptr->timer_id = 0;
    this->timers.erase(timerptr);
}
int timer_mgr::reset_timer(timer_id_t& timerptr, uint timeouts)
{
	EVENTLOG(VERBOSE, "reset_timer");
	if (this->timers.empty())
        return -1;
    uint timer_type = timerptr->timer_type;
    timer::Action action = timerptr->action;
    void *arg1 = timerptr->arg1;
    void *arg2 = timerptr->arg2;
    delete_timer(timerptr);
    timerptr = add_timer(timer_type, timeouts, action, arg1, arg2);
    return 0;
}
int timer_mgr::timeouts()
{
	if (this->timers.empty())
        return -1;

    // get now and timeout
    struct timeval now;
    if (gettimenow(&now) < 0) return -1;

    const struct timeval& timeout = this->timers.front().action_time;
    int secs = timeout.tv_sec - now.tv_sec;
    if (secs < 0) return 0; // sec timeouts

	int usecs = timeout.tv_usec - now.tv_usec;
    if (usecs < 0)
    {
        //as usecs has timeout, we need ti check if secs checkouts
        //if  two secs equals, secs == 0, then must timeout
        // if two secs difference greater than 1 sec, then must not timeout
        secs--;
        usecs += 1000000;
    }

    if (secs < 0) return 0; //secs timeouts

    // no type overflow because number is very small
    return ((int)(secs * 1000 + usecs / 1000));
}


void timer_mgr::print_timer(short event_log_level, const timer& item)
{
    const char* ttype;

    switch (item.timer_type)
    {
        case TIMER_TYPE_INIT:
            ttype = "Init Timer";
            break;
        case TIMER_TYPE_SACK:
            ttype = "SACK Timer";
            break;
        case TIMER_TYPE_RTXM:
            ttype = "T3 RTX Timer";
            break;
        case TIMER_TYPE_SHUTDOWN:
            ttype = "Shutdown Timer";
            break;
        case TIMER_TYPE_CWND:
            ttype = "CWND Timer";
            break;
        case TIMER_TYPE_HEARTBEAT:
            ttype = "Heartbeat Timer";
            break;
        case TIMER_TYPE_USER:
            ttype = "User Timer";
            break;
        default:
            ttype = "Unknown Timer";
            break;
    }
    EVENTLOG4(VVERBOSE,
        "TimerID: %u, Type : %s, action_time: {%ld sec, %ld us}",
        item.timer_id, ttype, item.action_time.tv_sec,
        item.action_time.tv_usec);
}
void timer_mgr::print(short event_log_level)
{
    if (this->timers.size() == 0)
    {
        EVENTLOG(event_log_level, "No timers!");
        return;
    }
    print_time_now(event_log_level);
    EVENTLOG1(event_log_level, "lList Length : %ld", this->timers.size());
    for (auto& timer : this->timers)
    {
        this->print_timer(event_log_level, timer);
    }
}



