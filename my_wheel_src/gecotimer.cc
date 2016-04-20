/*
 * gecotimer.cpp
 *
 *  Created on: 20 Apr 2016
 *      Author: jakez
 */

#include <gecotimer.h>
#include <algorithm>
using namespace geco::ultils;

timer_mgr::timer_mgr()
{
    this->tid = 1;
}
timer_mgr::~timer_mgr()
{
}

uint timer_mgr::add_timer(uint timer_type,uint timeouts, timer::Action action, void *arg1,
        void *arg2)
{
    timeval tval;
    gettimenow(&tval);

    timer item;
    item.timer_id = this->tid++;
    item.timer_type = timer_type;
    item.action_time =  timenow_us(&tval)+timeouts*1000;
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
    event_logi(loglvl_verbose, "Insert item : timer id %u ", item.timer_id);
    return item.timer_id;
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
        ttype = "HB Timer";
        break;
    case TIMER_TYPE_USER:
        ttype = "User Timer";
        break;
    default:
        ttype = "Unknown Timer";
        break;
    }
    event_logiii(event_log_level,
            "TimerID: %d, Type : %s, action_time: %ld us\n", item.timer_id,
            ttype, item.action_time);
}
void timer_mgr::print(short event_log_level)
{
    event_log(event_log_level, "Enter timer_mgr::print_debug_list");
    if (this->timers.size() == 0)
    {
        event_log(event_log_level, "No timers!");
        return;
    }
    print_time_now(event_log_level);
    event_logi(event_log_level, "List Length : %u ", this->timers.size());
    for (auto& timer : this->timers)
    {
        this->print_timer(event_log_level, timer);
    }
    event_log(event_log_level, "Leave timer_mgr::print_debug_list");
}
