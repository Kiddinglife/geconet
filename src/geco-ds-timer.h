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

#define WHEEL_8BITS 8
#define WHEEL_6BITS 6
#define WHEEL_8BITS_SIZE (1 << WHEEL_8BITS) //256 = 2^8
#define WHEEL_6BITS_SIZE (1 << WHEEL_6BITS) //64 = 2^6
#define WHEEL_8BITS_MASK (WHEEL_8BITS_SIZE - 1)
#define WHEEL_6BITS_MASK (WHEEL_6BITS_SIZE - 1)
#define WHEEL_NUM 5

const uint threshold1 = WHEEL_8BITS_SIZE; // max time 256 ms
const uint threshold2 = 1 << (WHEEL_8BITS + WHEEL_6BITS); //max number of units  64 * (256)
const uint threshold3 = 1 << (WHEEL_8BITS + 2 * WHEEL_6BITS); //max number of units 64 * ( 64*(256) ) ms
const uint threshold4 = 1 << (WHEEL_8BITS + 3 * WHEEL_6BITS); //max number of units 64 * ( 64*(64*256) ) ms
const uint max_threshold = 1 << (WHEEL_8BITS + 4 * WHEEL_6BITS); /*max number of units 2^32 ms*/
const uint max_timeout_ms = max_threshold * GRANULARITY;

struct slot_node_t
{
	slot_node_t *prev;
	slot_node_t *next;
	slot_node_t()
	{
		prev = next = this;
	} //circle
};
struct timer_node_t
{
	slot_node_t link;
	time_t action_time; /* the time when it is to go off*/
	time_t cur_time;
	int timer_type;
	void* event_handle;
	void* event_handle_args;
};

struct time_wheel_t
{
	slot_node_t *slots_; /// 轮子的插槽数组
	int curr_slot_idx_; /// 轮子当前转到的索引
	int slots_count_; /// 轮子大小

	time_wheel_t()
	{
		slots_ = NULL;
		curr_slot_idx_ = slots_count_ = 0;
	}

	time_wheel_t(int slots_count)
	{
		slots_ = new slot_node_t[slots_count];
		slots_count_ = slots_count;
		curr_slot_idx_ = 0;
	}

	~time_wheel_t()
	{
		if (slots_ != NULL)
			delete[] slots_;
		slots_ = NULL;
		curr_slot_idx_ = slots_count_ = 0;
	}

	void init()
	{
		for (int i = 0; i < slots_count_; i++)
		{
			/// 让指针指向自己
			slots_[i].next = slots_[i].prev = slots_ + i;
		}
	}

	/// 把news插入到prev,next之间
	void insert_listnode(slot_node_t *news, slot_node_t* prev,
			slot_node_t* next)
	{
		next->prev = news;
		news->next = next;
		news->prev = prev;
		prev->next = news;
	}

	/// 插入到链表头
	void insert_head(slot_node_t* news, slot_node_t* head)
	{
		insert_listnode(news, head, head->next);
	}

	/// 插入到链表尾
	void insert_tail(slot_node_t* news, slot_node_t* head)
	{
		insert_listnode(news, head->prev, head);
	}

	/// 删除节点
	void list_del(slot_node_t* list)
	{
		list->next->prev = list->prev;
		list->prev->next = list->next;
	}

	/// 得到轮子插槽的指针
	slot_node_t* GetNode(int index) const
	{
		return (index >= slots_count_ ? NULL : (slots_ + index));
	}
};

class wheel_timer_mgr_t
{
public:
	wheel_timer_mgr_t(uint resolution = GRANULARITY) // min unit is 1ms
	{
		resolution_ = resolution;
		Init();
	}
	virtual ~wheel_timer_mgr_t()
	{
		for (uint i = 0; i < WHEEL_NUM; i++)
		{
			if (g_vecs_[i] != NULL)
				delete g_vecs_[i];
			g_vecs_[i] = NULL;
		}
		m_tv1 = m_tv2 = m_tv3 = m_tv4 = m_tv5 = NULL;
	}

	/// 初始化定时器管理类
	void Init()
	{
		gettimenow_ms(&last_time_);
		gtick_ = last_time_;
		max_timeout_point_ = gtick_ + max_timeout_ms;

		m_tv1 = new time_wheel_t(WHEEL_8BITS_SIZE);
		m_tv1->init();
		g_vecs_[0] = m_tv1;
		for (uint i = 1; i < WHEEL_NUM; i++)
		{
			m_tv1 = new time_wheel_t(WHEEL_6BITS_SIZE);
			m_tv1->init();
			g_vecs_[i] = m_tv1;
		}
	}

	/// 增加一个定时器
	/// max timeout interval is 2^32 ms (around 49.5 days)
	/// if you use timeout interval > 2^32 ms, it will never be triggered !
	void start(timer_node_t *timernode)
	{
		/*
		 20, 25, 26, 5, 6, 20->
		 span (1ms)
		 0 - (2^8-1)*10        2^8*10 -> (2^14-1)*10   ........   2^26*10 - 2^32-1*10
		 wheel one                   wheel two                              wheel 5
		 unit span (@resolution_ ms):
		 0 - (2^8-1)        2^8 -> (2^14-1)   ........   2^26 - 2^32-1
		 wheel one             wheel two                       wheel 5
		 2) determine bucket index where this timer is located
		 */

		// 1) do nothing if timer exists
		if (!exists(timernode))
			return;
		if (timernode->action_time < gtick_)
			return;

		/*2) determine bucket index where this timer is located*/
		uint units_count = (timernode->action_time - gtick_) / resolution_;

		time_wheel_t* lve;
		slot_node_t * lvec;
		uint slot_idx;
		uint overflow_timeout;

		/*3) determine index within the span of max interval 2^32.
		 * when units_count == WHEEL_8BITS_SIZE, it shouldbe sotred
		 * in slot indexed 0 of the next wheel*/
		if (units_count < threshold1) //[0, 2^8)
		{
			// now we konw:
			// units_size = 128,  m_tv1->curr_slot_idx_ = 230,
			// WHEEL_8BITS_MASK =  255 = 0 1111  1111
			// sum                          =  358 = 1  0110 0110
			// we can calculate index like this:
			// index =  0 1111  1111 & 1  0110 0110
			// = 0 0110 0110 = 102 = 358 - 256 = 102
			// this is equevient to modole operation (128+230) % 256 = 102
			// alos can write like this:
			// (units_count + m_tv1->curr_slot_idx_) % WHEEL_8BITS_SIZE
			// but slower than bit operation,
			slot_idx = (units_count + m_tv1->curr_slot_idx_) & WHEEL_8BITS_MASK;
			lvec = m_tv1->GetNode(slot_idx);
			lve = m_tv1;
		}
		else if (units_count < threshold2) //[2^8, 2^(8+6))
		{
			slot_idx = ((units_count >> WHEEL_8BITS) + m_tv2->curr_slot_idx_)
					& WHEEL_6BITS_MASK;
		}
		else if (units_count < threshold3) //[2^8, 2^(8+6))
		{
			slot_idx = (units_count + m_tv3->curr_slot_idx_) & WHEEL_6BITS_MASK;
		}
	}
	///	检测定时器是否存在
	/// @return  如果存在返回true,否则为false
	bool exists(timer_node_t* timernode)
	{
		return !(timernode->link.next == NULL && timernode->link.prev == NULL);
	}
	///	删除定时器
	/// @return  如果删除成功返回true,否则为false
	bool stop(time_wheel_t* list, timer_node_t *times);
	/// 重新初始化一个定时器
	void reset(timer_node_t* timers);
	/// 执行当前已经到期的定时器,所有小于jeffies的定时器
	void timeouts(time_t jeffies);

private:
	/// 定时器的迁移，也即将一个定时器从它原来所处的定时器向量迁移到另一个定时器向量中。
	void cascade_timer(time_wheel_t* timers);
	/// 重新计算一个定时器
	void Mod_timer(timer_node_t* timers);

	/// 定时器全局tick
	time_t gtick_;
	/// 上次运行时间
	time_t last_time_;
	/// 精确到毫秒
	time_t resolution_;
	time_t max_timeout_point_;
	/// 5个轮子
	time_wheel_t* m_tv1;
	time_wheel_t* m_tv2;
	time_wheel_t* m_tv3;
	time_wheel_t* m_tv4;
	time_wheel_t* m_tv5;
	time_wheel_t* g_vecs_[WHEEL_NUM];
	static wheel_timer_mgr_t* instance_;
};
#endif /* MY_WHEEL_SRC_GECOTIMER_H_ */
