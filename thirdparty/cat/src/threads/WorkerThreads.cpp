/*
	Copyright (c) 2009-2011 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of LibCat nor the names of its contributors may be used
	  to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include <cat/threads/WorkerThreads.hpp>
#include <cat/time/Clock.hpp>
#include <cat/port/SystemInfo.hpp>
#include <cat/io/Log.hpp>
using namespace cat;

static const u32 INITIAL_TIMERS_ALLOCATED = 16;

static Clock *m_clock = 0;
static SystemInfo *m_system_info = 0;


//// WorkerThread

WorkerThread::WorkerThread()
{
	_kill_flag = false;

	_timers = new (std::nothrow) WorkerTimer[INITIAL_TIMERS_ALLOCATED];
	_timers_count = 0;
	_timers_allocated = INITIAL_TIMERS_ALLOCATED;

	_new_timers = new (std::nothrow) WorkerTimer[INITIAL_TIMERS_ALLOCATED];
	_new_timers_count = 0;
	_new_timers_allocated = INITIAL_TIMERS_ALLOCATED;

	for (u32 ii = 0; ii < WQPRIO_COUNT; ++ii)
	{
		_workqueues[ii].queued.Clear();
	}
}

bool WorkerThread::Associate(RefObject *object, WorkerTimerDelegate callback)
{
	if (!object || !callback)
		return false;

	//WARN("WorkerThreads") << "Adding timer " << object;

	AutoMutex lock(_new_timers_lock);

	u32 new_timers_count = _new_timers_count + 1;
	if (new_timers_count > _new_timers_allocated)
	{
		u32 new_allocated = new_timers_count * 2;

		WorkerTimer *new_timers = new (std::nothrow) WorkerTimer[new_allocated];
		if (!new_timers) return false;

		memcpy(new_timers, _new_timers, _new_timers_count * sizeof(WorkerTimer));

		delete []_new_timers;

		_new_timers = new_timers;
		_new_timers_allocated = new_allocated;
	}
	_new_timers[_new_timers_count].callback = callback;
	_new_timers[_new_timers_count].object = object;
	_new_timers_count = new_timers_count;

	lock.Release();

	object->AddRef(CAT_REFOBJECT_TRACE);
	return true;
}

void WorkerThread::DeliverBuffers(u32 priority, const BatchSet &buffers)
{
	_workqueues[priority].lock.Enter();
	_workqueues[priority].queued.PushBack(buffers);
	_workqueues[priority].lock.Leave();

	_event_flag.Set();
}

void WorkerThread::TickTimers(u32 now)
{
	u32 timers_count = _timers_count;

	// For each timer,
	for (u32 ii = 0; ii < timers_count; ++ii)
	{
		WorkerTimer *timer = &_timers[ii];

		// If session is shutting down,
		if (timer->object->IsShutdown())
		{
			//WARN("WorkerThreads") << "Removing shutdown timer " << timer->object;

			timer->object->ReleaseRef(CAT_REFOBJECT_TRACE);

			_timers_count = --timers_count;
			_timers[ii--] = _timers[timers_count];
		}
		else
		{
			timer->callback(_tls, now);
		}
	}

	// If new timers have been added,
	if (_new_timers_count > 0)
	{
		AutoMutex lock(_new_timers_lock);

		u32 combined_count = _timers_count + _new_timers_count;

		if (combined_count > _timers_allocated)
		{
			u32 allocated = combined_count * 2;

			WorkerTimer *timers = new (std::nothrow) WorkerTimer[allocated];
			if (!timers) return;

			memcpy(timers, _timers, _timers_count * sizeof(WorkerTimer));

			delete []_timers;

			_timers = timers;
			_timers_allocated = allocated;
		}

		memcpy(_timers + _timers_count, _new_timers, _new_timers_count * sizeof(WorkerTimer));
		_timers_count = combined_count;
		_new_timers_count = 0;
	}
}

static CAT_INLINE void ExecuteWorkQueue(ThreadLocalStorage &tls, const BatchSet &queue)
{
	// If there is nothing in the queue,
	if (!queue.head) return;

#if defined(CAT_WORKER_THREADS_REORDER_EVENTS)

	/*
		This version performs a median filter on the events in the queue
		so that events that specify the same callback tend to be batched
		together even when other callbacks also speckle the input queue.
		This improves overall throughput but causes re-ordering.

		For a network workload the speckles would be intermittent messages
		such as time synchronization pings or other events that should get
		a low-latency treatment.  And the large batch that is de-speckled
		would be file transfer or some other flood of bulk packets that are
		not so important to handle with low latency.  So the median filter
		is essentially helping prioritize packets properly.

		Derived from the following truth table:
		-------------------------------------------------------------------
		prev	current	next	|	Desired result:
		------------------------|------------------------------------------
		A		A		A		|	Store current into prev
		A		A		B		|	Store current into prev
		A		B		B		|	Run prev, Store current into prev
		A		B		A		|	Run current (main case of interest!)
		A		B		C		|	Run prev, Store current into prev
		0		A		A		|	Store current into prev (first loop)
		0		A		B		|	Store current into prev (first loop)
		In all cases, current becomes next.  If next is null, it halts.

		Translated to the following pseudo-code:
		if prev = 0						<--- Unrolled first loop
			Store current into prev		<--- Unrolled first loop
		else
			if prev = current
				Store current into prev
			else
				if prev = next
					Run current
				else
					Run prev
					Store current into prev

		When next becomes null, it just needs to check if it should run them as
		a batch together (prev = current) or to run current and then the prev.
	*/

	WorkerBuffer *prev =  static_cast<WorkerBuffer*>( queue.head );
	WorkerBuffer *current = static_cast<WorkerBuffer*>( prev->batch_next );

	// If only one element in set,
	if (!current)
	{
		prev->callback(tls, queue);
		return;
	}

	// Unroll first loop
	BatchSet batch(prev);
	WorkerBuffer *next = static_cast<WorkerBuffer*>( current->batch_next );

	// While there is a (current,next) pair remaining to filter,
	while (next)
	{
		if (prev->callback == current->callback)
			batch.PushBack(current);
		else
		{
			if (prev->callback == next->callback)
				current->callback(tls, current);
			else
			{
				prev->callback(tls, batch);
				batch = current;
				prev = current;
			}
		}

		current = next;
		next = static_cast<WorkerBuffer*>( next->batch_next );
	}

	CAT_DEBUG_ENFORCE(prev && current);

	// If previous batch includes last one,
	if (prev->callback == current->callback)
		batch.PushBack(current);
	else
		current->callback(tls, current);

	// Run remaining
	prev->callback(tls, batch);

#else // CAT_WORKER_THREADS_REORDER_EVENTS

	BatchSet buffers;
	buffers.head = queue.head;

	WorkerBuffer *last = static_cast<WorkerBuffer*>( queue.head );

	CAT_FOREVER
	{
		WorkerBuffer *next = static_cast<WorkerBuffer*>( last->batch_next );

		if (!next || next->callback != last->callback)
		{
			// Close out the previous buffer group
			buffers.tail = last;
			last->batch_next = 0;

			last->callback(tls, buffers);

			if (!next) break;

			// Start a new one
			buffers.head = next;
		}

		last = next;
	}

#endif // CAT_WORKER_THREADS_REORDER_EVENTS
}

bool WorkerThread::Entrypoint(void *vmaster)
{
	WorkerThreads *master = (WorkerThreads*)vmaster;

	u32 tick_interval = master->_tick_interval;
	u32 next_tick = 0; // Tick right away

	while (!_kill_flag)
	{
		u32 now = m_clock->msec();

		// Check if an event is waiting or the timer interval is up
		bool check_events = false;

		for (u32 ii = 0; ii < WQPRIO_COUNT; ++ii)
		{
			if (_workqueues[ii].queued.head)
			{
				check_events = true;
				break;
			}
		}

		// If no events occurred,
		if (!check_events)
		{
			u32 wait_time = next_tick - now;

			if ((s32)wait_time >= 0)
			{
				if (_event_flag.Wait(wait_time))
					check_events = true;

				now = m_clock->msec();
			}
		}

		// Grab queue if event is flagged
		if (check_events)
		{
			for (u32 ii = 0; ii < WQPRIO_COUNT; ++ii)
			{
				if (_workqueues[ii].queued.head)
				{
					_workqueues[ii].lock.Enter();
					BatchSet queue = _workqueues[ii].queued;
					_workqueues[ii].queued.Clear();
					_workqueues[ii].lock.Leave();

					ExecuteWorkQueue(_tls, queue);
				} // end if queue seems full
			} // next priority level
		} // end if check_events

		// If tick interval is up,
		if ((s32)(now - next_tick) >= 0)
		{
			TickTimers(now);

			// Set up next tick
			next_tick += tick_interval;

			// If next tick has already occurred,
			if ((s32)(now - next_tick) >= 0)
			{
				// Push off next tick one interval into the future
				next_tick = now + tick_interval;

				CAT_INANE("WorkerThread") << "Slow worker tick";
			}
		}
	}

	u32 timers_count = _timers_count;

	// For each timer,
	for (u32 ii = 0; ii < timers_count; ++ii)
	{
		WorkerTimer *timer = &_timers[ii];

		timer->object->ReleaseRef(CAT_REFOBJECT_TRACE);
	}

	return true;
}


//// WorkerThreads

CAT_REF_SINGLETON(WorkerThreads);

bool WorkerThreads::OnInitialize()
{
	Use(m_clock, m_system_info);

	_tick_interval = 10;
	_worker_count = m_system_info->GetProcessorCount();
	_workers = 0;
	_round_robin_worker_id = 0;

	u32 worker_count = _worker_count;

	// Allocate worker thread objects
	_workers = new (std::nothrow) WorkerThread[worker_count];
	if (!_workers)
	{
		CAT_FATAL("WorkerThreads") << "Out of memory while allocating " << worker_count << " worker thread objects";
		return false;
	}

	// For each worker,
	for (u32 ii = 0; ii < worker_count; ++ii)
	{
		// Start its thread
		if (!_workers[ii].StartThread(this))
		{
			CAT_WARN("WorkerThreads") << "StartThread error " << GetLastError();
			return ii > 0; // Indicate success if at least one thread was started successfully
		}

		// Try to tie each thread to an ideal processor core to help with scheduling
		if (worker_count > 2) _workers[ii].SetIdealCore(ii);
	}

	return true;
}

void WorkerThreads::OnFinalize()
{
	u32 worker_count = _worker_count;

	// For each worker,
	for (u32 ii = 0; ii < worker_count; ++ii)
	{
		// Set the kill flag
		_workers[ii].SetKillFlag();
	}

	const int SHUTDOWN_WAIT_TIMEOUT = 15000; // 15 seconds

	// For each worker thread,
	for (u32 ii = 0; ii < worker_count; ++ii)
	{
		if (!_workers[ii].WaitForThread(SHUTDOWN_WAIT_TIMEOUT))
		{
			CAT_FATAL("WorkerThreads") << "Thread " << ii << "/" << worker_count << " refused to die!  Attempting lethal force...";
			_workers[ii].AbortThread();
		}
	}

	_worker_count = 0;

	// Free worker thread objects
	if (_workers)
	{
		delete []_workers;
		_workers = 0;
	}
}

u32 WorkerThreads::FindLeastPopulatedWorker()
{
	u32 lowest_session_count = _workers[0].GetTimerCount();
	u32 worker_id = 0;

	// For each other worker,
	for (u32 ii = 1, worker_count = _worker_count; ii < worker_count; ++ii)
	{
		u32 session_count = _workers[ii].GetTimerCount();

		// If the session count is lower,
		if (session_count < lowest_session_count)
		{
			// Use this one
			lowest_session_count = session_count;
			worker_id = ii;
		}
	}

	return worker_id;
}

#if defined(CAT_NO_ATOMIC_POPCOUNT)

u32 WorkerThreads::GetTotalPopulation()
{
	u32 session_count = _workers[0].GetSessionCount();

	// For each other worker,
	for (u32 ii = 1, worker_count = _worker_count; ii < worker_count; ++ii)
	{
		session_count += _workers[ii].GetSessionCount();
	}

	return session_count;
}

#endif // CAT_NO_ATOMIC_POPCOUNT
