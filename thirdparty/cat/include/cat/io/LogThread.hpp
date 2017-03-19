/*
	Copyright (c) 2011-2012 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_LOG_THREAD_HPP
#define CAT_LOG_THREAD_HPP

#include <cat/lang/RefSingleton.hpp>
#include <cat/threads/Thread.hpp>
#include <cat/threads/WaitableFlag.hpp>

/*
	LogThread singleton

	The purpose of this object is to greatly reduce the latency caused by
	the Log subsystem.

	After acquiring the LogThread singleton, a thread will be started that
	will take care of invoking the Log singleton callback instead of running
	it immediately.
*/

namespace cat {


// Log item
class LogItem
{
	EventSeverity _severity;
	const char *_source;
	std::string _msg;

public:
	CAT_INLINE EventSeverity GetSeverity() { return _severity; }
	CAT_INLINE const char *GetSource() { return _source; }
	CAT_INLINE const std::string &GetMsg() { return _msg; }

	CAT_INLINE void Set(EventSeverity severity, const char *source, const std::string &msg)
	{
		_severity = severity;
		_source = source;
		_msg = msg;
	}
};


// Log thread
class LogThread : public RefSingleton<LogThread>, public Thread
{
	bool OnInitialize();
	void OnFinalize();

	static const u32 DUMP_INTERVAL = 100; // milliseconds
	static const u32 MAX_LIST_SIZE = DUMP_INTERVAL * 20; // 20 events per millisecond max

	WaitableFlag _wakeup;
	volatile bool _die;			// Thread marked for death on next wakeup
	volatile u32 _flagged;		// Wakeup has been triggered, to avoid giving semaphore multiple times (optimization)

	// Double-buffered log item list to reduce contention further
	volatile int _list_writing;
	LogItem *_list_ptr[2];
	u32 _list_size[2];

	LogItem *_list_a, *_list_b;

	void RunList();
	bool Entrypoint(void *param);

	void Cleanup();

public:
	void Write(EventSeverity severity, const char *source, const std::string &msg);
};


} // namespace cat

#endif // CAT_LOG_THREAD_HPP
