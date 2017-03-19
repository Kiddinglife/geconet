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

#include <cat/io/LogThread.hpp>
#include <cat/io/Log.hpp>
using namespace cat;

static Log *m_log = 0;


//// LogThread

CAT_REF_SINGLETON(LogThread);

bool LogThread::OnInitialize()
{
	_list_writing = 0;

	_list_a = new LogItem[MAX_LIST_SIZE];
	_list_b = new LogItem[MAX_LIST_SIZE];

	_list_size[0] = 0;
	_list_size[1] = 0;
	_list_ptr[0] = _list_a;
	_list_ptr[1] = _list_b;

	_die = false;

	return StartThread();
}

void LogThread::OnFinalize()
{
	_die = true;
	_wakeup.Set();

	WaitForThread();

	delete []_list_a;
	delete []_list_b;
}

void LogThread::RunList()
{
	int writing_list = _list_writing;

	// If there are none waiting, abort
	u32 list_size = _list_size[writing_list];
	if (list_size <= 0) return;

	// Lock and swap the reading/writing lists
	int reading_list = writing_list;
	writing_list ^= 1;

	m_log->_lock.Enter();

		_list_writing = writing_list;

	m_log->_lock.Leave();

	// Refresh the list size
	list_size = _list_size[reading_list];
	CAT_DEBUG_ENFORCE(list_size > 0);

	// Invoke callbacks for each item
	LogItem *items = _list_ptr[reading_list];

	for (u32 ii = 0; ii < list_size; ++ii)
		m_log->_backend(items[ii].GetSeverity(), items[ii].GetSource(), items[ii].GetMsg());

	// Reset size to zero
	_list_size[reading_list] = 0;
}

void LogThread::Cleanup()
{
	// Gracefully remove myself from the output flow
	m_log->ResetFrontend();

	// Run any that remain
	RunList();
	RunList();
}

bool LogThread::Entrypoint(void *param)
{
	// Get Log reference
	m_log = Log::ref();
	if (!m_log || !m_log->IsInitialized()) return false;

	// Set thread priority low to encourage the scheduler to batch wakeups across log messages when under load
	SetExecPriority(P_LOW);

	// Inject myself into the output flow
	m_log->SetFrontend(Log::Callback::FromMember<LogThread, &LogThread::Write>(this));

	// Pump messages periodically
	while (_wakeup.Wait())
	{
		// Unset flag
		Atomic::Set(&_flagged, 0);

		// Mark the semaphore as being taken to re-enable it
		do
		{
			// If it is time to go the way that all threads must,
			if (_die)
			{
				Cleanup();
				return true;
			}

			// Process task list
			RunList();
		} while (Atomic::Set(&_flagged, 0));

		// Enforce some minimal delay between wakeups to encourage batching
		Clock::sleep(DUMP_INTERVAL);
	}

	Cleanup();
	return true;
}

void LogThread::Write(EventSeverity severity, const char *source, const std::string &msg)
{
	int list_writing = _list_writing;
	int list_size = _list_size[list_writing];

	// If list size is too large already,
	if (list_size >= MAX_LIST_SIZE-1)
	{
		// Abort after last one
		if (list_size >= MAX_LIST_SIZE)
		{
			m_log->_lock.Leave();

			return;
		}

		// Indicate overflow by changing source right before overflow occurs
		source = "LOG OVERFLOW";
	}

	// Append log item to the end
	LogItem *items = _list_ptr[list_writing];
	items[list_size++].Set(severity, source, msg);

	// Store list size
	_list_size[list_writing] = list_size;

	m_log->_lock.Leave();

	// If not flagged,
	if (!Atomic::Set(&_flagged, 1))
	{
		// Give semaphore (slow)
		_wakeup.Set();
	}
}
