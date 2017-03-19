/*
	Copyright (c) 2009-2012 Christopher A. Taylor.  All rights reserved.

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

#include <cat/iocp/IOThreadPools.hpp>
#include <cat/io/Buffers.hpp>
#include <cat/time/Clock.hpp>
#include <cat/port/SystemInfo.hpp>
#include <cat/io/Log.hpp>
#include <cat/io/LogThread.hpp>
#include <cat/io/Settings.hpp>
using namespace cat;

static IOThreadPools *m_io_thread_pools = 0;
static WorkerThreads *m_worker_threads = 0;
static Settings *m_settings = 0;
static UDPSendAllocator *m_udp_send_allocator = 0;
static Clock *m_clock = 0;
static SystemInfo *m_system_info = 0;
static LogThread *m_log_thread = 0;


//// IOThread

CAT_INLINE bool IOThread::HandleCompletion(IOThreadPool *master, OVERLAPPED_ENTRY entries[], u32 count, u32 event_msec, BatchSet &sendq, BatchSet &recvq, UDPEndpoint *&prev_recv_endpoint, u32 &recv_count)
{
	bool exit_flag = false;
	UDPEndpoint *update_node = 0;

	// For each entry,
	for (u32 ii = 0; ii < count; ++ii)
	{
		IOCPOverlapped *ov_iocp = reinterpret_cast<IOCPOverlapped*>( entries[ii].lpOverlapped );
		IOThreadsAssociator *associator = reinterpret_cast<IOThreadsAssociator*>( entries[ii].lpCompletionKey );
		u32 bytes = entries[ii].dwNumberOfBytesTransferred;

		// Terminate thread on zero completion
		if (!ov_iocp)
		{
			exit_flag = true;
			continue;
		}

		// Based on type of IO,
		switch (ov_iocp->io_type)
		{
		case IOTYPE_UDP_SEND:
			{
				UDPEndpoint *udp_endpoint = static_cast<UDPEndpoint*>( associator );
				SendBuffer *buffer = reinterpret_cast<SendBuffer*>( (u8*)ov_iocp - offsetof(SendBuffer, iointernal.ov) );

				CAT_INANE("IOThread") << "IOTYPE_UDP_SEND completed for " << udp_endpoint;

				// Link to sendq
				if (sendq.tail) sendq.tail->batch_next = buffer;
				else sendq.head = buffer;

				sendq.tail = buffer;
				buffer->batch_next = 0;

				// Add to list of references to release
				if (udp_endpoint->_update_count)
					udp_endpoint->_update_count++;
				else
				{
					udp_endpoint->_update_next = update_node;
					update_node = udp_endpoint;
					udp_endpoint->_update_count = 1;
				}
			}
			break;

		case IOTYPE_UDP_RECV:
			{
				UDPEndpoint *udp_endpoint = static_cast<UDPEndpoint*>( associator );
				RecvBuffer *buffer = reinterpret_cast<RecvBuffer*>( (u8*)ov_iocp - offsetof(RecvBuffer, iointernal.ov) );

				CAT_INANE("IOThread") << "IOTYPE_UDP_RECV completed for " << udp_endpoint;

				// Write event completion results to buffer
				buffer->data_bytes = bytes;
				buffer->event_msec = event_msec;

				// If the same UDP endpoint got the last request too,
				if (prev_recv_endpoint == udp_endpoint)
				{
					// Append to recvq
					recvq.tail->batch_next = buffer;
					recvq.tail = buffer;
					++recv_count;
				}
				else
				{
					// If recvq is not empty,
					if (recvq.head)
					{
						// Finalize the recvq and post it
						recvq.tail->batch_next = 0;
						prev_recv_endpoint->OnRecvCompletion(recvq, recv_count);
					}

					// Reset recvq
					recvq.head = recvq.tail = buffer;
					recv_count = 1;
					prev_recv_endpoint = udp_endpoint;
				}
			}
			break;

		case IOTYPE_FILE_WRITE:
			{
				AsyncFile *async_file = static_cast<AsyncFile*>( associator );
				WriteBuffer *buffer = reinterpret_cast<WriteBuffer*>( (u8*)ov_iocp - offsetof(WriteBuffer, iointernal.ov) );

				CAT_INANE("IOThread") << "IOTYPE_FILE_WRITE completed for " << async_file;

				// Write event completion results to buffer
				buffer->offset = ((u64)buffer->iointernal.ov.OffsetHigh << 32) | buffer->iointernal.ov.Offset;
				buffer->data_bytes = bytes;

				// If callback is valid,
				if (buffer->callback.IsValid())
				{
					// Invoke callback inline rather than defer to worker threads for file io
					buffer->callback(GetTLS(), buffer);
				}

				async_file->ReleaseRef(CAT_REFOBJECT_TRACE);
			}
			break;

		case IOTYPE_FILE_READ:
			{
				AsyncFile *async_file = static_cast<AsyncFile*>( associator );
				ReadBuffer *buffer = reinterpret_cast<ReadBuffer*>( (u8*)ov_iocp - offsetof(ReadBuffer, iointernal.ov) );

				CAT_INANE("IOThread") << "IOTYPE_FILE_READ completed for " << async_file;

				// Write event completion results to buffer
				buffer->offset = ((u64)buffer->iointernal.ov.OffsetHigh << 32) | buffer->iointernal.ov.Offset;
				buffer->data_bytes = bytes;

				// If callback is valid,
				if (buffer->callback.IsValid())
				{
					// Invoke callback inline rather than defer to worker threads for file io
					buffer->callback(GetTLS(), buffer);
				}

				async_file->ReleaseRef(CAT_REFOBJECT_TRACE);
			}
			break;
		}
	}

	// If recvq is not empty,
	if (recvq.head)
	{
		// Finalize the recvq and post it
		recvq.tail->batch_next = 0;
		prev_recv_endpoint->OnRecvCompletion(recvq, recv_count);

		recvq.Clear();
		prev_recv_endpoint = 0;
		recv_count = 0;
	}

	// If sendq is not empty,
	if (sendq.head)
	{
		sendq.tail->batch_next = 0;
		m_udp_send_allocator->ReleaseBatch(sendq);

		sendq.Clear();

		// If ref counts need to be updated, (only if sendq was added to)
		while (update_node)
		{
			update_node->ReleaseRef(CAT_REFOBJECT_TRACE, update_node->_update_count);
			update_node->_update_count = 0;
			update_node = update_node->_update_next;
		}
	}

	return exit_flag;
}

void IOThread::UseVistaAPI(IOThreadPool *master)
{
	PGetQueuedCompletionStatusEx pGetQueuedCompletionStatusEx =
		m_io_thread_pools->GetIOThreadImports()->pGetQueuedCompletionStatusEx;
	HANDLE port = master->GetIOPort();

	static const u32 MAX_IO_GATHER = 128;
	OVERLAPPED_ENTRY entries[MAX_IO_GATHER];
	unsigned long ulEntriesRemoved;

	BatchSet sendq, recvq;
	sendq.Clear();
	recvq.Clear();

	UDPEndpoint *prev_recv_endpoint = 0;
	u32 recv_count = 0;

	u32 max_io_gather = m_settings->getInt("IO.IOThreadPool.MaxIOGather", MAX_IO_GATHER);
	if (max_io_gather > MAX_IO_GATHER) max_io_gather = MAX_IO_GATHER;
	if (max_io_gather < 1) max_io_gather = 1;

	while (pGetQueuedCompletionStatusEx(port, entries, max_io_gather, &ulEntriesRemoved, INFINITE, FALSE))
	{
		u32 event_time = m_clock->msec();

		// Quit if we received the quit signal
		if (HandleCompletion(master, entries, ulEntriesRemoved, event_time, sendq, recvq, prev_recv_endpoint, recv_count))
			break;
	}
}

void IOThread::UsePreVistaAPI(IOThreadPool *master)
{
	HANDLE port = master->GetIOPort();

	DWORD bytes;
	ULONG_PTR key;
	LPOVERLAPPED ov;

	static const u32 MAX_IO_GATHER = 4;
	OVERLAPPED_ENTRY entries[MAX_IO_GATHER];
	u32 count = 0;

	BatchSet sendq, recvq;
	sendq.Clear();
	recvq.Clear();

	UDPEndpoint *prev_recv_endpoint = 0;
	u32 recv_count = 0;

	CAT_FOREVER
	{
		BOOL bResult = GetQueuedCompletionStatus(port, &bytes, &key, &ov, INFINITE);

		u32 event_time = m_clock->msec();

		// Attempt to pull off a number of events at a time
		do 
		{
			entries[count].lpOverlapped = ov;
			entries[count].lpCompletionKey = key;
			entries[count].dwNumberOfBytesTransferred = bytes;
			if (++count >= MAX_IO_GATHER) break;

			bResult = GetQueuedCompletionStatus((HANDLE)port, &bytes, &key, &ov, 0);
		} while (bResult || ov);

		// Quit if we received the quit signal
		if (HandleCompletion(master, entries, count, event_time, sendq, recvq, prev_recv_endpoint, recv_count))
			break;

		count = 0;
	}
}

bool IOThread::Entrypoint(void *vmaster)
{
	IOThreadPool *master = reinterpret_cast<IOThreadPool*>( vmaster );

	if (m_io_thread_pools->GetIOThreadImports()->pGetQueuedCompletionStatusEx)
		UseVistaAPI(master);
	else
		UsePreVistaAPI(master);

	return true;
}


//// IOThreadPool

IOThreadPool::IOThreadPool()
{
	_io_port = 0;

	_worker_count = 0;
	_workers = 0;
}

bool IOThreadPool::Startup(u32 max_worker_count)
{
	// If startup was previously attempted,
	if (_worker_count || _io_port)
	{
		// Clean up and try again
		Shutdown();
	}

	// Initialize the worker count to the number of processors
	u32 worker_count = m_system_info->GetProcessorCount();
	if (worker_count < 1) worker_count = 1;

	// If worker count override is set,
	u32 worker_count_override = m_settings->getInt("IO.IOThreadPool.WorkerCount", 0);
	if (worker_count_override != 0)
	{
		// Use it instead of the number of processors
		worker_count = worker_count_override;
	}

	// Impose max worker count if it is specified
	if (max_worker_count && worker_count > max_worker_count)
		worker_count = max_worker_count;

	_workers = new (std::nothrow) IOThread[worker_count];
	if (!_workers)
	{
		CAT_FATAL("IOThreadPools") << "Out of memory while allocating " << worker_count << " worker thread objects";
		return false;
	}

	_worker_count = worker_count;

	_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);

	if (!_io_port)
	{
		CAT_FATAL("IOThreadPools") << "CreateIoCompletionPort error " << GetLastError();
		return false;
	}

	// For each worker,
	for (u32 ii = 0; ii < worker_count; ++ii)
	{
		// Start its thread
		if (!_workers[ii].StartThread(this))
		{
			CAT_FATAL("IOThreadPools") << "StartThread error " << GetLastError();
			return false;
		}

		// Try to tie each thread to an ideal processor core to help with scheduling
		if (worker_count > 2) _workers[ii].SetIdealCore(ii);
	}

	return true;
}

bool IOThreadPool::Shutdown()
{
	u32 worker_count = _worker_count;

	// If port was created,
	if (_io_port)
	{
		CAT_INFO("IOThreadPool") << "Shutting down thread pool...";

		// For each worker,
		for (u32 ii = 0; ii < worker_count; ++ii)
		{
			// Post a completion event that kills the worker threads
			if (!PostQueuedCompletionStatus(_io_port, 0, 0, 0))
			{
				CAT_FATAL("IOThreadPools") << "PostQueuedCompletionStatus error " << GetLastError();
			}
		}
	}

	const int SHUTDOWN_WAIT_TIMEOUT = 15000; // 15 seconds
	const int REPOST_TIMEOUT = 50; // 50 milliseconds

	// For each worker thread,
	for (u32 ii = 0; ii < worker_count; ++ii)
	{
		u32 start_time = Clock::msec_fast();

		while (!_workers[ii].WaitForThread(REPOST_TIMEOUT))
		{
			if (Clock::msec_fast() - start_time > SHUTDOWN_WAIT_TIMEOUT)
			{
				CAT_FATAL("IOThreadPools") << "Thread " << ii << "/" << worker_count << " refused to die!  Attempting lethal force...";
				_workers[ii].AbortThread();
				break;
			}
			else
			{
				// Post a completion event that kills the worker threads
				if (_io_port && !PostQueuedCompletionStatus(_io_port, 0, 0, 0))
				{
					CAT_FATAL("IOThreadPools") << "PostQueuedCompletionStatus error " << GetLastError();
				}
			}
		}
	}

	// If port was created,
	if (_io_port)
	{
		CloseHandle(_io_port);
		_io_port = 0;
	}

	// TODO: Figure out where the bug really is
	m_clock->sleep(100);

	// Free worker thread objects
	if (_workers)
	{
		delete []_workers;
		_workers = 0;
	}

	_worker_count = 0;

	return true;
}

bool IOThreadPool::Associate(IOThreadsAssociator *associator)
{
	if (!_io_port)
	{
		CAT_FATAL("IOThreadPools") << "Unable to associate handle since completion port was never created";
		return false;
	}

	HANDLE result = CreateIoCompletionPort(associator->GetHandle(), _io_port, (ULONG_PTR)associator, 0);

	if (result != _io_port)
	{
		CAT_FATAL("IOThreadPools") << "Associating handle error " << GetLastError();
		return false;
	}

	return true;
}


//// IOThreadImports

void IOThreadImports::Initialize()
{
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");

	// Attempt to use Vista+ API
	pGetQueuedCompletionStatusEx = (PGetQueuedCompletionStatusEx)GetProcAddress(kernel32, "GetQueuedCompletionStatusEx");
	pSetFileCompletionNotificationModes = (PSetFileCompletionNotificationModes)GetProcAddress(kernel32, "SetFileCompletionNotificationModes");
	pSetFileIoOverlappedRange = (PSetFileIoOverlappedRange)GetProcAddress(kernel32, "SetFileIoOverlappedRange");
	pSetFileValidData = (PSetFileValidData)GetProcAddress(kernel32, "SetFileValidData");
}


//// IOThreadPools

CAT_REF_SINGLETON(IOThreadPools);

bool IOThreadPools::OnInitialize()
{
	_imports.Initialize();

	m_io_thread_pools = this;

	Use(m_worker_threads, m_settings, m_udp_send_allocator, m_clock, m_system_info);
	Use(m_log_thread);

	return IsInitialized() && _shared_pool.Startup();
}

void IOThreadPools::OnFinalize()
{
	// For each pool,
	for (pools_iter ii = _private_pools; ii; ++ii)
		ii->Shutdown();

	_private_pools.Clear();

	_shared_pool.Shutdown();
}

IOThreadPool *IOThreadPools::AssociatePrivate(IOThreadsAssociator *associator)
{
	AutoMutex lock(_lock);

	IOThreadPool *pool = new (std::nothrow) IOThreadPool;
	if (!pool) return false;

	_private_pools.PushFront(pool);

	pools_iter ii = _private_pools;

	if (!ii->Startup(1) || !ii->Associate(associator))
	{
		_private_pools.Erase(ii);
		delete pool;
		return 0;
	}

	return ii;
}

bool IOThreadPools::DissociatePrivate(IOThreadPool *pool)
{
	if (!pool) return true;

	bool success = pool->Shutdown();

	AutoMutex lock(_lock);

	_private_pools.Erase(pool);

	return success;
}

bool IOThreadPools::AssociateShared(IOThreadsAssociator *associator)
{
	return _shared_pool.Associate(associator);
}
