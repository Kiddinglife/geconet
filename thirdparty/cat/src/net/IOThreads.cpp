/*
	Copyright (c) 2011 Christopher A. Taylor.  All rights reserved.

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
#include <cat/io/IOLayer.hpp>
#include <cat/net/Buffers.hpp>
#include <cat/time/Clock.hpp>
#include <cat/port/SystemInfo.hpp>
#include <cat/io/Logging.hpp>
#include <cat/io/Settings.hpp>
using namespace cat;

CAT_INLINE bool IOThread::HandleCompletion(IOThreads *master, OVERLAPPED_ENTRY entries[], u32 count, u32 event_msec)
{
	bool exit_flag = false;

	BatchSet sendq, recvq;
	sendq.Clear();
	recvq.Clear();

	UDPEndpoint *prev_recv_endpoint = 0;
	u32 recv_count = 0;

	// For each entry,
	for (u32 ii = 0; ii < count; ++ii)
	{
		UDPEndpoint *udp_endpoint = reinterpret_cast<UDPEndpoint*>( entries[ii].lpCompletionKey );
		IOCPOverlapped *ov_iocp = reinterpret_cast<IOCPOverlapped*>( entries[ii].lpOverlapped );
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
				SendBuffer *buffer = reinterpret_cast<SendBuffer*>( (u8*)ov_iocp - offsetof(SendBuffer, iointernal.ov) );

				// Link to sendq
				if (sendq.tail) sendq.tail->batch_next = buffer;
				else sendq.head = buffer;

				sendq.tail = buffer;
				buffer->batch_next = 0;

				udp_endpoint->ReleaseRef();
			}
			break;

		case IOTYPE_UDP_RECV:
			{
				RecvBuffer *buffer = reinterpret_cast<RecvBuffer*>( (u8*)ov_iocp - offsetof(RecvBuffer, iointernal.ov) );

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
						prev_recv_endpoint->OnReadCompletion(recvq, recv_count);
					}

					// Reset recvq
					recvq.head = recvq.tail = buffer;
					recv_count = 1;
					prev_recv_endpoint = udp_endpoint;
				}
			}
			break;
		}
	}

	// If recvq is not empty,
	if (recvq.head)
	{
		// Finalize the recvq and post it
		recvq.tail->batch_next = 0;
		prev_recv_endpoint->OnReadCompletion(recvq, recv_count);
	}

	// If sendq is not empty,
	if (sendq.head)
	{
		sendq.tail->batch_next = 0;
		StdAllocator::ii->ReleaseBatch(sendq);
	}

	return exit_flag;
}

void IOThread::UseVistaAPI(IOThreads *master)
{
	PGetQueuedCompletionStatusEx pGetQueuedCompletionStatusEx = master->_GetQueuedCompletionStatusEx;
	HANDLE port = master->_io_port;

	static const u32 MAX_IO_GATHER = 32;
	OVERLAPPED_ENTRY entries[MAX_IO_GATHER];
	unsigned long ulEntriesRemoved;

	while (pGetQueuedCompletionStatusEx(port, entries, MAX_IO_GATHER, &ulEntriesRemoved, INFINITE, FALSE))
	{
		u32 event_time = Clock::msec();

		// Quit if we received the quit signal
		if (HandleCompletion(master, entries, ulEntriesRemoved, event_time))
			break;
	}
}

void IOThread::UsePreVistaAPI(IOThreads *master)
{
	HANDLE port = master->_io_port;

	DWORD bytes;
	ULONG_PTR key;
	LPOVERLAPPED ov;

	static const u32 MAX_IO_GATHER = 4;
	OVERLAPPED_ENTRY entries[MAX_IO_GATHER];
	u32 count = 0;

	for (;;)
	{
		BOOL bResult = GetQueuedCompletionStatus(port, &bytes, &key, &ov, INFINITE);

		u32 event_time = Clock::msec();

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
		if (HandleCompletion(master, entries, count, event_time))
			break;

		count = 0;
	}
}

bool UDPReadThread::ThreadFunction(void *vmaster)
{
	UDPThreads *master = reinterpret_cast<UDPThreads*>( vmaster );

	
}

bool UDPWriteThread::ThreadFunction(void *vmaster)
{
	UDPThreads *master = reinterpret_cast<UDPThreads*>( vmaster );

	UDPEndpoint *endpoint = master->GetEndpoint();

	endpoint->DoWrites();
}

bool UDPThreads::Associate(UDPEndpoint *endpoint)
{
	_endpoint = endpoint;
	if (!_writer.StartThread(this)) return false;
	if (!_reader.StartThread(this)) return false;
	return true;
}

void UDPThreads::Shutdown()
{
}


//// IOThreads

IOThreads::IOThreads()
{
	_recv_allocator = 0;
}

IOThreads::~IOThreads()
{
	Shutdown();
}

bool IOThreads::Startup()
{
	// If startup was previously attempted,
	if (_recv_allocator)
	{
		// Clean up and try again
		Shutdown();
	}

	_recv_allocator = new BufferAllocator(sizeof(RecvBuffer) + IOTHREADS_BUFFER_READ_BYTES, IOTHREADS_BUFFER_COUNT);

	if (!_recv_allocator || !_recv_allocator->Valid())
	{
		FATAL("IOThreads") << "Out of memory while allocating " << IOTHREADS_BUFFER_COUNT << " buffers for a shared pool";
		return false;
	}

	return true;
}

bool IOThreads::Shutdown()
{
	u32 count = _udp_workers.size();
	
	for (u32 ii = 0; ii < count; ++ii)
	{
		UDPThread *worker = _udp_workers[ii];
		worker->Shutdown();
	}

	u32 worker_count = _worker_count;

	// If port was created,
	if (_io_port)
	{
		// For each worker,
		for (u32 ii = 0; ii < worker_count; ++ii)
		{
			// Post a completion event that kills the worker threads
			if (!PostQueuedCompletionStatus(_io_port, 0, 0, 0))
			{
				FATAL("IOThreads") << "PostQueuedCompletionStatus error " << GetLastError();
			}
		}
	}

	const int SHUTDOWN_WAIT_TIMEOUT = 15000; // 15 seconds

	// For each worker thread,
	for (u32 ii = 0; ii < worker_count; ++ii)
	{
		if (!_workers[ii].WaitForThread(SHUTDOWN_WAIT_TIMEOUT))
		{
			FATAL("IOThreads") << "Thread " << ii << "/" << worker_count << " refused to die!  Attempting lethal force...";
			_workers[ii].AbortThread();
		}
	}

	// Free worker thread objects
	if (_workers)
	{
		delete []_workers;
		_workers = 0;
	}

	_worker_count = 0;

	// If port was created,
	if (_io_port)
	{
		CloseHandle(_io_port);
		_io_port = 0;
	}

	// If allocator was created,
	if (_recv_allocator)
	{
		delete _recv_allocator;
		_recv_allocator = 0;
	}

	return true;
}

bool IOThreads::Associate(UDPEndpoint *udp_endpoint)
{
	if (!_io_port)
	{
		FATAL("IOThreads") << "Unable to associate handle since completion port was never created";
		return false;
	}

	HANDLE result = CreateIoCompletionPort((HANDLE)udp_endpoint->GetSocket(), _io_port, (ULONG_PTR)udp_endpoint, 0);

	if (result != _io_port)
	{
		FATAL("IOThreads") << "Associating UDPEndpoint error " << GetLastError();
		return false;
	}

	return true;
}
