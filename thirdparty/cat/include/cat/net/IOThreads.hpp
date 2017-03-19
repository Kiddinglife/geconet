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

#ifndef CAT_NET_IO_THREADS_HPP
#define CAT_NET_IO_THREADS_HPP

#include <cat/threads/Thread.hpp>
#include <cat/net/Sockets.hpp>
#include <cat/threads/RefObject.hpp>
#include <cat/mem/BufferAllocator.hpp>

namespace cat {


struct NetOverlapped;
struct IOTLS;
class IOThread;
class IOThreads;
class UDPEndpoint;

struct NetOverlapped
{
	int addr_len;
	NetAddr::SockAddr addr;
};

struct NetOverlappedRecvFrom : NetOverlapped
{
};

struct NetOverlappedSendTo : NetOverlapped
{
};

typedef NetOverlappedRecvFrom IOLayerRecvOverhead;
typedef NetOverlappedSendTo IOLayerSendOverhead;

static const u32 IOTHREADS_BUFFER_READ_BYTES = 1450;
static const u32 IOTHREADS_BUFFER_COUNT = 10000;


class UDPReadThread : public Thread
{
	bool ThreadFunction(void *vmaster);
};

class UDPWriteThread : public Thread
{
	bool ThreadFunction(void *vmaster);
};


// IO thread
class CAT_EXPORT UDPThreads : public Thread
{
	UDPReadThread _reader;
	UDPWriteThread _writer;
	UDPEndpoint *_endpoint;

public:
	CAT_INLINE UDPEndpoint *GetEndpoint() { return _endpoint; }

	bool Associate(UDPEndpoint *endpoint);
	void Shutdown();
};


// IO threads
class CAT_EXPORT IOThreads
{
	friend class IOThread;

	std::vector<UDPThread*> _udp_workers;

	BufferAllocator *_recv_allocator;

public:
	IOThreads();
	virtual ~IOThreads();

	CAT_INLINE BufferAllocator *GetRecvAllocator() { return _recv_allocator; }

	bool Startup();
	bool Shutdown();
	bool Associate(UDPEndpoint *udp_endpoint);
};


} // namespace cat

#endif // CAT_NET_IO_THREADS_HPP
