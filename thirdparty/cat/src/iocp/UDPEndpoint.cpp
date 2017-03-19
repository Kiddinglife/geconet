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

#include <cat/iocp/UDPEndpoint.hpp>
#include <cat/io/Log.hpp>
#include <cat/io/Settings.hpp>
#include <cat/io/Buffers.hpp>
#include <cat/net/UDPRecvAllocator.hpp>
#include <MSWSock.h>
using namespace std;
using namespace cat;

static UDPRecvAllocator *m_recv_allocator = 0;
static IOThreadPools *m_io_thread_pools = 0;
static UDPSendAllocator *m_udp_send_allocator = 0;


//// UDPEndpoint

bool UDPEndpoint::OnInitialize()
{
	Use(m_io_thread_pools, m_udp_send_allocator, m_recv_allocator);

	return true;
}

void UDPEndpoint::OnDestroy()
{
	Close();
}

bool UDPEndpoint::OnFinalize()
{
	IOThreadPools::ref()->DissociatePrivate(_pool);

	return true;
}

UDPEndpoint::UDPEndpoint()
{
	_pool = 0;
	_update_count = 0;
}

UDPEndpoint::~UDPEndpoint()
{
}

bool UDPEndpoint::Initialize(Port port, bool ignoreUnreachable, bool RequestIPv6, bool RequireIPv4, int kernelReceiveBufferBytes)
{
	// If not able to create a socket,
	if (!Create(RequestIPv6, RequireIPv4))
		return false;

	// Set SO_RCVBUF as requested (often defaults are far too low for UDP servers or UDP file transfer clients)
	if (kernelReceiveBufferBytes < 64000) kernelReceiveBufferBytes = 64000;
	SetRecvBufferSize(kernelReceiveBufferBytes);

	// Set SO_SNDBUF to zero for a zero-copy network stack (we maintain the buffers)
	SetRecvBufferSize(0);

	// If ignoring ICMP unreachable,
    if (ignoreUnreachable)
		IgnoreUnreachable(true);

	// If not able to bind,
	if (!Bind(port))
		return false;

	AddRef(CAT_REFOBJECT_TRACE);
	_buffers_posted = 0;

	// Associate with IOThreadPools
	_pool = IOThreadPools::ref()->AssociatePrivate(this);
	if (!_pool)
	{
		CAT_FATAL("UDPEndpoint") << "Unable to associate with IOThreadPools";
		Close();
		ReleaseRef(CAT_REFOBJECT_TRACE); // Release temporary references keeping the object alive until function returns
		return false;
	}

	// If no reads could be posted,
	if (PostReads(UDP_SIMULTANEOUS_READS) == 0)
	{
		CAT_FATAL("UDPEndpoint") << "No reads could be launched";
		Close();
		ReleaseRef(CAT_REFOBJECT_TRACE); // Release temporary reference keeping the object alive until function returns
		return false;
	}

    CAT_INFO("UDPEndpoint") << "Open on port " << GetPort();

	ReleaseRef(CAT_REFOBJECT_TRACE); // Release temporary reference keeping the object alive until function returns
    return true;
}


//// Begin Events

bool UDPEndpoint::PostRead(RecvBuffer *buffer)
{
	CAT_OBJCLR(buffer->iointernal.ov);
	buffer->iointernal.io_type = IOTYPE_UDP_RECV;
	buffer->iointernal.addr_len = sizeof(buffer->iointernal.addr);

	WSABUF wsabuf;
	wsabuf.buf = reinterpret_cast<CHAR*>( GetTrailingBytes(buffer) );
	wsabuf.len = IOTHREADS_BUFFER_READ_BYTES;

	// Queue up a WSARecvFrom()
	DWORD flags = 0, bytes;
	int result = WSARecvFrom(GetSocket(), &wsabuf, 1, &bytes, &flags,
		reinterpret_cast<sockaddr*>( &buffer->iointernal.addr ),
		&buffer->iointernal.addr_len, &buffer->iointernal.ov, 0); 

	// This overlapped operation will always complete unless
	// we get an error code other than ERROR_IO_PENDING.
	if (result && WSAGetLastError() != ERROR_IO_PENDING)
	{
		CAT_FATAL("UDPEndpoint") << "WSARecvFrom error: " << Sockets::GetLastErrorString();
		return false;
	}

	return true;
}

u32 UDPEndpoint::PostReads(s32 limit, s32 reuse_count, BatchSet set)
{
	if (IsShutdown())
	{
		if (reuse_count > 0) ReleaseRef(CAT_REFOBJECT_TRACE, reuse_count);
		return 0;
	}

	// Check if there is a deficiency
	s32 count = (s32)(UDP_SIMULTANEOUS_READS - _buffers_posted);

	// Obey the read limit
	if (count > limit)
		count = limit;

	// If there is no deficiency,
	if (count <= 0)
	{
		if (reuse_count > 0) ReleaseRef(CAT_REFOBJECT_TRACE, reuse_count);
		return 0;
	}

	// If reuse count is more than needed,
	s32 acquire_count = 0, posted_reads = 0, release_count = 0;

	if (reuse_count < count)
	{
		BatchSet allocated;

		// Acquire a batch of buffers
		u32 request_count = count - reuse_count;
		acquire_count = m_recv_allocator->AcquireBatch(allocated, request_count);

		if (acquire_count != request_count)
		{
			count -= request_count - acquire_count;

			CAT_WARN("UDPEndpoint") << "Only able to acquire " << acquire_count << " of " << request_count << " buffers";
		}

		set.PushBack(allocated);

		// Add references for number of expected new posts
		if (acquire_count > 0) AddRef(CAT_REFOBJECT_TRACE, acquire_count);
	}
	else
	{
		release_count = reuse_count - count;
	}

	// For each buffer,
	BatchHead *node;
	for (node = set.head; node && posted_reads < count; node = node->batch_next, ++posted_reads)
		if (!PostRead(static_cast<RecvBuffer*>( node )))
			break;

	// Increment the buffer posted count
	if (posted_reads > 0) Atomic::Add(&_buffers_posted, posted_reads);

	// If not all posts succeeded,
	if (posted_reads < count)
	{
		CAT_WARN("UDPEndpoint") << "Not all read posts succeeded: " << posted_reads << " of " << count;
	}

	// Release excess references
	release_count += count - posted_reads;
	if (release_count > 0) ReleaseRef(CAT_REFOBJECT_TRACE, release_count);

	// If nodes were unused,
	if (node)
	{
		set.head = node;
		m_recv_allocator->ReleaseBatch(set);
	}

	return posted_reads;
}

bool UDPEndpoint::Write(const BatchSet &buffers, u32 count, const NetAddr &addr)
{
	NetAddr::SockAddr out_addr;
	int addr_len;

	// If in the process of shutdown or input invalid,
	if (IsShutdown() || !addr.Unwrap(out_addr, addr_len))
	{
		StdAllocator::ref()->ReleaseBatch(buffers);
		return false;
	}

	u32 write_count = 0;

	AddRef(CAT_REFOBJECT_TRACE, count);

	for (BatchHead *next, *node = buffers.head; node; node = next)
	{
		next = node->batch_next;
		SendBuffer *buffer = static_cast<SendBuffer*>( node );

		WSABUF wsabuf;
		wsabuf.buf = reinterpret_cast<CHAR*>( GetTrailingBytes(buffer) );
		wsabuf.len = buffer->data_bytes;

		CAT_OBJCLR(buffer->iointernal.ov);
		buffer->iointernal.io_type = IOTYPE_UDP_SEND;

		CAT_WARN("UDPEndpoint") << "Posting datagram: " << cat::HexDumpString(wsabuf.buf, wsabuf.len);

		// Fire off a WSASendTo() and forget about it
		int result = WSASendTo(GetSocket(), &wsabuf, 1, 0, 0,
			reinterpret_cast<const sockaddr*>( &out_addr ),
			addr_len, &buffer->iointernal.ov, 0);

		// This overlapped operation will always complete unless
		// we get an error code other than ERROR_IO_PENDING.
		if (result && WSAGetLastError() != ERROR_IO_PENDING)
		{
			CAT_WARN("UDPEndpoint") << "WSASendTo error: " << Sockets::GetLastErrorString();

			m_udp_send_allocator->ReleaseBatch(node);
			ReleaseRef(CAT_REFOBJECT_TRACE);
			continue;
		}

		++write_count;
	}

	PostReads(UDP_READ_POST_LIMIT);

	return count == write_count;
}

bool UDPEndpoint::Write(u8 *data, u32 data_bytes, const NetAddr &addr)
{
	SendBuffer *buffer = SendBuffer::Promote(data);
	buffer->data_bytes = data_bytes;
	return Write(buffer, 1, addr);
}

void UDPEndpoint::SetRemoteAddress(RecvBuffer *buffer)
{
	buffer->addr.Wrap(buffer->iointernal.addr);
}


//// Event Completion

void UDPEndpoint::ReleaseRecvBuffers(BatchSet buffers, u32 count)
{
	if (buffers.head)
		PostReads(UDP_READ_POST_LIMIT, count, buffers);
}

void UDPEndpoint::OnRecvCompletion(const BatchSet &buffers, u32 count)
{
	// Subtract the number of buffers completed from the total posted
	Atomic::Add(&_buffers_posted, 0 - count);

	// If reads completed during shutdown,
	if (IsShutdown())
	{
		// Just release the read buffers
		m_recv_allocator->ReleaseBatch(buffers);

		ReleaseRef(CAT_REFOBJECT_TRACE, count);

		return;
	}

	// Notify derived class about new buffers
	OnRecvRouting(buffers);

	PostReads(UDP_SIMULTANEOUS_READS);
}
