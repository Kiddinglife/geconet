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

#include <cat/iocp/UDPEndpoint.hpp>
#include <cat/io/Logging.hpp>
#include <cat/io/Settings.hpp>
#include <cat/io/IOLayer.hpp>
#include <cat/net/Buffers.hpp>
using namespace std;
using namespace cat;

#if defined(CAT_OS_WINDOWS)

#include <MSWSock.h>

// Add missing definition for MinGW
#if !defined(SIO_UDP_CONNRESET)
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR,12)
#endif

#endif


//// UDPEndpoint

void UDPEndpoint::OnShutdownRequest()
{
	if (_socket != SOCKET_ERROR)
	{
		CloseSocket(_socket);
		_socket = SOCKET_ERROR;
	}
}

bool UDPEndpoint::OnZeroReferences()
{
	return true;
}

UDPEndpoint::UDPEndpoint()
{
    _port = 0;
    _socket = SOCKET_ERROR;
}

UDPEndpoint::~UDPEndpoint()
{
    if (_socket != SOCKET_ERROR)
        CloseSocket(_socket);
}

Port UDPEndpoint::GetPort()
{
	// Get bound port if it was random
	if (_port == 0)
	{
		_port = GetBoundPort(_socket);

		if (!_port)
		{
			WARN("UDPEndpoint") << "Unable to get own address: " << SocketGetLastErrorString();
			return 0;
		}
	}

	return _port;
}

bool UDPEndpoint::IgnoreUnreachable()
{
    // FALSE = Disable behavior where, after receiving an ICMP Unreachable message,
    // WSARecvFrom() will fail.  Disables ICMP completely; normally this is good.
    // But when you're writing a client endpoint, you probably want to listen to
    // ICMP Port Unreachable or other failures until you get the first packet.
    // After that call IgnoreUnreachable() to avoid spoofed ICMP exploits.

	if (_socket == SOCKET_ERROR)
		return false;

#if defined(CAT_OS_WINDOWS)

	DWORD dwBytesReturned = 0;
    BOOL bNewBehavior = FALSE;
    if (WSAIoctl(_socket, SIO_UDP_CONNRESET, &bNewBehavior,
				 sizeof(bNewBehavior), 0, 0, &dwBytesReturned, 0, 0) == SOCKET_ERROR)
	{
		WARN("UDPEndpoint") << "Unable to ignore ICMP Unreachable: " << SocketGetLastErrorString();
		return false;
	}
	
#else

#error "TODO"

#endif

	return true;
}

bool UDPEndpoint::DontFragment(bool df)
{
	if (_socket == SOCKET_ERROR)
		return false;

	DWORD bNewBehavior = df ? TRUE : FALSE;
	if (setsockopt(_socket, IPPROTO_IP, IP_DONTFRAGMENT, (const char*)&bNewBehavior, sizeof(bNewBehavior)))
	{
		WARN("UDPEndpoint") << "Unable to change don't fragment bit: " << SocketGetLastErrorString();
		return false;
	}

	return true;
}

bool UDPEndpoint::Bind(IOLayer *iolayer, bool onlySupportIPv4, Port port, bool ignoreUnreachable, int rcv_buffsize)
{
	// Create an unbound, overlapped UDP socket for the endpoint
    Socket s;
	if (!CreateSocket(SOCK_DGRAM, IPPROTO_UDP, true, s, onlySupportIPv4))
	{
		FATAL("UDPEndpoint") << "Unable to create a UDP socket: " << SocketGetLastErrorString();
		return false;
    }
	_ipv6 = !onlySupportIPv4;

	// Set SO_SNDBUF to zero for a zero-copy network stack (we maintain the buffers)
	int snd_buffsize = 0;
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&snd_buffsize, sizeof(snd_buffsize)))
	{
		WARN("UDPEndpoint") << "Unable to zero the send buffer: " << SocketGetLastErrorString();
		CloseSocket(s);
		return false;
	}

	// Set SO_RCVBUF as requested (often defaults are far too low for UDP servers or UDP file transfer clients)
	if (rcv_buffsize < 64000) rcv_buffsize = 64000;
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&rcv_buffsize, sizeof(rcv_buffsize)))
	{
		WARN("UDPEndpoint") << "Unable to setsockopt SO_RCVBUF " << rcv_buffsize << ": " << SocketGetLastErrorString();
		CloseSocket(s);
		return false;
	}

	_socket = s;

	// Ignore ICMP Unreachable
    if (ignoreUnreachable) IgnoreUnreachable();

    // Bind the socket to a given port
    if (!NetBind(s, port, onlySupportIPv4))
    {
        FATAL("UDPEndpoint") << "Unable to bind to port: " << SocketGetLastErrorString();
        CloseSocket(s);
        _socket = SOCKET_ERROR;
        return false;
    }

	_port = port;
	_iolayer = iolayer;

	// Add reference to keep object alive until function returns
	AddRef();
	_buffers_posted = SIMULTANEOUS_READS;

	// Associate with IOThreads
	if (!iolayer->GetIOThreads()->Associate(this))
	{
		FATAL("UDPEndpoint") << "Unable to associate with IOThreads";
		CloseSocket(s);
		_socket = SOCKET_ERROR;
		ReleaseRef(); // Release temporary references keeping the object alive until function returns
		return false;
	}

	// Now that we're in the IO layer, start watching the object for shutdown
	iolayer->Watch(this);

    INFO("UDPEndpoint") << "Open on port " << GetPort();

	ReleaseRef(); // Release temporary reference keeping the object alive until function returns
    return true;
}


//// Begin Event

bool UDPEndpoint::Write(const BatchSet &buffers, u32 count, const NetAddr &addr)
{
	NetAddr::SockAddr out_addr;
	int addr_len;

	// If in the process of shutdown or input invalid,
	if (IsShutdown() || !addr.Unwrap(out_addr, addr_len))
	{
		StdAllocator::ii->ReleaseBatch(buffers);
		return false;
	}

	// For each buffer,
	for (BatchHead *node = buffers.head; node; node = node->batch_next)
	{
		SendBuffer *buffer = reinterpret_cast<SendBuffer*>( node );

		// Fill in the address
		buffer->iointernal.addr = out_addr;
		buffer->iointernal.addr_len = addr_len;
	}

	_write_lock.Enter();
	_write_buffers.PushBack(buffers);
	_write_lock.Leave();

	return true;
}

CAT_INLINE bool UDPEndpoint::Write(u8 *data, u32 data_bytes, const NetAddr &addr)
{
	SendBuffer *buffer = SendBuffer::Promote(data);
	buffer->SetBytes(data_bytes);
	return Write(buffer, 1, addr);
}

CAT_INLINE void UDPEndpoint::SetRemoteAddress(RecvBuffer *buffer)
{
	buffer->addr.Wrap(buffer->iointernal.addr);
}


//// Event Completion

void UDPEndpoint::ReleaseRecvBuffers(BatchSet buffers, u32 count)
{
	if (!buffers.head) return;

	_iolayer->GetIOThreads()->GetRecvAllocator()->ReleaseBatch(buffers);
}

void UDPEndpoint::ProcessReads()
{
	BufferAllocator *allocator = _iolayer->GetRecvAllocator();

	const u32 READ_BATCH_SIZE = 32;

	for (;;)
	{
		BatchSet set;
		u32 acquired = allocator->AcquireBatch(set, READ_BATCH_SIZE);

		if (acquired == 0)
		{
			WARN("UDPEndpoint") << "Out of memory acquiring read buffers";
			
			//
		}

		// For each buffer,
		for (BatchHead *node = set.head; node; node = node->batch_next)
		{
		}

		RecvBuffer *buffer = reinterpret_cast<RecvBuffer*>( set.head );
		u8 *data = GetTrailingBytes(buffer);

		buffer->iointernal.addr_len = sizeof(buffer->iointernal.addr);

		if (recvfrom(_socket, data, IOTHREADS_BUFFER_READ_BYTES,
					 &buffer->iointernal.addr, &buffer->iointernal.addr_len) == SOCKET_ERROR)
		{
			INFO("UDPEndpoint") << "Read processing halted: recvfrom() failure " << SocketGetLastErrorString();
			return;
		}

		// Notify derived class about new buffers
		OnReadRouting(buffers);
	}
}

void UDPEndpoint::ProcessWrites()
{
	for (;;)
	{
		_write_flag.Wait();

		if (IsShutdown())
		{
			INFO("UDPEndpoint") << "Write processing halted: Flagged for shutdown";
			return;
		}

		// Steal the write buffers
		_write_lock.Enter();
		BatchSet write_buffers = _write_buffers;
		_write_buffers.Clear();
		_write_lock.Leave();

		// For each buffer,
		for (BatchHead *node = write_buffers.head; node; node = node->next)
		{
			SendBuffer *buffer = reinterpret_cast<SendBuffer*>( node );
			u8 *data = GetTrailingBytes(buffer);
			u32 bytes = buffer->GetBytes();

			// Transmit it without checking return value
			sendto(_socket, &buffer->iointernal.addr, &buffer->iointernal.addr_len);
		}

		StdAllocator::ii->ReleaseBatch(write_buffers);
	}
}
