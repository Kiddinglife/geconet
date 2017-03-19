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

#ifndef CAT_NET_UDP_ENDPOINT_HPP
#define CAT_NET_UDP_ENDPOINT_HPP

#include <cat/net/Sockets.hpp>
#include <cat/lang/RefObject.hpp>
#include <cat/mem/IAllocator.hpp>

/*
	To get maximum performance from the UDP sockets, be sure to adjust your
	registry settings:

	HKLM\System\CurrentControlSet\Services\Afd\Parameters
	ADD REG_DWORD KEY FastSendDatagramThreshold
	Set it to 1500
*/

/*
	ICMP Unreachable

	When an ICMP unreachable message arrives, it will cause a read to
	complete with zero data bytes.

	This is indistinguishable from a socket close event.  A server
	will not want to accept unreachable messages.
*/

namespace cat {


class IOLayer;
struct RecvBuffer;
struct SendBuffer;


// Number of IO outstanding on a UDP endpoint
static const u32 SIMULTANEOUS_READS = 128;


// Object that represents a UDP endpoint bound to a single port
class CAT_EXPORT UDPEndpoint : public WatchedRefObject
{
	friend class UDPReadThread;
	friend class UDPWriteThread;

	IOLayer *_iolayer;
	Socket _socket;
	Port _port;
	bool _ipv6;

	Mutex _write_lock;
	BatchSet _write_buffers;
	WaitableFlag _write_flag;

	void ProcessReads();
	void ProcessWrites();

public:
    UDPEndpoint();
    virtual ~UDPEndpoint();

	CAT_INLINE bool Valid() { return _socket != SOCKET_ERROR; }
	CAT_INLINE Socket GetSocket() { return _socket; }
    Port GetPort();
	CAT_INLINE Port GetCachedPort() { return _port; }

	// Is6() result is only valid AFTER Bind()
	CAT_INLINE bool Is6() { return _ipv6; }

    // For servers: Bind() with ignoreUnreachable = true ((default))
    // For clients: Bind() with ignoreUnreachable = false and call this
    //              after the first packet from the server is received.
    bool IgnoreUnreachable();

	// Disabled by default; useful for MTU discovery
	bool DontFragment(bool df = true);

	bool Bind(IOLayer *iolayer, bool onlySupportIPv4, Port port = 0, bool ignoreUnreachable = true, int kernelReceiveBufferBytes = 0);

	// If Is6() == true, the address must be promoted to IPv6
	// before calling using addr.PromoteTo6()
	// This function takes approximately 1 ms per ~20 buffers
	bool Write(const BatchSet &buffers, u32 count, const NetAddr &addr);

	CAT_INLINE bool Write(u8 *data, u32 data_bytes, const NetAddr &addr);

	// When done with read buffers, call this function to add them back to the available pool
	void ReleaseRecvBuffers(BatchSet buffers, u32 count);

protected:
	CAT_INLINE IOLayer *GetIOLayer() { return _iolayer; }

	CAT_INLINE void SetRemoteAddress(RecvBuffer *buffer);

	virtual void OnShutdownRequest();
	virtual bool OnZeroReferences();

	virtual void OnReadRouting(const BatchSet &buffers) = 0;
};


} // namespace cat

#endif // CAT_NET_UDP_ENDPOINT_HPP
