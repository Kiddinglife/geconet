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

#ifndef CAT_SOCKETS_HPP
#define CAT_SOCKETS_HPP

#include <cat/lang/RefSingleton.hpp>
#include <string>

#if defined(CAT_OS_WINDOWS)
# include <WS2tcpip.h>
#else
# include <unistd.h>
#endif

/*
	Any portable socket functionality belongs in this module.

	Classes like UDPEndpoint provide a full wrapper that also does I/O,
	which is platform-dependent.

	OS socket layer startup/cleanup code is completely hidden from the library
	user thanks to the Sockets RefSingleton.  It is only referenced internally,
	so that the user doesn't even need to know about it.
*/

namespace cat {


//// Basic definitions

#define CAT_LOOPBACK_IPV4 "127.0.0.1"
#define CAT_LOOPBACK_IPV6 "::1"

typedef u16 Port;

#if defined(CAT_OS_WINDOWS)
	typedef SOCKET SocketHandle;
	CAT_INLINE bool CloseSocketHandle(SocketHandle s) { return !closesocket(s); }
#else
	typedef int SocketHandle;
	static const SocketHandle INVALID_SOCKET = -1;
	static const int SOCKET_ERROR = -1;
	CAT_INLINE bool CloseSocketHandle(Socket s) { return !close(s); }
#endif


//// Address

#pragma pack(push)
#pragma pack(1)

// Base version of NetAddr that has no ctors so that it can be used in a union
struct CAT_EXPORT UNetAddr
{
	union
	{
		u8 v6_bytes[16];
		u16 v6_words[8];
		u64 v6[2];
		struct {
			u32 v4;
			u32 v4_padding[3];
		};
	} _ip; // Network order

	union
	{
		u32 _valid;
		struct {
			Port _port; // Host order
			u16 _family; // Host order
		};
	};

	static const int IP4_BYTES = 4;
	static const int IP6_BYTES = 16;

	typedef sockaddr_in6 SockAddr;

	// These functions are designed to support when this object overlaps the
	// memory space of the input
	bool Wrap(const sockaddr_in &addr);
	bool Wrap(const sockaddr *addr);

	CAT_INLINE bool Wrap(const sockaddr_in6 &addr)
	{
		// May be IPv4 that has been stuffed into an IPv6 sockaddr
		return Wrap(reinterpret_cast<const sockaddr*>( &addr ));
	}

	// Promote an IPv4 address to an IPv6 address if needed
	bool PromoteTo6();

	// Check if an IPv6 address can be demoted to IPv4 address
	bool CanDemoteTo4() const;

	// Demote an IPv6 address to an IPv4 address if possible,
	// otherwise marks address as invalid and returns false
	bool DemoteTo4();

	CAT_INLINE bool Convert(bool To6) { if (To6) return PromoteTo6(); else return DemoteTo4(); }

	CAT_INLINE bool Valid() const { return _valid != 0; }
	CAT_INLINE bool Is6() const { return _family == AF_INET6; }

	CAT_INLINE const u32 GetIP4() const { return _ip.v4; }
	CAT_INLINE const u64 *GetIP6() const { return _ip.v6; }

	CAT_INLINE Port GetPort() const { return _port; }
	CAT_INLINE void SetPort(Port port) { _port = port; }

	// Mark the address as invalid
	CAT_INLINE void Invalidate() { _valid = 0; }

	bool EqualsIPOnly(const UNetAddr &addr) const;

	CAT_INLINE bool operator==(const UNetAddr &addr) const
	{
		// Check port
		if (addr._port != _port)
			return false; // "not equal"

		// Tail call IP checking function
		return EqualsIPOnly(addr);
	}

	CAT_INLINE bool operator!=(const UNetAddr &addr) const
	{
		return !(*this == addr);
	}

	// To validate external input; don't want clients connecting
	// to their local network instead of the actual game server.
	bool IsInternetRoutable();

	// Returns true if the address is routable on local network or Internet.
	// Returns false if the address is IPv4 multicast, loopback, or weird.
	bool IsRoutable();

	bool SetFromString(const char *ip_str, Port port = 0);
	std::string IPToString() const;

	bool SetFromRawIP(const u8 *ip_binary, int bytes);
	bool SetFromDotDecimals(int a, int b, int c, int d, Port port = 0);

	bool Unwrap(SockAddr &addr, int &addr_len, bool PromoteToIP6 = false) const;
};

// Wrapper for IPv4 and IPv6 addresses
struct CAT_EXPORT NetAddr : UNetAddr
{
	CAT_INLINE NetAddr() {}

	CAT_INLINE NetAddr(const char *ip_str, Port port = 0)
	{
		// Invoke SetFromString(), ignoring the return value because
		// it will leave the object in an invalid state if needed.
		SetFromString(ip_str, port);
	}
	CAT_INLINE NetAddr(const sockaddr_in6 &addr)
	{
		Wrap(addr);
	}
	CAT_INLINE NetAddr(const sockaddr_in &addr)
	{
		Wrap(addr);
	}
	CAT_INLINE NetAddr(const sockaddr *addr)
	{
		Wrap(addr);
	}
	CAT_INLINE NetAddr(int a, int b, int c, int d, Port port = 0)
	{
		// Invoke SetFromDotDecimals(), ignoring the return value because
		// it will leave the object in an invalid state if needed.
		SetFromDotDecimals(a, b, c, d, port);
	}

	CAT_INLINE NetAddr(const NetAddr &addr)
	{
		_valid = addr._valid;
		_ip.v6[0] = addr._ip.v6[0];
		_ip.v6[1] = addr._ip.v6[1];
	}

	CAT_INLINE NetAddr &operator=(const NetAddr &addr)
	{
		_valid = addr._valid;
		_ip.v6[0] = addr._ip.v6[0];
		_ip.v6[1] = addr._ip.v6[1];
		return *this;
	}
};

#pragma pack(pop)


//// Socket

class CAT_EXPORT Socket
{
	bool _support4, _support6;
	Port _port;
	SocketHandle _s;

public:
	Socket();
	virtual ~Socket();

	// The RequestIPv6 flag is a suggestion.  Use SupportsIPv6() to check success.  The RequireIPv4 flag is always respected.
	// NOTE: Socket only supports IPv6 operations after Bind() completes
	bool Create(int type, int protocol, bool RequestIPv6 = true, bool RequireIPv4 = true);

	// Call these before binding:

	bool SetSendBufferSize(int bytes);
	bool SetRecvBufferSize(int bytes);

	bool Bind(Port port);

	// Call these after binding:

	CAT_INLINE bool Valid() { return _s != INVALID_SOCKET; }
	CAT_INLINE bool SupportsIPv4() { return _support4; }
	CAT_INLINE bool SupportsIPv6() { return _support6; }
	CAT_INLINE SocketHandle GetSocket() { return _s; }

	Port GetPort();

	void Close();
};


//// UDP Socket

// Adds functions only used for UDP sockets
class CAT_EXPORT UDPSocket : public Socket
{
public:
	CAT_INLINE virtual ~UDPSocket() {}

	CAT_INLINE bool Create(bool RequestIPv6 = true, bool RequireIPv4 = true) { return Socket::Create(SOCK_DGRAM, IPPROTO_UDP, RequestIPv6, RequireIPv4); }

	// Call these before binding:

	// Disabled by default; ignore ICMP unreachable errors
	bool IgnoreUnreachable(bool ignore = true);

	// Call these after binding:

	// Disabled by default; useful for MTU discovery
	bool DontFragment(bool df = true);
};


//// TCP Socket

// Adds functions only used for TCP sockets
class CAT_EXPORT TCPSocket : public Socket
{
public:
	CAT_INLINE virtual ~TCPSocket() {}

	CAT_INLINE bool Create(bool RequestIPv6 = true, bool RequireIPv4 = true) { return Socket::Create(SOCK_STREAM, IPPROTO_TCP, RequestIPv6, RequireIPv4); }
};


// Internal class
class CAT_EXPORT Sockets : public RefSingleton<Sockets>
{
	bool OnInitialize();
	void OnFinalize();

public:
	// Will unset SupportIPv6 flag if it was unable to support IPv6.  Always respects SupportIPv4 flag.
	// Always creates an overlapped socket in Windows.
	bool Create(int type, int protocol, bool RequireIPv4, bool &SupportIPv6, SocketHandle &out_s);

	static bool AllowIPv4OnIPv6Socket(SocketHandle s);
	static bool NetBind(SocketHandle s, Port port, bool SupportIPv6);
	static Port GetBoundPort(SocketHandle s);

	// Returns a string describing the last error
	static std::string GetLastErrorString();
	static std::string GetErrorString(int code);
};


} // namespace cat

#endif // CAT_SOCKETS_HPP
