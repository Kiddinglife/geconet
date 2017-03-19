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

#include <cat/net/Sockets.hpp>
#include <sstream>
using namespace std;
using namespace cat;

#if defined(CAT_COMPILER_MSVC)
#pragma comment(lib, "ws2_32.lib")
#endif

// Fix missing definitions (mainly for MinGW)
#if !defined(IPV6_V6ONLY)
#define IPV6_V6ONLY 27
#endif
#if !defined(SIO_UDP_CONNRESET)
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR,12)
#endif


//// Socket

Socket::Socket()
{
	_s = INVALID_SOCKET;
}

Socket::~Socket()
{
	Close();
}

Port Socket::GetPort()
{
	if (_port == 0)
		_port = Sockets::GetBoundPort(_s);

	return _port;
}

bool Socket::Create(int type, int protocol, bool SupportIPv6, bool SupportIPv4)
{
	Close();

	SocketHandle s;

	if (!Sockets::ref()->Create(type, protocol, SupportIPv4, SupportIPv6, s))
	{
		CAT_FATAL("Socket") << "Unable to create a socket: " << Sockets::GetLastErrorString();
		return false;
	}

	_s = s;
	_port = 0;
	_support4 = SupportIPv4;
	_support6 = SupportIPv6;
	return true;
}

bool Socket::SetSendBufferSize(int bytes)
{
	int snd_buffsize = bytes;
	if (setsockopt(_s, SOL_SOCKET, SO_SNDBUF, (char*)&snd_buffsize, sizeof(snd_buffsize)))
	{
		CAT_WARN("Socket") << "Unable to zero the send buffer: " << Sockets::GetLastErrorString();
		return false;
	}

	return true;
}

bool Socket::SetRecvBufferSize(int bytes)
{
	int rcv_buffsize = bytes;
	if (setsockopt(_s, SOL_SOCKET, SO_RCVBUF, (char*)&rcv_buffsize, sizeof(rcv_buffsize)))
	{
		CAT_WARN("Socket") << "Unable to setsockopt SO_RCVBUF " << rcv_buffsize << ": " << Sockets::GetLastErrorString();
		return false;
	}

	return true;
}

bool Socket::Bind(Port port)
{
	// Bind the socket to a given port
	if (!Sockets::NetBind(_s, port, _support6))
	{
		CAT_FATAL("Socket") << "Unable to bind to port: " << Sockets::GetLastErrorString();
		CloseSocketHandle(_s);
		_s = INVALID_SOCKET;
		return false;
	}

	return true;
}

void Socket::Close()
{
	if (_s != INVALID_SOCKET)
		CloseSocketHandle(_s);
}


//// UDP Socket

bool UDPSocket::IgnoreUnreachable(bool ignore)
{
	// FALSE = Disable behavior where, after receiving an ICMP Unreachable message,
	// WSARecvFrom() will fail.  Disables ICMP completely; normally this is good.
	// But when you're writing a client endpoint, you probably want to listen to
	// ICMP Port Unreachable or other failures until you get the first packet.
	// After that call IgnoreUnreachable() to avoid spoofed ICMP exploits.

	DWORD behavior = ignore ? FALSE : TRUE;
	if (ioctlsocket(GetSocket(), SIO_UDP_CONNRESET, &behavior) == SOCKET_ERROR)
	{
		CAT_WARN("UDPSocket") << "Unable to ignore ICMP Unreachable: " << Sockets::GetLastErrorString();
		return false;
	}

	return true;
}

bool UDPSocket::DontFragment(bool df)
{
	DWORD behavior = df ? TRUE : FALSE;
	if (setsockopt(GetSocket(), IPPROTO_IP, IP_DONTFRAGMENT, (const char*)&behavior, sizeof(behavior)))
	{
		CAT_WARN("UDPSocket") << "Unable to change don't fragment bit: " << Sockets::GetLastErrorString();
		return false;
	}

	return true;
}


//// Sockets

CAT_REF_SINGLETON(Sockets);

bool Sockets::OnInitialize()
{
#if defined(CAT_OS_WINDOWS)
	WSADATA wsaData;

	// Request Winsock 2.2
	if (NO_ERROR != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		CAT_FATAL("Sockets") << "Unable to initialize Winsock 2.2";
		return false;
	}
#endif

	return true;
}

void Sockets::OnFinalize()
{
#if defined(CAT_OS_WINDOWS)
	WSACleanup();
#endif
}

bool Sockets::AllowIPv4OnIPv6Socket(SocketHandle s)
{
	int on = 0;

	// Turn off IPV6_V6ONLY so that IPv4 is able to communicate with the socket also
	return 0 == setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&on, sizeof(on));
}

bool Sockets::Create(int type, int protocol, bool RequireIPv4, bool &SupportIPv6, SocketHandle &out_s)
{
	// If IPv6 support requested,
	if (SupportIPv6)
	{
		// Attempt to create an IPv6 socket
#if defined(CAT_OS_WINDOWS)
		SocketHandle s = WSASocket(AF_INET6, type, protocol, 0, 0, WSA_FLAG_OVERLAPPED);
#else
		SocketHandle s = socket(AF_INET6, type, protocol);
#endif

		// If the socket was created,
		if (s != INVALID_SOCKET)
		{
			// If does not need to support IPv4 or able to disable IPv6-only mode,
			if (!RequireIPv4 || AllowIPv4OnIPv6Socket(s))
			{
				//SupportIPv6 = true;
				out_s = s;
				return true;
			}

			// If IPv4 cannot be supported, just create an IPv4 socket
			CloseSocketHandle(s);
		}
	}

	// Attempt to create an IPv4 socket
#if defined(CAT_OS_WINDOWS)
	SocketHandle s = WSASocket(AF_INET, type, protocol, 0, 0, WSA_FLAG_OVERLAPPED);
#else
	SocketHandle s = socket(AF_INET, type, protocol);
#endif

	// If the socket was created,
	if (s == INVALID_SOCKET)
		return false;

	SupportIPv6 = false;
	out_s = s;
	return true;
}

bool Sockets::NetBind(SocketHandle s, Port port, bool SupportIPv6)
{
	if (s == SOCKET_ERROR)
		return false;

	// Bind socket to port
	sockaddr_in6 addr;
	int addr_len;

	// If IPv6 support is enabled,
	if (SupportIPv6)
	{
		// Fill in IPv6 sockaddr
		CAT_OBJCLR(addr);
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_any;
		addr.sin6_port = htons(port);

		addr_len = sizeof(sockaddr_in6);
	}
	else
	{
		// Fill in IPv4 sockaddr within IPv6 addr
		sockaddr_in *addr4 = reinterpret_cast<sockaddr_in*>( &addr );

		addr4->sin_family = AF_INET;
		addr4->sin_addr.S_un.S_addr = INADDR_ANY;
		addr4->sin_port = htons(port);
		CAT_OBJCLR(addr4->sin_zero);

		addr_len = sizeof(sockaddr_in);
	}

	// Attempt to bind
	return 0 == bind(s, reinterpret_cast<sockaddr*>( &addr ), addr_len);
}

Port Sockets::GetBoundPort(SocketHandle s)
{
	sockaddr_in6 addr;
	int namelen = sizeof(addr);

	// If socket name cannot be determined,
	if (getsockname(s, reinterpret_cast<sockaddr*>( &addr ), &namelen))
		return 0;

	// Port is placed in the same location for IPv4 and IPv6
	return ntohs(addr.sin6_port);
}

std::string Sockets::GetLastErrorString()
{
	int code;

#if defined(CAT_OS_WINDOWS)
	code = WSAGetLastError();
#else
	code = errno;
#endif

	return GetErrorString(code);
}

std::string Sockets::GetErrorString(int code)
{
	switch (code)
	{
#if defined(CAT_OS_WINDOWS)
	case WSAEADDRNOTAVAIL:         return "[Address not available]";
	case WSAEADDRINUSE:            return "[Address is in use]";
	case WSANOTINITIALISED:        return "[Winsock not initialized]";
	case WSAENETDOWN:              return "[Network is down]";
	case WSAEINPROGRESS:           return "[Operation in progress]";
	case WSA_NOT_ENOUGH_MEMORY:    return "[Out of memory]";
	case WSA_INVALID_HANDLE:       return "[Invalid handle]";
	case WSA_INVALID_PARAMETER:    return "[Invalid parameter]";
	case WSAEFAULT:                return "[Fault]";
	case WSAEINTR:                 return "[Interrupted]";
	case WSAEINVAL:                return "[Invalid]";
	case WSAEISCONN:               return "[Is connected]";
	case WSAENETRESET:             return "[Network reset]";
	case WSAENOTSOCK:              return "[Parameter is not a socket]";
	case WSAEOPNOTSUPP:            return "[Operation not supported]";
	case WSAESOCKTNOSUPPORT:       return "[Socket type not supported]";
	case WSAESHUTDOWN:             return "[Shutdown]";
	case WSAEWOULDBLOCK:           return "[Operation would block]";
	case WSAEMSGSIZE:              return "[Message size]";
	case WSAETIMEDOUT:             return "[Operation timed out]";
	case WSAECONNRESET:            return "[Connection reset]";
	case WSAENOTCONN:              return "[Socket not connected]";
	case WSAEDISCON:               return "[Disconnected]";
	case WSAENOBUFS:               return "[No buffer space available]";
	case ERROR_IO_PENDING:         return "[IO operation will complete in IOCP worker thread]";
	case WSA_OPERATION_ABORTED:    return "[Operation aborted]";
	case ERROR_CONNECTION_ABORTED: return "[Connection aborted locally]";
	case ERROR_NETNAME_DELETED:    return "[Socket was already closed]";
	case ERROR_PORT_UNREACHABLE:   return "[Destination port is unreachable]";
	case ERROR_MORE_DATA:          return "[More data is available]";
#else
	case EPERM:		return "[Operation not permitted]";
	case ENOENT:	return "[No such file or directory]";
	case ESRCH:		return "[No such process]";
	case EINTR:		return "[Interrupted system call]";
	case EIO:		return "[I/O error]";
	case ENXIO:		return "[No such device or address]";
	case E2BIG:		return "[Arg list too long]";
	case ENOEXEC:	return "[Exec format error]";
	case EBADF:		return "[Bad file number]";
	case ECHILD:	return "[No child processes]";
	case EAGAIN:	return "[Try again]";
	case ENOMEM:	return "[Out of memory]";
#endif
	};

	ostringstream oss;
	oss << "[Error code: " << code << " (0x" << hex << code << ")]";
	return oss.str();
}


//// UNetAddr

bool UNetAddr::Wrap(const sockaddr_in &addr)
{
	// Can only fit IPv4 in this address structure
	if (addr.sin_family == AF_INET)
	{
		Port port = ntohs(addr.sin_port);
		u32 ip = addr.sin_addr.S_un.S_addr;

		_family = AF_INET;
		_port = port;
		_ip.v4 = ip;
		return true;
	}
	else
	{
		_valid = 0;
		return false;
	}
}

bool UNetAddr::Wrap(const sockaddr *addr)
{
	u16 family = addr->sa_family;

	// Based on the family of the sockaddr,
	if (family == AF_INET)
	{
		const sockaddr_in *addr4 = reinterpret_cast<const sockaddr_in*>( addr );
		Port port = ntohs(addr4->sin_port);
		u32 ip = addr4->sin_addr.S_un.S_addr;

		_family = AF_INET;
		_port = port;
		_ip.v4 = ip;
		return true;
	}
	else if (family == AF_INET6)
	{
		const sockaddr_in6 *addr6 = reinterpret_cast<const sockaddr_in6*>( addr );
		Port port = ntohs(addr6->sin6_port);

		memmove(_ip.v6, &addr6->sin6_addr, sizeof(_ip.v6));

		_family = AF_INET6;
		_port = port;
		return true;
	}
	else
	{
		// Other address families not supported, so make object invalid
		_valid = 0;
		return false;
	}
}

bool UNetAddr::EqualsIPOnly(const UNetAddr &addr) const
{
	// If one is IPv4 and the other is IPv6,
	if (_family != addr._family)
		return false; // "not equal"

	// Compare IP addresses based on address family:

	if (_family == AF_INET)
	{
		// Compare 32-bit IPv4 addresses
		return _ip.v4 == addr._ip.v4;
	}
	else if (_family == AF_INET6)
	{
		// Compare 128-bit IPv6 addresses
		return 0 == ((_ip.v6[0] ^ addr._ip.v6[0]) |
					 (_ip.v6[1] ^ addr._ip.v6[1]));
	}
	else
	{
		// If either address is invalid,
		return false; // "not equal"
	}
}

bool UNetAddr::IsInternetRoutable()
{
	if (_family == AF_INET)
	{
		u32 ipv4 = ntohl(_ip.v4);

		switch ((u8)(ipv4 >> 24))
		{
		case   0: // This Net: 0.0.0.0
		case  10: // Private: 10/8
		case 127: // Loopback: 127/8
		case 255: // Broadcast: 255.255.255.255
			return false;

		case 192: // Private: 192.168/16
			return ((ipv4 & 0xFFFF0000) != 0xC0A80000);

		case 172: // Private: 172.16.0.0 ... 172.31.0.0
			{
				u8 b = (u8)(ipv4 >> 16);

				return b < 16 || b > 31;
			}

		default:
			// Otherwise it is Internet routable
			return true;
		}
	}
	else if (_family == AF_INET6)
	{
		// Site-local addresses (fec0:/16) [may be deprecated now...]
		if (_ip.v6_words[0] == 0xfec0) return false;

		// Link-local addresses (fe80:/16)
		if (_ip.v6_words[0] == 0xfe80) return false;

		// Unique local addresses (fc00:/7)
		if ((_ip.v6_words[0] & 0xfe00) == 0xfc00) return false;

		// Loopback address (::1)
		if (_ip.v6[0] == 0 && _ip.v6_words[4] == 0 &&
			_ip.v6_words[5] == 0 && _ip.v6_words[6] == 0 &&
			_ip.v6_bytes[14] == 0 && _ip.v6_bytes[15] == 1)
		{
			return false;
		}

		return true;
	}
	else
	{
		// Catches invalid addresses
		return false;
	}
}

bool UNetAddr::IsRoutable()
{
	if (_family == AF_INET)
	{
		u32 ipv4 = ntohl(_ip.v4);

		switch ((u8)(ipv4 >> 24))
		{
		case   0: // This Net: 0.0.0.0
		case 127: // Loopback: 127/8
		case 255: // Broadcast: 255.255.255.255
			return false;

		default:
			// Otherwise it is routable
			return true;
		}
	}
	else if (_family == AF_INET6)
	{
		if (_ip.v6[0] == 0)
		{
			// Invalid address (::)
			if (_ip.v6[1] == 0)
			{
				return false;
			}

			// Loopback address (::1)
			if (_ip.v6_bytes[15] == 1 &&
				_ip.v6_words[4] == 0 && _ip.v6_words[5] == 0 &&
				_ip.v6_words[6] == 0 && _ip.v6_bytes[14] == 0)
			{
				return false;
			}
		}

		return true;
	}
	else
	{
		// Catches invalid addresses
		return false;
	}
}

bool UNetAddr::SetFromString(const char *ip_str, Port port)
{
	// Try to convert from IPv6 address first
	sockaddr_in6 addr6;
	int out_addr_len6 = sizeof(addr6);

	if (!WSAStringToAddressA((char*)ip_str, AF_INET6, 0,
							 (sockaddr*)&addr6, &out_addr_len6))
	{
		// Copy address from temporary object
		_family = AF_INET6;
		_port = port;
		memcpy(_ip.v6, &addr6.sin6_addr, sizeof(_ip.v6));
		return true;
	}
	else
	{
		// Try to convert from IPv4 address if that failed
		sockaddr_in addr4;
		int out_addr_len4 = sizeof(addr4);

		if (!WSAStringToAddressA((char*)ip_str, AF_INET, 0,
								 (sockaddr*)&addr4, &out_addr_len4))
		{
			// Copy address from temporary object
			_family = AF_INET;
			_port = port;
			_ip.v4 = addr4.sin_addr.S_un.S_addr;
			return true;
		}
		else
		{
			// Otherwise mark address as invalid and return false
			_valid = 0;
			return false;
		}
	}
}

bool UNetAddr::SetFromRawIP(const u8 *ip_binary, int bytes)
{
	if (bytes == IP4_BYTES)
	{
		const u32 *ipv4 = reinterpret_cast<const u32*>( ip_binary );

		_family = AF_INET;
		_ip.v4 = *ipv4; // Endian agnostic
		// Does not touch port
		return true;
	}
	else if (bytes == IP6_BYTES)
	{
		_family = AF_INET6;
		memcpy(_ip.v6_bytes, ip_binary, IP6_BYTES); // Endian agnostic
		// Does not touch port
		return true;
	}
	else
	{
		// Otherwise mark address as invalid and return false
		_valid = 0;
		return false;
	}
}

bool UNetAddr::SetFromDotDecimals(int a, int b, int c, int d, Port port)
{
	if ((a | b | c | d) & 0xFFFFFF00)
	{
		_valid = 0;
		return false;
	}
	else
	{
		_family = AF_INET;
		_port = port;

		_ip.v4 = htonl((a << 24) | (b << 16) | (c << 8) | d);
		return true;
	}
}

std::string UNetAddr::IPToString() const
{
	if (_family == AF_INET6)
	{
		// Construct an IPv6 sockaddr, with port = 0
		sockaddr_in6 addr6;
		CAT_OBJCLR(addr6);
		addr6.sin6_family = _family;
		memcpy(&addr6.sin6_addr, _ip.v6, sizeof(_ip.v6));

		// Allocate space for address string
		char addr_str6[INET6_ADDRSTRLEN + 32];
		DWORD str_len6 = sizeof(addr_str6);

		// Because inet_ntop() is not supported in Windows XP, only Vista+
		if (SOCKET_ERROR == WSAAddressToStringA((sockaddr*)&addr6, sizeof(addr6),
												0, addr_str6, &str_len6))
			return Sockets::GetLastErrorString();

		return addr_str6;
	}
	else if (_family == AF_INET)
	{
		// Construct an IPv4 sockaddr, with port = 0
		sockaddr_in addr4;
		CAT_OBJCLR(addr4);
		addr4.sin_family = _family;
		addr4.sin_addr.S_un.S_addr = _ip.v4;

		// Allocate space for address string
		char addr_str4[INET_ADDRSTRLEN + 32];
		DWORD str_len4 = sizeof(addr_str4);

		// Because inet_ntop() is not supported in Windows XP, only Vista+
		if (SOCKET_ERROR == WSAAddressToStringA((sockaddr*)&addr4, sizeof(addr4),
												0, addr_str4, &str_len4))
			return Sockets::GetLastErrorString();

		return addr_str4;
	}
	else
	{
		// If protocol family is unrecognized,
		return "[Invalid]";
	}
}

bool UNetAddr::Unwrap(SockAddr &addr, int &addr_len, bool PromoteToIP6) const
{
	if (_family == AF_INET)
	{
		// If the user wants us to unwrap to an IPv6 address,
		if (PromoteToIP6)
		{
			sockaddr_in6 *addr6 = reinterpret_cast<sockaddr_in6*>( &addr );

			CAT_OBJCLR(*addr6);
			addr6->sin6_family = AF_INET6;
			addr6->sin6_port = htons(_port);

			u32 ipv4 = ntohl(_ip.v4);

			// If loopback,
			if ((ipv4 & 0xFF000000) == 0x7F000000)
			{
				addr6->sin6_addr.s6_addr[15] = 1;
			}
			else
			{
				addr6->sin6_addr.s6_addr[10] = 0xFF;
				addr6->sin6_addr.s6_addr[11] = 0xFF;
				addr6->sin6_addr.s6_addr[12] = (u8)(ipv4 >> 24);
				addr6->sin6_addr.s6_addr[13] = (u8)(ipv4 >> 16);
				addr6->sin6_addr.s6_addr[14] = (u8)(ipv4 >> 8);
				addr6->sin6_addr.s6_addr[15] = (u8)(ipv4);
			}

			addr_len = sizeof(sockaddr_in6);
		}
		else
		{
			sockaddr_in *addr4 = reinterpret_cast<sockaddr_in*>( &addr );

			addr4->sin_family = AF_INET;
			addr4->sin_port = htons(_port);
			addr4->sin_addr.S_un.S_addr = _ip.v4;
			CAT_OBJCLR(addr4->sin_zero);

			addr_len = sizeof(sockaddr_in);
		}

		return true;
	}
	else if (_family == AF_INET6)
	{
		sockaddr_in6 *addr6 = reinterpret_cast<sockaddr_in6*>( &addr );

		CAT_OBJCLR(*addr6);
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(_port);
		memcpy(&addr6->sin6_addr, _ip.v6, sizeof(_ip.v6));

		addr_len = sizeof(sockaddr_in6);

		return true;
	}
	else
	{
		return false;
	}
}

bool UNetAddr::PromoteTo6()
{
	if (_family == AF_INET6)
	{
		// Already IPv6
		return true;
	}
	else if (_family == AF_INET)
	{
		_family = AF_INET6;

		u32 ipv4 = ntohl(_ip.v4);

		_ip.v6[0] = 0;

		// If loopback,
		if ((ipv4 & 0xFF000000) == 0x7F000000)
		{
			_ip.v6[1] = 0;
			_ip.v6_bytes[15] = 1;
		}
		else
		{
			_ip.v6_words[4] = 0;
			_ip.v6_words[5] = 0xFFFF;
			_ip.v6_bytes[12] = (u8)(ipv4 >> 24);
			_ip.v6_bytes[13] = (u8)(ipv4 >> 16);
			_ip.v6_bytes[14] = (u8)(ipv4 >> 8);
			_ip.v6_bytes[15] = (u8)(ipv4);
		}

		return true;
	}
	else
	{
		// Already invalid
		return false;
	}
}

bool UNetAddr::CanDemoteTo4() const
{
	if (_family == AF_INET)
	{
		// Already IPv4
		return true;
	}
	else if (_family == AF_INET6)
	{
		if (_ip.v6[0] != 0 || _ip.v6_words[4] != 0)
		{
			return false;
		}
		else if (_ip.v6_words[5] == 0 && _ip.v6_words[6] == 0 &&
			_ip.v6_bytes[14] == 0 && _ip.v6_bytes[15] == 1)
		{
			// Loopback
			return true;
		}
		else if (_ip.v6_words[5] == 0xFFFF)
		{
			// Embedded IPv4 address
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		// Already invalid
		return false;
	}
}

bool UNetAddr::DemoteTo4()
{
	if (_family == AF_INET)
	{
		// Already IPv4
		return true;
	}
	else if (_family == AF_INET6)
	{
		if (_ip.v6[0] != 0 || _ip.v6_words[4] != 0)
		{
			_valid = 0;
			return false;
		}
		else if (_ip.v6_words[5] == 0 && _ip.v6_words[6] == 0 &&
				 _ip.v6_bytes[14] == 0 && _ip.v6_bytes[15] == 1)
		{
			// Loopback
			_family = AF_INET;
			_ip.v4 = htonl(0x7F000001);
			return true;
		}
		else if (_ip.v6_words[5] == 0xFFFF)
		{
			// Embedded IPv4 address
			_family = AF_INET;
			_ip.v4 = htonl( ((u32)_ip.v6_bytes[12] << 24) |
							((u32)_ip.v6_bytes[13] << 16) |
							((u32)_ip.v6_bytes[14] << 8) |
							((u32)_ip.v6_bytes[15]) );
			return true;
		}
		else
		{
			_valid = 0;
			return false;
		}
	}
	else
	{
		// Already invalid
		return false;
	}
}
