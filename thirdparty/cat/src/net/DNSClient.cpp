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

#include <cat/net/DNSClient.hpp>
#include <cat/io/Log.hpp>
#include <cat/time/Clock.hpp>
#include <cat/lang/Strings.hpp>
#include <cat/port/EndianNeutral.hpp>
#include <cat/io/Settings.hpp>
#include <cat/io/Buffers.hpp>
#include <cat/crypt/rand/Fortuna.hpp>
#include <cstdio>
#include <fstream>
using namespace cat;

#if defined(CAT_OS_WINDOWS)
#include <Iphlpapi.h>
#endif

static WorkerThreads *m_worker_threads = 0;
static Settings *m_settings = 0;
static FortunaOutput *m_csprng = 0;
static DNSClient *m_dns_client = 0;
static UDPSendAllocator *m_udp_send_allocator = 0;

/*
	DNS protocol:

	All fields are big-endian

	Header
		ID(16)
		QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4) [=16]
		QDCOUNT(16)
		ANCOUNT(16)
		NSCOUNT(16)
		ARCOUNT(16)
	Question
		QNAME(x)
		QTYPE(16)
		QCLASS(16)
	Answer, Authority, Additional
		NAME(x)
		TYPE(16)
		CLASS(16)
		TTL(32)
		RDLENGTH(16)
		RDATA(x)
*/

enum HeaderBits
{
	DNSHDR_QR = 15,
	DNSHDR_OPCODE = 11,
	DNSHDR_AA = 10,
	DNSHDR_TC = 9,
	DNSHDR_RD = 8,
	DNSHDR_RA = 7,
	DNSHDR_Z = 4,
	DNSHDR_RCODE = 0
};

enum SectionWordOffsets
{
	DNS_ID,
	DNS_HDR,
	DNS_QDCOUNT,
	DNS_ANCOUNT,
	DNS_NSCOUNT,
	DNS_ARCOUNT,
};

enum QuestionFooterWordOffsets
{
	DNS_FOOT_QTYPE,
	DNS_FOOT_QCLASS
};

enum SectionSizes
{
	DNS_HDRLEN = 12,
	DNS_QUESTION_FOOTER = 4,
	DNS_ANS_HDRLEN = 12
};

enum QTypes
{
	QTYPE_ADDR_IPV4 = 1,
	QTYPE_ADDR_IPV6 = 28
};

enum QClasses
{
	QCLASS_INTERNET = 1
};


//// DNSClientEndpoint

void DNSClientEndpoint::OnRecvRouting(const BatchSet &buffers)
{
	// For each message,
	for (BatchHead *node = buffers.head; node; node = node->batch_next)
	{
		RecvBuffer *buffer = static_cast<RecvBuffer*>( node );

		// Set the receive callback
		buffer->callback.SetMember<DNSClientEndpoint, &DNSClientEndpoint::OnRecv>(this);
	}

	m_worker_threads->DeliverBuffers(WQPRIO_HI, _worker_id, buffers);
}

void DNSClientEndpoint::OnRecv(ThreadLocalStorage &tls, const BatchSet &buffers)
{
	u32 buffer_count = 0;
	for (BatchHead *node = buffers.head; node; node = node->batch_next)
	{
		++buffer_count;
		RecvBuffer *buffer = static_cast<RecvBuffer*>( node );

		SetRemoteAddress(buffer);
		buffer->callback.SetMember<DNSClientEndpoint, &DNSClientEndpoint::OnRecv>(this);

		// If packet source is not the server, ignore this packet
		if (_server_addr != buffer->addr)
		{
			CAT_INANE("DNSClient") << "Received DNS from unexpected source address " << buffer->addr.IPToString() << " : " << buffer->addr.GetPort();
			continue;
		}

		// If packet is truncated, ignore this packet
		if (buffer->data_bytes < DNS_HDRLEN)
		{
			CAT_WARN("DNSClient") << "DNS server sent truncated response bytes=" << buffer->data_bytes;
			continue;
		}

		u16 *hdr_words = reinterpret_cast<u16*>( GetTrailingBytes(buffer) );

		// QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4) [=16]
		u16 hdr = getBE(hdr_words[DNS_HDR]);

		// Header bits
		u16 qr = (hdr >> DNSHDR_QR) & 1; // Response
		u16 opcode = (hdr >> DNSHDR_OPCODE) & 0x000F; // Opcode

		// If header is invalid, ignore this packet
		if (!qr || opcode != 0)
		{
			CAT_WARN("DNSClient") << "DNS server sent invalid response: qr=" << qr << " opcode=" << opcode;
			continue;
		}

		// Extract ID; endian agnostic
		u16 id = hdr_words[DNS_ID];

		AutoMutex lock(_request_lock);

		// Pull request from pending queue
		DNSRequest *req = PullRequest(id);

		// If request was not found to match ID,
		if (!req)
		{
			CAT_WARN("DNSClient") << "DNS server sent response with unmatched id " << id;
			continue;
		}

		// Initialize number of responses to zero
		req->num_responses = 0;

		//u16 aa = (hdr >> DNSHDR_AA) & 1; // Authoritative
		//u16 tc = (hdr >> DNSHDR_TC) & 1; // Truncated
		//u16 rd = (hdr >> DNSHDR_RD) & 1; // Recursion desired
		//u16 ra = (hdr >> DNSHDR_RA) & 1; // Recursion available
		//u16 z = (hdr >> DNSHDR_Z) & 0x0007; // Reserved
		u16 rcode = hdr & 0x000F; // Reply code

		// If non-error result,
		if (rcode == 0)
		{
			int qdcount = getBE(hdr_words[DNS_QDCOUNT]); // Question count
			int ancount = getBE(hdr_words[DNS_ANCOUNT]); // Answer RRs
			//int nscount = getBE(hdr_words[DNS_NSCOUNT]); // Authority RRs
			//int arcount = getBE(hdr_words[DNS_ARCOUNT]); // Additional RRs

			ProcessDNSResponse(req, qdcount, ancount, GetTrailingBytes(buffer), buffer->data_bytes);
		}
		else
		{
			CAT_WARN("DNSClient") << "DNS server sent response with error result: rcode=" << rcode;
		}

		NotifyRequesters(req);
	}

	ReleaseRecvBuffers(buffers, buffer_count);
}

void DNSClientEndpoint::OnTick(ThreadLocalStorage &tls, u32 now)
{
	AutoMutex lock(_request_lock);

	// For each pending request,
	for (rqiter ii = _request_list; ii; ++ii)
	{
		// NOTE: In the case of a shutdown, the repost time of 300 ms will cause proper cleanup.

		// If the request has timed out or reposting failed,
		if (((s32)(now - ii->first_post_time) >= DNSREQ_TIMEOUT) ||
			((s32)(now - ii->last_post_time) >= DNSREQ_REPOST_TIME && !PostDNSPacket(ii, now)))
		{
			_request_list.Erase(ii);
			--_request_queue_size;

			NotifyRequesters(ii);
		}
	}
}

bool DNSClientEndpoint::OnInitialize()
{
	_server_addr.Invalidate();

	_cache_size = 0;
	_request_queue_size = 0;

	_worker_id = INVALID_WORKER_ID;

	if (!UDPEndpoint::OnInitialize())
		return false;

	// Attempt to bind to any port; ignore ICMP unreachable messages
	if (!BindToRandomPort())
	{
		CAT_WARN("DNSClient") << "Initialization failure: Unable to bind to any port";
		return false;
	}

	// Assign to a worker
	u32 worker_id = m_worker_threads->FindLeastPopulatedWorker();

	if (!m_worker_threads->AssignTimer(worker_id, this, WorkerTimerDelegate::FromMember<DNSClientEndpoint, &DNSClientEndpoint::OnTick>(this)))
	{
		CAT_WARN("DNSClient") << "Initialization failure: Unable to assign timer";
		return false;
	}

	_worker_id = worker_id;

	// Attempt to get server address from operating system
	if (!GetServerAddr())
	{
		CAT_WARN("DNSClient") << "Initialization failure: Unable to discover DNS server address";
		return false;
	}

	m_dns_client->SetEndpoint(this);

	return true;
}

bool DNSClientEndpoint::OnFinalize()
{
	m_dns_client->SetEndpoint(0);

	// For each cache node,
	for (rqiter ii = _cache_list; ii; ++ii)
		delete ii;

	// Clear cache
	_cache_list.Clear();
	_cache_size = 0;

	if (_request_queue_size > 0)
	{
		CAT_WARN("DNSClient") << "Request queue not empty during cleanup";

		// For each pending request,
		for (rqiter req = _request_list; req; ++req)
		{
			// For each requester,
			for (cbiter ii = req->callbacks; ii; ++ii)
			{
				// Invoke the callback (fail result)
				ii->cb(req->hostname, 0, 0);

				// Release ref if requested
				RefObject::Release(ii->ref);

				delete ii;
			}

			_request_list.Erase(req);
		}
		_request_queue_size = 0;
	}

	return UDPEndpoint::OnFinalize();
}

bool DNSClientEndpoint::GetServerAddr()
{
	// Mark server address as invalid
	_server_addr.Invalidate();

#if defined(CAT_OS_WINDOWS)

	/*
		Use IP Helper API instead of registry because the registry solution has bugs.
		In particular, it stores interfaces that are not active and I couldn't find
		any obvious way to identify an inactive interface.  This was causing DNS
		lookup to fail on my laptop because both the first and last interfaces listed
		in the registry were from an inactive wireless adapter and both had valid-
		looking DhcpNameServer records.
	*/

	FIXED_INFO *pFixedInfo = (FIXED_INFO*)malloc(sizeof(FIXED_INFO));
	ULONG ulOutBufLen = sizeof(FIXED_INFO);
	DWORD dwRetVal;

	// Find buffer size needed
	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		if (pFixedInfo) free(pFixedInfo);
		pFixedInfo = (FIXED_INFO*)malloc(ulOutBufLen);
	}

	// Grab network params
	if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) != NO_ERROR)
	{
		if (pFixedInfo) free(pFixedInfo);
	}        

	// For each DNS server string,
	for (IP_ADDR_STRING *addr = &pFixedInfo->DnsServerList; addr; addr = addr->Next)
	{
		// Convert address string to binary address
		NetAddr netaddr((const char*)addr->IpAddress.String, 53);

		// If address is routable,
		if (netaddr.IsRoutable())
		{
			_server_addr = netaddr;
		}
	}

/*	Version for Windows 9x:
	// Based on approach used in Tiny Asynchronous DNS project by
	// Sergey Lyubka <valenok@gmail.com>.  I owe you a beer! =)
	const int SUBKEY_NAME_MAXLEN = 512;
	const int SUBKEY_DATA_MAXLEN = 512;

	// Open Tcpip Interfaces key
	HKEY key;
	LONG err = RegOpenKeyA(HKEY_LOCAL_MACHINE,
		"SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces", &key);

	// Handle errors opening the key
	if (err != ERROR_SUCCESS)
	{
		CAT_WARN("DNSClient") << "Initialization: Unable to open registry key for Tcpip interfaces: " << err;
		return false;
	}

	// For each subkey,
	char subkey_name[SUBKEY_NAME_MAXLEN];
	for (int ii = 0; ERROR_SUCCESS == RegEnumKeyA(key, ii, subkey_name, sizeof(subkey_name)); ++ii)
	{
		HKEY subkey;

		// Open interface subkey
		if (ERROR_SUCCESS == RegOpenKeyA(key, subkey_name, &subkey))
		{
			BYTE data[SUBKEY_DATA_MAXLEN];
			DWORD type, data_len;
			u32 lease_time = 0;

			// Get subkey's DhcpNameServer value
			data_len = sizeof(data);
			if (ERROR_SUCCESS == RegQueryValueExA(subkey, "DhcpNameServer", 0, &type, data, &data_len))
			{
				// If type is a string,
				if (type == REG_EXPAND_SZ || type == REG_SZ)
				{
					// Insure it is nul-terminated
					data[sizeof(data) - 1] = '\0';

					// Replace the first non-number/dot with nul
					for (int ii = 0; ii < sizeof(data); ++ii)
					{
						char ch = data[ii];

						if ((ch < '0' || ch > '9') && ch != '.')
						{
							data[ii] = '\0';
							break;
						}
					}

					// Convert address string to binary address
					NetAddr addr((const char*)data, 53);

					// If address is routable,
					if (addr.IsRoutable())
					{
						_server_addr = addr;
					}
				}
			}
		}
	}

	RegCloseKey(key);
*/
#else // Unix version:

	const char *DNS_ADDRESS_FILE = "/etc/resolv.conf";
	std::ifstream file(DNS_ADDRESS_FILE);

	if (!!file)
	{
		const int LINE_MAXCHARS = 512;
		char line[LINE_MAXCHARS];

		// For each line in the address file,
		while (file.getline(line, sizeof(line)))
		{
			// Insure the line is nul-terminated
			line[sizeof(line)-1] = '\0';

			int a, b, c, d;

			// If the line contains a nameserver addrses in dot-decimal format,
			if (std::sscanf(line, "nameserver %d.%d.%d.%d", &a, &b, &c, &d) == 4)
			{
				NetAddr addr(a, b, c, d, 53);

				// If address is routable,
				if (addr.IsRoutable())
				{
					// Set server address to the last valid one in the enumeration
					_server_addr = addr;
				}
			}
		}
	}

#endif

	// Return success if server address is now valid
	if (_server_addr.Valid() &&
		_server_addr.Convert(SupportsIPv6()))
	{
		CAT_INANE("DNSClient") << "Using nameserver at " << _server_addr.IPToString();
	}
	else
	{
		const char *ANYCAST_DNS_SERVER = "4.2.2.1"; // Level 3 / Verizon

		CAT_WARN("DNSClient") << "Unable to determine nameserver from OS.  Using anycast address " << ANYCAST_DNS_SERVER;

		// Attempt to get server address from anycast DNS server string
		if (!_server_addr.SetFromString(ANYCAST_DNS_SERVER, 53) ||
			!_server_addr.Convert(SupportsIPv6()))
		{
			CAT_FATAL("DNSClient") << "Unable to resolve anycast address " << ANYCAST_DNS_SERVER;
			return false;
		}
	}

	return true;
}

bool DNSClientEndpoint::BindToRandomPort()
{
	// NOTE: Ignores ICMP unreachable errors from DNS server; prefers timeouts

	// Attempt to bind to a more random port.
	// This is the standard fix for Dan Kaminsky's DNS exploit
	const int RANDOM_BIND_ATTEMPTS_MAX = 16;

	// Get settings
	bool request_ip6 = m_settings->getInt("Sphynx.DNSClient.RequestIPv6", 1) != 0;
	bool require_ip4 = m_settings->getInt("Sphynx.DNSClient.RequireIPv4", 1) != 0;

	// Try to use a more random port
	int tries = RANDOM_BIND_ATTEMPTS_MAX;
	while (tries--)
	{
		// Generate a random port
		Port port = (u16)m_csprng->Generate();

		// If bind succeeded,
		if (port >= 1024 && Initialize(port, true, request_ip6, require_ip4))
			return true;
	}

	// Fall back to OS-chosen port
	return Initialize(0, true, request_ip6, require_ip4);
}

bool DNSClientEndpoint::PostDNSPacket(DNSRequest *req, u32 now)
{
	// Allocate send buffer
	int str_len = (int)strlen(req->hostname);
	int bytes = DNS_HDRLEN + 1 + str_len + 1 + DNS_QUESTION_FOOTER;

	u8 *pkt = m_udp_send_allocator->Acquire(bytes);
	if (!pkt) return false;

	u16 *dns_hdr = reinterpret_cast<u16*>( pkt );

	// Write header
	dns_hdr[DNS_ID] = req->id; // Endianness doesn't matter
	dns_hdr[DNS_HDR] = getBE16(1 << DNSHDR_RD);
	dns_hdr[DNS_QDCOUNT] = getBE16(1); // One question
	dns_hdr[DNS_ANCOUNT] = 0;
	dns_hdr[DNS_NSCOUNT] = 0;
	dns_hdr[DNS_ARCOUNT] = 0;

	// Copy hostname over
	int last_dot = str_len-1;

	pkt[DNS_HDRLEN + 1 + str_len] = '\0';

	for (int ii = last_dot; ii >= 0; --ii)
	{
		u8 byte = req->hostname[ii];

		// Replace dots with label lengths
		if (byte == '.')
		{
			byte = (u8)(last_dot - ii);
			last_dot = ii-1;
		}

		pkt[DNS_HDRLEN + ii + 1] = byte;
	}

	pkt[DNS_HDRLEN] = (u8)(last_dot + 1);

	// Write request footer
	u16 *foot = reinterpret_cast<u16*>( pkt + DNS_HDRLEN + 1 + str_len + 1 );

	foot[DNS_FOOT_QTYPE] = getBE16(QTYPE_ADDR_IPV4);
	foot[DNS_FOOT_QCLASS] = getBE16(QCLASS_INTERNET);

	// Post DNS request
	req->last_post_time = now;

	return Write(pkt, bytes, _server_addr);
}

bool DNSClientEndpoint::PerformLookup(DNSRequest *req)
{
	u32 now = Clock::msec_fast();

	if (!PostDNSPacket(req, now))
		return false;

	req->first_post_time = now;

	_request_list.PushBack(req);
	++_request_queue_size;

	return true;
}

void DNSClientEndpoint::CacheAdd(DNSRequest *req)
{
	// If still growing cache,
	if (_cache_size < DNSCACHE_MAX_REQS)
		_cache_size++;
	else
	{
		rqiter ii = _cache_list.Tail();
		if (ii)
		{
			_cache_list.Erase(ii);
			delete ii;
		}
	}

	_cache_list.PushFront(req);

	// Set update time
	req->last_post_time = Clock::msec_fast();
}

DNSRequest *DNSClientEndpoint::CacheGet(const char *hostname)
{
	u32 now = Clock::msec_fast();

	// For each cache entry,
	for (rqiter ii = _cache_list; ii; ++ii)
	{
		// If the cache has not expired,
		if ((s32)(now - ii->last_post_time) < DNSCACHE_TIMEOUT)
		{
			// If hostname of cached request equals the new request,
			if (iStrEqual(ii->hostname, hostname))
				return ii;
		}
		else
		{
			DList kills = _cache_list.Chop(ii);

			// For each item that was unlinked,
			for (rqiter ii = kills; ii; ++ii)
			{
				// Delete each item
				delete ii;

				// Reduce the cache size
				--_cache_size;
			}

			// Return indicating that the cache did not contain the hostname
			return 0;
		}
	}

	return 0;
}

void DNSClientEndpoint::CacheKill(DNSRequest *req)
{
	_cache_list.Erase(req);
	--_cache_size;

	// Free memory
	delete req;
}

bool DNSClientEndpoint::GetUnusedID(u16 &unused_id)
{
	// If too many requests already pending,
	if (_request_queue_size >= DNSREQ_MAX_SIMUL)
		return false;

	// Attempt to generate an unused ID
	const int INCREMENT_THRESHOLD = 32;
	bool already_used;
	int tries = 0;
	u16 id;
	do 
	{
		// If we have been sitting here trying for a long time,
		if (++tries >= INCREMENT_THRESHOLD)
			++id; // Just use incrementing IDs to insure we exit eventually
		else
			id = (u16)m_csprng->Generate(); // Generate a random ID

		// For each pending request,
		already_used = false;
		for (rqiter ii = _request_list; ii; ++ii)
		{
			// If the ID is already used,
			if (ii->id == id)
			{
				// Try again
				already_used = true;
				break;
			}
		}
	} while (already_used);

	unused_id = id;

	return true;
}

bool DNSClientEndpoint::IsValidHostname(const char *hostname)
{
	int str_len = (int)strlen(hostname);

	// Name can be up to 63 characters
	if (str_len > HOSTNAME_MAXLEN)
		return false;

	// Initialize state
	char last_char = '\0';
	bool seen_alphabetic = false;

	// For each symbol in the hostname,
	++str_len;
	for (int ii = 0; ii < str_len; ++ii)
	{
		char symbol = hostname[ii];

		// Switch based on symbol type:
		if ((symbol >= 'A' && symbol <= 'Z') ||
			(symbol >= 'a' && symbol <= 'z')) // Alphabetic
		{
			seen_alphabetic = true;
			// Don't react to alphabetic until label end
		}
		else if (symbol >= '0' && symbol <= '9') // Numeric
		{
			// Don't react to numeric until label end
		}
		else if (symbol == '-') // Dash
		{
			// Don't allow strings of - or start with -
			if (last_char == '-' || last_char == '\0') return false;
		}
		else if (symbol == '.' || symbol == '\0') // End of a label
		{
			// If we didn't see an alphabetic character in this label,
			if (!seen_alphabetic) return false;

			// If last character in label was not alphanumeric,
			if ((last_char < 'A' || last_char > 'Z') &&
				(last_char < 'a' || last_char > 'z') &&
				(last_char < '0' || last_char > '9'))
			{
				return false;
			}

			// Reset state for next label
			seen_alphabetic = false;
			last_char = '\0';

			continue;
		}
		else
		{
			return false;
		}

		last_char = symbol;
	}

	return true;
}

bool DNSClientEndpoint::Resolve(const char *hostname, DNSDelegate callback, RefObject *holdRef)
{
	// If DNSClient is shutdown,
	if (IsShutdown())
		return false;

	// Try to interpret hostname as numeric
	NetAddr addr(hostname);

	// If it was numeric,
	if (addr.Valid())
	{
		// Immediately invoke callback
		callback(hostname, &addr, 1);

		return true;
	}

	// If hostname is invalid,
	if (!IsValidHostname(hostname))
		return false;

	AutoMutex cache_lock(_cache_lock);

	// Check cache
	DNSRequest *cached_request = CacheGet(hostname);

	// If it was in the cache,
	if (cached_request)
	{
		// Immediately invoke callback
		if (!callback(hostname, cached_request->responses, cached_request->num_responses))
		{
			// Kill cached request when asked
			CacheKill(cached_request);
		}

		return true;
	}

	cache_lock.Release();

	AutoMutex req_lock(_request_lock);

	for (rqiter ii = _request_list; ii; ++ii)
	{
		if (iStrEqual(ii->hostname, hostname))
		{
			DNSCallback *cb = new (std::nothrow) DNSCallback;
			if (!cb) return false;

			if (holdRef) holdRef->AddRef(CAT_REFOBJECT_TRACE);

			cb->cb = callback;
			cb->ref = holdRef;
			ii->callbacks.PushFront(cb);

			return true;
		}
	}

	// Get an unused ID
	u16 id;
	if (!GetUnusedID(id))
	{
		CAT_WARN("DNSClient") << "Too many DNS requests pending";
		return false;
	}

	CAT_INANE("DNSClient") << "Transmitting DNS request with id " << id;

	// Create a new request
	DNSRequest *request = new (std::nothrow) DNSRequest;
	if (!request) return false;

	// Create a new callback
	DNSCallback *cb = new (std::nothrow) DNSCallback;
	if (!cb)
	{
		delete request;
		return false;
	}

	// Fill request
	CAT_STRNCPY(request->hostname, hostname, sizeof(request->hostname));
	cb->ref = holdRef;
	cb->cb = callback;
	request->callbacks.PushFront(cb);
	request->id = id;
	request->num_responses = 0;

	if (holdRef) holdRef->AddRef(CAT_REFOBJECT_TRACE);

	// Attempt to perform lookup
	if (!PerformLookup(request))
	{
		RefObject::Release(holdRef);
		return false;
	}

	return true;
}

DNSRequest *DNSClientEndpoint::PullRequest(u16 id)
{
	// For each pending request,
	for (rqiter ii = _request_list; ii; ++ii)
	{
		// If ID matches,
		if (ii->id == id)
		{
			_request_list.Erase(ii);
			--_request_queue_size;

			return ii;
		}
	}

	return 0;
}

void DNSClientEndpoint::NotifyRequesters(DNSRequest *req)
{
	bool add_to_cache = false;

	// For each requester,
	for (cbiter ii = req->callbacks; ii; ++ii)
	{
		// Invoke the callback
		add_to_cache |= ii->cb(req->hostname, req->responses, req->num_responses);

		// Release ref if requested
		RefObject::Release(ii->ref);

		delete ii;
	}

	// If any of the callbacks requested us to add it to the cache,
	if (add_to_cache)
	{
		req->callbacks.Clear();

		AutoMutex lock(_cache_lock);
		CacheAdd(req);
	}
	else
	{
		delete req;
	}
}

void DNSClientEndpoint::ProcessDNSResponse(DNSRequest *req, int qdcount, int ancount, u8 *data, u32 bytes)
{
	u32 offset = DNS_HDRLEN;

	// Get past question part
	while (qdcount-- > 0)
	{
		while (offset < bytes)
		{
			u8 byte = data[offset++];
			if (!byte) break;

			offset += byte;
		}

		offset += 4;

		// On overflow,
		if (offset >= bytes)
		{
			return;
		}
	}

	// Crunch answers
	while (ancount-- > 0)
	{
		while (offset < bytes)
		{
			u16 *words = reinterpret_cast<u16*>( data + offset );

			//u16 name_offset = getBE(words[0]);
			u16 name_type = getBE(words[1]);
			u16 name_class = getBE(words[2]);
			//u32 name_ttl = getBE(words[3] | words[4]);
			u16 addr_len = getBE(words[5]);
			u8 *addr_data = data + offset + DNS_ANS_HDRLEN;

			offset += DNS_ANS_HDRLEN + addr_len;

			// 32-bit IPv4
			if (name_type == QTYPE_ADDR_IPV4 &&
				name_class == QCLASS_INTERNET &&
				addr_len == NetAddr::IP4_BYTES && offset <= bytes &&
				req->responses[req->num_responses].SetFromRawIP(addr_data, NetAddr::IP4_BYTES))
			{
				if (++req->num_responses >= DNSCACHE_MAX_RESP)
				{
					return;
				}
			}

			// 128-bit IPv6
			if (name_type == QTYPE_ADDR_IPV6 &&
				name_class == QCLASS_INTERNET &&
				addr_len == NetAddr::IP6_BYTES && offset <= bytes &&
				req->responses[req->num_responses].SetFromRawIP(addr_data, NetAddr::IP6_BYTES))
			{
				if (++req->num_responses >= DNSCACHE_MAX_RESP)
				{
					return;
				}
			}
		}

		// On overflow,
		if (offset >= bytes)
		{
			return;
		}
	}
}


//// DNSClient

CAT_REF_SINGLETON(DNSClient);

bool DNSClient::OnInitialize()
{
	_endpoint = 0;
	m_dns_client = this;

	CAT_ENFORCE(_lock.Valid());

	Use(m_worker_threads, m_settings, m_udp_send_allocator);
	Use<IOThreadPools>();

	// Attempt to get a CSPRNG
	m_csprng = Use<FortunaFactory>()->Create();
	if (!m_csprng)
	{
		CAT_WARN("DNSClient") << "Unable to get a CSPRNG";
		return false;
	}

	// Stop here if not initialized
	if (!IsInitialized()) return false;

	return RefObjects::Create(CAT_REFOBJECT_TRACE, _endpoint) != 0;
}

void DNSClient::OnFinalize()
{
	if (m_csprng)
	{
		delete m_csprng;
		m_csprng = 0;
	}
}

bool DNSClient::Resolve(const char *hostname, DNSDelegate callback, RefObject *holdRef)
{
	AutoMutex lock(_lock);

	if (!_endpoint)
	{
		CAT_WARN("DNSClient") << "Unable to service DNS request: Endpoint unavailable";
		callback(hostname, 0, 0);
		return false;
	}

	if (!_endpoint->Resolve(hostname, callback, holdRef))
	{
		callback(hostname, 0, 0);
		return false;
	}

	return true;
}
