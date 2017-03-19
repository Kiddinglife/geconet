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

#ifndef CAT_IOCP_IO_THREADS_HPP
#define CAT_IOCP_IO_THREADS_HPP

#include <cat/threads/Thread.hpp>
#include <cat/net/Sockets.hpp>
#include <cat/mem/BufferAllocator.hpp>
#include <cat/lang/LinkedLists.hpp>
#include <cat/lang/RefSingleton.hpp>

namespace cat {


struct IOCPOverlapped;
struct IOTLS;
class IOThread;
class IOThreadPool;
class IOThreadPools;
class UDPEndpoint;
class AsyncFile;

enum IOType
{
	IOTYPE_UDP_SEND,
	IOTYPE_UDP_RECV,
	IOTYPE_FILE_WRITE,
	IOTYPE_FILE_READ
};

struct IOCPOverlapped
{
	OVERLAPPED ov;

	// A value from enum IOType
	u32 io_type;
};

struct IOCPOverlappedRecvFrom : IOCPOverlapped
{
	int addr_len;
	sockaddr_in6 addr;
};

struct IOCPOverlappedSendTo : IOCPOverlapped
{
};

typedef IOCPOverlappedRecvFrom IOLayerRecvOverhead;
typedef IOCPOverlappedSendTo IOLayerSendOverhead;

struct IOCPOverlappedReadFile : IOCPOverlapped
{
};

struct IOCPOverlappedWriteFile : IOCPOverlapped
{
};

typedef IOCPOverlappedReadFile IOLayerReadOverhead;
typedef IOCPOverlappedWriteFile IOLayerWriteOverhead;

static const u32 IOTHREADS_BUFFER_READ_BYTES = 1450;
static const u32 IOTHREADS_BUFFER_COUNT = 10000;

// Manually imported functions from the Windows API, which are not
// available in all versions of Windows.
typedef BOOL (WINAPI *PGetQueuedCompletionStatusEx)(
	HANDLE CompletionPort,
	LPOVERLAPPED_ENTRY lpCompletionPortEntries,
	ULONG ulCount,
	PULONG ulNumEntriesRemoved,
	DWORD dwMilliseconds,
	BOOL fAlertable
	);

typedef BOOL (WINAPI *PSetFileCompletionNotificationModes)(
	HANDLE FileHandle,
	UCHAR Flags
	);

typedef BOOL (WINAPI *PSetFileIoOverlappedRange)(
	HANDLE FileHandle,
	PUCHAR OverlappedRangeStart,
	ULONG Length
	);

typedef BOOL (WINAPI *PSetFileValidData)(
	HANDLE hFile,
	LONGLONG ValidDataLength
	);

class IOThreadImports
{
	friend class IOThreadPools;

	void Initialize();

public:
	PGetQueuedCompletionStatusEx pGetQueuedCompletionStatusEx;
	PSetFileCompletionNotificationModes pSetFileCompletionNotificationModes;
	PSetFileIoOverlappedRange pSetFileIoOverlappedRange;
	PSetFileValidData pSetFileValidData;
};


// An associator object
class CAT_EXPORT IOThreadsAssociator
{
public:
	CAT_INLINE virtual ~IOThreadsAssociator() {}

	CAT_INLINE virtual HANDLE GetHandle() = 0;
};


// IOCP thread
class CAT_EXPORT IOThread : public Thread
{
	CAT_INLINE bool HandleCompletion(IOThreadPool *master, OVERLAPPED_ENTRY entries[], u32 count,
		u32 event_msec, BatchSet &sendq, BatchSet &recvq,
		UDPEndpoint *&prev_recv_endpoint, u32 &recv_count);

	void UseVistaAPI(IOThreadPool *master);
	void UsePreVistaAPI(IOThreadPool *master);

	virtual bool Entrypoint(void *vmaster);

public:
	CAT_INLINE virtual ~IOThread() {}
};


// A pool of IOThreadPools
class CAT_EXPORT IOThreadPool : public DListItem
{
	HANDLE _io_port;

	u32 _worker_count;
	IOThread *_workers;

public:
	IOThreadPool();

	CAT_INLINE HANDLE GetIOPort() { return _io_port; }

	bool Startup(u32 max_worker_count = 0); // 0 = no limit
	bool Shutdown();

	bool Associate(IOThreadsAssociator *associator);
};


// A collection of IOThreadPools
class CAT_EXPORT IOThreadPools : public RefSingleton<IOThreadPools>
{
	bool OnInitialize();
	void OnFinalize();

	IOThreadImports _imports;

	Mutex _lock;
	DListForward _private_pools;
	typedef DListForward::Iterator<IOThreadPool> pools_iter;

	IOThreadPool _shared_pool;

public:
	CAT_INLINE IOThreadImports *GetIOThreadImports() { return &_imports; }

	IOThreadPool *AssociatePrivate(IOThreadsAssociator *associator);
	bool DissociatePrivate(IOThreadPool *pool);

	bool AssociateShared(IOThreadsAssociator *associator);
};


} // namespace cat

#endif // CAT_IOCP_IO_THREADS_HPP
