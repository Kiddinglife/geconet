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

/*
	TODO: ASYNCFILE_NOBUFFER might cause problems in some cases

	Technically, you're supposed to detect the sector size and allocate buffers
	aligned to the sector size.  However, the page size seems to be larger, and
	they are both powers of two, and the buffer sizes are a multiple of the page
	size.  So allocating buffers on page boundaries seems to be good enough.

	This saves us from having to determine the alignment for each file...
*/

#ifndef CAT_IOCP_ASYNCFILE_HPP
#define CAT_IOCP_ASYNCFILE_HPP

#include <cat/lang/RefObject.hpp>
#include <cat/io/Buffers.hpp>

namespace cat {

struct ReadBuffer;
struct WriteBuffer;


enum AsyncFileFlags
{
	// Open for read and/or write?
	ASYNCFILE_READ = 1,
	ASYNCFILE_WRITE = 2,

	// Select whether the data will be accessed sequentially or randomly
	ASYNCFILE_RANDOM = 4,
	ASYNCFILE_SEQUENTIAL = 8,

	// Only a good idea for infrequently accessed data or in combination with manual memory caching
	ASYNCFILE_NOBUFFER = 16,

	// Truncate the file if it already exists (only makes a difference with writing)
	ASYNCFILE_TRUNC = 32,
};


class CAT_EXPORT AsyncFile : public RefObject, public IOThreadsAssociator
{
	friend class IOThread;

	HANDLE _file;

public:
	AsyncFile();
	virtual ~AsyncFile();

	CAT_INLINE const char *GetRefObjectName() { return "AsyncFile"; }

	CAT_INLINE bool Valid() { return _file != INVALID_HANDLE_VALUE; }
	CAT_INLINE HANDLE GetHandle() { return _file; }

	/*
		In read mode, Open() will fail if the file does not exist.
		In write mode, Open() will create the file if it does not exist.

		async_file_modes may be any combination of AsyncFileFlags
	*/
	bool Open(const char *file_path, u32 async_file_modes);
	void Close();

	bool SetSize(u64 bytes);
	u64 GetSize();

	// Set the callback and worker_id before invoking these functions
	// Note that the data buffers must be pinned in memory until the read/write completes
	// If ASYNCFILE_NOBUFFER is specified, the data buffers must be aligned to a page boundary
	bool Read(ReadBuffer *buffer, u64 offset, void *data, u32 bytes);
	bool Write(WriteBuffer *buffer, u64 offset, void *data, u32 bytes);

protected:
	virtual bool OnInitialize();
	virtual void OnDestroy();
	virtual bool OnFinalize();
};


} // namespace cat

#endif // CAT_IOCP_ASYNCFILE_HPP
