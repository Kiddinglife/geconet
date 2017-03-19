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

#ifndef CAT_POLLED_FILE_READER_HPP
#define CAT_POLLED_FILE_READER_HPP

#include <cat/io/Buffers.hpp>

/*
	This implementation of a polled file reader is designed for maximum
	throughput.  The access patterns are tuned to work for a wide range
	of common disk types:

	+ The reads are hinted as sequential access pattern to help the OS.
	I have noticed this helping ever so slightly.  It cannot hurt anyway.

	+ Each read is not buffered by the OS since that halves the throughput
	in some cases.  File caching should be implemented by the application
	to have your cake and eat it too.  Note that this means that the read
	buffers must be page-aligned, but that is handled internally here.

	+ There are always 2 * (processor count) requests outstanding, and at
	least 16 even if the processor count is low to allow for very fast
	RAID arrays of SSDs to perform at their peak.
	For single mechanical disks, this can be set lower without hurting.

	+ Each read from the disks is 32768 bytes.  It's the magic number.
	In some cases raising the number will help.
	In most cases lowering this number will hurt.
*/

namespace cat {


// See above for rationale of these choices
static const u32 OPTIMAL_FILE_READ_CHUNK_SIZE = 32768;
static const u32 OPTIMAL_FILE_MINIMUM_PARALLELISM = 16;
static const u32 OPTIMAL_FILE_READ_MODE = ASYNCFILE_READ | ASYNCFILE_SEQUENTIAL | ASYNCFILE_NOBUFFER;

class CAT_EXPORT PolledFileReader : public AsyncFile
{
	// Double-buffered cache system
	u8 *_cache[2];
	u32 _cache_size;		// Bytes in each cache buffer
	u32 _cache_front_index;	// Buffer index where data is available now
	u32 _cache_front_bytes;	// Bytes available in front buffer
	u32 _cache_offset;		// Offset to next unread byte in front buffer
	u8 _cache_back_done;	// Flag to indicate that the back buffer read completed
	u8 _cache_front_done;	// Flag to indicate that the front buffer read completed
	u32 _cache_back_bytes;	// Bytes available in back buffer

	// Read state
	u64 _file_size;			// Total file size
	u64 _offset;			// Next offset for reading from disk
	ReadBuffer _buffer;		// Read request object for reading from disk

	void OnFirstRead(ThreadLocalStorage &tls, const BatchSet &buffers);
	void OnRead(ThreadLocalStorage &tls, const BatchSet &buffers);

public:
	PolledFileReader();
	virtual ~PolledFileReader();

	CAT_INLINE u64 Offset() { return _offset; }
	CAT_INLINE u64 Size() { return _file_size; }
	CAT_INLINE u64 Remaining()
	{
		s64 remaining = (s64)(_file_size - _offset);
		return remaining > 0 ? remaining : 0;
	}

	bool Open(const char *file_path, u32 worker_id);

	/*
		If Read() returns false, then the end of file has been found.
		Otherwise, 'bytes_read' will be set to the number of bytes read.

		Not thread-safe to read from the same object with multiple threads.
	*/
	bool Read(u8 *buffer, u32 requested, u32 &bytes_read);
};


} // namespace cat

#endif // CAT_POLLED_FILE_READER_HPP
