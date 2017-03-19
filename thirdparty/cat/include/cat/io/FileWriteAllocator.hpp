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

#ifndef CAT_FILE_WRITE_ALLOCATOR_HPP
#define CAT_FILE_WRITE_ALLOCATOR_HPP

#include <cat/mem/IAllocator.hpp>
#include <cat/threads/Mutex.hpp>
#include <cat/lang/RefSingleton.hpp>

/*
	FileWriteAllocator

	Pre-allocates a number of buffers that are disk-sector aligned.

	The first few allocated pages are for WriteBuffer objects,
	followed by the actual buffers, which are all the same size.
	Use FileWriteAllocator::ref()->GetBufferBytes() to query the
	size of the buffers.
*/

namespace cat {


class FileWriteAllocator : public RefSingleton<FileWriteAllocator>, public IAllocator
{
	static const int MAX_BUFFER_BYTES = 2097152;
	static const int DEFAULT_BUFFER_BYTES = 65536; // Apparently some SSDs have this alignment requirement
	static const int MIN_BUFFER_BYTES = DEFAULT_BUFFER_BYTES;

	static const int MAX_BUFFER_COUNT = 10000;
	static const int DEFAULT_BUFFER_COUNT = 200;
	static const int MIN_BUFFER_COUNT = 10;

	bool OnInitialize();
	void OnFinalize();

	u32 _buffer_bytes, _buffer_count;
	u8 *_buffers;

	Mutex _acquire_lock;
	BatchHead * volatile _acquire_head;

	Mutex _release_lock;
	BatchHead * volatile _release_head;

	// This interface really doesn't make sense for this allocator
	void *Acquire(u32 bytes) { return 0; }
	void *Resize(void *ptr, u32 bytes) { return 0; }
	void Release(void *buffer) {}

public:
	CAT_INLINE u32 GetBufferBytes() { return _buffer_bytes; }

	// Attempt to acquire a number of buffers, pre-fixed size
	// Returns the number of valid buffers it was able to allocate
	u32 AcquireBatch(BatchSet &batch_set, u32 count, u32 bytes = 0);

	// Release a number of buffers simultaneously
	void ReleaseBatch(const BatchSet &batch_set);
};


} // namespace cat

#endif // CAT_FILE_WRITE_ALLOCATOR_HPP
