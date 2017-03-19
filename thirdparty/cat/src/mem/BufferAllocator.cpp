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

#include <cat/mem/BufferAllocator.hpp>
#include <cat/mem/LargeAllocator.hpp>
#include <cat/port/SystemInfo.hpp>
#include <cat/io/Log.hpp>
using namespace cat;

static LargeAllocator *m_large_allocator = 0;


//// BufferAllocator

BufferAllocator::BufferAllocator(u32 buffer_min_size, u32 buffer_count)
{
	if (buffer_count < 4) buffer_count = 4;

	m_large_allocator = LargeAllocator::ref();

	u32 cacheline_bytes = SystemInfo::ref()->GetCacheLineBytes();

	const u32 overhead_bytes = sizeof(BatchHead);
	u32 buffer_bytes = CAT_CEIL(overhead_bytes + buffer_min_size, cacheline_bytes);
	u32 total_bytes = buffer_count * buffer_bytes;
	u8 *buffers = (u8*)m_large_allocator->Acquire(total_bytes);

	_buffer_bytes = buffer_bytes;
	_buffer_count = buffer_count;
	_buffers = buffers;

	if (!buffers)
	{
		CAT_FATAL("BufferAllocator") << "Unable to allocate " << buffer_count << " buffers of " << buffer_min_size;
		return;
	}

	// Construct linked list of free nodes
	BatchHead *tail = reinterpret_cast<BatchHead*>( buffers );

	_acquire_head = tail;
	_release_head = 0;

	for (u32 ii = 1; ii < buffer_count; ++ii)
	{
		buffers += buffer_bytes;
		BatchHead *node = reinterpret_cast<BatchHead*>( buffers );

		tail->batch_next = node;
		tail = node;
	}

	tail->batch_next = 0;

	CAT_INFO("BufferAllocator") << "Allocated and marked " << buffer_count << " buffers of " << buffer_min_size;
}

BufferAllocator::~BufferAllocator()
{
	CAT_INFO("BufferAllocator") << "Releasing buffers";

	m_large_allocator->Release(_buffers);
}

u32 BufferAllocator::AcquireBatch(BatchSet &set, u32 count, u32 bytes)
{
	u32 ii = 0;

	_acquire_lock.Enter();

	// Select up to count items from the list
	BatchHead *last = _acquire_head;

	set.head = last;

	if (last)
	{
		CAT_FOREVER
		{
			BatchHead *next = last->batch_next;

			// If we are done,
			if (++ii >= count)
			{
				_acquire_head = next;
				_acquire_lock.Leave();

				set.tail = last;
				last->batch_next = 0;
				return ii;
			}

			// If the list ran out,
			if (!next) break;

			last = next;
		}
	}

	// End up here if the acquire list was empty or is empty now

	// If it looks like the release list has more,
	if (_release_head)
	{
		// Escalate lock and steal from release list
		_release_lock.Enter();
		BatchHead *next = _release_head;
		_release_head = 0;
		_release_lock.Leave();

		if (next)
		{
			// Link acquire list to release list
			// Handle the case where the acquire list was empty
			if (last) last->batch_next = next;
			else set.head = next;

			last = next;

			CAT_FOREVER
			{
				next = last->batch_next;

				// If we are done,
				if (++ii >= count)
				{
					_acquire_head = next;
					_acquire_lock.Leave();

					set.tail = last;
					last->batch_next = 0;
					return ii;
				}

				// If the list ran out,
				if (!next) break;

				last = next;
			}
		}
	}

	_acquire_head = 0;
	_acquire_lock.Leave();

	set.tail = last;

	if (last)
	{
		//last->batch_next = 0;
		CAT_DEBUG_ENFORCE(!last->batch_next);
	}

	return ii;
}

void BufferAllocator::ReleaseBatch(const BatchSet &set)
{
	if (!set.head) return;

#if defined(CAT_DEBUG)
	BatchHead *node;
	for (node = set.head; node->batch_next; node = node->batch_next);

	if (node != set.tail)
	{
		CAT_FATAL("BufferAllocator") << "ERROR: ReleaseBatch detected an error in input";
	}
#endif // CAT_DEBUG

	_release_lock.Enter();
	set.tail->batch_next = _release_head;
	_release_head = set.head;
	_release_lock.Leave();
}
