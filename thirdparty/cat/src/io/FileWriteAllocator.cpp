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

#include <cat/io/FileWriteAllocator.hpp>
#include <cat/port/SystemInfo.hpp>
#include <cat/io/Settings.hpp>
#include <cat/mem/LargeAllocator.hpp>
#include <cat/math/BitMath.hpp>
#include <cat/io/Buffers.hpp>
using namespace cat;

static Settings *m_settings = 0;
static SystemInfo *m_system_info = 0;
static LargeAllocator *m_large_allocator = 0;


//// FileWriteAllocator

CAT_REF_SINGLETON(FileWriteAllocator);

bool FileWriteAllocator::OnInitialize()
{
	Use(m_settings, m_large_allocator, m_system_info);
	if (!IsInitialized()) return false;

	// Read settings
	u32 buffer_count = (u32)m_settings->getInt("IO::FileWriteAllocator.BufferCount", DEFAULT_BUFFER_COUNT, MIN_BUFFER_COUNT, MAX_BUFFER_COUNT);
	u32 buffer_bytes = (u32)m_settings->getInt("IO::FileWriteAllocator.BufferBytes", DEFAULT_BUFFER_BYTES, MIN_BUFFER_BYTES, MAX_BUFFER_BYTES);

	// Conform it to be a multiple of the sector size
	u32 max_sector_size = m_system_info->GetMaxSectorSize();
	if (!CAT_IS_POWER_OF_2(max_sector_size))
		max_sector_size = NextHighestPow2(max_sector_size);
	u32 sector_low_bits = buffer_bytes & (max_sector_size-1);
	if (sector_low_bits)
		buffer_bytes += max_sector_size - sector_low_bits;

	// Allocate space for buffers and overhead
	const u32 overhead_bytes = sizeof(WriteBuffer);
	u32 total_bytes = (buffer_bytes + overhead_bytes) * buffer_count + buffer_bytes; // extra buffer for alignment guarantee
	u8 *buffers = (u8*)m_large_allocator->Acquire(total_bytes);

	if (!buffers)
	{
		CAT_FATAL("FileWriteAllocator") << "Unable to allocate " << buffer_count << " buffers of " << buffer_bytes;
		return false;
	}

	// Store results
	_buffer_bytes = buffer_bytes;
	_buffer_count = buffer_count;
	_buffers = buffers;

	// Align start of buffers with buffer bytes
	u32 buffer_low_bits = (u32)buffers & (buffer_bytes - 1);
	if (buffer_low_bits)
		buffers += buffer_bytes - buffer_low_bits;

	// Construct linked list of free nodes
	u8 *data_buffer = buffers;
	WriteBuffer *overhead = reinterpret_cast<WriteBuffer*>( buffers + buffer_bytes * buffer_count );

	_acquire_head = overhead;
	_release_head = 0;
	overhead->data = data_buffer;

	for (u32 ii = 1; ii < buffer_count; ++ii)
	{
		WriteBuffer *node = overhead + 1;
		overhead->batch_next = node;

		data_buffer += buffer_bytes;
		node->data = data_buffer;
		overhead = node;
	}

	overhead->batch_next = 0;

	CAT_INFO("FileWriteAllocator") << "Allocated and marked " << buffer_count << " buffers of " << buffer_bytes;

	return true;
}

void FileWriteAllocator::OnFinalize()
{
	m_large_allocator->Release(_buffers);
}

u32 FileWriteAllocator::AcquireBatch(BatchSet &batch_set, u32 count, u32 bytes)
{
	u32 ii = 0;

	_acquire_lock.Enter();

	// Select up to count items from the list
	BatchHead *last = _acquire_head;

	batch_set.head = last;

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

				batch_set.tail = last;
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
			else batch_set.head = next;

			last = next;

			CAT_FOREVER
			{
				next = last->batch_next;

				// If we are done,
				if (++ii >= count)
				{
					_acquire_head = next;
					_acquire_lock.Leave();

					batch_set.tail = last;
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

	batch_set.tail = last;

	if (last)
	{
		//last->batch_next = 0;
		CAT_DEBUG_ENFORCE(!last->batch_next);
	}

	return ii;
}

void FileWriteAllocator::ReleaseBatch(const BatchSet &batch_set)
{
	if (!batch_set.head) return;

#if defined(CAT_DEBUG)
	BatchHead *node;
	for (node = batch_set.head; node->batch_next; node = node->batch_next);

	if (node != batch_set.tail)
	{
		CAT_FATAL("FileWriteAllocator") << "ERROR: ReleaseBatch detected an error in input";
	}
#endif // CAT_DEBUG

	_release_lock.Enter();
	batch_set.tail->batch_next = _release_head;
	_release_head = batch_set.head;
	_release_lock.Leave();
}
