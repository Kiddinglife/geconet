/*
	Copyright (c) 2012 Christopher A. Taylor.  All rights reserved.

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

#include <cat/net/UDPSendAllocator.hpp>
#include <cat/io/Buffers.hpp>
#include <cat/io/Settings.hpp>
#include <cat/io/Log.hpp>
using namespace cat;


//// UDPSendAllocator

CAT_REF_SINGLETON(UDPSendAllocator);

bool UDPSendAllocator::OnInitialize()
{
	// Grab buffer count
	_num_allocators = Use<Settings>()->getInt("Net::UDPSendAllocator.NumAllocators", DEFAULT_ALLOC_COUNT, MIN_ALLOC_COUNT, MAX_ALLOC_COUNT);

	CAT_INFO("UDPSendAllocator") << "Initializing with " << _num_allocators << " allocator bins";

	_allocators = new (std::nothrow) ReuseAllocator *[_num_allocators];
	if (!_allocators)
	{
		CAT_WARN("UDPSendAllocator") << "Out of memory";
		return false;
	}

	const u32 MIN_BYTES = REUSE_MINIMUM_SIZE;
	const u32 MAX_BYTES = sizeof(SendBuffer) + IOTHREADS_BUFFER_READ_BYTES;

	CAT_DEBUG_ENFORCE(MIN_BYTES > sizeof(SendBuffer)) << "Minimum size is too small!";

	// For each allocator,
	bool success = true;
	for (int ii = 0, count = _num_allocators; ii < count; ++ii)
	{
		u32 buffer_bytes = MIN_BYTES + (ii * (MAX_BYTES - MIN_BYTES)) / (count - 1);

		ReuseAllocator *alloc = new (std::nothrow) ReuseAllocator(buffer_bytes);
		if (!alloc)
		{
			CAT_WARN("UDPSendAllocator") << "Out of memory";
			success = false;
		}

		_allocators[ii] = alloc;
	}

	return success;
}

void UDPSendAllocator::OnFinalize()
{
	CAT_INFO("UDPSendAllocator") << "Releasing buffers...";

	if (_allocators)
	{
		for (int ii = 0, count = _num_allocators; ii < count; ++ii)
		{
			ReuseAllocator *alloc = _allocators[ii];
			if (alloc) delete alloc;
		}

		delete []_allocators;
	}
}

u8 *UDPSendAllocator::Acquire(u32 trailing_bytes)
{
	u32 buffer_bytes = sizeof(SendBuffer) + trailing_bytes;

#if defined(CAT_UDP_SEND_ALLOCATOR)
	const u32 MIN_BYTES = REUSE_MINIMUM_SIZE;
	const u32 MAX_BYTES = sizeof(SendBuffer) + IOTHREADS_BUFFER_READ_BYTES;

	CAT_DEBUG_ENFORCE(buffer_bytes <= MAX_BYTES) << "Requested buffer size larger than the maximum!";

	// For small sizes,
	if (buffer_bytes < MIN_BYTES)
	{
		// Skip re-use allocators and just use default allocator
		SendBuffer *buffer = reinterpret_cast<SendBuffer*>( new (std::nothrow) u8[buffer_bytes] );
		if (!buffer) return 0;

		// Remember bin index
		buffer->_udp_send_allocator_bin_index = 0;
		return GetTrailingBytes(buffer);
	}

	// Determine bin to use
	u32 bin_index = ( (buffer_bytes - MIN_BYTES) * (_num_allocators - 1) + (MAX_BYTES - MIN_BYTES - 1)) / (MAX_BYTES - MIN_BYTES);

	// Allocate from this bin
	ReuseAllocator *alloc = _allocators[bin_index];
	SendBuffer *buffer = reinterpret_cast<SendBuffer*>( alloc->Acquire() );
	if (!buffer) return 0;

	// Remember bin index
	buffer->_udp_send_allocator_bin_index = (u8)(bin_index + 1);
	return GetTrailingBytes(buffer);
#else // CAT_UDP_SEND_ALLOCATOR
	SendBuffer *buffer = reinterpret_cast<SendBuffer*>( new (std::nothrow) u8[buffer_bytes] );
	if (!buffer) return 0;
	return GetTrailingBytes(buffer);
#endif // CAT_UDP_SEND_ALLOCATOR
}

// Release a number of buffers simultaneously
void UDPSendAllocator::ReleaseBatch(const BatchSet &set)
{
	if (!set.head) return;

	// Initialize kill set
	BatchSet kills;
	u32 prev_bin = 0;

	// For each node to release,
	for (BatchHead *next, *node = set.head; node; node = next)
	{
		next = node->batch_next;

#if defined(CAT_UDP_SEND_ALLOCATOR)
		// Lookup bin index
		UDPSendBatchHead *inner_data = reinterpret_cast<UDPSendBatchHead*>( node );
		u32 bin_index = inner_data->_udp_send_allocator_bin_index;

		// If it is not in a bin,
		if (bin_index == 0)
		{
			u8 *pkt = reinterpret_cast<u8*>( node );
			delete []pkt;
		}
		// If two bins in a row match,
		else if (prev_bin == bin_index)
		{
			// Add to kills list
			kills.PushBack(node);
		}
		else
		{
			// If previous bin is non-zero,
			if (prev_bin > 0) _allocators[prev_bin - 1]->ReleaseBatch(kills);

			kills = node;
			prev_bin = bin_index;
		}
#else // CAT_UDP_SEND_ALLOCATOR
		u8 *pkt = reinterpret_cast<u8*>( node );
		delete []pkt;
#endif // CAT_UDP_SEND_ALLOCATOR
	}

	// If previous bin is non-zero,
	if (prev_bin > 0) _allocators[prev_bin - 1]->ReleaseBatch(kills);
}
