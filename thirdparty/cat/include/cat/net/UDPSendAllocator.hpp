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

#ifndef CAT_UDP_SEND_ALLOCATOR_HPP
#define CAT_UDP_SEND_ALLOCATOR_HPP

#include <cat/mem/ReuseAllocator.hpp>
#include <cat/lang/RefSingleton.hpp>

/*
	UDP SendTo() buffer allocator

	Does not preallocate anything.  Instead, buffers above a certain
	size are broken into fixed sizes in bins, and released buffers are
	added to a free list for later reuse.

	This design was chosen because the default allocator is exceptionally
	fast and sometimes lockless for small sizes, but is exceptionally slow
	for larger sizes.  Furthermore, multiple sizes were chosen so that
	reuse is encouraged and lock contention is reduced between different
	buffer size allocations.
*/

namespace cat {


struct SendBuffer;


struct UDPSendBatchHead : BatchHead
{
	// Remember which bin was used to allocate this one, or 0 for none
	u8 _udp_send_allocator_bin_index;
};

class UDPSendAllocator : public RefSingleton<UDPSendAllocator>
{
	static const int DEFAULT_ALLOC_COUNT = 16;
	static const int MIN_ALLOC_COUNT = 2;
	static const int MAX_ALLOC_COUNT = 255;

	static const int REUSE_MINIMUM_SIZE = 256;

	ReuseAllocator **_allocators;
	int _num_allocators;
	u32 _bin_divisor;

	bool OnInitialize();
	void OnFinalize();

public:
	// Acquire a buffer with the given number of trailing bytes
	u8 *Acquire(u32 trailing_bytes);

	// Release a number of buffers simultaneously
	void ReleaseBatch(const BatchSet &set);
};


} // namespace cat

#endif // CAT_UDP_SEND_ALLOCATOR_HPP
