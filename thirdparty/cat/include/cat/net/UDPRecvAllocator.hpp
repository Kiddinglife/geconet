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

#ifndef CAT_UDP_RECV_ALLOCATOR_HPP
#define CAT_UDP_RECV_ALLOCATOR_HPP

#include <cat/mem/BufferAllocator.hpp>
#include <cat/lang/RefSingleton.hpp>

/*
	UDP RecvFrom() buffer allocator

	Preallocates buffers large enough to contain a UDP packet with overhead,
	which will be used when receiving data from remote hosts.
*/

namespace cat {


class UDPRecvAllocator : public RefSingleton<UDPRecvAllocator>
{
	static const int MAX_BUFFER_COUNT = 100000;
	static const int DEFAULT_BUFFER_COUNT = 10000;
	static const int MIN_BUFFER_COUNT = 1000;

	BufferAllocator *_allocator;

	bool OnInitialize();
	void OnFinalize();

public:
	// Attempt to acquire a number of buffers, pre-fixed size
	// Returns the number of valid buffers it was able to allocate
	CAT_INLINE u32 AcquireBatch(BatchSet &set, u32 count)
	{
		return _allocator->AcquireBatch(set, count);
	}

	// Release a number of buffers simultaneously
	CAT_INLINE void ReleaseBatch(const BatchSet &set)
	{
		_allocator->ReleaseBatch(set);
	}
};


} // namespace cat

#endif // CAT_UDP_RECV_ALLOCATOR_HPP
