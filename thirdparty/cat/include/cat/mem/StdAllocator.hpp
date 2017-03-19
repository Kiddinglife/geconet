/*
	Copyright (c) 2009-2010 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_STD_ALLOCATOR_HPP
#define CAT_STD_ALLOCATOR_HPP

#include <cat/mem/IAllocator.hpp>
#include <cat/lang/Singleton.hpp>
#include <cstdlib>

namespace cat {


// Small to medium -size unaligned heap allocator
class CAT_EXPORT StdAllocator : public IAllocator, public Singleton<StdAllocator>
{
public:
	CAT_INLINE virtual ~StdAllocator() {}

	// Acquires memory aligned to a CPU cache-line byte boundary from the heap
	// NOTE: Call DetermineCacheLineBytes() before using
    CAT_INLINE void *Acquire(u32 bytes)
	{
		return malloc(bytes);
	}

	// Resizes an aligned pointer
	CAT_INLINE void *Resize(void *ptr, u32 bytes)
	{
		return realloc(ptr, bytes);
	}

    // Release an aligned pointer
    CAT_INLINE void Release(void *ptr)
	{
		free(ptr);
	}
};


} // namespace cat

#endif // CAT_STD_ALLOCATOR_HPP
