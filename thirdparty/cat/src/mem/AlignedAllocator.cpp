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

#include <cat/mem/AlignedAllocator.hpp>
#include <cat/port/SystemInfo.hpp>
#include <cstdlib>
#include <cstdio>
using namespace std;
using namespace cat;

#if defined(CAT_OS_APPLE)
#include <sys/sysctl.h>
#endif

// Add your compiler here if it supports aligned malloc
#if defined(CAT_COMPILER_MSVC)
# define CAT_HAS_ALIGNED_ALLOC
# define aligned_malloc _aligned_malloc
# define aligned_realloc _aligned_realloc
# define aligned_free _aligned_free
#endif

static CAT_INLINE u8 DetermineOffset(u32 cacheline_bytes, void *ptr)
{
#if defined(CAT_WORD_64)
	return (u8)( cacheline_bytes - ((u32)*(u64*)&ptr & (cacheline_bytes-1)) );
#else
	return (u8)( cacheline_bytes - (*(u32*)&ptr & (cacheline_bytes-1)) );
#endif
}

static const u32 OLD_BYTES_OVERHEAD = sizeof(u32);

static u32 m_cacheline_bytes;

CAT_SINGLETON(AlignedAllocator);

bool AlignedAllocator::OnInitialize()
{
	m_cacheline_bytes = Use<SystemInfo>()->GetCacheLineBytes();

	return true;
}

// Allocates memory aligned to a CPU cache-line byte boundary from the heap
void *AlignedAllocator::Acquire(u32 bytes)
{
#if defined(CAT_HAS_ALIGNED_ALLOC)

	return aligned_malloc(bytes, m_cacheline_bytes);

#else

    u8 *buffer = (u8*)malloc(OLD_BYTES_OVERHEAD + m_cacheline_bytes + bytes);
    if (!buffer) return 0;

	// Store number of allocated bytes
	*(u32*)buffer = bytes;

	// Get buffer aligned address
	u8 offset = OLD_BYTES_OVERHEAD + DetermineOffset(m_cacheline_bytes, buffer + OLD_BYTES_OVERHEAD);

	// Write offset to number of allocated bytes
    buffer += offset;
    buffer[-1] = offset;

	return buffer;

#endif
}

// Resizes an aligned pointer
void *AlignedAllocator::Resize(void *ptr, u32 bytes)
{
#if defined(CAT_HAS_ALIGNED_ALLOC)

	return aligned_realloc(ptr, bytes, m_cacheline_bytes);

#else

	if (!ptr) return Acquire(bytes);

	// Can assume here that cacheline bytes has been determined

	// Get buffer base address
	u8 *buffer = reinterpret_cast<u8*>( ptr );
	u8 old_offset = buffer[-1];
	buffer -= old_offset;

	// Read number of old bytes
	u32 old_bytes = *(u32*)buffer;

	buffer = (u8*)realloc(buffer, OLD_BYTES_OVERHEAD + m_cacheline_bytes + bytes);
	if (!buffer) return 0;

	// Get buffer aligned address
	u8 offset = OLD_BYTES_OVERHEAD + DetermineOffset(m_cacheline_bytes, buffer + OLD_BYTES_OVERHEAD);

	if (offset != old_offset)
	{
		// Need to shift the buffer around if alignment changed
		// This sort of inefficiency is why I wrote my own allocator
		memmove(buffer + offset, buffer + old_offset, min(bytes, old_bytes));
	}

	buffer += offset;
	buffer[-1] = offset;

	return buffer;

#endif
}

// Frees an aligned pointer
void AlignedAllocator::Release(void *ptr)
{
#if defined(CAT_HAS_ALIGNED_ALLOC)

	aligned_free(ptr);

#else

	if (ptr)
	{
		// Get buffer base address
		u8 *buffer = reinterpret_cast<u8*>( ptr );
		buffer -= buffer[-1];

		free(buffer);
	}

#endif
}
