/*
	Copyright (c) 2009-2011 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_MEM_RESIZABLE_BUFFER_HPP
#define CAT_MEM_RESIZABLE_BUFFER_HPP

#include <cat/mem/StdAllocator.hpp>

namespace cat {


// Base class for a buffer that has trailing bytes that can be resized
template<class T>
class ResizableBuffer
{
	static const u32 RESIZABLE_BUFFER_PREALLOCATION = 200;

protected:
	u32 _bytes;

public:
	CAT_INLINE u32 GetBytes() { return _bytes; }
	CAT_INLINE void SetBytes(u32 bytes) { _bytes = bytes; }

	static u8 *Acquire(u32 trailing_bytes)
	{
		u32 allocated = trailing_bytes;
		if (allocated < RESIZABLE_BUFFER_PREALLOCATION)
			allocated = RESIZABLE_BUFFER_PREALLOCATION;

		T *buffer = StdAllocator::ref()->AcquireTrailing<T>(allocated);
		if (!buffer) return 0;

		//buffer->allocated_bytes = trailing_bytes;
		buffer->SetBytes(allocated);
		return GetTrailingBytes(buffer);
	}

	static CAT_INLINE T *Promote(u8 *ptr)
	{
		u32 size = sizeof(T);
		return reinterpret_cast<T*>( ptr - sizeof(T) );
	}

	static u8 *Resize(T *buffer, u32 new_trailing_bytes)
	{
		if (!buffer) return Acquire(new_trailing_bytes);

		if (new_trailing_bytes <= buffer->GetBytes())
			return GetTrailingBytes(buffer);

		// Grow buffer ahead of requested bytes according to golden ratio
		new_trailing_bytes = (new_trailing_bytes << 3) / 5;

		buffer = StdAllocator::ref()->ResizeTrailing(buffer, new_trailing_bytes);
		if (!buffer) return 0;

		buffer->SetBytes(new_trailing_bytes);

		return GetTrailingBytes(buffer);
	}

	static CAT_INLINE u8 *Resize(u8 *ptr, u32 new_trailing_bytes)
	{
		if (!ptr) return Acquire(new_trailing_bytes);
		return Resize(Promote(ptr), new_trailing_bytes);
	}

	static CAT_INLINE void Release(T *buffer)
	{
		StdAllocator::ref()->Release(buffer);
	}

	static CAT_INLINE void Release(u8 *ptr)
	{
		if (ptr) T::Release(T::Promote(ptr));
	}
};


} // namespace cat

#endif // CAT_MEM_RESIZABLE_BUFFER_HPP
