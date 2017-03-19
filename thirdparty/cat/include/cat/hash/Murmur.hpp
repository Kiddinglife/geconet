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

/*
    MurmurHash3 is a very fast non-cryptographic 128-bit hash

    Algorithm by Austin Appleby <aappleby@gmail.com>
    http://code.google.com/p/smhasher/wiki/MurmurHash3

	Based on the "final final" version r136
*/

#ifndef CAT_MURMUR_HPP
#define CAT_MURMUR_HPP

#include <cat/Platform.hpp>

namespace cat {


class CAT_EXPORT MurmurHash
{
protected:
	u64 _c1, _c2, _h1, _h2, _bytes;

public:
	// Incremental hash interface
	MurmurHash(u64 seed = 0);
	void Add(const void *key, u64 bytes);
	void End();

public:
	// One-shot hash interface
	MurmurHash(const void *key, u64 bytes, u64 seed = 0);

public:
	// Generate 128-bit hash
	CAT_INLINE void Get128(u64 &h1, u64 &h2)
	{
		h1 = _h1;
		h2 = _h2;
	}

	// Generate 64-bit hash
	CAT_INLINE u64 Get64()
	{
		return _h1;
	}

	// Generate 32-bit hash
	CAT_INLINE u32 Get32()
	{
		return (u32)_h1;
	}
};


// Use Murmur hash to generate an unbiased random number within a given inclusive range
u32 CAT_EXPORT MurmurGenerateUnbiased(const void *key, u64 bytes, u32 range_low, u32 range_high);


} // namespace cat

#endif // CAT_MURMUR_HPP
