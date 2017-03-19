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

#ifndef CAT_I_RANDOM_HPP
#define CAT_I_RANDOM_HPP

#include <cat/math/BitMath.hpp>

namespace cat {


// Pseudo-random number generators will derive from IRandom and implement its public methods
class CAT_EXPORT IRandom
{
public:
	virtual ~IRandom() {}

	// Generate a 32-bit random number
	virtual u32 Generate() = 0;

	// Generate a variable number of random bytes
	virtual void Generate(void *buffer, int bytes) = 0;

public:
	// Generate a 32-bit random number in the range [low..high] inclusive
	u32 GenerateUnbiased(u32 low, u32 high)
	{
		u32 range = high - low;
		if (range == 0) return low;

		// Round range up to the next pow(2)-1
		u32 available = BSR32(range);
		u32 v = (((1 << available) - 1) << 1) | 1;
		available = 32 - available;

		// Generate an unbiased random number in the inclusive range [0..(high-low)]
		u32 x;
		for (u32 trials = 0; trials < 16; ++trials)
		{
			x = Generate();
			u32 y = x;

			u32 count = available;
			while (count--)
			{
				u32 z = y & v;
				if (z <= range) return low + z;
				y >>= 1;
			}
		}

		// Give up on being unbiased because it is taking too long
		return low + (x % (range + 1));
	}
};


} // namespace cat

#endif // CAT_I_RANDOM_HPP
