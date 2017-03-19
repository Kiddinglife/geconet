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

#include <cat/hash/Murmur.hpp>
#include <cat/port/EndianNeutral.hpp>
#include <cat/math/BitMath.hpp>
using namespace cat;

static CAT_INLINE void Seed(const u64 seed, u64 &h1, u64 &h2)
{
	h1 = 0x9368e53c2f6af274ULL ^ seed;
	h2 = 0x586dcd208f7cd3fdULL ^ seed;
}

static const u64 C1 = 0x87c37b91114253d5ULL;
static const u64 C2 = 0x4cf5ad432745937fULL;

static CAT_INLINE void bmix64(u64 &h1, u64 &h2, u64 &k1, u64 &k2)
{
	// First part of key
	k1 *= C1; 
	k1  = CAT_ROL64(k1, 31); 
	k1 *= C2;
	h1 ^= k1;

	h1 = CAT_ROL64(h1, 27);
	h1 += h2;
	h1 = h1 * 5 + 0x52dce729;

	// Second part of key
	k2 *= C2; 
	k2  = CAT_ROL64(k2, 33); 
	k2 *= C1;
	h2 ^= k2;

	h2 = CAT_ROL64(h2, 31);
	h2 += h1;
	h2 = h2 * 5 + 0x38495ab5;
}

static CAT_INLINE u64 fmix64(u64 k)
{
	k ^= k >> 33;
	k *= 0xff51afd7ed558ccdULL;
	k ^= k >> 33;
	k *= 0xc4ceb9fe1a85ec53ULL;
	k ^= k >> 33;

	return k;
}

static CAT_INLINE void Hash(const void *key, const u64 bytes, u64 &h1, u64 &h2)
{
	// body

	const u64 *blocks = (const u64 *)key;
	u64 nblocks = bytes / 16;

	while (nblocks--)
	{
		u64 k1 = getLE(blocks[0]), k2 = getLE(blocks[1]);

		bmix64(h1, h2, k1, k2);

		blocks += 2;
	}

	// tail

	const u8 *tail = (const u8 *)blocks;
	u64 k1 = 0, k2 = 0;

	switch (bytes & 15)
	{
	case 15: k2 ^= u64(tail[14]) << 48;
	case 14: k2 ^= u64(tail[13]) << 40;
	case 13: k2 ^= u64(tail[12]) << 32;
	case 12: k2 ^= u64(tail[11]) << 24;
	case 11: k2 ^= u64(tail[10]) << 16;
	case 10: k2 ^= u64(tail[ 9]) << 8;
	case  9: k2 ^= u64(tail[ 8]);
		k2 *= C2;
		k2  = CAT_ROL64(k2, 33);
		k2 *= C1;
		h2 ^= k2;

	case  8: k1 ^= u64(tail[ 7]) << 56;
	case  7: k1 ^= u64(tail[ 6]) << 48;
	case  6: k1 ^= u64(tail[ 5]) << 40;
	case  5: k1 ^= u64(tail[ 4]) << 32;
	case  4: k1 ^= u64(tail[ 3]) << 24;
	case  3: k1 ^= u64(tail[ 2]) << 16;
	case  2: k1 ^= u64(tail[ 1]) << 8;
	case  1: k1 ^= u64(tail[ 0]);
		k1 *= C1;
		k1  = CAT_ROL64(k1, 31);
		k1 *= C2;
		h1 ^= k1;
	};
}

static CAT_INLINE void FinalMix(const u64 bytes, u64 &h1, u64 &h2)
{
	// Mix in number of bytes in key
	h1 ^= bytes;
	h2 ^= bytes;

	// Mix together h1, h2
	h1 += h2;
	h2 += h1;

	h1 = fmix64(h1);
	h2 = fmix64(h2);

	h1 += h2;
	h2 += h1;
}


// Incremental hash interface
MurmurHash::MurmurHash(u64 seed)
{
	Seed(seed, _h1, _h2);

	_bytes = 0;
}

void MurmurHash::Add(const void *key, u64 bytes)
{
	Hash(key, bytes, _h1, _h2);

	_bytes += bytes;
}

void MurmurHash::End()
{
	FinalMix(_bytes, _h1, _h2);
}

// One-shot hash interface
MurmurHash::MurmurHash(const void *key, u64 bytes, u64 seed)
{
	Seed(seed, _h1, _h2);

	Hash(key, bytes, _h1, _h2);

	FinalMix(bytes, _h1, _h2);
}

u32 cat::MurmurGenerateUnbiased(const void *key, u64 bytes, u32 low, u32 high)
{
	u64 h1, h2;

	u32 range = high - low;
	if (range == 0) return low;

	// Round range up to the next pow(2)-1
	u32 available = BSR32(range);
	u32 v = (((1 << available) - 1) << 1) | 1;
	available = 64 - available;

	// For each trial,
	for (u32 trial = 0; trial < 16; ++trial)
	{
		MurmurHash(key, bytes, trial).Get128(h1, h2);

		// Try to find a bit region that is within range anywhere in the hash output:
		u32 count = available;
		u64 h = h1;
		while (count--)
		{
			u32 x = h & v;
			if (x <= range) return low + x;
			h >>= 1;
		}

		count = available;
		h = h2;
		while (count--)
		{
			u32 x = h & v;
			if (x <= range) return low + x;
			h >>= 1;
		}
	}

	// Give up on being unbiased because it is taking too long
	return low + (h1 % (range + 1));
}
