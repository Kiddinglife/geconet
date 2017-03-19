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

#include <cat/crypt/symmetric/ChaCha.hpp>
#include <cat/port/EndianNeutral.hpp>
#include <string.h>
using namespace cat;

static const int CAT_CHACHA_ROUNDS = 14; // Multiple of 2


//// ChaChaKey

ChaChaKey::~ChaChaKey()
{
	CAT_SECURE_OBJCLR(state);
}

static u32 InitialState[12] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	// These are from BLAKE-32:
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	// Took the rest of these from the SHA-256 SBOX constants:
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
};

// Key up to 384 bits
void ChaChaKey::Set(const void *key, int bytes)
{
	// Precondition: Bytes must be a multiple of 4
	if (bytes > 48) bytes = 48;

	memcpy(state, InitialState, sizeof(InitialState));

	const u32 *in32 = (const u32 *)key;
	int words = bytes / 4;

	for (int ii = 0; ii < words; ++ii)
	{
		state[ii] ^= getLE(in32[ii]);
	}
}


//// ChaChaOutput

#define QUARTERROUND(A,B,C,D)							\
	x[A] += x[B]; x[D] = CAT_ROL32(x[D] ^ x[A], 16);	\
	x[C] += x[D]; x[B] = CAT_ROL32(x[B] ^ x[C], 12);	\
	x[A] += x[B]; x[D] = CAT_ROL32(x[D] ^ x[A], 8);		\
	x[C] += x[D]; x[B] = CAT_ROL32(x[B] ^ x[C], 7);

#define CHACHA_MIX	\
	for (int round = CAT_CHACHA_ROUNDS; round > 0; round -= 2)	\
	{								\
		QUARTERROUND(0, 4, 8,  12)	\
		QUARTERROUND(1, 5, 9,  13)	\
		QUARTERROUND(2, 6, 10, 14)	\
		QUARTERROUND(3, 7, 11, 15)	\
		QUARTERROUND(0, 5, 10, 15)	\
		QUARTERROUND(1, 6, 11, 12)	\
		QUARTERROUND(2, 7, 8,  13)	\
		QUARTERROUND(3, 4, 9,  14)	\
	}

void ChaChaOutput::GenerateNeutralKeyStream(u32 out_words[16])
{
	// Update block counter
	if (!++state[12]) state[13]++;

	register u32 x[16];

	// Copy state into work registers
	for (int ii = 0; ii < 16; ++ii)
		x[ii] = state[ii];

	CHACHA_MIX;

	// Add state to mixed state
	for (int jj = 0; jj < 16; ++jj)
		out_words[jj] = getLE(x[jj] + state[jj]);
}

ChaChaOutput::~ChaChaOutput()
{
	CAT_OBJCLR(state);
}

void ChaChaOutput::ReKey(const ChaChaKey &key, u64 iv)
{
	for (int ii = 0; ii < 12; ++ii)
		state[ii] = key.state[ii];

	// Initialize block counter to zero
	state[12] = 0;
	state[13] = 0;

	// Initialize IV
	state[14] = (u32)iv;
	state[15] = (u32)(iv >> 32);
}

void ChaChaOutput::Crypt(const void *in_bytes, void *out_bytes, int bytes)
{
	const u32 *in32 = (const u32 *)in_bytes;
	u32 *out32 = (u32 *)out_bytes;

#ifdef CAT_AUDIT
	int initial_bytes = bytes;
	printf("AUDIT: ChaCha input ");
	for (int ii = 0; ii < bytes; ++ii)
	{
		printf("%02x", ((cat::u8*)in_bytes)[ii]);
	}
	printf("\n");
#endif

	while (bytes >= 64)
	{
		if (!++state[12]) state[13]++;

		register u32 x[16];

		// Copy state into work registers
		for (int ii = 0; ii < 16; ++ii)
			x[ii] = state[ii];

		CHACHA_MIX;

		for (int ii = 0; ii < 16; ++ii)
			out32[ii] = in32[ii] ^ getLE(x[ii] + state[ii]);

		out32 += 16;
		in32 += 16;
		bytes -= 64;
	}

	if (bytes)
	{
		if (!++state[12]) state[13]++;

		register u32 x[16];

		// Copy state into work registers
		for (int ii = 0; ii < 16; ++ii)
			x[ii] = state[ii];

		CHACHA_MIX;

		int words = bytes / 4;
		for (int ii = 0; ii < words; ++ii)
			out32[ii] = in32[ii] ^ getLE(x[ii] + state[ii]);

		const u8 *in8 = (const u8 *)(in32 + words);
		u8 *out8 = (u8 *)(out32 + words);

		u32 final_key = getLE(x[words] + state[words]);

		switch (bytes % 4)
		{
		case 3: out8[2] = in8[2] ^ (u8)(final_key >> 16);
		case 2: out8[1] = in8[1] ^ (u8)(final_key >> 8);
		case 1: out8[0] = in8[0] ^ (u8)final_key;
		}
	}

#ifdef CAT_AUDIT
	printf("AUDIT: ChaCha output ");
	for (int ii = 0; ii < initial_bytes; ++ii)
	{
		printf("%02x", ((cat::u8*)out_bytes)[ii]);
	}
	printf("\n");
#endif
}

#undef QUARTERROUND
#undef CHACHA_MIX
