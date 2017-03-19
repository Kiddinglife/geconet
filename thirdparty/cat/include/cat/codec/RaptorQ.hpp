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

/*
	Based on the IETF draft version 5 of RaptorQ by M. Luby and Qualcomm
	http://tools.ietf.org/html/draft-ietf-rmt-bb-fec-raptorq-05
*/

#ifndef CAT_RAPTORQ_HPP
#define CAT_RAPTORQ_HPP

#include <cat/Platform.hpp>

namespace cat {


/*
	RaptorQ, a systematic fountain code:

	Efficient O(n) forward error correction (FEC) within 1 dB of Shannon
	channel capacity for the binary erasure channel (BEC)
*/
class RaptorQ
{
	// Common
	u64 F; // Total bytes (< 2^40)
	u16 T; // Symbol bytes, a multiple of symbol alignment (Al)

	// Scheme-Specific
	u16 Z; // Source block count
	u16 N; // Sub-block count
	u16 Al; // Symbol alignment

public:
};


} // namespace cat

#endif // CAT_RAPTORQ_HPP
