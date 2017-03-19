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

#include <cat/net/UDPRecvAllocator.hpp>
#include <cat/io/Buffers.hpp>
#include <cat/io/Settings.hpp>
using namespace cat;


//// UDPRecvAllocator

CAT_REF_SINGLETON(UDPRecvAllocator);

bool UDPRecvAllocator::OnInitialize()
{
	// Grab buffer count
	int buffer_count = Use<Settings>()->getInt("Net::UDPRecvAllocator.BufferCount", DEFAULT_BUFFER_COUNT, MIN_BUFFER_COUNT, MAX_BUFFER_COUNT);

	_allocator = new (std::nothrow) BufferAllocator(sizeof(RecvBuffer) + IOTHREADS_BUFFER_READ_BYTES, buffer_count);

	return _allocator && _allocator->Valid(); 
}

void UDPRecvAllocator::OnFinalize()
{
	if (_allocator) delete _allocator;
}
