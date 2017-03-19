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

#include <cat/mem/IAllocator.hpp>
using namespace cat;

u32 IAllocator::AcquireBatch(BatchSet &set, u32 count, u32 bytes)
{
	if (count < 1) return 0;

	BatchHead *tail;
	set.head = tail = reinterpret_cast<BatchHead*>( Acquire(sizeof(BatchHead) + bytes) );

	if (!tail) return 0;

	u32 ii;
	for (ii = 1; ii < count; ++ii)
	{
		BatchHead *node = reinterpret_cast<BatchHead*>( Acquire(sizeof(BatchHead) + bytes) );
		if (!node) break;

		tail->batch_next = node;
		tail = node;
	}

	tail->batch_next = 0;
	set.tail = tail;

	return ii;
}

void IAllocator::ReleaseBatch(const BatchSet &batch)
{
	for (BatchHead *next, *node = batch.head; node; node = next)
	{
		next = node->batch_next;

		Release(node);
	}
}
