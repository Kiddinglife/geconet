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

#include <cat/io/PolledFileReader.hpp>
#include <cat/port/SystemInfo.hpp>
#include <cat/io/Settings.hpp>
#include <cat/mem/LargeAllocator.hpp>
using namespace cat;

PolledFileReader::PolledFileReader()
{
	u32 cache_size = Settings::ref()->getInt("IO.PolledFileReader.ReadAheadCacheSize", 1024*1024*2);
	u32 page_size = SystemInfo::ref()->GetPageSize();

	// Make it a multiple of the page size
	// NOTE: Actually needs to be sector aligned but if the file is on a CD then the sector size
	// is usually larger than any of the fixed disks.  The page size is usually larger than the
	// sector size of any media, so it is safe to use here.
	cache_size -= cache_size % page_size;
	cache_size += page_size;
	_cache_size = cache_size;

	// Allocate cache space and split it into two buffers
	_cache[0] = (u8*)LargeAllocator::ref()->Acquire(cache_size * 2);
	_cache[1] = _cache[0] + cache_size;
}

PolledFileReader::~PolledFileReader()
{
	LargeAllocator::ref()->Release(_cache[0]);
}

bool PolledFileReader::Open(const char *file_path, u32 worker_id)
{
	// If file could not be opened,
	if (!AsyncFile::Open(file_path, ASYNCFILE_READ))
	{
		CAT_WARN("PolledFileReader") << "Unable to open " << file_path;
		return false;
	}

	// Reset members
	_file_size = AsyncFile::GetSize();
	_offset = _cache_size * 2;
	_cache_front_index = 0;
	_cache_front_bytes = 0;
	_cache_back_bytes = 0;
	_cache_offset = 0;
	_cache_back_done = 0;

	_buffer.worker_id = worker_id;
	_buffer.callback.SetMember<PolledFileReader, &PolledFileReader::OnFirstRead>(this);

	CAT_FENCE_COMPILER

	// Read both buffers at once
	if (!AsyncFile::Read(&_buffer, 0, _cache[0], _cache_size * 2))
	{
		CAT_WARN("PolledFileReader") << "Unable to make initial read";

		// Simulate an EOF in Read()
		_cache_front_done = 1;
		_cache_back_done = 1;
		return false;
	}

	return true;
}

bool PolledFileReader::Read(u8 *buffer, u32 requested, u32 &bytes_read)
{
	// If front buffer hasn't finished reading yet,
	if (!_cache_front_done)
	{
		bytes_read = 0;
		return true;
	}

	CAT_FOREVER
	{
		// Calculate number of bytes to be read off the front buffer
		u32 front_remaining = _cache_front_bytes - _cache_offset;
		u32 front_read = min(front_remaining, requested);

		// Copy from front buffer
		memcpy(buffer, _cache[_cache_front_index] + _cache_offset, front_read);

		// Update counters
		buffer += front_read;
		bytes_read = front_read;
		requested -= front_read;
		_cache_offset += front_read;

		// If front still has more data, stop reading here
		if (front_remaining > front_read)
			break;

		// If back buffer read is not done, stop reading here
		if (!_cache_back_done)
			break;

		// If end of file was reached,
		if (_cache_back_bytes == 0)
			return false;

		// Otherwise swap in the new data to the front buffer
		_cache_front_bytes = _cache_back_bytes;
		_cache_back_bytes = 0;
		_cache_offset = 0;
		_cache_back_done = 0;

		CAT_FENCE_COMPILER

		// If read request fails,
		if (!AsyncFile::Read(&_buffer, _offset, _cache[_cache_front_index], _cache_size))
		{
			CAT_WARN("PolledFileReader") << "Unable to make initial read";
			Close();

			// Simulate an EOF condition
			_cache_back_done = 1;
			_cache_back_bytes = 0;
			break;
		}

		// Swap buffers
		_cache_front_index ^= 1;
		_offset += _cache_size;
	}

	return true;
}

void PolledFileReader::OnFirstRead(ThreadLocalStorage &tls, const BatchSet &buffers)
{
	// For each buffer,
	for (BatchHead *node = buffers.head; node; node = node->batch_next)
	{
		ReadBuffer *buffer = static_cast<ReadBuffer*>( node );
		u32 data_bytes = buffer->data_bytes;

		// Set the number of bytes in the back buffer
		_cache_back_bytes = data_bytes;

		// If the file is larger than a cache buffer,
		if (data_bytes > _cache_size)
		{
			_cache_front_bytes = _cache_size;
			data_bytes -= _cache_size;
		}
		else
		{
			_cache_front_bytes = data_bytes;
			data_bytes = 0;
		}

		_cache_back_done = 1;
		_cache_back_bytes = data_bytes;

		_buffer.callback.SetMember<PolledFileReader, &PolledFileReader::OnRead>(this);

		CAT_FENCE_COMPILER

		_cache_front_done = 1;

		// Just handle the first response - only ever have one outstanding at a time
		break;
	}
}

void PolledFileReader::OnRead(ThreadLocalStorage &tls, const BatchSet &buffers)
{
	// For each buffer,
	for (BatchHead *node = buffers.head; node; node = node->batch_next)
	{
		ReadBuffer *buffer = static_cast<ReadBuffer*>( node );
		u32 data_bytes = buffer->data_bytes;

		// Set the number of bytes in the back buffer
		_cache_back_bytes = data_bytes;

		CAT_FENCE_COMPILER

		_cache_back_done = 1;

		break;
	}
}
