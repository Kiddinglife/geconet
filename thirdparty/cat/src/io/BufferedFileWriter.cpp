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

#include <cat/io/BufferedFileWriter.hpp>
#include <cat/io/FileWriteAllocator.hpp>
#include <cat/io/Settings.hpp>
using namespace cat;

static FileWriteAllocator *m_file_write_allocator = 0;
static Settings *m_settings = 0;


//// BufferedFileWriter

bool BufferedFileWriter::OnInitialize()
{
	Use(m_file_write_allocator, m_settings);

	_cache_bucket_size = m_file_write_allocator->GetBufferBytes();

	_cache_bucket_count = m_settings->getInt("IO::BufferedFileWriter.BufferCount", DEFAULT_BUFFER_COUNT, MIN_BUFFER_COUNT, MAX_BUFFER_COUNT);

	_cache_set.Clear();

	return AsyncFile::OnInitialize();
}

bool BufferedFileWriter::OnFinalize()
{
	if (_cache_set.head) m_file_write_allocator->ReleaseBatch(_cache_set);

	return AsyncFile::OnFinalize();
}

bool BufferedFileWriter::Open(const char *file_path, u64 file_size, u32 worker_id)
{
	// If file could not be opened,
	if (!AsyncFile::Open(file_path, ASYNCFILE_WRITE | ASYNCFILE_SEQUENTIAL | ASYNCFILE_NOBUFFER))
	{
		CAT_WARN("BufferedFileWriter") << "Unable to open " << file_path;
		return false;
	}

	u64 rounded_file_size = file_size;
	u32 overflow_bytes = (u32)file_size & (_cache_bucket_size-1);

	// Round up to next bucket size multiple
	if (overflow_bytes)
		rounded_file_size += _cache_bucket_size - overflow_bytes;

	// If resizing fails,
	if (!AsyncFile::SetSize(rounded_file_size))
	{
		CAT_WARN("BufferedFileWriter") << "Unable to resize " << file_path;
		return false;
	}

	_file_size = file_size;
	_file_offset = 0;
	_worker_id = worker_id;

	return true;
}

void BufferedFileWriter::OnWrite(ThreadLocalStorage &tls, const BatchSet &set)
{
	m_file_write_allocator->ReleaseBatch(set);
}

bool BufferedFileWriter::Write(const u8 *in_buffer, u32 bytes)
{
	// While there is data left to write,
	while (bytes > 0)
	{
		// Check output buffer
		WriteBuffer *out_buffer = reinterpret_cast<WriteBuffer*>( _cache_set.head );

		// If no output buffer exists,
		if (!out_buffer)
		{
			m_file_write_allocator->AcquireBatch(_cache_set, _cache_bucket_count);

			_cache_bucket_offset = 0;
			out_buffer = reinterpret_cast<WriteBuffer*>( _cache_set.head );

			if (!out_buffer)
			{
				// TODO: Fall back on malloc
				CAT_WARN("BufferedFileWriter") << "Out of memory";
				return false;
			}
		}

		// Prepare to copy
		u8 *data = static_cast<u8*>( out_buffer->data );
		u32 write_bytes = bytes;
		u32 remaining = _cache_bucket_size - _cache_bucket_offset;
		if (write_bytes > remaining)
			write_bytes = remaining;

		// Copy and consume data bytes
		memcpy(data + _cache_bucket_offset, in_buffer, write_bytes);
		bytes -= write_bytes;
		_cache_bucket_offset += write_bytes;

		// If out of cache space,
		if (_cache_bucket_offset >= _cache_bucket_size)
		{
			// Write buffer
			out_buffer->callback = WorkerDelegate::FromMember<BufferedFileWriter, &BufferedFileWriter::OnWrite>(this);
			out_buffer->worker_id = _worker_id;

			if (!AsyncFile::Write(out_buffer, _file_offset, data, _cache_bucket_size))
			{
				// TODO: Fail gracefully
				CAT_WARN("BufferedFileWriter") << "Unable to write a bucket to disk at offset " << _file_offset;
				return false;
			}

			// Remove this buffer from the cache set
			_cache_set.head = out_buffer->batch_next;
			_cache_bucket_offset = 0;
			_file_offset += _cache_bucket_size;
		}
		// If at the final buffer,
		else if (_file_size - _file_offset <= _cache_bucket_offset)
		{
			// Zero remaining data in the buffer
			memset(data + _cache_bucket_offset, 0, _cache_bucket_size - _cache_bucket_offset);

			// Write buffer
			out_buffer->callback = WorkerDelegate::FromMember<BufferedFileWriter, &BufferedFileWriter::OnWrite>(this);
			out_buffer->worker_id = _worker_id;

			if (!AsyncFile::Write(out_buffer, _file_offset, data, _cache_bucket_size))
			{
				// TODO: Fail gracefully
				CAT_WARN("BufferedFileWriter") << "Unable to write a bucket to disk at offset " << _file_offset;
				return false;
			}
		}
	}

	return true;
}
