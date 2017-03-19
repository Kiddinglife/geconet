/*
	Copyright (c) 2009-2012 Christopher A. Taylor.  All rights reserved.

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

#include <cat/iocp/AsyncFile.hpp>
#include <cat/io/Log.hpp>
#include <cat/io/Settings.hpp>
using namespace std;
using namespace cat;

bool AsyncFile::OnInitialize()
{
	return true;
}

void AsyncFile::OnDestroy()
{
	Close();
}

bool AsyncFile::OnFinalize()
{
	return true;
}

AsyncFile::AsyncFile()
{
    _file = INVALID_HANDLE_VALUE;
}

AsyncFile::~AsyncFile()
{
    Close();
}

bool AsyncFile::Open(const char *file_path, u32 async_file_modes)
{
	Close();

	u32 modes = 0, flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED;
	u32 creation = OPEN_EXISTING;

	if (async_file_modes & ASYNCFILE_READ)
		modes |= GENERIC_READ;

	if (async_file_modes & ASYNCFILE_WRITE)
	{
		modes |= GENERIC_WRITE;

		// Open it whether it exists or not
		creation = OPEN_ALWAYS;

		// If in truncate mode,
		if (async_file_modes & ASYNCFILE_TRUNC)
		{
			// Truncate existing file
			creation |= TRUNCATE_EXISTING;
		}
	}

	if (async_file_modes & ASYNCFILE_RANDOM)
		flags |= FILE_FLAG_RANDOM_ACCESS;
	else if (async_file_modes & ASYNCFILE_SEQUENTIAL)
		flags |= FILE_FLAG_SEQUENTIAL_SCAN;

	if (async_file_modes & ASYNCFILE_NOBUFFER)
		flags |= FILE_FLAG_NO_BUFFERING;

	_file = CreateFile(file_path, modes, 0, 0, creation, flags, 0);
	if (!_file) return false;

	if (!IOThreadPools::ref()->AssociateShared(this))
	{
		Close();
		return false;
	}

	return true;
}

void AsyncFile::Close()
{
	if (_file != INVALID_HANDLE_VALUE)
	{
		CloseHandle(_file);
		_file = INVALID_HANDLE_VALUE;
	}
}

bool AsyncFile::SetSize(u64 bytes)
{
	LARGE_INTEGER offset;

	offset.QuadPart = bytes;

	if (!SetFilePointerEx(_file, offset, 0, FILE_BEGIN))
	{
		CAT_WARN("AsyncFile") << "SetFilePointerEx error: " << GetLastError();
		return false;
	}

	if (!SetEndOfFile(_file))
	{
		CAT_WARN("AsyncFile") << "SetEndOfFile error: " << GetLastError();
		return false;
	}

	return true;
}

u64 AsyncFile::GetSize()
{
	LARGE_INTEGER size;

	if (!GetFileSizeEx(_file, &size))
		return 0;

	return size.QuadPart;
}

bool AsyncFile::Read(ReadBuffer *buffer, u64 offset, void *data, u32 bytes)
{
	buffer->data = data;
	buffer->iointernal.ov.Internal = 0;
	buffer->iointernal.ov.InternalHigh = 0;
	buffer->iointernal.ov.Offset = (u32)offset;
	buffer->iointernal.ov.OffsetHigh = (u32)(offset >> 32);
	buffer->iointernal.ov.hEvent = 0;
	buffer->iointernal.io_type = IOTYPE_FILE_READ;

	AddRef(CAT_REFOBJECT_TRACE);

	BOOL result = ReadFile(_file, data, bytes, 0, &buffer->iointernal.ov);

	if (!result && GetLastError() != ERROR_IO_PENDING)
	{
		CAT_WARN("AsyncFile") << "ReadFile error: " << GetLastError();
		ReleaseRef(CAT_REFOBJECT_TRACE);
		return false;
	}

	return true;
}

bool AsyncFile::Write(WriteBuffer *buffer, u64 offset, void *data, u32 bytes)
{
	buffer->data = data;
	buffer->iointernal.ov.Internal = 0;
	buffer->iointernal.ov.InternalHigh = 0;
	buffer->iointernal.ov.Offset = (u32)offset;
	buffer->iointernal.ov.OffsetHigh = (u32)(offset >> 32);
	buffer->iointernal.ov.hEvent = 0;
	buffer->iointernal.io_type = IOTYPE_FILE_WRITE;

	AddRef(CAT_REFOBJECT_TRACE);

	BOOL result = WriteFile(_file, data, bytes, 0, &buffer->iointernal.ov);

	if (!result && GetLastError() != ERROR_IO_PENDING)
	{
		CAT_WARN("AsyncFile") << "WriteFile error: " << GetLastError();
		ReleaseRef(CAT_REFOBJECT_TRACE);
		return false;
	}

	return true;
}
