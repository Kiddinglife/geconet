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

#include <cat/sphynx/FileTransfer.hpp>
#include <cat/threads/Atomic.hpp>
#include <cat/io/Log.hpp>
#include <cat/io/Settings.hpp>
#include <ext/lz4/lz4.h>
using namespace cat;
using namespace sphynx;


static UDPSendAllocator *m_udp_send_allocator = 0;
static u32 m_max_encode_streams = 0, m_max_decode_streams = 0, m_sector_bytes = 0;

static bool InitializeSingletons()
{
	m_udp_send_allocator = UDPSendAllocator::ref();
	return !!m_udp_send_allocator;
}

// NOTE: This is not thread-safe.  It would cause problems if the max streams setting changes during initialization.
// To avoid problems, don't programmatically change the max streams setting.

static u32 GetMaxEncodeStreams()
{
	// If max encode streams not initialized,
	if (!m_max_encode_streams)
	{
		// Retrieve it from settings
		m_max_encode_streams = Settings::ref()->getInt("Sphynx.FileTransfer.Encoder.MaxStreams", 4, 1, 255);
	}

	return m_max_encode_streams;
}

static u32 GetMaxDecodeStreams()
{
	// If max decode streams not initialized,
	if (!m_max_decode_streams)
	{
		// Retrieve it from settings
		m_max_decode_streams = Settings::ref()->getInt("Sphynx.FileTransfer.Decoder.MaxStreams", 4, 1, 255);
	}

	return m_max_decode_streams;
}

static u32 GetSectorBytes()
{
	// If max decode streams not initialized,
	if (!m_sector_bytes)
	{
		// Lookup sector size
		m_sector_bytes = SystemInfo::ref()->GetPageSize();

		CAT_DEBUG_ENFORCE(CAT_IS_POWER_OF_2(m_sector_bytes));
	}

	return m_sector_bytes;
}


//// Free functions

const char *cat::sphynx::GetTransferAbortReasonString(int reason)
{
	switch (reason)
	{
	case TXERR_NO_PROBLEMO:		return "OK";
	case TXERR_BUSY:			return "Source is not idle and cannot service another request";
	case TXERR_REJECTED:		return "Source rejected the request based on file name";
	case TXERR_INVALID_INPUT:	return "Operation input was invalid";
	case TXERR_BAD_STATE:		return "Operation requested in bad state";
	case TXERR_FILE_OPEN_FAIL:	return "Source unable to open the requested file";
	case TXERR_FILE_READ_FAIL:	return "Source unable to read part of the requested file";
	case TXERR_FILE_WRITE_FAIL:	return "Receiver unable to write part of the transmitted file";
	case TXERR_FEC_FAIL:		return "Forward error correction codec reported an error";
	case TXERR_OUT_OF_MEMORY:	return "Source ran out of memory";
	case TXERR_USER_ABORT:		return "Closed by user";
	case TXERR_SHUTDOWN:		return "Remote host is shutting down";
	default:					return "[Unknown]";
	}
}

#if defined(CAT_OS_WINDOWS)

// scctmnate() : AKA str_case_cmp_truncated_modulo_number_at_the_end()
// Preconditions: s_input nul-terminated, t_compare is nul-terminated and all lower-case
static bool scctmnate(const char *s_input, const char *t_compare)
{
	// For each character to compare,
	CAT_FOREVER
	{
		// If test string is empty, check modulo number at end
		char b = *t_compare++;
		if (!b) break;

		// If string to test is truncated,
		char a = *s_input++;
		if (!a) return false; // No match!

		// Convert both to lower-case
		char lower_a = a;
		if (lower_a >= 'A' && lower_a <= 'Z')
			lower_a += 'a' - 'A';

		// If input doesn't match a character,
		if (lower_a != b)
			return false; // No match!
	}

	// If exact match,
	char last_a = *s_input;
	if (!last_a) return true;

	// If last character is not a number,
	if (last_a < '0' || last_a > '9')
		return false; // Not a match!

	// It is a match if it ends in a single-digit number
	return (*++s_input == '\0');
}

#endif // CAT_OS_WINDOWS

bool cat::sphynx::IsValidFileTransferPath(const char *file_path)
{
	char c = *file_path++;

	// If filename is truncated, danger!
	if (!c) return false;

#if defined(CAT_OS_WINDOWS)

	// Get lower-case c
	char lower_c = c;
	if (lower_c >= 'A' && lower_c <= 'Z')
		lower_c += 'a' - 'A';

	// Test for Windows device file names
	switch (lower_c)
	{
	case 'c':
		if (scctmnate(file_path, "on"))
			return false;
		if (scctmnate(file_path, "om"))
			return false;
		if (scctmnate(file_path, "lock$"))
			return false;
		break;

	case 'p':
		if (scctmnate(file_path, "rn"))
			return false;
		break;

	case 'a':
		if (scctmnate(file_path, "ux"))
			return false;
		break;

	case 'n':
		if (scctmnate(file_path, "ul"))
			return false;
		break;

	case 'l':
		if (scctmnate(file_path, "pt"))
			return false;
		break;

	default:
		break;
	}

#endif // CAT_OS_WINDOWS

	do
	{
		// If a character is unusual, danger!
		if (c != ' ' &&
			c != '.' &&
			c != '_' &&
			(c < '0' || c > '9') &&
			(c < 'a' || c > 'z') &&
			(c < 'A' || c > 'Z'))
		{
			return false;
		}
	} while ((c = *file_path++));

	return true;
}


//// FECHugeEndpoint

FECHugeEndpoint::FECHugeEndpoint()
{
	_read_bytes = 0;
	_file = 0;

	_encode_streams = 0;
	_decode_streams = 0;
}

FECHugeEndpoint::~FECHugeEndpoint()
{
	CleanupEncoder();
	CleanupDecoder();
}

void FECHugeEndpoint::Initialize(Transport *transport, u8 opcode)
{
	// Initialize state
	_state = TXS_IDLE;
	_abort_reason = TXERR_NO_PROBLEMO;
	_transport = transport;
	_opcode = opcode;

	// Clear completion callbacks
	_on_send_done.Invalidate();
	_on_recv_done.Invalidate();

	// Use default validation callbacks
	_on_send_request.SetFree<&IsValidFileTransferPath>();
	_on_recv_request.SetFree<&IsValidFileTransferPath>();
}

bool FECHugeEndpoint::SetupEncoder()
{
	// Hack: Initialize singleton references here
	if (!InitializeSingletons()) return false;

	CleanupEncoder();

	if (_read_bytes == 0)
	{
		// Round up to the next multiple of the page size above CHUNK_TARGET_LEN
		const u32 sector_bytes = _lcm_sector_bytes;
		_read_bytes = CHUNK_TARGET_LEN - (CHUNK_TARGET_LEN & (sector_bytes - 1)) + sector_bytes;
		CAT_DEBUG_ENFORCE(_read_bytes >= CHUNK_TARGET_LEN);
	}

	const u32 max_encode_streams = GetMaxEncodeStreams();

	if (!_encode_streams)
	{
		// Allocate read buffer objects
		EncodeStream **streams = new (std::nothrow) EncodeStream*[max_encode_streams];
		if (!streams) return false;
		_encode_streams = streams;
	}

	// Initialize encode stream count
	_used_encode_streams = 0;

	return true;
}

int FECHugeEndpoint::GetFreeEncoderStream()
{
	// Re-use a slot if possible
	const u32 used_encode_streams = _used_encode_streams;
	for (u32 ii = 0; ii < used_encode_streams; ++ii)
	{
		// If stream is idle,
		if (_encode_streams[ii]->ready_flag == TXFLAG_IDLE)
		{
			return ii;
		}
	}

	// If already at the encode stream limit,
	if (used_encode_streams >= _encode_stream_limit)
		return -2;

	// Add a new EncodeStream object
	EncodeStream *stream;
	do stream = new (std::nothrow)EncodeStream;
	while (!stream);

	// Initialize the stream
	stream->read_buffer_object.callback = WorkerDelegate::FromMember<FECHugeEndpoint, &FECHugeEndpoint::OnFileRead>(this);

	// Determine number of bytes compression can inflate to when it fails
	u32 max_inflated_read_bytes = LZ4_compressBound(_read_bytes);

	// Allocate buffers
	u32 alloc_bytes = _read_bytes + max_inflated_read_bytes;
	CAT_INFO("FileTransfer") << "Allocating " << alloc_bytes << " bytes for file transfer buffers";

	// If allocation fails,
	u8 *read_buffer = (u8*)LargeAllocator::ref()->Acquire(alloc_bytes);
	if (!read_buffer)
	{
		delete stream;
		return -1; // Return error code
	}

	// Remember pointer to buffers
	stream->read_buffer = read_buffer;

	// Insert the new stream
	_encode_streams[used_encode_streams] = stream;

	// Increment the used encode stream count
	_used_encode_streams = used_encode_streams + 1;

	return used_encode_streams;
}

void FECHugeEndpoint::CleanupEncoder()
{
	CAT_WARN("FECHugeEndpoint") << "Cleanup encoder";

	// If encode streams are allocated,
	if (_encode_streams)
	{
		// Deallocate memory for each encode stream
		for (u32 ii = 0, count = m_max_encode_streams; ii < count; ++ii)
		{
			void *read_buffer = _encode_streams[ii]->read_buffer;
			if (read_buffer) LargeAllocator::ref()->Release(read_buffer);

			delete _encode_streams[ii];
		}

		// Deallocate memory for array
		delete []_encode_streams;
		_encode_streams = 0;
	}
}

bool FECHugeEndpoint::SetupDecoder()
{
	//TODO

	// Hack: Initialize singleton references here
	if (!InitializeSingletons()) return false;

	if (_read_bytes == 0)
	{
		// Round up to the next multiple of the page size above CHUNK_TARGET_LEN
		const u32 sector_bytes = _sector_bytes;
		_read_bytes = CHUNK_TARGET_LEN - (CHUNK_TARGET_LEN & (sector_bytes - 1)) + sector_bytes;
		CAT_DEBUG_ENFORCE(_read_bytes >= CHUNK_TARGET_LEN);
	}

	//const u32 num_decode_streams = _num_decode_streams;
    const u32 num_decode_streams = 5;
	if (!_decode_streams)
	{
		// Allocate streams
		DecodeStream *streams = new (std::nothrow) DecodeStream[num_decode_streams];
		if (!streams) return false;
		_decode_streams = streams;

		// Initialize buffers
		for (u32 ii = 0; ii < num_decode_streams; ++ii)
		{
			streams[ii].write_buffer_object.callback = WorkerDelegate::FromMember<FECHugeEndpoint, &FECHugeEndpoint::OnFileWrite>(this);
			streams[ii].requested = 0;
			streams[ii].read_buffer = 0;
		}
	}

	if (!_encode_streams[0].read_buffer)
	{
		// Determine number of bytes compression can inflate to when it fails
		u32 compress_bytes = LZ4_compressBound(_read_bytes);

		u32 compress_offset = _read_bytes * num_decode_streams;
		u32 alloc_bytes = compress_offset + compress_bytes * num_decode_streams;
		CAT_INFO("FileTransfer") << "Allocating " << alloc_bytes << " bytes for file transfer buffers";

		// Allocate read buffers
		u8 *buffer = (u8*)LargeAllocator::ref()->Acquire(alloc_bytes);
		if (!buffer) return false;

		// Initialize buffers
		u8 *read_buffer = buffer;
		u8 *compress_buffer = buffer + compress_offset;
		for (u32 ii = 0; ii < num_decode_streams; ++ii)
		{
			_encode_streams[ii].read_buffer = read_buffer;
			_encode_streams[ii].compress_buffer = compress_buffer;

			read_buffer += _read_bytes;
			compress_buffer += compress_bytes;
		}
	}

	return true;
}

void FECHugeEndpoint::CleanupDecoder()
{
	//TODO

	CAT_WARN("FECHugeEndpoint") << "Cleanup decoder";

	if (_decode_streams)
	{
		void *write_buffer = _decode_streams[0].write_buffer;
		if (write_buffer) LargeAllocator::ref()->Release(write_buffer);

		delete []_decode_streams;
		_decode_streams = 0;
	}
}

bool FECHugeEndpoint::OpenFileRead(const char *file_path)
{
	// If file is already open,
	if (_file)
	{
		CAT_WARN("FECHugeEndpoint") << "OpenFileRead: File was already open (bad state)";
		return false;
	}

	// Open new file
	AsyncFile *file;
	if (!RefObjects::ref()->Create(CAT_REFOBJECT_TRACE, file))
	{
		CAT_WARN("FECHugeEndpoint") << "OpenFileRead: Could not create refobject for " << file_path;
		return false;
	}

	// If file could not be opened,
	if (!file->Open(file_path, ASYNCFILE_READ | ASYNCFILE_SEQUENTIAL | ASYNCFILE_NOBUFFER))
	{
		CAT_WARN("FECHugeEndpoint") << "OpenFileRead: File " << file_path << " could not be opened for async sequential reading";
		file->Destroy(CAT_REFOBJECT_TRACE);
		return false;
	}

	// Cache file size
	_file_size = file->GetSize();

	// Store file object
	_file = file;

	return true;
}

bool FECHugeEndpoint::OpenFileWrite(const char *file_path)
{
	// If file is already open,
	if (_file)
	{
		CAT_WARN("FECHugeEndpoint") << "OpenFileWrite: File was already open (bad state)";
		return false;
	}

	// Open new file
	AsyncFile *file;
	if (!RefObjects::ref()->Create(CAT_REFOBJECT_TRACE, file))
	{
		CAT_WARN("FECHugeEndpoint") << "OpenFileWrite: Could not create refobject for " << file_path;
		return false;
	}

	// If file could not be opened,
	if (!file->Open(file_path, ASYNCFILE_WRITE | ASYNCFILE_TRUNC | ASYNCFILE_SEQUENTIAL | ASYNCFILE_NOBUFFER))
	{
		CAT_WARN("FECHugeEndpoint") << "OpenFileWrite: File " << file_path << " could not be opened for async sequential reading";
		file->Destroy(CAT_REFOBJECT_TRACE);
		return false;
	}

	// Store file object
	_file = file;

	return true;
}

void FECHugeEndpoint::OnFileRead(ThreadLocalStorage &tls, const BatchSet &set)
{
	// For each buffer in the set,
	for (BatchHead *node = set.head; node; node = node->batch_next)
	{
		// Unpack buffer
		ReadBuffer *buffer = static_cast<ReadBuffer*>( node );
		EncodeStream *stream = reinterpret_cast<EncodeStream*>( (u8*)buffer - offsetof(EncodeStream, read_buffer_object) );
		u8 *data = (u8*)buffer->data;

		// If buffer is not expected,
		if (stream->read_buffer != data)
		{
			CAT_WARN("FECHugeEndpoint") << "OnFileRead: Ignoring data from wrong buffer";
			_abort_reason = TXERR_INTERNAL;
			continue; // Ignore it
		}

		// If read failed,
		u32 bytes = buffer->data_bytes;
		if (bytes == 0)
		{
			CAT_WARN("FECHugeEndpoint") << "OnFileRead: File read with length = 0 indicating read failure";
			_abort_reason = TXERR_FILE_READ_FAIL;
			continue; // Ignore it
		}

		// Compress data (slow!)
		u8 *compress_buffer = stream->read_buffer + _read_bytes;
		int compress_bytes = LZ4_compress((const char*)data, (char*)compress_buffer, bytes);
		if (!compress_bytes)
		{
			compress_buffer = data;
			compress_bytes = bytes;
		}

		// Fix block bytes at the start of the transfer
		// Payload loadout = HDR(1) + TYPE|STREAM(1) + ID(3) + DATA
		int mss = _transport->GetMaxPayloadBytes();
		int block_bytes = CAT_FT_MSS_TO_BLOCK_BYTES(mss);

		// Grab stream ID from its hackish location
		const int stream_id = stream->next_id;

		// Set up stream state
		stream->mss = mss;
		stream->compress_bytes = compress_bytes;
		stream->next_id = 0;

		// Initialize the encoder (slow!)
		wirehair::Result r = stream->encoder.BeginEncode(compress_buffer, compress_bytes, block_bytes);
		if (r == wirehair::R_WIN || (r == wirehair::R_TOO_SMALL && compress_bytes <= block_bytes))
		{
			const u32 block_count = stream->encoder.BlockCount();

			CAT_WARN("FECHugeEndpoint") << "OnFileRead: Read " << bytes << " bytes, compressed to " << compress_bytes << " block_bytes=" << block_bytes << " and blocks=" << block_count;

			stream->ready_flag = TXFLAG_WAIT_ACK;

			// If could not post stream start,
			if (!PostStreamStart(buffer->offset, bytes, compress_bytes, block_bytes, stream_id))
			{
				CAT_WARN("FECHugeEndpoint") << "Unable to post start message";
				_abort_reason = TXERR_INTERNAL;
			}
		}
		else
		{
			stream->ready_flag = TXFLAG_IDLE;

			CAT_WARN("FECHugeEndpoint") << "Wirehair encoder failed with error " << wirehair::GetResultString(r);
			_abort_reason = TXERR_FEC_FAIL;
		}

		break;
	}
}

void FECHugeEndpoint::OnFileWrite(ThreadLocalStorage &tls, const BatchSet &set)
{
	// For each buffer in the set,
	for (BatchHead *node = set.head; node; node = node->batch_next)
	{
		// Unpack stream
		WriteBuffer *buffer = static_cast<WriteBuffer*>( node );
		DecodeStream *stream = reinterpret_cast<DecodeStream*>( (u8*)buffer - offsetof(DecodeStream, write_buffer_object) );

		// If write failed,
		if (buffer->data_bytes == 0)
		{
			CAT_WARN("FECHugeEndpoint") << "Write failure: " << GetLastError();
			_abort_reason = TXERR_FILE_WRITE_FAIL;
		}

		// Mark stream as idle for re-use
		stream->ready_flag = TXFLAG_IDLE;
	}
}

bool FECHugeEndpoint::PostPart(u32 stream_id, BatchSet &buffers, u32 &count)
{
	CAT_WARN("FECHugeEndpoint") << "PostPart for stream_id=" << stream_id;

	EncodeStream *stream = _encode_streams[stream_id];
	const u32 mss = stream->mss;

	u8 *msg = m_udp_send_allocator->Acquire(mss + SPHYNX_OVERHEAD);
	if (!msg) return false;

	// Generate header and length
	u32 hdr = IOP_HUGE | ((stream_id & FT_STREAM_ID_MASK) << FT_STREAM_ID_SHIFT);

	// Attach header
	msg[0] = Transport::HUGE_HEADER_BYTE;

	// Add compress bit to header
	u32 hdr_bytes;
	u32 data_id = stream->next_id++;
	if (data_id < 65536)
	{
		hdr |= FT_COMPRESS_ID_MASK;
		hdr_bytes = 4;
	}
	else
	{
		msg[4] = (u8)(data_id >> 16);
		hdr_bytes = 5;
	}

	// Write header
	msg[1] = hdr;
	msg[2] = (u8)data_id;
	msg[3] = (u8)(data_id >> 8);

	// If FEC is bypassed,
	u32 bytes;
	if (stream->encoder.BlockCount() <= 1)
	{
		bytes = stream->compress_bytes;
		memcpy(msg + hdr_bytes, stream->read_buffer, bytes);
	}
	else
	{
		bytes = stream->encoder.Encode(data_id, msg + hdr_bytes);
	}

	// Zero compression flag
	msg[hdr_bytes + bytes] = 0;

	// Carve out just the part of the buffer we're using
	SendBuffer *buffer = SendBuffer::Promote(msg);
	buffer->data_bytes = bytes + hdr_bytes + SPHYNX_OVERHEAD;

	// Add it to the list
	buffers.PushBack(buffer);
	++count;

	return true;
}

bool FECHugeEndpoint::PostPushRequest(const char *file_path)
{
	CAT_WARN("FECHugeEndpoint") << "PostPushRequest for file " << file_path;

	int file_name_length = (int)strlen(file_path);

	const u32 msg_bytes = 1 + 1 + file_name_length + 1;
	u8 *msg = OutgoingMessage::Acquire(msg_bytes);
	if (!msg) return false;

	msg[0] = _opcode;
	msg[1] = TOP_PUSH_REQUEST;
	memcpy(msg + 2, file_path, file_name_length + 1);

	return _transport->WriteReliableZeroCopy(STREAM_1, msg, msg_bytes);
}

bool FECHugeEndpoint::PostPullRequest(u32 sector_bytes, u8 stream_count, const char *file_path)
{
	CAT_WARN("FECHugeEndpoint") << "PostPullRequest for file " << file_path << " sector_bytes=" << sector_bytes << " stream_count=" << (int)stream_count;

	int file_name_length = (int)strlen(file_path);

	const u32 msg_bytes = 1 + 1 + 4 + 1 + file_name_length + 1;
	u8 *msg = OutgoingMessage::Acquire(msg_bytes);
	if (!msg) return false;

	msg[0] = _opcode;
	msg[1] = TOP_PULL_REQUEST;
	*(u32*)(msg + 2) = getLE(sector_bytes);
	msg[6] = stream_count;
	memcpy(msg + 7, file_path, file_name_length + 1);

	return _transport->WriteReliableZeroCopy(STREAM_1, msg, msg_bytes);
}

bool FECHugeEndpoint::PostPullGo(u32 lcm_sector_bytes, u64 file_bytes)
{
	CAT_WARN("FECHugeEndpoint") << "PostPullGo file_bytes=" << file_bytes << " lcm_sector_bytes=" << lcm_sector_bytes;

	const u32 msg_bytes = 1 + 1 + 4 + 8;
	u8 *msg = OutgoingMessage::Acquire(msg_bytes);
	if (!msg) return false;

	msg[0] = _opcode;
	msg[1] = TOP_PULL_GO;
	*(u32*)(msg + 2) = getLE(lcm_sector_bytes);
	*(u64*)(msg + 2 + 4) = getLE(file_bytes);

	return _transport->WriteReliableZeroCopy(STREAM_1, msg, msg_bytes);
}

bool FECHugeEndpoint::PostDeny(u8 reason)
{
	CAT_WARN("FECHugeEndpoint") << "PostDeny for reason " << (int)reason << " : " << GetTransferAbortReasonString(reason);

	const u32 msg_bytes = 1 + 1 + 1;
	u8 *msg = OutgoingMessage::Acquire(msg_bytes);
	if (!msg) return false;

	msg[0] = _opcode;
	msg[1] = TOP_DENY;
	msg[2] = reason;

	return _transport->WriteReliableZeroCopy(STREAM_1, msg, msg_bytes);
}

bool FECHugeEndpoint::PostStreamStart(u8 stream_id, u64 file_offset, u32 chunk_decompressed_size, u32 chunk_compressed_size, u16 block_bytes)
{
	CAT_WARN("FECHugeEndpoint") << "PostStreamStart stream_id=" << (int)stream_id << " file_offset=" << file_offset << " chunk_decompressed_size=" << chunk_decompressed_size << " chunk_compressed_size=" << chunk_compressed_size << " block_bytes=" << block_bytes;

	const u32 msg_bytes = 1 + 1 + 8 + 4 + 4 + 2 + 1;
	u8 *msg = OutgoingMessage::Acquire(msg_bytes);
	if (!msg) return false;

	msg[0] = _opcode;
	msg[1] = TOP_STREAM_START;
	msg[2] = stream_id;
	*(u64*)(msg + 3) = getLE(file_offset);
	*(u32*)(msg + 3 + 8) = getLE(chunk_decompressed_size);
	*(u32*)(msg + 3 + 8 + 4) = getLE(chunk_compressed_size);
	*(u16*)(msg + 3 + 8 + 4 + 4) = getLE(block_bytes);

	return _transport->WriteReliableZeroCopy(STREAM_1, msg, msg_bytes);
}

bool FECHugeEndpoint::PostStreamRequest(u8 stream_id, u16 request_count)
{
	CAT_WARN("FECHugeEndpoint") << "PostStreamRequest stream id=" << (int)stream_id << " request_count=" << request_count;

	const u32 msg_bytes = 1 + 1 + 1 + 2;
	u8 *msg = OutgoingMessage::Acquire(msg_bytes);
	if (!msg) return false;

	msg[0] = _opcode;
	msg[1] = TOP_STREAM_REQUEST;
	msg[2] = stream_id;
	*(u16*)(msg + 3) = getLE(request_count);

	return _transport->WriteReliableZeroCopy(STREAM_1, msg, msg_bytes);
}

bool FECHugeEndpoint::PostStreamDone(u8 stream_id)
{
	CAT_WARN("FECHugeEndpoint") << "PostStreamDone stream_id=" << stream_id;

	const u32 msg_bytes = 1 + 1 + 1;
	u8 *msg = OutgoingMessage::Acquire(msg_bytes);
	if (!msg) return false;

	msg[0] = _opcode;
	msg[1] = TOP_STREAM_DONE;
	msg[2] = (u8)stream_id;

	return _transport->WriteReliableZeroCopy(STREAM_1, msg, msg_bytes);
}

bool FECHugeEndpoint::PostRate(u32 rate_counter)
{
	CAT_WARN("FECHugeEndpoint") << "PostRate rate_counter=" << rate_counter;

	const u32 msg_bytes = 1 + 1 + 4;
	u8 *msg = OutgoingMessage::Acquire(msg_bytes);
	if (!msg) return false;

	msg[0] = _opcode;
	msg[1] = TOP_RATE;
	*(u32*)(msg + 2) = getLE(rate_counter);

	return _transport->WriteReliableZeroCopy(STREAM_1, msg, msg_bytes);
}

bool FECHugeEndpoint::PostClose(u8 reason)
{
	CAT_WARN("FECHugeEndpoint") << "PostClose for reason " << reason << " : " << GetTransferAbortReasonString(reason);

	const u32 msg_bytes = 1 + 1 + 1;
	u8 *msg = OutgoingMessage::Acquire(msg_bytes);
	if (!msg) return false;

	msg[0] = _opcode;
	msg[1] = TOP_CLOSE;
	msg[2] = reason;

	return _transport->WriteReliableZeroCopy(STREAM_1, msg, msg_bytes);
}

CAT_INLINE u32 gcd(u32 a, u32 b)
{
	if (!b) return a;

	CAT_FOREVER
	{
		a %= b;
		if (!a) return b;

		b %= a;
		if (!b) return a;
	}
}

void FECHugeEndpoint::OnPushRequest(const char *file_path)
{
	// If state is not idle,
	if (_state != TXS_IDLE)
	{
		CAT_WARN("FECHugeEndpoint") << "OnPushRequest: Ignoring push request for file " << file_path << " as state is not idle";
		PostDeny(TXERR_BUSY);
		return;
	}

	// If recv request callback rejects the file path,
	if (_on_recv_request.IsValid() && !_on_recv_request(file_path))
	{
		CAT_WARN("FECHugeEndpoint") << "OnPushRequest: Rejecting push request for file " << file_path << " by callback";
		PostDeny(TXERR_REJECTED);
		return;
	}

	// If unable to post a pull request,
	if (!PostPullRequest(GetSectorBytes(), GetMaxDecodeStreams(), file_path))
	{
		CAT_WARN("FECHugeEndpoint") << "OnPushRequest: Unable to post pull request";
		PostDeny(TXERR_OUT_OF_MEMORY);
		return;
	}

	CAT_WARN("FECHugeEndpoint") << "OnPushRequest: Accepted push request for file " << file_path;
}

void FECHugeEndpoint::OnPullRequest(u32 sector_bytes, u8 stream_count, const char *file_path)
{
	// If input is invalid,
	if (stream_count == 0)
	{
		CAT_WARN("FECHugeEndpoint") << "OnPullRequest: Stream count invalid";
		PostDeny(TXERR_INVALID_INPUT);
		return;
	}

	// If state is not idle,
	if (_state != TXS_IDLE)
	{
		CAT_WARN("FECHugeEndpoint") << "OnPullRequest: Ignoring pull request for file " << file_path << " because state is not idle";
		PostDeny(TXERR_BUSY);
		return;
	}

	// If send request callback rejects the file path,
	if (_on_send_request.IsValid() && !_on_send_request(file_path))
	{
		CAT_WARN("FECHugeEndpoint") << "OnPullRequest: File " << file_path << " rejected by send request callback";
		PostDeny(TXERR_REJECTED);
		return;
	}

	// If not able to open,
	if (!OpenFileRead(file_path))
	{
		CAT_WARN("FECHugeEndpoint") << "OnPullRequest: File " << file_path << " could not be opened";
		PostDeny(TXERR_FILE_OPEN_FAIL);
		return;
	}

	// Calculate LCM of remote and local sector bytes
	const u32 local_sector_bytes = GetSectorBytes();
	_lcm_sector_bytes = local_sector_bytes * sector_bytes / gcd(local_sector_bytes, sector_bytes);

	// Initialize the encode stream limit for this session
	const int remote_stream_count = stream_count;
	int chosen_stream_count = GetMaxEncodeStreams();
	if (chosen_stream_count > remote_stream_count)
		chosen_stream_count = remote_stream_count;
	_encode_stream_limit = chosen_stream_count;

	// If unable to setup encoder,
	int stream_id;
	if (!SetupEncoder() || (stream_id = GetFreeEncoderStream()) < 0)
	{
		CAT_WARN("FECHugeEndpoint") << "OnPullRequest: Could not initialize buffers (out of memory) for " << file_path;
		DestroyFileObject();
		PostDeny(TXERR_OUT_OF_MEMORY);
		return;
	}

	// Initialize state
	_state = TXS_PUSHING;
	_abort_reason = TXERR_NO_PROBLEMO;

	CAT_WARN("FECHugeEndpoint") << "OnPullRequest: Starting to read " << file_path;

	// If read could not be started,
	if (!StartRead(stream_id, 0, _read_bytes))
	{
		CAT_WARN("FECHugeEndpoint") << "OnPullRequest: Unreadable file " << file_path;
		_state = TXS_IDLE;
		DestroyFileObject();
		PostDeny(TXERR_FILE_READ_FAIL);
		return;
	}
}

void FECHugeEndpoint::OnPullGo(u32 lcm_sector_bytes, u64 file_bytes)
{
	CAT_WARN("FECHugeEndpoint") << "OnPullGo file_bytes=" << file_bytes << " stream_count=" << stream_count << " sector_bytes=" << sector_bytes;

	// Validate incoming sector bytes:

	// If sector bytes is not a multiple of our own or is ridiculously large,
	if (lcm_sector_bytes <= 0 ||
		lcm_sector_bytes % m_sector_bytes != 0 ||
		lcm_sector_bytes > CHUNK_TARGET_LEN / 2)
	{
		CAT_WARN("FECHugeEndpoint") << "OnPullGo: Rejected sector bytes that is invalid";
		_abort_reason = TXERR_INVALID_INPUT;
		return;
	}

	// Store LCM sector bytes from remote host
	_lcm_sector_bytes = lcm_sector_bytes;

	// Store file size
	_file_size = file_bytes;
}

void FECHugeEndpoint::OnDeny(int reason)
{
	CAT_WARN("FECHugeEndpoint") << "OnDeny for reason " << reason << " : " << GetTransferAbortReasonString(reason);

	// TODO
}

void FECHugeEndpoint::OnStreamStart(u64 file_offset, u32 chunk_decompressed_size, u32 chunk_compressed_size, int block_bytes, int stream_id)
{
	CAT_WARN("FECHugeEndpoint") << "OnStreamStart file_offset=" << file_offset << " chunk_decompressed_size=" << chunk_decompressed_size << " chunk_compressed_size=" << chunk_compressed_size << " block_bytes=" << block_bytes << " stream_id=" << stream_id;

	// TODO
}

void FECHugeEndpoint::OnStreamStartAck(int stream_id)
{
	CAT_WARN("FECHugeEndpoint") << "OnStreamStartAck for stream_id=" << stream_id;

	// TODO
}

void FECHugeEndpoint::OnStreamDone(int stream_id)
{
	CAT_WARN("FECHugeEndpoint") << "OnStreamDone for stream_id=" << stream_id;

	// If stream ID is invalid,
	if (stream_id >= _used_encode_streams)
	{
		CAT_WARN("FECHugeEndpoint") << "OnStreamDone: Input stream ID is unused";
		_abort_reason = TXERR_INVALID_INPUT;
		return;
	}

	// Lookup stream
	EncodeStream *stream = _encode_streams[stream_id];

	// Mark it as idle so that it can be reused, regardless of state
	stream->ready_flag = TXFLAG_IDLE;
}

void FECHugeEndpoint::OnRate(u32 rate_counter)
{
	CAT_WARN("FECHugeEndpoint") << "OnRate with rate_counter=" << rate_counter;

	// TODO
}

void FECHugeEndpoint::OnRequest(int stream_id, int request_count)
{
	CAT_WARN("FECHugeEndpoint") << "OnRequest with stream_id=" << stream_id << " and request_count=" << request_count;

	// If stream ID is invalid,
	if (stream_id >= _used_encode_streams ||
		request_count <= 0)
	{
		CAT_WARN("FECHugeEndpoint") << "OnRequest: Input invalid";
		_abort_reason = TXERR_INVALID_INPUT;
		return;
	}

	// Lookup stream
	EncodeStream *stream = _encode_streams[stream_id];
	if (stream->ready_flag == TXFLAG_IDLE)
	{
		CAT_WARN("FECHugeEndpoint") << "OnRequest: Ignoring request operation on idle stream";
		_abort_reason = TXERR_BAD_STATE;
		return;
	}

	// Increment requests by the provided count
	stream->requested += request_count;
}

void FECHugeEndpoint::OnClose(int reason)
{
	CAT_WARN("FECHugeEndpoint") << "OnClose for reason " << reason << " : " << GetTransferAbortReasonString(reason);

	_abort_reason = reason;
}

bool FECHugeEndpoint::HasData()
{
	// If state is not pushing, there is no data to send
	if (_state != TXS_PUSHING)
		return false;

	// If there is an abort message to send,
	if (_abort_reason != TXERR_NO_PROBLEMO)
		return true;

	// For each stream,
	for (u32 ii = 0, count = _used_encode_streams; ii < count; ++ii)
	{
		EncodeStream *stream = _encode_streams[ii];

		// If any stream has data to send,
		if (stream->requested > 0)
			return true;
	}

	// No data to send
	return false;
}

s32 FECHugeEndpoint::NextHuge(s32 available, BatchSet &buffers, u32 &count)
{
	s32 used = 0;

	// If no space, abort
	if (available <= 0) return 0;

	// If abortion requested,
	if (_abort_reason != TXERR_NO_PROBLEMO)
	{
		// NOTE: This will actually be sent late on the next tick
		PostClose(_abort_reason);

		_abort_reason = TXERR_NO_PROBLEMO;
		_state = TXS_IDLE;

		if (_file)
			_file->Destroy(CAT_REFOBJECT_TRACE);

		return 0;
	}

	// If state is idle, abort
	if (_state == TXS_IDLE) return 0;

	// If no streams, abort
	if (!_encode_streams) return 0;

	CAT_WARN("FECHugeEndpoint") << "NextHuge available=" << available;

	// Send requested streams first
	for (u32 stream_id = 0, count = _used_encode_streams; stream_id < count; ++stream_id)
	{
		// If non-dominant stream is requested,
		EncodeStream *stream = _encode_streams[stream_id];
		while (stream->requested > 0)
		{
			// Attempt to post a part of this stream
			if (!PostPart(stream_id, buffers, count))
				break;

			// Reduce request count on success
			// And if it reaches zero,
			if (--stream->requested == 0)
			{
				// Mark stream as stalled waiting for STREAM_DONE
				stream->ready_flag = TXFLAG_STALLED;
			}

			// If out of room,
			used += stream->mss;
			if (used >= available)
				return used;	// Done for now!
		}
	}

	// Still more bandwidth but nothing to do!  Add more streams!

	// If there are more streams to go,
	if (_file_offset < _file_size)
	{

	}

	return used;
}

void FECHugeEndpoint::OnHuge(u8 *data, u32 bytes)
{
	CAT_WARN("FECHugeEndpoint") << "OnHuge" << HexDumpString(data, bytes);

	// TODO
}

void FECHugeEndpoint::OnControlMessage(u8 *data, u32 bytes)
{
	if (bytes < 2)
	{
		CAT_WARN("FECHugeEndpoint") << "Ignored truncated control message";
		return;
	}

	if (data[0] != _opcode)
	{
		CAT_WARN("FECHugeEndpoint") << "Ignored control message with wrong opcode";
		return;
	}

	switch (data[1])
	{
	// Transmitter requesting to push a file, will cause receiver to issue a pull request
	case TOP_PUSH_REQUEST:	// HDR | FileName(X)
		if (bytes >= 2)
		{
			const char *file_path = reinterpret_cast<const char*>( data + 2 );

			// Ensure it is null-terminated
			data[bytes-1] = 0;

			OnPushRequest(file_path);
		}
		break;

	// Receiver requesting to pull a file
	case TOP_PULL_REQUEST:	// HDR | SectorBytes(4) | FileName(X)
		if (bytes >= 7)
		{
			u32 sector_bytes = getLE(*(u32*)(data + 2));
			const char *file_path = reinterpret_cast<const char*>( data + 2 + 4 );

			// Ensure it is null-terminated
			data[bytes-1] = 0;

			OnPullRequest(sector_bytes, file_path);
		}
		break;

	// Transmitter indicating start of a file transfer
	case TOP_PULL_GO:		// HDR | SectorBytes(4) | FileBytes(8) | StreamCount(1)
		if (bytes >= 15)
		{
			u32 sector_bytes = getLE(*(u32*)(data + 2));
			u64 file_bytes = getLE(*(u64*)(data + 2 + 4));
			int stream_count = (u32)data[2 + 4 + 8];

			OnPullGo(sector_bytes, file_bytes, stream_count);
		}
		break;

	// Deny a push or pull request with a reason
	case TOP_DENY:			// HDR | Reason(1)
		if (bytes >= 3)
		{
			int reason = (u32)data[2];

			OnDeny(reason);
		}
		break;

	// Transmitter notifying receiver that a stream is starting
	case TOP_STREAM_START:			// HDR | FileOffset(8) | ChunkDecompressedSize(4) | ChunkCompressedSize(4) | BlockBytes(2) | StreamID(1)
		if (bytes >= 21)
		{
			u64 file_offset = getLE(*(u64*)(data + 2));
			u32 chunk_decompressed_size = getLE(*(u32*)(data + 10));
			u32 chunk_compressed_size = getLE(*(u32*)(data + 14));
			int block_bytes = getLE(*(u16*)(data + 18));
			int stream_id = (u32)data[20];

			OnStreamStart(file_offset, chunk_decompressed_size, chunk_compressed_size, block_bytes, stream_id);
		}
		break;

	// Receiver notifying transmitter that it is ready to receive a stream
	case TOP_STREAM_GO:		// HDR | StreamID(1)
		if (bytes >= 3)
		{
			int stream_id = (u32)data[2];

			OnStreamStartAck(stream_id);
		}
		break;

	// Receiver notifying transmitter that it has finished a stream
	case TOP_STREAM_DONE:		// HDR | StreamID(1)
		if (bytes >= 3)
		{
			int stream_id = (u32)data[2];

			OnStreamDone(stream_id);
		}
		break;

	// Adjust transmit rate on all streams
	case TOP_RATE:			// HDR | RateCounter(4)
		if (bytes >= 6)
		{
			u32 rate_counter = getLE(*(u32*)(data + 2));

			OnRate(rate_counter);
		}
		break;

	// Request a number of blocks on a stream
	case TOP_STREAM_REQUEST:		// HDR | StreamID(1) | RequestCount(2)
		if (bytes >= 5)
		{
			int stream_id = (u32)data[2];
			int request_count = getLE(*(u16*)(data + 3));

			OnRequest(stream_id, request_count);
		}
		break;

	// Close transfer and indicate reason (including success)
	case TOP_CLOSE:			// HDR | Reason(1)
		if (bytes >= 3)
		{
			int reason = (u32)data[2];

			OnClose(reason);
		}
		break;
	}
}

bool FECHugeEndpoint::Request(const char *file_path)
{
	if (_state != TXS_IDLE)
	{
		CAT_WARN("FECHugeEndpoint") << "File transfer request ignored: Busy";
		return false;
	}

	return PostPullRequest(GetSectorBytes(), file_path);
}

bool FECHugeEndpoint::Send(const char *file_path)
{
	if (_state != TXS_IDLE)
	{
		CAT_WARN("FECHugeEndpoint") << "File transfer send ignored: Busy";
		return false;
	}

	return PostPushRequest(file_path);
}
