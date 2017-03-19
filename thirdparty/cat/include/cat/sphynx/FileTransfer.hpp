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

#ifndef CAT_SPHYNX_FILE_TRANSFER_HPP
#define CAT_SPHYNX_FILE_TRANSFER_HPP

#include <cat/sphynx/Transport.hpp>
#include <cat/fec/Wirehair.hpp>
#include <vector>
#include <queue> // priority_queue<>

/*
	File Transfer Header Format

	<--- LSB      MSB --->
	0 1 2|3|4|5 6|7|0 1|2 3 4 5 6|7| 0 1 2 3 4 5 6 7 | 0 1 2 3 4 5 6 7 | 0 1 2 3 4 5 6 7
	-----|-|-|---|-|---|---------|-|-----------------|-----------------|----------------
	 BLO |I|R|SOP|C|IOP|STREAM_ID|X| A A A A A A A A | B B B B B B B B | C C C C C C C C

	BLO = 1 (arbitrary)
	I = 1, R = 0 (indicating message takes whole datagram)
	SOP = INTERNAL
	C = 0
	IOP = HUGE
	STREAM_ID = Which concurrent FEC stream it corresponds to 0..31
	X = 0:No effect, 1:Part C of ID is implicitly zero and is not sent
	ID = C | B | A (high to low)

	Block data is appended to the header, and should be produced by Wirehair FEC.
*/

namespace cat {


namespace sphynx {


enum TransferOpCodes
{
	// Transmitter requesting to push a file, will cause receiver to issue a pull request
	// FileName : Name of file to push
	TOP_PUSH_REQUEST,	// HDR | FileName(X)

	// Receiver requesting to pull a file
	// SectorBytes : Number of bytes per sector for receiver
	// StreamCount : Maximum number of parallel streams accepted by receiver
	// FileName : Name of file to pull
	TOP_PULL_REQUEST,	// HDR | SectorBytes(4) | StreamCount(1) | FileName(X)

	// Transmitter indicating start of a file transfer
	// LCMSectorBytes : Lowest common multiple of number of bytes per sector for both ends
	// FileBytes : Number of bytes to transfer
	TOP_PULL_GO,		// HDR | LCMSectorBytes(4) | FileBytes(8)

	// Deny a push or pull request with a reason
	// Reason : TXERR_ code
	TOP_DENY,			// HDR | Reason(1)

	// Transmitter notifying receiver that a stream is starting (will wait for first request)
	// FileOffset : Offset into file for this stream (will be a multiple of sector size)
	// ChunkDecompressedSize : Number of bytes after decompression in this stream chunk
	// ChunkCompressedSize : Number of bytes after compression in this stream chunk
	// BlockBytes : Number of bytes of file data per packet
	// StreamID : Which stream it corresponds to
	TOP_STREAM_START,	// HDR | StreamID(1) | FileOffset(8) | ChunkDecompressedSize(4) | ChunkCompressedSize(4) | BlockBytes(2)

	// Receiver requesting a number of blocks on a stream (also used for first go)
	// StreamID : Which stream it corresponds to
	// RequestCount : Number of additional blocks to request
	TOP_STREAM_REQUEST,	// HDR | StreamID(1) | RequestCount(2)

	// Receiver notifying transmitter that it has finished a stream
	// StreamID : Which stream it corresponds to
	TOP_STREAM_DONE,	// HDR | StreamID(1)

	// Adjust transmit rate on all streams
	// RateCounter: Speed of transfer
	TOP_RATE,			// HDR | RateCounter(4)

	// Close transfer and indicate reason (including success)
	// Reason : TXERR_ code
	TOP_CLOSE,			// HDR | Reason(1)
};

/*
	File Transfer Protocol

	Example client->server flow:

	c2s TOP_PUSH_REQUEST "ThisIsSparta.txt"
	s2c TOP_PULL_REQUEST (sector size: 4096 bytes) (4 streams max) "ThisIsSparta.txt"
	c2s TOP_PULL_GO (sector size: 8192 bytes) (4 streams) (length: 4,650,000 bytes)
	c2s TOP_STREAM_START (stream 0) (file offset 0) (4,000,000 bytes decompressed) (3,500,000 bytes compressed) (1398 bytes per block)
	s2c TOP_STREAM_REQUEST (stream 0) (2504 blocks - whole chunk)
	s2c TOP_RATE (50 KB/s)
	c2s <HUGE DATA TRANSFER HERE>
	s2c TOP_RATE (70 KB/s)
	c2s <HUGE DATA TRANSFER HERE>
	s2c TOP_RATE (100 KB/s)
	c2s <HUGE DATA TRANSFER HERE>
	s2c TOP_STREAM_REQUEST (stream 0) (3 blocks - however much is missing)
	c2s TOP_STREAM_START (stream 1) (file offset 4,000,000) (650,000 bytes decompressed) (420,000 bytes compressed) (1398 bytes per block)
	s2c TOP_STREAM_REQUEST (stream 1) (2 blocks - whole chunk)
	c2s <HUGE DATA TRANSFER HERE>
	s2c TOP_STREAM_DONE (stream 0)
	s2c TOP_STREAM_DONE (stream 1)
	s2c TOP_CLOSE (success code!)

	Encode streams are added whenever there is no more data requested but more data to send in the file.
*/

enum TransferAbortReasons
{
	TXERR_NO_PROBLEMO,		// OK

	TXERR_BUSY,				// Source is not idle and cannot service another request
	TXERR_REJECTED,			// Source rejected the request based on file name
	TXERR_INVALID_INPUT,	// Operation input was invalid
	TXERR_BAD_STATE,		// Operation requested in bad state
	TXERR_FILE_OPEN_FAIL,	// Source unable to open the requested file
	TXERR_FILE_READ_FAIL,	// Source unable to read part of the requested file
	TXERR_FILE_WRITE_FAIL,	// Receiver unable to write part of the transmitted file
	TXERR_FEC_FAIL,			// Forward error correction codec reported an error
	TXERR_OUT_OF_MEMORY,	// Source ran out of memory
	TXERR_USER_ABORT,		// Closed by user
	TXERR_SHUTDOWN,			// Remote host is shutting down
	TXERR_INTERNAL,			// Some kind of internal error occurred
};


// Get string from reason code
const char *GetTransferAbortReasonString(int reason);

// Default file transfer path checker if no callback is specified
bool IsValidFileTransferPath(const char *file_path);


enum TransferStatusFlags
{
	TXFLAG_LOADING,		// Waiting on file input completion
	TXFLAG_WAIT_ACK,	// Waiting on start acknowledgment from receiver
	TXFLAG_PUSH,		// Exceptional case where FEC cannot be used since the data fits in one datagram
	TXFLAG_STALLED,		// Not transmitting any new data
	TXFLAG_IDLE,		// Not being used
};

static const u32 FT_STREAM_ID_SHIFT = 2;
static const u32 FT_STREAM_ID_MASK = 31;
static const u32 FT_COMPRESS_ID_MASK = 0x80;
static const u32 FT_MAX_HEADER_BYTES = 1 + 1 + 3;

#define CAT_FT_MSS_TO_BLOCK_BYTES(mss) ( (mss) - FT_MAX_HEADER_BYTES )


/*
	FECHugeEndpoint
*/
class CAT_EXPORT FECHugeEndpoint : public IHugeEndpoint
{
public:
	// Delegate types:

	// Return true to accept the file request (may still fail if file is not accessible)
	typedef Delegate1<bool, const char * /*file name*/> OnSendRequest;

	// Callback when file transfer completes, either with success or failure (check reason parameter)
	typedef Delegate1<void, int /*reason*/> OnSendDone;

	// Return true to accept the file request (may still fail if file is not accessible)
	typedef Delegate1<bool, const char * /*file name*/> OnRecvRequest;

	// Callback when file transfer completes, either with success or failure (check reason parameter)
	typedef Delegate1<void, int /*reason*/> OnRecvDone;

protected:
	static const u32 OVERHEAD = 1 + 1 + 3; // HDR(1) + IOP_HUGE|STREAM(1) + ID(3)
	static const u32 CHUNK_TARGET_LEN = 4000000; // 4 MB

	// State that the object is in, to switch between pushing and pulling
	enum TransferState
	{
		TXS_IDLE,

		TXS_PULLING,
		TXS_PUSHING,
	} _state;

	u32 _sector_bytes;		// Number of bytes per sector on the disk
	u32 _lcm_sector_bytes;	// LCM sector bytes between two endpoints

	bool InitializeSectorBytes();

	Transport *_transport;	// Transport object to use for posting messages
	u32 _read_bytes;		// Number of bytes to read in each chunk (multiple of page size)
	u8 _opcode;				// Message opcode to use for reliable messages (to integrate with other user opcodes)

	OnSendRequest _on_send_request;
	OnSendDone _on_send_done;
	OnRecvRequest _on_recv_request;
	OnRecvDone _on_recv_done;

	volatile u32 _abort_reason;		// If non-zero: Abort transfer with this reason

	AsyncFile *_file;				// AsyncIO file object
	u64 _file_size;					// Cached file size
	u64 _file_offset;				// Next read offset

	// Interleaved encoder streams
	struct EncodeStream
	{
		volatile u32 ready_flag;		// Synchronization flag
		u8 *read_buffer;				// Pointer to buffer receiving raw file data
		//u32 block_count;				// Number of blocks (not needed: can query from Encoder)
		//u8 *compress_buffer;			// Pointer to compressed data buffer (this is always calculated = buffer + _read_bytes)
		ReadBuffer read_buffer_object;	// AsyncIO read buffer object
		wirehair::Encoder encoder;		// FEC encoder object
		u32 next_id;					// Next ID number to transmit; initially used to store stream id until read
		u32 mss;						// Maximum segment size, which is the number of bytes sent per message
		u32 compress_bytes;				// Number of bytes that the file part compressed to
		int requested;					// Number of messages requested to send
	} **_encode_streams;				// Array of EncodeStream objects, initially all zero

	u32 _encode_stream_limit;			// Maximum number of encode streams permitted by receiver (at or below global limit)
	u32 _used_encode_streams;			// Number of encode streams that are in use (always 0..u-1)

	bool SetupEncoder();

	// Returns < 0 if it is unable to add the stream (maybe too many streams, etc)
	// Else returns stream id that was added
	int GetFreeEncoderStream();

	void CleanupEncoder();

	// Interleaved decoder streams
	struct DecodeStream
	{
		volatile u32 ready_flag;			// Synchronization flag
		u8 *write_buffer;					// Pointer to buffer receiving raw file data
		u8 *compress_buffer;				// Pointer to compressed data buffer
		WriteBuffer write_buffer_object;	// AsyncIO read buffer object
		wirehair::Decoder decoder;			// FEC decoder object
		u32 compress_bytes;					// Number of bytes that the file part compressed to
		u32 decompress_bytes;				// Number of bytes that the file part decompresses to
	} **_decode_streams;					// Array of DecodeStream objects, initially all zero

	u32 _used_decode_streams;				// Number of decoding streams that are in use (always 0..u-1)

	bool SetupDecoder();
	void CleanupDecoder();

	bool PostPart(u32 stream_id, BatchSet &buffers, u32 &count);

	CAT_INLINE bool StartRead(int stream_id, u64 offset, u32 bytes)
	{
		// Initialize stream
		EncodeStream *stream = _encode_streams[stream_id];
		stream->ready_flag = TXFLAG_LOADING;
		stream->requested = 0;
		stream->next_id = stream_id;

		return _file->Read(&stream->read_buffer_object, offset, stream->read_buffer, bytes);
	}

	void OnFileRead(ThreadLocalStorage &tls, const BatchSet &set);
	void OnFileWrite(ThreadLocalStorage &tls, const BatchSet &set);

	bool PostPushRequest(const char *file_path);
	bool PostPullRequest(u32 sector_bytes, u8 stream_count, const char *file_path);
	bool PostPullGo(u32 lcm_sector_bytes, u64 file_bytes);
	bool PostDeny(u8 reason);
	bool PostStreamStart(u8 stream_id, u64 file_offset, u32 chunk_decompressed_size, u32 chunk_compressed_size, u16 block_bytes);
	bool PostStreamRequest(u8 stream_id, u16 request_count);
	bool PostStreamDone(u8 stream_id);
	bool PostRate(u32 rate_counter);
	bool PostClose(u8 reason);

	void OnPushRequest(const char *file_path);
	void OnPullRequest(u32 sector_bytes, u8 stream_count, const char *file_path);
	void OnPullGo(u32 lcm_sector_bytes, u64 file_bytes);
	void OnDeny(u8 reason);
	void OnStreamStart(u8 stream_id, u64 file_offset, u32 chunk_decompressed_size, u32 chunk_compressed_size, u16 block_bytes);
	void OnStreamRequest(u8 stream_id, u16 request_count);
	void OnStreamDone(u8 stream_id);
	void OnRate(u32 rate_counter);
	void OnClose(u8 reason);

	bool OpenFileRead(const char *file_path);
	bool OpenFileWrite(const char *file_path);
	CAT_INLINE void DestroyFileObject()
	{
		_file->Destroy(CAT_REFOBJECT_TRACE);
		_file = 0;
	}

protected:
	// Returns true if has more data to send
	bool HasData();

	// Called by Transport layer when more data can be sent
	s32 NextHuge(s32 available, BatchSet &buffers, u32 &count);

	// On IOP_HUGE message arrives
	void OnHuge(u8 *data, u32 bytes);

public:
	FECHugeEndpoint();
	virtual ~FECHugeEndpoint();

	// Initialize the endpoint
	void Initialize(Transport *transport, u8 opcode);

	CAT_INLINE void SetSendCallbacks(const OnSendRequest &on_send_request, const OnSendDone &on_send_done)
	{
		_on_send_request = on_send_request;
		_on_send_done = on_send_done;
	}

	CAT_INLINE void SetRecvCallbacks(const OnRecvRequest &on_recv_request, const OnRecvDone &on_recv_done)
	{
		_on_recv_request = on_recv_request;
		_on_recv_done = on_recv_done;
	}

	// Pass in everything including the message opcode
	void OnControlMessage(u8 *data, u32 bytes);

	// Request a file from the remote host
	// May fail if a transfer is already in progress
	bool Request(const char *file_path);

	// Start sending the specified file
	// May fail if a transfer is already in progress
	bool Send(const char *file_path);

	// Abort an existing file transfer
	CAT_INLINE void Abort(int reason = TXERR_USER_ABORT) { _abort_reason = reason; }
};


} // namespace sphynx


} // namespace cat

#endif // CAT_SPHYNX_FILE_TRANSFER_HPP
