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

#ifndef CAT_SPHYNX_WRAPPER_HPP
#define CAT_SPHYNX_WRAPPER_HPP

#include <cat/AllSphynx.hpp>

class EasySphynxClient
{
	class InternalSphynxClient : public cat::sphynx::Client
	{
		friend class EasySphynxClient;

		EasySphynxClient *_parent;

		void OnDestroy();
		bool OnFinalize();
		void OnConnectFail(cat::sphynx::SphynxError err);
		void OnConnect();
		void OnMessages(cat::sphynx::IncomingMessage msgs[], cat::u32 count);
		void OnDisconnectReason(cat::u8 reason);
		void OnCycle(cat::u32 now);

	public:
		InternalSphynxClient();
	};

	InternalSphynxClient *_client;

public:
	EasySphynxClient();
	virtual ~EasySphynxClient();

	// Connect to server, specifying hostname, port, public key, and session key
	bool Connect(const char *hostname, unsigned short port, const unsigned char *public_key, int public_key_bytes, const char *session_key);

	// Copy data directly to the send buffer, no need to acquire an OutgoingMessage
	inline bool WriteOOB(unsigned char msg_opcode, const unsigned char *msg_data, unsigned int msg_bytes)
	{
		return _client->WriteOOB(msg_opcode, msg_data, msg_bytes);
	}

	inline bool WriteUnreliable(unsigned char msg_opcode, const unsigned char *msg_data, unsigned int msg_bytes)
	{
		return _client->WriteUnreliable(msg_opcode, msg_data, msg_bytes);
	}
	inline bool WriteReliable(unsigned int stream, unsigned char msg_opcode, const unsigned char *msg_data, unsigned int msg_bytes)
	{
		return _client->WriteReliable((cat::sphynx::StreamMode)stream, msg_opcode, msg_data, msg_bytes);
	}

	// TODO: Queue up a huge data transfer
	//inline bool WriteHuge(StreamMode stream, IHugeSource *source);

	// Flush send buffer after processing the current message from the remote host
	inline void FlushAfter()
	{
		_client->FlushAfter();
	}

	// Flush send buffer immediately, don't try to blob.
	// Try to use FlushAfter() unless you really see benefit from this!
	inline void FlushWrites()
	{
		_client->FlushWrites();
	}

	// Current local time
	inline unsigned int getLocalTime()
	{
		return _client->getLocalTime();
	}

	// Convert from local time to server time
	inline unsigned int toServerTime(unsigned int local_time)
	{
		return _client->toServerTime(local_time);
	}

	// Convert from server time to local time
	inline unsigned int fromServerTime(unsigned int server_time)
	{
		return _client->fromServerTime(server_time);
	}

	// Current server time
	inline unsigned int getServerTime()
	{
		return _client->getServerTime();
	}

	// Compress timestamp on client for delivery to server; byte order must be fixed before writing to message
	inline unsigned short encodeClientTimestamp(unsigned int local_time)
	{
		return _client->encodeClientTimestamp(local_time);
	}

	// Decompress a timestamp on client from server; byte order must be fixed before decoding
	inline unsigned int decodeServerTimestamp(unsigned int local_time, unsigned short timestamp)
	{
		return _client->decodeServerTimestamp(local_time, timestamp);
	}

	// Override these methods:
	virtual void OnDisconnect(const char *reason) {}
	virtual void OnConnectFailure(const char *reason) {}
	virtual void OnConnectSuccess() {}
	virtual void OnMessageArrivals(void *msgs, int count) {}
};

#endif // CAT_SPHYNX_WRAPPER_HPP
