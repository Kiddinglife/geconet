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

#include <cat/sphynx/Wrapper.hpp>
using namespace cat;
using namespace sphynx;

EasySphynxClient::InternalSphynxClient::InternalSphynxClient()
{
	_parent = 0;
}

void EasySphynxClient::InternalSphynxClient::OnDestroy()
{
	Client::OnDestroy();

	_parent->OnDisconnect(GetSphynxErrorString((SphynxError)GetDisconnectReason()));
}

bool EasySphynxClient::InternalSphynxClient::OnFinalize()
{
	return Client::OnFinalize();
}

void EasySphynxClient::InternalSphynxClient::OnConnectFail(cat::sphynx::SphynxError err)
{
	_parent->OnConnectFailure(GetSphynxErrorString(err));
}

void EasySphynxClient::InternalSphynxClient::OnConnect()
{
	_parent->OnConnectSuccess();
}

void EasySphynxClient::InternalSphynxClient::OnMessages(cat::sphynx::IncomingMessage msgs[], cat::u32 count)
{
	_parent->OnMessageArrivals((int*)msgs, count);
}

void EasySphynxClient::InternalSphynxClient::OnDisconnectReason(cat::u8 reason)
{

}

void EasySphynxClient::InternalSphynxClient::OnCycle(cat::u32 now)
{

}


//// EasySphynxClient

EasySphynxClient::EasySphynxClient()
{
	RefObjects::Create(CAT_REFOBJECT_TRACE("EasySphynxClient ctor"), _client);
	if (_client)
	{
		_client->_parent = this;

		_client->AddRef(CAT_REFOBJECT_TRACE("EasySphynxClient ctor"));
	}
}

EasySphynxClient::~EasySphynxClient()
{
	if (_client)
		_client->ReleaseRef(CAT_REFOBJECT_TRACE("EasySphynxClient dtor"));
}

bool EasySphynxClient::Connect(const char *hostname, unsigned short port, const unsigned char *public_key, int public_key_bytes, const char *session_key)
{
	TunnelPublicKey tunnel_public_key(public_key, public_key_bytes);
	if (!tunnel_public_key.Valid()) return false;

	return _client->Connect(hostname, port, tunnel_public_key, session_key);
}
