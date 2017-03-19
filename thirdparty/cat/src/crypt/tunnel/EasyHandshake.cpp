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

#include <cat/crypt/tunnel/EasyHandshake.hpp>
#include <cat/crypt/tunnel/Keys.hpp>
#include <cat/time/Clock.hpp>
using namespace cat;


//// EasyHandshake

CAT_REF_SINGLETON(EasyHandshake);

bool EasyHandshake::OnInitialize()
{
	_tls = new (std::nothrow) TunnelTLS;
	return _tls && _tls->Valid();
}

void EasyHandshake::OnFinalize()
{
	if (_tls) delete _tls;
}

bool EasyHandshake::GenerateServerKey(TunnelKeyPair &key_pair)
{
	return key_pair.Generate(_tls);
}

void EasyHandshake::GenerateRandomNumber(void *out_num, int bytes)
{
	_tls->CSPRNG()->Generate(out_num, bytes);
}


//// ServerEasyHandshake

ServerEasyHandshake::ServerEasyHandshake()
{
	_tls = EasyHandshake::ref()->GetTLS();
}

void ServerEasyHandshake::FillCookieJar(CookieJar *jar)
{
	jar->Initialize(_tls->CSPRNG());
}

bool ServerEasyHandshake::Initialize(TunnelKeyPair &key_pair)
{
	if (!key_pair.Valid()) return false;

	// Initialize the tunnel server object using the provided key
	return _tun_server.Initialize(_tls, key_pair);
}

bool ServerEasyHandshake::ProcessChallenge(const void *in_challenge, void *out_answer, AuthenticatedEncryption *auth_enc)
{
	const u8 *challenge = reinterpret_cast<const u8*>( in_challenge );
	u8 *answer = reinterpret_cast<u8*>( out_answer );

	// Create a key hash object on the stack
	Skein key_hash;

	// Process and validate the client challenge.  This is an expensive operation
	// where most of the magic of the handshake occurs
	if (!_tun_server.ProcessChallenge(_tls,
									  challenge, CHALLENGE_BYTES,
									  answer, ANSWER_BYTES, &key_hash))
	{
		return false;
	}

	// Normally you would have the ability to key several authenticated encryption
	// objects from the same handshake, and give each one a different name.  For
	// simplicity I only allow one authenticated encryption object to be created per
	// handshake.  This would be useful for encrypting several different channels,
	// such as one handshake being used to key and encrypt a TCP stream and UDP
	// packets, or multiple TCP streams keyed from the same handshake, etc
	if (!_tun_server.KeyEncryption(&key_hash, auth_enc, "NtQuerySystemInformation"))
		return false;

	return true;
}

bool ServerEasyHandshake::VerifyInitiatorIdentity(const void *in_answer /* EasyHandshake::ANSWER_BYTES */,
												  const void *in_proof /* EasyHandshake::IDENTITY_BYTES */,
												  void *out_public_key /* EasyHandshake::PUBLIC_KEY_BYTES */)
{
	const u8 *answer = reinterpret_cast<const u8*>( in_answer );
	const u8 *ident = reinterpret_cast<const u8*>( in_proof );
	u8 *public_key = reinterpret_cast<u8*>( out_public_key );

	return _tun_server.VerifyInitiatorIdentity(_tls, answer, ANSWER_BYTES, ident, IDENTITY_BYTES, public_key, PUBLIC_KEY_BYTES);
}


//// ClientEasyHandshake

ClientEasyHandshake::ClientEasyHandshake()
{
	_tls = EasyHandshake::ref()->GetTLS();
}

bool ClientEasyHandshake::Initialize(TunnelPublicKey &public_key)
{
	// Initialize the tunnel client with the given public key
	return _tun_client.Initialize(_tls, public_key);
}

bool ClientEasyHandshake::SetIdentity(TunnelKeyPair &key_pair)
{
	// Initialize the tunnel client's identity
	return _tun_client.SetIdentity(_tls, key_pair);
}

bool ClientEasyHandshake::GenerateChallenge(void *out_challenge)
{
	u8 *challenge = reinterpret_cast<u8*>( out_challenge );

	// Generate a challenge
	return _tun_client.GenerateChallenge(_tls, challenge, CHALLENGE_BYTES);
}

bool ClientEasyHandshake::ProcessAnswer(const void *in_answer, AuthenticatedEncryption *auth_enc)
{
	const u8 *answer = reinterpret_cast<const u8*>( in_answer );

	// Create a key hash object on the stack
	Skein key_hash;

	// Process and validate the server's answer to our challenge.
	// This is an expensive operation
	if (!_tun_client.ProcessAnswer(_tls, answer, ANSWER_BYTES, &key_hash))
		return false;

	// Normally you would have the ability to key several authenticated encryption
	// objects from the same handshake, and give each one a different name.  For
	// simplicity I only allow one authenticated encryption object to be created per
	// handshake.  This would be useful for encrypting several different channels,
	// such as one handshake being used to key and encrypt a TCP stream and UDP
	// packets, or multiple TCP streams keyed from the same handshake, etc
	if (!_tun_client.KeyEncryption(&key_hash, auth_enc, "NtQuerySystemInformation"))
		return false;

	// Erase the ephemeral private key we used for the handshake now that it is done
	_tun_client.SecureErasePrivateKey();

	return true;
}

bool ClientEasyHandshake::ProcessAnswerWithIdentity(const void *in_answer, void *out_identity, AuthenticatedEncryption *auth_enc)
{
	const u8 *answer = reinterpret_cast<const u8*>( in_answer );
	u8 *ident = reinterpret_cast<u8*>( out_identity );

	// Create a key hash object on the stack
	Skein key_hash;

	// Process and validate the server's answer to our challenge.
	// This is an expensive operation
	if (!_tun_client.ProcessAnswerWithIdentity(_tls, answer, ANSWER_BYTES, &key_hash, ident, IDENTITY_BYTES))
		return false;

	// Normally you would have the ability to key several authenticated encryption
	// objects from the same handshake, and give each one a different name.  For
	// simplicity I only allow one authenticated encryption object to be created per
	// handshake.  This would be useful for encrypting several different channels,
	// such as one handshake being used to key and encrypt a TCP stream and UDP
	// packets, or multiple TCP streams keyed from the same handshake, etc
	if (!_tun_client.KeyEncryption(&key_hash, auth_enc, "NtQuerySystemInformation"))
		return false;

	// Erase the ephemeral private key we used for the handshake now that it is done
	_tun_client.SecureErasePrivateKey();

	return true;
}
