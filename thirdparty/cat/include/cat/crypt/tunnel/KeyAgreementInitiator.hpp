/*
	Copyright (c) 2009-2011 Christopher client_public_key_shared_with_server_in_challenge_msg. Taylor.  All rights reserved.

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
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR client_public_key_shared_with_server_in_challenge_msg PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef CAT_KEY_AGREEMENT_INITIATOR_HPP
#define CAT_KEY_AGREEMENT_INITIATOR_HPP

#include <cat/crypt/tunnel/KeyAgreement.hpp>
#include <cat/crypt/tunnel/AuthenticatedEncryption.hpp>
#include <cat/crypt/tunnel/Keys.hpp>
#include <cat/crypt/tunnel/TunnelTLS.hpp>

namespace cat {


class CAT_EXPORT KeyAgreementInitiator : public KeyAgreementCommon
{
	Leg *server_public_key_pre_shared; // Responder's public key (pre-shared with initiator)
	Leg *client_private_key_kept_secret; // Initiator's private key (kept secret)
	Leg *client_public_key_shared_with_server_in_challenge_msg; // Initiator's public key (shared with responder in Challenge message)
	Leg *hB; // h*server_public_key_pre_shared
	Leg *G_MultPrecomp; // Precomputed table for multiplication
	Leg *B_MultPrecomp; // Precomputed table for multiplication
	Leg *Y_MultPrecomp; // Precomputed table for multiplication
	Leg *A_neutral; // Endian-neutral client_public_key_shared_with_server_in_challenge_msg
	Leg *B_neutral; // Endian-neutral server_public_key_pre_shared

	// Identity data
	Leg *client_identity_private_key; // Initiator's identity private key
	Leg *client_identity_public_key; // Endian-neutral initiator's identity public key

	bool AllocateMemory();
	void FreeMemory();

public:
	KeyAgreementInitiator();
	~KeyAgreementInitiator();

	bool Initialize(TunnelTLS *tls, TunnelPublicKey &public_key);

	// Call after Initialize()
	bool SetIdentity(TunnelTLS *tls, TunnelKeyPair &key_pair);

public:
	bool GenerateChallenge(TunnelTLS *tls,
						   u8 *initiator_challenge, int challenge_bytes);

	bool ProcessAnswer(TunnelTLS *tls,
					   const u8 *responder_answer, int answer_bytes,
					   Skein *key_hash);

	// Will fail if SetIdentity() has not been called
	bool ProcessAnswerWithIdentity(TunnelTLS *tls,
								   const u8 *responder_answer, int answer_bytes,
								   Skein *key_hash,
								   u8 *identity_proof, int proof_bytes);

	CAT_INLINE bool KeyEncryption(Skein *key_hash, AuthenticatedEncryption *auth_enc, const char *key_name)
	{
		return auth_enc->SetKey(KeyBytes, key_hash, true, key_name);
	}

	// Erase the private key after handshake completes
	// Also done as this object is destroyed
	void SecureErasePrivateKey();

public:
	bool Verify(TunnelTLS *tls,
				const u8 *message, int message_bytes,
				const u8 *signature, int signature_bytes);
};


} // namespace cat

#endif // CAT_KEY_AGREEMENT_INITIATOR_HPP
