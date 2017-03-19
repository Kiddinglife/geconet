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

#include <cat/crypt/tunnel/KeyAgreementResponder.hpp>
#include <cat/crypt/tunnel/AuthenticatedEncryption.hpp>
#include <cat/crypt/SecureEqual.hpp>
#include <cat/mem/AlignedAllocator.hpp>
#include <cat/time/Clock.hpp>
using namespace cat;


//// KeyAgreementResponder

bool KeyAgreementResponder::AllocateMemory()
{
    FreeMemory();

    server_private_key_kept_secret = AlignedAllocator::ref()->AcquireArray<Leg>(KeyLegs * 15);
    server_public_key_pre_shared_with_client = server_private_key_kept_secret + KeyLegs;
	B_neutral = server_public_key_pre_shared_with_client + KeyLegs*2;
	server_temp_private_key_kept_secret[0] = B_neutral + KeyLegs*2;
	server_temp_private_key_kept_secret[1] = server_temp_private_key_kept_secret[0] + KeyLegs;
	server_temp_public_key[0] = server_temp_private_key_kept_secret[1] + KeyLegs;
	server_temp_public_key[1] = server_temp_public_key[0] + KeyLegs*4;

    return !!server_private_key_kept_secret;
}

void KeyAgreementResponder::FreeMemory()
{
 	AlignedAllocator *allocator = AlignedAllocator::ref();

   if (server_private_key_kept_secret)
    {
        CAT_SECURE_CLR(server_private_key_kept_secret, KeyBytes);
        CAT_SECURE_CLR(server_temp_private_key_kept_secret[0], KeyBytes);
        CAT_SECURE_CLR(server_temp_private_key_kept_secret[1], KeyBytes);
        allocator->Delete(server_private_key_kept_secret);
        server_private_key_kept_secret = 0;
    }

	if (G_MultPrecomp)
	{
		allocator->Delete(G_MultPrecomp);
		G_MultPrecomp = 0;
	}
}

KeyAgreementResponder::KeyAgreementResponder()
{
    server_private_key_kept_secret = 0;
    G_MultPrecomp = 0;
}

KeyAgreementResponder::~KeyAgreementResponder()
{
	FreeMemory();
}

void KeyAgreementResponder::Rekey(TunnelTLS *tls)
{
	CAT_DEBUG_ENFORCE(tls && tls->Valid());

	BigTwistedEdwards *math = tls->Math();

	// NOTE: This function is very fragile because it has to be thread-safe
	u32 NextY = ActiveY ^ 1;

	// server_temp_private_key_kept_secret = ephemeral key
	GenerateKey(tls, server_temp_private_key_kept_secret[NextY]);

	// Y = server_temp_private_key_kept_secret * G
	Leg *Y = server_temp_public_key[NextY];
	math->PtMultiply(G_MultPrecomp, 8, server_temp_private_key_kept_secret[NextY], 0, Y);
	math->SaveAffineXY(Y, Y, Y + KeyLegs);

	ActiveY = NextY;

#if defined(CAT_NO_ATOMIC_RESPONDER)

	m_thread_id_mutex.Enter();
	ChallengeCount = 0;
	m_thread_id_mutex.Leave();

#else // CAT_NO_ATOMIC_RESPONDER

	Atomic::Set(&ChallengeCount, 0);

#endif // CAT_NO_ATOMIC_RESPONDER
}

bool KeyAgreementResponder::Initialize(TunnelTLS *tls, TunnelKeyPair &key_pair)
{
	CAT_DEBUG_ENFORCE(tls && tls->Valid());

	if (!key_pair.Valid()) return false;

#if defined(CAT_NO_ATOMIC_RESPONDER)
	if (!m_thread_id_mutex.Valid()) return false;
#endif // CAT_NO_ATOMIC_RESPONDER

	BigTwistedEdwards *math = tls->Math();

	int bits = math->RegBytes() * 8;

    // Validate and accept number of bits
    if (!KeyAgreementCommon::Initialize(bits))
        return false;

	// Verify that inputs are of the correct length
	if (key_pair.GetPrivateKeyBytes() != KeyBytes) return false;
	if (key_pair.GetPublicKeyBytes() != KeyBytes*2) return false;

    // Allocate memory space for the responder's key pair and generator point
    if (!AllocateMemory())
        return false;

	// Precompute an 8-bit table for multiplication
	G_MultPrecomp = math->PtMultiplyPrecompAlloc(8);
    if (!G_MultPrecomp) return false;
    math->PtMultiplyPrecomp(math->GetGenerator(), 8, G_MultPrecomp);

    // Unpack the responder's public point
	u8 *responder_public_key = key_pair.GetPublicKey();
    math->Load(key_pair.GetPrivateKey(), KeyBytes, server_private_key_kept_secret);
    if (!math->LoadVerifyAffineXY(responder_public_key, responder_public_key+KeyBytes, server_public_key_pre_shared_with_client))
        return false;
    math->PtUnpack(server_public_key_pre_shared_with_client);

	// Verify public point is not identity element
	if (math->IsAffineIdentity(server_public_key_pre_shared_with_client))
		return false;

	// Store a copy of the endian-neutral version of server_public_key_pre_shared_with_client for later
	memcpy(B_neutral, responder_public_key, KeyBytes*2);

	// Initialize re-keying
	ChallengeCount = 0;
	ActiveY = 0;
	Rekey(tls);

    return true;
}

bool KeyAgreementResponder::ProcessChallenge(TunnelTLS *tls,
											 const u8 *initiator_challenge, int challenge_bytes,
                                             u8 *responder_answer, int answer_bytes, Skein *key_hash)
{
	CAT_DEBUG_ENFORCE(tls && tls->Valid() && challenge_bytes == KeyBytes*2 && answer_bytes == KeyBytes*4);

	BigTwistedEdwards *math = tls->Math();
	FortunaOutput *csprng = tls->CSPRNG();

    Leg *A = math->Get(0);
    Leg *S = math->Get(8);
    Leg *T = math->Get(12);
    Leg *hA = math->Get(16);

    // Unpack the initiator's A into registers
    if (!math->LoadVerifyAffineXY(initiator_challenge, initiator_challenge + KeyBytes, A))
        return false;

	// Verify the point is not the additive identity (should never happen unless being attacked)
	if (math->IsAffineIdentity(A))
		return false;

    // hA = h * A for small subgroup attack resistance
    math->PtDoubleZ1(A, hA);
    math->PtEDouble(hA, hA);

#if defined(CAT_NO_ATOMIC_RESPONDER)

	bool time_to_rekey = false;

	m_thread_id_mutex.Enter();

	// Check if it is time to rekey
	if (ChallengeCount++ == 100)
		time_to_rekey = true;

	m_thread_id_mutex.Leave();

	if (time_to_rekey)
		Rekey(math, csprng);

#else // CAT_NO_ATOMIC_RESPONDER

	// Check if it is time to rekey
	if (Atomic::Add(&ChallengeCount, 1) == 100)
		Rekey(tls);

#endif // CAT_NO_ATOMIC_RESPONDER

	// Copy the current endian neutral Y to the responder answer
	u32 ThisY = ActiveY;
	memcpy(responder_answer, server_temp_public_key[ThisY], KeyBytes*2);

	do
	{
		// random n-bit number r
		csprng->Generate(responder_answer + KeyBytes*2, KeyBytes);

		// S = H(A,server_public_key_pre_shared_with_client,Y,r)
		if (!key_hash->BeginKey(KeyBits))
			return false;
		key_hash->Crunch(initiator_challenge, KeyBytes*2); // A
		key_hash->Crunch(B_neutral, KeyBytes*2); // server_public_key_pre_shared_with_client
		key_hash->Crunch(responder_answer, KeyBytes*3); // Y,r
		key_hash->End();
		key_hash->Generate(S, KeyBytes);
		math->Load(S, KeyBytes, S);

		// Repeat while S is small
	} while (math->LessX(S, 1000));

	// T = S*server_temp_private_key_kept_secret + server_private_key_kept_secret (mod q)
	math->MulMod(S, server_temp_private_key_kept_secret[ThisY], math->GetCurveQ(), T); // Should use Barrett reduction here
	if (math->Add(T, server_private_key_kept_secret, T))
		math->Subtract(T, math->GetCurveQ(), T);
	while (!math->Less(T, math->GetCurveQ()))
		math->Subtract(T, math->GetCurveQ(), T);

	// T = AffineX(T * hA)
	math->PtMultiply(hA, T, 0, S);
    math->SaveAffineX(S, T);

	// k = H(d,T)
	if (!key_hash->BeginKDF())
		return false;
	key_hash->Crunch(T, KeyBytes);
	key_hash->End();

	// Generate responder proof of key
	Skein mac;

	if (!mac.SetKey(key_hash) || !mac.BeginMAC()) return false;
	mac.CrunchString("shfolder.dll");
	mac.End();

	mac.Generate(responder_answer + KeyBytes*3, KeyBytes);

	return true;
}

bool KeyAgreementResponder::VerifyInitiatorIdentity(TunnelTLS *tls,
													const u8 *responder_answer, int answer_bytes,
													const u8 *proof, int proof_bytes,
													u8 *public_key, int public_bytes)
{
	CAT_DEBUG_ENFORCE(tls && tls->Valid() && proof_bytes == KeyBytes*5 && answer_bytes == KeyBytes*4 && public_bytes == KeyBytes*2);

	BigTwistedEdwards *math = tls->Math();

	/*
		Format of identity buffer:

		256-bit security: [Initiator Public Key] (64) || [Initiator Random Number] (32) || [Signature] (64)
	*/

	// Copied from Verify() in KeyAgreementInitiator.cpp

	Leg *e = math->Get(0);
	Leg *s = math->Get(1);
	Leg *Kp = math->Get(2);
	Leg *ep = math->Get(6);
	Leg *I_public = math->Get(7);

	// Load e, s from proof
	math->Load(proof + KeyBytes * 3, KeyBytes, e);
	math->Load(proof + KeyBytes * 4, KeyBytes, s);

	// e = e (mod q), for checking if it is congruent to q
	while (!math->Less(e, math->GetCurveQ()))
		math->Subtract(e, math->GetCurveQ(), e);

	// Check e, s are in the range [1,q-1]
	if (math->IsZero(e) || math->IsZero(s) ||
		!math->Less(e, math->GetCurveQ()) ||
		!math->Less(s, math->GetCurveQ()))
	{
		return false;
	}

	// Unpack the initiator's public key
	if (!math->LoadVerifyAffineXY(proof, proof + KeyBytes, I_public))
		return false;

	// Verify public point is not identity element
	if (math->IsAffineIdentity(I_public))
		return false;

	// Precompute a table for multiplication
	Leg *I_MultPrecomp = math->PtMultiplyPrecompAlloc(8);
	if (!I_MultPrecomp) return false;
	math->PtUnpack(I_public);
	math->PtMultiplyPrecomp(I_public, 8, I_MultPrecomp);

	// K' = s*G + e*I_public
	math->PtSiMultiply(G_MultPrecomp, I_MultPrecomp, 8, s, 0, e, 0, Kp);
	math->SaveAffineX(Kp, Kp);

	AlignedAllocator::ref()->Delete(I_MultPrecomp);

	// e' = H(IRN || RRN || K')
	Skein H;
	if (!H.BeginKey(KeyBits)) return false;
	H.Crunch(proof + KeyBytes * 2, KeyBytes); // client random number
	H.Crunch(responder_answer + KeyBytes * 2, KeyBytes); // server random number
	H.Crunch(Kp, KeyBytes);
	H.End();
	H.Generate(ep, KeyBytes);

	// Verify that e' == e
	bool success = SecureEqual(proof + KeyBytes * 3, ep, KeyBytes);

	// On successful identity verification, copy the public key to the destination
	if (success) memcpy(public_key, proof, KeyBytes*2);

	return success;
}


bool KeyAgreementResponder::Sign(TunnelTLS *tls,
								 const u8 *message, int message_bytes,
								 u8 *signature, int signature_bytes)
{
	CAT_DEBUG_ENFORCE(tls && tls->Valid() && signature_bytes == KeyBytes*2 && message_bytes >= 0);

	BigTwistedEdwards *math = tls->Math();

    Leg *k = math->Get(0);
    Leg *K = math->Get(1);
    Leg *e = math->Get(5);
    Leg *s = math->Get(6);

	do {

		do {

			// k = ephemeral key
			GenerateKey(tls, k);

			// K = k * G
			math->PtMultiply(G_MultPrecomp, 8, k, 0, K);
			math->SaveAffineX(K, K);

			// e = H(M || K)
			Skein H;

			if (!H.BeginKey(KeyBits)) return false;
			H.Crunch(message, message_bytes);
			H.Crunch(K, KeyBytes);
			H.End();
			H.Generate(signature, KeyBytes);

			math->Load(signature, KeyBytes, e);

			// e = e (mod q), for checking if it is congruent to q
			while (!math->Less(e, math->GetCurveQ()))
				math->Subtract(e, math->GetCurveQ(), e);

		} while (math->IsZero(e));

		// s = server_private_key_kept_secret * e (mod q)
		math->MulMod(server_private_key_kept_secret, e, math->GetCurveQ(), s);

		// s = -s (mod q)
		if (!math->IsZero(s)) math->Subtract(math->GetCurveQ(), s, s);

		// s = s + k (mod q)
		if (math->Add(s, k, s))
			while (!math->Subtract(s, math->GetCurveQ(), s));
		while (!math->Less(s, math->GetCurveQ()))
			math->Subtract(s, math->GetCurveQ(), s);

	} while (math->IsZero(s));

	math->Save(s, signature + KeyBytes, KeyBytes);

	// Erase the ephemeral secret from memory
	math->CopyX(0, k);

	return true;
}
