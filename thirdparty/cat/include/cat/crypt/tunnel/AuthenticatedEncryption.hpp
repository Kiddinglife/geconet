/*
	Copyright (c) 2009-2010 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_AUTHENTICATED_ENCRYPTION_HPP
#define CAT_AUTHENTICATED_ENCRYPTION_HPP

#include <cat/crypt/symmetric/ChaCha.hpp>
#include <cat/crypt/hash/Skein.hpp>
#include <cat/crypt/hash/VHash.hpp>
#include <cat/threads/Mutex.hpp>

namespace cat {


/*
    Tunnel Authenticated Encryption "Calico" protocol:

    Run after the Key Agreement protocol completes.
    Uses a 1024-bit anti-replay sliding window, suitable for Internet file transfer over UDP.

	Cipher: ChaCha with 256-bit or 384-bit keys
	KDF: Key derivation function (Skein)
	MAC: Message authentication code (64-bit VMAC-ChaCha)
	IV: Initialization vector incrementing by 1 each time

    c2sMKey = KDF(k) { "upstream-MAC" }
    s2cMKey = KDF(k) { "downstream-MAC" }
    c2sEKey = KDF(k) { "upstream-ENC" }
    s2cEKey = KDF(k) { "downstream-ENC" }
	c2sIV = KDF(k) { "upstream-IV" }
	s2cIV = KDF(k) { "downstream-IV" }

	To transmit a message, the client writes the message IV to the last 3 bytes of the output.
	The first block of encryption keystream is stored temporarily.
	Then the client uses c2sEKey to encrypt the message.
	The MAC is produced and XOR'd with the first 8 bytes of keystream and stored to the end.

    c2s Encrypt(c2sEKey) { message || MAC(c2sMKey) [ENC{message}] } || Obfuscated { trunc-iv-us }

        encrypted { MESSAGE(X) MAC(8by) } IV(3by) = 11 bytes overhead at end of packet

	To transmit a message, the server writes the message IV to the first 3 bytes of the output.
	The first block of encryption keystream is stored temporarily.
	Then the server uses s2cEKey to encrypt 8 bytes of zeroes and the message.
	The MAC is produced and XOR'd with the first 8 bytes of keystream and stored to the end.

    s2c Encrypt(s2cEKey) { message || MAC(s2cMKey) [ENC{message}] } || Obfuscated { trunc-iv-ds }

        encrypted { MESSAGE(X) MAC(8by) } IV(3by) = 11 bytes overhead at end of packet

	The full 64-bit IVs are initialized to c2sIV and s2cIV, and the first one sent is IV+1.
*/


class KeyAgreementResponder;
class KeyAgreementInitiator;


// NOTE: Only the encryption is thread safe
class CAT_EXPORT AuthenticatedEncryption
{
    friend class KeyAgreementResponder;
    friend class KeyAgreementInitiator;

    bool _is_initiator, _accept_out_of_order;
    Skein key_hash;

    VHash _local_mac, _remote_mac;
    ChaChaKey local_cipher_key, remote_cipher_key;
    u64 remote_iv;

	Mutex _local_iv_lock;
	u64 local_iv;

    // Anti-replay sliding window
    static const int BITMAP_BITS = 1024;
    static const int BITMAP_WORDS = BITMAP_BITS / 64;
    u64 iv_bitmap[BITMAP_WORDS];

public:
	CAT_INLINE AuthenticatedEncryption() {}
	CAT_INLINE ~AuthenticatedEncryption() {}

    // Tunnel overhead bytes
    static const int MAC_BYTES = 8;
    static const int IV_BYTES = 3;
    static const u32 OVERHEAD_BYTES = IV_BYTES + MAC_BYTES;

    // IV constants
    static const int IV_BITS = IV_BYTES * 8;
    static const u32 IV_MSB = (1 << IV_BITS);
    static const u32 IV_MASK = (IV_MSB - 1);
    static const u32 IV_FUZZ = 0x9F286AD7;

protected:
    bool SetKey(int KeyBytes, Skein *key, bool is_initiator, const char *key_name);

    bool IsValidIV(u64 iv);
    void AcceptIV(u64 iv);

public:
	// Use a key derivation function to generate a new key from the existing key
	bool GenerateKey(const char *key_name, void *key, int bytes);

public:
    // Generate a proof that the local host has the key
    bool GenerateProof(u8 *local_proof, int proof_bytes);

    // Validate a proof that the remote host has the key
    bool ValidateProof(const u8 *remote_proof, int proof_bytes);

public:
	// NOTE: Doesn't break the security guarantee, will still ignore duplicates!
	void AllowOutOfOrder(bool allowed = true) { _accept_out_of_order = allowed; }

public:
	// buf_bytes: Number of bytes in the buffer,
	//            including OVERHEAD_BYTES at the end of the packet
	// First byte after message will be a 1 or 0 (for compression bit)
    bool Decrypt(u8 *buffer, u32 buf_bytes);

	// Grab a range of IVs so that locking only needs to be done once
	u64 GrabIVRange(u32 count);

	// To encrypt messages, first grab an IV range.
	// Then call Encrypt(), incrementing the IV each time.
	// buf_bytes: Number of bytes in the buffer,
	//            including OVERHEAD_BYTES at the end of the packet
	// Preserves the first byte after the message if it is a 1 or 0 (for compression bit)
    bool Encrypt(u64 &iv, u8 *buffer, u32 buf_bytes);
};


} // namespace cat

#endif // CAT_AUTHENTICATED_ENCRYPTION_HPP
