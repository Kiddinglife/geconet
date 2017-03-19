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

#include <cat/crypt/tunnel/AuthenticatedEncryption.hpp>
#include <cat/port/EndianNeutral.hpp>
#include <cat/crypt/SecureEqual.hpp>
#include <cat/crypt/tunnel/KeyAgreement.hpp>
#include <cat/math/BitMath.hpp>
using namespace cat;

// Obfuscated key names, collected here for ease of modification and less chance of typos
#define CAT_KEYNAME_MAC(WHOAMI) ((WHOAMI) ? "dsound.dll" : "opengl32.dll")
#define CAT_KEYNAME_CIPHER(WHOAMI) ((WHOAMI) ? "Advapi32.dll" : "OpenProcessToken")
#define CAT_KEYNAME_IV(WHOAMI) ((WHOAMI) ? "RichEd20.Dll" : "KERNEL32.DLL")
#define CAT_KEYNAME_PROOF(WHOAMI) ((WHOAMI) ? "ddraw.dll" : "shfolder.dll")

bool AuthenticatedEncryption::SetKey(int KeyBytes, Skein *key, bool is_initiator, const char *key_name)
{
	_accept_out_of_order = true;
    _is_initiator = is_initiator;
	CAT_OBJCLR(iv_bitmap);

	// Add key name:

	if (!key_hash.SetKey(key)) return false;
	if (!key_hash.BeginKDF()) return false;
	key_hash.CrunchString(key_name);
    key_hash.End();

	// MAC keys:

	u8 mac_key[160];

	if (!GenerateKey(CAT_KEYNAME_MAC(is_initiator), mac_key, sizeof(mac_key)))
		return false;
	_local_mac.SetKey(mac_key);

	if (!GenerateKey(CAT_KEYNAME_MAC(!is_initiator), mac_key, sizeof(mac_key)))
		return false;
	_remote_mac.SetKey(mac_key);

	// Encryption keys:

	u8 cipher_key[KeyAgreementCommon::MAX_BYTES];

	if (!GenerateKey(CAT_KEYNAME_CIPHER(is_initiator), cipher_key, KeyBytes))
		return false;
    local_cipher_key.Set(cipher_key, KeyBytes);

#ifdef CAT_AUDIT
	printf("AUDIT: local_cipher_key ");
	for (int ii = 0; ii < KeyBytes; ++ii)
	{
		printf("%02x", (cat::u8)cipher_key[ii]);
	}
	printf("\n");
#endif

	if (!GenerateKey(CAT_KEYNAME_CIPHER(!is_initiator), cipher_key, KeyBytes))
		return false;
	remote_cipher_key.Set(cipher_key, KeyBytes);

#ifdef CAT_AUDIT
	printf("AUDIT: remote_cipher_key ");
	for (int ii = 0; ii < KeyBytes; ++ii)
	{
		printf("%02x", (cat::u8)cipher_key[ii]);
	}
	printf("\n");
#endif

	// Random IVs:

	if (!GenerateKey(CAT_KEYNAME_IV(is_initiator), &local_iv, sizeof(local_iv)))
		return false;
	local_iv = getLE(local_iv);

#ifdef CAT_AUDIT
	printf("AUDIT: local_iv ");
	for (int ii = 0; ii < sizeof(local_iv); ++ii)
	{
		printf("%02x", ((cat::u8*)(&local_iv))[ii]);
	}
	printf("\n");
#endif

	if (!GenerateKey(CAT_KEYNAME_IV(!is_initiator), &remote_iv, sizeof(remote_iv)))
		return false;
	remote_iv = getLE(remote_iv);

#ifdef CAT_AUDIT
	printf("AUDIT: remote_iv ");
	for (int ii = 0; ii < sizeof(remote_iv); ++ii)
	{
		printf("%02x", ((cat::u8*)(&remote_iv))[ii]);
	}
	printf("\n");
#endif

	return true;
}

bool AuthenticatedEncryption::GenerateKey(const char *key_name, void *key, int bytes)
{
	Skein kdf;

	if (!kdf.SetKey(&key_hash)) return false;
	if (!kdf.BeginKDF()) return false;
	kdf.CrunchString(key_name);
	kdf.End();
	kdf.Generate(key, bytes);

	return true;
}

bool AuthenticatedEncryption::GenerateProof(u8 *local_proof, int proof_bytes)
{
    Skein mac;

    if (!mac.SetKey(&key_hash) || !mac.BeginMAC()) return false;
    mac.CrunchString(CAT_KEYNAME_PROOF(_is_initiator));
    mac.End();

    mac.Generate(local_proof, proof_bytes);

    return true;
}

bool AuthenticatedEncryption::ValidateProof(const u8 *remote_proof, int proof_bytes)
{
    if (proof_bytes > KeyAgreementCommon::MAX_BYTES) return false;

    Skein mac;

    if (!mac.SetKey(&key_hash) || !mac.BeginMAC()) return false;
    mac.CrunchString(CAT_KEYNAME_PROOF(!_is_initiator));
    mac.End();

    u8 expected[KeyAgreementCommon::MAX_BYTES];
    mac.Generate(expected, proof_bytes);

    return SecureEqual(expected, remote_proof, proof_bytes);
}

bool AuthenticatedEncryption::IsValidIV(u64 iv)
{
    // Check how far in the past this IV is
    int delta = (int)(remote_iv - iv);

    // If it is in the past,
    if (delta >= 0)
    {
		// Check if we do not accept out of order messages
		if (!_accept_out_of_order) return false;

        // Check if we have kept a record for this IV
        if (delta >= BITMAP_BITS) return false;

        u64 *map = &iv_bitmap[delta >> 6];
        u64 mask = (u64)1 << (delta & 63);

        // If it was seen, abort
        if (*map & mask) return false;
    }

    return true;
}

void AuthenticatedEncryption::AcceptIV(u64 iv)
{
    // Check how far in the past/future this IV is
    int delta = (int)(iv - remote_iv);

    // If it is in the future,
    if (delta > 0)
    {
        // If it would shift out everything we have seen,
        if (delta >= BITMAP_BITS)
        {
            // Set low bit to 1 and all other bits to 0
            iv_bitmap[0] = 1;
            CAT_CLR(&iv_bitmap[1], sizeof(iv_bitmap) - sizeof(u64));
        }
        else
        {
            int word_shift = delta >> 6;
            int bit_shift = delta & 63;

            // Shift replay window
            u64 last = iv_bitmap[BITMAP_WORDS - 1 - word_shift];
            for (int ii = BITMAP_WORDS - 1; ii >= word_shift + 1; --ii)
            {
                u64 x = iv_bitmap[ii - word_shift - 1];
                iv_bitmap[ii] = (last << bit_shift) | (x >> (64-bit_shift));
                last = x;
            }
            iv_bitmap[word_shift] = last << bit_shift;

            // Zero the words we skipped
            for (int ii = 0; ii < word_shift; ++ii)
                iv_bitmap[ii] = 0;

            // Set low bit for this IV
            iv_bitmap[0] |= 1;
        }

        // Only update the IV if the MAC was valid and the new IV is in the future
        remote_iv = iv;
    }
    else // Process an out-of-order packet
    {
        delta = -delta;

        // Set the bit in the bitmap for this IV
        iv_bitmap[delta >> 6] |= (u64)1 << (delta & 63);
    }
}

bool AuthenticatedEncryption::Decrypt(u8 *buffer, u32 buf_bytes)
{
    if (buf_bytes < OVERHEAD_BYTES) return false;

	u32 msg_bytes = buf_bytes - OVERHEAD_BYTES;

    u8 *overhead = buffer + msg_bytes;
    // overhead: encrypted { ... MAC(8 bytes) } || truncated IV(3 bytes)

    // De-obfuscate the truncated IV
    u32 trunc_iv = ((u32)overhead[MAC_BYTES+2] << 16) | ((u32)overhead[MAC_BYTES+1] << 8) | (u32)overhead[MAC_BYTES];
	trunc_iv = IV_MASK & (trunc_iv ^ getLE(*(u32*)overhead) ^ IV_FUZZ);

#ifdef CAT_AUDIT
	printf("AUDIT: Decrypting message with De-Obfuscated IV ");
	for (int ii = 0; ii < 4; ++ii)
	{
		printf("%02x", ((cat::u8*)(&trunc_iv))[ii]);
	}
	printf("\n");
#endif

    // Reconstruct the original, full IV
    u64 iv = ReconstructCounter<IV_BITS>(remote_iv, trunc_iv);

#ifdef CAT_AUDIT
	printf("AUDIT: Decrypting message with Reconstructed IV ");
	for (int ii = 0; ii < 8; ++ii)
	{
		printf("%02x", ((cat::u8*)(&iv))[ii]);
	}
	printf("\n");
#endif

    if (!IsValidIV(iv))
	{
#ifdef CAT_AUDIT
		printf("AUDIT: Not valid IV!\n");
#endif
		return false;
	}

#ifdef CAT_AUDIT
	printf("AUDIT: Valid IV!\n");
#endif

	// Key the cipher with the IV
	ChaChaOutput remote_cipher;
	remote_cipher.ReKey(remote_cipher_key, iv);

	// Generate first block and discard all but first 8 bytes
	u32 first_block[16];
	remote_cipher.GenerateNeutralKeyStream(first_block);

	// Generate the MAC by encrypting (XORing) VHash with the first 8 bytes of keystream
	const u64 *vhash_keystream = reinterpret_cast<const u64*>( first_block );
	const u64 *mac_input = reinterpret_cast<u64*>( overhead );
	u64 remote_vhash = getLE(*mac_input ^ *vhash_keystream);
	u32 lsb = remote_vhash & 1;

	// Generate VHash of the ciphertext
	overhead[0] = (u8)lsb;
	u64 vhash = _remote_mac.Hash(buffer, msg_bytes + 1) << 1;

	// Validate the MAC
	if ((remote_vhash ^ vhash) >> 1)
	{
#ifdef CAT_AUDIT
		printf("AUDIT: MAC invalid!\n");
#endif
		return false;
	}

	// Decrypt the message in-place
    remote_cipher.Crypt(buffer, buffer, msg_bytes);

#ifdef CAT_AUDIT
	printf("AUDIT: MAC valid!  Message successfully decrypted!\n");
#endif

    AcceptIV(iv);

    return true;
}

u64 AuthenticatedEncryption::GrabIVRange(u32 count)
{
	u64 iv;

	_local_iv_lock.Enter();

	iv = local_iv;
	local_iv = iv + count;

	_local_iv_lock.Leave();

	return iv;
}

bool AuthenticatedEncryption::Encrypt(u64 &next_iv, u8 *buffer, u32 buf_bytes)
{
	u32 msg_bytes = buf_bytes - OVERHEAD_BYTES;
    u8 *overhead = buffer + buf_bytes - OVERHEAD_BYTES;
	u32 lsb = overhead[0] & 1;

	// Outgoing IV increments by one each time, and starts one ahead of remotely generated IV
	u64 iv = next_iv;
	next_iv = iv + 1;

#ifdef CAT_AUDIT
	printf("AUDIT: Encrypting message with IV ");
	for (int ii = 0; ii < 8; ++ii)
	{
		printf("%02x", ((cat::u8*)(&iv))[ii]);
	}
	printf("\n");
#endif

	// Key the cipher with the IV
	ChaChaOutput local_cipher;
	local_cipher.ReKey(local_cipher_key, iv);

	// Generate first block and discard all but first 8 bytes
	u32 first_block[16];
	local_cipher.GenerateNeutralKeyStream(first_block);

    // Encrypt the message and MAC
    local_cipher.Crypt(buffer, buffer, msg_bytes);

	// Generate VHash of the ciphertext
	u64 vhash = (_local_mac.Hash(buffer, msg_bytes + 1) << 1) | lsb;

	// Generate the MAC by encrypting (XORing) VHash with the first 8 bytes of keystream
	const u64 *vhash_keystream = reinterpret_cast<const u64*>( first_block );
	u64 *mac_output = reinterpret_cast<u64*>( overhead );
	*mac_output = *vhash_keystream ^ getLE(vhash);

#ifdef CAT_AUDIT
	printf("AUDIT: Encrypted message with MAC ");
	for (int ii = 0; ii < MAC_BYTES; ++ii)
	{
		printf("%02x", (cat::u8)overhead[ii]);
	}
	printf("\n");
#endif

    // Obfuscate the truncated IV
    u32 trunc_iv = IV_MASK & ((u32)iv ^ getLE(*(u32*)overhead) ^ IV_FUZZ);

    overhead[MAC_BYTES] = (u8)trunc_iv;
    overhead[MAC_BYTES+1] = (u8)(trunc_iv >> 8);
    overhead[MAC_BYTES+2] = (u8)(trunc_iv >> 16);

#ifdef CAT_AUDIT
	printf("AUDIT: Encrypting message with Obfuscated IV ");
	for (int ii = 0; ii < 4; ++ii)
	{
		printf("%02x", ((cat::u8*)(&trunc_iv))[ii]);
	}
	printf("\n");
#endif

	return true;
}
