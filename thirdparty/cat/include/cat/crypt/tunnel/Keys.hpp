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

#ifndef CAT_TUNNEL_KEYS_HPP
#define CAT_TUNNEL_KEYS_HPP

#include <cat/crypt/tunnel/KeyAgreement.hpp>
#include <cat/crypt/rand/Fortuna.hpp>
#include <cat/crypt/tunnel/TunnelTLS.hpp>
#include <string>

namespace cat {


class CAT_EXPORT TunnelKeyPair : KeyAgreementCommon
{
	u8 _key_pair[KeyAgreementCommon::MAX_BYTES * 3];
	u32 _key_bytes;
	bool _valid;

public:
	CAT_INLINE u8 *GetPublicKey() { return _key_pair; }
	CAT_INLINE u8 *GetPrivateKey() { return _key_pair + _key_bytes * 2; }
	CAT_INLINE u32 GetPublicKeyBytes() { return _key_bytes * 2; }
	CAT_INLINE u32 GetPrivateKeyBytes() { return _key_bytes; }
	CAT_INLINE bool Valid() { return _valid; }

	TunnelKeyPair();
	~TunnelKeyPair();

	TunnelKeyPair(const void *key, u32 bytes);

	bool LoadMemory(const void *key, u32 bytes);

	bool LoadBase64(const char *base64_encoded);
	std::string SaveBase64();

	bool LoadFile(const char *file_path);
	bool SaveFile(const char *file_path);

	bool Generate(TunnelTLS *tls);
};


class CAT_EXPORT TunnelPublicKey
{
	u8 _public_key[KeyAgreementCommon::MAX_BYTES * 2];
	u32 _key_bytes;
	bool _valid;

public:
	CAT_INLINE u8 *GetPublicKey() { return _public_key; }
	CAT_INLINE u32 GetPublicKeyBytes() { return _key_bytes * 2; }
	CAT_INLINE bool Valid() { return _valid; }

	TunnelPublicKey();
	~TunnelPublicKey();

	TunnelPublicKey(TunnelKeyPair &pair); // Copy from key pair
	TunnelPublicKey &operator=(TunnelKeyPair &pair); // Copy from key pair

	TunnelPublicKey(const void *key, u32 bytes);

	bool LoadMemory(const void *key, u32 bytes);

	bool LoadBase64(const char *base64_encoded);
	std::string SaveBase64();

	bool LoadFile(const char *file_path);
	bool SaveFile(const char *file_path);
};


} // namespace cat

#endif // CAT_TUNNEL_KEYS_HPP
