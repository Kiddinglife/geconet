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

#include <cat/crypt/tunnel/Keys.hpp>
#include <cat/parse/Base64.hpp>
#include <cat/io/MappedFile.hpp>
#include <fstream>
using namespace cat;
using namespace std;


//// TunnelKeyPair

TunnelKeyPair::TunnelKeyPair()
{
	_key_bytes = 0;
	_valid = false;
}

TunnelKeyPair::~TunnelKeyPair()
{
	CAT_SECURE_OBJCLR(_key_pair);
}

TunnelKeyPair::TunnelKeyPair(const void *key, u32 bytes)
{
	_valid = LoadMemory(key, bytes);
}

bool TunnelKeyPair::LoadMemory(const void *key, u32 bytes)
{
	if (bytes != (256 / 8) * 3 &&
		bytes != (384 / 8) * 3 &&
		bytes != (512 / 8) * 3)
	{
		return false;
	}

	_key_bytes = bytes / 3;

	memcpy(_key_pair, key, bytes);

	_valid = true;
	return true;
}

bool TunnelKeyPair::LoadBase64(const char *base64_encoded)
{
	_valid = false;

	int encoded_bytes = (int)strlen(base64_encoded);

	// Decode the public key || private key pair
	int copied = ReadBase64(base64_encoded, encoded_bytes, _key_pair, sizeof(_key_pair));

	if (copied != (256 / 8) * 3 &&
		copied != (384 / 8) * 3 &&
		copied != (512 / 8) * 3)
	{
		return false;
	}

	_key_bytes = copied / 3;

	_valid = true;
	return true;
}

std::string TunnelKeyPair::SaveBase64()
{
	if (!Valid()) return "<invalid key pair>";

	u32 pair_bytes = _key_bytes * 3;
	int encoded_bytes = GetBase64LengthFromBinaryLength(pair_bytes);
	char *base64_encoded = new (std::nothrow) char[encoded_bytes + 1];
	if (!base64_encoded) return "<out of memory>";

	int bytes = WriteBase64Str(_key_pair, pair_bytes, base64_encoded, encoded_bytes);

	std::string str;

	if (bytes <= 0) str = "<corrupt key pair>";
	else str = base64_encoded;

	delete []base64_encoded;

	return str;
}

bool TunnelKeyPair::LoadFile(const char *file_path)
{
	_valid = false;

	SequentialFileReader file;
	if (!file.Open(file_path)) return false;

	u32 bytes = (u32)file.GetLength();

	if (bytes != (256 / 8) * 3 &&
		bytes != (384 / 8) * 3 &&
		bytes != (512 / 8) * 3)
	{
		return false;
	}

	_key_bytes = bytes / 3;

	memcpy(_key_pair, file.Read(bytes), bytes);

	_valid = true;
	return true;
}

bool TunnelKeyPair::SaveFile(const char *file_path)
{
	if (!_valid) return false;

	ofstream keyfile(file_path, ios_base::out | ios_base::binary);

	if (!keyfile) return false;

	keyfile.write((char*)_key_pair, _key_bytes * 3);

	return keyfile.good();
}

bool TunnelKeyPair::Generate(TunnelTLS *tls)
{
	CAT_DEBUG_ENFORCE(tls && tls->Valid());

	BigTwistedEdwards *math = tls->Math();
	int bits = math->RegBytes() * 8;

	// Validate and accept number of bits
	if (!KeyAgreementCommon::Initialize(bits))
		return false;

	Leg *b = math->Get(0);
	Leg *B = math->Get(1);

	// Generate private key
	GenerateKey(tls, b);

	// Generate public key
	math->PtMultiply(math->GetGenerator(), b, 0, B);

	// Save key pair and generator point
	math->SaveAffineXY(B, _key_pair, _key_pair + KeyBytes);
	math->Save(b, _key_pair + KeyBytes * 2, KeyBytes);

	_key_bytes = KeyBytes;
	_valid = true;

	return true;
}


//// TunnelPublicKey

TunnelPublicKey::TunnelPublicKey()
{
	_key_bytes = 0;
	_valid = false;
}

TunnelPublicKey::~TunnelPublicKey()
{
}

TunnelPublicKey::TunnelPublicKey(const void *key, u32 bytes)
{
	_valid = LoadMemory(key, bytes);
}

bool TunnelPublicKey::LoadMemory(const void *key, u32 bytes)
{
	if (bytes != (256 / 8) * 2 &&
		bytes != (384 / 8) * 2 &&
		bytes != (512 / 8) * 2)
	{
		return false;
	}

	_key_bytes = bytes / 2;

	memcpy(_public_key, key, bytes);

	_valid = true;
	return true;
}

TunnelPublicKey::TunnelPublicKey(TunnelKeyPair &pair)
{
	operator=(pair);
}

TunnelPublicKey &TunnelPublicKey::operator=(TunnelKeyPair &pair)
{
	_key_bytes = 0;
	_valid = false;

	if (!pair.Valid()) return *this;

	_key_bytes = pair.GetPrivateKeyBytes();

	memcpy(_public_key, pair.GetPublicKey(), _key_bytes * 2);

	_valid = true;
	return *this;
}

bool TunnelPublicKey::LoadBase64(const char *base64_encoded)
{
	_valid = false;

	int encoded_bytes = (int)strlen(base64_encoded);

	// Decode the public key || private key pair
	int copied = ReadBase64(base64_encoded, encoded_bytes, _public_key, sizeof(_public_key));

	if (copied != (256 / 8) * 2 &&
		copied != (384 / 8) * 2 &&
		copied != (512 / 8) * 2)
	{
		return false;
	}

	_key_bytes = copied / 2;

	_valid = true;
	return true;
}

bool TunnelPublicKey::LoadFile(const char *file_path)
{
	_valid = false;

	// Attempt to map key file
	SequentialFileReader file;

	if (!file.Open(file_path)) return false;

	u32 bytes = (u32)file.GetLength();

	if (bytes != (256 / 8) * 2 &&
		bytes != (384 / 8) * 2 &&
		bytes != (512 / 8) * 2)
	{
		return false;
	}

	_key_bytes = bytes / 2;

	memcpy(_public_key, file.Read(bytes), bytes);

	_valid = true;
	return true;
}

bool TunnelPublicKey::SaveFile(const char *file_path)
{
	if (!_valid) return false;

	ofstream keyfile(file_path, ios_base::out | ios_base::binary);

	if (!keyfile) return false;

	keyfile.write((char*)_public_key, _key_bytes * 2);

	return keyfile.good();
}
