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

// Include all libcat Sphynx headers

#include <cat/AllCommon.hpp>
#include <cat/AllCrypt.hpp>
#include <cat/AllMath.hpp>
#include <cat/AllTunnel.hpp>
#include <cat/AllAsyncIO.hpp>

#if defined(CAT_COMPILER_MSVC) && defined(CAT_BUILD_DLL)
# pragma warning(push)
# pragma warning(disable:4251) // Remove "not exported" warning from STL
#endif

#include <cat/net/DNSClient.hpp>

#include <cat/sphynx/Common.hpp>
#include <cat/sphynx/Connexion.hpp>
#include <cat/sphynx/ConnexionMap.hpp>
#include <cat/sphynx/Collexion.hpp>
#include <cat/sphynx/Client.hpp>
#include <cat/sphynx/FlowControl.hpp>
#include <cat/sphynx/Server.hpp>
#include <cat/sphynx/Transport.hpp>
#include <cat/sphynx/FileTransfer.hpp>

#if defined(CAT_COMPILER_MSVC) && defined(CAT_BUILD_DLL)
# pragma warning(pop)
#endif
