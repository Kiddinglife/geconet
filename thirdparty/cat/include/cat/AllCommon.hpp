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

// Include all libcat Common headers

#include <cat/Platform.hpp>

#if defined(CAT_COMPILER_MSVC) && defined(CAT_BUILD_DLL)
# pragma warning(push)
# pragma warning(disable:4251) // Remove "not exported" warning from STL
#endif

#include <cat/time/Clock.hpp>

#include <cat/rand/IRandom.hpp>
#include <cat/rand/MersenneTwister.hpp>
#include <cat/rand/StdRand.hpp>
#include <cat/rand/SmallPRNG.hpp>
#include <cat/rand/AbyssinianPRNG.hpp>

#include <cat/hash/Murmur.hpp>

#include <cat/threads/Atomic.hpp>
#include <cat/threads/Mutex.hpp>
#include <cat/threads/RWLock.hpp>
#include <cat/threads/Thread.hpp>
#include <cat/threads/WaitableFlag.hpp>
#include <cat/threads/WorkerThreads.hpp>

#include <cat/math/BitMath.hpp>

#include <cat/net/Sockets.hpp>

#include <cat/port/SystemInfo.hpp>
#include <cat/port/EndianNeutral.hpp>

#include <cat/lang/Strings.hpp>
#include <cat/lang/Delegates.hpp>
#include <cat/lang/LinkedLists.hpp>
#include <cat/lang/Singleton.hpp>
#include <cat/lang/RefSingleton.hpp>
#include <cat/lang/RefObject.hpp>
#include <cat/lang/MergeSort.hpp>
#include <cat/lang/HashTable.hpp>

#include <cat/io/Log.hpp>
#include <cat/io/LogThread.hpp>
#include <cat/io/MappedFile.hpp>
#include <cat/io/RagdollFile.hpp>
#include <cat/io/Settings.hpp>

#include <cat/parse/BufferTok.hpp>
#include <cat/parse/BufferStream.hpp>
#include <cat/parse/Base64.hpp>

#include <cat/mem/IAllocator.hpp>
#include <cat/mem/StdAllocator.hpp>
#include <cat/mem/AlignedAllocator.hpp>
#include <cat/mem/LargeAllocator.hpp>
#include <cat/mem/BufferAllocator.hpp>

#if defined(CAT_COMPILER_MSVC) && defined(CAT_BUILD_DLL)
# pragma warning(pop)
#endif
