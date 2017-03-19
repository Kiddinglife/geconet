/*
	Copyright (c) 2009-2012 Christopher A. Taylor.  All rights reserved.

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

#ifndef CAT_THREAD_HPP
#define CAT_THREAD_HPP

#include <cat/lang/Delegates.hpp>
#include <cat/lang/Singleton.hpp>
#include <cat/threads/Mutex.hpp>
#include <cat/lang/HashTable.hpp>
#include <cat/lang/RefSingleton.hpp>

#if !defined(CAT_OS_WINDOWS)
# include <pthread.h>
#endif

namespace cat {


//// Thread priority modification

enum ThreadPrio
{
	P_IDLE,
	P_LOW,
	P_NORMAL,
	P_HIGH,
	P_HIGHEST,
};

bool SetExecPriority(ThreadPrio prio = P_NORMAL);

u32 GetThreadID();


//// Thread-Local Storage (TLS) 

static const int MAX_TLS_BINS = 16;

/*
	ITLS

		Thread-local storage interface base class

	Derive from this class to implement your TLS data

	Derivative classes must define a static member called GetNameString()
*/
class CAT_EXPORT ITLS
{
	bool _is_initialized;

public:
	CAT_INLINE ITLS() { _is_initialized = false; }
	CAT_INLINE virtual ~ITLS() {} // Must define a virtual dtor

	CAT_INLINE bool TryInitialize()
	{
		if (!_is_initialized)
			_is_initialized = OnInitialize();
	}

	// Called when TLS object is inserted into the TLS slot
	CAT_INLINE virtual bool OnInitialize() { return false; }

	// Called during thread termination
	CAT_INLINE virtual void OnFinalize() {}

	// Must override this
	static CAT_INLINE const char *GetNameString() { return "SetUniqueNameHere"; }

	// Usage: MyTLSDerivativeType *mine; tls->Unwrap(mine);
	template<class T> CAT_INLINE void Unwrap(T *&to)
	{
		to = (this == 0) ? 0 : static_cast<T*>( this );
	}
};


/*
	ThreadLocalStorage

		TLS implementation built on top of Thread for portability.
	Contains slots that must be registered at runtime for use by
	the TLSClaim singleton.

		I would love to be able to use the TLS built into compilers
	but it is unreliable on platforms that I care about.
*/
class CAT_EXPORT ThreadLocalStorage
{
	ITLS *_bins[MAX_TLS_BINS];

public:
	CAT_INLINE ThreadLocalStorage()
	{
		CAT_OBJCLR(_bins);
	}

	// Pre-condition: index < MAX_BINS
	CAT_INLINE ITLS *&operator[](u32 index)
	{
		return _bins[index];
	}
};


/*
	SlowThreadLocalStorage

		Aptly-named because it is a standard TLS implementation based
	on operating system thread ID instead of Thread object extension.
*/
class SlowTLS : public RefSingleton<SlowTLS>
{
	bool OnInitialize();
	void OnFinalize();

	Mutex _lock;

	class TLSItem : public HashItem
	{
	public:
		CAT_INLINE TLSItem(const KeyAdapter &key)
			: HashItem(key)
		{
		}

		ThreadLocalStorage tls;
	};

	HashTable<TLSItem> *_map;

public:
	ThreadLocalStorage *Get();

	// Grab TLS instance of slot
	template<class T>
	void Find(T *&slot)
	{
		TLSInstance<T> instance;

		ThreadLocalStorage *tls = Get();

		slot = instance.Ref(*tls);
	}
};


/*
	TLSClaim

		Claim an id number for a TLS slot for a specific purpose at
	runtime in a thread-safe way.
*/
class CAT_EXPORT TLSClaim : public Singleton<TLSClaim>
{
	bool OnInitialize();

	Mutex _lock;
	u32 _next_index;

	HashTableBase _map;

public:
	// Returns an unsigned bin index from a unique text string
	// Or an error if return value >= MAX_TLS_BINS
	u32 Claim(const char *key_name);
};


/*
	TLSInstance
*/
template<class T>
class TLSInstance
{
	static const u32 INVALID = ~(u32)0;

	volatile u32 _index;

	u32 GetIndex()
	{
		u32 index = _index;
		if (index == INVALID)
		{
			index = TLSClaim::ref()->Claim(T::GetNameString());
			_index = index;
		}
		return index;
	}

public:
	TLSInstance()
	{
		_index = INVALID;
	}

	T *Ref(ThreadLocalStorage &tls)
	{
		u32 index = GetIndex();

		T *instance;
		tls[index]->Unwrap(instance);

		if (!instance)
		{
			instance = new T;
			if (instance)
			{
				if (instance->OnInitialize())
					tls[index] = instance;
				else
				{
					instance->OnFinalize();
					delete instance;
				}
			}
		}

		return instance;
	}

	T *Peek(ThreadLocalStorage &tls)
	{
		u32 index = GetIndex();

		T *instance;
		tls[index]->Unwrap(instance);

		return instance;
	}
};


/*
	A thread that executes ThreadFunction and then exits.

	Derive from this class and implement ThreadFunction().
*/
class CAT_EXPORT Thread
{
protected:
	void *_caller_param;
	volatile bool _thread_running;

#if defined(CAT_OS_WINDOWS)
	volatile HANDLE _thread;
	static unsigned int __stdcall ThreadWrapper(void *this_object);
#else
	pthread_t _thread;
	static void *ThreadWrapper(void *this_object);
#endif

public:
	bool StartThread(void *param = 0);
	void SetIdealCore(u32 index);
	bool WaitForThread(int milliseconds = -1); // < 0 = infinite wait
	void AbortThread();

	CAT_INLINE bool ThreadRunning() { return _thread_running; }

protected:
	virtual bool Entrypoint(void *param) = 0;

public:
	Thread();
	CAT_INLINE virtual ~Thread() {}

	/*
		thread_atexit() framework

		This allows you to specify callbacks to invoke when the Thread terminates.

		Simply pass a callback to Thread::AtExit() and it will be queued up for
		execution in the local storage for that thread.

		For threads that are not implemented with Thread you can still invoke the
		AtExit callbacks by calling Thread::InvokeAtExit();
	*/
	typedef Delegate0<void> AtExitCallback;

	bool AtExit(const AtExitCallback &cb);
	void InvokeAtExit(); // Only need to use this if not a Thread thread

private:
	static const int MAX_CALLBACKS = 16;

	int _cb_count;
	AtExitCallback _callbacks[MAX_CALLBACKS];

protected:
	// Thread itself gets access to the TLS bins - Only modify these from the entrypoint!
	ThreadLocalStorage _tls;

public:
	CAT_INLINE ThreadLocalStorage &GetTLS() { return _tls; }
};


} // namespace cat

#endif // CAT_THREAD_HPP
