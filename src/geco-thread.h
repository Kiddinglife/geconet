/*
*
* Copyright (c) 1994
* Hewlett-Packard Company SGI_STL
*
* Permission to use, copy, modify, distribute and sell this software
* and its documentation for SGI_STL purpose is hereby granted without fee,
* provided that the above copyright notice appear in all copies and
* that both that copyright notice and this permission notice appear
* in supporting documentation.  Hewlett-Packard Comp SGI_STL makes no
* representations about the suitability of this software for SGI_STL
* purpose.  It is provided "as is" without express or implied warranty.
*
* Copyright (c) 1997
* Silicon Graphics
*
* Permission to use, copy, modify, distribute and sell this software
* and its documentation for SGI_STL purpose is hereby granted without fee,
* provided that the above copyright notice appear in all copies and
* that both that copyright notice and this permission notice appear
* in supporting documentation.  Silicon Graphics makes no
* representations about the suitability of this software for SGI_STL
* purpose.  It is provided "as is" without express or implied warranty.
*
* Copyright (c) 2016
* Geco Gaming Company
*
* Permission to use, copy, modify, distribute and sell this software
* and its documentation for GECO purpose is hereby granted without fee,
* provided that the above copyright notice appear in all copies and
* that both that copyright notice and this permission notice appear
* in supporting documentation.  GECO makes no representations about
* the suitability of this software for GECO purpose.
* It is provided "as is" without express or implied warranty.
*
*/




/*
* geco-ds-type-traitor-ext.h
*
*  Created on: 30 April 2016
*      Author: jakez
*/

# ifndef __INCLUDE_GECO_THREAD_H
# define __INCLUDE_GECO_THREAD_H

#include "geco-ds-config.h"

// Supported threading models are 
// native SGI, 
// pthreads,
// uithreads (similar to pthreads, but based on an earlier draft of the Posix threads standard)
// Win32 threads. 
#if defined(GECO_SGI_THREADS)
#include <mutex.h>
#include <time.h>
#elif defined(GECO_PTHREADS)
#include <pthread.h>
#elif defined(GECO_UITHREADS)
#include <thread.h>
#include <synch.h>
#elif defined(GECO_WIN32THREADS)
#include <windows.h>
#endif

GECO_BEGIN_NAMESPACE

# ifdef GECO_WIN32THREADS
typedef long rfcount_val_t;
# else
typedef size_t rfcount_val_t;
#endif

struct ref_count_t
{

    // The data member rfcount_val_
    volatile rfcount_val_t rfcount_val_;

    // Constructor
# if defined(GECO_UITHREADS)
    mutex_t         rfcval_locker_;
    ref_count_t(rfcount_val_t __n) : rfcount_val_(__n)
    {
        mutex_init(&rfcval_locker_, USYNC_THREAD, 0);
    }
# else
    ref_count_t(rfcount_val_t __n) : rfcount_val_(__n) {}
# endif

    /*----incr and decr-------*/
# ifdef GECO_SGI_THREADS
    void incr() { __add_and_fetch(&rfcount_val_, 1); }
    rfcount_val_t decr() { return __add_and_fetch(&rfcount_val_, (size_t)-1); }
# elif defined (GECO_WIN32THREADS)
    void incr() { InterlockedIncrement(&rfcount_val_); }
    rfcount_val_t decr() { return InterlockedDecrement(&rfcount_val_); }
# elif defined (GECO_PTHREADS)
    void incr() {  __sync_add_and_fetch (&rfcount_val_, 1); }
    rfcount_val_t decr() { return __sync_sub_and_fetch (&rfcount_val_, 1); }
# elif defined (GECO_UITHREADS)
    void incr() 
    {
        mutex_lock(&rfcval_locker_);
        ++rfcount_val_;
        mutex_unlock(&rfcval_locker_);
    }
    rfcount_val_t decr()
    {
        mutex_lock(&rfcval_locker_);
        /*volatile*/ rfcount_val_t __tmp = --rfcount_val_;
        mutex_unlock(&rfcval_locker_);
        return __tmp;
    }
#else 
    // No threads 
    void incr() { ++rfcount_val_; }
    rfcount_val_t decr() { return --rfcount_val_; }
#endif

    /**
    // Atomic swap on unsigned long
    // This is guaranteed to behave as though it were atomic only if all
    // possibly concurrent updates use _Atomic_swap.
    // In some cases the operation is emulated with a lock.
    */
# ifdef GECO_SGI_THREADS
    inline unsigned long swap(unsigned long * __p, unsigned long __q) 
    {
#if __mips < 3 || !(defined (_ABIN32) || defined(_ABI64))
        return test_and_set(__p, __q);
# else
        return __test_and_set(__p, (unsigned long)__q);
#endif
    }
# elif defined (GECO_WIN32THREADS)
    inline unsigned long swap(unsigned long __q)
    {
        return (unsigned long)InterlockedExchange((LPLONG)&rfcount_val_,
            (long)__q);
    }
# elif defined (GECO_PTHREADS)
    inline unsigned long swap(unsigned long __q)
    {
        return (unsigned long)__sync_lock_test_and_set (&rfcount_val_, __q);
    }
# elif defined (GECO_UITHREADS)
    // We use a template here only to get a unique initialized instance.
    template<int __dummy>
    struct _Swap_lock_struct {static mutex_t _S_swap_lock; };

    template<int __dummy>
    mutex_t  _Swap_lock_struct<__dummy>::_S_swap_lock = DEFAULTMUTEX;

    // This should be portable, but performance is expected
    // to be quite awful.  This really needs platform specific
    // code.
    inline unsigned long swap(unsigned long __q)
    {
        mutex_lock(&_Swap_lock_struct<0>::_S_swap_lock);
        unsigned long __result = rfcount_val_;
        rfcount_val_ = __q;
        mutex_unlock(&_Swap_lock_struct<0>::_S_swap_lock);
        return __result;
    }
#else 
    // No threads 
    static inline unsigned long swap(unsigned long __q)
    {
        unsigned long __result = rfcount_val_;
        rfcount_val_ = __q;
        return __result;
    }
#endif
};

// Locking class.  Note that this class *does not have a constructor*.
// It must be initialized either statically, with LOCKER_INITIALIZER,
// or dynamically, by explicitly calling the _M_initialize member function.
// (This is similar to the ways that a pthreads mutex can be initialized.)
// There are explicit member functions for acquiring and releasing the lock.

// There is no constructor because static initialization is essential for
// some uses, and only a class aggregate (see section 8.5.1 of the C++
// standard) can be initialized that way.  That means we must have no
// constructors, no base classes, no virtual functions, and no private or
// protected members.
enum : unsigned { __low_max = 30, __high_max = 1000 };
struct locker_t
{

#if defined(GECO_USE_STL_THREADS)
    // It should be relatively easy to get this to work on any modern Unix.
    ref_count_t refc_;

    // Low if we suspect uniprocessor, high for multiprocessor.
    unsigned __max;
    unsigned __last;

    locker_t() :
        refc_(
#if defined(GECO_UITHREADS)
        DEFAULTMUTEX
#else
        0
#endif
        )
    {
        __last = 0;
        __max = __low_max;
    }

    inline void nsec_sleep(int __log_nsec)
    {
#ifdef GECO_SGI_THREADS
        struct timespec __ts;
        /* Max sleep is 2**27nsec ~ 60msec      */
        __ts.tv_sec = 0;
        __ts.tv_nsec = 1 << __log_nsec;
        nanosleep(&__ts, 0);
#elif defined(GECO_WIN32THREADS)
        __log_nsec <= 20 ? Sleep(0) : Sleep(1 << (__log_nsec - 20));
#else
#       error unimplemented
#endif
    }

    void acquire()
    {
        geco_printf("acquire()\n");
        // unlocked val_ = 0, locked val_=1
        // swap returns zero means we are first thread to acquire the locker
        // so no need to spin loger, just simply return and start to work
        // when we return, the locker will be locked by setting __lock to 1
        // when othr threads comes in, they have to spin and wait us finish
        if (!refc_.swap(1))
        {
            return;
        }

        unsigned __my_spin_max = __max;
        unsigned __my_last_spins = __last;
        volatile unsigned __junk = 16;      // Value doesn't matter.
        unsigned __i;
        for (__i = 0; __i < __my_spin_max; __i++)
        {
            // at least spin half of the last nuber of spins until unlocked
            if (__i < (__my_last_spins >> 1) || refc_.rfcount_val_)
            {
                __junk *= __junk; __junk *= __junk;
                __junk *= __junk; __junk *= __junk;
                continue;
            }

            if (!refc_.swap(1))
            {
                // Spinning worked and get unlocked.   
                // this may imply that the working thread probably not being scheduled
                // against the other process with which we were contending.
                // because __max is for low uniprocessor and  the spinning thread waits for
                // get unlocked within no more than __max number of spins
                // 
                __last = __i;
                __max = __high_max;
                return;
            }
        }

        // the working thread are probably being scheduled against the other process.  
        // that is why it is still locked even through this spinning thread finisup all spins 
        // working thread is also scheduled on some other processors for other tasks 
        // and have to jump between different processors, the time it takes exceed that of 
        // low_max number of spins the spinning thread has done.
        // so we need let spinning thread sleep a while to save cpu cycles
        __max = __low_max;
        for (__i = 0;; ++__i)
        {
            int __log_nsec = __i + 6;
            if (__log_nsec > 27) __log_nsec = 27; // we sleep at most 27 nsecs
            if (!refc_.swap(1))
            {
                return;
            }
            nsec_sleep(__log_nsec); // sleep to save cpu cycles
        }
    }

    void release()
    {
        geco_printf("release\n");
        // unlocked val_ = 0, locked val_=1
        refc_.swap(0);

        //#   if defined(GECO_SGI_THREADS) && defined(__GNUC__) && __mips >= 3
        //        asm("sync");
        //        *__lock = 0;
        //#   elif defined(GECO_SGI_THREADS) && __mips >= 3 \
                                                                                                //         && (defined (_ABIN32) || defined(_ABI64))
        //        __lock_release(__lock);
        //#   else 
        //        *__lock = 0;
        //        // This is not sufficient on many multiprocessors, since
        //        // writes to protected variables and the lock may be reordered.
        //#   endif
    }
#else
    void acquire() {}
    void release() {}
#endif
};


// A locking class that uses locker_t.  The constructor takes a
// reference to an locker_t, and acquires a lock.  The
// destructor releases the lock.  It's not clear that this is exactly
// the right functionality.  It will probably change in the future.

struct auto_locker_t
{
    locker_t& _M_lock;

    auto_locker_t(locker_t& __lock) : _M_lock(__lock)
    {
        _M_lock.acquire();
    }
    ~auto_locker_t() { _M_lock.release(); }

    private:
    void operator=(const auto_locker_t&);
    auto_locker_t(const auto_locker_t&);
};

GECO_END_NAMESPACE

#endif