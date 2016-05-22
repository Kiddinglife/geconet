/*
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
 * geco-malloc.h
 *
 *  Created on: 22 Mar 2016
 * Author:     jake zhang
 * E - mail:   Jakezhang1989@hotmail.com
 * GitHub:    https://!github.com/Kiddinglife
 */

#ifndef __INCLUDE_GECO_DS_MALLOC_H
#define __INCLUDE_GECO_DS_MALLOC_H

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cstdio>
#include "geco-ds-config.h"

#ifndef __RESTRICT
#  define __RESTRICT
#endif

#ifdef __SUNPRO_CC
#   define PRIVATE public
//! SUN编译器对private限制过多, 需要开放权限 
//! Extra access restrictions prevent us from really making some things
//! private.
#else
#   define PRIVATE private
#endif

//! 为了保证兼容性, 对于不支持模板类静态成员的情况, 使用malloc()进行内存分配 
#ifdef GECO_STATIC_TEMPLATE_MEMBER_BUG
#  define GECO_USE_MALLOC
#endif

//! allocation primitives意在分配不大于原始STL allocator分配的独立的对象  
//! This implements some standard node allocators.  These are
//! NOT the same as the allocators in the C++ draft standard or in
//! in the original STL.  They do not encapsulate different pointer
//! types; indeed we assume that there is only one pointer type.
//! The allocation primitives are intended to allocate individual objects,
//! not larger arenas as with the original STL allocators.
#ifndef THROW_BAD_ALLOC
#  if defined(GECO_NO_BAD_ALLOC) || !defined(GECO_USE_EXCEPTIONS)
#    include <cstdio>
#    define THROW_BAD_ALLOC fprintf(stderr, "out of memory\n"); exit(1)
#  else /* Standard conforming out-of-memory handling */
#    include <new>
#    define THROW_BAD_ALLOC throw std::bad_alloc()
#  endif
#endif

//#define GECO_NO_THREADS
#if defined(GECO_USE_STL_THREADS) && !defined(GECO_NO_THREADS)
#include "geco-thread.h"
#define GECO_ALLOC_USES_THREAD true
# ifdef GECO_SGI_THREADS
//! We test whether threads are in use before locking.
//! Perhaps this should be moved into stl_threads.h, but that
//! probably makes it harder to avoid the procedure call when
//! it isn't needed.
extern "C"
{
    extern int __us_rsthread_malloc;
}
//! The above is copied from malloc.h.  Including <malloc.h>
//! would be cleaner but fails with certain levels of standard
//! conformance.
# define GECO_ALLOC_LOCK \
if (threads && __us_rsthread_malloc) \
{ _S_node_allocator_lock.acquire(); }
# define GECO_ALLOC_UNLOCK
if (threads && __us_rsthread_malloc)
{   _S_node_allocator_lock.release();}
# else /* !GECO_SGI_THREADS */
# define GECO_ALLOC_LOCK \
{ if (threads) _S_node_allocator_lock.acquire(); }
# define GECO_ALLOC_UNLOCK \
{ if (threads) _S_node_allocator_lock.release(); }
# endif
#else
//!  Thread-unsafe
# define GECO_ALLOC_LOCK
# define GECO_ALLOC_UNLOCK
# define GECO_ALLOC_USES_THREAD false
#endif

#if defined(__sgi) && !defined(__GNUC__) && (_MIPS_SIM != _MIPS_SIM_ABI32)
#pragma set woff 1174
#endif

GECO_BEGIN_NAMESPACE

//! Malloc-based allocator.  Typically slower than default alloc below.
//! Typically thread-safe and more storage efficient.
#ifdef GECO_STATIC_TEMPLATE_MEMBER_BUG
# ifdef DECLARE_GLOBALS_HERE
void (* __malloc_alloc_oom_handler)() = 0;
//! g++ 2.7.2 does not handle static template data members.
# else
extern void (* __malloc_alloc_oom_handler)();
# endif
#endif

#define alloc_type_first 1
#define alloc_type_second 2
typedef void(*oom_handler_t)();

//! 一级配置器  使用malloc()分配内存
template<int inst>
class malloc_alloc
{
#ifndef GECO_STATIC_TEMPLATE_MEMBER_BUG
    //!! 如果编译器支持模板类静态成员, 则使用错误处理函数, 类似C++的set_new_handler()  
    //!! 默认值为0, 如果不设置, 则内存分配失败时直接THROW_BAD_ALLOC. 
    static oom_handler_t oom_handler;
#endif

    //!! 使用malloc()循环分配内存,  直到成功分配  
    static void* oom_malloc(size_t size)
    {
        //! 如果设置了oom_handler, 则首先执行错误处理函数, 然后循环分配直到成功
        //! 如果未设置oom_handler, THROW_BAD_ALLOC  
        void(*my_oom_handler)() = 0;
        void* result = 0;
        while (result == 0)
        {
            my_oom_handler = oom_handler;
            if (my_oom_handler == 0)
            {
                THROW_BAD_ALLOC;
            }
            (*my_oom_handler)();
            result = malloc(size);
        }
        return result;
    }

    //!! 使用realloc()循环分配内存,  直到成功分配 
    static void* oom_realloc(void* pointer, size_t size)
    {
        void(*my_oom_handler)() = 0;
        void* result = 0;
        while (result == 0)
        {
            my_oom_handler = oom_handler;
            if (my_oom_handler == 0)
            {
                THROW_BAD_ALLOC;
            }
            (*my_oom_handler)();
            result = realloc(pointer, size);
        }
        return result;
    }

    public:
    //!! 分配指定大小的内存(size_t n)， 如果分配失败, 则进入循环分配阶段
    //!! 循环分配前提是要保证正确设置了oom_handler.
    static void* allocate(size_t size)
    {
        void* result = malloc(size);
        if (0 == result) result = oom_malloc(size);
        return result;
    }

    //!! 后面的size_t是为了兼容operator delele
    static void deallocate(void* pointer, size_t size)
    {
        free(pointer);
    }

    //! 重新分配内存大小, 第二个参数是为了兼容operator new 
    static void* reallocate(void* pointer, size_t old_size, size_t new_size)
    {
        void* result = realloc(pointer, new_size);
        if (0 == result) result = oom_realloc(pointer, new_size);
        return result;
    }

    //!! 设置错误处理函数, 返回原来的函数指针 
    //!! 不属于C++标准规定的接口  
    //static void(*set_oom_handler(void(*oom_handler_)()))()
    //{
    //void(*old)() = oom_handler;
    //oom_handler = oom_handler_;
    // return (old);
    //}
    static oom_handler_t set_oom_handler(oom_handler_t oom_handler_)
    {
        oom_handler_t old = oom_handler;
        oom_handler = oom_handler_;
        return (old);
    }

    bool operator==(const malloc_alloc&)
    {
        return true;
    }

    bool operator!=(const malloc_alloc&)
    {
        return false;
    }
};

//! 这个版本的STL并没有使用non-type模板参数 
typedef malloc_alloc<0> malloc_allocator;

//! initialize out-of-memory handler when malloc() fails
#ifndef GECO_STATIC_TEMPLATE_MEMBER_BUG
template <int inst>
oom_handler_t malloc_alloc<inst>::oom_handler = 0;
#endif

//! simple_alloc中的接口其实就是STL标准中的allocator的接口  
//! 实际上所有的SGI STL都使用这个进行内存配置  
//! 例如: stl_vector.h中  
//! template <class T, class Alloc = alloc>  
//! class vector  
//! {  
//!      ...  
//! protected:  
//!      typedef simple_alloc<value_type, Alloc> data_allocator;  
//!      ...  
//!};  
template <class ValueType, class Alloc>
class simple_alloc
{
    public:
    static ValueType* allocate(size_t size)
    {
        return size == 0 ? 0 : (ValueType*)Alloc::allocate(size*sizeof(ValueType));
    }
    static ValueType* allocate(void)
    {
        return (ValueType*)Alloc::allocate(sizeof(ValueType));
    }
    static void deallocate(ValueType* pointer, size_t size)
    {
        if (0 != size) Alloc::deallocate(pointer, size * sizeof(ValueType));
    }
    static void deallocate(ValueType* pointer)
    {
        Alloc::deallocate(pointer, sizeof(ValueType));
    }
    static void destroy()
    {
        Alloc::destroy();
    }
};

//! Allocator adaptor to check size arguments for debugging.
//! Reports errors using assert.  Checking can be disabled with
//! NDEBUG, but it's far better to just use the underlying allocator
//! instead when no checking is desired.
//! There is some evidence that this can confuse Purify.
//! Purify is the C/C++ memory checker
template <class Alloc>
class debug_alloc
{
    enum
    {
        extra_size = 8
    };  //! Size of space used to store size.  Note

    //! that this must be large enough to preserve alignment.
    //! extra 保证不会分配为0的内存空间, 而且要保证内存对齐  
    //! 把分配内存的最前面设置成n的大小, 用于后面校验  
    //! 内存对齐的作用就是保护前面extra大小的数据不被修改  
    static void* allocate(size_t size)
    {
        char* __result = (char*)Alloc::allocate(size + (int)extra_size);
        *(size_t*)__result = size;
        return __result + (int)extra_size;
    }

    static void deallocate(void* pointer, size_t size)
    {
        char* __real_p = (char*)pointer - (int)extra_size;
        assert(*(size_t*)__real_p == size); //! 如果*(size_t *)real_p != n则肯定发生向前越界
        Alloc::deallocate(__real_p, size + (int)extra_size);
    }

    static void* reallocate(void* pointer, size_t __old_sz, size_t __new_sz)
    {
        char* __real_p = (char*)pointer - (int)extra_size;
        assert(*(size_t*)__real_p == __old_sz);
        char* result = (char*)Alloc::reallocate(__real_p,
            __old_sz + (int)extra_size,
            __new_sz + (int)extra_size);
        *(size_t*)result = __new_sz;
        return result + (int)extra_size;
    }

    public:
    bool operator==(const debug_alloc&)
    {
        return true;
    }

    bool operator!=(const debug_alloc&)
    {
        return false;
    }
};

//!编译器不支持template member的话，使用malloc()
#ifdef GECO_USE_MALLOC
typedef typename malloc_alloc_0 alloc;
typedef typename malloc_alloc_0 single_client_alloc;
#else
const size_t ALLOC_UNITS_SIZE = 256;
const size_t ALIGN = 8;
const size_t MAX_BYTES = 1512;
const size_t NFREELISTS = MAX_BYTES / ALIGN;

//! Default node allocator.
//! With a reasonable compiler, this should be roughly as fast as the
//! original STL class-specific allocators, but with less fragmentation.
//! default_alloc parameters are experimental and MAY
//! DISAPPEAR in the future.  Clients should just use alloc for now.
//!
//! Important implementation properties:
//! 1. If the client request an object of size > _MAX_BYTES, the resulting
//!    object will be obtained directly from malloc.
//! 2. In all other cases, we allocate an object of size exactly
//!    _S_round_up(requested_size).  Thus the client has enough size
//!    information that we can return the object to the proper free list
//!    without permanently losing part of the object.
//!

//! The first template parameter specifies whether more than one thread
//! may use this allocator.  It is safe to allocate an object from
//! one instance of a default_alloc and deallocate it with another
//! one.  This effectively transfers its ownership to the second one.
//! This may have undesirable effects on reference locality.
//! The second parameter is unreferenced and serves only to allow the
//! creation of multiple default_alloc instances.
//! Node that containers built on different allocator instances have
//! different types, limiting the utility of this approach.
// the sizeof(Unit) = bigger member's size = sizeof(Unit*) = 4 bytes

union Unit
{
    // when allcate, this field will be used to update next avaiable freelist
    // then it will be given to client who will be using this union safely
    //when reclaim, this field will be assigne a value and link to another uable freelist
    union Unit* _M_free_list_link;
    // The client sees this because it will be returned as pointer to client
    char _M_client_data[1];
};

template <bool threads, int inst>
class default_alloc
{
    private:
# if defined(__SUNPRO_CC) || defined(__GNUC__) || defined(__HP_aCC)
    static Unit* GECO_VOLATILE free_list[];
    // Specifying a size results in duplicate def for 4.1
# else
    // 这里分配的free_list为16  
    // 对应的内存链容量分别为8, 16, 32 ... 128....1512
    static Unit* GECO_VOLATILE free_list[NFREELISTS];
# endif

    static void* pools_[NFREELISTS];
    static size_t pool_num;

    // Unit allocation state.
    static char* start_free;// pool start address in each chunk
    static char* end_free;//  pool end address in each chunk
    static size_t heap_size;// 已经在堆上分配的空间大小

# ifdef GECO_USE_STL_THREADS
    static locker_t _S_node_allocator_lock;
# endif

    // It would be nice to use _STL_auto_lock here.  But we
    // don't need the NULL check.  And we do need a test whether
    // threads have actually been started.
    struct Guard
    {
        Guard()
        {
            GECO_ALLOC_LOCK;
        }
        ~Guard()
        {
            GECO_ALLOC_UNLOCK;
        }
    };
    friend struct Guard;

    //! 向上舍入操作
    //! 解释一下, ALIGN - 1指明的是实际内存对齐的粒度
    //! 例如ALIGN = 8时, 我们只需要7就可以实际表示8个数(0~7)
    //! 那么~(ALIGN - 1)就是进行舍入的粒度
    //! 我们将(bytes) + ALIGN-1)就是先进行进位, 然后截断
    //! 这就保证了我是向上舍入的
    //! 例如byte = 100, ALIGN = 8的情况
    //! ~(ALIGN - 1) = (1 000)B
    //! ((bytes) + ALIGN-1) = (1 101 011)B
    //! (((bytes) + ALIGN-1) & ~(ALIGN - 1)) = (1 101 000 )B = (104)D
    //! 104 / 8 = 13, 这就实现了向上舍入
    //! 对于byte刚好满足内存对齐的情况下, 结果保持byte大小不变
    //! 记得《Hacker's Delight》上面有相关的计算
    //! 这个表达式与下面给出的等价
    //! ((((bytes) + _ALIGN - 1) * _ALIGN) / _ALIGN)
    //! 但是SGI STL使用的方法效率非常高
    static size_t round_up(size_t size)
    {
        return (((size)+(size_t)ALIGN - 1) & ~((size_t)ALIGN - 1));
    }

    //! 根据待待分配的空间大小, 在free_list中选择合适的大小
    static size_t freelist_index(size_t size)
    {
        return (((size)+(size_t)ALIGN - 1) / (size_t)ALIGN - 1);
    }

    //! Returns an object of size @allocbytes, and optionally adds to size @allocbytes free list.
    //! We assume that size is properly aligned. 
    //! must  be locked if threads enabled
    static void* build_unit_list(size_t aligned_uint_size)
    {
        int alloc_units_size = ALLOC_UNITS_SIZE;
        char* unit = alloc_units(aligned_uint_size, alloc_units_size);

        if (alloc_units_size == 1)
            return (unit);

        // substract 1 as we counted the one returned to client already
        alloc_units_size -= 1;
        /* Build a free list in size of @allocbytes */
        //1) find an avaiable free list
        Unit* GECO_VOLATILE* my_free_list = free_list + freelist_index(aligned_uint_size);
        //2) find the start unit exclusive the first one for returning to client
        Unit* curr;
        Unit* next;
        *my_free_list = next = (Unit*)(unit + aligned_uint_size);//allocbytes has been rounded up
        //3) orgnize the units to a free list
        while (alloc_units_size > 1)
        {
            curr = next;
            next = (Unit*)(next->_M_client_data + aligned_uint_size);
            curr->_M_free_list_link = next;
            alloc_units_size--;
        }
        curr = next;
        curr->_M_free_list_link = 0;
        return unit;
    }

    //! 每次分配一大块内存, 防止多次分配小内存块带来的内存碎片
    //! 进行分配操作时, 根据具体环境决定是否加锁
    //! 我们假定要分配的内存满足内存对齐要求
    //! Allocates a number of units one-shot. num may be reduced
    //! if it is inconvenient to allocate the requested number.
    //! must  locked if threads enabled
    static char* alloc_units(size_t aligned_uint_size, int& alloc_units_size)
    {
        char* result;
        size_t remainig_bytes = end_free - start_free;
        size_t total_alloc_size = alloc_units_size * aligned_uint_size;

        // can alloc as required
        if (remainig_bytes >= total_alloc_size)
        {
            result = start_free;
            start_free += total_alloc_size;
            return (result);
        }

        // can alloc at least one
        if (remainig_bytes >= aligned_uint_size)
        {
            alloc_units_size = (int)(remainig_bytes / aligned_uint_size);
            total_alloc_size = aligned_uint_size*alloc_units_size;
            result = start_free;
            start_free += total_alloc_size;
            return result;
        }

        /* cannot even alloc one, start to shunk the pool */
        Unit* GECO_VOLATILE* my_free_list;
        size_t byte2alloc = 2 * total_alloc_size + round_up(heap_size >> 4);

        // Try to make use of the left-over piece.
        if (remainig_bytes > 0)
        {
            my_free_list = free_list + freelist_index(remainig_bytes);
            ((Unit*)start_free)->_M_free_list_link = *my_free_list;
            *my_free_list = ((Unit*)start_free);
        }

        start_free = (char*)malloc(byte2alloc);
        //printf("start_free == %lu\n", (ptrdiff_t)start_free);

        // 分配失败, 搜索原来已经分配的内存块, 看是否有大于等于当前请求的内存块
        if (start_free == NULL)
        {
            // Try to make do with what we have.  That can't
            // hurt.  We do not try smaller requests, since that tends
            // to result in disaster on multi-process machines.
            for (size_t newsize = aligned_uint_size;
                newsize <= MAX_BYTES;
                newsize += ALIGN)
            {
                my_free_list = free_list + freelist_index(newsize);
                Unit* unit = *my_free_list;
                if (unit != NULL)
                {
                    *my_free_list = unit->_M_free_list_link;
                    start_free = unit->_M_client_data;
                    end_free = start_free + newsize;
                    // Any leftover piece will eventually make it to the right free list.
                    return alloc_units(aligned_uint_size, alloc_units_size);
                }
            }

            // no even one avaiable unit poll completely empty
            // This should either throw an exception or remedy the situation.
            // Thus we assume it succeeded.
            end_free = 0;
            start_free = (char*)malloc_allocator::allocate(byte2alloc);
        }

        //we get memory now 
        heap_size += byte2alloc;
        end_free = start_free + byte2alloc;

        //store it to polls for memory release when prgram exits
        if (pool_num < NFREELISTS)
        {
            pools_[pool_num] = start_free;
            pool_num++;
        }
        else
        {
            fprintf(stderr, "allocate()::pool_num >= NFREELISTS at line 608\n");
            printf("allocate()::pool_num >= NFREELISTS at line 608\n");
            abort();
        }
        // try to alloc again
        return alloc_units(aligned_uint_size, alloc_units_size);
    }

    public:
    static void* allocate(size_t size)
    {
        if (size == 0) return NULL;

        // use maalocator if bigger than MAX_BYTES
        if (size > MAX_BYTES)
        {
            return malloc_allocator::allocate(size);
        }

        /*find an avaiable free list*/
        Unit* GECO_VOLATILE* my_free_list = free_list + freelist_index(size);

#if defined(GECO_USE_STL_THREADS) && !defined(GECO_NO_THREADS)
        GECO_ALLOC_LOCK;
#endif

        void* __RESTRICT result = (void*)(*my_free_list);
        if (result == 0)
        {
            // 如果是第一次使用这个容量的链表, 则分配此链表需要的内存
            // 如果不是, 则判断内存吃容量, 不够则分配
            // not find, refill more free lists to be used
            size = round_up(size);
            result = build_unit_list(size);
        }
        *my_free_list = ((Unit*)result)->_M_free_list_link;

#if defined(GECO_USE_STL_THREADS) && !defined(GECO_NO_THREADS)
        GECO_ALLOC_UNLOCK;
#endif

        return (result);
    }

    //! p may not be 0
    static void deallocate(void* pointer, size_t size)
    {
        if (pointer == NULL)
            return;

        if (size > MAX_BYTES)
        {
            malloc_allocator::deallocate(pointer, size);
            return;
        }
        Unit* GECO_VOLATILE* my_free_list = free_list + freelist_index(size);
        Unit* unit = (Unit*)pointer;
#if defined(GECO_USE_STL_THREADS) && !defined(GECO_NO_THREADS)
        GECO_ALLOC_LOCK;
#endif
        unit->_M_free_list_link = *my_free_list;
        *my_free_list = unit;
#if defined(GECO_USE_STL_THREADS) && !defined(GECO_NO_THREADS)
        GECO_ALLOC_UNLOCK;
#endif
    }

    static void* reallocate(void* unit_pointer, size_t old_unit_size, size_t new_unit_size)
    {
        // 如果old_size和new_size均大于__MAX_BYTES, 则直接调用realloc()
        // 因为这部分内存不是经过内存池分配的
        if (old_unit_size > MAX_BYTES && new_unit_size > MAX_BYTES)
        {
            return (malloc_allocator::reallocate(unit_pointer, old_unit_size, new_unit_size));
        }

        // 如果ROUND_UP(old_sz) == ROUND_UP(new_sz), 内存大小没变化, 不进行重新分配
        if (round_up(old_unit_size) == round_up(new_unit_size))
        {
            return unit_pointer;
        }

        // 进行重新分配并拷贝数据
        void* result = allocate(new_unit_size);
        size_t cpyszie = new_unit_size > old_unit_size ? old_unit_size : new_unit_size;
        memcpy(result, unit_pointer, cpyszie);
        deallocate(unit_pointer, old_unit_size);
        return (result);
    }

    static void destroy()
    {
        memset((void*)free_list, 0, NFREELISTS);
        start_free = end_free = 0;
        heap_size = 0;

        for (int i = 0; i < pool_num; i++)
        {
            if (pools_[i] != NULL)
            {
                free(pools_[i]);
                pools_[i] = NULL;
            }
        }
        pool_num = 0;
    }

    bool operator==(const default_alloc&)
    {
        return true;
    }

    bool operator!=(const default_alloc&)
    {
        return false;
    }
};

typedef  default_alloc<GECO_ALLOC_USES_THREAD, 0> alloc;
typedef  default_alloc<false, 0> single_client_alloc;

// INITIALIZE MEMBERS
#ifdef GECO_USE_STL_THREADS
template <bool __threads, int __inst>
locker_t default_alloc<__threads, __inst>::_S_node_allocator_lock;
#endif

template<bool threads, int inst>
char* default_alloc<threads, inst>::start_free = 0;
template<bool threads, int inst>
char* default_alloc<threads, inst>::end_free = 0;
template<bool threads, int inst>
size_t default_alloc<threads, inst>::heap_size = 0;
template<bool threads, int inst>
void* default_alloc<threads, inst>::pools_[NFREELISTS] = { 0 };
template<bool threads, int inst>
size_t default_alloc<threads, inst>::pool_num = 0;

// The 16 zeros are necessary to make version 4.1 of the SunPro
// compiler happy.  Otherwise it appears to allocate too little
// space for the array.
template<bool threads, int inst>
Unit* GECO_VOLATILE
default_alloc<threads, inst>::free_list[NFREELISTS] = { 0 };
#endif  /* ! GECO__USE_MALLOC */

// This implements allocators as specified in the C++ standard.
//
// Note that standard-conforming allocators use many language features
// that are not yet widely implemented.  In particular, they rely on
// member templates, partial specialization, partial ordering of function
// templates, the typename keyword, and the use of the template keyword
// to refer to a template member of a dependent type.
#ifdef GECO_USE_STD_ALLOCATORS
template <class val_type>
struct allocator
{
    typedef alloc Alloc;
    typedef single_client_alloc SAlloc;

    typedef size_t size_type;
    typedef ptrdiff_t difference_type;
    typedef val_type* pointer;
    typedef const val_type* const_pointer;
    typedef val_type& reference;
    typedef const val_type& const_reference;
    typedef val_type value_type;

    template <class valtype>
    struct rebind
    {
        typedef allocator<valtype> other;
    };

    allocator() GECO_NOTHROW
    {} //default ctor
    allocator(const allocator&) GECO_NOTHROW
    {} //cpy ctor
    template <class _Tp1>
    allocator(const allocator<_Tp1>&) GECO_NOTHROW
    {} //tpl  cpy-ctor
    ~allocator() GECO_NOTHROW
    {} //dtor

    pointer address(reference x) const
    {
        return &x;
    }
    const_pointer address(const_reference x) const
    {
        return &x;
    }

    //! alloc_size is permitted to be 0.
    //! C++ standard says nothing about what the return value is when alloc_size = 0.
    pointer allocate(size_type alloc_size, const void* = 0)
    {
        return alloc_size == 0 ?
        NULL : (pointer)(Alloc::allocate(alloc_size*sizeof(value_type)));
    }

    //! __p is not permitted to be a null pointer.
    void deallocate(pointer ptr, size_type alloc_size)
    {
        Alloc::deallocate(ptr, alloc_size * sizeof(value_type));
    }

    size_type max_size() const GECO_NOTHROW
    {
        return size_t(-1) / sizeof(value_type);
    }

        void construct(pointer ptr, const value_type& val)
    {
        new (ptr)value_type(val);
    }

    void destroy(pointer ptr)
    {
        ptr->~value_type();
    }
};

// full specialization
GECO_TEMPLATE_NULL
struct allocator<void>
{
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;
    typedef void* pointer;
    typedef const void* const_pointer;
    typedef void value_type;

    template <class val_type>
    struct rebind
    {
        typedef allocator<val_type> other;
    };
};

template <class _T1, class _T2>
inline bool operator==(const allocator<_T1>&, const allocator<_T2>&)
{
    return true;
}

template <class _T1, class _T2>
inline bool operator!=(const allocator<_T1>&, const allocator<_T2>&)
{
    return false;
}

// the first kind of Allocator adaptor to turn an SGI-style allocator (e.g. alloc, malloc_alloc)
// into a standard-conforming allocator.   Note that this adaptor does
// *not* assume that all objects of the underlying alloc class are
// identical, nor does it assume that all of the underlying alloc's
// member functions are static member functions.  Note, also, that
// alloc_adaptor<_Tp, alloc> is essentially the same thing as allocator<_Tp>.
template <class val_type, class Alloc>
struct alloc_adaptor_0
{
    Alloc allocator_;

    typedef size_t size_type;
    typedef ptrdiff_t difference_type;
    typedef val_type* pointer;
    typedef const val_type* const_pointer;
    typedef val_type& reference;
    typedef const val_type& const_reference;
    typedef val_type value_type;

    template <class valtype>
    struct rebind
    {
        typedef allocator<valtype> other;
    };

    alloc_adaptor_0() GECO_NOTHROW
    {}
    alloc_adaptor_0(const alloc_adaptor_0& __a) GECO_NOTHROW
    : allocator_(__a.allocator_)
    {}
    template <class _Tp1>
    alloc_adaptor_0(const alloc_adaptor_0<val_type, Alloc>& __a) GECO_NOTHROW
        : alloc_adaptor_0(__a.allocator_)
    {}
    ~alloc_adaptor_0() GECO_NOTHROW
    {}

    pointer address(reference x) const
    {
        return &x;
    }
    const_pointer address(const_reference x) const
    {
        return &x;
    }

    //! alloc_size is permitted to be 0.
    //! C++ standard says nothing about what the return value is when alloc_size = 0.
    pointer allocate(size_type alloc_size, const void* = 0)
    {
        return alloc_size == 0 ?
        NULL : (pointer)(allocator_.allocate(alloc_size*sizeof(value_type)));
    }

    //! __p is not permitted to be a null pointer.
    void deallocate(pointer ptr, size_type alloc_size)
    {
        allocator_.deallocate(ptr, alloc_size * sizeof(value_type));
    }

    size_type max_size() const GECO_NOTHROW
    {
        return size_t(-1) / sizeof(value_type);
    }

        void construct(pointer ptr, const value_type& val)
    {
        new (ptr)value_type(val);
    }

    void destroy(pointer ptr)
    {
        ptr->~value_type();
    }
};

template <class Alloc>
class alloc_adaptor_0<void, Alloc>
{
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;
    typedef void* pointer;
    typedef const void* const_pointer;
    typedef void value_type;

    template <class valtype> struct rebind
    {
        typedef alloc_adaptor_0<valtype, Alloc> other;
    };
};

// the second kind of  allocator adaptor.  This serves two
// purposes.  First, make it possible to write containers that can use
// either SGI-style allocators or standard-conforming allocator.
// Second, provide a mechanism so that containers can query whether or
// not the allocator has distinct instances.  If not, the container
// can avoid wasting a word of memory to store an empty object.

// This adaptor uses partial specialization.  The general case of
// _Alloc_traits<_Tp, _Alloc> assumes that _Alloc is a
// standard-conforming allocator, possibly with non-equal instances
// and non-static members.  (It still behaves correctly even if _Alloc
// has static member and if all instances are equal.  Refinements
// affect performance, not correctness.)

// There are always two members: allocator_type, which is a standard-
// conforming allocator type for allocating objects of type _Tp, and
// _S_instanceless, a static const member of type bool.  If
// _S_instanceless is true, this means that there is no difference
// between any two instances of type allocator_type.  Furthermore, if
// _S_instanceless is true, then _Alloc_traits has one additional
// member: _Alloc_type.  This type encapsulates allocation and
// deallocation of objects of type _Tp through a static interface; it
// has two member functions, whose signatures are
//    static _Tp* allocate(size_t)
//    static void deallocate(_Tp*, size_t)

// 1) General version.
template <class valtype, class Alloc>
struct alloc_adaptor_1
{
    static const bool instanceless = false;
    //typedef  GECO_TEMPLATE Alloc::rebind<valtype>::other allocator_type;
};
template <class valtype, class Alloc>
const bool alloc_adaptor_1<valtype, Alloc>::instanceless;

// 2) Version for the allocator
// internallu typedef  'alloc'  Alloc , either malloc_alloc or default_alloc
// based on macro define GECO_USE_MALLOC
template <class valtype, class valtype1>
struct alloc_adaptor_1<valtype, allocator<valtype1>>
{
    static const bool instanceless = true;
    typedef simple_alloc<valtype, alloc> simple_alloc_type;
    typedef allocator<valtype> allocator_type;
};

// 3) Versions for the predefined SGI-style allocators.
// 1) for malloc_alloc
template <class valtype, int inst>
struct alloc_adaptor_1<valtype, malloc_alloc<inst>>
{
    static const bool instanceless = true;
    typedef simple_alloc<valtype, malloc_alloc<inst>> simple_alloc_type;
    typedef alloc_adaptor_0<valtype, malloc_alloc<inst>> allocator_type;
};
// 2) for default_alloc
template <class _Tp, bool __threads, int __inst>
struct alloc_adaptor_1<_Tp, default_alloc<__threads, __inst> >
{
    static const bool _S_instanceless = true;
    typedef simple_alloc<_Tp, default_alloc<__threads, __inst> >
        simple_alloc_type;
    typedef alloc_adaptor_0<_Tp, default_alloc<__threads, __inst> >
        allocator_type;
};
template <class _Tp, class _Alloc>
struct alloc_adaptor_1<_Tp, debug_alloc<_Alloc> >
{
    static const bool _S_instanceless = true;
    typedef simple_alloc<_Tp, debug_alloc<_Alloc> > simple_alloc_type;
    typedef alloc_adaptor_0<_Tp, debug_alloc<_Alloc> > allocator_type;
};

// 4) Versions for the alloc_adaptor_0 adaptor used with the predefined
// SGI-style allocators.
template <class _Tp, class _Tp1, int __inst>
struct alloc_adaptor_1<_Tp,
    alloc_adaptor_0<_Tp1, malloc_alloc<__inst> > >
{
    static const bool _S_instanceless = true;
    typedef simple_alloc<_Tp, malloc_alloc<__inst> > _Alloc_type;
    typedef alloc_adaptor_0<_Tp, malloc_alloc<__inst> > allocator_type;
};

template <class _Tp, class _Tp1, bool __thr, int __inst>
struct alloc_adaptor_1<_Tp,
    alloc_adaptor_0<_Tp1,
    default_alloc<__thr, __inst> > >
{
    static const bool _S_instanceless = true;
    typedef simple_alloc<_Tp, default_alloc<__thr, __inst> >
        _Alloc_type;
    typedef alloc_adaptor_0<_Tp, default_alloc<__thr, __inst> >
        allocator_type;
};

template <class _Tp, class _Tp1, class _Alloc>
struct alloc_adaptor_1<_Tp, alloc_adaptor_0<_Tp1, debug_alloc<_Alloc> > >
{
    static const bool _S_instanceless = true;
    typedef simple_alloc<_Tp, debug_alloc<_Alloc> > _Alloc_type;
    typedef alloc_adaptor_0<_Tp, debug_alloc<_Alloc> > allocator_type;
};
#endif 

#if defined(__sgi) && !defined(__GNUC__) && (_MIPS_SIM != _MIPS_SIM_ABI32)
#pragma reset woff 1174
#endif

GECO_END_NAMESPACE
#undef __PRIVATE
#endif /* INCLUDE_GECO_DS_MALLOC_H_ */
