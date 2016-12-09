#ifndef WHEEL_TIMER_BIT_OPS_H_
#define WHEEL_TIMER_BIT_OPS_H_

#define TIMEOUT_DISABLE_BUILTIN_BITOPS

#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>     /* _BitScanForward, _BitScanReverse */
#endif

///* First define ctz and clz functions; these are compiler-dependent if
// * you want them to be fast. */
//#if defined(__GNUC__) && !defined(TIMEOUT_DISABLE_GNUC_BITOPS)
//
// /* On GCC and clang and some others, we can use __builtin functions. They
//  * are not defined for n==0, but timeout.s never calls them with n==0. */
//
//#define ctz64(n) __builtin_ctzll(n)
//#define clz64(n) __builtin_clzll(n)
//#if LONG_BITS == 32
//#define ctz32(n) __builtin_ctzl(n)
//#define clz32(n) __builtin_clzl(n)
//#else
//#define ctz32(n) __builtin_ctz(n)
//#define clz32(n) __builtin_clz(n)
//#endif
//
//#elif defined(_MSC_VER) && !defined(TIMEOUT_DISABLE_MSVC_BITOPS)
//
// /* On MSVC, we have these handy functions. We can ignore their return
//  * values, since we will never supply val == 0. */
//static __inline int ctz32(unsigned long val)
//{
//
//	unsigned long zeros = 0;
//	_BitScanForward(&zeros, val);
//	return zeros;
//}
//static __inline int clz32(unsigned long val)
//{
//	unsigned long zeros = 0;
//	_BitScanReverse(&zeros, val);
//	return zeros;
//}
//#ifdef _WIN64
///* According to the documentation, these only exist on Win64. */
//static __inline int ctz64(uint64_t val)
//{
//	unsigned long zeros = 0;
//	_BitScanForward64(&zeros, val);
//	return zeros;
//}
//static __inline int clz64(uint64_t val)
//{
//	unsigned long zeros = 0;
//	_BitScanReverse64(&zeros, val);
//	return zeros;
//}
//#else
//static __inline int ctz64(uint64_t val)
//{
//	uint32_t lo = (uint32_t)val;
//	uint32_t hi = (uint32_t)(val >> 32);
//	return lo ? ctz32(lo) : 32 + ctz32(hi);
//}
//static __inline int clz64(uint64_t val)
//{
//	uint32_t lo = (uint32_t)val;
//	uint32_t hi = (uint32_t)(val >> 32);
//	return hi ? clz32(hi) : 32 + clz32(lo);
//}
//#endif
//
///* End of MSVC case. */
//
//#else
//
// /* TODO: There are more clever ways to do this in the generic case. */
//
//
//#define process_(one, cz_bits, bits)					\
//	if (x < ( one << (cz_bits - bits))) { rv += bits; x <<= bits; }
//
//#define process64(bits) process_((UINT64_C(1)), 64, (bits))
//static inline int clz64(uint64_t x)
//{
//	int rv = 0;
//
//	process64(32);
//	process64(16);
//	process64(8);
//	process64(4);
//	process64(2);
//	process64(1);
//	return rv;
//}
//#define process32(bits) process_((UINT32_C(1)), 32, (bits))
//static inline int clz32(uint32_t x)
//{
//	int rv = 0;
//
//	process32(16);
//	process32(8);
//	process32(4);
//	process32(2);
//	process32(1);
//	return rv;
//}
//
//#undef process_
//#undef process32
//#undef process64
//#define process_(one, bits)						\
//	if ((x & ((one << (bits))-1)) == 0) { rv += bits; x >>= bits; }
//
//#define process64(bits) process_((UINT64_C(1)), bits)
//static inline int ctz64(uint64_t x)
//{
//	int rv = 0;
//
//	process64(32);
//	process64(16);
//	process64(8);
//	process64(4);
//	process64(2);
//	process64(1);
//	return rv;
//}
//
//#define process32(bits) process_((UINT32_C(1)), bits)
//static inline int ctz32(uint32_t x)
//{
//	int rv = 0;
//
//	process32(16);
//	process32(8);
//	process32(4);
//	process32(2);
//	process32(1);
//	return rv;
//}
//
//#undef process32
//#undef process64
//#undef process_
//
///* End of generic case */
//
//#endif /* End of defining ctz */

//- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//	                                      Section:  timer bit operations
//- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
/**
*  @return sizeofbits -1  if given 0, eg uint64_t a = 0, ctz64(a) returns 63
*  other number will be fine
* */
#if defined(__GNUC__) && !defined(TIMEOUT_DISABLE_BUILTIN_BITOPS)
/* First define ctz and clz functions; these are compiler-dependent if
* you want them to be fast. On GCC and clang and some others,
* we can use __builtin functions. They are not defined for n==0,
* but timeout.s never calls them with n==0 */
inline int ctz32(unsigned int val)
{
	return __builtin_ctz(val);
}
inline int clz32(unsigned int val)
{
	return __builtin_clz(val);
}
inline int ctz64(uint64_t val)
{
	return __builtin_ctzll(val);
}
inline int clz64(uint64_t val)
{
	return __builtin_clzll(val);
}
#elif defined(_MSC_VER) && !defined(TIMEOUT_DISABLE_BUILTIN_BITOPS)
/* On MSVC, we have these handy functions. We can ignore their return
* values, since we will never supply val == 0. */
__inline int ctz32(unsigned long val)
{
	unsigned long zeros = 0;
	_BitScanForward(&zeros, val);
	return (int)zeros;
}
__inline int clz32(unsigned long val)
{
	unsigned long zeros = 0;
	_BitScanReverse(&zeros, val);
	return (int)zeros;
}
#ifdef _WIN64
/* According to the documentation, these only exist on Win64. */
__inline int ctz64(uint64_t val)
{
	unsigned long zeros = 0;
	_BitScanForward64(&zeros, val);
	return (int)zeros;
}
__inline int clz64(uint64_t val)
{
	unsigned long zeros = 0;
	_BitScanReverse64(&zeros, val);
	return (int)zeros;
}
#else
__inline int ctz64(uint64_t val)
{
	uint32_t lo = (uint32_t)val;
	uint32_t hi = (uint32_t)(val >> 32);
	return lo ? ctz32(lo) : 32 + ctz32(hi);
}
__inline int clz64(uint64_t val)
{
	uint32_t lo = (uint32_t)val;
	uint32_t hi = (uint32_t)(val >> 32);
	return hi ? clz32(hi) : 32 + clz32(lo);
}
#endif
#else
/*we have to impl these functions by ourselves*/
/* uint64_t will take 8 times assignment to be reversed */

inline void reverse(unsigned char *src, const unsigned int length)
{
	unsigned char temp;
	for (unsigned int i = 0; i < (length >> 1); i++)
	{
		temp = src[i];
		src[i] = src[length - i - 1];
		src[length - i - 1] = temp;
	}
}
inline static int get_leading_zeros_size(char x)
{
	return get_leading_zeros_size((unsigned char)x);
}
inline static int get_leading_zeros_size(unsigned char x)
{
	// x = 0000 0010, n = 8,
	// y = x >>4 = 0000 0000
	// y = x >>2 = 0000 0000
	// y = x >>1 = 0000 0001 != 0 -> return 8-2 = 6

	// x = 0100 0000, n = 8,
	// y = x >>4 = 0000 0100 != 0 -> n = 4, x = 0000 0100
	// y = x >>2 = 0000 0001 != 0 -> n = 2, x = 0000 0001
	// y = x >>1 = 0000 0000 != 0 -> return 2-1 = 1

	unsigned char y;
	int n;

	n = 8;
	y = x >> 4;
	if (y != 0)
	{
		n = n - 4;
		x = y;
	}
	y = x >> 2;
	if (y != 0)
	{
		n = n - 2;
		x = y;
	}
	y = x >> 1;
	if (y != 0)
		return (int)(n - 2);
	return (int)(n - 1);
}
inline static int get_trailing_zeros_size(unsigned char x)
{
	// x = 0000 1000,
	// y = x << 4 = 1000 0000 != 0 -> n = 4, x = 1000 0000
	// y = x <<2 = 0000 0000
	// y = x <<1 = 0000 0000 == 0 -> return 4-1 = 3
	// x = 0000 0010,
	// y = x << 4 = 0010 0000 != 0 -> n = 4, x = 0010 0000
	// y = x <<2 = 1000 0000 != 0 -> n = 2
	// y = x <<1 = 0000 0000 == 0 -> return 2-1 = 1
	// x = 0010 0000,
	// y = x << 4 = 0000 0000
	// y = x <<2 =  1000 0000 != 0, n = 6, x = 1000 0000
	// y = x <<1 =  0000 0000 != 0 -> n-2 = 8-2 = 6
	unsigned char y;
	int n;

	n = 8;
	y = x << 4;
	if (y != 0)
	{
		n = n - 4;
		x = y;
	}
	y = x << 2;
	if (y != 0)
	{
		n = n - 2;
		x = y;
	}
	y = x << 1;
	if (y != 0)
		return (int)(n - 2);
	return (int)(n - 1);
}
inline static int get_leading_zeros_size(unsigned short x)
{
	unsigned short y;
	int n;

	n = 16;
	y = x >> 8;
	if (y != 0)
	{
		n = n - 8;
		x = y;
	}
	y = x >> 4;
	if (y != 0)
	{
		n = n - 4;
		x = y;
	}
	y = x >> 2;
	if (y != 0)
	{
		n = n - 2;
		x = y;
	}
	y = x >> 1;
	if (y != 0)
		return (int)(n - 2);
	return (int)(n - 1);
}
inline static int get_trailing_zeros_size(unsigned short x)
{
	unsigned short y;
	int n;

	n = 16;
	y = x << 8;
	if (y != 0)
	{
		n = n - 8;
		x = y;
	}
	y = x << 4;
	if (y != 0)
	{
		n = n - 4;
		x = y;
	}
	y = x << 2;
	if (y != 0)
	{
		n = n - 2;
		x = y;
	}
	y = x << 1;
	if (y != 0)
		return (int)(n - 2);
	return (int)(n - 1);
}
inline static int get_leading_zeros_size(short x)
{
	return get_leading_zeros_size((unsigned short)x);
}
inline static int get_leading_zeros_size(unsigned int x)
{
	unsigned int y;
	int n;

	n = 32;
	y = x >> 16;
	if (y != 0)
	{
		n = n - 16;
		x = y;
	}
	y = x >> 8;
	if (y != 0)
	{
		n = n - 8;
		x = y;
	}
	y = x >> 4;
	if (y != 0)
	{
		n = n - 4;
		x = y;
	}
	y = x >> 2;
	if (y != 0)
	{
		n = n - 2;
		x = y;
	}
	y = x >> 1;
	if (y != 0)
		return (int)(n - 2);
	return (int)(n - 1);
}
inline static int get_trailing_zeros_size(unsigned int x)
{
	unsigned int y;
	int n;

	n = 32;
	y = x << 16;
	if (y != 0)
	{
		n = n - 16;
		x = y;
	}
	y = x << 8;
	if (y != 0)
	{
		n = n - 8;
		x = y;
	}
	y = x << 4;
	if (y != 0)
	{
		n = n - 4;
		x = y;
	}
	y = x << 2;
	if (y != 0)
	{
		n = n - 2;
		x = y;
	}
	y = x << 1;
	if (y != 0)
		return (int)(n - 2);
	return (int)(n - 1);
}
inline static int get_leading_zeros_size(int x)
{
	return get_leading_zeros_size((unsigned int)x);
}
inline static int get_leading_zeros_size(uint64_t x)
{
	uint64_t y;
	int n;

	n = 64;
	y = x >> 32;
	if (y != 0)
	{
		n = n - 32;
		x = y;
	}
	y = x >> 16;
	if (y != 0)
	{
		n = n - 16;
		x = y;
	}
	y = x >> 8;
	if (y != 0)
	{
		n = n - 8;
		x = y;
	}
	y = x >> 4;
	if (y != 0)
	{
		n = n - 4;
		x = y;
	}
	y = x >> 2;
	if (y != 0)
	{
		n = n - 2;
		x = y;
	}
	y = x >> 1;
	if (y != 0)
		return (int)(n - 2);
	return (int)(n - 1);
}
inline static int get_trailing_zeros_size(uint64_t x)
{
	// x = 8 = 7 zero chars 1000
	// x = 3 zero char + 1000 ...
	// x = 1 zero char + 1000 ...
	//x = 0000 1000 ...
	// x = 1000 ...
	// x = 00 ...
	uint64_t y;
	int n = 64;

	y = x << 32;
	if (y != 0)
	{
		n -= 32;
		x = y;
	}
	y = x << 16;
	if (y != 0)
	{
		n -= 16;
		x = y;
	}
	y = x << 8;
	if (y != 0)
	{
		n -= 8;
		x = y;
	}
	y = x << 4;
	if (y != 0)
	{
		n -= 4;
		x = y;
	}
	y = x << 2;
	if (y != 0)
	{
		n -= 2;
		x = y;
	}
	y = x << 1;
	if (y != 0)
		return (int)(n - 2);
	return (int)(n - 1);
}
inline static int get_leading_zeros_size(int64_t x)
{
	return get_leading_zeros_size((uint64_t)x);
}
inline int clz32(unsigned int val)
{
	return get_leading_zeros_size(val);
}
inline int ctz32(unsigned int val)
{
	return get_trailing_zeros_size(val);
}
inline int clz64(uint64_t val)
{
	return get_leading_zeros_size(val);
}
inline int ctz64(uint64_t val)
{
	return get_trailing_zeros_size(val);
}
#endif
#endif

