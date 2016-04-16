/*
 * Copyright (c) 2016
 * Geco Gaming Company
 *
 * Permission to use, copy, modify, distribute and sell this software
 * and its documentation for GECO purpose is hereby granted without fee,
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation. Geco Gaming makes no
 * representations about the suitability of this software for GECO
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 */

#ifndef  __INCLUDE_GECO_BASIC_TYPE_DEFS_H
#define __INCLUDE_GECO_BASIC_TYPE_DEFS_H

#if defined(__GNUC__) || defined(__GCCXML__) || defined(__SNC__) || defined(__S3E__)
#include <stdint.h>
typedef int8_t Int8;
typedef uint8_t UInt8;
typedef int16_t Int16;
typedef uint16_t UInt16;
typedef int32_t Int32;
typedef uint32_t UInt32;
typedef int64_t Int64;
typedef uint64_t UInt64;
#else
typedef char Int8;
typedef unsigned char UInt8;
typedef short Int16;
typedef unsigned short UInt16;
typedef __int32 Int32;
typedef unsigned __int32 UInt32;
#   if defined(_MSC_VER) && _MSC_VER < 1300
typedef unsigned __int64 UInt64;
typedef signed __int64 Int64;
#  else
typedef long long Int64;
typedef unsigned long long UInt64;
#  endif
#endif

#endif//end
