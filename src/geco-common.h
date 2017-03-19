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

 /*
 The operating system, must be one of: (Q_OS_x)

 MACX   - Mac OS X
 MAC9   - Mac OS 9
 MSDOS  - MS-DOS and Windows
 OS2    - OS/2
 OS2EMX - XFree86 on OS/2 (not PM)
 WIN32  - Win32 (Windows 95/98/ME and Windows NT/2000/XP)
 CYGWIN - Cygwin
 SOLARIS    - Sun Solaris
 HPUX   - HP-UX
 ULTRIX - DEC Ultrix
 LINUX  - Linux
 FREEBSD    - FreeBSD
 NETBSD - NetBSD
 OPENBSD    - OpenBSD
 BSDI   - BSD/OS
 IRIX   - SGI Irix
 OSF    - HP Tru64 UNIX
 SCO    - SCO OpenServer 5
 UNIXWARE   - UnixWare 7, Open UNIX 8
 AIX    - AIX
 HURD   - GNU Hurd
 DGUX   - DG/UX
 RELIANT    - Reliant UNIX
 DYNIX  - DYNIX/ptx
 QNX    - QNX
 QNX6   - QNX RTP 6.1
 LYNX   - LynxOS
 BSD4   - Any BSD 4.4 system
 UNIX   - Any UNIX BSD/SYSV system
 */

#if defined(__APPLE__) && defined(__GNUC__)
#  define Q_OS_MACX
#elif defined(__MACOSX__)
#  define Q_OS_MACX
#elif defined(macintosh)
#  define Q_OS_MAC9
#elif defined(__CYGWIN__)
#  define Q_OS_CYGWIN
#elif defined(MSDOS) || defined(_MSDOS)
#  define Q_OS_MSDOS
#elif defined(__OS2__)
#  if defined(__EMX__)
#    define Q_OS_OS2EMX
#  else
#    define Q_OS_OS2
#  endif
#elif !defined(SAG_COM) && (defined(WIN64) || defined(_WIN64) || defined(__WIN64__))
#  define Q_OS_WIN32
#  define Q_OS_WIN64
#elif !defined(SAG_COM) && (defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__))
#  define Q_OS_WIN32
#elif defined(__MWERKS__) && defined(__INTEL__)
#  define Q_OS_WIN32
#elif defined(__sun) || defined(sun)
#  define Q_OS_SOLARIS
#elif defined(hpux) || defined(__hpux)
#  define Q_OS_HPUX
#elif defined(__ultrix) || defined(ultrix)
#  define Q_OS_ULTRIX
#elif defined(sinix)
#  define Q_OS_RELIANT
#elif defined(__linux__) || defined(__linux)
#  define Q_OS_LINUX
#elif defined(__FreeBSD__)
#  define Q_OS_FREEBSD
#  define Q_OS_BSD4
#elif defined(__NetBSD__)
#  define Q_OS_NETBSD
#  define Q_OS_BSD4
#elif defined(__OpenBSD__)
#  define Q_OS_OPENBSD
#  define Q_OS_BSD4
#elif defined(__bsdi__)
#  define Q_OS_BSDI
#  define Q_OS_BSD4
#elif defined(__sgi)
#  define Q_OS_IRIX
#elif defined(__osf__)
#  define Q_OS_OSF
#elif defined(_AIX)
#  define Q_OS_AIX
#elif defined(__Lynx__)
#  define Q_OS_LYNX
#elif defined(__GNU_HURD__)
#  define Q_OS_HURD
#elif defined(__DGUX__)
#  define Q_OS_DGUX
#elif defined(__QNXNTO__)
#  define Q_OS_QNX6
#elif defined(__QNX__)
#  define Q_OS_QNX
#elif defined(_SEQUENT_)
#  define Q_OS_DYNIX
#elif defined(_SCO_DS)                   /* SCO OpenServer 5 + GCC */
#  define Q_OS_SCO
#elif defined(__USLC__)                  /* all SCO platforms + UDK or OUDK */
#  define Q_OS_UNIXWARE
#  define Q_OS_UNIXWARE7
#elif defined(__svr4__) && defined(i386) /* Open UNIX 8 + GCC */
#  define Q_OS_UNIXWARE
#  define Q_OS_UNIXWARE7
#else
#  error "Qt has not been ported to this OS - talk to qt-bugs@trolltech.com"
#endif

#if defined(Q_OS_MAC9) || defined(Q_OS_MACX)
#  define Q_OS_MAC
#endif

#if defined(Q_OS_MAC9) || defined(Q_OS_MSDOS) || defined(Q_OS_OS2) || defined(Q_OS_WIN32) || defined(Q_OS_WIN64)
#  undef Q_OS_UNIX
#elif !defined(Q_OS_UNIX)
#  define Q_OS_UNIX
#endif

/*-------------- basic type defs -------------*/
/// This type is an unsigned character.
typedef unsigned char uchar;
/// This type is an unsigned short.
typedef unsigned short ushort;
/// This type is an unsigned integer.
typedef unsigned int uint;
/// This type is an unsigned longer.
typedef unsigned long ulong;

#if defined( PLAYSTATION3 )
typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef intptr_t intptr;
typedef uintptr_t uintptr;
#define PRId64 "lld"
#define PRIu64 "llu"
#define PRIx64 "llx"
#define PRIX64 "llX"
#define PRIu32 "lu"
#define PRId32 "ld"
#else
#ifdef _WIN32
typedef __int8 int8;
typedef unsigned __int8 uint8;
typedef __int16 int16;
typedef unsigned __int16 uint16;
typedef __int32 int32;
typedef unsigned __int32 uint32;
typedef __int64 int64;
typedef unsigned __int64 uint64;
/// This type is an integer with the size of a pointer.
//typedef INT_PTR intptr;
/// This type is an unsigned integer with the size of a pointer.
//typedef UINT_PTR uintptr;
#define PRId64 "lld"
#define PRIu64 "llu"
#define PRIx64 "llx"
#define PRIX64 "llX"
#define PRIu32 "lu"
#define PRId32 "ld"
#define GECO_FAST_CALL __fastcall
#else //unix or linux
#define GECO_FAST_CALL
#include <stdint.h>
/// This type is an integer with a size of 8 bits.
typedef int8_t int8;
/// This type is an unsigned integer with a size of 8 bits.
typedef uint8_t uint8;
/// This type is an integer with a size of 16 bits.
typedef int16_t int16;
/// This type is an unsigned integer with a size of 16 bits.
typedef uint16_t uint16;
/// This type is an integer with a size of 32 bits.
typedef int32_t int32;
/// This type is an unsigned integer with a size of 32 bits.
typedef uint32_t uint32;
/// This type is an integer with a size of 64 bits.
typedef int64_t int64;
/// This type is an unsigned integer with a size of 64 bits.
typedef uint64_t uint64;
#ifdef _LP64
typedef int64 intptr;
typedef uint64 uintptr;
#define PRId64 "ld"
#define PRIu64 "lu"
#define PRIx64 "lx"
#define PRIX64 "lX"
#else
typedef int32 intptr;
typedef uint32 uintptr;
#define PRId64 "lld"
#define PRIu64 "llu"
#define PRIx64 "llx"
#define PRIX64 "llX"
#endif
#ifndef PRId32
#define PRId32 "zd"
#endif
#ifndef PRIu32
#define PRIu32 "zu"
#endif
#endif

#endif

#endif//end
