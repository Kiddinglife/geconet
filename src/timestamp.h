/*
 * Geco Gaming Company
 * All Rights Reserved.
 * Copyright (c)  2016 GECOEngine.
 *
 * GECOEngine is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GECOEngine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with KBEngine.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// created on 28-June-2016 by Jackie Zhang
#ifndef TIMESTAMP_HPP
#define TIMESTAMP_HPP

#include "geco-common.h"

// Indicates whether or not to use a call to RDTSC (Read Time Stamp Counter)
// to calculate timestamp. The benefit of using this is that it is fast and
// accurate, returning actual clock ticks. The downside is that this does not
// work well with CPUs that use Speedstep technology to vary their clock speeds.
//
// Alternate Linux implementation uses gettimeofday. In rough tests, this can
// be between 20 and 600 times slower than using RDTSC. Also, there is a problem
// under 2.4 kernels where two consecutive calls to gettimeofday may actually
// return a result that goes backwards.
#ifndef _XBOX360
#endif // _XBOX360

//#define GECO_USE_RDTSC

#if defined(__unix__) || defined(__linux__)
/**　This function returns the processor's (real-time) clock cycle counter.
 *　Read Time-Stamp Counterloads current value of processor's timestamp counter into EDX:EAX
 */
inline uint64 gettimestamp()
{
	uint32 rethi, retlo;
	__asm__ __volatile__(
			"rdtsc\n":
			"=d" (rethi),
			"=a" (retlo)
	);
	return uint64(rethi) << 32 | retlo;
}
#elif defined(_WIN32)
#ifdef GECO_USE_RDTSC
#pragma warning (push)
#pragma warning (disable: 4035)
#ifdef _AMD64_
/* remember myself that i should use geco:debugging namespace in timestamp.cpp,
 * othwerwise will cause c3018 error */
extern "C" uint64 _fastcall asm_time();
#define gettimestamp asm_time
#else
inline uint64 gettimestamp()
{
	//__asm rdtsc
	// refers to this link http://blog.csdn.net/rabbit729/article/details/3849932
	// 因为RDTSC不被C++的内嵌汇编器直接支持，所以我们要用_emit伪指令直接嵌入该指令的机器码形式0X0F、0X31，如下：
	__asm _emit 0x0F
	__asm _emit 0x31
}
#endif
#pragma warning (pop)
#else // GECO_USE_RDTSC
#ifdef _XBOX360
#include <xtl.h>
#else // _XBOX360
#include <windows.h>
#endif // _XBOX360
inline uint64 gettimestamp()
{
	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);
	return counter.QuadPart;
}
inline uint64 gettimeofday() //us
{
	static uint64 curTime;
	static LARGE_INTEGER Peral;
	static LARGE_INTEGER yo1;
	static uint64 quotient, remainder;
	QueryPerformanceFrequency(&yo1);
	QueryPerformanceCounter(&Peral);
	quotient = ((Peral.QuadPart) / yo1.QuadPart);
	remainder = ((Peral.QuadPart) % yo1.QuadPart);
	curTime = (uint64)quotient*(uint64)1000000 + (remainder * 1000000 / yo1.QuadPart);
	return curTime;
}
#endif
#elif defined( PLAYSTATION3 )
inline uint64 gettimestamp()
{
	uint64 ts;
	SYS_TIMEBASE_GET(ts);
	return ts;
}
#else
#error Unsupported platform!
#endif

/**
 *	This function tells you how many there are in a second. It caches its reply
 *	after being called for the first time, however that call may take some time.
 */
uint64 stamps_per_sec();
/**
 *	This function tells you how many there are in a second as a double precision
 *	floating point value. It caches its reply after being called for the first
 *	time, however that call may take some time.
 */
double stamps_per_sec_double();

uint64 stamps_per_ms();
double stamps_per_ms_double();

uint64 stamps_per_us();
double stamps_per_us_double();

double stamps2sec(uint64 stamps);
/** This class stores a value in stamps but has access functions in seconds.*/
struct time_stamp_t
{
		uint64 stamp_;

		time_stamp_t(uint64 stamps = 0) :
				stamp_(stamps)
		{
		}
		operator uint64 &()
		{
			return stamp_;
		}
		operator uint64() const
		{
			return stamp_;
		}

		/*This method returns this timestamp in seconds.*/
		double inSecs() const
		{
			return toSecs(stamp_);
		}
		/*This method sets this timestamp from seconds.*/
		void setInSecs(double seconds)
		{
			stamp_ = fromSecs(seconds);
		}
		/*This method returns the number of stamps from this TimeStamp to now.*/
		time_stamp_t ageInStamps() const
		{
			return gettimestamp() - stamp_;
		}
		/*This method returns the number of seconds from this TimeStamp to now.*/
		double agesInSec() const
		{
			return toSecs(this->ageInStamps());
		}
		/*This static method converts a timestamp value into seconds.*/
		static double toSecs(uint64 stamps)
		{
			return double(stamps) / stamps_per_sec_double();
		}
		/*This static method converts seconds into timestamps.*/
		static time_stamp_t fromSecs(double seconds);

};

#endif
