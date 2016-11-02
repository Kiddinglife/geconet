/*
 * globals.cc
 *
 *  Created on: 14 Apr 2016
 *      Author: jakez
 */

#include "geco-net-common.h"
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <ctime>
#include <sys/types.h>
#include <sys/timeb.h>

#ifdef WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

geco_return_enum global_ret_val = geco_return_enum::good;

//++++++++++++++++++ logging ++++++++++++++++++++
static bool globalTrace = true;
static bool fileTrace = false;
static FILE* logfile = 0;
static int noOftracedModules;
static char traced_modules[TRACE_MUDULE_SIZE][70];
static int error_trace_levels[TRACE_MUDULE_SIZE];
static int event_trace_levels[TRACE_MUDULE_SIZE];
static const char* error_loglvls_str[4] =
{ "fatal_error_exit", "major_error_abort", "minor_error", "lwarnning_error" };
static const char* event_loglvls_str[6] =
{ "extevent_unexpected", "extevent", "intevent_important", "intevent", "VERBOSE", "lvverbos" };

void read_trace_levels(void)
{
	int i;
	int ret;
	char filename[100];
	noOftracedModules = 0;

	// this will be relative path  to project dir if you run it by ctrl_F5 in vs studio
	// if you want to run relative path to the exutable, you have to manually click it and run it,
	FILE* fptr = fopen("../../tracelevels.in", "r");
	if (fptr != NULL)
	{
		globalTrace = true;
		for (i = 0; i < TRACE_MUDULE_SIZE; i++)
		{
			ret = fscanf(fptr, "%s%d%d", traced_modules[i], &error_trace_levels[i],
				&event_trace_levels[i]);
			if (ret >= 1)
			{
				if (strcmp(traced_modules[i], "LOGFILE") == 0)
				{
					printf("Logging all errors and events to file ./tmp%d.log\n", (int)getpid());
					fileTrace = true;
					sprintf(filename, "./tmp%d.log", (int)getpid());
					logfile = fopen(filename, "w+");
					return;
				}
			}

			if (ferror(fptr)) abort();

			//if we have less than TRACE_MUDULE_SIZE mudlues to trace, this will break loop
			if (feof(fptr)) break;

			globalTrace = false;
		}
		noOftracedModules = i;
		if (i <= 1) globalTrace = true;
		printf("  globalTrace = %s \n", globalTrace ? "TRUE" : "FALSE");
	}
	else
	{
		globalTrace = true;
	}
	printf("globalTrace '%s', modules size '%d'\n", globalTrace ? "TRUE" : "FALSE",
		noOftracedModules);
	for (i = 0; i < noOftracedModules; i++)
		printf("%20s %2d %2d\n", traced_modules[i], error_trace_levels[i], event_trace_levels[i]);
}

// -1 not found, >0 = module index
static int is_module_traced(const char* modulename)
{
	for (int i = 0; i < TRACE_MUDULE_SIZE; i++)
	{
		if (!strcmp(traced_modules[i], modulename))
		{
			return i;
		}
	}
	return -1;
}

uint get_safe_time_ms(void)
{
	struct timeval cur_tval;
	gettimenow(&cur_tval);
	/* modulo overflows every every 15 days*/
	return ((cur_tval.tv_sec % OVERFLOW_SECS) * 1000 + cur_tval.tv_usec);
}

//int adl_gettime(struct timeval *tv)
int gettimenow(struct timeval *tv)
{
#ifdef WIN32
	struct timeb tb;
	ftime(&tb);
	(tv)->tv_sec = tb.time;
	(tv)->tv_usec = (time_t)tb.millitm * 1000;
	return 0;
#else
	return (gettimeofday(tv, (struct timezone *) NULL));
#endif
}
int gettimenow(struct timeval *tv, struct tm *the_time)
{
	if (gettimenow(tv) > -1)
	{
		time_t tt = (time_t)tv->tv_sec;
		*the_time = *(localtime(&tt));
		return 0;
	}
	else
	{
		return -1;
	}
}
int gettimenow_ms(time_t* ret)
{
	struct timeval now;
	if (gettimenow(&now) > -1)
	{
		EVENTLOG2(EXTERNAL_TRACE, "Time now: %ld sec, %ld usec \n", now.tv_sec, now.tv_usec);
		*ret = ((time_t)now.tv_sec) * 1000 + ((time_t)now.tv_usec) / 1000;
		return 0;
	}
	else
	{
		return -1;
	}
}
int gettimenow_us(time_t* ret)
{
	struct timeval now;
	if (gettimenow(&now) > -1)
	{
		EVENTLOG2(EXTERNAL_TRACE, "Time now: %ld sec, %ld usec \n", now.tv_sec, now.tv_usec);
		*ret = ((time_t)now.tv_sec) * 1000000 + (time_t)now.tv_usec;
		return 0;
	}
	else
	{
		return -1;
	}
}

void sum_time(timeval* a, timeval* b, timeval* result)
{

	result->tv_sec = (a)->tv_sec + (b)->tv_sec;
	result->tv_usec = (a)->tv_usec + (b)->tv_usec;
	if (result->tv_usec >= 1000000)
	{
		++result->tv_sec;
		result->tv_usec -= 1000000;
	}
}
void subtract_time(timeval* a, timeval* b, timeval* result)
{
	result->tv_sec = (a)->tv_sec - (b)->tv_sec;
	result->tv_usec = (a)->tv_usec - (b)->tv_usec;
	if (result->tv_usec < 0)
	{
		--result->tv_sec;
		result->tv_usec += 1000000;
	}
}

int subtract_time(timeval* a, timeval* b)
{
	struct timeval result;
	/* result = a-b */
	subtract_time(a, b, &result);
	int retval = result.tv_sec * 1000 + result.tv_usec / 1000;
	EVENTLOG1(VERBOSE, "Computed Time Difference : %d msecs\n", retval);
	return ((retval < 0) ? -1 : retval);
}

void sum_time(timeval* a, time_t inteval, timeval* result)
{
	timeval tv;
	fills_timeval(&tv, inteval);
	sum_time(a, &tv, result);
}
void subtract_time(timeval* a, time_t inteval, timeval* result)
{
	timeval tv;
	fills_timeval(&tv, inteval);
	subtract_time(a, &tv, result);
}
void print_time_now(ushort level)
{
	struct timeval now;
	gettimenow(&now);
	EVENTLOG2(level, "Time now: %ld sec, %ld usec", now.tv_sec, now.tv_usec);
}
void print_timeval(timeval* tv)
{
	EVENTLOG2(INTERNAL_TRACE, "timeval {%ld, %ld}", tv->tv_sec, tv->tv_usec);
}

static int debug_vwrite(FILE* fd, const char* formate, va_list ap)
{
	struct timeval tv;  // this is used for get usec
	struct tm the_time;  // only contains data infos, no ms and us
	if (!gettimenow(&tv, &the_time))
	{
		// write fixed log header
		if (fprintf(fd, "%02d:%02d:%02d.%03d - ", the_time.tm_hour, the_time.tm_min,
			the_time.tm_sec, (int)(tv.tv_usec / 1000)) < 1)  // change to  ms
			return -1;
		// then write log msg
		if (vfprintf(fd, formate, ap) < 1) return -1;
		return 0;
	}
	else
	{
		return -1;
	}
}
void debug_print(FILE * fd, const char *f, ...)
{
	va_list va;
	va_start(va, f);
	debug_vwrite(fd, f, va);
	va_end(va);
	fflush(fd);
}

void event_log1(short event_log_level, const char *module_name, int line, const char *log_info, ...)
{
	int mi;
	struct timeval tv;
	struct tm the_time;

	va_list va;
	va_start(va, log_info);
	bool f1 = globalTrace == true && event_log_level <= CURR_EVENT_LOG_LEVEL;
	int moduleindex = is_module_traced(module_name);
	bool f2 = globalTrace == false && moduleindex > 0
		&& event_log_level <= event_trace_levels[moduleindex];
	if (f1 || f2)
	{
		if (event_log_level < NOTICE)
		{
			if (fileTrace == true)
			{
				debug_print(logfile, "Event in Module: %s............\n", module_name);
			}
			else
			{
				debug_print(stdout, "Event in Module: %s............\n", module_name);
			}
		}
		gettimenow(&tv, &the_time);
		if (fileTrace == true)
		{
			fprintf(logfile, "%02d:%02d:%02d.%03d:%d ", the_time.tm_hour, the_time.tm_min,
				the_time.tm_sec, (int)(tv.tv_usec / 1000), line);
			vfprintf(logfile, log_info, va);
			fprintf(logfile, "\n");
			fflush(logfile);
		}
		else
		{
			fprintf(stdout, "%02d:%02d:%02d.%03d:%d ", the_time.tm_hour, the_time.tm_min,
				the_time.tm_sec, (int)(tv.tv_usec / 1000), line);
			vfprintf(stdout, log_info, va);
			fprintf(stdout, "\n");
			fflush(stdout);
		}
	}
	va_end(va);
}
void error_log1(short error_loglvl, const char *module_name, int line_no, const char *log_info, ...)
{
	int mi;
	va_list va;

	va_start(va, log_info);
	bool f1 = globalTrace == true && error_loglvl <= CURR_EVENT_LOG_LEVEL;
	int moduleindex = is_module_traced(module_name);
	bool f2 = globalTrace == false && moduleindex > 0
		&& error_loglvl <= event_trace_levels[moduleindex];
	if (f1 || f2)
	{
		if (fileTrace == true)
		{
			debug_print(logfile, "Error[%2d,%s] in %s at line %d\n", error_loglvl,
				error_loglvls_str[error_loglvl - 1], module_name, line_no);
			/*   fprintf(logfile, "Error Info: ");*/
			vfprintf(logfile, log_info, va);
			fprintf(logfile, "\n");
		}
		else
		{
			debug_print(stderr, "Error[%2d,%s] in %s at line %d, ", error_loglvl,
				error_loglvls_str[error_loglvl - 1], module_name, line_no);
			/*   fprintf(logfile, "Error Info: ");*/
			vfprintf(stderr, log_info, va);
			fprintf(stderr, "\n");
		}
	}
	va_end(va);

	if (fileTrace == true)
	{
		fflush(logfile);
	}
	else
	{
		fflush(stderr);
	}
	if (error_loglvl == FALTAL_ERROR_EXIT)
	{
		char str[32];
		sprintf(str, "%s exits at line %d", module_name, line_no);
		perr_exit(str);
	}
	if (error_loglvl == MAJOR_ERROR)
	{
		char str[32];
		sprintf(str, "%s aborts at line %d", module_name, line_no);
		perr_abort(str);
	}
}
void error_log_sys1(short error_log_level, const char *module_name, int line_no, short errnumber)
{
	error_log1(error_log_level, module_name, line_no, strerror(errnumber));
}

void perr_exit(const char *infostring)
{
	perror(infostring);
	exit(1);
	abort();
}
void perr_abort(const char *infostring)
{
	perror(infostring);
	abort();
}
//++++++++++++++++++ helpers +++++++++++++++
bool safe_before(uint seq1, uint seq2)
{
	// INT32_MAX = (2147483647)
	// INT32_MIN = (-2147483647-1)
	// UINT32_MAX = 4294967295U
	// assume a extream situation where seq1 = 0, seq2 = UINT32_MAX,
	// seq1 - seq2 = -4294967295 ���int��ʵ��ֵ���� (int) ��-1�� ��Ϊ
	// INT32_MAX-INT32_MIN ����UINT32_MAX���պ������int�ĸ�ֵ����
	// Ҳ����С��0�� �������ǵ���Ҫ
	// ʵ�������ǻ����Է���һ���ȱȽϵ����͸�������ͣ���֯�������Ĳ���
	// ����   return (uint64) (seq1 - seq2) < 0;
	return ((int)(seq1 - seq2)) < 0;
}
bool safe_after(uint seq1, uint seq2)
{
	return ((int)(seq2 - seq1)) < 0;
}
bool safe_before(ushort seq1, ushort seq2)
{
	return ((short)(seq1 - seq2)) < 0;
}
bool safe_after(ushort seq1, ushort seq2)
{
	return ((short)(seq2 - seq1)) < 0;
}
// if s1 <= s2 <= s3
// @pre seq1 <= seq3
bool safe_between(uint seq1, uint seq2, uint seq3)
{
	return safe_before(seq1, seq3) ? seq3 - seq1 >= seq2 - seq1 : seq3 - seq1 <= seq2 - seq1;
}
// @pre make sure seq1 <= seq3
bool unsafe_between(uint seq1, uint seq2, uint seq3)
{
	return seq3 - seq1 >= seq2 - seq1;
}
/**
 * helper function for sorting list of chunks in tsn order
 * @param  one pointer to chunk data
 * @param  two pointer to other chunk data
 * @return 0 if chunks have equal tsn, -1 if tsn1 < tsn2, 1 if tsn1 > tsn2
 */
int sort_tsn(const internal_data_chunk_t& one, const internal_data_chunk_t& two)
{
	if (safe_before(one.chunk_tsn, two.chunk_tsn)) return -1;
	else if (safe_after(one.chunk_tsn, two.chunk_tsn)) return 1;
	else return 0; /* one==two */
}
int sort_ssn(const internal_stream_data_t& one, const internal_stream_data_t& two)
{
	if (one.stream_id < two.stream_id)
	{
		return -1;
	}
	else if (one.stream_id > two.stream_id)
	{
		return 1;
	}
	else /* one.sid==two.sid */
	{
		if (safe_before(one.stream_sn, two.stream_sn)) return -1;
		else if (safe_after(one.stream_sn, two.stream_sn)) return 1;
	}
	return 0;
}

char* Bitify(size_t mWritePosBits, char* mBuffer)
{
	static char out[1024 * 1024];

	if (mWritePosBits <= 0)
	{
		strcpy(out, "no bits to print\n");
		return NULL;
	}
	int strIndex = 0;
	int inner;
	int stopPos;
	int outter;
	int len = BITS_TO_BYTES(mWritePosBits);

	for (outter = 0; outter < len; outter++)
	{
		if (outter == len - 1) stopPos = 8 - (((mWritePosBits - 1) & 7) + 1);
		else stopPos = 0;

		for (inner = 7; inner >= stopPos; inner--)
		{
			if ((mBuffer[outter] >> inner) & 1) out[strIndex++] = '1';
			else out[strIndex++] = '0';
		}
		//out[strIndex++] = '\n';
		out[strIndex++] = ' ';
	}

	//out[strIndex++] = '\n';
	out[strIndex++] = 0;

	return out;
}
void Bitify(char* out, size_t mWritePosBits, char* mBuffer)
{
	if (mWritePosBits <= 0)
	{
		strcpy(out, "no bits to print\n");
		return;
	}
	int strIndex = 0;
	int inner;
	int stopPos;
	int outter;
	int len = BITS_TO_BYTES(mWritePosBits);

	for (outter = 0; outter < len; outter++)
	{
		if (outter == len - 1) stopPos = 8 - (((mWritePosBits - 1) & 7) + 1);
		else stopPos = 0;

		for (inner = 7; inner >= stopPos; inner--)
		{
			if ((mBuffer[outter] >> inner) & 1) out[strIndex++] = '1';
			else out[strIndex++] = '0';
		}
		//out[strIndex++] = '\n';
		out[strIndex++] = ' ';
	}

	//out[strIndex++] = '\n';
	out[strIndex++] = 0;

}
unsigned int sockaddr2hashcode(const sockaddrunion* sa)
{
	ushort local_saaf = saddr_family(sa);
	unsigned int lastHash = SuperFastHashIncremental((const char*)&sa->sin.sin_port,
		sizeof(sa->sin.sin_port), local_saaf);
	if (local_saaf == AF_INET)
	{
		lastHash = SuperFastHashIncremental((const char*)&sa->sin.sin_addr.s_addr, sizeof(in_addr),
			lastHash);
	}
	else if (local_saaf == AF_INET6)
	{
		lastHash = SuperFastHashIncremental((const char*)&sa->sin6.sin6_addr.s6_addr,
			sizeof(in6_addr), lastHash);
	}
	else
	{
		ERRLOG1(FALTAL_ERROR_EXIT, "sockaddr2hashcode()::no such af (%u)", local_saaf);
	}
	return lastHash;
}
unsigned int transportaddr2hashcode(const sockaddrunion* local_sa, const sockaddrunion* peer_sa)
{
	ushort local_saaf = saddr_family(local_sa);
	unsigned int lastHash = SuperFastHashIncremental((const char*)&local_sa->sin.sin_port,
		sizeof(local_sa->sin.sin_port), local_saaf);
	if (local_saaf == AF_INET)
	{
		lastHash = SuperFastHashIncremental((const char*)&local_sa->sin.sin_addr.s_addr,
			sizeof(in_addr), lastHash);
	}
	else if (local_saaf == AF_INET6)
	{
		lastHash = SuperFastHashIncremental((const char*)&local_sa->sin6.sin6_addr.s6_addr,
			sizeof(in6_addr), lastHash);
	}
	else
	{
		ERRLOG1(FALTAL_ERROR_EXIT, "sockaddr2hashcode()::no such af (%u)", local_saaf);
	}
	ushort peer_saaf = saddr_family(peer_sa);
	lastHash = SuperFastHashIncremental((const char*)&peer_sa->sin.sin_port,
		sizeof(peer_sa->sin.sin_port), lastHash);
	if (peer_saaf == AF_INET)
	{
		lastHash = SuperFastHashIncremental((const char*)&peer_sa->sin.sin_addr.s_addr,
			sizeof(in_addr), lastHash);
	}
	else if (peer_saaf == AF_INET6)
	{
		lastHash = SuperFastHashIncremental((const char*)&peer_sa->sin6.sin6_addr.s6_addr,
			sizeof(in6_addr), lastHash);
	}
	else
	{
		ERRLOG1(FALTAL_ERROR_EXIT, "sockaddr2hashcode()::no such af (%u)", peer_saaf);
	}
	return lastHash;
}

#undef get16bits

#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const unsigned short *) (d)))
#else
#define get16bits(d) ((((unsigned int)(((const unsigned char *)(d))[1])) << 8)\
	+(unsigned int)(((const unsigned char *)(d))[0]) )
#endif

static const int INCREMENTAL_READ_BLOCK = 65536;
unsigned long SuperFastHash(const char * data, int length)
{
	// All this is necessary or the hash does not match SuperFastHashIncremental
	int bytesRemaining = length;
	unsigned int lastHash = length;
	int offset = 0;
	while (bytesRemaining >= INCREMENTAL_READ_BLOCK)
	{
		lastHash = SuperFastHashIncremental(data + offset, INCREMENTAL_READ_BLOCK, lastHash);
		bytesRemaining -= INCREMENTAL_READ_BLOCK;
		offset += INCREMENTAL_READ_BLOCK;
	}
	if (bytesRemaining > 0)
	{
		lastHash = SuperFastHashIncremental(data + offset, bytesRemaining, lastHash);
	}
	return lastHash;

	//	return SuperFastHashIncremental(data,len,len);
}
unsigned long SuperFastHashIncremental(const char * data, int len, unsigned int lastHash)
{
	unsigned int hash = (unsigned int)lastHash;
	unsigned int tmp;
	int rem;

	if (len <= 0 || data == NULL) return 0;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
	for (; len > 0; len--)
	{
		hash += get16bits(data);
		tmp = (get16bits(data + 2) << 11) ^ hash;
		hash = (hash << 16) ^ tmp;
		data += 2 * sizeof(unsigned short);
		hash += hash >> 11;
	}

	/* Handle end cases */
	switch (rem)
	{
	case 3:
		hash += get16bits(data);
		hash ^= hash << 16;
		hash ^= data[sizeof(unsigned short)] << 18;
		hash += hash >> 11;
		break;
	case 2:
		hash += get16bits(data);
		hash ^= hash << 11;
		hash += hash >> 17;
		break;
	case 1:
		hash += *data;
		hash ^= hash << 10;
		hash += hash >> 1;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return (unsigned int)hash;

}
unsigned long SuperFastHashFile(const char * filename)
{
	FILE *fp = fopen(filename, "rb");
	if (fp == 0) return 0;
	unsigned int hash = SuperFastHashFilePtr(fp);
	fclose(fp);
	return hash;
}
unsigned long SuperFastHashFilePtr(FILE *fp)
{
	fseek(fp, 0, SEEK_END);
	int length = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	int bytesRemaining = length;
	unsigned int lastHash = length;
	char readBlock[INCREMENTAL_READ_BLOCK];
	while (bytesRemaining >= (int) sizeof(readBlock))
	{
		fread(readBlock, sizeof(readBlock), 1, fp);
		lastHash = SuperFastHashIncremental(readBlock, (int) sizeof(readBlock), lastHash);
		bytesRemaining -= (int) sizeof(readBlock);
	}
	if (bytesRemaining > 0)
	{
		fread(readBlock, bytesRemaining, 1, fp);
		lastHash = SuperFastHashIncremental(readBlock, bytesRemaining, lastHash);
	}
	return lastHash;
}

char* Itoa(int value, char* result, int base)
{
	// check that the base if valid
	if (base < 2 || base > 16)
	{
		*result = 0;
		return result;
	}

	char* out = result;
	int quotient = value;
	int absQModB;

	do
	{
		// KevinJ - get rid of this dependency
		//*out = "0123456789abcdef"[ std::abs( quotient % base ) ];
		absQModB = quotient % base;
		if (absQModB < 0)
		{
			absQModB = -absQModB;
		}
		*out = "0123456789abcdef"[absQModB];
		++out;
		quotient /= base;
	} while (quotient);

	// Only apply negative sign for base 10
	if (value < 0 && base == 10) *out++ = '-';

	// KevinJ - get rid of this dependency
	// std::reverse( result, out );
	*out = 0;

	// KevinJ - My own reverse code
	char *start = result;
	char temp;
	out--;
	while (start < out)
	{
		temp = *start;
		*start = *out;
		*out = temp;
		start++;
		out--;
	}

	return result;
}

bool typeofaddr(union sockaddrunion* newAddress, IPAddrType flags)
{
	bool ret = false;
	bool b1;
	bool b2;

#ifdef _DEBUG
	char addrstr[MAX_IPADDR_STR_LEN];
	saddr2str(newAddress, addrstr, MAX_IPADDR_STR_LEN);
#endif

	switch (saddr_family(newAddress))
	{
	case AF_INET:
		if ((IN_MULTICAST(ntohl(newAddress->sin.sin_addr.s_addr))
			&& (flags & MulticastAddrType))
			|| (IN_EXPERIMENTAL(ntohl(newAddress->sin.sin_addr.s_addr))
				&& (flags & ReservedAddrType))
			|| (IN_BADCLASS(ntohl(newAddress->sin.sin_addr.s_addr))
				&& (flags & ReservedAddrType))
			|| ((INADDR_BROADCAST == ntohl(newAddress->sin.sin_addr.s_addr))
				&& (flags & BroadcastAddrType))
			|| ((INADDR_LOOPBACK == ntohl(newAddress->sin.sin_addr.s_addr))
				&& (flags & LoopBackAddrType))
			|| ((INADDR_LOOPBACK != ntohl(newAddress->sin.sin_addr.s_addr))
				&& (flags & AllExceptLoopbackAddrTypes))
			|| (ntohl(newAddress->sin.sin_addr.s_addr) == INADDR_ANY))
		{
#ifdef _DEBUG
			EVENTLOG2(DEBUG, "typeofaddr(ret=%d) %s  IS type of filtered addr BAD", 1, addrstr);
#endif
			ret = true;
			goto leave;
		}
#ifdef _DEBUG
		else
			EVENTLOG2(DEBUG, "typeofaddr(ret=%d) %s  IS-NOT type of filtered addr GOOD", 0, addrstr);
#endif
		break;
	case AF_INET6:
#if defined (__linux__)
		if ((!IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr.s6_addr))
			&& (flags & AllExceptLoopbackAddrTypes))
			|| (IN6_IS_ADDR_LOOPBACK(
				&(newAddress->sin6.sin6_addr.s6_addr))
				&& (flags & LoopBackAddrType))
			|| (IN6_IS_ADDR_LINKLOCAL(
				&(newAddress->sin6.sin6_addr.s6_addr))
				&& (flags & LinkLocalAddrType))
			|| (!IN6_IS_ADDR_LINKLOCAL(
				&(newAddress->sin6.sin6_addr.s6_addr))
				&& (flags & AllExceptLinkLocalAddrTypes))
			|| (!IN6_IS_ADDR_SITELOCAL(
				&(newAddress->sin6.sin6_addr.s6_addr))
				&& (flags & ExceptSiteLocalAddrTypes))
			|| (IN6_IS_ADDR_SITELOCAL(
				&(newAddress->sin6.sin6_addr.s6_addr))
				&& (flags & SiteLocalAddrType))
			|| (IN6_IS_ADDR_MULTICAST(
				&(newAddress->sin6.sin6_addr.s6_addr))
				&& (flags & MulticastAddrType))
			|| IN6_IS_ADDR_UNSPECIFIED(
				&(newAddress->sin6.sin6_addr.s6_addr)))
		{
#ifdef _DEBUG
			EVENTLOG2(DEBUG, "typeofaddr(ret=%d) %s  IS type of filtered addr BAD", 1, addrstr);
#endif
			ret = true;
			goto leave;
		}
#ifdef _DEBUG
		else
			EVENTLOG2(DEBUG, "typeofaddr(ret=%d) %s  IS-NOT type of filtered addr GOOD", 0, addrstr);
#endif
#else
		if (
			(!IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr)) && (flags & AllExceptLoopbackAddrTypes)) ||
			(IN6_IS_ADDR_LOOPBACK(&(newAddress->sin6.sin6_addr)) && (flags & LoopBackAddrType)) ||
			(!IN6_IS_ADDR_LINKLOCAL(&(newAddress->sin6.sin6_addr)) && (flags & AllExceptLinkLocalAddrTypes)) ||
			(!IN6_IS_ADDR_SITELOCAL(&(newAddress->sin6.sin6_addr)) && (flags & ExceptSiteLocalAddrTypes)) ||
			(IN6_IS_ADDR_LINKLOCAL(&(newAddress->sin6.sin6_addr)) && (flags & LinkLocalAddrType)) ||
			(IN6_IS_ADDR_SITELOCAL(&(newAddress->sin6.sin6_addr)) && (flags & SiteLocalAddrType)) ||
			(IN6_IS_ADDR_MULTICAST(&(newAddress->sin6.sin6_addr)) && (flags & MulticastAddrType)) ||
			IN6_IS_ADDR_UNSPECIFIED(&(newAddress->sin6.sin6_addr))
			)
		{
#ifdef _DEBUG
			EVENTLOG2(DEBUG, "typeofaddr(ret=%d) %s IS type of filtered addr BAD", 1, addrstr);
#endif
			ret = true;
			goto leave;
		}
#ifdef _DEBUG
		else
			EVENTLOG2(DEBUG, "typeofaddr(ret=%d) %s  IS-NOT type of filtered addr GOOD", 0, addrstr);
#endif
#endif
		break;
	default:
#ifdef _DEBUG
		EVENTLOG2(DEBUG, "typeofaddr(ret=%d) %s  IS type of filtered addr BAD", 1, addrstr);
#endif
		ret = true;
		goto leave;
		break;
	}
leave:
	return ret;
}
bool get_local_addresses(union sockaddrunion **addresses,
	int *numberOfNets, int sctp_fd, bool with_ipv6, int *max_mtu,
	const IPAddrType flags)
{
#ifdef WIN32
	union sockaddrunion *localAddresses = NULL;
	union sockaddrunion *localAddresses4 = NULL;
	union sockaddrunion * localAddresses6 = NULL;
	int ip4addrsize = 0, ip6addrsize = 0;
	SOCKET s[MAXIMUM_WAIT_OBJECTS];
	WSAEVENT hEvent[MAXIMUM_WAIT_OBJECTS];
	WSAOVERLAPPED ol[MAXIMUM_WAIT_OBJECTS];
	struct addrinfo *local = NULL, hints,
		*ptr = NULL;
	SOCKET_ADDRESS_LIST *slist = NULL;
	DWORD bytes;
	char addrbuf[ADDRESS_LIST_BUFFER_SIZE], host[NI_MAXHOST], serv[NI_MAXSERV];
	int socketcount = 0,
		addrbuflen = ADDRESS_LIST_BUFFER_SIZE,
		rc, i, j, hostlen = NI_MAXHOST, servlen = NI_MAXSERV;
	struct sockaddr_in Addr;
	struct sockaddr_in6 Addr6;

	/* Enumerate the local bind addresses - to wait for changes we only need
	one socket but to enumerate the addresses for a particular address
	family, we need a socket of that type  */

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	if ((rc = getaddrinfo(NULL, "0", &hints, &local)) != 0)
	{
		local = NULL;
		fprintf(stderr, "Unable to resolve the bind address!\n");
		return -1;
	}

	/* Create a socket and event for each address returned*/
	ptr = local;
	while (ptr)
	{
		s[socketcount] = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (s[socketcount] == INVALID_SOCKET)
		{
			fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
			return -1;
		}

		hEvent[socketcount] = WSACreateEvent();
		if (hEvent == NULL)
		{
			fprintf(stderr, "WSACreateEvent failed: %d\n", WSAGetLastError());
			return -1;
		}

		socketcount++;

		ptr = ptr->ai_next;

		if (ptr && (socketcount > MAXIMUM_WAIT_OBJECTS))
		{
			printf("Too many address families returned!\n");
			break;
		}
	}

	for (i = 0; i < socketcount; i++)
	{
		memset(&ol[i], 0, sizeof(WSAOVERLAPPED));
		ol[i].hEvent = hEvent[i];
		if ((rc = WSAIoctl(s[i], SIO_ADDRESS_LIST_QUERY, NULL, 0, addrbuf, addrbuflen,
			&bytes, NULL, NULL)) == SOCKET_ERROR)
		{
			fprintf(stderr, "WSAIoctl: SIO_ADDRESS_LIST_QUERY failed: %d\n", WSAGetLastError());
			return -1;
		}

		slist = (SOCKET_ADDRESS_LIST *)addrbuf;
		localAddresses6 = (sockaddrunion*)calloc(slist->iAddressCount, sizeof(union sockaddrunion));
		ip6addrsize = slist->iAddressCount;
		for (j = 0; j < slist->iAddressCount; j++)
		{
			if ((rc = getnameinfo(slist->Address[j].lpSockaddr, slist->Address[j].iSockaddrLength,
				host, hostlen, serv, servlen, NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
				fprintf(stderr, "%s: getnameinfo failed: %d\n", __FILE__, rc);
			Addr6.sin6_family = slist->Address[j].lpSockaddr->sa_family;
			inet_pton(AF_INET6, (const char *)host, &Addr6.sin6_addr);
			memcpy(&((localAddresses6)[j].sin6), &Addr6, sizeof(Addr6));
		}

		/* Register for change notification*/
		if ((rc = WSAIoctl(s[i], SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &bytes, &ol[i], NULL)) == SOCKET_ERROR)
		{
			if (WSAGetLastError() != WSA_IO_PENDING)
			{
				fprintf(stderr, "WSAIoctl: SIO_ADDRESS_LIST_CHANGE failed: %d\n", WSAGetLastError());
				return -1;
			}
		}
	}

	freeaddrinfo(local);
	for (i = 0; i < socketcount; i++)
		closesocket(s[i]);

	local = NULL;
	ptr = NULL;
	slist = NULL;
	socketcount = 0;
	addrbuflen = ADDRESS_LIST_BUFFER_SIZE;
	hostlen = NI_MAXHOST;
	servlen = NI_MAXSERV;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	if ((rc = getaddrinfo(NULL, "0", &hints, &local)) != 0)
	{
		local = NULL;
		fprintf(stderr, "Unable to resolve the bind address!\n");
		return -1;
	}

	/* Create a socket and event for each address returned*/
	ptr = local;
	while (ptr)
	{
		s[socketcount] = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (s[socketcount] == INVALID_SOCKET)
		{
			fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
			return -1;
		}

		hEvent[socketcount] = WSACreateEvent();
		if (hEvent == NULL)
		{
			fprintf(stderr, "WSACreateEvent failed: %d\n", WSAGetLastError());
			return -1;
		}

		socketcount++;

		ptr = ptr->ai_next;

		if (ptr && (socketcount > MAXIMUM_WAIT_OBJECTS))
		{
			printf("Too many address families returned!\n");
			break;
		}
	}

	for (i = 0; i < socketcount; i++)
	{
		memset(&ol[i], 0, sizeof(WSAOVERLAPPED));
		ol[i].hEvent = hEvent[i];
		if ((rc = WSAIoctl(s[i], SIO_ADDRESS_LIST_QUERY, NULL, 0, addrbuf, addrbuflen,
			&bytes, NULL, NULL)) == SOCKET_ERROR)
		{
			fprintf(stderr, "WSAIoctl: SIO_ADDRESS_LIST_QUERY failed: %d\n", WSAGetLastError());
			return -1;
		}

		slist = (SOCKET_ADDRESS_LIST *)addrbuf;
		localAddresses4 = (sockaddrunion*)calloc(slist->iAddressCount, sizeof(union sockaddrunion));
		ip4addrsize = slist->iAddressCount;
		for (j = 0; j < slist->iAddressCount; j++)
		{
			if ((rc = getnameinfo(slist->Address[j].lpSockaddr, slist->Address[j].iSockaddrLength,
				host, hostlen, serv, servlen, NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
				fprintf(stderr, "%s: getnameinfo failed: %d\n", __FILE__, rc);
			Addr.sin_family = slist->Address[j].lpSockaddr->sa_family;
			Addr.sin_addr.s_addr = inet_addr(host);
			memcpy(&((localAddresses4)[j].sin), &Addr, sizeof(Addr));
		}

		/* Register for change notification*/
		if ((rc = WSAIoctl(s[i], SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &bytes, &ol[i], NULL)) == SOCKET_ERROR)
		{
			if (WSAGetLastError() != WSA_IO_PENDING)
			{
				fprintf(stderr, "WSAIoctl: SIO_ADDRESS_LIST_CHANGE failed: %d\n", WSAGetLastError());
				return -1;
			}
		}
	}

	freeaddrinfo(local);
	for (i = 0; i < socketcount; i++)
		closesocket(s[i]);


	*numberOfNets = ip4addrsize + ip6addrsize;
	*max_mtu = 1500;
	localAddresses = (sockaddrunion*)calloc(*numberOfNets, sizeof(union sockaddrunion));
	for (j = 0; j < ip4addrsize; j++)
	{
		memcpy(&localAddresses[j], &localAddresses4[j], sizeof(sockaddrunion));
	}
	for (; j < (*numberOfNets); j++)
	{
		memcpy(&localAddresses[j], &localAddresses6[j - ip4addrsize], sizeof(sockaddrunion));
	}
	*addresses = localAddresses;
#else
#if defined (__linux__)
	int i;
	int addedNets;
	char addrBuffer[256];
	FILE *v6list;
	struct sockaddr_in6 sin6;
	int numAlocIPv4Addr = 0;
#endif

	char addrBuffer2[64];
	/* unsigned short intf_flags; */
	struct ifconf cf;
	int pos = 0, copSiz = 0, numAlocAddr = 0, ii;
	char buffer[8192];
	struct sockaddr *toUse;
	int saveMTU = 1500; /* default maximum MTU for now */
#ifdef HAS_SIOCGLIFADDR
	struct if_laddrreq lifaddr;
#endif
	struct ifreq local;
	struct ifreq *ifrequest, *nextif;
	int dup, xxx, tmp;
	union sockaddrunion * localAddresses = NULL;

	cf.ifc_buf = buffer;
	cf.ifc_len = 8192;
	*max_mtu = 0;
	*numberOfNets = 0;

	/* Now gather the master address information */
	if (ioctl(sctp_fd, SIOCGIFCONF, (char *)&cf) == -1)
	{
		return (false);
	}

#ifdef USES_BSD_4_4_SOCKET
	for (pos = 0; pos < cf.ifc_len;)
	{
		ifrequest = (struct ifreq *)&buffer[pos];
#ifdef SOLARIS
		pos += (sizeof(struct sockaddr) + sizeof(ifrequest->ifr_name));
#else
#ifdef NEUTRINO_RTOS
		if (ifrequest->ifr_addr.sa_len + IFNAMSIZ > sizeof(struct ifreq))
		{
			pos += ifrequest->ifr_addr.sa_len + IFNAMSIZ;
		}
		else
		{
			pos += sizeof(struct ifreq);
		}
#else
		pos += (ifrequest->ifr_addr.sa_len + sizeof(ifrequest->ifr_name));

		if (ifrequest->ifr_addr.sa_len == 0)
		{
			/* if the interface has no address then you must
			* skip at a minium a sockaddr structure
			*/
			pos += sizeof(struct sockaddr);
		}
#endif // NEUTRINO_RTOS
#endif
		numAlocAddr++;
	}
#else
	numAlocAddr = cf.ifc_len / sizeof(struct ifreq);
	/* ????????????  numAlocAddr++; */
	ifrequest = cf.ifc_req;
#endif
#if defined  (__linux__)
	numAlocIPv4Addr = numAlocAddr;
	addedNets = 0;
	v6list = fopen(LINUX_PROC_IPV6_FILE, "r");
	if (v6list != NULL)
	{
		while (fgets(addrBuffer, sizeof(addrBuffer), v6list) != NULL)
		{
			addedNets++;
		}
		fclose(v6list);
	}
	numAlocAddr += addedNets;
	EVENTLOG2(VERBOSE, "Found additional %d v6 addresses, total now %d\n",
		addedNets, numAlocAddr);
#endif
	/* now allocate the appropriate memory */
	localAddresses = (union sockaddrunion*) calloc(numAlocAddr,
		sizeof(union sockaddrunion));

	if (localAddresses == NULL)
	{
		ERRLOG(FALTAL_ERROR_EXIT,
			"Out of Memory in adl_gatherLocalAddresses() !");
		return (false);
	}

	pos = 0;
	/* Now we go through and pull each one */

#if defined (__linux__)
	v6list = fopen(LINUX_PROC_IPV6_FILE, "r");
	if (v6list != NULL)
	{
		memset((char *)&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;

		while (fgets(addrBuffer, sizeof(addrBuffer), v6list) != NULL)
		{
			if (strncmp(addrBuffer, "00000000000000000000000000000001", 32)
				== 0)
			{
				EVENTLOG(VERBOSE, "At least I found the local IPV6 address !");
				if (inet_pton(AF_INET6, "::1", (void *)&sin6.sin6_addr) > 0)
				{
					sin6.sin6_family = AF_INET6;
					memcpy(&((localAddresses)[*numberOfNets]), &sin6,
						sizeof(sin6));
					EVENTLOG5(VERBOSE,
						"copied the local IPV6 address %x:%x:%x:%x, family %x",
						sin6.sin6_addr.s6_addr32[3],
						sin6.sin6_addr.s6_addr32[2],
						sin6.sin6_addr.s6_addr32[1],
						sin6.sin6_addr.s6_addr32[0], sin6.sin6_family);
					(*numberOfNets)++;
				}
				continue;
			}
			memset(addrBuffer2, 0, sizeof(addrBuffer2));
			strncpy(addrBuffer2, addrBuffer, 4);
			addrBuffer2[4] = ':';
			strncpy(&addrBuffer2[5], &addrBuffer[4], 4);
			addrBuffer2[9] = ':';
			strncpy(&addrBuffer2[10], &addrBuffer[8], 4);
			addrBuffer2[14] = ':';
			strncpy(&addrBuffer2[15], &addrBuffer[12], 4);
			addrBuffer2[19] = ':';
			strncpy(&addrBuffer2[20], &addrBuffer[16], 4);
			addrBuffer2[24] = ':';
			strncpy(&addrBuffer2[25], &addrBuffer[20], 4);
			addrBuffer2[29] = ':';
			strncpy(&addrBuffer2[30], &addrBuffer[24], 4);
			addrBuffer2[34] = ':';
			strncpy(&addrBuffer2[35], &addrBuffer[28], 4);

			if (inet_pton(AF_INET6, addrBuffer2, (void *)&sin6.sin6_addr) > 0)
			{
				if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr))
				{
					sscanf((const char*)&addrBuffer[34], "%x",
						&sin6.sin6_scope_id);
				}
				memcpy(&((localAddresses)[*numberOfNets]), &sin6, sizeof(sin6));

			}
			else
			{
				ERRLOG1(FALTAL_ERROR_EXIT, "Could not translate string %s",
					addrBuffer2);
			}
		}
		fclose(v6list);
	}
#endif

	/* set to the start, i.e. buffer[0] */
	ifrequest = (struct ifreq *) &buffer[pos];

#if defined (__linux__)
	for (ii = 0; ii < numAlocIPv4Addr; ii++, ifrequest = nextif)
	{
#else
	for (ii = 0; ii < numAlocAddr; ii++, ifrequest = nextif)
	{
#endif
#ifdef USES_BSD_4_4_SOCKET
		/* use the sa_len to calculate where the next one will be */
#ifdef SOLARIS
		pos += (sizeof(struct sockaddr) + sizeof(ifrequest->ifr_name));
#else
#ifdef NEUTRINO_RTOS
		if (ifrequest->ifr_addr.sa_len + IFNAMSIZ > sizeof(struct ifreq))
		{
			pos += ifrequest->ifr_addr.sa_len + IFNAMSIZ;
		}
		else
		{
			pos += sizeof(struct ifreq);
		}
#else
		pos += (ifrequest->ifr_addr.sa_len + sizeof(ifrequest->ifr_name));

		if (ifrequest->ifr_addr.sa_len == 0)
		{
			/* if the interface has no address then you must
			* skip at a minium a sockaddr structure
			*/
			pos += sizeof(struct sockaddr);
		}
#endif // NEUTRINO_RTOS
#endif
		nextif = (struct ifreq *)&buffer[pos];
#else
		nextif = ifrequest + 1;
#endif

#ifdef _NO_SIOCGIFMTU_
		*max_mtu = DEFAULT_MTU_CEILING;
#else
		memset(&local, 0, sizeof(local));
		memcpy(local.ifr_name, ifrequest->ifr_name, IFNAMSIZ);
		EVENTLOG3(VERBOSE, "Interface %d, NAME %s, Hex: %x", ii, local.ifr_name,
			local.ifr_name);

		if (ioctl(sctp_fd, SIOCGIFMTU, (char *)&local) == -1)
		{
			/* cant get the flags? */
			continue;
		}
		saveMTU = local.ifr_mtu;
		EVENTLOG2(VERBOSE, "Interface %d, MTU %d", ii, saveMTU);
#endif
		toUse = &ifrequest->ifr_addr;

		saddr2str((union sockaddrunion*) toUse, addrBuffer2, MAX_IPADDR_STR_LEN,
			NULL);
		EVENTLOG1(VERBOSE, "we are talking about the address %s", addrBuffer2);

		memset(&local, 0, sizeof(local));
		memcpy(local.ifr_name, ifrequest->ifr_name, IFNAMSIZ);

		if (ioctl(sctp_fd, SIOCGIFFLAGS, (char *)&local) == -1)
		{
			/* can't get the flags, skip this guy */
			continue;
		}
		/* Ok get the address and save the flags */
		/*        intf_flags = local.ifr_flags; */

		if (!(local.ifr_flags & IFF_UP))
		{
			/* Interface is down */
			continue;
		}

		if (flags & LoopBackAddrType)
		{
			if (typeofaddr((union sockaddrunion*) toUse,
				LoopBackAddrType))
			{
				/* skip the loopback */
				EVENTLOG1(VERBOSE, "Interface %d, skipping loopback", ii);
				continue;
			}
		}
		if (typeofaddr((union sockaddrunion*) toUse, ReservedAddrType))
		{
			/* skip reserved */
			EVENTLOG1(VERBOSE, "Interface %d, skipping reserved", ii);
			continue;
		}

		if (toUse->sa_family == AF_INET)
		{
			copSiz = sizeof(struct sockaddr_in);
		}
		else if (toUse->sa_family == AF_INET6)
		{
			copSiz = sizeof(struct sockaddr_in6);
		}
		if (*max_mtu < saveMTU)
			*max_mtu = saveMTU;

		/* Now, we may have already gathered this address, if so skip
		* it
		*/
		EVENTLOG2(VERBOSE,
			"Starting checking for duplicates ! MTU = %d, nets: %d",
			saveMTU, *numberOfNets);

		if (*numberOfNets)
		{
			tmp = *numberOfNets;
			dup = 0;
			/* scan for the dup */
			for (xxx = 0; xxx < tmp; xxx++)
			{
				EVENTLOG1(VERBOSE, "duplicates loop xxx=%d", xxx);
				if (saddr_equals(&localAddresses[xxx],
					(union sockaddrunion*) toUse))
				{
					if ((localAddresses[xxx].sa.sa_family == AF_INET6) &&
						(toUse->sa_family == AF_INET) &&
						(IN6_IS_ADDR_V4MAPPED(&localAddresses[xxx].sin6.sin6_addr) ||
							IN6_IS_ADDR_V4COMPAT(&localAddresses[xxx].sin6.sin6_addr)))
					{
						/* There are multiple interfaces, one has ::ffff:a.b.c.d or
						::a.b.c.d address. Use address which is IPv4 native instead. */
						memcpy(&localAddresses[xxx], toUse, sizeof(localAddresses[xxx]));
					}
					else
					{
						EVENTLOG(VERBOSE, "Interface %d, found duplicate");
						dup = 1;
					}
				}
			}
			if (dup)
			{
				/* skip the duplicate name/address we already have it*/
				continue;
			}
		}

		/* copy address */
		EVENTLOG1(VERBOSE, "Copying %d bytes", copSiz);
		memcpy(&localAddresses[*numberOfNets], (char *)toUse, copSiz);
		EVENTLOG(VERBOSE, "Setting Family");
		/* set family */
		(&(localAddresses[*numberOfNets]))->sa.sa_family = toUse->sa_family;

#ifdef USES_BSD_4_4_SOCKET
#ifndef SOLARIS
		/* copy the length */
		(&(localAddresses[*numberOfNets]))->sa.sa_len = toUse->sa_len;
#endif
#endif
		(*numberOfNets)++;
		EVENTLOG2(VERBOSE, "Interface %d, Number of Nets: %d", ii,
			*numberOfNets);
	}

	EVENTLOG1(VERBOSE, "adl_gatherLocalAddresses: Found %d addresses",
		*numberOfNets);
	for (ii = 0; ii < (*numberOfNets); ii++)
	{
		saddr2str(&(localAddresses[ii]), addrBuffer2, MAX_IPADDR_STR_LEN, NULL);
		EVENTLOG2(VERBOSE, "adl_gatherAddresses : Address %d: %s", ii,
			addrBuffer2);

	}
	*addresses = localAddresses;
#endif

	// reorder addres to put ip4 addr together and ip6 addres together
	sockaddrunion* buf = (sockaddrunion*)calloc(*numberOfNets, sizeof(sockaddrunion));
	for (i = 0; i < *numberOfNets; i++)
	{
		memcpy(&buf[i], &(*addresses)[i], sizeof(sockaddrunion));
	}
	free(*addresses);
	*addresses = buf;

	char addrdebug[MAX_IPADDR_STR_LEN];
	for (i = 0; i < *numberOfNets; i++)
	{
		saddr2str(&(*addresses)[i], addrdebug, MAX_IPADDR_STR_LEN, 0);
		EVENTLOG2(DEBUG, "default local addr %d = %s", i, addrdebug);
	}
	return (true);
}
