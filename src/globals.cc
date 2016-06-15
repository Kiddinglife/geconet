/*
 * globals.cc
 *
 *  Created on: 14 Apr 2016
 *      Author: jakez
 */

#include "globals.h"
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

//++++++++++++++++++ logging ++++++++++++++++++++
static bool globalTrace = true;
static bool fileTrace = false;
static FILE* logfile = 0;
static int noOftracedModules;
static char traced_modules[TRACE_MUDULE_SIZE][70];
static int error_trace_levels[TRACE_MUDULE_SIZE];
static int event_trace_levels[TRACE_MUDULE_SIZE];
static const char* error_loglvls_str[4] = { "fatal_error_exit",
        "major_error_abort", "minor_error", "lwarnning_error" };
static const char* event_loglvls_str[6] = { "extevent_unexpected", "extevent",
        "intevent_important", "intevent", "VERBOSE", "lvverbos" };

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
            ret = fscanf(fptr, "%s%d%d", traced_modules[i],
                    &error_trace_levels[i], &event_trace_levels[i]);
            if (ret >= 1)
            {
                if (strcmp(traced_modules[i], "LOGFILE") == 0)
                {
                    printf(
                            "Logging all errors and events to file ./tmp%d.log\n",
                            (int) getpid());
                    fileTrace = true;
                    sprintf(filename, "./tmp%d.log", (int) getpid());
                    logfile = fopen(filename, "w+");
                    return;
                }
            }

            if (ferror(fptr))
                abort();

            //if we have less than TRACE_MUDULE_SIZE mudlues to trace, this will break loop
            if (feof(fptr))
                break;

            globalTrace = false;
        }
        noOftracedModules = i;
        if (i <= 1)
            globalTrace = true;
        printf("  globalTrace = %s \n", globalTrace ? "TRUE" : "FALSE");
    }
    else
    {
        globalTrace = true;
    }
    printf("globalTrace '%s', modules size '%d'\n",
            globalTrace ? "TRUE" : "FALSE", noOftracedModules);
    for (i = 0; i < noOftracedModules; i++)
        printf("%20s %2d %2d\n", traced_modules[i], error_trace_levels[i],
                event_trace_levels[i]);
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
        time_t tt = (time_t) tv->tv_sec;
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
        EVENTLOG2(EXTERNAL_TRACE, "Time now: %ld sec, %ld usec \n", now.tv_sec,
                now.tv_usec);
        *ret = ((time_t) now.tv_sec) * 1000 + ((time_t) now.tv_usec) / 1000;
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
        EVENTLOG2(EXTERNAL_TRACE, "Time now: %ld sec, %ld usec \n", now.tv_sec,
                now.tv_usec);
        *ret = ((time_t) now.tv_sec) * 1000000 + (time_t) now.tv_usec;
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
    EVENTLOG2(level, "Time now: %ld sec, %ld usec \n", now.tv_sec, now.tv_usec);
}
void print_timeval(timeval* tv)
{
    EVENTLOG2(INTERNAL_TRACE, "timeval {%ld, %ld}\n", tv->tv_sec, tv->tv_usec);
}

static int debug_vwrite(FILE* fd, const char* formate, va_list ap)
{
    struct timeval tv; // this is used for get usec
    struct tm the_time; // only contains data infos, no ms and us
    if (!gettimenow(&tv, &the_time))
    {
        // write fixed log header
        if (fprintf(fd, "%02d:%02d:%02d.%03d - ", the_time.tm_hour,
                the_time.tm_min, the_time.tm_sec, (int) (tv.tv_usec / 1000))
                < 1) // change to  ms
            return -1;
        // then write log msg
        if (vfprintf(fd, formate, ap) < 1)
            return -1;
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

extern void event_log1(short event_log_level, const char *module_name,
        const char *log_info, ...)
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
        if (event_log_level < VERBOSE)
        {
            if (fileTrace == true)
            {
                debug_print(logfile, "Event in Module: %s............\n",
                        module_name);
            }
            else
            {
                debug_print(stdout, "Event in Module: %s............\n",
                        module_name);
            }
        }
        gettimenow(&tv, &the_time);
        if (fileTrace == true)
        {
            fprintf(logfile, "%02d:%02d:%02d.%03d - ", the_time.tm_hour,
                    the_time.tm_min, the_time.tm_sec,
                    (int) (tv.tv_usec / 1000));
            vfprintf(logfile, log_info, va);
            fprintf(logfile, "\n");
            fflush(logfile);
        }
        else
        {
            fprintf(stdout, "%02d:%02d:%02d.%03d - ", the_time.tm_hour,
                    the_time.tm_min, the_time.tm_sec,
                    (int) (tv.tv_usec / 1000));
            vfprintf(stdout, log_info, va);
            fprintf(stdout, "\n");
            fflush(stdout);
        }
    }
    va_end(va);
}
extern void error_log1(short error_loglvl, const char *module_name, int line_no,
        const char *log_info, ...)
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
            debug_print(logfile, "Error[%2d,%s] in %s at line %d\n",
                    error_loglvl, error_loglvls_str[error_loglvl - 1],
                    module_name, line_no);
            /*   fprintf(logfile, "Error Info: ");*/
            vfprintf(logfile, log_info, va);
            fprintf(logfile, "\n");
        }
        else
        {
            debug_print(stderr, "Error[%2d,%s] in %s at line %d, ",
                    error_loglvl, error_loglvls_str[error_loglvl - 1],
                    module_name, line_no);
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
void error_log_sys1(short error_log_level, const char *module_name, int line_no,
        short errnumber)
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
    return ((int) (seq1 - seq2)) < 0;
}
bool safe_after(uint seq1, uint seq2)
{
    return ((int) (seq2 - seq1)) < 0;
}
bool safe_before(ushort seq1, ushort seq2)
{
    return ((short) (seq1 - seq2)) < 0;
}
bool safe_after(ushort seq1, ushort seq2)
{
    return ((short) (seq2 - seq1)) < 0;
}
// if s1 <= s2 <= s3
// @pre seq1 <= seq3
bool safe_between(uint seq1, uint seq2, uint seq3)
{
    return safe_before(seq1, seq3) ?
            seq3 - seq1 >= seq2 - seq1 : seq3 - seq1 <= seq2 - seq1;
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
    if (safe_before(one.chunk_tsn, two.chunk_tsn))
        return -1;
    else if (safe_after(one.chunk_tsn, two.chunk_tsn))
        return 1;
    else
        return 0; /* one==two */
}
int sort_ssn(const internal_stream_data_t& one,
        const internal_stream_data_t& two)
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
        if (safe_before(one.stream_sn, two.stream_sn))
            return -1;
        else if (safe_after(one.stream_sn, two.stream_sn))
            return 1;
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
        if (outter == len - 1)
            stopPos = 8 - (((mWritePosBits - 1) & 7) + 1);
        else
            stopPos = 0;

        for (inner = 7; inner >= stopPos; inner--)
        {
            if ((mBuffer[outter] >> inner) & 1)
                out[strIndex++] = '1';
            else
                out[strIndex++] = '0';
        }
        out[strIndex++] = '\n';
    }

    out[strIndex++] = '\n';
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
        if (outter == len - 1)
            stopPos = 8 - (((mWritePosBits - 1) & 7) + 1);
        else
            stopPos = 0;

        for (inner = 7; inner >= stopPos; inner--)
        {
            if ((mBuffer[outter] >> inner) & 1)
                out[strIndex++] = '1';
            else
                out[strIndex++] = '0';
        }
        out[strIndex++] = '\n';
    }

    out[strIndex++] = '\n';
    out[strIndex++] = 0;

}
unsigned int sockaddr2hashcode(const sockaddrunion* sa)
{
    ushort local_saaf = saddr_family(sa);
    unsigned int lastHash = SuperFastHashIncremental(
            (const char*) &sa->sin.sin_port, sizeof(sa->sin.sin_port),
            local_saaf);
    if (local_saaf == AF_INET)
    {
        lastHash = SuperFastHashIncremental(
                (const char*) &sa->sin.sin_addr.s_addr, sizeof(in_addr),
                lastHash);
    }
    else if (local_saaf == AF_INET6)
    {
        lastHash = SuperFastHashIncremental(
                (const char*) &sa->sin6.sin6_addr.s6_addr, sizeof(in6_addr),
                lastHash);
    }
    else
    {
        ERRLOG1(FALTAL_ERROR_EXIT, "sockaddr2hashcode()::no such af (%u)",
                local_saaf);
    }
    return lastHash;
}
unsigned int transportaddr2hashcode(const sockaddrunion* local_sa,
        const sockaddrunion* peer_sa)
{
    ushort local_saaf = saddr_family(local_sa);
    unsigned int lastHash = SuperFastHashIncremental(
            (const char*) &local_sa->sin.sin_port,
            sizeof(local_sa->sin.sin_port), local_saaf);
    if (local_saaf == AF_INET)
    {
        lastHash = SuperFastHashIncremental(
                (const char*) &local_sa->sin.sin_addr.s_addr, sizeof(in_addr),
                lastHash);
    }
    else if (local_saaf == AF_INET6)
    {
        lastHash = SuperFastHashIncremental(
                (const char*) &local_sa->sin6.sin6_addr.s6_addr,
                sizeof(in6_addr), lastHash);
    }
    else
    {
        ERRLOG1(FALTAL_ERROR_EXIT, "sockaddr2hashcode()::no such af (%u)",
                local_saaf);
    }
    ushort peer_saaf = saddr_family(peer_sa);
    lastHash = SuperFastHashIncremental((const char*) &peer_sa->sin.sin_port,
            sizeof(peer_sa->sin.sin_port), lastHash);
    if (peer_saaf == AF_INET)
    {
        lastHash = SuperFastHashIncremental(
                (const char*) &peer_sa->sin.sin_addr.s_addr, sizeof(in_addr),
                lastHash);
    }
    else if (peer_saaf == AF_INET6)
    {
        lastHash = SuperFastHashIncremental(
                (const char*) &peer_sa->sin6.sin6_addr.s6_addr,
                sizeof(in6_addr), lastHash);
    }
    else
    {
        ERRLOG1(FALTAL_ERROR_EXIT, "sockaddr2hashcode()::no such af (%u)",
                peer_saaf);
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
        lastHash = SuperFastHashIncremental(data + offset,
                INCREMENTAL_READ_BLOCK, lastHash);
        bytesRemaining -= INCREMENTAL_READ_BLOCK;
        offset += INCREMENTAL_READ_BLOCK;
    }
    if (bytesRemaining > 0)
    {
        lastHash = SuperFastHashIncremental(data + offset, bytesRemaining,
                lastHash);
    }
    return lastHash;

    //	return SuperFastHashIncremental(data,len,len);
}
unsigned long SuperFastHashIncremental(const char * data, int len,
        unsigned int lastHash)
{
    unsigned int hash = (unsigned int) lastHash;
    unsigned int tmp;
    int rem;

    if (len <= 0 || data == NULL)
        return 0;

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

    return (unsigned int) hash;

}
unsigned long SuperFastHashFile(const char * filename)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == 0)
        return 0;
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
        lastHash = SuperFastHashIncremental(readBlock, (int) sizeof(readBlock),
                lastHash);
        bytesRemaining -= (int) sizeof(readBlock);
    }
    if (bytesRemaining > 0)
    {
        fread(readBlock, bytesRemaining, 1, fp);
        lastHash = SuperFastHashIncremental(readBlock, bytesRemaining,
                lastHash);
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
    if (value < 0 && base == 10)
        *out++ = '-';

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
