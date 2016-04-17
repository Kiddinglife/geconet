/*
 * globals.cc
 *
 *  Created on: 14 Apr 2016
 *      Author: jakez
 */

#include "globals.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#include <sys/timeb.h>

#ifdef WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

//++++++++++++++++++ logging ++++++++++++++++++++
bool globalTrace;
bool fileTrace = false;
FILE* logfile;
static int noOftracedModules;
static char traced_modules[TRACE_MUDULE_SIZE][70];
static int error_trace_levels[TRACE_MUDULE_SIZE];
static int event_trace_levels[TRACE_MUDULE_SIZE];

void read_trace_levels(void)
{
    size_t i;
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
                    printf("Logging all errors and events to file ./tmp%d.log\n", (int)getpid());
                    fileTrace = true;
                    sprintf(filename, "./tmp%d.log", (int)getpid());
                    logfile = fopen(filename, "w+");
                    return;
                }
            }

            if (ferror(fptr))
                abort();

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
    printf("globalTrace '%s', modules size '%d'\n",
        globalTrace ? "TRUE" : "FALSE", noOftracedModules);
    for (i = 0; i < noOftracedModules; i++)
        printf("%20s %2d %2d\n", traced_modules[i], error_trace_levels[i],
        event_trace_levels[i]);
}

// -1 not found, >0 = module index
static int  is_module_traced(const char* modulename)
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


/**
* helper function for the sake of a cleaner interface :-)
*/
int get_time_now(struct timeval *tv)
{
#ifdef WIN32
    struct timeb tb;
    ftime(&tb);
    tv->tv_sec = tb.time;
    tv->tv_usec = tb.millitm * 1000;
    return 0;
#else
    return (gettimeofday(tv, (struct timezone *) NULL));
#endif
}
static int debug_vwrite(FILE* fd, const char* formate, va_list ap)
{
    struct timeval tv; // this is used for get usec
    struct tm *the_time; // only contains data infos, no ms and us

    get_time_now(&tv);
    time_t tt = (time_t)tv.tv_sec;
    the_time = localtime(&tt);

    // write fixed log header 
    if (fprintf(fd, "%02d:%02d:%02d.%03d - ",
        the_time->tm_hour,
        the_time->tm_min, the_time->tm_sec, (int)(tv.tv_usec / 1000)) < 1) // change to  ms
        return -1;
    // then write log msg
    if (vfprintf(fd, formate, ap) < 1) return -1;
    return 0;
}
void debug_print(FILE * fd, const char *f, ...)
{
    va_list va;
    va_start(va, f);
    debug_vwrite(fd, f, va);
    va_end(va);
    fflush(fd);
}
void print_time(ushort level)
{
    struct timeval now;
    get_time_now(&now);
    event_logii(level, "Time now: %ld sec, %ld usec \n", now.tv_sec, now.tv_usec);
}
inline void perr_exit(const char *infostring)
{
    perror(infostring);
    abort();
}
//++++++++++++++++++ helpers +++++++++++++++
inline bool safe_before(uint seq1, uint seq2)
{
    // INT32_MAX = (2147483647)
    // INT32_MIN = (-2147483647-1)
    // UINT32_MAX = 4294967295U
    // assume a extream situation where seq1 = 0, seq2 = UINT32_MAX,
    // seq1 - seq2 = -4294967295 溢出int，实际值等于 (int) （-1， 因为
    // INT32_MAX-INT32_MIN 等于UINT32_MAX，刚好溢出到int的负值区域
    // 也就是小于0， 符合我们的需要
    // 实际上我们还可以返回一个比比较的类型更大的类型，纺织溢出问题的产生
    // 例如   return (uint64) (seq1 - seq2) < 0;
    return ((int)(seq1 - seq2)) < 0;
}
inline bool safe_after(uint seq1, uint seq2)
{
    return ((int)(seq2 - seq1)) < 0;
}
inline bool safe_before(ushort seq1, ushort seq2)
{
    return ((short)(seq1 - seq2)) < 0;
}
inline bool safe_after(ushort seq1, ushort seq2)
{
    return ((short)(seq2 - seq1)) < 0;
}
// if s1 <= s2 <= s3
// @pre seq1 <= seq3
inline bool safe_between(uint seq1, uint seq2, uint seq3)
{
    return safe_before(seq1, seq3) ?
        seq3 - seq1 >= seq2 - seq1 : seq3 - seq1 <= seq2 - seq1;
}
// @pre make sure seq1 <= seq3
inline bool unsafe_between(uint seq1, uint seq2, uint seq3)
{
    return seq3 - seq1 >= seq2 - seq1;
}
/**
 * helper function for sorting list of chunks in tsn order
 * @param  one pointer to chunk data
 * @param  two pointer to other chunk data
 * @return 0 if chunks have equal tsn, -1 if tsn1 < tsn2, 1 if tsn1 > tsn2
 */
inline int sort_tsn(const internal_data_chunk_t& one,
    const internal_data_chunk_t& two)
{
    if (safe_before(one.chunk_tsn, two.chunk_tsn))
        return -1;
    else if (safe_after(one.chunk_tsn, two.chunk_tsn))
        return 1;
    else
        return 0; /* one==two */
}
inline int sort_ssn(const internal_stream_data_t& one,
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