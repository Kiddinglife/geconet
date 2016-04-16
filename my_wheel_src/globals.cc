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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef WIN32
#include <process.h>
#else
#include <sys/types.h>
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

    FILE* fptr = fopen("./tracelevels.in", "r");
    if (fptr != NULL)
    {
        globalTrace = true;
        for (i = 0; i < TRACE_MUDULE_SIZE; i++)
        {
            ret = fscanf(fptr, "%s %d %d", traced_modules[i],
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
        }
        if (ferror(fptr))
            abort();
        if (feof(fptr))
            break;
        globalTrace = true;
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

// -1 found, >0 = module index
int  is_module_traced(const char* modulename)
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

//++++++++++++++++++ helpers +++++++++++++++
inline bool safe_before(UInt32 seq1, UInt32 seq2)
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
    return ((int) (seq1 - seq2)) < 0;
}
inline bool safe_after(UInt32 seq1, UInt32 seq2)
{
    return ((int) (seq2 - seq1)) < 0;
}
inline bool safe_before(UInt16 seq1, UInt16 seq2)
{
    return ((short) (seq1 - seq2)) < 0;
}
inline bool safe_after(UInt16 seq1, UInt16 seq2)
{
    return ((short) (seq2 - seq1)) < 0;
}
// if s1 <= s2 <= s3
// @pre seq1 <= seq3
inline bool safe_between(UInt32 seq1, UInt32 seq2, UInt32 seq3)
{
    return safe_before(seq1, seq3) ?
            seq3 - seq1 >= seq2 - seq1 : seq3 - seq1 <= seq2 - seq1;
}
// @pre make sure seq1 <= seq3
inline bool unsafe_between(UInt32 seq1, UInt32 seq2, UInt32 seq3)
{
    return seq3 - seq1 >= seq2 - seq1;
}
/**
 * helper function for sorting list of chunks in tsn order
 * @param  one pointer to chunk data
 * @param  two pointer to other chunk data
 * @return 0 if chunks have equal tsn, -1 if tsn1 < tsn2, 1 if tsn1 > tsn2
 */
inline Int32 sort_tsn(const internal_data_chunk_t& one,
        const internal_data_chunk_t& two)
{
    if (safe_before(one.chunk_tsn, two.chunk_tsn))
        return -1;
    else if (safe_after(one.chunk_tsn, two.chunk_tsn))
        return 1;
    else
        return 0; /* one==two */
}
inline Int32 sort_ssn(const internal_stream_data_t& one,
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