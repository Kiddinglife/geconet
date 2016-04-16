/*
* globals.h
*
*  Created on: 12 Apr 2016
*      Author: jakez
*/

#ifndef MY_GLOBALS_H_
#define MY_GLOBALS_H_

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <climits>


#ifdef WIN32
#include <winsock2.h>
#include <time.h>
#include <sys/types.h>
#endif

#ifndef WIN32
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#ifdef FreeBSD
#include <netinet/in_systm.h>
#include <sys/types.h>
#endif

#ifdef SOLARIS
#include <netinet/in_systm.h>
#include <stdarg.h>
#endif


#include "messages.h"

/* Define a protocol id to be used in the IP Header..... */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP    132
#endif

/*this parameter specifies the maximum number of addresses that an endpoInt32 may have */
#define MAX_NUM_ADDRESSES      32

#define SECRET_KEYSIZE  4096
#define KEY_INIT     0
#ifndef KEY_READ
#define KEY_READ     1
#endif
#define MAX_DEST    16

//<--------------------------------------------------------- log --------------------------------------------->
#define TRACE_MUDULE_SIZE 50
/* Definition of levels for the logging of events */
#define very_verbos           6 /* very verbose logging of events   */
#define verbose            5  /* more verbose logging of events   */
#define Int32ernal_event_trace   4 /* pure execution flow trace */
#define Int32ernal_event   3    /* important Int32ernal events */
#define external_event     2  /* for events from ULP, peer or Timers */
#define external_event_unexpected 1/* for unexpected external events from ULP, peer or Timers */
#define log_byte_string   0 /* set to != 0 if byte string logging should be done */
/* Defines the level up to which the events are prInt32ed.
VVERBOSE (6) means all events are prInt32ed.
This parameter could also come from a command line option */
#define current_event_log_level 0

/* Definition of levels for the logging of errors */
#define error_no_need_recover 4 /* warning, recovery not necessary. */
#define error_fully_recove  3/* recovery from error was possible without affecting the system. */
/*recovery from error was possible with some affects to the system,
* for instance abort of an association.*/
#define error_partially_recover  2
#define error_cannot_recover 1 /* recovery from error was not possible, the program exits. */
/* Defines the level up to which the errors are prInt32ed.
*ERROR_WARNING (4) means all events are prInt32ed.
*This parameter could also come from a command line option*/
#define current_error_log_level 1

#define event_log(x,y)\
if (current_event_log_level >= x) event_log1((x), __FILE__, (y))
#define event_logi(x,y,z)\
if (current_event_log_level >= x) event_log1((x), __FILE__, (y), (z))
#define event_logii(x,y,z,i)\
if (current_event_log_level >= x) event_log1((x), __FILE__, (y), (z), (i))
#define event_logiii(x,y,z,i,j)\
if (current_event_log_level >= x) event_log1((x), __FILE__, (y), (z), (i), (j))
#define event_logiiii(x,y,z,i,j,k)\
if (current_event_log_level >= x) event_log1((x), __FILE__, (y), (z), (i), (j),(k))
#define event_logiiiii(x,y,z,i,j,k,l)\
if (current_event_log_level >= x) event_log1((x), __FILE__, (y), (z), (i), (j),(k),(l))
#define event_logiiiiiiii(x,y,z,i,j,k,l,m,n,o)\
if (current_event_log_level >= x) event_log1((x), __FILE__, (y), (z), (i), (j),(k),(l),(m),(n),(o))

#define error_log(x,y)  \
if (current_error_log_level >= x) error_log1((x), __FILE__, __LINE__, (y))
#define error_logi(x,y,z)\
if (current_error_log_level >= x) error_log1((x), __FILE__, __LINE__, (y),(z))
#define error_logii(x,y,z,i)   \
if (current_error_log_level >= x) error_log1((x), __FILE__, __LINE__, (y),(z),(i))
#define error_logiii(x,y,z,i,j)     \
if (current_error_log_level >= x) error_log1((x), __FILE__, __LINE__, (y),(z),(i),(j))
#define error_logiiii(x,y,z,i,j,k)    \
if (current_error_log_level >= x) error_log1((x), __FILE__, __LINE__, (y),(z),(i),(j),(k))
#define error_log_sys(x,y)    \
error_log_sys1((x), __FILE__, __LINE__, (y))
#define DLL_error_log(x,y)    \
if (current_error_log_level >= x) error_log1((x), __FILE__, __LINE__, (y))
#define IF_LOG(x, y)       \
if (x <= current_error_log_level) {y}

/**
*read_tracelevels reads from a file the tracelevels for errors and events for each module.
*Modules that are not listed in the file will not be traced. if the file does not exist or
*is empty, the global tracelevel defined in globals.h will be used. THe name of the file has
*to be {\texttt tracelevels.in} in the current directory where the executable is located.
*The normal format of the file is:
*\begin{verbatim}
*module1.c errorTraceLevel eventTraceLevel
*module2.c errorTraceLevel eventTraceLevel
*....
*\end{verbatim}
*The file must be terminated by a null line.
*Alternatively there may be the entry
*\begin{verbatim}
* LOGFILE
*\end{verbatim}
* in that file, which causes all output from event_logs() to go into a logfile in the local
* directory.
*/
void read_trace_levels(void);

void debug_prInt32(FILE * fd, const char *f, ...);

/**
* function to output the result of the adl_gettime-call, i.e. the time now
*/
void prInt32_time(short level);

/**
* prInt32 the error string after a system call and exit
*/
void perr_exit(const char *infostring);

/* This function logs events.
Parameters:
@param event_log_level : INTERNAL_EVENT_0 INTERNAL_EVENT_1 EXTERNAL_EVENT_X EXTERNAL_EVENT
@param module_name :     the name of the module that received the event.
@param log_info :        the info that is prInt32ed with the modulename.
@param anyno :           optional poInt32er to uint32, which is prInt32ed along with log_info.
The conversion specification must be contained in log_info.
@author     H�zlwimmer
*/
void event_log1(short event_log_level, const char *module_name,
    const char *log_info, ...);

/* This function logs errors.
Parameters:
@param error_log_level : ERROR_MINOR ERROR_MAJOR ERROR_FATAL
@param module_name :     the name of the module that received the event.
@param line_no :         the line number within above module.
@param log_info :        the info that is prInt32ed with the modulename.
@author     H�zlwimmer
*/
void error_log1(short error_log_level, const char *module_name, int line_no,
    const char *log_info, ...);

/* This function logs system call errors.
This function calls error_log.
Parameters:
@param error_log_level : ERROR_MINOR ERROR_MAJOR ERROR_FATAL
@param module_name :     the name of the module that received the event.
@param line_no :         the line number within above module.
@param errnumber :       the errno from systemlibrary.
@param log_info :        the info that is prInt32ed with the modulename and error text.
@author     H�zlwimmer
*/
void error_log_sys1(short error_log_level, const char *module_name,
    int line_no, short errnumber);

//<--------------------------------------------------------- timer --------------------------------------------->
typedef uchar boolean;
typedef uint32 TimerID;
#define TIMER_TYPE_INIT       0
#define   TIMER_TYPE_SHUTDOWN   1
#define   TIMER_TYPE_RTXM       3
#define   TIMER_TYPE_SACK       2
#define   TIMER_TYPE_CWND       4
#define   TIMER_TYPE_HEARTBEAT  5
#define   TIMER_TYPE_USER       6

//<--------------------------------------------------------- helpers --------------------------------------------->
struct internal_stream_data_t
{
    uint16 stream_id;
    uint16 stream_sn;
};
struct internal_data_chunk_t
{
    uint32 chunk_len;
    uint32 chunk_tsn; /* for efficiency */
    uchar data[MAX_PACKET_VALUE_SIZE];

    uint32 gap_reports;

    struct timeval transmission_time;
    /* ack_time : in msecs after transmission time, initially 0, -1 if retransmitted */
    int ack_time;
    uint32 num_of_transmissions;

    /* time after which chunk should not be retransmitted */
    struct timeval expiry_time;
    bool dontBundle;

    /* lst destination used to send chunk to */
    uint32 last_destination;
    int initial_destination;

    /* this is set to true, whenever chunk is sent/received on unreliable stream */
    bool isUnreliable;

    bool hasBeenAcked;
    bool hasBeenDropped;
    bool hasBeenFastRetransmitted;
    bool hasBeenRequeued;
    bool context;
};

/**
* helper functions that correctly handle overflowed issue.
* int溢出超出了int类型的最大值，如果是两个正数相加，溢出得到一个负数，
* 或两个负数相加，溢出得到一个正数的情况，就叫溢出。
* 或者两个整数相减，溢出得到与实际不相符的结果，都叫溢出问题
* 总结一下：
* 获取与编译器相关的int、char、long的最大值的方法分别为
* 　1） 使用头文件 <limits.h> 里面分别有关于最大、最小的char 、int、long的。
* 2） 分别将-1转换成对应的unsigned char 、unsigned int、unsigned long值
*/
bool safe_before(uint32 seq1, uint32 seq2);
bool safe_after(uint32 seq1, uint32 seq2);
bool safe_before(uint16 seq1, uint16 seq2);
bool safe_after(uint16 seq1, uint16 seq2);

// if s1 <= s2 <= s3
// @pre seq1 <= seq3
int safe_between(uint32 seq1, uint32 seq2, uint32 seq3);
// @pre make sure seq1 <= seq3
int unsafe_between(uint32 seq1, uint32 seq2, uint32 seq3);

/**
* compute IP checksum yourself. If packet does not have even packet boundaries,
* last byte will be set 0 and length increased by one. (should never happen in
* this SCTP implementation, since we always have 32 bit boundaries !
* Make sure the checksum is computed last thing before sending, and the checksum
* field is initialized to 0 before starting the computation
*/
uint16 in_check(uchar *buf, int sz);
int sort_ssn(const internal_stream_data_t& one,
    const internal_stream_data_t& two);
// function that correctly sorts TSN values, minding wrapround
int sort_tsn(const internal_data_chunk_t& one,
    const internal_data_chunk_t& two);

#endif /* MY_GLOBALS_H_ */