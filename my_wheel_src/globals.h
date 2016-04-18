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
#define open_byte_string_log   false  /* set to != 0 if byte string logging should be done */

/* Definition of levels for the logging of events */
/* very verbose logging of events   */
#define loglvl_vverbos           6
/* more verbose logging of events   */
#define loglvl_verbose            5
/* pure execution flow trace */
#define loglvl_intevent   4
/* important inernal events */
#define loglvl_intevent_important  3
/* for events from ULP, peer or Timers */
#define loglvl_extevent   2
/* for unexpected external events from ULP, peer or Timers */
#define loglvl_extevent_unexpected 1
/* Defines the level up to which the events are prInt32ed.
VVERBOSE (6) means all events are prInt32ed.
This parameter could also come from a command line option */
#define current_event_loglvl 0

/* Definition of levels for the logging of errors */
/* warning, recovery not necessary. */
#define loglvl_warnning_error 4
/* recovery from error was possible without affecting the system. */
#define loglvl_minor_error  3
/*recovery from error was possible with some affects to the system,
* for instance abort of an association.*/
#define loglvl_major_error_abort  2
/* recovery from error was not possible, the program exits. */
#define loglvl_fatal_error_exit 1
/* Defines the level up to which the errors are prInt32ed.
*ERROR_WARNING (4) means all events are prInt32ed.
*This parameter could also come from a command line option*/
#define current_error_loglvl 1

#define event_log(x,y)\
if (current_event_loglvl >= x) event_log1((x), __FILE__, (y))
#define event_logi(x,y,z)\
if (current_event_loglvl >= x) event_log1((x), __FILE__, (y), (z))
#define event_logii(x,y,z,i)\
if (current_event_loglvl >= x) event_log1((x), __FILE__, (y), (z), (i))
#define event_logiii(x,y,z,i,j)\
if (current_event_loglvl >= x) event_log1((x), __FILE__, (y), (z), (i), (j))
#define event_logiiii(x,y,z,i,j,k)\
if (current_event_loglvl >= x) event_log1((x), __FILE__, (y), (z), (i), (j),(k))
#define event_logiiiii(x,y,z,i,j,k,l)\
if (current_event_loglvl >= x) event_log1((x), __FILE__, (y), (z), (i), (j),(k),(l))
#define event_logiiiiiiii(x,y,z,i,j,k,l,m,n,o)\
if (current_event_loglvl >= x) event_log1((x), __FILE__, (y), (z), (i), (j),(k),(l),(m),(n),(o))

#define error_log(x,y)  \
if (current_error_loglvl >= x) error_log1((x), __FILE__, __LINE__, (y))
#define error_logi(x,y,z)\
if (current_error_loglvl >= x) error_log1((x), __FILE__, __LINE__, (y),(z))
#define error_logii(x,y,z,i)   \
if (current_error_loglvl >= x) error_log1((x), __FILE__, __LINE__, (y),(z),(i))
#define error_logiii(x,y,z,i,j)     \
if (current_error_loglvl >= x) error_log1((x), __FILE__, __LINE__, (y),(z),(i),(j))
#define error_logiiii(x,y,z,i,j,k)    \
if (current_error_loglvl >= x) error_log1((x), __FILE__, __LINE__, (y),(z),(i),(j),(k))

#define error_log_sys(x,y)    \
error_log_sys1((x), __FILE__, __LINE__, (y))

#define DLL_error_log(x,y)    \
if (current_error_loglvl >= x) error_log1((x), __FILE__, __LINE__, (y))

#define IF_LOG(x, y)       \
if (x <= current_error_loglvl) {y}

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
extern void read_trace_levels(void);

extern void debug_print(FILE * fd, const char *f, ...);

/**
* function to output the result of the get_time_now-call, i.e. the time now
*/
extern void print_time_now(ushort level);

/**
* print the error string after a system call and exit
perror和strerror都是C语言提供的库函数，用于获取与erno相关的错误信息，区别不大，
用法也简单。最大的区别在于perror向stderr输出结果，而 strerror向stdout输出结果。
perror ( )用 来 将 上 一 个 函 数 发 生 错 误 的 原 因 输 出 到 标 准 设备 (stderr) 。
参数 s 所指的字符串会先打印出,后面再加上错误原因字符串。
此错误原因依照全局变量error 的值来决定要输出的字符串。　　
在库函数中有个error变量，每个error值对应着以字符串表示的错误类型。
当你调用"某些"函数出错时，该函数已经重新设置了error的值。
perror函数只是将你输入的一些信息和现在的error所对应的错误一起输出。
stderror 只向屏幕输出， 但是stdout可以被重定向到各种输出设备， 如文件 等
see http://www.cnblogs.com/zhangyabin---acm/p/3203745.html
http://blog.csdn.net/lalor/article/details/7555019
*/
extern void perr_exit(const char *infostring);

/* This function logs events.
Parameters:
@param event_loglvl : INTERNAL_EVENT_0 INTERNAL_EVENT_1 EXTERNAL_EVENT_X EXTERNAL_EVENT
@param module_name :     the name of the module that received the event.
@param log_info :        the info that is prInt32ed with the modulename.
@param anyno :           optional poInt32er to uint, which is prInt32ed along with log_info.
The conversion specification must be contained in log_info.
@author     H�zlwimmer
*/
extern void event_log1(short event_loglvl, const char *module_name,
    const char *log_info, ...);

/* This function logs errors.
Parameters:
@param error_loglvl : ERROR_MINOR ERROR_MAJOR ERROR_FATAL
@param module_name :     the name of the module that received the event.
@param line_no :         the line number within above module.
@param log_info :        the info that is prInt32ed with the modulename.
@author     H�zlwimmer
*/
extern void error_log1(short error_loglvl, const char *module_name, int line_no,
    const char *log_info, ...);

/* This function logs system call errors.
This function calls error_log.
Parameters:
@param error_loglvl : ERROR_MINOR ERROR_MAJOR ERROR_FATAL
@param module_name :     the name of the module that received the event.
@param line_no :         the line number within above module.
@param errnumber :       the errno from systemlibrary.
@param log_info :        the info that is prInt32ed with the modulename and error text.
@author     H�zlwimmer
*/
extern void error_log_sys1(short error_loglvl, const char *module_name,
    int line_no, short errnumber);

//<--------------------------------------------------------- timer --------------------------------------------->
typedef uchar boolean;
typedef uint TimerID;
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
    ushort stream_id;
    ushort stream_sn;
};
struct internal_data_chunk_t
{
    uint chunk_len;
    uint chunk_tsn; /* for efficiency */
    uchar data[MAX_PACKET_VALUE_SIZE];

    uint gap_reports;

    struct timeval transmission_time;
    /* ack_time : in msecs after transmission time, initially 0, -1 if retransmitted */
    int ack_time;
    uint num_of_transmissions;

    /* time after which chunk should not be retransmitted */
    struct timeval expiry_time;
    bool dontBundle;

    /* lst destination used to send chunk to */
    uint last_destination;
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
bool safe_before(uint seq1, uint seq2);
bool safe_after(uint seq1, uint seq2);
bool safe_before(ushort seq1, ushort seq2);
bool safe_after(ushort seq1, ushort seq2);

// if s1 <= s2 <= s3
// @pre seq1 <= seq3
bool safe_between(uint seq1, uint seq2, uint seq3);
// @pre make sure seq1 <= seq3
bool unsafe_between(uint seq1, uint seq2, uint seq3);

/**
* compute IP checksum yourself. If packet does not have even packet boundaries,
* last byte will be set 0 and length increased by one. (should never happen in
* this SCTP implementation, since we always have 32 bit boundaries !
* Make sure the checksum is computed last thing before sending, and the checksum
* field is initialized to 0 before starting the computation
*/
ushort in_check(uchar *buf, int sz);
int sort_ssn(const internal_stream_data_t& one,
    const internal_stream_data_t& two);
// function that correctly sorts TSN values, minding wrapround
int sort_tsn(const internal_data_chunk_t& one,
    const internal_data_chunk_t& two);

int gettimenow(struct timeval *tv);
int gettimenow(struct timeval *tv, struct tm *the_time);
#endif /* MY_GLOBALS_H_ */
