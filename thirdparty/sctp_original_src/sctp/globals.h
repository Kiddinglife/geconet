/* $Id: globals.h 2771 2013-05-30 09:09:07Z dreibh $
 * --------------------------------------------------------------------------
 *
 *           //=====   //===== ===//=== //===//  //       //   //===//
 *          //        //         //    //    // //       //   //    //
 *         //====//  //         //    //===//  //       //   //===<<
 *              //  //         //    //       //       //   //    //
 *       ======//  //=====    //    //       //=====  //   //===//
 *
 * -------------- An SCTP implementation according to RFC 4960 --------------
 *
 * Copyright (C) 2000 by Siemens AG, Munich, Germany.
 * Copyright (C) 2001-2004 Andreas Jungmaier
 * Copyright (C) 2004-2013 Thomas Dreibholz
 *
 * Acknowledgements:
 * Realized in co-operation between Siemens AG and the University of
 * Duisburg-Essen, Institute for Experimental Mathematics, Computer
 * Networking Technology group.
 * This work was partially funded by the Bundesministerium fuer Bildung und
 * Forschung (BMBF) of the Federal Republic of Germany
 * (Förderkennzeichen 01AK045).
 * The authors alone are responsible for the contents.
 *
 * This library is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contact: sctp-discussion@sctp.de
 *          dreibh@iem.uni-due.de
 *          tuexen@fh-muenster.de
 *          andreas.jungmaier@web.de
 */

#ifndef GLOBALS_H
#define GLOBALS_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif


#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>


#ifdef  STDC_HEADERS
 #ifdef  HAVE_SYS_TIME_H
  #include <sys/time.h>
  #ifdef TIME_WITH_SYS_TIME
   #include <time.h>
  #endif
 #endif
 #ifdef  HAVE_UNISTD_H
  #include <unistd.h>
 #endif
#endif

#ifdef WIN32
#include <winsock2.h>
#include <time.h>
#endif

#ifdef FreeBSD
#include <netinet/in_systm.h>
#include <sys/types.h>
#endif

#ifdef SOLARIS
#include <netinet/in_systm.h>
#include <stdarg.h>
#endif


/* turn on  Posix 1g for compatible cmsg structure */
/* #ifdef USE_RFC2292BIS
     #define _XPG4_2
  #endif
*/

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "messages.h"

/* timer granularity in millliseconds..... */
#define GRANULARITY		1

/* Define a protocol id to be used in the IP Header..... */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP    132
#endif

/** this parameter specifies the maximum number of addresses that an endpoint may have */
#define MAX_NUM_ADDRESSES      32


#define SECRET_KEYSIZE  4096
#define KEY_INIT     0
#ifndef KEY_READ
#define KEY_READ     1
#endif
#define MAX_DEST 	16


/* Definition of levels for the logging of events */
#define ByteString_log_    0    /* set to != 0 if byte string logging should be done */

#define VVERBOSE           6    /* very verbose logging of events   */
#define VERBOSE            5    /* more verbose logging of events   */
#define INTERNAL_EVENT_0   4    /* pure execution flow trace */
#define INTERNAL_EVENT_1   3    /* important internal events */
#define EXTERNAL_EVENT     2    /* for events from ULP, peer or Timers */
#define EXTERNAL_EVENT_X   1    /* for unexpected external events from ULP, peer or Timers */


#define Current_event_log_ 0    /* Defines the level up to which the events are printed.
                                   VVERBOSE (6) means all events are printed.
                                   This parameter could also come from a command line option */

/* Definition of levels for the logging of errors */
#define ERROR_WARNING      4    /* warning, recovery not necessary. */
#define ERROR_MINOR        3    /* recovery from error was possible without affecting the system. */
#define ERROR_MAJOR        2    /* recovery from error was possible with some affects to the system,
                                   for instance abort of an association. */
#define ERROR_FATAL        1    /* recovery from error was not possible, the program exits. */

#define Current_error_log_ 1    /* Defines the level up to which the errors are printed.
                                   ERROR_WARNING (4) means all events are printed.
                                   This parameter could also come from a command line option */

typedef unsigned char boolean;
typedef unsigned int TimerID;

#define   TIMER_TYPE_INIT       0
#define   TIMER_TYPE_SHUTDOWN   1
#define   TIMER_TYPE_RTXM       3
#define   TIMER_TYPE_SACK       2
#define   TIMER_TYPE_CWND       4
#define   TIMER_TYPE_HEARTBEAT  5
#define   TIMER_TYPE_USER       6

typedef struct chunk_data_struct
{
    unsigned int chunk_len;
    unsigned int chunk_tsn;     /* for efficiency */
    unsigned char data[MAX_SCTP_PDU];
    unsigned int gap_reports;
    struct timeval transmission_time;
    /* ack_time : in msecs after transmission time, initially 0, -1 if retransmitted */
    int ack_time;
    unsigned int num_of_transmissions;
    /* time after which chunk should not be retransmitted */
    struct timeval expiry_time;
    gboolean dontBundle;
    /* lst destination used to send chunk to */
    unsigned int last_destination;
    int initial_destination;
    /* this is set to true, whenever chunk is sent/received on unreliable stream */
    gboolean isUnreliable;
    gboolean hasBeenAcked;
    gboolean hasBeenDropped;
    gboolean hasBeenFastRetransmitted;
    gboolean hasBeenRequeued;
    gpointer context;
} chunk_data;

#ifndef max
#define max(x,y)            ((x)>(y))?(x):(y)
#endif
#ifndef min
#define min(x,y)            ((x)<(y))?(x):(y)
#endif

#define event_log(x,y)        if (Current_event_log_ >= x) event_log1((x), __FILE__, (y))
#define event_logi(x,y,z)	  if (Current_event_log_ >= x) event_log1((x), __FILE__, (y), (z))
#define event_logii(x,y,z,i)	  if (Current_event_log_ >= x) event_log1((x), __FILE__, (y), (z), (i))
#define event_logiii(x,y,z,i,j)	  if (Current_event_log_ >= x) event_log1((x), __FILE__, (y), (z), (i), (j))
#define event_logiiii(x,y,z,i,j,k)	  if (Current_event_log_ >= x) event_log1((x), __FILE__, (y), (z), (i), (j),(k))
#define event_logiiiii(x,y,z,i,j,k,l)	  if (Current_event_log_ >= x) event_log1((x), __FILE__, (y), (z), (i), (j),(k),(l))
#define event_logiiiiiiii(x,y,z,i,j,k,l,m,n,o)	  if (Current_event_log_ >= x) event_log1((x), __FILE__, (y), (z), (i), (j),(k),(l),(m),(n),(o))


#define error_log(x,y)        if (Current_error_log_ >= x) error_log1((x), __FILE__, __LINE__, (y))
#define error_logi(x,y,z)        if (Current_error_log_ >= x) error_log1((x), __FILE__, __LINE__, (y),(z))
#define error_logii(x,y,z,i)        if (Current_error_log_ >= x) error_log1((x), __FILE__, __LINE__, (y),(z),(i))
#define error_logiii(x,y,z,i,j)        if (Current_error_log_ >= x) error_log1((x), __FILE__, __LINE__, (y),(z),(i),(j))
#define error_logiiii(x,y,z,i,j,k)        if (Current_error_log_ >= x) error_log1((x), __FILE__, __LINE__, (y),(z),(i),(j),(k))
#define error_log_sys(x,y)    error_log_sys1((x), __FILE__, __LINE__, (y))
#define DLL_error_log(x,y)    if (Current_error_log_ >= x) error_log1((x), __FILE__, __LINE__, (y))

#define IF_LOG(x, y)       if (x <= Current_error_log_) {y}
/* read_tracelevels reads from a file the tracelevels for errors and events for each module.
   Modules that are not listed in the file will not be traced. if the file does not exist or
   is empty, the global tracelevel defined in globals.h will be used.
   The format of the file is
   module1.c errorTraceLevel eventTraceLevel
   module2.c errorTraceLevel eventTraceLevel
   ....

   The file must be terminated by a null line.
*/
void read_tracelevels(void);


void debug_print(FILE * fd, const char *f, ...);

/**
 * function to output the result of the adl_gettime-call, i.e. the time now
 */
void print_time(short level);

/**
 * print the error string after a system call and exit
 */
void perr_exit(const char *infostring);


/* This function logs events.
   Parameters:
   @param event_log_level : INTERNAL_EVENT_0 INTERNAL_EVENT_1 EXTERNAL_EVENT_X EXTERNAL_EVENT
   @param module_name :     the name of the module that received the event.
   @param log_info :        the info that is printed with the modulename.
   @param anyno :           optional pointer to unsigned int, which is printed along with log_info.
                            The conversion specification must be contained in log_info.
   @author     H�zlwimmer
*/
void event_log1(short event_log_level, const char *module_name, const char *log_info, ...);



/* This function logs errors.
   Parameters:
   @param error_log_level : ERROR_MINOR ERROR_MAJOR ERROR_FATAL
   @param module_name :     the name of the module that received the event.
   @param line_no :         the line number within above module.
   @param log_info :        the info that is printed with the modulename.
   @author     H�zlwimmer
*/
void error_log1(short error_log_level, const char *module_name, int line_no, const char *log_info, ...);


/* This function logs system call errors.
   This function calls error_log.
   Parameters:
   @param error_log_level : ERROR_MINOR ERROR_MAJOR ERROR_FATAL
   @param module_name :     the name of the module that received the event.
   @param line_no :         the line number within above module.
   @param errnumber :       the errno from systemlibrary.
   @param log_info :        the info that is printed with the modulename and error text.
   @author     H�zlwimmer
*/
void error_log_sys1(short error_log_level, const char *module_name, int line_no, short errnumber);


/**
 * helper functions that correctly handle the 32bit wrapround
 */
int before(unsigned int seq1, unsigned int seq2);
int after(unsigned int seq1, unsigned int seq2);
int sAfter(unsigned short seq1, unsigned short seq2);
int sBefore(unsigned short seq1, unsigned short seq2);

/**
 *  is s1 <= s2 <= s3 ?
 */
int between(unsigned int seq1, unsigned int seq2, unsigned int seq3);

/**
 * compute IP checksum yourself. If packet does not have even packet boundaries,
 * last byte will be set 0 and length increased by one. (should never happen in
 * this SCTP implementation, since we always have 32 bit boundaries !
 * Make sure the checksum is computed last thing before sending, and the checksum
 * field is initialized to 0 before starting the computation
 */
unsigned short in_check(unsigned char *buf, int sz);


int sort_prChunk(pr_stream_data* one, pr_stream_data* two);

/*
 * function that correctly sorts TSN values, minding the
 * wrapround
 */
int sort_tsn(chunk_data * one, chunk_data * two);

void free_list_element(gpointer list_element, gpointer user_data);


/* shortcut macro to specify address field of struct sockaddr */
#define sock2ip(X)   (((struct sockaddr_in *)(X))->sin_addr.s_addr)
#ifdef HAVE_IPV6
    #define sock2ip6(X)  (((struct sockaddr_in6 *)(X))->sin6_addr.s6_addr)
    #define sock2ip6addr(X)  (((struct sockaddr_in6 *)(X))->sin6_addr)
#endif                          /* HAVE_IPV6 */

/* union for handling either type of addresses: ipv4 and ipv6 */
#ifndef SOCKUNION_DEFINE
#define SOCKUNION_DEFINE    1
union sockunion
{
    struct sockaddr sa;
    struct sockaddr_in sin;
#ifdef HAVE_IPV6
    struct sockaddr_in6 sin6;
#endif                          /* HAVE_IPV6 */
};

#endif  /* SOCKUNION_DEFINE */

#define sockunion_family(X)  (X)->sa.sa_family

#define SUPPORT_ADDRESS_TYPE_IPV4        0x00000001

#define SUPPORT_ADDRESS_TYPE_IPV6        0x00000002
#define SUPPORT_ADDRESS_TYPE_DNS         0x00000004

typedef enum {
      flag_HideLoopback           = (1 << 0),
      flag_HideLinkLocal          = (1 << 1),
      flag_HideSiteLocal          = (1 << 2),
      flag_HideLocal              = flag_HideLoopback|flag_HideLinkLocal|flag_HideSiteLocal,
      flag_HideAnycast            = (1 << 3),
      flag_HideMulticast          = (1 << 4),
      flag_HideBroadcast          = (1 << 5),
      flag_HideReserved           = (1 << 6),
      flag_Default                = flag_HideBroadcast|flag_HideMulticast|flag_HideAnycast,
      flag_HideAllExceptLoopback  = (1 << 7),
      flag_HideAllExceptLinkLocal = (1 << 8),
      flag_HideAllExceptSiteLocal = (1 << 9)
} AddressScopingFlags;


#define DEFAULT_MTU_CEILING     1500


#ifndef CHECK
#define CHECK(cond) if(!(cond)) { fprintf(stderr, "INTERNAL ERROR in %s, line %u: condition %s is not satisfied!\n", __FILE__, __LINE__, #cond); abort(); }
#endif

#endif
