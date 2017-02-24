/* $Id: globals.c 2771 2013-05-30 09:09:07Z dreibh $
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

#include "globals.h"
#include "adaptation.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
        
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef WIN32
#include <process.h>
#endif


boolean globalTrace;
boolean fileTrace = FALSE;
FILE* logfile;
static int noOftracedModules;
static char tracedModules[50][70];
static int errorTraceLevel[50];
static int eventTraceLevel[50];

/**
 * helper function for sorting list of chunks in tsn order
 * @param  one pointer to chunk data
 * @param  two pointer to other chunk data
 * @return 0 if chunks have equal tsn, -1 if tsn1 < tsn2, 1 if tsn1 > tsn2
 */
int sort_tsn(chunk_data * one, chunk_data * two)
{
    if (before(one->chunk_tsn, two->chunk_tsn)) {
        return -1;
    } else if (after(one->chunk_tsn, two->chunk_tsn)) {
        return 1;
    } else                      /* one==two */
        return 0;
}

int sort_prChunk(pr_stream_data* one, pr_stream_data* two)
{
    if (one->stream_id < two->stream_id) {
        return -1;
    } else if (one->stream_id > two->stream_id) {
        return 1;
    } else  /* one.sid==two.sid */ {
        if (sBefore(one->stream_sn, two->stream_sn)) return -1;
        else if (sAfter(one->stream_sn, two->stream_sn)) return 1;
    }
    return 0;
}


/**
   read_tracelevels reads from a file the tracelevels for errors and events for each module.
   Modules that are not listed in the file will not be traced. if the file does not exist or
   is empty, the global tracelevel defined in globals.h will be used. THe name of the file has
   to be {\texttt tracelevels.in} in the current directory where the executable is located.
   The normal format of the file is:
   \begin{verbatim}
   module1.c errorTraceLevel eventTraceLevel
   module2.c errorTraceLevel eventTraceLevel
   ....
   \end{verbatim}
   The file must be terminated by a null line.
    Alternatively there may be the entry
   \begin{verbatim}
    LOGFILE
   \end{verbatim}
    in that file, which causes all output from event_logs() to go into a logfile in the local
    directory.
*/
void read_tracelevels()
{
    FILE *fptr;
    int i;
    char filename[100];

    noOftracedModules = 0;
    fptr = fopen("./tracelevels.in", "r");

    if (fptr != NULL) {
        globalTrace = TRUE;

        for (i = 0; i < 50; i++) {
            if(fscanf(fptr, "%s %d %d", tracedModules[i], &errorTraceLevel[i], &eventTraceLevel[i]) >= 1) {
               if (strcmp(tracedModules[i], "LOGFILE") == 0) {
                   /*
                   printf("Logging all errors and events to file ./tmp%d.log\n", (int)getpid());
                   */
                   fileTrace = TRUE;
                   sprintf(filename, "./tmp%d.log",(int)getpid());
                   logfile = fopen(filename, "w+");
                   return;
               }
            }
            if (ferror(fptr))
                abort();
            if (feof(fptr))
                break;
            globalTrace = FALSE;
        }
        noOftracedModules = i;
        if (i<= 1) globalTrace = TRUE;
        /*
        printf("  globalTrace = %s \n",  (globalTrace==TRUE)?"TRUE":"FALSE");
        */
    } else {
        globalTrace = TRUE; /* ??? */
    }
    /*
    printf("global = %d, #of modules = %d\n", (int) globalTrace, noOftracedModules);
    for (i = 0; i < noOftracedModules; i++)
      printf("%20s %2d %2d\n", tracedModules[i], errorTraceLevel[i], eventTraceLevel[i]);
    */
}



boolean traceModule(const char *moduleName, int *moduleIndex)
{
    int i;
    boolean found;

    found = FALSE;

    for (i = 0; i < noOftracedModules; i++)
        if (!strcmp(tracedModules[i], moduleName)) {
            found = TRUE;
            break;
        }

    *moduleIndex = i;

    return found;
}




int debug_vwrite(FILE * fd, const char *format, va_list ap)
{
    struct timeval tv;
    struct tm *the_time;

    adl_gettime(&tv);
    the_time = localtime((time_t *) & (tv.tv_sec));

    if (fprintf(fd, "%02d:%02d:%02d.%03d - ",
                the_time->tm_hour,
                the_time->tm_min, the_time->tm_sec, (int) (tv.tv_usec / 1000)) < 1)
        return (-1);
    if (vfprintf(fd, format, ap) < 1)
        return (-1);
    return (0);
}


void debug_print(FILE * fd, const char *f, ...)
{
    va_list va;
    va_start(va, f);
    debug_vwrite(fd, f, va);
    va_end(va);
    fflush(fd);
    return;
}



void perr_exit(const char *infostring)
{
    perror(infostring);
    abort();
}


void print_time(short level)
{
    struct timeval now;

    adl_gettime(&now);
    event_logii(level, "Time now: %ld sec, %ld usec \n", now.tv_sec, now.tv_usec);
}



/**
  This function logs events.
   @param event_log_level  INTERNAL_EVENT_0 INTERNAL_EVENT_1 EXTERNAL_EVENT_X EXTERNAL_EVENT
   @param module_name      the name of the module that received the event.
   @param log_info         the info that is printed with the modulename.
   @param anyno            optional pointer to unsigned int, which is printed along with log_info.
                            The conversion specification must be contained in log_info.
*/
void event_log1(short event_log_level, const char *module_name, const char *log_info, ...)
{
    int mi;
    struct timeval tv;
    struct tm *the_time;

    va_list va;

    va_start(va, log_info);

    if ((globalTrace && event_log_level <= Current_event_log_) ||
        (!globalTrace && traceModule(module_name, &mi)
         && event_log_level <= eventTraceLevel[mi])) {

        if (event_log_level < VERBOSE) {
            if (fileTrace == TRUE) {
                debug_print(logfile, "Event in Module: %s............\n", module_name);
            } else {
                debug_print(stdout, "Event in Module: %s............\n", module_name);
            }
        }
        adl_gettime(&tv);
        the_time = localtime((time_t *) & (tv.tv_sec));
        if (fileTrace == TRUE) {
            fprintf(logfile, "%02d:%02d:%02d.%03d - ",
                    the_time->tm_hour, the_time->tm_min, the_time->tm_sec, (int) (tv.tv_usec / 1000));
            vfprintf(logfile, log_info, va);
            fprintf(logfile, "\n");
            fflush(logfile);
        } else {
            fprintf(stdout, "%02d:%02d:%02d.%03d - ",
                    the_time->tm_hour, the_time->tm_min, the_time->tm_sec, (int) (tv.tv_usec / 1000));
            vfprintf(stdout, log_info, va);
            fprintf(stdout, "\n");
            fflush(stdout);
        }
    }
    va_end(va);
    return;
}




/**
   This function logs errors.
   @param error_log_level  ERROR_MINOR ERROR_MAJOR ERROR_FATAL
   @param module_name      the name of the module that received the event.
   @param line_no          the line number within above module.
   @param log_info         the info that is printed with the modulename.
   @param anyno            optional pointer to unsigned int, which is printed along with log_info.
                           The conversion specification must be contained in log_info.

*/
void error_log1(short error_log_level, const char *module_name, int line_no, const char *log_info, ...)
{
    int mi;
    va_list va;

    va_start(va, log_info);

    if ((globalTrace && error_log_level <= Current_error_log_) ||
        (!globalTrace && traceModule(module_name, &mi)
         && error_log_level <= eventTraceLevel[mi])) {
        if (fileTrace == TRUE) {
            if (error_log_level > ERROR_MINOR)
            debug_print(logfile,
                        "+++++++++++++++  Error (Level %2d) in %s at line %d  +++++++++++++++++++\n",
                        error_log_level, module_name, line_no);
            fprintf(logfile, "Error Info: ");
            debug_vwrite(logfile, log_info, va);
            fprintf(logfile, "\n");
        } else {
            if (error_log_level > ERROR_MINOR)
            debug_print(stderr,
                        "+++++++++++++++  Error (Level %2d) in %s at line %d  +++++++++++++++++++\n",
                        error_log_level, module_name, line_no);
            fprintf(stderr, "Error Info: ");
            debug_vwrite(stderr, log_info, va);
            fprintf(stderr, "\n");
        }
    }
    va_end(va);
    if (fileTrace == TRUE) {
       fflush(logfile);
    } else {
       fflush(stderr);
    }
    if (error_log_level == ERROR_FATAL) {
        abort();
    }
}

/**
   This function logs system call errors. It calls error_log.
   @param error_log_level  ERROR_MINOR ERROR_MAJOR ERROR_FATAL
   @param module_name      the name of the module that received the event.
   @param line_no          the line number within above module.
   @param errnumber        the errno from systemlibrary.
   @param log_info         the info that is printed with the modulename and error text.
*/
void error_log_sys1(short error_log_level, const char *module_name, int line_no, short errnumber)
{
    error_log1(error_log_level, module_name, line_no, strerror(errnumber));
}


/**
 * functions correctly handle wraparound
 */
int before(unsigned int seq1, unsigned int seq2)
{
    return (int) (seq1 - seq2) < 0;
}

int after(unsigned int seq1, unsigned int seq2)
{
    return (int) (seq2 - seq1) < 0;
}

int sAfter(unsigned short seq1, unsigned short seq2)
{
    return (int)((short)(seq2 - seq1)) < 0;
}

int sBefore(unsigned short seq1, unsigned short seq2)
{
    return (int)((short) (seq1 - seq2) < 0);
}



/**
 *  is s1 <= s2 <= s3 ?
 */
int between(unsigned int seq1, unsigned int seq2, unsigned int seq3)
{
    return seq3 - seq1 >= seq2 - seq1;
}

void free_list_element(gpointer list_element, gpointer user_data)
{
    chunk_data * chunkd = (chunk_data*) list_element;

    if (user_data == NULL) {
        if (list_element != NULL) free (list_element);
        return;
    } else if (GPOINTER_TO_INT(user_data) == 1) {   /* call from flowcontrol */
        if (list_element != NULL) {
           if (chunkd->num_of_transmissions == 0) free (list_element);
        }
    } else if (GPOINTER_TO_INT(user_data) == 2) {   /* call from reltransfer */
        if (list_element != NULL) {
           if (chunkd->num_of_transmissions != 0) free (list_element);
        }
    }
}
