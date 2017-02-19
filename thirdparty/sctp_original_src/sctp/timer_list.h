/* $Id: timer_list.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef TIMER_LIST_H
#define TIMER_LIST_H

#ifdef HAVE_CONFIG_H
 #include <config.h>
#endif

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
#endif

#if (defined (SOLARIS) || defined (WIN32))
#define timeradd(a, b, result) \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                          \
    if ((result)->tv_usec >= 1000000)                                         \
      {                                                                       \
        ++(result)->tv_sec;                                                   \
        (result)->tv_usec -= 1000000;                                         \
      }                                                                       \
  } while (0)

#define timersub(a, b, result)                                                \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)

#endif

#include "globals.h"

/**
  *  A singly linked list for timer events
  */



typedef struct alarm_timer
{
    unsigned int timer_id;
    int timer_type;
/* the time when it is to go off */
    struct timeval action_time;
/* pointer to possible arguments */
    void *arg1;
    void *arg2;
/* the callback function 	*/
    void (*action) (TimerID, void *, void *);
/* arranged in a sorted, linked list	*/
}
AlarmTimer;
/**
 *	function to initialize a list. Creates a timer_list structure
 *	@param	new_list 	pointer to newly alloc'ed list structure
 *	@return	0 success, -1 for out of memory.
 */
void init_timer_list(void);

/**
 *	function to delete a list. Walks through the list and deallocates
 *	all timer_item structs. Finally destroys the timer_list struct
 *	@param	del_list	pointer to the timer_list struct to be deleted
 *	@return	0 on success, -1 if pointer was NULL or other error
 */
void del_timer_list(void);


/**
 *	this function inserts a timer_item into the list. Keeps it ordered,
 *	and updates length, and possibly one timeval entry. Checks whether
 *	we insert at beginning/end first. timer_item must have been alloc'ed
 *	first by the application, this is not done by this function !
 *	@param	tlist		pointer to the timer_list instance
 *	@param	item	pointer to the event item that is to be added
 *	@return	timer id  on success, 0 if a pointer was NULL or other error
 */
unsigned int insert_item(AlarmTimer * item);

/**
 *	a function to remove a certain action item, first checks current_item,
 *	then traverses the list from the start, updates length etc.
 *	@param	tlist		pointer to the timer_list instance
 *	@param	timer_id	id of the timer to be removed
 *	@param	item	pointer to where deleted data is to be copied !
 *	@return	0 on success, -1 if a pointer was NULL or other error, 1 if not found
 */
int remove_item(unsigned int id);

/**
 * same function, but remove timer by its pointer to the AlarmTimer
 * data structure. This is easier on the list
 */
int remove_timer(AlarmTimer* item);

/**
 *      function to be called, when a timer is reset. Basically calls get_item(),
 *    saves the function pointer, updates the execution time (msecs milliseconds
 *      from now) and removes the item from the list. Then calls insert_item
 *      with the updated timer_item struct.
 *      @param  tlist           pointer to the timer_list instance
 *      @param  timer_id        id of the timer to be updated
 *      @param  msecs           action to be executed msecs ms from _now_
 *      @return timer id
 */
unsigned int update_item(unsigned int id, unsigned int msecs);
unsigned int micro_update_item(unsigned int id, unsigned int seconds, unsigned int microseconds);

/*
 * function prototype from function in adaptation.h/.c
 * @return milliseconds up to the expiry of the next timer
 */
int get_msecs_to_nexttimer(void);


void adl_add_msecs_totime(struct timeval *t, unsigned int msecs);

void print_debug_list(short event_log_level);

/**
 * @return 1 (true) if list empty, 0 if list not empty
 */
int timer_list_empty(void);

/**
 * copies first event to where the pointer dest points to
 */
int get_next_event(AlarmTimer ** dest);

#endif
