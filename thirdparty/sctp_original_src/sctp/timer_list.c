/* $Id: timer_list.c 2771 2013-05-30 09:09:07Z dreibh $
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

#include "timer_list.h"
#include "adaptation.h"

#include <stdio.h>
#include <glib.h>

static unsigned int tid = 1;
static GList* timer_list = NULL;


/**
 *	function to initialize a list. Creates a timer_list structure
 *	@param	new_list 	pointer to newly alloc'ed list structure
 */
void init_timer_list()
{
    if (timer_list != NULL) error_log(ERROR_FATAL, "init_timer_list() should not have been called -> fix program");
    timer_list = NULL;
}



gint timercompare(gconstpointer a, gconstpointer b)
{
    AlarmTimer *one, *two;

    one = (AlarmTimer *) a;
    two = (AlarmTimer *) b;
    if (timercmp(&(one->action_time), &(two->action_time), ==))
        return 0;
    else if timercmp
        (&(one->action_time), &(two->action_time), <)return -1;
    else if timercmp
        (&(one->action_time), &(two->action_time), >)return 1;
    /* never reached   */
    return 0;
}


int idcompare(gconstpointer a, gconstpointer b)
{
    AlarmTimer *one;
    unsigned int *two;

    one = (AlarmTimer *) a;
    two = (unsigned int *) b;

    if (one->timer_id == *two)
        return 0;
    else if (one->timer_id < *two)
        return -1;
    else if (one->timer_id > *two)
        return 1;
    /* never reached */
    return 0;
}


/**
 *	function to delete a list. Walks through the list and deallocates
 *	all timer_item structs. Finally destroys the timer_list struct
 *	@param	del_list	pointer to the timer_list struct to be deleted
 *	@return	0 on success, -1 if pointer was NULL or other error
 */
void del_timer_list(void)
{
    g_list_foreach(timer_list, &free_list_element, NULL);
    g_list_free(timer_list);
}



/**
 *	this function inserts a timer_item into the list. Keeps it ordered,
 *	and updates length, and possibly one timeval entry. Checks whether
 *	we insert at beginning/end first. timer_item must have been alloc'ed
 *	first by the application, this is not done by this function !
 *	@param	tlist		pointer to the timer_list instance
 *	@param	item	pointer to the event item that is to be added
 *	@return	timer_id on success, 0 if a pointer was NULL or other error
 */
unsigned int insert_item(AlarmTimer * item)
{

    item->timer_id = tid++;

    event_logi(VERBOSE, "Insert item : timer id %u ", item->timer_id);

    if (item->timer_id == 0) {
        tid++;
        item->timer_id = 1;
    }
    timer_list = g_list_insert_sorted(timer_list, item, timercompare);

    /* print_debug_list(VERBOSE); */

    return item->timer_id;
}


/**
 *	a function to remove a certain action item,
 *	then traverses the list from the start, updates length etc.
 *	@param	tlist		pointer to the timer_list instance
 *	@param	tid	id of the timer to be removed
 *	@param	item	pointer to where deleted data is to be copied !
 *	@return	0 on success, -1 if a pointer was NULL or other error, -1 if not found
 */
int remove_item(unsigned int id)
{
    GList* tmp=NULL;
    gpointer dat;

    event_logi(VERBOSE, "Remove item : timer id %u called", id);

    tmp = g_list_find_custom(timer_list, &id, idcompare);

    if (tmp != NULL) {
        event_logi(VERBOSE, "Remove item : found timer id %u", ((AlarmTimer*)(tmp->data))->timer_id);
    } else {
        event_logi(VERBOSE, "Remove item : did NOT find timer id %u", id);
    }

    if (tmp == NULL) return -1;

    dat = tmp->data;
    free_list_element(dat, NULL);
    timer_list=g_list_remove(timer_list, dat);

    /* print_debug_list(VERBOSE); */

    return 0;
}

int remove_timer(AlarmTimer* item)
{
    if (item == NULL) return -1;

    event_logi(VERBOSE, "Remove item : timer id %u called", item->timer_id);

    timer_list=g_list_remove(timer_list, item);
    free_list_element(item, NULL);
    /* print_debug_list(VERBOSE); */

    return 0;
}

/**
 *	a function to get the pointer to a certain action item, traverses the list
 *    copies the item into the provided pointer (reserve enough space !!)
 *	@param	tlist		pointer to the timer_list instance
 *	@param	timer_id	id of the timer to be found
 *	@param	item	pointer to where found data is to be copied !
 *	@return	0 on success, -1 if a pointer was NULL or other error
 */
/*int get_item(unsigned int id, AlarmTimer * item)
{

    GList* result=NULL;
    result=g_list_find(timer_list,item);
    if (result!=NULL)
     	return 0;

   	error_log(ERROR_FATAL, "No valid result in  get_item !\n");
    return -1;
}
*/

/**
 *      function to be called, when a timer is reset. Basically calls get_item(),
 *    saves the function pointer, updates the execution time (msecs milliseconds
 *      from now) and removes the item from the list. Then calls insert_item
 *      with the updated timer_item struct.
 *      @param  tlist           pointer to the timer_list instance
 *      @param  id                      id of the timer to be updated
 *      @param  msecs           action to be executed msecs ms from _now_
 *      @return new timer_id, 0 if a pointer was NULL or other error
 */
unsigned int update_item(unsigned int id, unsigned int msecs)
{
    AlarmTimer* tmp_item;
    GList* tmp=NULL;

    event_logi(VERBOSE, "Update item : timer id %u called", id);

    if (timer_list == NULL)  return 0;

    tmp = g_list_find_custom(timer_list, &id, idcompare);

    if (tmp != NULL){
        event_logi(VERBOSE, "Update item : found timer id %u", ((AlarmTimer*)(tmp->data))->timer_id);
    } else {
        event_logi(VERBOSE, "Update item : did NOT find timer id %u", id);
    }

    if (tmp == NULL) return 0;

    tmp_item = (AlarmTimer*)tmp->data;
    timer_list = g_list_remove(timer_list, tmp->data);

    /* update action time, and  write back to the list */
    adl_gettime(&(tmp_item->action_time));
    adl_add_msecs_totime(&(tmp_item->action_time), msecs);

    /* print_debug_list(VERBOSE); */

    return (insert_item(tmp_item));
}

unsigned int micro_update_item(unsigned int id, unsigned int seconds, unsigned int microseconds)
{
    AlarmTimer* tmp_item;
    GList* tmp=NULL;
    struct timeval delta, now;

    event_logi(VERBOSE, "Micro-Update item : timer id %u called", id);

    if (timer_list == NULL)  return 0;

    tmp = g_list_find_custom(timer_list, &id, idcompare);

    if (tmp != NULL){
        event_logi(VERBOSE, "Micro-Update item : found timer id %u", ((AlarmTimer*)(tmp->data))->timer_id);
    } else {
        event_logi(VERBOSE, "Micro-Update item : did NOT find timer id %u", id);
    }

    if (tmp == NULL) return 0;

    tmp_item = (AlarmTimer*)tmp->data;
    timer_list = g_list_remove(timer_list, tmp->data);
    delta.tv_sec = seconds;
    delta.tv_sec += (microseconds / 1000000); /* usually 0 */
    delta.tv_usec = (microseconds % 1000000); /* usually == microseconds */

    /* update action time, and  write back to the list */
    adl_gettime(&now);
    timeradd(&now, &delta, &(tmp_item->action_time));

    /* print_debug_list(VERBOSE); */

    return (insert_item(tmp_item));
}


void print_item_info(short event_log_level, AlarmTimer * item)
{
    const char* ttype;

    switch(item->timer_type) {
        case TIMER_TYPE_INIT: ttype = "Init Timer";
            break;
        case TIMER_TYPE_SACK: ttype = "SACK Timer";
            break;
        case TIMER_TYPE_RTXM: ttype = "T3 RTX Timer";
            break;
        case TIMER_TYPE_SHUTDOWN: ttype = "Shutdown Timer";
            break;
        case TIMER_TYPE_CWND : ttype = "CWND Timer";
            break;
        case TIMER_TYPE_HEARTBEAT: ttype = "HB Timer";
            break;
        case TIMER_TYPE_USER: ttype = "User Timer";
            break;
        default:  ttype = "Unknown Timer";
            break;
    }
    event_logii(event_log_level, "TimerID: %d, Type : %s", item->timer_id, ttype);
    event_logii(event_log_level, "action_time: %ld sec, %ld usec\n",
                item->action_time.tv_sec, item->action_time.tv_usec);
}

void print_debug_list(short event_log_level)
{
    GList* tmp=NULL;
    unsigned int  j, i;

    if (event_log_level <= Current_event_log_) {
        event_log(event_log_level,"-------------Entering print_debug_list() ------------------------");
        if (timer_list == NULL) {
            event_log(event_log_level, "tlist pointer == NULL");
            return;
        }

        tmp=g_list_first(timer_list);

        if (tmp==NULL) {
            event_log(event_log_level, "Timer-List is empty !");
            return;
        }
        print_time(event_log_level);
        j=g_list_length(timer_list);
        event_logi(event_log_level, "List Length : %u ", j);

        for (i=0; i < j; i++)
        {
            print_item_info(event_log_level, (AlarmTimer*)tmp->data);
            tmp = g_list_next(tmp);
        }
        event_log(event_log_level,"-------------Leaving print_debug_list() ------------------------");
    }
    return;
}


/**
* the semantics of this function :
* @return -1 if no timer in list, 0 if timeout and action must be taken, else time to
           next eventin milliseconds....
*/
int get_msecs_to_nexttimer()
{
    long secs, usecs;
    GList* result=NULL;
    int msecs;
    AlarmTimer* next;
    struct timeval now;

    result = g_list_first(timer_list);

    if (result == NULL) return -1;

    adl_gettime(&now);
    next = (AlarmTimer*)result->data;

    secs = next->action_time.tv_sec - now.tv_sec;
    usecs = next->action_time.tv_usec - now.tv_usec;

    if (secs < 0)  return 0;

    if (usecs < 0) {
        secs--;
        usecs += 1000000;
    }

    if (secs < 0) return 0;

    /* here we will be cutting of the rest..... */
    msecs = (int) (1000 * secs + usecs / 1000);
    return (msecs);
}

int get_next_event(AlarmTimer ** dest)
{
    GList* result=NULL;
    *dest = NULL;

    if (g_list_first(timer_list) == NULL) return -1;
    result = g_list_first(timer_list);
    *dest = (AlarmTimer*)result->data;

    return 0;
}


int timer_list_empty()
{
    if (g_list_first(timer_list) == NULL)
        return 1;
    else
        return 0;
}
