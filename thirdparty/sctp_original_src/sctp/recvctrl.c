/* $Id: recvctrl.c 2771 2013-05-30 09:09:07Z dreibh $
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

#include "recvctrl.h"
#include "adaptation.h"
#include "bundling.h"
#include "distribution.h"
#include "streamengine.h"
#include "SCTP-control.h"

#include <glib.h>
#include <string.h>

/**
 * this struct contains all necessary data for creating SACKs from received data chunks
 */
typedef struct rxc_buffer_struct
{
    /*@{ */
    /** */
    void *sack_chunk;
    /** */
    GList *frag_list;
    /** */
    GList *dup_list;
    /** cumulative TSN acked */
    unsigned int ctsna;
    /** store lowest tsn value for dups (!) */
    unsigned int lowest;
    /** stores highest tsn received so far, taking care of wraps
        i.e. highest < lowest indicates a wrap */
    unsigned int highest;
    /** */
    boolean contains_valid_sack;
    /** */
    boolean timer_running;
    /** indicates whether a chunk was recvd that is truly new */
    boolean new_chunk_received;
    /** timer for delayed sacks */
    TimerID sack_timer;
    int datagrams_received;
     /* either 1 (= sack each data chunk) or 2 (=sack every second chunk)*/
    unsigned int sack_flag;
    /** */
    unsigned int last_address;
    /** */
    unsigned int my_association;
    /** */
    unsigned int my_rwnd;
    /** delay for delayed ACK in msecs */
    unsigned int delay;
    /** number of dest addresses */
    unsigned int num_of_addresses;
    /*@} */
} rxc_buffer;


/**
 * function creates and allocs new rxc_buffer structure.
 * There is one such structure per established association
 * @param  remote_initial_TSN initial tsn of the peer
 * @return pointer to the newly created structure
 */
void *rxc_new_recvctrl(unsigned int remote_initial_TSN, unsigned int number_of_destination_addresses, void* sctpInstance)
{
    rxc_buffer *tmp;
/*
    unsigned int count;
*/
    tmp = (rxc_buffer*)malloc(sizeof(rxc_buffer));
    if (!tmp) error_log(ERROR_FATAL, "Malloc failed");

    tmp->frag_list = NULL;
    tmp->dup_list = NULL;
    tmp->num_of_addresses = number_of_destination_addresses;
    tmp->sack_chunk = malloc(sizeof(SCTP_sack_chunk));
    tmp->ctsna = remote_initial_TSN - 1; /* as per section 4.1 */
    tmp->lowest = remote_initial_TSN - 1;
    tmp->highest = remote_initial_TSN - 1;
    tmp->contains_valid_sack = FALSE;
    tmp->timer_running = FALSE;
    tmp->datagrams_received = -1;
    tmp->sack_flag = 2;
    tmp->last_address = 0;
    tmp->my_rwnd =  mdi_getDefaultMyRwnd();
    tmp->delay =    mdi_getDefaultDelay(sctpInstance);
    tmp->my_association = mdi_readAssociationID();
    event_logi(VVERBOSE, "RecvControl : Association-ID== %d ", tmp->my_association);
    if (tmp->my_association == 0)
        error_log(ERROR_FATAL, "Association was not set, should be......");
    return (tmp);
}

/**
 * function deletes a rxc_buffer structure (when it is not needed anymore)
 * @param rxc_instance pointer to a rxc_buffer, that was previously created
 */
void rxc_delete_recvctrl(void *rxc_instance)
{
    rxc_buffer *tmp;
    tmp = (rxc_buffer *) rxc_instance;
    event_log(INTERNAL_EVENT_0, "deleting receivecontrol");
    free(tmp->sack_chunk);

    if (tmp->timer_running == TRUE) {
        sctp_stopTimer(tmp->sack_timer);
        tmp->timer_running = FALSE;
    }

    g_list_foreach(tmp->frag_list, &free_list_element, NULL);
    g_list_free(tmp->frag_list);
    g_list_foreach(tmp->dup_list, &free_list_element, NULL);
    g_list_free(tmp->dup_list);
    free(tmp);
}


/**
 * function to find out, whether a chunk is duplicate or not
 * @param rbuf	instance of rxc_buffer
 * @param chunk_tsn	tsn we just received
 * @return the boolean response
 */
boolean rxc_chunk_is_duplicate(rxc_buffer * rbuf, unsigned int chunk_tsn)
{
    unsigned int low = rbuf->lowest;
    unsigned int hi = rbuf->highest;
    unsigned int ctsna = rbuf->ctsna;
    fragment32 *frag;
    GList *temp = NULL;

    /* Assume, lowest and highest have already been updated */
    if (between(low, chunk_tsn, ctsna))
        return TRUE;
    if (!between(ctsna, chunk_tsn, hi))
        return FALSE;

    /* Now check, whether chunk_tsn is in the (sorted !) list of fragments */
    if (rbuf->frag_list == NULL) /* no fragments ! */
        return FALSE;

    /* if we are still here, we need to check, whether chunk_tsn is between any fragment bounds */
    temp = g_list_first(rbuf->frag_list);
    while (temp != NULL) {
        if (temp->data == NULL) {
            error_log(ERROR_FATAL, "LIST ERROR rxc_chunk_is_duplicate(2)");
            temp = g_list_next(temp);
            continue;
        }
        frag = (fragment32*) temp->data;
        if (between(frag->start_tsn, chunk_tsn, frag->stop_tsn))
            return TRUE;
        /* assuming an ordered list of fragments */
        if (after(frag->stop_tsn, chunk_tsn))
           return FALSE;
        temp = g_list_next(temp);
    }
    /* never reached */
    error_log(ERROR_MAJOR, "while loop went past end of list....should not have happened !");
    return FALSE;
}

/**
 * Helper function to do the correct update of rxc->lowest
 * Function is only called, if that is necessary !
 * @param rbuf	instance of rxc_buffer
 * @param chunk_tsn	tsn we just received
 * @return boolean indicating whether lowest was updated or not
 */
boolean rxc_update_lowest(rxc_buffer * rbuf, unsigned int chunk_tsn)
{
    unsigned int low = rbuf->lowest;
    if (before(chunk_tsn, low)) {
        rbuf->lowest = chunk_tsn;
        /* and it must be a duplicate ! */
        return TRUE;
    } else
        return FALSE /* no update of lowest */ ;
}

/**
 * Helper function to do the correct update of rxc->highest
 * Function is only called, if that is necessary !
 * @param rbuf	instance of rxc_buffer
 * @param chunk_tsn	tsn we just received
 * @return boolean indicating whether highest was updated or not
 */
boolean rxc_update_highest(rxc_buffer * rbuf, unsigned int chunk_tsn)
{
    unsigned int hi = rbuf->highest;
    if (after(chunk_tsn, hi)) {
        rbuf->highest = chunk_tsn;
        return TRUE;
    } else
        return FALSE /* no update of highest */ ;
}

int rxc_sort_duplicates(duplicate * one, duplicate * two)
{
    if (before(one->duplicate_tsn, two->duplicate_tsn)) {
        return -1;
    } else if (after(one->duplicate_tsn, two->duplicate_tsn)) {
         return 1;
    } else                      /* one==two */
        return 0;
}

int rxc_sort_fragments(fragment32 * one, fragment32 * two)
{
    if (before(one->start_tsn, two->start_tsn) && before(one->stop_tsn, two->stop_tsn)) {
        return -1;
    } else if (after(one->start_tsn, two->start_tsn) && after(one->stop_tsn, two->stop_tsn)) {
         return 1;
    } else                      /* one==two */
        return 0;
}


/**
 * Helper function for inserting chunk_tsn in the list of duplicates
 * @param rbuf	instance of rxc_buffer
 * @param chunk_tsn	tsn we just received
 */
void rxc_update_duplicates(rxc_buffer * rbuf, unsigned int ch_tsn)
{
    duplicate* match;
    GList* current = NULL;

    current = g_list_first(rbuf->dup_list);
    while (current != NULL) {
        match = (duplicate*)current->data;
        if (ch_tsn == match->duplicate_tsn) return;
        current = g_list_next(current);
    }
    /* its new - add it to the list */
    match = (duplicate*)malloc(sizeof(duplicate));
    match->duplicate_tsn = ch_tsn;
    rbuf->dup_list =  g_list_insert_sorted(rbuf->dup_list, match, (GCompareFunc) rxc_sort_duplicates);

}



/**
 * Helper function to do the correct update of rxc->ctsna
 * @param rbuf	instance of rxc_buffer
 * @param chunk_tsn	tsn we just received
 */
void rxc_bubbleup_ctsna(rxc_buffer * rbuf)
{
    fragment32 *frag;
    GList *temp = NULL, *old = NULL;

    event_log(INTERNAL_EVENT_0, "Entering rxc_bubbleup_ctsna... ");

    if (rbuf->frag_list == NULL) return;

    temp = g_list_first(rbuf->frag_list);

    while (temp != NULL) {
        frag = (fragment32*)temp->data;
        if (frag != NULL){
            if (rbuf->ctsna + 1 == frag->start_tsn) {
                rbuf->ctsna = frag->stop_tsn;
                old = temp;
                temp = g_list_next(temp);
                rbuf->frag_list = g_list_remove_link(rbuf->frag_list, old);
                g_list_free_1(old); free(frag);
            }
            else
                return;
        } else {
            error_log(ERROR_FATAL, "rxc_bubbleup_ctsna: fragment data was NULL !!!!!!! ");
            return;
        }
    }  /* end while */
}

boolean rxc_update_fragments(rxc_buffer * rbuf, unsigned int ch_tsn)
{
    unsigned int lo, hi, gapsize;
    fragment32 *frag=NULL, *new_frag, * lo_frag;
    GList *current = NULL, *tmp = NULL;

    event_logi(INTERNAL_EVENT_0, "Entering rxc_update_fragments.tsn==%u.. ", ch_tsn);

    lo = rbuf->ctsna + 1;

    current = g_list_first(rbuf->frag_list);

    while (current != NULL) {
        frag = (fragment32*)current->data;

        hi = frag->start_tsn - 1;
        event_logiii(VVERBOSE, "while-loop: lo=%u, tsn=%u, hi=%u, \n", lo, ch_tsn, hi);

        if (between(lo, ch_tsn, hi)) {
            gapsize = hi - lo + 1;
            if (gapsize > 1) {
                event_logi(INTERNAL_EVENT_0, "Value of Gapsize (should be > 1 :) ", gapsize);
                if (ch_tsn == hi) {
                    event_log(VVERBOSE, "ch_tsn==hi....");
                    frag->start_tsn = ch_tsn;
                    rbuf->new_chunk_received = TRUE;
                    return TRUE;
                } else if (ch_tsn == lo) {
                    event_logii(VVERBOSE, "ch_tsn==lo==%u....rbuf->ctsna==%u....", lo, rbuf->ctsna);
                    if (ch_tsn == (rbuf->ctsna + 1)) {
                        rbuf->ctsna++;
                        rbuf->new_chunk_received = TRUE;
                        return TRUE;
                    }
                    current = g_list_previous(current);
                    if (current==NULL) {
                        error_log(ERROR_MAJOR, "Error in Fragment List HANDLING - check program");
                        return FALSE;
                    }
                    frag = (fragment32*)current->data;
                    frag->stop_tsn = ch_tsn;
                    rbuf->new_chunk_received = TRUE;
                    return TRUE;
                } else {    /* a fragment in between */
                    new_frag = (fragment32*)malloc(sizeof(fragment32));
                    new_frag->start_tsn = new_frag->stop_tsn = ch_tsn;
                    event_log(VVERBOSE, "Inserting new fragment....");
                    rbuf->frag_list = g_list_insert_sorted(rbuf->frag_list, new_frag, (GCompareFunc) rxc_sort_fragments);
                    rbuf->new_chunk_received = TRUE;
                    return FALSE;
                }
            } else {        /*gapsize == 1 */
                event_logi(INTERNAL_EVENT_0, "Value of Gapsize (should be 1 :) %u", gapsize);
                /* delete fragment, return TRUE */
                if (lo == rbuf->ctsna + 1) {
                    rbuf->ctsna = frag->stop_tsn;
                    rbuf->frag_list = g_list_remove_link(rbuf->frag_list, current);
                    g_list_free_1(current); free(frag);
                    rbuf->new_chunk_received = TRUE;
                    return TRUE;
                } else {
                    tmp = current;
                    current = g_list_previous(current);
                    if (current == NULL) {
                        error_log(ERROR_MAJOR, "Error 2 in Fragment List HANDLING - check program");
                        return FALSE;
                    }
                    lo_frag = (fragment32*)current->data;
                    frag->start_tsn = lo_frag->start_tsn;
                    rbuf->frag_list = g_list_remove_link(rbuf->frag_list, current);
                    g_list_free_1(current); free(lo_frag);
                    current = tmp;
                    rbuf->new_chunk_received = TRUE;
                    return TRUE;
                }
            }
        } else {            /* ch_tsn is not in the gap between these two fragments */
            lo = frag->stop_tsn + 1;
            event_logi(VVERBOSE, "rxc_update_fragments: Setting lo to %u ", lo);
        }
        current = g_list_next(current);
    }

    /* (NULL LISTE)  OR  (End of Fragment List was passed) */
    if (ch_tsn == lo) {
        /* just increase ctsna, handle rest in separate update_ctsna() */
        if (ch_tsn == rbuf->ctsna + 1) {
            event_logi(VVERBOSE, "Updating rbuf->ctsna==%u", ch_tsn);
            rbuf->ctsna = ch_tsn;
            rbuf->new_chunk_received = TRUE;
            return TRUE;
        }
        /* Update last fragment....increase stop_tsn by one */
        current = g_list_last(rbuf->frag_list);
        if (current == NULL) {
            error_log(ERROR_MAJOR, "rxc_update_fragments: Went past end of List....");
            return FALSE;
        }
        frag = (fragment32*)current->data;
        frag->stop_tsn = frag->stop_tsn + 1;
        rbuf->new_chunk_received = TRUE;

        event_logiii(VVERBOSE, "Updating last fragment frag.start==%u, frag.stop==%u, tsn=%u",
                     frag->start_tsn, frag->stop_tsn, ch_tsn);
        return FALSE;
    } else {                    /* a new fragment altogether */
        current = g_list_last(rbuf->frag_list);
        new_frag = (fragment32*)malloc(sizeof(fragment32));
        new_frag->start_tsn = ch_tsn;
        new_frag->stop_tsn = ch_tsn;
        rbuf->frag_list = g_list_append(rbuf->frag_list, new_frag);
        event_logiii(VVERBOSE,
                     "Inserting new  fragment at end...frag.start==%u,frag.stop==%u, tsn=%u",
                     new_frag->start_tsn, new_frag->stop_tsn, ch_tsn);
        rbuf->new_chunk_received = TRUE;
        return FALSE;           /* no ctsna update necessary whatsoever */
    }
}


/**
 * For now this function treats only one incoming data chunk' tsn
 * @param chunk the data chunk that was received by the bundling
 */
int rxc_data_chunk_rx(SCTP_data_chunk * se_chk, unsigned int ad_idx)
{
    rxc_buffer *rxc;
    unsigned int chunk_tsn;
    unsigned int chunk_len;
    unsigned int assoc_state;
    boolean result = FALSE;
    int bytesQueued = 0;
    unsigned current_rwnd = 0;

    event_log(INTERNAL_EVENT_0, "Entering function rxc_data_chunk_rx");
    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return (-1);
    }


    /* resetting it */
    rxc->new_chunk_received = FALSE;
    rxc->last_address = ad_idx;

    bytesQueued = se_getQueuedBytes();
    if (bytesQueued < 0) bytesQueued = 0;
    if ((unsigned int)bytesQueued > rxc->my_rwnd) {
        current_rwnd = 0;
    } else {
        current_rwnd = rxc->my_rwnd - bytesQueued;
    }

    /* do SWS prevention */
    if (current_rwnd > 0 && current_rwnd <= 2 * MAX_SCTP_PDU) current_rwnd = 1;

    /*
     * if any received data chunks have not been acked, sender
     * should create a SACK and bundle it with the outbound data
     */
    rxc->contains_valid_sack = FALSE;

    chunk_tsn = ntohl(se_chk->tsn);
    chunk_len = ntohs(se_chk->chunk_length);
    assoc_state = sci_getState();

    if ( (after(chunk_tsn, rxc->highest) && current_rwnd == 0) ||
         (assoc_state == SHUTDOWNRECEIVED) ||
         (assoc_state == SHUTDOWNACKSENT) ) {
        /* drop chunk, if either: our rwnd is 0, or we are already shutting down */
        rxc->new_chunk_received = FALSE;
        return 1;
    }

    /* TODO :  Duplicates : see Note in section 6.2 :  */
    /*  Note: When a datagram arrives with duplicate DATA chunk(s) and no new
        DATA chunk(s), the receiver MUST immediately send a SACK with no
        delay. Normally this will occur when the original SACK was lost, and
        the peers RTO has expired. The duplicate TSN number(s) SHOULD be
        reported in the SACK as duplicate.
     */
    event_logii(VERBOSE, "rxc_data_chunk_rx : chunk_tsn==%u, chunk_len=%u", chunk_tsn, chunk_len);
    if (rxc_update_lowest(rxc, chunk_tsn) == TRUE) {
        /* tsn is even lower than the lowest one received so far */
        rxc_update_duplicates(rxc, chunk_tsn);
    } else if (rxc_update_highest(rxc, chunk_tsn) == TRUE) {
        rxc->new_chunk_received = TRUE;
        result = rxc_update_fragments(rxc, chunk_tsn);
    } else if (rxc_chunk_is_duplicate(rxc, chunk_tsn) == TRUE)
        rxc_update_duplicates(rxc, chunk_tsn);
    else
        result = rxc_update_fragments(rxc, chunk_tsn);

    if (result == TRUE) rxc_bubbleup_ctsna(rxc);

    event_logi(VVERBOSE, "rxc_data_chunk_rx: after rxc_bubbleup_ctsna, rxc->ctsna=%u", rxc->ctsna);

    if (rxc->new_chunk_received == TRUE) {
        if(se_recvDataChunk(se_chk, chunk_len, ad_idx) == SCTP_SUCCESS) {
            /* resetting it */
            rxc->new_chunk_received = FALSE;
        }
        /* else: ABORT has been sent and the association (possibly) removed in callback! */
    }
    return 1;
}

/**
 * Function triggered by flowcontrol, tells recvcontrol to
 * send SACK to bundling using bu_put_SACK_Chunk() function.
 * @return boolean to indicate, whether a SACK was generated, and should be sent !
 */
boolean rxc_create_sack(unsigned int *destination_address, boolean force_sack)
{
    rxc_buffer *rxc;
    unsigned int num_of_frags;

    event_logii(VVERBOSE,
                "Entering rxc_create_sack(address==%u, force_sack==%s",
                ((destination_address != NULL) ? *destination_address : 0),
                ((force_sack == TRUE) ? "TRUE" : "FALSE"));

    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return FALSE;
    }

    if (rxc->contains_valid_sack == FALSE) {
        event_log(INTERNAL_EVENT_0, "SACK structure was not updated (should have been)");
        rxc_all_chunks_processed(FALSE);
    }

    num_of_frags = g_list_length(rxc->frag_list);

    if (num_of_frags > 0)
        rxc_send_sack_everytime();
    else
        rxc_send_sack_every_second_time();

    /* send sacks along every second time, generally */
    /* some timers may want to have a SACK anyway */
    /* first sack is sent at once, since datagrams_received==-1 */
    if (force_sack == TRUE) {
        rxc->lowest = rxc->ctsna;
        bu_put_SACK_Chunk((SCTP_sack_chunk*)rxc->sack_chunk, destination_address);
        return TRUE;
    } else {

        /* in case we have not yet got any data, we will not want to send a SACK */
        if (rxc->datagrams_received == -1)
            return FALSE;

        if (rxc->datagrams_received % rxc->sack_flag != 0) {
                event_log(VVERBOSE, "Did not send SACK here - returning");
                return FALSE;
        }
        rxc->lowest = rxc->ctsna;
        bu_put_SACK_Chunk((SCTP_sack_chunk*)rxc->sack_chunk,destination_address);
        return TRUE;
    }
    return FALSE;
}



/**
 * the callback function when the sack timer goes off, and we must sack previously
 * received data (e.g. after 200 msecs)
 * Has three parameters as all timer callbacks
 * @param   tid id of the timer that has gone off
 * @param   assoc  pointer to the association this event belongs to
 * @param   dummy  pointer that is not used here
 */
void rxc_sack_timer_cb(TimerID tid, void *assoc, void *dummy)
{
    unsigned short res;

    rxc_buffer *rxc;
    event_log(INTERNAL_EVENT_1, "Timer Callback Function activated -> initiate sending of a SACK");
    res = mdi_setAssociationData(*(unsigned int *) assoc);
    if (res == 1)
        error_log(ERROR_MAJOR, " association does not exist !");
    if (res == 2) {
        error_log(ERROR_MAJOR, "Association was not cleared..... !!!");
        /* failure treatment ? */
    }
    /* all should be well now */
    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return;
    }
    rxc->timer_running = FALSE;
    /* sending sack */
    /* FIXME : maybe choose different address ??? */
    rxc_create_sack(&rxc->last_address, TRUE);
    bu_sendAllChunks(&rxc->last_address);

    mdi_clearAssociationData();
    return;
}

/**
 * function called by bundling when a SACK is actually sent, to stop
 * a possibly running  timer
 */
void rxc_stop_sack_timer(void)
{
    rxc_buffer *rxc;
    int result;

    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MINOR, "rxc_buffer instance not set !");
        return;
    }
    /* also make sure you forget all the duplicates we received ! */
    g_list_foreach(rxc->dup_list, &free_list_element, NULL);
    g_list_free(rxc->dup_list);
    rxc->dup_list = NULL;

    if (rxc->timer_running == TRUE) {
        result = sctp_stopTimer(rxc->sack_timer);
        event_logi(INTERNAL_EVENT_0, "Stopped Timer, Result was %d", result);
        rxc->timer_running = FALSE;
    }
    return;
}

boolean rxc_sack_timer_is_running(void)
{
    rxc_buffer *rxc;
    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MINOR, "rxc_buffer instance not set !");
        return FALSE;
    }
    if (rxc->timer_running == TRUE) return TRUE;
    return FALSE;
}

/**
 * called by bundling, after new data has been processed (so we may start building a sack chunk)
 * or by streamengine, when ULP has read some data, and we want to update the RWND.
 */
void rxc_all_chunks_processed(boolean new_data_received)
{
    /* now go and create SACK structure from the array */
    rxc_buffer *rxc=NULL;
    SCTP_sack_chunk *sack=NULL;
    unsigned short num_of_frags, num_of_dups;
    unsigned short len16, count, frag_start16, frag_stop16;
    unsigned int pos;
    duplicate *dptr=NULL, d;
    fragment32 *f32=NULL;
    fragment chunk_frag;
    GList *temp=NULL;
    int bytesQueued = 0;
    unsigned current_rwnd = 0;

    event_log(INTERNAL_EVENT_0, "Entering funtion rxc_all_chunks_processed ()");

    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return;
    }

    if (new_data_received == TRUE) rxc->datagrams_received++;

    num_of_frags = g_list_length(rxc->frag_list);
    num_of_dups  = g_list_length(rxc->dup_list);

    /* limit size of SACK to 80 bytes plus fixed size chunk and chunk header */
    /* FIXME : Limit number of Fragments/Duplicates according to ->PATH MTU<-  */
    if (num_of_frags > 10) num_of_frags = 10;
    if (num_of_dups > 10)  num_of_dups = 10;

    event_logii(VVERBOSE, "len of frag_list==%u, len of dup_list==%u", num_of_frags, num_of_dups);

    bytesQueued = se_getQueuedBytes();
    if (bytesQueued < 0) bytesQueued = 0;
    if ((unsigned int)bytesQueued > rxc->my_rwnd) {
        current_rwnd = 0;
    } else {
        current_rwnd = rxc->my_rwnd - bytesQueued;
    }
    /* do SWS prevention */
    if (current_rwnd > 0 && current_rwnd <= 2 * MAX_SCTP_PDU) current_rwnd = 1;


    sack = (SCTP_sack_chunk*)rxc->sack_chunk;
    sack->chunk_header.chunk_id = CHUNK_SACK;
    sack->chunk_header.chunk_flags = 0;
    len16 = sizeof(SCTP_chunk_header) + (2 + num_of_dups) * sizeof(unsigned int) +
            (2 * num_of_frags + 2) * sizeof(unsigned short);

    sack->chunk_header.chunk_length = htons(len16);
    sack->cumulative_tsn_ack = htonl(rxc->ctsna);
    /* FIXME : deduct size of data still in queue, that is waiting to be picked up by an ULP */
    sack->a_rwnd = htonl(current_rwnd);
    sack->num_of_fragments  = htons(num_of_frags);
    sack->num_of_duplicates = htons(num_of_dups);
    pos = 0L;

    temp = g_list_first(rxc->frag_list); count = 0;
    while ((temp != NULL) && (count < num_of_frags)) {

        f32 = (fragment32*)temp->data;

        event_logiii(VVERBOSE,"ctsna==%u, fragment.start==%u, fragment.stop==%u",
                     rxc->ctsna, f32->start_tsn, f32->stop_tsn);

        if (((f32->start_tsn - rxc->ctsna) > 0xFFFF) || ((f32->stop_tsn - rxc->ctsna) > 0xFFFF)) {
            error_log(ERROR_MINOR, "Fragment offset becomes too big");
            break;
        }
        frag_start16 = (unsigned short) (f32->start_tsn - rxc->ctsna);
        frag_stop16 = (unsigned short) (f32->stop_tsn - rxc->ctsna);
        event_logii(VVERBOSE, "frag_start16==%u, frag_stop16==%u", frag_start16, frag_stop16);

        chunk_frag.start = htons((unsigned short)(f32->start_tsn - rxc->ctsna));
        chunk_frag.stop = htons((unsigned short)(f32->stop_tsn - rxc->ctsna));
        event_logii(VVERBOSE, "chunk_frag.start=%u,chunk_frag.stop ==%u",
                                ntohs(chunk_frag.start), ntohs(chunk_frag.stop));
        memcpy(&sack->fragments_and_dups[pos], &chunk_frag, sizeof(fragment));
        pos += sizeof(fragment);
        temp = g_list_next(temp); count++;
    }

    temp = g_list_first(rxc->dup_list); count = 0;
    while ((temp != NULL) && (count < num_of_dups)) {
        dptr = (duplicate*)temp->data;
        if (dptr) d.duplicate_tsn = htonl(dptr->duplicate_tsn);
        memcpy(&sack->fragments_and_dups[pos], &d, sizeof(duplicate));
        pos += sizeof(duplicate);
        temp = g_list_next(temp); count++;
    }
    /* start sack_timer set to 200 msecs */
    if (rxc->timer_running != TRUE && new_data_received == TRUE) {
        rxc->sack_timer = adl_startTimer(rxc->delay, &rxc_sack_timer_cb, TIMER_TYPE_SACK, &(rxc->my_association), NULL);
        event_log(INTERNAL_EVENT_0, "Started SACK Timer !");
        rxc->timer_running = TRUE;
    }
    rxc->contains_valid_sack = TRUE;
    return;
}


/**
  Function starts a SACK timer after data has been read by the ULP, and the
  buffer is about to change...
 */
int rxc_start_sack_timer(unsigned int oldQueueLen)
{
    rxc_buffer *rxc;
    int bytesQueued = 0;

    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MINOR, "rxc_buffer instance not set - returning 0");
        return (-1);
    }

    bytesQueued = se_getQueuedBytes();
    if (bytesQueued < 0) bytesQueued = 0;
    /* no new data received, but we want updated SACK to be sent */
    rxc_all_chunks_processed(FALSE);
    if ((rxc->my_rwnd - oldQueueLen < 2 * MAX_SCTP_PDU) &&
        (rxc->my_rwnd - bytesQueued >= 2 * MAX_SCTP_PDU)) {
        /* send SACK at once */
        rxc_create_sack(&rxc->last_address, TRUE);
        bu_sendAllChunks(&rxc->last_address);
        rxc_stop_sack_timer();
    } else {    /* normal application read, no need to rush things */
        if (rxc->timer_running != TRUE) {
            rxc->sack_timer = adl_startTimer(rxc->delay, &rxc_sack_timer_cb, TIMER_TYPE_SACK, &(rxc->my_association), NULL);
            event_log(INTERNAL_EVENT_0, "Started SACK Timer !");
            rxc->timer_running = TRUE;
        }
    }
    return 0;
}


/**
  @return my current receiver window (32 bit unsigned value)
 */
unsigned int rxc_get_local_receiver_window(void)
{
    rxc_buffer *rxc;
    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MINOR, "rxc_buffer instance not set - returning 0");
        return (0);
    }
    event_logi(VERBOSE, "function rxc_get_my_receiver_window() returns %u", rxc->my_rwnd);
    return rxc->my_rwnd;
}


/**
  @return my current sack delay in msecs
 */
int rxc_get_sack_delay(void)
{
    rxc_buffer *rxc;
    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MINOR, "rxc_buffer instance not set - returning default");
        return (-1);
    }
    event_logi(VERBOSE, "function rxc_get_sack_delay() returns %u", rxc->delay);
    return ((int)rxc->delay);
}

/**
  @return my current sack delay in msecs
 */
int rxc_set_sack_delay(unsigned int new_delay)
{
    rxc_buffer *rxc;
    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MINOR, "rxc_buffer instance not set - returning default");
        return (-1);
    }
    rxc->delay = new_delay;
    event_logi(VERBOSE, "Setting new sack delay  to %u msecs", rxc->delay);
    return 0;
}

/**
 Set the size of my receiver window. This needs to reflect buffer sizes.
 Beware, this is really only a DUMMY function, too !
 @param  new local receiver window (32 bit unsigned value)
 @return 0 on success, else -1 on failure
 */
int rxc_set_local_receiver_window(unsigned int new_window)
{
    rxc_buffer *rxc;
    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return (-1);
    }
    event_logi(VERBOSE, "function rxc_set_my_receiver_window(%u)", new_window);
    rxc->my_rwnd = new_window;
    return 0;
}


/**
  Get the number of the current cumulative TSN, that we may ack
  @return my current ctsna (32 bit unsigned value)
 */
unsigned int rxc_read_cummulativeTSNacked(void)
{
    rxc_buffer *rxc;

    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return (0);
    }
    return (rxc->ctsna);
}

/**
 * Helper function called, when we have gap reports in incoming
 * SACK chunks....
 */
void rxc_send_sack_everytime(void)
{
    rxc_buffer *rxc;

    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return;
    }
    rxc->sack_flag = 1;
}

/**
 * Helper function called, when we have no gap reports in incoming
 * SACK chunks....
 */
void rxc_send_sack_every_second_time(void)
{
    rxc_buffer *rxc;

    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return;
    }
    rxc->sack_flag = 2;

}


/**
 function only called in a restart case.
 Beware : this has been largely untested !
 @param  new_remote_TSN new tsn value of peer that has restarted
 */
void rxc_restart_receivecontrol(unsigned int my_rwnd, unsigned int new_remote_TSN)
{
    rxc_buffer *rxc;

    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return;
    }
    rxc_stop_sack_timer();
    g_list_foreach(rxc->frag_list, &free_list_element, NULL);
    g_list_free(rxc->frag_list);
    rxc->ctsna = new_remote_TSN - 1;
    rxc->lowest = new_remote_TSN - 1;
    rxc->highest = new_remote_TSN - 1;
    /* initialize and set up lists */

    rxc->frag_list = NULL;
    rxc->dup_list = NULL;
    rxc->contains_valid_sack = FALSE;
    rxc->timer_running = FALSE;
    rxc->datagrams_received = -1;
    rxc->sack_flag = 2;
    rxc->last_address = 0;
    rxc->my_rwnd = my_rwnd;
    rxc->my_association = mdi_readAssociationID();
    return;
}


int rxc_process_forward_tsn(void* chunk)
{
    rxc_buffer *rxc=NULL;
    unsigned int fw_tsn;
    unsigned int chunk_len;
    unsigned int lo, hi;
    fragment32 *frag=NULL;
    GList *current = NULL;

    SCTP_forward_tsn_chunk* chk = (SCTP_forward_tsn_chunk*)chunk;

    fw_tsn = ntohl(chk->forward_tsn);
    chunk_len = ntohs(chk->chunk_header.chunk_length);

    event_logii(INTERNAL_EVENT_0, "rxc_process_forward_tsn: %u, len:%u",fw_tsn, chunk_len);
    rxc = (rxc_buffer *) mdi_readRX_control();
    if (!rxc) {
        error_log(ERROR_MAJOR, "rxc_buffer instance not set !");
        return (-1);
    }
    /* discard old FORWARD_TSN */
    if (after(rxc->ctsna, fw_tsn) || fw_tsn==rxc->ctsna || mdi_supportsPRSCTP() == FALSE) {
        event_logii(VERBOSE, "rxc_process_forward_tsn --> discard fw_tsn !! (fw_tsn %u <= ctsna %u)",fw_tsn, rxc->ctsna);
        return 0;
    }

    current = g_list_first(rxc->frag_list);

    /* -get first fragment
       -case1: fw_tsn after hi: delete fragment, continue with next fragment;
       -case2: fw_tsn between hi and lo-1:
                delete fragment, set ctsna=hi, break;
       -case3: fw_tsn before lo-1, set ctsna => fw_tsn, break;
     */
    while (current != NULL) {
        frag = (fragment32*)current->data;
        if (current != NULL && frag != NULL){
            lo = frag->start_tsn;
            hi = frag->stop_tsn;
            if (before(fw_tsn, lo-1)) {
                /* case3: fw_tsn before lo-1, set ctsna => fw_tsn, break; */
                event_logi(VERBOSE, "process- case3: update ctsna to %u !",fw_tsn);
                rxc->ctsna  = fw_tsn;
                break;
            } else if (between(lo-1, fw_tsn, hi)) {
                /* case2: fw_tsn between hi and lo-1: delete fragment, set ctsna=hi, break; */
                rxc->frag_list = g_list_remove_link(rxc->frag_list, current);
                g_list_free_1(current); free(frag);
                event_logi(VERBOSE, "process- case2: remove fragment and update ctsna to %u !",hi);
                rxc->ctsna = hi;
                break;
            } else if (after(fw_tsn, hi)) {
                /* case1: fw_tsn after hi: delete fragment, continue with next fragment; */
                rxc->frag_list = g_list_remove_link(rxc->frag_list, current);
                g_list_free_1(current); free(frag);
                event_logi(VERBOSE, "process- case1: remove fragment, and set ctsna => %u !",hi);
                rxc->ctsna = fw_tsn;
            } else {
                error_log(ERROR_FATAL, "rxc_process_forward_tsn: impossible conditon");
                abort();
            }
        }
        /* we are still here, take next fragment == first fragment */
        current = g_list_first(rxc->frag_list);
    }
    if (after(fw_tsn, rxc->ctsna)) {
        rxc->ctsna = fw_tsn;
        event_logi(VERBOSE, "rxc_process_forward_tsn: case4: set ctsna => %u !",fw_tsn);
    }
    se_deliver_unreliably(rxc->ctsna, chk);

    rxc_all_chunks_processed(TRUE);

    return 0;
}

