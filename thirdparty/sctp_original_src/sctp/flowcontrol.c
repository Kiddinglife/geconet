/* $Id: flowcontrol.c 2771 2013-05-30 09:09:07Z dreibh $
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

#include "flowcontrol.h"
#include "bundling.h"
#include "adaptation.h"
#include "recvctrl.h"

#include <stdio.h>
#include <glib.h>

/* #define Current_event_log_ 6 */
/**
 * this struct contains all relevant congestion control parameters for
 * one PATH to the destination/association peer endpoint
 */
typedef struct __congestion_parameters
{
    /*@{ */
    /** */
    unsigned int cwnd;
    /** */
    unsigned int cwnd2;
    /** */
    unsigned int partial_bytes_acked;
    /** */
    unsigned int ssthresh;
    /** */
    unsigned int mtu;
    /** */
    struct timeval time_of_cwnd_adjustment;
    /** */
    struct timeval last_send_time;
    /*@} */
} cparm;

typedef struct flowcontrol_struct
{
    /*@{*/
    /** */
    unsigned int outstanding_bytes;
    /** */
    unsigned int announced_rwnd;
    /** */
    unsigned int number_of_addresses;
    /** pointer to array of congestion window parameters */
    cparm *cparams;
    /** */
    unsigned int current_tsn;
    /** */
    GList *chunk_list;
    /** */
    unsigned int list_length;
    /** one timer may be running per destination address */
    TimerID *T3_timer;
    /** for passing as parameter in callback functions */
    unsigned int *addresses;
    /** */
    unsigned int my_association;
    /** */
    boolean shutdown_received;
    /** */
    boolean waiting_for_sack;
    /** */
    boolean t3_retransmission_sent;
    /** */
    boolean one_packet_inflight;
    /** */
    boolean doing_retransmission;
    /** */
    unsigned int maxQueueLen;
    /*@} */
} fc_data;


/* ---------------  Function Prototypes -----------------------------*/
int fc_check_for_txmit(void *fc_instance, unsigned int oldListLen, gboolean doInitialRetransmit);
/* ---------------  Function Prototypes -----------------------------*/


/**
 * Creates new instance of flowcontrol module and returns pointer to it
 * TODO : should parameter be unsigned short ?
 * TODO : get and update MTU (guessed values ?) per destination address
 * @param  peer_rwnd receiver window that peer allowed us when setting up the association
 * @param  my_iTSN my initial TSN value
 * @param  number_of_destination_addresses the number of paths to the association peer
 * @return  pointer to the new fc_data instance
*/
void *fc_new_flowcontrol(unsigned int peer_rwnd,
                         unsigned int my_iTSN,
                         unsigned int number_of_destination_addresses,
                         unsigned int maxQueueLen)
{
    fc_data *tmp;
    unsigned int count;

    tmp = (fc_data*)malloc(sizeof(fc_data));
    if (!tmp)
        error_log(ERROR_FATAL, "Malloc failed");
    tmp->current_tsn = my_iTSN;

    event_logi(VERBOSE,
               "Flowcontrol: ===== Num of number_of_destination_addresses = %d ",
               number_of_destination_addresses);

    tmp->cparams = (cparm*)malloc(number_of_destination_addresses * sizeof(cparm));
    if (!tmp->cparams)
        error_log(ERROR_FATAL, "Malloc failed");

    tmp->T3_timer = (TimerID*)malloc(number_of_destination_addresses * sizeof(TimerID));
    if (!tmp->T3_timer)
        error_log(ERROR_FATAL, "Malloc failed");

    tmp->addresses = (unsigned int*)malloc(number_of_destination_addresses * sizeof(unsigned int));
    if (!tmp->addresses)
        error_log(ERROR_FATAL, "Malloc failed");

    for (count = 0; count < number_of_destination_addresses; count++) {
        tmp->T3_timer[count] = 0; /* i.e. timer not running */
        tmp->addresses[count] = count;
        (tmp->cparams[count]).cwnd = 2 * MAX_MTU_SIZE;
        (tmp->cparams[count]).cwnd2 = 0L;
        (tmp->cparams[count]).partial_bytes_acked = 0L;
        (tmp->cparams[count]).ssthresh = peer_rwnd;
        (tmp->cparams[count]).mtu = MAX_SCTP_PDU;
        adl_gettime( &(tmp->cparams[count].time_of_cwnd_adjustment));
        timerclear(&(tmp->cparams[count].last_send_time));
    }
    tmp->outstanding_bytes = 0;
    tmp->announced_rwnd = peer_rwnd;
    tmp->number_of_addresses = number_of_destination_addresses;
    tmp->waiting_for_sack = FALSE;
    tmp->shutdown_received = FALSE;
    tmp->t3_retransmission_sent = FALSE;
    tmp->one_packet_inflight = FALSE;
    tmp->doing_retransmission = FALSE;
    tmp->chunk_list = NULL;
    tmp->maxQueueLen = maxQueueLen;
    tmp->list_length = 0;

    rtx_set_remote_receiver_window(peer_rwnd);

    tmp->my_association = mdi_readAssociationID();
    event_logi(VVERBOSE, "FlowControl : Association-ID== %d \n", tmp->my_association);
    if (tmp->my_association == 0)
        error_log(ERROR_FATAL, "Association was not set, should be......");
    return tmp;
}

/**
 * this function stops all currently running timers, and may be called when
 * the shutdown is imminent
 * @param  new_rwnd new receiver window of the association peer
 */
void fc_restart(guint32 new_rwnd, unsigned int iTSN, unsigned int maxQueueLen)
{
    fc_data *tmp;
    guint32 count;

    tmp = (fc_data *) mdi_readFlowControl();
    event_log(INTERNAL_EVENT_0, "fc_restart()... ");
    if (!tmp) {
        error_log(ERROR_MINOR, "fc_data instance not set !");
        return;
    }
    fc_stop_timers();
    for (count = 0; count < tmp->number_of_addresses; count++) {
        (tmp->cparams[count]).cwnd = 2 * MAX_MTU_SIZE;
        (tmp->cparams[count]).cwnd2 = 0L;
        (tmp->cparams[count]).partial_bytes_acked = 0L;
        (tmp->cparams[count]).ssthresh = new_rwnd;
        (tmp->cparams[count]).mtu = MAX_SCTP_PDU;
        adl_gettime( &(tmp->cparams[count].time_of_cwnd_adjustment) );
        timerclear(&(tmp->cparams[count].last_send_time));
    }
    tmp->outstanding_bytes = 0;
    tmp->announced_rwnd = new_rwnd;
    tmp->waiting_for_sack = FALSE;
    tmp->shutdown_received = FALSE;
    tmp->t3_retransmission_sent = FALSE;
    tmp->one_packet_inflight = FALSE;
    tmp->doing_retransmission = FALSE;
    tmp->current_tsn = iTSN;
    tmp->maxQueueLen = maxQueueLen;
    rtx_set_remote_receiver_window(new_rwnd);
    if ((tmp->chunk_list) != NULL) {
        /* TODO : pass chunks in this list back up to the ULP ! */
        g_list_foreach(tmp->chunk_list, &free_list_element, GINT_TO_POINTER(1));
        error_log(ERROR_MINOR, "FLOWCONTROL RESTART : List is deleted...");
    }
    g_list_free(tmp->chunk_list);
    tmp->chunk_list = NULL;
    tmp->list_length = 0;
}

/**
 * Deletes data occupied by a flow_control data structure
 * @param fc_instance pointer to the flow_control data structure
 */
void fc_delete_flowcontrol(void *fc_instance)
{
    fc_data *tmp;

    tmp = (fc_data *) fc_instance;
    event_log(INTERNAL_EVENT_0, "fc_delete_flowcontrol(): stop timers and delete flowcontrol data");
    fc_stop_timers();
    free(tmp->cparams);
    free(tmp->T3_timer);
    free(tmp->addresses);
    if ((tmp->chunk_list) != NULL) {
        error_log(ERROR_MINOR, "FLOWCONTROL : List is deleted with chunks still queued...");
        g_list_foreach(tmp->chunk_list, &free_list_element, GINT_TO_POINTER(1));
    }
    g_list_free(tmp->chunk_list);
    tmp->chunk_list = NULL;
    free(fc_instance);
}

/**
 * function to print debug data (flow control parameters of all paths)
 *  @param event_log_level  INTERNAL_EVENT_0 INTERNAL_EVENT_1 EXTERNAL_EVENT_X EXTERNAL_EVENT
 */
void fc_debug_cparams(short event_log_level)
{
    fc_data *fc;
    unsigned int count;

    if (event_log_level <= Current_event_log_) {
        fc = (fc_data *) mdi_readFlowControl();
        if (!fc) {
            error_log(ERROR_MAJOR, "fc_data instance not set !");
            return;
        }
        event_log(event_log_level,
                  "----------------------------------------------------------------------");
        event_log(event_log_level, "Debug-output for Congestion Control Parameters ! ");
        event_logii(event_log_level, "outstanding_bytes == %u; current_tsn == %u; ",
                                fc->outstanding_bytes, fc->current_tsn);
        event_logi(event_log_level, "chunks queued in flowcontrol== %lu; ", fc->list_length);
        event_logii(event_log_level,
                    "shutdown_received == %s; waiting_for_sack == %s",
                    ((fc->shutdown_received == TRUE) ? "TRUE" : "FALSE"),
                    ((fc->waiting_for_sack == TRUE) ? "TRUE" : "FALSE"));

        event_logi(event_log_level, "t3_retransmission_sent == %s ",
                   ((fc->t3_retransmission_sent == TRUE) ? "TRUE" : "FALSE"));
        for (count = 0; count < fc->number_of_addresses; count++) {
            event_logiii(event_log_level,"cwnd:%u  ssthresh:%u  address=%u XYZ",
                         (fc->cparams[count]).cwnd, (fc->cparams[count]).ssthresh,count);
            event_logiiiii(event_log_level,
                           "%u :  mtu=%u   T3=%u   cwnd2=%u   pb_acked=%u",
                           count, (fc->cparams[count]).mtu,
                           fc->T3_timer[count], (fc->cparams[count]).cwnd2,
                           (fc->cparams[count]).partial_bytes_acked);
        }
        event_log(event_log_level,
                  "----------------------------------------------------------------------");

    }
    return;
}


/**
 * this function should be called to signal to flowcontrol, that our ULP
 * has initiated a shutdown procedure. We must only send unacked data from
 * now on ! The association is about to terminate !
 */
void fc_shutdown()
{
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();
    event_log(VERBOSE, "fc_shutdown()... ");
    if (!fc) {
        error_log(ERROR_MINOR, "fc_data instance not set !");
        return;
    }
    fc->shutdown_received = TRUE;
    return;
}


/**
 * this function stops all currently running timers of the flowcontrol module
 * and may be called when the shutdown is imminent
 */
void fc_stop_timers(void)
{
    fc_data *fc;
    unsigned int count;
    int result;

    fc = (fc_data *) mdi_readFlowControl();
    event_log(INTERNAL_EVENT_0, "fc_stop_timers()... ");
    if (!fc) {
        event_log(INTERNAL_EVENT_0, "fc_data instance not set !");
        return;
    }
    for (count = 0; count < fc->number_of_addresses; count++) {
        if (fc->T3_timer[count] != 0) {
            result = sctp_stopTimer(fc->T3_timer[count]);
            fc->T3_timer[count] = 0;
            if (result == 1)
                error_log(ERROR_MINOR, "Timer not correctly reset to 0 !");
            event_logii(VVERBOSE, "Stopping T3-Timer(%d) = %d ", count, result);
        }
    }
    return;
}


/**
 *  function, that resets cwnd, when data was not sent for at least one RTO on a path.
 *  @param  pathId      ID of the path, where the cwnd is to be reset to 2*MTU
 *  @return   error parameter (SCTP_SUCCESS, SCTP_PARAMETER_PROBLEM, SCTP_MODULE_NOT_FOUND)
 */
int fc_reset_cwnd(unsigned int pathId)
{
    fc_data *fc = NULL;
    unsigned int rto;
    short pId;
    struct timeval now, resetTime;


    fc = (fc_data *) mdi_readFlowControl();
    if (!fc) {
        error_log(ERROR_MAJOR, "fc_data instance not set !");
        return SCTP_MODULE_NOT_FOUND;
    }
    /* try opening up, if possible */
    if (fc->outstanding_bytes == 0) {
        fc->one_packet_inflight = FALSE;
    }
    if (pathId >= fc->number_of_addresses) {
        error_logi(ERROR_MAJOR, "Address Parameter wrong in fc_reset_cwnd(== %u)", pathId);
        return SCTP_PARAMETER_PROBLEM;
    }
    pId = (short)pathId;
    adl_gettime(&now);
    rto = pm_readRTO(pId);
    resetTime = fc->cparams[pathId].last_send_time;
    adl_add_msecs_totime(&resetTime, rto);
    if (timercmp(&now, &resetTime, > )) {
        event_logi(INTERNAL_EVENT_0, "----- fc_reset_cwnd(): resetting CWND for idle path %u ------", pathId);
        /* path has been idle for at least on RTO */
        fc->cparams[pathId].cwnd = 2 * MAX_MTU_SIZE;
        adl_gettime(&(fc->cparams[pathId].last_send_time));
        event_logii(INTERNAL_EVENT_0, "resetting cwnd[%d], setting it to : %d\n", pathId, fc->cparams[pathId].cwnd);
    }
    return SCTP_SUCCESS;
}

unsigned int fc_getNextActivePath(fc_data* fc, unsigned int start)
{
    unsigned int count = 0, path = start;
    while (count < fc->number_of_addresses) {
        path = (path+1)%fc->number_of_addresses;
        count++;
        if (pm_readState((short)path) == PM_ACTIVE) return path;
    }
    return path;
}

/**
 * function that selects destination index for data chunks when they are sent,
 * or possibly new address when they are retransmitted.
 * @param  fc   pointer to the flow control structure
 * @param  dat  pointer to the data chunk that is to be sent
 * @param  data_retransmitted   has the chunk already been transmitted ?
 * @param  old_destination      if so, we pass a pointer to the index of the last address used, else NULL
 * @return index of the address where we should send this chunk to, now
 */
unsigned int
fc_select_destination(fc_data * fc, chunk_data * dat,
                      boolean data_retransmitted, unsigned int *old_destination)
{
    /* TODO : check for number_of_addresses == 1, ==2 */
    unsigned int next = pm_readPrimaryPath();

    event_logiii(VVERBOSE, "fc_select_destination: chunk-tsn=%u, retrans=%s, primary path=%d ",
                 dat->chunk_tsn, ((data_retransmitted == TRUE) ? "TRUE" : "FALSE"), next);

    if (old_destination) {
        event_logi(VERBOSE, "fc_select_destination: old_dest = %u\n", *old_destination);
    } else {
        event_log(VERBOSE, "fc_select_destination: old_dest = NULL Pointer \n");
    }
    /* 1. return  a value that is equal to old_destination, if possible */
    if (old_destination) {
        if (pm_readState((short)*old_destination) == PM_ACTIVE) {
            return *old_destination;
        } else {
            return (fc_getNextActivePath(fc, *old_destination));
        }
    }
    /* 2. try user selected address */
    if (dat->initial_destination != -1) {
        next = (short) dat->initial_destination;
    }
    /* 3. else try the primary */
    if ((data_retransmitted == FALSE) && (pm_readState((short)next) == PM_ACTIVE))
        return next;
    /* 4. send retransmitted chunks to the next possible address */
    if (data_retransmitted == TRUE) next = dat->last_destination;

    return (fc_getNextActivePath(fc, next));
}


/**
 *  timer controlled callback function, called when T3 timer expires and data must be retransmitted
 *  This timer also adjusts the slow start threshold and cwnd values
 *  As all timer callbacks, it takes three arguments, the timerID, and two pointers to relevant data
 *  @param  tid the id of the timer that has gone off
 *  @param  assoc  pointer to the association structure to which this T3 timer belongs
 *  @param  data2  pointer to the index of the address where  T3 timer had been running
 */
void fc_timer_cb_t3_timeout(TimerID tid, void *assoc, void *data2)
{
    fc_data *fc;
    unsigned int ad_idx, res /*, retransmitted_bytes = 0 */;
    unsigned int oldListLen;
    int count;
    int num_of_chunks;
    chunk_data **chunks;
    gboolean removed_association = FALSE;

    res = mdi_setAssociationData(*(unsigned int *) assoc);
    if (res == 1) {
        error_log(ERROR_FATAL, " association does not exist !");
        return;
    }

    if (res == 2) {
        error_log(ERROR_MAJOR, "Association was not cleared..... !!!");
    }

    fc = (fc_data *) mdi_readFlowControl();
    if (!fc) {
        error_log(ERROR_FATAL, "fc_data instance not set !");
        return;
    }

    ad_idx = *((unsigned int *) data2);
    event_logi(INTERNAL_EVENT_0, "===============> fc_timer_cb_t3_timeout(address=%u) <========", ad_idx);
    fc->T3_timer[ad_idx] = 0;

    num_of_chunks = rtx_readNumberOfUnackedChunks();
    event_logii(INTERNAL_EVENT_0, "Address-Index : %u, Number of Chunks==%d", ad_idx, num_of_chunks);

    if (num_of_chunks <= 0) {
        event_log(VERBOSE, "Number of Chunks was 0 BEFORE calling rtx_t3_timeout - returning");
        if (fc->shutdown_received == TRUE) {
            error_log(ERROR_MAJOR,
                      "T3 Timeout with 0 chunks in rtx-queue,  sci_allChunksAcked() should have been called !");
        }
        mdi_clearAssociationData();
        return;
    }

    chunks = (chunk_data**)malloc(num_of_chunks * sizeof(chunk_data *));
    num_of_chunks = rtx_t3_timeout(&(fc->my_association), ad_idx, fc->cparams[ad_idx].mtu, chunks);
    if (num_of_chunks <= 0) {
        event_log(VERBOSE, "No Chunks to re-transmit - AFTER calling rtx_t3_timeout - returning");
        free(chunks);
        mdi_clearAssociationData();
        return;
    }
    oldListLen = fc->list_length;

    /* do not do this if we are in fast recovery mode - see SCTP imp guide */
    if (rtx_is_in_fast_recovery() == FALSE) {
        /* adjust ssthresh, cwnd - section 6.3.3.E1, respectively 7.2.3) */
        /* basically we halve the ssthresh, and set cwnd = mtu */
        fc->cparams[ad_idx].ssthresh = max(fc->cparams[ad_idx].cwnd / 2, 2 * fc->cparams[ad_idx].mtu);
        fc->cparams[ad_idx].cwnd = fc->cparams[ad_idx].mtu;
        /* as per implementor's guide */
        fc->cparams[ad_idx].partial_bytes_acked = 0;
    }
/*
    for (count = 0; count < num_of_chunks; count++) {
        retransmitted_bytes += chunks[count]->chunk_len;
        event_logi(VERBOSE, "fc_timer_cb_t3_timeout: Got TSN==%u for RTXmit\n",
                   chunks[count]->chunk_tsn);

    }

    if (fc->outstanding_bytes >= retransmitted_bytes)
        fc->outstanding_bytes -= retransmitted_bytes;
    else
        fc->outstanding_bytes = 0;

*/
    /* insert chunks to be retransmitted at the beginning of the list */
    /* make sure, that they are unique in this list ! */
    for (count = num_of_chunks - 1; count >= 0; count--) {
        if (g_list_find(fc->chunk_list, chunks[count]) == NULL){
            if (chunks[count]->hasBeenAcked == FALSE) {
                fc->chunk_list = g_list_insert_sorted(fc->chunk_list, chunks[count], (GCompareFunc) sort_tsn);
                /* these chunks will not be counted, until they are actually sent again */
                chunks[count]->hasBeenRequeued = TRUE;
                fc->list_length++;
            }
        } else {
            event_logi(VERBOSE, "Chunk number %u already in list, skipped adding it", chunks[count]->chunk_tsn);
        }

    }
    event_log(VVERBOSE, "\n-----FlowControl (T3 timeout): Chunklist after reinserting chunks -------");
    chunk_list_debug(VVERBOSE, fc->chunk_list);
    fc_debug_cparams(VVERBOSE);
    event_log(VVERBOSE, "-----FlowControl (T3 timeout): Debug Output End -------\n");
    free(chunks);

    /* section 7.2.3 : assure that only one data packet is in flight, until a new sack is received */
    fc->waiting_for_sack        = TRUE;
    fc->t3_retransmission_sent  = FALSE; /* we may again send one packet ! */
    fc->one_packet_inflight     = FALSE;

    removed_association = pm_chunksRetransmitted((short) ad_idx);

    if (removed_association) {
        event_log(INTERNAL_EVENT_0, "fc_timer_cb_t3_timeout: Association was terminated by pm_chunksRetransmitted()");
        mdi_clearAssociationData();
        return;
    }
    pm_rto_backoff((short)ad_idx);

    fc_check_for_txmit(fc, oldListLen, TRUE);

    mdi_clearAssociationData();
    return;
}

/**
 * function increases chunk's number of transmissions, stores used destination, updates counts per addresses
 */
void fc_update_chunk_data(fc_data * fc, chunk_data * dat, unsigned int destination)
{
    unsigned int rwnd;

    rwnd = rtx_read_remote_receiver_window();
    dat->num_of_transmissions++;

    event_logiii(VERBOSE,
                 "fc_update_chunk_data(),dat->TSN=%u, dat->num_of_transmissions %d , dest %d\n",
                 dat->chunk_tsn, dat->num_of_transmissions, destination);

    if (dat->num_of_transmissions == 1) {
        dat->last_destination = destination;
    }else if (dat->num_of_transmissions >= MAX_DEST) {
        error_log(ERROR_MINOR, "Maximum number of assumed transmissions exceeded ");
        dat->num_of_transmissions = MAX_DEST - 1;
    } else if (dat->num_of_transmissions < 1) {
        error_log(ERROR_FATAL, "Somehow dat->num_of_transmissions became 0 !");
        abort();
    }

    /* this time we will send dat to destination */
    dat->last_destination = destination;
    /* this chunk must be counted as outstanding */
    dat->hasBeenRequeued = FALSE;

    /* section 6.2.1.B */
    /* leave    peers arwnd untouched for retransmitted data !!!!!!!!! */
    if (dat->num_of_transmissions == 1) {
        /* outstanding byte counter has been decreased if chunks were scheduled for RTX, increase here ! */
        fc->outstanding_bytes += dat->chunk_len;
        if (dat->chunk_len >= rwnd)
            rtx_set_remote_receiver_window(0);
        else
            rtx_set_remote_receiver_window(rwnd - dat->chunk_len);
    }

    event_logi(VERBOSE, "outstanding_bytes overall: %u", fc->outstanding_bytes);
    return;
}

gboolean fc_send_okay(fc_data* fc,
                      chunk_data* nextChunk,
                      unsigned int destination,
                      unsigned int totalSize,
                      unsigned int obpa)
{

    if (nextChunk == NULL) return FALSE;


    if (fc->doing_retransmission == TRUE) {
        if (totalSize + nextChunk->chunk_len > fc->cparams[destination].mtu) {
            fc->doing_retransmission = FALSE;
        } else {
            /* we must send at least on MTU worth of data without paying */
            /* attention to the CWND */
            return TRUE;
        }
    }
    if ((totalSize + obpa < (fc->cparams[destination].cwnd+fc->cparams[destination].mtu-1)) &&
        (
         ((nextChunk->num_of_transmissions==0)&&(rtx_read_remote_receiver_window() > nextChunk->chunk_len)) ||
         (fc->one_packet_inflight == FALSE) ||
         (nextChunk->num_of_transmissions > 0)) ) {
        event_logii(VERBOSE, "fc_send_okay --> TRUE (totalSize == %u, obpa == %u)",totalSize, obpa);
        return TRUE;
    }
    event_logii(VERBOSE, "fc_send_okay --> FALSE (totalSize == %u, obpa == %u)",totalSize, obpa);
    return FALSE;
}


/**
 *  function that checks whether we may transmit data that is currently in the send queue.
 *  Any time that some data chunk is added to the send queue, we must check, whether we can send
 *  the chunk, or must wait until cwnd opens up.
 *  @param fc_instance  pointer to the flowcontrol instance used here
 *  @return  0 for successful send event, -1 for error, 1 if nothing was sent
 */
int fc_check_for_txmit(void *fc_instance, unsigned int oldListLen, gboolean doInitialRetransmit)
{
    unsigned int len, obpa;
    fc_data *fc;
    chunk_data *dat;
    unsigned int total_size, destination, oldDestination, peer_rwnd;

    gboolean data_is_retransmitted = FALSE;
    gboolean lowest_tsn_is_retransmitted = FALSE;
    gboolean data_is_submitted = FALSE;
    peer_rwnd = rtx_read_remote_receiver_window();

    event_logi(INTERNAL_EVENT_0, "Entering fc_check_for_txmit(rwnd=%u)... ", peer_rwnd);

    fc = (fc_data *) fc_instance;

    if (fc->chunk_list != NULL) {
        dat = (chunk_data*)g_list_nth_data(fc->chunk_list, 0);
    } else {
        return -1;
    }

    if (dat->num_of_transmissions >= 1)  data_is_retransmitted = TRUE;

    destination = fc_select_destination(fc, dat, (unsigned char)data_is_retransmitted, NULL);

    total_size = 0;

    /* ------------------------------------ DEBUGGING --------------------------------------------------- */
    event_logii(VERBOSE, "Called fc_select_destination == %d, chunk_len=%u", destination, dat->chunk_len);
    event_logiiii(VERBOSE, "cwnd(%u) == %u, mtu == %u, MAX_MTU = %d ",
                  destination, fc->cparams[destination].cwnd, fc->cparams[destination].mtu, MAX_MTU_SIZE);
    /* ------------------------------------- DEBUGGING --------------------------------------------------- */

    if (peer_rwnd == 0 && fc->one_packet_inflight == TRUE) {    /* section 6.1.A */
        event_log(VERBOSE, "NOT SENDING (peer rwnd == 0 and already one packet in flight ");
        event_log(VERBOSE, "################## -> Returned in fc_check_for_txmit ##################");
        return 1;
    }

    obpa = rtx_get_obpa(destination, &fc->outstanding_bytes);
    if (obpa < 0) {
        error_log(ERROR_MAJOR, "rtx_get_obpa error !");
        return -1;
    }

    if (!doInitialRetransmit) {
        if (fc->cparams[destination].cwnd <= obpa) {
            event_logiii(VERBOSE, "NOT SENDING (cwnd=%u, outstanding(%u)=%u)",
                         fc->cparams[destination].cwnd, destination, obpa);
            return 1;
        }
    } else {
        /* set this flag here, it will be reset after the while loop */
        fc->doing_retransmission = TRUE;
    }

    /*   make sure we send only one retransmission after T3 timeout      */
    /*   waiting_for_sack is only TRUE after T3 timeout.                 */
    if (fc->waiting_for_sack == TRUE && data_is_retransmitted == TRUE) {
        if (fc->t3_retransmission_sent == TRUE) {
            event_log(VERBOSE, "################## -> Returned in fc_check_for_txmit ##################");
            return 1;
        }
    }
    /* check, if the destination path has been idle for more than one RTO */
    /* if so, reset CWND to 2*MTU                                         */
    fc_reset_cwnd(destination);

    while (fc_send_okay(fc, dat, destination, total_size, obpa) == TRUE) {

        /* size is used to see, whether we may send this next chunk, too */
        total_size += dat->chunk_len;

        /* -------------------- DEBUGGING --------------------------------------- */
        event_logiii(VVERBOSE, "Chunk: len=%u, tsn=%u, gap_reports=%u",
                     dat->chunk_len, dat->chunk_tsn, dat->gap_reports);
        event_logii(VVERBOSE, "Chunk: ack_time=%d, num_of_transmissions=%u",
                    dat->ack_time, dat->num_of_transmissions);
        /* -------------------- DEBUGGING --------------------------------------- */

        bu_put_Data_Chunk((SCTP_simple_chunk *) dat->data, &destination);
        data_is_submitted = TRUE;
        adl_gettime(&(fc->cparams[destination].last_send_time));

        /* -------------------- DEBUGGING --------------------------------------- */
        event_logi(VERBOSE, "sent chunk (tsn=%u) to bundling", dat->chunk_tsn);
        event_log(VVERBOSE, "=======###======== Calling fc_update_chunk_data =========###========");
        /* -------------------- DEBUGGING --------------------------------------- */

        fc_update_chunk_data(fc, dat, destination);
        if (dat->num_of_transmissions == 1) {
            adl_gettime(&(dat->transmission_time));
            event_log(INTERNAL_EVENT_0, "Storing chunk in retransmission list -> calling rtx_save_retrans");
            rtx_save_retrans_chunks(dat);
        } else {
            if (lowest_tsn_is_retransmitted == FALSE)
                /* must not be reset to FALSE here */
                lowest_tsn_is_retransmitted = rtx_is_lowest_tsn(dat->chunk_tsn);
        }
        fc->one_packet_inflight = TRUE;
        fc->chunk_list = g_list_remove(fc->chunk_list, (gpointer) dat);
        fc->list_length--;

        dat = (chunk_data*)g_list_nth_data(fc->chunk_list, 0);
        if (dat != NULL) {
            if (dat->num_of_transmissions >= 1)    data_is_retransmitted = TRUE;
            else if (dat->num_of_transmissions == 0) data_is_retransmitted = FALSE;
            oldDestination = destination;
            destination = fc_select_destination(fc, dat, (unsigned char)data_is_retransmitted, &destination);
            if (destination != oldDestination) {
                obpa = rtx_get_obpa(destination, &fc->outstanding_bytes);
                if (obpa < 0) {
                    error_log(ERROR_MAJOR, "rtx_get_obpa error !");
                    break;
                }
                total_size = 0;
            }
            event_logii(VERBOSE, "Called fc_select_destination == %d, obpa = %d \n", destination, obpa);

            if ((rtx_read_remote_receiver_window() < dat->chunk_len) && data_is_retransmitted == FALSE) {
                break;
            }

        }     /* if (dat != NULL) */

    }  /* while ((dat != NULL) && */


    if ((fc->waiting_for_sack == TRUE) && (fc->t3_retransmission_sent == FALSE)) {
        if (data_is_submitted == TRUE && data_is_retransmitted == TRUE) {
            event_log(VERBOSE, "Retransmission Condition in fc_check_for_txmit !!!!!!!! ");
            /* Keep me from retransmitting more than once */
            fc->t3_retransmission_sent = TRUE;
        }
    }

    /* ------------------ DEBUGGING ----------------------------- */
    event_log(VVERBOSE, "Printing Chunk List / Congestion Params in fc_check_for_txmit");
    chunk_list_debug(VVERBOSE, fc->chunk_list);
    /* fc_debug_cparams(VVERBOSE);*/
    /* ------------------ DEBUGGING ----------------------------- */

    if (fc->T3_timer[destination] == 0) { /* see section 5.1 */

        fc->T3_timer[destination] =  adl_startTimer(pm_readRTO((short)destination),
                                                    &fc_timer_cb_t3_timeout,
                                                    TIMER_TYPE_RTXM,
                                                   &(fc->my_association),
                                                    &(fc->addresses[destination]));

        event_logiii(INTERNAL_EVENT_0,
                     "fc_check_for_transmit: started T3 Timer with RTO(%u)==%u msecs on address %u",
                     destination, pm_readRTO((short)destination), fc->addresses[destination]);
    } else {
        /* restart only if lowest TSN is being retransmitted, else leave running */
        /* see section 6.1 */
        if (lowest_tsn_is_retransmitted) {
            event_logiii(INTERNAL_EVENT_0,
                         "RTX of lowest TSN: Restarted T3 Timer with RTO(%u)==%u msecs on address %u",
                         destination, pm_readRTO((short)destination), fc->addresses[destination]);

            fc->T3_timer[destination] =  adl_restartTimer(fc->T3_timer[destination], pm_readRTO((short)destination));
        }
    }

    len = fc->list_length;

    if (data_is_submitted == TRUE) {
        fc->one_packet_inflight = TRUE;
        bu_sendAllChunks(&destination);

        if (fc->maxQueueLen != 0) {
            if (len < fc->maxQueueLen && oldListLen >= fc->maxQueueLen) {
                 mdi_queueStatusChangeNotif(SCTP_SEND_QUEUE, 0, len);
            } else if (len > fc->maxQueueLen && oldListLen <= fc->maxQueueLen) {
                 mdi_queueStatusChangeNotif(SCTP_SEND_QUEUE, 0, len);
            }
        }
        return 0;
    }

    if (fc->maxQueueLen != 0) {
        if (len < fc->maxQueueLen && oldListLen >= fc->maxQueueLen) {
            mdi_queueStatusChangeNotif(SCTP_SEND_QUEUE, 0, len);
        } else if (len > fc->maxQueueLen && oldListLen <= fc->maxQueueLen) {
            mdi_queueStatusChangeNotif(SCTP_SEND_QUEUE, 0, len);
        }
    }

    return 1;
}

/*
  this function checks whether T3 may be stopped, restarted or left running
  @param ad_idx  index of the destination address concerned (which may have a T3 timer running)
  @param all_acked   has all data been acked ?
  @param new_acked   have new chunks been acked ? CHECKME : has the ctsna advanced ?
*/
void fc_check_t3(unsigned int ad_idx, boolean all_acked, boolean new_acked)
{
    fc_data *fc = NULL;
    int result, obpa = 0;
    unsigned int count;

    fc = (fc_data *) mdi_readFlowControl();
    if (!fc) {
        error_log(ERROR_MAJOR, "fc_data instance not set !");
        return;
    }
    obpa = rtx_get_obpa(ad_idx, &fc->outstanding_bytes);
    if (obpa < 0) return;

    event_logiiii(INTERNAL_EVENT_0, "fc_check_t3(), outstanding==%u on path %u (all_acked=%s, new_acked=%s)... ",
                    obpa, ad_idx, (all_acked == TRUE) ? "true" : "false", (new_acked == TRUE) ? "true" : "false");

    if (all_acked == TRUE) {
        for (count = 0; count < fc->number_of_addresses; count++) {
            if (fc->T3_timer[count] != 0) {
                result = sctp_stopTimer(fc->T3_timer[count]);
                event_logii(INTERNAL_EVENT_0, "Stopped T3 Timer(%d), Result was %d ", count, result);
                fc->T3_timer[count] = 0;
            }
        }
        return;
    }
    /* see section 6.3.2.R2 */
    if (obpa == 0) {
        if (fc->T3_timer[ad_idx] != 0) {
            result = sctp_stopTimer(fc->T3_timer[ad_idx]);
            event_logii(INTERNAL_EVENT_0, "Stopped T3 Timer(%u), Result was %d ", ad_idx, result);
            fc->T3_timer[ad_idx] = 0;
        }
        return;
    }
    /*
     *  6.3.2 R3) Whenever a SACK is received that acknowledges new data chunks
     *  including the one with the earliest outstanding TSN on that address,
     *  restart T3-rxt timer of that address with its current RTO. (if there is
     *  still data outstanding on that address
     */

    if (new_acked == TRUE) {
        /* 6.2.4.4) Restart T3, if SACK acked lowest outstanding tsn, OR
         *                      we are retransmitting the first outstanding data chunk
         */
        if (fc->T3_timer[ad_idx] != 0) {
            fc->T3_timer[ad_idx] =
                adl_restartTimer(fc->T3_timer[ad_idx], pm_readRTO((short)ad_idx));
            event_logii(INTERNAL_EVENT_0,
                        "Restarted T3 Timer with RTO==%u msecs on address %u",
                        pm_readRTO((short)ad_idx), ad_idx);
        } else {
            fc->T3_timer[ad_idx] =
                adl_startTimer(pm_readRTO((short)ad_idx), &fc_timer_cb_t3_timeout, TIMER_TYPE_RTXM,
                                &(fc->my_association), &(fc->addresses[ad_idx]));
            event_logii(INTERNAL_EVENT_0,
                        "Started T3 Timer with RTO==%u msecs on address %u",
                        pm_readRTO((short)ad_idx), ad_idx);

        }
        return;
    }
    event_log(INTERNAL_EVENT_0, "Left T3 Timer running...");
    /* else leave T3 running  */
    return;
}

/**
 * Function called by stream engine to enqueue data chunks in the flowcontrol
 * module. After function returns, we should be able to  delete the pointer
 * to the data (i.e. some lower module must have copied the data...e.g. the
 * Flowcontrol, ReliableTransfer, or Bundling
 * @param  chunk    pointer to the data chunk to be sent
 * @param destAddressIndex index to address to send data structure to...
 * @param  lifetime NULL if unused, else pointer to a value of msecs,
           after which data will not be sent anymore
 * @param   dontBundle NULL if unused, by default bundling is allowed,
            else pointer to boolean indicating whether it is or it is not allowed.
 * @return -1 on error, 0 on success, (1 if problems occurred ?)
 */
int fc_send_data_chunk(chunk_data * chunkd,
                       short destAddressIndex,
                       unsigned int lifetime,
                       gboolean dontBundle,
                       gpointer context)
{
    fc_data *fc=NULL;

    SCTP_data_chunk* s_chunk;

    event_log(INTERNAL_EVENT_0, "fc_send_data_chunk is being executed.");

    fc = (fc_data *) mdi_readFlowControl();
    if (!fc) {
        error_log(ERROR_MAJOR, "fc_data instance not set !");
        return (SCTP_MODULE_NOT_FOUND);
    }

    if (fc->shutdown_received == TRUE) {
        error_log(ERROR_MAJOR,
                  "fc_send_data_chunk() called, but shutdown_received==TRUE - send not allowed !");
        free(chunkd);
        /* FIXME: see that error treatment gives direct feedback of  this to the ULP ! */
        return SCTP_SPECIFIC_FUNCTION_ERROR;
    }

    /* event_log(VVERBOSE, "Printing Chunk List / Congestion Params in fc_send_data_chunk - before");
    chunk_list_debug(VVERBOSE, fc->chunk_list); */

    event_log(VERBOSE, "FlowControl got a Data Chunk to send ");

    s_chunk = (SCTP_data_chunk*)chunkd->data;

    /* early TSN assignment */
    s_chunk->tsn        =  htonl(fc->current_tsn++);
    chunkd->chunk_len   = CHUNKP_LENGTH(s_chunk);
    chunkd->chunk_tsn   = ntohl(s_chunk->tsn);
    chunkd->gap_reports = 0L;
    chunkd->ack_time    = 0;
    chunkd->context     = context;
    chunkd->hasBeenAcked= FALSE;
    chunkd->hasBeenDropped = FALSE;
    chunkd->hasBeenFastRetransmitted = FALSE;
    chunkd->hasBeenRequeued = FALSE;
    chunkd->last_destination = 0;

    if (destAddressIndex >= 0) chunkd->initial_destination = destAddressIndex;
    else chunkd->initial_destination = -1;

    if (lifetime == 0xFFFFFFFF) {
        timerclear(&(chunkd->expiry_time));
    } else if (lifetime == 0) {
        adl_gettime(&(chunkd->expiry_time));
    } else {
        adl_gettime(&(chunkd->expiry_time));
        adl_add_msecs_totime(&(chunkd->expiry_time), lifetime);
    }

    timerclear(&(chunkd->transmission_time));

    chunkd->dontBundle           = dontBundle;
    chunkd->num_of_transmissions = 0;

    /* insert chunk at the list's tail */
    fc->chunk_list = g_list_append(fc->chunk_list, chunkd);
    fc->list_length++;
    event_log(VVERBOSE, "Printing Chunk List / Congestion Params in  fc_send_data_chunk - after");
    chunk_list_debug(VVERBOSE, fc->chunk_list);

    fc_check_for_txmit(fc, fc->list_length, FALSE);

    return SCTP_SUCCESS;
}


int fc_dequeue_acked_chunks(unsigned int ctsna)
{
    chunk_data *dat = NULL;
    GList* tmp = NULL;
    fc_data *fc = NULL;

    fc = (fc_data *) mdi_readFlowControl();
    if (!fc) {
        error_log(ERROR_FATAL, "fc_data instance not set in fc_dequeue_acked_chunks !");
        return (-1);
    }

    tmp = g_list_first(fc->chunk_list);

    while (tmp != NULL) {
        dat = (chunk_data*)tmp->data;
         if (before(dat->chunk_tsn, ctsna) || (dat->chunk_tsn == ctsna)) {
            tmp = g_list_next(tmp);
            fc->chunk_list = g_list_remove(fc->chunk_list, (gpointer) dat);
            fc->list_length--;
            event_logii(INTERNAL_EVENT_0, "Removed chunk %u from Flowcontrol-List, Listlength now %u",
                dat->chunk_tsn, fc->list_length);
        } else
            break;
    }

    return 0;
}

int fc_adjustCounters(fc_data *fc, unsigned int addressIndex,
                      unsigned int num_acked,
                      gboolean all_data_acked,
                      gboolean new_data_acked,
                      unsigned int number_of_addresses)

{
    unsigned int count;
    int diff;
    struct timeval last_update, now;
    unsigned int rtt_time;

    fc->outstanding_bytes = (fc->outstanding_bytes <= num_acked) ? 0 : (fc->outstanding_bytes - num_acked);
    /* see section 6.2.1, section 6.2.2 */
    if (fc->cparams[addressIndex].cwnd <= fc->cparams[addressIndex].ssthresh) { /* SLOW START */
        for (count = 0; count < number_of_addresses; count++) {
            fc->cparams[count].partial_bytes_acked = 0;
        }

       if (new_data_acked == TRUE) {
           fc->cparams[addressIndex].cwnd += min(MAX_MTU_SIZE, num_acked);
           adl_gettime(&(fc->cparams[addressIndex].time_of_cwnd_adjustment));
       }

    } else {                    /* CONGESTION AVOIDANCE, as per section 6.2.2 */
        if (new_data_acked == TRUE) {
            fc->cparams[addressIndex].partial_bytes_acked += num_acked;
            event_logii(VVERBOSE, "CONG. AVOIDANCE : new data acked: increase PBA(%u) to %u",
                addressIndex, fc->cparams[addressIndex].partial_bytes_acked);
        }
        /*
         * Section 7.2.2 :
         * "When partial_bytes_acked is equal to or greater than cwnd and
         * before the arrival of the SACK the sender had cwnd or more bytes
         * of data outstanding (i.e., before arrival of the SACK, flightsize
         * was greater than or equal to cwnd), increase cwnd by MTU, and
         * reset partial_bytes_acked to (partial_bytes_acked - cwnd)."
         */
        rtt_time = pm_readSRTT((short)addressIndex);
        last_update = fc->cparams[addressIndex].time_of_cwnd_adjustment;
        adl_add_msecs_totime(&last_update, rtt_time);
        adl_gettime(&now);
        diff = adl_timediff_to_msecs(&now, &last_update); /* a-b */
        event_logii(VVERBOSE, "CONG. AVOIDANCE : rtt_time=%u diff=%d", rtt_time, diff);

        if (diff >= 0) {
            if ((fc->cparams[addressIndex].partial_bytes_acked >= fc->cparams[addressIndex].cwnd)
                && (fc->outstanding_bytes >= fc->cparams[addressIndex].cwnd)) {
                fc->cparams[addressIndex].cwnd += MAX_MTU_SIZE;
                fc->cparams[addressIndex].partial_bytes_acked -= fc->cparams[addressIndex].cwnd;
                /* update time of window adjustment (i.e. now) */
                event_log(VVERBOSE,
                          "CONG. AVOIDANCE : updating time of adjustment !!!!!!!!!! NOW ! ");
                adl_gettime(&(fc->cparams[addressIndex].time_of_cwnd_adjustment));
            }
            event_logii(VERBOSE, "CONG. AVOIDANCE : updated counters: %u bytes outstanding, cwnd=%u",
                        fc->outstanding_bytes, fc->cparams[addressIndex].cwnd);
        }

        event_logii(VVERBOSE, "CONG. AVOIDANCE : partial_bytes_acked(%u)=%u ",
                    addressIndex, fc->cparams[addressIndex].partial_bytes_acked);

        /* see section 7.2.2 */
        if (all_data_acked == TRUE) fc->cparams[addressIndex].partial_bytes_acked = 0;

    }
    return SCTP_SUCCESS;
}


/**
 * function called by Reliable Transfer, when it requests retransmission
 * in SDL diagram this signal is called (Req_RTX, RetransChunks)
 * @param  all_data_acked indicates whether or not all data chunks have been acked
 * @param   new_data_acked indicates whether or not new data has been acked
 * @param   num_acked number of bytes that have been newly acked, else 0
 * @param   number_of_addresses so many addresses may have outstanding bytes
 *          actually that value may also be retrieved from the association struct (?)
 * @param   number_of_rtx_chunks number indicatin, how many chunks are to be retransmitted in on datagram
 * @param   chunks  array of pointers to data_chunk structures. These are to be retransmitted
 * @return   -1 on error, 0 on success, (1 if problems occurred ?)
 */
int fc_fast_retransmission(unsigned int address_index, unsigned int arwnd, unsigned int ctsna,
                     unsigned int rtx_bytes, boolean all_data_acked,
                     boolean new_data_acked, unsigned int num_acked,
                     unsigned int number_of_addresses,
                     int number_of_rtx_chunks, chunk_data ** chunks)
{
    fc_data *fc;
    int count, result;
    unsigned int oldListLen, peer_rwnd;

    fc = (fc_data *) mdi_readFlowControl();
    if (!fc) {
        error_log(ERROR_MAJOR, "fc_data instance not set !");
        return (-1);
    }

    oldListLen = fc->list_length;

    /* apply rules from sections 7.2.1 and 7.2.2 */
    fc_adjustCounters(fc, address_index, num_acked, all_data_acked, new_data_acked,
                      number_of_addresses);

    /* ------------------ DEBUGGING ----------------------------- */
    fc_debug_cparams(VERBOSE);
    for (count = 0; count < number_of_rtx_chunks; count++) {
        event_logi(VERBOSE, "fc_fast_retransmission: Got TSN==%u for RTXmit\n",chunks[count]->chunk_tsn);
    }
    /* ------------------ DEBUGGING ----------------------------- */

    fc->t3_retransmission_sent = FALSE; /* we have received a SACK, so reset this */

    /* just checking if the other guy is still alive */
    fc->waiting_for_sack = FALSE;

    result = -2;
    /* We HAVE retransmission, so DO UPDATE OF WINDOW PARAMETERS unless we are in fast recovery, */
    /* see sections 7.2.3 and 7.2.4 and the implementors guide */
    if (rtx_is_in_fast_recovery() == FALSE) {
        fc->cparams[address_index].ssthresh =
            max(fc->cparams[address_index].cwnd / 2, 2 * fc->cparams[address_index].mtu);
        fc->cparams[address_index].cwnd = fc->cparams[address_index].ssthresh;
        /* as per implementor's guide */
        fc->cparams[address_index].partial_bytes_acked = 0;
        rtx_enter_fast_recovery();
    }
    event_logiii(VERBOSE, "fc_fast_retransmission: updated: %u bytes outstanding,cwnd=%u, ssthresh=%u",
                  fc->outstanding_bytes, fc->cparams[address_index].cwnd, fc->cparams[address_index].ssthresh);

    /* This is to be an ordered list containing no duplicate entries ! */
    for (count = number_of_rtx_chunks - 1; count >= 0; count--) {

        if (g_list_find(fc->chunk_list, chunks[count]) != NULL){
            event_logii(VERBOSE, "chunk_tsn==%u, count==%u already in the list -- continue with next\n",
                        chunks[count]->chunk_tsn, count);
            continue;
        }
        event_logii(INTERNAL_EVENT_0, "inserting chunk_tsn==%u, count==%u in the list\n",
                    chunks[count]->chunk_tsn, count);

        fc->chunk_list = g_list_insert_sorted(fc->chunk_list, chunks[count], (GCompareFunc) sort_tsn);
        fc->list_length++;
    }

    /* ------------------ DEBUGGING ----------------------------- */
    event_log(VVERBOSE, "============== fc_fast_retransmission: FlowControl Chunklist after Re-Insertion ======================");
    chunk_list_debug(VVERBOSE, fc->chunk_list);
    /* ------------------ DEBUGGING ----------------------------- */

    fc_check_t3(address_index, all_data_acked, new_data_acked);

    /* section 6.2.1.D ?? */
    if (arwnd >= fc->outstanding_bytes) {
        peer_rwnd = arwnd - fc->outstanding_bytes;
    } else {
        peer_rwnd = 0;
    }
    /* section 6.2.1.C */
    rtx_set_remote_receiver_window(peer_rwnd);

    if (all_data_acked == TRUE) {
        fc->one_packet_inflight = FALSE;
    } else {
        fc->one_packet_inflight = TRUE;
    }

    /* send as many to bundling as allowed, requesting new destination address */
    if (fc->chunk_list != NULL){
       result = fc_check_for_txmit(fc, oldListLen, TRUE);
    }
    /* make sure that SACK chunk is actually sent ! */
    if (result != 0) bu_sendAllChunks(NULL);

    adl_gettime(&(fc->cparams[address_index].time_of_cwnd_adjustment));

    return 1;
}     /* end: fc_fast_retransmission */


/**
 * function called by Reliable Transfer, after it has got a SACK chunk
 * in SDL diagram this signal is called SACK_Info
 * @param  all_data_acked indicates whether or not all data chunks have been acked
 * @param   new_data_acked indicates whether or not new data has been acked
 * @param   num_acked number of bytes that have been newly acked, else 0
 * @param   number_of_addresses so many addresses may have outstanding bytes
 *          actually that value may also be retrieved from the association struct (?)
 */
void fc_sack_info(unsigned int address_index, unsigned int arwnd,unsigned int ctsna,
             boolean all_data_acked, boolean new_data_acked,
             unsigned int num_acked, unsigned int number_of_addresses)
{
    fc_data *fc;
    unsigned int oldListLen;

    fc = (fc_data *) mdi_readFlowControl();
    if (!fc) {
        error_log(ERROR_MAJOR, "fc_data instance not set !");
        return;
    }
    /* ------------------ DEBUGGING ----------------------------- */
    fc_debug_cparams(VERBOSE);
    /* ------------------ DEBUGGING ----------------------------- */

    event_logii(INTERNAL_EVENT_0,
                "fc_sack_info...bytes acked=%u on address %u ", num_acked, address_index);
    fc->t3_retransmission_sent = FALSE; /* we have received a SACK, so reset this */

    /* just check that the other guy is still alive */
    fc->waiting_for_sack = FALSE;

    oldListLen = fc->list_length;

    fc_adjustCounters(fc, address_index, num_acked, all_data_acked, new_data_acked,
                      number_of_addresses);

    fc_check_t3(address_index, all_data_acked, new_data_acked);

    if (fc->outstanding_bytes == 0) {
        fc->one_packet_inflight = FALSE;
    } else {
        fc->one_packet_inflight = TRUE;
    }


    /* section 6.2.1.C */
    if (arwnd > fc->outstanding_bytes)
        rtx_set_remote_receiver_window(arwnd - fc->outstanding_bytes);
    else
        rtx_set_remote_receiver_window(0);

    if (fc->chunk_list != NULL) {
        fc_check_for_txmit(fc, oldListLen, FALSE);
    }

    else {
        if (fc->maxQueueLen != 0) {
            /* Bugfix: Without this, no queueStatusChangeNotif would be
                       called if there are fragmented chunks! */
            if (fc->outstanding_bytes == 0) {
                mdi_queueStatusChangeNotif(SCTP_SEND_QUEUE, 0, fc->list_length);
            }
        }
    }

    return;
}    /* end: fc_sack_info  */



int fc_dequeueUnackedChunk(unsigned int tsn)
{
    fc_data *fc = NULL;
    chunk_data *dat = NULL;
    GList *tmp = NULL;
    gboolean found = FALSE;
    fc = (fc_data *) mdi_readFlowControl();
    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return SCTP_MODULE_NOT_FOUND;
    }
    dat = (chunk_data*)g_list_nth_data(fc->chunk_list, 0);
    tmp = fc->chunk_list;
    while (dat != NULL && tmp != NULL) {
        event_logii(VVERBOSE, "fc_dequeueOldestUnsentChunks(): checking chunk tsn=%u, num_rtx=%u ", dat->chunk_tsn, dat->num_of_transmissions);
        if (dat->chunk_tsn == tsn) {
            found = TRUE;
            break;
        } else {
            tmp = g_list_next(tmp);
            if (tmp != NULL) {
                dat = (chunk_data*)tmp->data;
            } else {
                dat = NULL;
            }
        }
    }
    if (found) { /* delete */
        fc->chunk_list = g_list_remove(fc->chunk_list, (gpointer) dat);
        fc->list_length--;
        event_log(VVERBOSE, "fc_dequeueUnackedChunk(): checking list");
        chunk_list_debug(VVERBOSE, fc->chunk_list);
        return 1;
    }
    /* else */
    return 0;
}

int fc_dequeueOldestUnsentChunk(unsigned char *buf, unsigned int *len, unsigned int *tsn,
                                unsigned short *sID, unsigned short *sSN,unsigned int* pID,
                                unsigned char* flags, gpointer* ctx)
{
    fc_data *fc = NULL;
    chunk_data *dat = NULL;
    GList *tmp = NULL;
    SCTP_data_chunk* dchunk;
    int listlen;

    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return SCTP_MODULE_NOT_FOUND;
    }
    listlen =  fc_readNumberOfUnsentChunks();

    if (listlen <= 0)               return SCTP_UNSPECIFIED_ERROR;
    if (fc->chunk_list == NULL) return  SCTP_UNSPECIFIED_ERROR;
    dat = (chunk_data*)g_list_nth_data(fc->chunk_list, 0);
    tmp = fc->chunk_list;
    while (dat != NULL && tmp != NULL) {
        event_logii(VVERBOSE, "fc_dequeueOldestUnsentChunks(): checking chunk tsn=%u, num_rtx=%u ", dat->chunk_tsn, dat->num_of_transmissions);
        if (dat->num_of_transmissions != 0) {
            tmp = g_list_next(tmp);
            dat = (chunk_data*)tmp->data;
        /* should be a sorted list, and not happen here */
        } else break;
    }
    if ((*len) <  (dat->chunk_len - FIXED_DATA_CHUNK_SIZE)) return SCTP_BUFFER_TOO_SMALL;

    event_logii(VVERBOSE, "fc_dequeueOldestUnsentChunks(): returning chunk tsn=%u, num_rtx=%u ", dat->chunk_tsn, dat->num_of_transmissions);

    dchunk = (SCTP_data_chunk*) dat->data;
    *len = dat->chunk_len - FIXED_DATA_CHUNK_SIZE;
    memcpy(buf, dchunk->data, dat->chunk_len - FIXED_DATA_CHUNK_SIZE);
    *tsn = dat->chunk_tsn;
    *sID = ntohs(dchunk->stream_id);
    *sSN = ntohs(dchunk->stream_sn);
    *pID = dchunk->protocolId;
    *flags = dchunk->chunk_flags;
    *ctx = dat->context;
    fc->chunk_list = g_list_remove(fc->chunk_list, (gpointer) dat);
    fc->list_length--;
    /* be careful ! data may only be freed once: this module ONLY takes care of untransmitted chunks */
    free(dat);
    event_log(VVERBOSE, "fc_dequeueOldestUnsentChunks(): checking list");
    chunk_list_debug(VVERBOSE, fc->chunk_list);
    return (listlen-1);
}

int fc_readNumberOfUnsentChunks(void)
{
    int queue_len = 0;
    fc_data *fc;
    GList* tmp;
    chunk_data *cdat = NULL;

    fc = (fc_data *) mdi_readFlowControl();
    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return SCTP_MODULE_NOT_FOUND;
    }
    if (fc->chunk_list == NULL) return 0;
    tmp = g_list_first(fc->chunk_list);
    while (tmp) {
        cdat = (chunk_data*)tmp->data; /* deref list data */
        event_logii(VERBOSE, "fc_readNumberOfUnsentChunks(): checking chunk tsn=%u, num_rtx=%u ", cdat->chunk_tsn, cdat->num_of_transmissions);
        if (cdat->num_of_transmissions == 0) queue_len++;
        tmp = g_list_next(tmp);
    }
    event_logi(VERBOSE, "fc_readNumberOfUnsentChunks() returns %u", queue_len);
    return queue_len;
}


/**
 * function returns number of chunks, that are waiting in the transmission queue
 * These have been submitted from the upper layer, but not yet been sent, or
 * retransmitted.
 * @return size of the send queue of the current flowcontrol module
 */
unsigned int fc_readNumberOfQueuedChunks(void)
{
    unsigned int queue_len;
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return 0;
    }
    if (fc->chunk_list != NULL){
        queue_len = fc->list_length;
    }
    else
        queue_len=0;

    event_logi(VERBOSE, "fc_readNumberOfQueuedChunks() returns %u", queue_len);
    return queue_len;
}




/**
 * Function returns cwnd value of a certain path.
 * @param path_id    path index of which we want to know the cwnd
 * @return current cwnd value, else -1
 */
int fc_readCWND(short path_id)
{
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return -1;
    }

    if ((unsigned int)path_id >= fc->number_of_addresses || path_id < 0) {
        error_logi(ERROR_MAJOR, "Association has only %u addresses !!! ", fc->number_of_addresses);
        return -1;
    }
    return (int)fc->cparams[path_id].cwnd;
}


/**
 * Function returns cwnd2 value of a certain path.
 * @param path_id    path index of which we want to know the cwnd2
 * @return current cwnd2 value, else -1
 */
int fc_readCWND2(short path_id)
{
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return -1;
    }

    if ((unsigned int)path_id >= fc->number_of_addresses || path_id < 0) {
        error_logi(ERROR_MAJOR, "Association has only %u addresses !!! ", fc->number_of_addresses);
        return -1;
    }
    return (int)fc->cparams[path_id].cwnd2;
}

/**
 * Function returns ssthresh value of a certain path.
 * @param path_id    path index of which we want to know the ssthresh
 * @return current ssthresh value, else -1
 */
int fc_readSsthresh(short path_id)
{
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return -1;
    }
    if ((unsigned int)path_id >= fc->number_of_addresses || path_id < 0) {
        error_logi(ERROR_MAJOR, "Association has only %u addresses !!! ", fc->number_of_addresses);
        return -1;
    }
    return (int)fc->cparams[path_id].ssthresh;
}

/**
 * Function returns mtu value of a certain path.
 * @param path_id    path index of which we want to know the mtu
 * @return current MTU value, else 0
 */
unsigned int fc_readMTU(short path_id)
{
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return 0;
    }
    if ((unsigned int)path_id >= fc->number_of_addresses || path_id < 0) {
        error_logi(ERROR_MAJOR, "Association has only %u addresses !!! ", fc->number_of_addresses);
        return 0;
    }
    return fc->cparams[path_id].mtu;
}

/**
 * Function returns the partial bytes acked value of a certain path.
 * @param path_id    path index of which we want to know the PBA
 * @return current PBA value, else -1
 */
int fc_readPBA(short path_id)
{
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return -1;
    }
    if ((unsigned int)path_id >= fc->number_of_addresses || path_id < 0) {
        error_logi(ERROR_MAJOR, "Association has only %u addresses !!! ", fc->number_of_addresses);
        return -1;
    }
    return (int)fc->cparams[path_id].partial_bytes_acked;
}


/**
 * Function returns the outstanding byte count value of this association.
 * @return current outstanding_bytes value, else -1
 */
int fc_readOutstandingBytes(void)
{
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return -1;
    }
    return (int)fc->outstanding_bytes;
}

int fc_get_maxSendQueue(unsigned int * queueLen)
{
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return -1;
    }
    *queueLen = fc->maxQueueLen;
    return 0;

}

int fc_set_maxSendQueue(unsigned int maxQueueLen)
{
    fc_data *fc;
    fc = (fc_data *) mdi_readFlowControl();

    if (!fc) {
        error_log(ERROR_MAJOR, "flow control instance not set !");
        return -1;
    }
    fc->maxQueueLen = maxQueueLen;
    event_logi(VERBOSE, "fc_set_maxSendQueue(%u)", maxQueueLen);
    return 0;

}
