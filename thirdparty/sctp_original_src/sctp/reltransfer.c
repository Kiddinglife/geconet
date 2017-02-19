/* $Id: reltransfer.c 2771 2013-05-30 09:09:07Z dreibh $
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

#include "adaptation.h"
#include "reltransfer.h"
#include "flowcontrol.h"
#include "recvctrl.h"
#include "pathmanagement.h"
#include "distribution.h"
#include "SCTP-control.h"
#include "bundling.h"

#include <string.h>
#include <stdio.h>

#define MAX_NUM_OF_CHUNKS   500

static chunk_data *rtx_chunks[MAX_NUM_OF_CHUNKS];

/* #define Current_event_log_ 6 */

/**
 * this struct contains all necessary data for retransmissions
 * and processing of received SACKs
 */
typedef struct rtx_buffer_struct
{
    /*@{ */
    /** storing the lowest tsn that is in the list */
    unsigned int lowest_tsn;
    /** */
    unsigned int highest_tsn;
    /** */
    unsigned int num_of_chunks;
    /** */
    unsigned int highest_acked;
    /** a list that is ordered by ascending tsn values */
    GList *chunk_list;
    /** */
    struct timeval sack_arrival_time;
    /** */
    struct timeval saved_send_time;
    /** this val stores 0 if retransmitted chunks have been acked, else 1 */
    unsigned int save_num_of_txm;
    /** */
    unsigned int newly_acked_bytes;
    /** */
    unsigned int num_of_addresses;
    /** */
    unsigned int my_association;
    /** */
    unsigned int peer_arwnd;
    /** */
    gboolean all_chunks_are_unacked;
    /** */
    gboolean shutdown_received;
    /** */
    gboolean fast_recovery_active;
    /** the exit point is only valid, if we are in fast recovery */
    unsigned int fr_exit_point;
    unsigned int advancedPeerAckPoint;
    /** */
    unsigned int lastSentForwardTSN;
    unsigned int lastReceivedCTSNA;

    GArray *prChunks;
/*@} */
} rtx_buffer;


/**
 * after submitting results from a SACK to flowcontrol, the counters in
 * reliable transfer must be reset
 * @param rtx   pointer to a rtx_buffer, where acked bytes per address will be reset to 0
 */
void rtx_reset_bytecounters(rtx_buffer * rtx)
{
    rtx->newly_acked_bytes = 0L;
    return;
}


/**
 * function creates and allocs new rtx_buffer structure.
 * There is one such structure per established association
 * @param   number_of_destination_addresses     number of paths to the peer of the association
 * @return pointer to the newly created structure
 */
void *rtx_new_reltransfer(unsigned int number_of_destination_addresses, unsigned int iTSN)
{
    rtx_buffer *tmp;

    tmp = (rtx_buffer*)malloc(sizeof(rtx_buffer));
    if (!tmp)
        error_log(ERROR_FATAL, "Malloc failed");

    event_logi(VVERBOSE,
               "================== Reltransfer: number_of_destination_addresses = %d",
               number_of_destination_addresses);

    tmp->chunk_list = NULL;

    tmp->lowest_tsn = iTSN-1;
    tmp->highest_tsn = iTSN-1;
    tmp->lastSentForwardTSN = iTSN-1;
    tmp->highest_acked = iTSN - 1;
    tmp->lastReceivedCTSNA = iTSN - 1;
    tmp->newly_acked_bytes = 0L;
    tmp->num_of_chunks = 0L;
    tmp->save_num_of_txm = 0L;
    tmp->peer_arwnd = 0L;
    tmp->shutdown_received = FALSE;
    tmp->fast_recovery_active = FALSE;
    tmp->all_chunks_are_unacked = TRUE;
    tmp->fr_exit_point = 0L;
    tmp->num_of_addresses = number_of_destination_addresses;
    tmp->advancedPeerAckPoint = iTSN - 1;   /* a save bet */
    tmp->prChunks = g_array_new(FALSE, TRUE, sizeof(pr_stream_data));
    tmp->my_association = mdi_readAssociationID();
    event_logi(VVERBOSE, "RTX : Association-ID== %d ", tmp->my_association);
    if (tmp->my_association == 0)
        error_log(ERROR_FATAL, "Association was not set, should be......");
    rtx_reset_bytecounters(tmp);
    return (tmp);
}

/**
 * function deletes a rtx_buffer structure (when it is not needed anymore)
 * @param rtx_instance pointer to a rtx_buffer, that was previously created
            with rtx_new_reltransfer()
 */
void rtx_delete_reltransfer(void *rtx_instance)
{
    rtx_buffer *rtx;
    rtx = (rtx_buffer *) rtx_instance;
    event_log(INTERNAL_EVENT_0, "deleting reliable transfer");
    if (rtx->chunk_list != NULL)
        error_log(ERROR_MINOR, "List is being deleted, but chunks are still queued...");

    g_list_foreach(rtx->chunk_list, &free_list_element, GINT_TO_POINTER(2));
    g_list_free(rtx->chunk_list);
    g_array_free(rtx->prChunks, TRUE);

    free(rtx_instance);
}


/**
 * helper function that calls pm_chunksAcked()
 * and tells path management, if new chunks have  been acked, and new RTT may be guessed
 * @param  adr_idx  CHECKME : address where chunks have been acked (is this correct ?);
            may we take src address of the SACK, or must we take destination address of our data ?
 * @param    rtx    pointer to the currently active rtx structure
 */
void rtx_rtt_update(unsigned int adr_idx, rtx_buffer * rtx)
{
    /* FIXME : check this routine !!!!!!!!!!! */
    int rtt;
    event_logi(INTERNAL_EVENT_0, "rtx_update_rtt(address=%u... ", adr_idx);
    if (rtx->save_num_of_txm == 1) {
        rtx->save_num_of_txm = 0;
        rtt = adl_timediff_to_msecs(&(rtx->sack_arrival_time), &(rtx->saved_send_time));
        if (rtt != -1) {
            event_logii(ERROR_MINOR, "Calling pm_chunksAcked(%u, %d)...", adr_idx, rtt);
            pm_chunksAcked((short)adr_idx, (unsigned int)rtt);
        }
    } else {
        event_logi(VERBOSE, "Calling pm_chunksAcked(%u, 0)...", adr_idx);
        pm_chunksAcked((short)adr_idx, (unsigned int)0L);
    }
    return;
}


/**
 * this function enters fast recovery and sets correct exit point
 * iff fast recovery is not already active
 */
int rtx_enter_fast_recovery(void)
{
    rtx_buffer *rtx = NULL;
    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return (SCTP_MODULE_NOT_FOUND);
    }

    if (rtx->fast_recovery_active == FALSE) {
        event_logi(INTERNAL_EVENT_0, "=============> Entering FAST RECOVERY !!!, Exit Point: %u <================", rtx->highest_tsn);
        rtx->fast_recovery_active = TRUE;
        rtx->fr_exit_point = rtx->highest_tsn;
    }
    return SCTP_SUCCESS;
}


/**
 * this function leaves fast recovery if it was activated, and all chunks up to
 * fast recovery exit point were acknowledged.
 */
static inline int rtx_check_fast_recovery(rtx_buffer* rtx, unsigned int ctsna)
{
    if (rtx->fast_recovery_active == TRUE) {
        if (after (ctsna, rtx->fr_exit_point) || ctsna == rtx->fr_exit_point) {
            event_logi(INTERNAL_EVENT_0, "=============> Leaving FAST RECOVERY !!! CTSNA: %u <================", ctsna);
            rtx->fast_recovery_active = FALSE;
            rtx->fr_exit_point = 0;
        }
    }
    return SCTP_SUCCESS;
}

/**
 * this function returns true, if fast recovery is active
 * else it returns FALSE
 */
gboolean rtx_is_in_fast_recovery(void)
{
    rtx_buffer *rtx = NULL;
    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return (FALSE);
    }
    return rtx->fast_recovery_active;
}


/**
 * Function takes out chunks up to ctsna, updates newly acked bytes
 * @param   ctsna   the ctsna value, that has just been received in a sack
 * @return -1 if error (such as ctsna > than all chunk_tsn), 0 on success
 */
int rtx_dequeue_up_to(unsigned int ctsna, unsigned int addr_index)
{
    rtx_buffer *rtx;
    chunk_data *dat, *old_dat;
/*
    boolean deleted_chunk = FALSE;
    guint i=0, list_length = 0;
*/
    unsigned int chunk_tsn;
    GList* tmp;

    event_logi(INTERNAL_EVENT_0, "rtx_dequeue_up_to...%u ", ctsna);

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return (-1);
    }
    if (rtx->chunk_list == NULL) {
        event_log(INTERNAL_EVENT_0, "List is NULL in rtx_dequeue_up_to()");
        return -1;
    }

    /* first remove all stale chunks from flowcontrol list           */
    /* so that these are not referenced after they are freed here    */
    fc_dequeue_acked_chunks(ctsna);

    tmp = g_list_first(rtx->chunk_list);

    while (tmp) {
        dat = (chunk_data*)g_list_nth_data(rtx->chunk_list, 0);
        if (!dat) return -1;

        chunk_tsn = dat->chunk_tsn;

        event_logiiii(VVERBOSE,
                      " dat->num_of_transmissions==%u, chunk_tsn==%u, chunk_len=%u, ctsna==%u ",
                      dat->num_of_transmissions, chunk_tsn, dat->chunk_len, ctsna);

        tmp = g_list_next(tmp);

        if (before(dat->chunk_tsn, ctsna) || (dat->chunk_tsn == ctsna)) {

            if (dat->num_of_transmissions < 1)
                error_log(ERROR_FATAL, "Somehow dat->num_of_transmissions is less than 1 !");

            if (dat->hasBeenAcked == FALSE && dat->hasBeenDropped == FALSE) {
                rtx->newly_acked_bytes += dat->chunk_len;
                dat->hasBeenAcked = TRUE;
                if (dat->num_of_transmissions == 1 && addr_index == dat->last_destination) {
                    rtx->save_num_of_txm = 1;
                    rtx->saved_send_time = dat->transmission_time;
                    event_logiii(VERBOSE,
                                 "Saving Time (after dequeue) : %lu secs, %06lu usecs for tsn=%u",
                                 dat->transmission_time.tv_sec,
                                 dat->transmission_time.tv_usec, dat->chunk_tsn);
                }
            }

            event_logi(INTERNAL_EVENT_0, "Now delete chunk with tsn...%u", chunk_tsn);
            old_dat = dat;
            rtx->chunk_list = g_list_remove(rtx->chunk_list, (gpointer)dat);
            free(old_dat);
        }
        /* it is a sorted list, so it is safe to get out in this case */
        if (after(chunk_tsn, ctsna))
            break;

    }
    return 0;
}


static int rtx_update_fwtsn_list(rtx_buffer *rtx, chunk_data* dat)
{
    int count = 0, result = 0, arrayLen = 0;
    pr_stream_data prChunk, *prPtr=NULL;
    SCTP_data_chunk* prChunkData = (SCTP_data_chunk*)dat->data;

    prChunk.stream_id = ntohs(prChunkData->stream_id);
    prChunk.stream_sn = ntohs(prChunkData->stream_sn);

    arrayLen = rtx->prChunks->len;
    if (arrayLen == 0) {
        rtx->prChunks = g_array_append_val(rtx->prChunks, prChunk);
        result = 2;
    } else {
        for (count = 0; count < arrayLen; count++) {
            prPtr = &g_array_index(rtx->prChunks, pr_stream_data, count);

            if (prChunk.stream_id < prPtr->stream_id) {    /* prepend */
                rtx->prChunks = g_array_insert_val(rtx->prChunks, count, prChunk);
                event_logii(VVERBOSE, "FW-TSN: prepended chunk (SID=%u, SSN=%u)",prChunk.stream_id, prChunk.stream_sn);
                result = -1;
                break;
            } else if (prChunk.stream_id == prPtr->stream_id) {   /* check/replace */
                if (sAfter(prChunk.stream_sn,prPtr->stream_sn)) {
                    event_logii(VVERBOSE, "FW-TSN: replaced chunk (SID=%u, SSN=%u)",prChunk.stream_id, prChunk.stream_sn);
                    prPtr->stream_sn = prChunk.stream_sn;
                    result = 0;
                    break;
                } else {
                    result = -2;
                    break;
                }
            } else if (count== arrayLen -1)  { /* and append */
                rtx->prChunks = g_array_insert_val(rtx->prChunks, count+1, prChunk);
                event_logii(VVERBOSE, "FW-TSN: appended chunk (SID=%u, SSN=%u)",prChunk.stream_id, prChunk.stream_sn);
                result = 1;
                break;
            }
        }
    }
    event_logiiii(VERBOSE, "Scheduling Chunk (TSN=%u, SID=%u, SSN=%u) for FW-TSN Report, Result: %d",
                dat->chunk_tsn, prChunk.stream_id, prChunk.stream_sn, result);
    return result;
}


static int rtx_advancePeerAckPoint(rtx_buffer *rtx)
{
    chunk_data *dat = NULL;
    GList* tmp = NULL;

    /* restart with a fresh array */
    g_array_free(rtx->prChunks, TRUE);
    rtx->prChunks = g_array_new(FALSE, TRUE, sizeof(pr_stream_data));

    tmp = g_list_first(rtx->chunk_list);

    while (tmp) {
        dat = (chunk_data*)g_list_nth_data(tmp, 0);
        if (!dat) return -1;
        if (!dat->hasBeenDropped) return 0;
        event_logi(VVERBOSE, "rtx_advancePeerAckPoint: Set advancedPeerAckPoint to %u", dat->chunk_tsn);
        rtx->advancedPeerAckPoint = dat->chunk_tsn;
        rtx_update_fwtsn_list(rtx, dat);
        tmp = g_list_next(tmp);
    }
    return 0;
}


int rtx_send_forward_tsn(rtx_buffer *rtx, unsigned int forward_tsn, unsigned int idx, gboolean sendAtOnce){

    int result;
    unsigned int count;

    SCTP_forward_tsn_chunk chk;
    pr_stream_data * psd;
    pr_stream_data   hton_psd;
    for (count = 0; count < rtx->prChunks->len; count++) {
        psd =  &g_array_index(rtx->prChunks, pr_stream_data, count);
        event_logii(VVERBOSE, "rtx_send_forward_tsn: chunk SID=%u, SSN=%u", psd->stream_id, psd->stream_sn);
        hton_psd.stream_id = htons(psd->stream_id);
        hton_psd.stream_sn = htons(psd->stream_sn);
        memcpy(&(chk.variableParams[count*sizeof(pr_stream_data)]), &hton_psd, sizeof(pr_stream_data));
    }
    chk.forward_tsn                = htonl(forward_tsn);
    chk.chunk_header.chunk_id      = CHUNK_FORWARD_TSN;
    chk.chunk_header.chunk_flags   = 0;
    chk.chunk_header.chunk_length  = htons((unsigned short)(sizeof(SCTP_chunk_header)+
                                           sizeof(unsigned int)+
                                           rtx->prChunks->len*sizeof(pr_stream_data)));

    event_logi(INTERNAL_EVENT_0, "===================>  Sending FORWARD TSN : %u",forward_tsn);

    result = bu_put_Ctrl_Chunk((SCTP_simple_chunk *) &chk, &idx);
    if (sendAtOnce == TRUE) {
        result = bu_sendAllChunks(&idx);
    }
    rtx->lastSentForwardTSN = forward_tsn;
    return result;
}


int rtx_get_obpa(unsigned int adIndex, unsigned int *totalInFlight)
{
    rtx_buffer *rtx=NULL;
    chunk_data *dat=NULL;
    int count, len, numBytesPerAddress = 0, numTotalBytes = 0;

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_FATAL, "rtx_buffer instance not set !");
        return SCTP_MODULE_NOT_FOUND;
    }
    len = g_list_length(rtx->chunk_list);
    if (len == 0) {
        *totalInFlight = 0;
        return 0;
    }
    for (count = 0; count < len; count++) {
        dat = (chunk_data*)g_list_nth_data(rtx->chunk_list, count);
        if (dat == NULL) break;
        /* do not count chunks that were retransmitted by T3 timer              */
        /* dat->hasBeenRequeued will be set to FALSE when these are sent again  */
        if (!dat->hasBeenDropped && !dat->hasBeenAcked && !dat->hasBeenRequeued) {
            if (dat->last_destination == adIndex) {
                numBytesPerAddress+= dat->chunk_len;
            }
            numTotalBytes += dat->chunk_len;
        }
    }
    *totalInFlight = numTotalBytes;
    return numBytesPerAddress;
}

/**
 * this is called by bundling, when a SACK needs to be processed. This is a LONG function !
 * FIXME : check correct update of rtx->lowest_tsn !
 * FIXME : handling of out-of-order SACKs
 * CHECK : did SACK ack lowest outstanding tsn, restart t3 timer (section 7.2.4.4) )
 * @param  adr_index   index of the address where we got that sack
 * @param  sack_chunk  pointer to the sack chunk
 * @return -1 on error, 0 if okay.
 */
int rtx_process_sack(unsigned int adr_index, void *sack_chunk, unsigned int totalLen)
{
    rtx_buffer *rtx=NULL;
    SCTP_sack_chunk *sack=NULL;
    fragment *frag=NULL;
    chunk_data *dat=NULL;
    GList* tmp_list = NULL;
    int result;
    unsigned int advertised_rwnd, old_own_ctsna;
    unsigned int low, hi, ctsna, pos;
    unsigned int chunk_len, var_len, gap_len, dup_len;
    unsigned int num_of_dups, num_of_gaps;
    unsigned int max_rtx_arraysize;
    unsigned int retransmitted_bytes = 0L;
    int chunks_to_rtx = 0;
    guint i=0;
    boolean rtx_necessary = FALSE, all_acked = FALSE, new_acked = FALSE;

    event_logi(INTERNAL_EVENT_0, "rtx_process_sack(address==%u)", adr_index);

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return (-1);
    }

    /*      chunk_list_debug(rtx->chunk_list); */

    sack = (SCTP_sack_chunk *) sack_chunk;
    ctsna = ntohl(sack->cumulative_tsn_ack);

    /* discard old SACKs */
    if (before(ctsna, rtx->highest_acked)) return 0;
    else rtx->highest_acked = ctsna;

    rtx->lastReceivedCTSNA = ctsna;

    old_own_ctsna = rtx->lowest_tsn;
    event_logii(VERBOSE, "Received ctsna==%u, old_own_ctsna==%u", ctsna, old_own_ctsna);

    adl_gettime(&(rtx->sack_arrival_time));

    event_logii(VERBOSE, "SACK Arrival Time : %lu secs, %06lu usecs",
                rtx->sack_arrival_time.tv_sec, rtx->sack_arrival_time.tv_usec);

    /* a false value here may do evil things !!!!! */
    chunk_len = ntohs(sack->chunk_header.chunk_length);
    /* this is just a very basic safety check */
    if (chunk_len > totalLen) return -1;

    rtx_check_fast_recovery(rtx,  ctsna);

    /* maybe add some more sanity checks  !!! */
    advertised_rwnd = ntohl(sack->a_rwnd);
    num_of_gaps = ntohs(sack->num_of_fragments);
    num_of_dups = ntohs(sack->num_of_duplicates);
    /* var_len contains gap acks AND duplicates ! Thanks to Janar for pointing this out */
    var_len = chunk_len - sizeof(SCTP_chunk_header) - 2 * sizeof(unsigned int) - 2 * sizeof(unsigned short);
    gap_len = num_of_gaps * sizeof(unsigned int);
    dup_len = num_of_dups * sizeof(unsigned int);
    if (var_len != gap_len+dup_len) {
        event_logiiii(EXTERNAL_EVENT, "Drop SACK chunk (incorrect length fields) chunk_len=%u, var_len=%u, gap_len=%u, dup_len=%u",
                     chunk_len, var_len, gap_len, dup_len);
        return -1;
    }

    event_logiiiii(VVERBOSE, "chunk_len=%u, a_rwnd=%u, var_len=%u, gap_len=%u, du_len=%u",
                    chunk_len, advertised_rwnd, var_len, gap_len, dup_len);

    if (after(ctsna, rtx->lowest_tsn) || (ctsna == rtx->lowest_tsn)) {
        event_logiii(VVERBOSE, "after(%u, %u) == true, call rtx_dequeue_up_to(%u)",
                     ctsna, rtx->lowest_tsn, ctsna);
        result = rtx_dequeue_up_to(ctsna, adr_index);
        if (result < 0) {
            event_log(EXTERNAL_EVENT_X,
                      "Bad ctsna arrived in SACK or no data in queue - discarding SACK");
            return -1;
        }
        rtx->lowest_tsn = ctsna;
        event_logi(VVERBOSE, "Updated rtx->lowest_tsn==ctsna==%u", ctsna);
    }

    chunk_list_debug(VVERBOSE, rtx->chunk_list);

    if (ntohs(sack->num_of_fragments) != 0) {
        event_logi(VERBOSE, "Processing %u fragment reports", ntohs(sack->num_of_fragments));
        max_rtx_arraysize = g_list_length(rtx->chunk_list);
        if (max_rtx_arraysize == 0) {
            /*rxc_send_sack_everytime(); */
            event_log(VERBOSE,
                      "Size of retransmission list was zero, we received fragment report -> ignore");
        } else {
            /* this may become expensive !!!!!!!!!!!!!!!! */
            pos = 0;
            dat = (chunk_data*)g_list_nth_data(rtx->chunk_list, i);
            if (rtx->chunk_list != NULL && dat != NULL) {
                do {
                frag = (fragment *) & (sack->fragments_and_dups[pos]);
                    low = ctsna + ntohs(frag->start);
                    hi = ctsna + ntohs(frag->stop);
                    event_logiii(VVERBOSE, "chunk_tsn==%u, lo==%u, hi==%u", dat->chunk_tsn, low, hi);
                    if (after(dat->chunk_tsn, hi)) {
                        event_logii(VVERBOSE, "after(%u,%u)==true", dat->chunk_tsn, hi);
                        pos += sizeof(fragment);
                        if (pos >= gap_len)
                            break;
                        continue;
                    }
                    if (before(dat->chunk_tsn, low)) {
                        /* this chunk is in a gap... */
                        dat->gap_reports++;
                        event_logiii(VVERBOSE,
                                     "Chunk in a gap: before(%u,%u)==true -- Marking it up (%u Gap Reports)!",
                                     dat->chunk_tsn, low, dat->gap_reports);
                        if (dat->gap_reports >= 4) {
                            /* FIXME : Get MTU of address, where RTX is to take place, instead of MAX_SCTP_PDU */
                            event_logi(VVERBOSE, "Got four gap_reports, ==checking== chunk %u for rtx OR drop", dat->chunk_tsn);
                            /* check sum of chunk sizes (whether it exceeds MTU for current address */
                            if(dat->hasBeenDropped == FALSE) {
                                if (timerisset(&dat->expiry_time) && timercmp(&(rtx->sack_arrival_time), &(dat->expiry_time), >)) {
                                    event_logi(VVERBOSE, "Got four gap_reports, dropping chunk %u !!!", dat->chunk_tsn);
                                    dat->hasBeenDropped = TRUE;
                                    /* this is a trick... */
                                    dat->hasBeenFastRetransmitted = TRUE;
                                } else if (dat->hasBeenFastRetransmitted == FALSE) {
                                    event_logi(VVERBOSE, "Got four gap_reports, scheduling %u for RTX", dat->chunk_tsn);
                                    /* retransmit it, chunk is not yet expired */
                                    rtx_necessary = TRUE;
                                    rtx_chunks[chunks_to_rtx] = dat;
                                    dat->gap_reports = 0;
                                    dat->hasBeenFastRetransmitted = TRUE;
                                    chunks_to_rtx++;
                                    /* preparation for what is in section 6.2.1.C */
                                    retransmitted_bytes += dat->chunk_len;
                                }
                            } /*  if(dat->hasBeenDropped == FALSE)  */
                        }     /*  if (dat->gap_reports == 4) */
                        /* read next chunk */
                        i++;
                        dat = (chunk_data*)g_list_nth_data(rtx->chunk_list, i);
                        if (dat == NULL)
                            break; /* was the last chunk in the list */
                        if (chunks_to_rtx == MAX_NUM_OF_CHUNKS)
                            break;
                        else continue;

                    } else if (between(low, dat->chunk_tsn, hi)) {
                        event_logiii(VVERBOSE, "between(%u,%u,%u)==true", low, dat->chunk_tsn, hi);
                        if (dat->hasBeenAcked == FALSE && dat->hasBeenDropped == FALSE) {
                            rtx->newly_acked_bytes += dat->chunk_len;
                            dat->hasBeenAcked = TRUE;
                            rtx->all_chunks_are_unacked = FALSE;
                            dat->gap_reports = 0;
                            if (dat->num_of_transmissions == 1 && adr_index == dat->last_destination) {
                                rtx->saved_send_time = dat->transmission_time;
                                rtx->save_num_of_txm = 1;
                                event_logiii(VERBOSE, "Saving Time (chunk in gap) : %lu secs, %06lu usecs for tsn=%u",
                                                     dat->transmission_time.tv_sec,
                                                     dat->transmission_time.tv_usec, dat->chunk_tsn);

                            }
                        }

                        if (dat->num_of_transmissions < 1) {
                            error_log(ERROR_FATAL, "Somehow dat->num_of_transmissions is less than 1 !");
                            break;
                        }
                        /* reset number of gap reports so it does not get fast retransmitted */
                        dat->gap_reports = 0;

                        i++;
                        dat = (chunk_data*)g_list_nth_data(rtx->chunk_list, i);
                        if (dat == NULL)
                            break; /* was the last chunk in the list or chunk is empty*/
                        else continue;
                    } else if (after(dat->chunk_tsn, hi)) {
                        error_log(ERROR_MINOR, "Problem with fragment boundaries (low_2 <= hi_1)");
                        break;
                    }

                }
                while ((pos < gap_len));

            }  /* end: if(rtx->chunk_list != NULL && dat != NULL) */
            else {
                event_log(EXTERNAL_EVENT,
                          "Received duplicated SACK for Chunks that are not in the queue anymore");
            }
        }

    } else {                    /* no gaps reported in this SACK */
        /* do nothing */
        if (rtx->all_chunks_are_unacked == FALSE) {
            /* okay, we have chunks in the queue that were acked by a gap report before       */
            /* and reneged: reset their status to unacked, since that is what peer reported   */
            /* fast retransmit reneged chunks, as per section   6.2.1.D.iii) of RFC 4960      */
            event_log(VVERBOSE, "rtx_process_sack: resetting all *hasBeenAcked* attributes");
            tmp_list = g_list_first(rtx->chunk_list);
            while (tmp_list) {
                dat = (chunk_data*)g_list_nth_data(tmp_list, 0);
                if (!dat) break;
                if (dat->hasBeenAcked == TRUE && dat->hasBeenDropped == FALSE) {
                    dat->hasBeenAcked = FALSE;
                    rtx_necessary = TRUE;
                    rtx_chunks[chunks_to_rtx] = dat;
                    dat->gap_reports = 0;
                    dat->hasBeenFastRetransmitted = TRUE;
                    event_logi(VVERBOSE, "rtx_process_sack: RENEG --> fast retransmitting chunk tsn %u ", dat->chunk_tsn);
                    chunks_to_rtx++;
                    /* preparation for what is in section 6.2.1.C */
                    retransmitted_bytes += dat->chunk_len;
                }
                tmp_list = g_list_next(tmp_list);
            }
            rtx->all_chunks_are_unacked = TRUE;
        }
    }

    event_log(INTERNAL_EVENT_0, "Marking of Chunks done in rtx_process_sack()");
    chunk_list_debug(VVERBOSE, rtx->chunk_list);

    /* also tell pathmanagement, that we got a SACK, possibly updating RTT/RTO. */
    rtx_rtt_update(adr_index, rtx);

    /*
     * new_acked==TRUE means our own ctsna has advanced :
     * also see section 6.2.1 (Note)
     */
    if (rtx->chunk_list == NULL) {
        if ((rtx->highest_tsn == rtx->highest_acked)) {
            all_acked = TRUE;
        }
        /* section 6.2.1.D.ii) */
        rtx->peer_arwnd = advertised_rwnd;
        rtx->lowest_tsn = rtx->highest_tsn;
        if (after(rtx->lowest_tsn, old_own_ctsna)) new_acked = TRUE;

        /* in the case where shutdown was requested by the ULP, and all is acked (i.e. ALL queues are empty) ! */
        if (rtx->shutdown_received == TRUE) {
            if (fc_readNumberOfQueuedChunks() == 0) {
                sci_allChunksAcked();
            }
        }
    } else {
        /* there are still chunks in that queue */
        if (rtx->chunk_list != NULL)
            dat = (chunk_data*)g_list_nth_data(rtx->chunk_list, 0);
        if (dat == NULL) {
            error_log(ERROR_FATAL, "Problem with RTX-chunklist, CHECK Program and List Handling");
            return -1;
        }
        rtx->lowest_tsn = dat->chunk_tsn;
        /* new_acked is true, when own  ctsna advances... */
        if (after(rtx->lowest_tsn, old_own_ctsna)) new_acked = TRUE;
    }

    if (rtx->shutdown_received == TRUE) rxc_send_sack_everytime();

    event_logiiii(VVERBOSE,
                  "rtx->lowest_tsn==%u, new_acked==%s, all_acked==%s, rtx_necessary==%s\n",
                  rtx->lowest_tsn, ((new_acked == TRUE) ? "TRUE" : "FALSE"),
                  ((all_acked == TRUE) ? "TRUE" : "FALSE"),
                  ((rtx_necessary == TRUE) ? "TRUE" : "FALSE"));

    if (rtx_necessary == FALSE) {
        fc_sack_info(adr_index, advertised_rwnd, ctsna, all_acked, new_acked,
                     rtx->newly_acked_bytes, rtx->num_of_addresses);
        rtx_reset_bytecounters(rtx);
    } else {
        /* retval = */
        fc_fast_retransmission(adr_index, advertised_rwnd,ctsna,
                                            retransmitted_bytes,
                                            all_acked, new_acked,
                                            rtx->newly_acked_bytes,
                                            rtx->num_of_addresses,
                                            chunks_to_rtx, rtx_chunks);
        rtx_reset_bytecounters(rtx);
    }

    if (before(rtx->advancedPeerAckPoint,ctsna)) {
        rtx->advancedPeerAckPoint = ctsna;
    }

    event_logiii(VERBOSE, "FORWARD_TSN check: ctsna: %u, advPeerAckPoint %u, rtx->lowest: %u",
        ctsna, rtx->advancedPeerAckPoint,rtx->lowest_tsn);
    /*-----------------------------------------------------------------------------*/
    if (mdi_supportsPRSCTP() == TRUE) {
        rtx_advancePeerAckPoint(rtx);
        if (after(rtx->advancedPeerAckPoint, ctsna)) {
            result = rtx_send_forward_tsn(rtx, rtx->advancedPeerAckPoint,adr_index, TRUE);
            event_logi(INTERNAL_EVENT_0, "rtx_process_sack: sent FORWARD_TSN, result : %d", result);
        }
    }
    /*-----------------------------------------------------------------------------*/

    return 0;
}


/**
 * called from flow-control to trigger retransmission of chunks that have previously
 * been sent to the address that timed out.
 * It is only called from flowcontrol, so association should be set correctly here
 * @param  assoc_id     pointer to the id value of the association, where timeout occurred
 * @param  address      address that timed out
 * @param   mtu         current path mtu (this needs to be fixed, too !)
 * @param   chunks      pointer to an array, that will contain pointers to chunks that need to
                        be retransmitted after this function returns. Provide space !
 * @return  -1 on error, 0 for empty list, else number of chunks that can be retransmitted
 */
int rtx_t3_timeout(void *assoc_id, unsigned int address, unsigned int mtu, chunk_data ** chunks)
{
    rtx_buffer *rtx;
    /* assume a SACK with 5 fragments and 5 duplicates :-) */
    /* it's size == 20+5*4+5*4 == 60        */
    unsigned int size = 60;
    int chunks_to_rtx = 0, result=0;
    struct timeval now;
    GList *tmp;
    chunk_data *dat=NULL;
    event_logi(INTERNAL_EVENT_0, "========================= rtx_t3_timeout (address==%u) =====================", address);

    rtx = (rtx_buffer *) mdi_readReliableTransfer();

    if (rtx->chunk_list == NULL) return 0;

    adl_gettime(&now);

    tmp = g_list_first(rtx->chunk_list);

    while (tmp) {
        if (((chunk_data *)(tmp->data))->num_of_transmissions < 1) {
            error_log(ERROR_FATAL, "Somehow chunk->num_of_transmissions is less than 1 !");
            break;
        }
        /* only take chunks that were transmitted to *address* */
        if (((chunk_data *)(tmp->data))->last_destination == address) {
            if (((chunk_data *)(tmp->data))->hasBeenDropped == FALSE) {
                if (timerisset( &((chunk_data *)(tmp->data))->expiry_time)) {
                    if (timercmp(&now, &((chunk_data *)(tmp->data))->expiry_time, > )) {
                        /* chunk has expired, maybe send FORWARD_TSN */
                        ((chunk_data *)(tmp->data))->hasBeenDropped = TRUE;
                    } else { /* chunk has not yet expired */
                        chunks[chunks_to_rtx] = (chunk_data*)tmp->data;
                        size += chunks[chunks_to_rtx]->chunk_len;
                        event_logii(VVERBOSE, "Scheduling chunk (tsn==%u), len==%u for rtx",
                                    chunks[chunks_to_rtx]->chunk_tsn, chunks[chunks_to_rtx]->chunk_len);
                        /* change SCI2002 */
                        chunks[chunks_to_rtx]->gap_reports = 0;
                        chunks_to_rtx++;
                    }
                } else {
                    chunks[chunks_to_rtx] = (chunk_data*)tmp->data;
                    size += chunks[chunks_to_rtx]->chunk_len;
                    event_logii(VVERBOSE, "Scheduling chunk (tsn==%u), len==%u for rtx",
                            chunks[chunks_to_rtx]->chunk_tsn, chunks[chunks_to_rtx]->chunk_len);
                    /* change SCI2002 */
                    chunks[chunks_to_rtx]->gap_reports = 0;

                    chunks_to_rtx++;
                }
            }       /* hasBeenDropped == FALSE     */
        }           /* last_destination == address */
        tmp = g_list_next(tmp);
    }
    event_logi(VVERBOSE, "Scheduled %d chunks for rtx", chunks_to_rtx);

    if (rtx->chunk_list != NULL) {
        dat = (chunk_data*)g_list_nth_data(rtx->chunk_list, 0);
        if (dat == NULL) {
           error_log(ERROR_FATAL, "Problem with RTX-chunklist, CHECK Program and List Handling");
           return chunks_to_rtx;
        }
        rtx->lowest_tsn = dat->chunk_tsn;
    } else {
        rtx->lowest_tsn = rtx->highest_tsn;
    }


    if (mdi_supportsPRSCTP() == TRUE) {
        /* properly advance rtx->advancedPeerAckPoint. If it is larger than last ctsna, send FW-TSN */
        rtx_advancePeerAckPoint(rtx);
        if (after(rtx->advancedPeerAckPoint, rtx->lastReceivedCTSNA)) {
            result = rtx_send_forward_tsn(rtx, rtx->advancedPeerAckPoint,address, TRUE);
            event_logi(INTERNAL_EVENT_0, "rtx_process_sack: sent FORWARD_TSN, result : %d", result);
        }
    }

    return chunks_to_rtx;
}


/**
 * a function called by FlowCtrl, when chunks have been given to the bundling
 * instance, but need to be kept in the buffer until acknowledged
 * @return 0 if OK, -1 if there is an error (list error)
 */
int rtx_save_retrans_chunks(void *data_chunk)
{
    chunk_data *dat;
    rtx_buffer *rtx;

    event_log(INTERNAL_EVENT_0, "rtx_save_retrans_chunks");

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return (-1);
    }

    /*      chunk_list_debug(rtx->chunk_list); */

    dat = (chunk_data *) data_chunk;

    /* TODO : check, if all values are set correctly */
    dat->gap_reports = 0L;
    rtx->chunk_list = g_list_insert_sorted(rtx->chunk_list, dat, (GCompareFunc)sort_tsn);

    if (after(dat->chunk_tsn, rtx->highest_tsn))
        rtx->highest_tsn = dat->chunk_tsn;
    else
        error_log(ERROR_MINOR, "Data Chunk has TSN that was already assigned (i.e. is too small)");

    chunk_list_debug(VVERBOSE, rtx->chunk_list);

    rtx->num_of_chunks = g_list_length(rtx->chunk_list);
    return 0;
}

/**
 * output debug messages for the list of saved chunks
 * @param   event_log_level  INTERNAL_EVENT_0 INTERNAL_EVENT_1 EXTERNAL_EVENT_X EXTERNAL_EVENT
 * @param   chunk_list  the list about which we print information
 */
void chunk_list_debug(short event_log_level, GList * chunk_list)
{
    chunk_data *dat;
    unsigned int size, counter;
    unsigned int last_tsn;
    guint i=0;

    last_tsn = 0;
    if (event_log_level <= Current_event_log_) {
/*    if (1) { */
        event_log(event_log_level, "------------- Chunk List Debug ------------------------");
        if ((size = g_list_length(chunk_list)) == 0) {
            event_log(event_log_level, " Size of List == 0 ! ");
        } else if (size <= 200) {
            event_logi(event_log_level, " Size of List == %u ! Printing first 10 chunks....", size);
            dat = (chunk_data*)g_list_nth_data(chunk_list, 0);
            last_tsn = dat->chunk_tsn - 1;
            if (size > 10) counter = 10;
            else counter = size;
            for (i=0; i<counter; i++) {
                dat = (chunk_data*)g_list_nth_data(chunk_list, i);
                event_logii(event_log_level,
                            "________________ Chunk _________________\nChunk Size %u  -- TSN : %u  ",
                            dat->chunk_len, dat->chunk_tsn);
                event_logiii(event_log_level, "Gap repts=%u -- initial dest=%d  Transmissions = %u",
                              dat->gap_reports, dat->initial_destination, dat->num_of_transmissions);
                event_logii(event_log_level,  "Transmission Time : %lu secs, %06lu usecs",
                            dat->transmission_time.tv_sec, dat->transmission_time.tv_usec);
                event_logii(event_log_level, "Destination[%u] == %u", dat->num_of_transmissions,
                            dat->last_destination);

                if (dat->chunk_len > 10000)
                    error_log(ERROR_FATAL, "Corrput TSN length in queue 1 ! Terminate");

                if (! after(dat->chunk_tsn, last_tsn)) error_log(ERROR_FATAL, "TSN not in sequence ! Bye");
                last_tsn = dat->chunk_tsn;
            }
            for (i=counter; i<size; i++) {
                dat = (chunk_data*)g_list_nth_data(chunk_list, i);
                if (! after(dat->chunk_tsn, last_tsn))
                    error_log(ERROR_FATAL, "Higher TSNs not in sequence ! Terminate");
                if (dat->chunk_tsn - last_tsn > 10000)
                    error_log(ERROR_FATAL, "Corrput TSN in queue ! Terminate");
                if (dat->chunk_len > 10000)
                    error_log(ERROR_FATAL, "Corrput TSN length in queue 2 ! Terminate");

                last_tsn = dat->chunk_tsn;
            }
            event_log(event_log_level, "------------- Chunk List Debug : DONE  ------------------------");
        } else {
            event_logi(event_log_level, " Size of List == %u ! ", size);
        }
    }
}


/**
 * function that returns the consecutive tsn number that has been acked by the peer.
 * @return the ctsna value
 */
unsigned int rtx_readLocalTSNacked()
{
    rtx_buffer *rtx;

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        event_log(INTERNAL_EVENT_0, "rtx_buffer instance not set !");
        return (0);
    }
    return rtx->lowest_tsn;
}

gboolean rtx_is_lowest_tsn(unsigned int atsn)
{
    rtx_buffer *rtx;

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        event_log(INTERNAL_EVENT_0, "rtx_buffer instance not set !");
        return (0);
    }
    return rtx->lowest_tsn == atsn;
}


/**
 * called, when a Cookie, that indicates the peer's restart, is received in the ESTABLISHED state
    -> we need to restart too
 */
void* rtx_restart_reliable_transfer(void* rtx_instance, unsigned int numOfPaths, unsigned int iTSN)
{
    void * new_rtx = NULL;
    /* ******************************************************************* */
    /* IMPLEMENTATION NOTE: It is an implementation decision on how
       to handle any pending datagrams. The implementation may elect
       to either A) send all messages back to its upper layer with the
       restart report, or B) automatically re-queue any datagrams
       pending by marking all of them as never-sent and assigning
       new TSN's at the time of their initial transmissions based upon
       the updated starting TSN (as defined in section 5).
       Version 13 says : SCTP data chunks MAY be retained !
       (this is implementation specific)
       ******************************************************************** */
    if (!rtx_instance) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return NULL;
    }
    event_logi(INTERNAL_EVENT_0, "Restarting Reliable Transfer with %u Paths", numOfPaths);

    rtx_delete_reltransfer(rtx_instance);
    /* For ease of implementation we will delete all old data ! */
    /* chunk_list_debug(VVERBOSE, rtx->chunk_list); */
    new_rtx = rtx_new_reltransfer(numOfPaths, iTSN);

    return new_rtx;
}

int rtx_dequeueOldestUnackedChunk(unsigned char *buf, unsigned int *len, unsigned int *tsn,
                                  unsigned short *sID, unsigned short *sSN,unsigned int* pID,
                                  unsigned char* flags, gpointer* ctx)
{
    int listlen, result;
    rtx_buffer *rtx;
    chunk_data *dat = NULL;
    SCTP_data_chunk* dchunk;

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return SCTP_MODULE_NOT_FOUND;
    }
    if (rtx->chunk_list == NULL) return  SCTP_UNSPECIFIED_ERROR;
    listlen = g_list_length(rtx->chunk_list);
    if (listlen <= 0) return SCTP_UNSPECIFIED_ERROR;
    dat = (chunk_data*)g_list_nth_data(rtx->chunk_list, 0);
    if (dat->num_of_transmissions == 0) return SCTP_UNSPECIFIED_ERROR;
    if ((*len) <  (dat->chunk_len - FIXED_DATA_CHUNK_SIZE)) return SCTP_BUFFER_TOO_SMALL;

    dchunk = (SCTP_data_chunk*) dat->data;
    *len = dat->chunk_len - FIXED_DATA_CHUNK_SIZE;
    memcpy(buf, dchunk->data, dat->chunk_len - FIXED_DATA_CHUNK_SIZE);
    *tsn = dat->chunk_tsn;
    *sID = ntohs(dchunk->stream_id);
    *sSN = ntohs(dchunk->stream_sn);
    *pID = dchunk->protocolId;
    *flags = dchunk->chunk_flags;
    *ctx = dat->context;
    event_logiii(VERBOSE, "rtx_dequeueOldestUnackedChunk() returns chunk tsn %u, num-trans: %u, chunks left: %u",
            dat->chunk_tsn, dat->num_of_transmissions, listlen-1);

    result = fc_dequeueUnackedChunk(dat->chunk_tsn);
    event_logi(VERBOSE, "fc_dequeueUnackedChunk() returns  %u", result);
    rtx->chunk_list = g_list_remove(rtx->chunk_list, (gpointer) dat);
    /* be careful ! data may only be freed once: this module ONLY takes care of unacked chunks */
    chunk_list_debug(VVERBOSE, rtx->chunk_list);

    free(dat);
    return (listlen-1);
}


/**
 * Function returns the number of chunks that are waiting in the queue to be acked
 * @return size of the retransmission queue
 */
unsigned int rtx_readNumberOfUnackedChunks()
{
    unsigned int queue_len;
    rtx_buffer *rtx;

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return 0;
    }
    queue_len = g_list_length(rtx->chunk_list);
    event_logi(VERBOSE, "rtx_readNumberOfUnackedChunks() returns %u", queue_len);
    return queue_len;
}


/**
 * function to return the last a_rwnd value we got from our peer
 * @return  peers advertised receiver window
 */
unsigned int rtx_read_remote_receiver_window()
{
    rtx_buffer *rtx;

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return 0;
    }
    event_logi(VERBOSE, "rtx_read_remote_receiver_window returns %u", rtx->peer_arwnd);
    return rtx->peer_arwnd;
}


/**
 * function to set the a_rwnd value when we got it from our peer
 * @param  new_arwnd      peers newly advertised receiver window
 * @return  0 for success, -1 for error
 */
int rtx_set_remote_receiver_window(unsigned int new_arwnd)
{
    rtx_buffer *rtx;

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return -1;
    }
    event_logi(VERBOSE, "rtx_set_his_receiver_window(%u)", new_arwnd);
    rtx->peer_arwnd = new_arwnd;
    return 0;
}

/**
 * function that is called by SCTP-Control, when ULP requests
 * shutdown in an established association
 * @return  0 for success, -1 for error
 */
int rtx_shutdown()
{
    rtx_buffer *rtx;

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return -1;
    }
    event_log(VERBOSE, "rtx_shutdown() activated");
    rtx->shutdown_received = TRUE;
    event_log(VERBOSE, "calling fc_shutdown()");
    fc_shutdown();
    return 0;
}


/*
   CHECKME : Check retransmission procedures case when SHUTDOWN is initiated.
 */


/**
 * function that is called by SCTP-Control, when peer indicates
 * shutdown and sends us his last ctsna...this function dequeues
 * all chunks, and returns the number of chunks left in the queue
 * @param  ctsna    up to this tsn we can dequeue all chunks here
 * @return  number of chunks that are still queued
 */
unsigned int rtx_rcv_shutdown_ctsna(unsigned int ctsna)
{
    rtx_buffer *rtx;
    int result;
    int rtx_queue_len = 0;
    gboolean all_acked = FALSE, new_acked = FALSE;

    event_logi(INTERNAL_EVENT_0, "rtx_rcv_shutdown_ctsna(ctsna==%u)", ctsna);

    rtx = (rtx_buffer *) mdi_readReliableTransfer();
    if (!rtx) {
        error_log(ERROR_MAJOR, "rtx_buffer instance not set !");
        return (0);
    }
    rxc_send_sack_everytime();

    if (after(ctsna, rtx->lowest_tsn) || (ctsna == rtx->lowest_tsn)) {
        event_logiii(VVERBOSE, "after(%u, %u) == true, call rtx_dequeue_up_to(%u)",
                     ctsna, rtx->lowest_tsn, ctsna);
        result = rtx_dequeue_up_to(ctsna , 0);
        if (result < 0) {
            event_log(VVERBOSE, "Bad ctsna arrived in shutdown or no chunks in queue");
        }
        rtx->lowest_tsn = ctsna;
        event_logi(VVERBOSE, "Updated rtx->lowest_tsn==ctsna==%u", ctsna);
        rtx_queue_len =  g_list_length(rtx->chunk_list);

        if (rtx->newly_acked_bytes != 0) new_acked = TRUE;
        if (rtx_queue_len == 0) all_acked = TRUE;
        fc_sack_info(0, rtx->peer_arwnd, ctsna, (boolean)all_acked, (boolean)new_acked,
                     rtx->newly_acked_bytes, rtx->num_of_addresses);
        rtx_reset_bytecounters(rtx);
    } else {
        rtx_queue_len =  g_list_length(rtx->chunk_list);
    }


    if (rtx->shutdown_received == TRUE) {
        if (fc_readNumberOfQueuedChunks() == 0 && rtx_queue_len == 0) {
            sci_allChunksAcked();
        }
    }
    return (rtx_queue_len);
}



