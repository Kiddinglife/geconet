/* $Id: pathmanagement.c 2771 2013-05-30 09:09:07Z dreibh $
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
#include "chunkHandler.h"
#include "SCTP-control.h"
#include "adaptation.h"
#include "bundling.h"
#include "pathmanagement.h"

/*------------------------ defines -----------------------------------------------------------*/
#define RTO_ALPHA            0.125
#define RTO_BETA              0.25


/*----------------------- Typedefs ------------------------------------------------------------*/


/**
 * this struct contains the necessary data per (destination or) path.
 * There may be more than one within an association
 */
typedef struct PATHDATA
{
    /*@{ */
    /** operational state of pathmanagement for one path */
    short state;
    /** true if heartbeat is enabled */
    boolean heartbeatEnabled;
    /** true as long as RTO-Calc. has been done */
    boolean firstRTO;
    /** Only once per HB-intervall */
    boolean timerBackoff;
    /** set to true when data chunks are acknowledged */
    boolean chunksAcked;
    /** TRUE, if chunks have been sent over that path within last RTO */
    boolean chunksSent;
    /** set to true when a heartbeat is sent. */
    boolean heartbeatSent;
    /** set to true when a hearbeat is acknowledged and to false when a
       heartbeat is sent when the heartbeat timer expires. */
    boolean heartbeatAcked;
    /** Counter for retransmissions on a single path */
    unsigned int pathRetranscount;
    /** Retransmission time out used for all retrans. timers */
    unsigned int rto;
    /** smoothed round trip time */
    unsigned int srtt;
    /** round trip time variation */
    unsigned int rttvar;
    /** defines the rate at which heartbeats are sent */
    unsigned int heartbeatIntervall;
    /** ID of the heartbeat timer */
    TimerID hearbeatTimer;
    /** time of last rto update */
    struct timeval rto_update;
    /** ID of path */
    unsigned int pathID;
    /*@} */
} PathData;


/**
 * this struct contains all necessary data for one instance of the path management
 * module. There is one such module per existing association.
 */
typedef struct PATHMANDATA
{
    /*@{ */
    /** stores the current primary path */
    short primaryPath;
    /** the number of paths used by this assoc. */
    short numberOfPaths;
    /** Counter for all retransmissions over all paths */
    unsigned int peerRetranscount;
    /** pointer to path-specific data */
    PathData *pathData;
    /** association-ID */
    unsigned int associationID;
    /** maximum retransmissions per path parameter */
    int maxPathRetransmissions;
    /** initial RTO, a configurable parameter */
    int rto_initial;
    /** minimum RTO, a configurable parameter */
    int rto_min;
    /** maximum RTO, a configurable parameter */
    int rto_max;
    /*@} */
} PathmanData;


/*----------------------Declares ----------------------------------------------------------------*/

/**
 * this pointer is set to point to the current asssociation's path management struct
 * it becomes zero after we have treated an incoming/outgoing datagram
 */
PathmanData *pmData;

/*-------------------------- Function Implementations -------------------------------------------*/

/*------------------- Internal Functions --------------------------------------------------------*/

/**
  return the current system time converted to a value of  milliseconds.
  MSB of tv_sec field are removed in order
  to make representation in millisecs possible. This done by taking the remainder of
  a division by 1728000 = 20x24x60x60, restarting millisecs count every 20 days.
  @return unsigned 32 bit value representing system time in milliseconds. Hmmmh.
*/
unsigned int pm_getTime(void)
{
    unsigned int curTimeMilli;
    struct timeval curTime;

    adl_gettime(&curTime);

    /* modulo operation overlfows every 20 days */
    curTimeMilli = (curTime.tv_sec % 1728000) * 1000 + curTime.tv_usec / 1000;

    return curTimeMilli;
}                               /* end: pm_ sctp_getTime */


/**
 *  handleChunksRetransmitted is called whenever datachunks are retransmitted or a hearbeat-request
 *  has not been acknowledged within the current heartbeat-intervall. It increases path- and peer-
 *  retransmission counters and compares these counters to the corresonding thresholds.
 *  @param  pathID index to the path that CAUSED retransmission
 *  @return TRUE if association was deleted, FALSE if not
 */
static gboolean handleChunksRetransmitted(short pathID)
{
    short pID;
    boolean allPathsInactive;
    PathmanData *old_pmData;

    if (!pmData->pathData) {
        error_logi(ERROR_MAJOR, "handleChunksRetransmitted(%d): Path Data Structures not initialized yet, returning !", pathID);
        return FALSE;
    }

    event_logiii(INTERNAL_EVENT_0,
                 "handleChunksRetransmitted(%d) : path-rtx-count==%u, peer-rtx-count==%u",
                 pathID, pmData->pathData[pathID].pathRetranscount, pmData->peerRetranscount);

    if (pmData->pathData[pathID].state == PM_PATH_UNCONFIRMED) {

        pmData->pathData[pathID].pathRetranscount++;

    } else if (pmData->pathData[pathID].state == PM_ACTIVE) {

        pmData->pathData[pathID].pathRetranscount++;
        pmData->peerRetranscount++;

    } else {
        event_log(INTERNAL_EVENT_0,
                  "handleChunksRetransmitted: ignored, because already inactive");
        return FALSE;
    }

    if (pmData->peerRetranscount >= (unsigned int)sci_getMaxAssocRetransmissions()) {
        mdi_deleteCurrentAssociation();
        mdi_communicationLostNotif(SCTP_COMM_LOST_EXCEEDED_RETRANSMISSIONS);
        mdi_clearAssociationData();

        event_log(INTERNAL_EVENT_0, "handleChunksRetransmitted: communication lost");
        return TRUE;
    }

    if (pmData->pathData[pathID].pathRetranscount >= (unsigned int)pmData->maxPathRetransmissions) {
        /* Set state of this path to inactive and notify change of state to ULP */
        pmData->pathData[pathID].state = PM_INACTIVE;
        event_logi(INTERNAL_EVENT_0, "handleChunksRetransmitted: path %d to INACTIVE ", pathID);
        /* check if an active path is left */
        allPathsInactive = TRUE;
        for (pID = 0; pID < pmData->numberOfPaths; pID++) {
            if (pmData->pathData[pID].state == PM_ACTIVE) {
                allPathsInactive = FALSE;
            }
        }
        if (allPathsInactive) {
            /* No active parts are left, communication lost to ULP */
            mdi_deleteCurrentAssociation();
            mdi_communicationLostNotif(SCTP_COMM_LOST_ENDPOINT_UNREACHABLE);
            /* will be called later anyway !
                mdi_clearAssociationData(); */
            event_log(INTERNAL_EVENT_0,
                      "handleChunksRetransmitted: communication lost (all paths are INACTIVE)");
            return TRUE;
        } else {
            old_pmData = pmData;
            mdi_networkStatusChangeNotif(pathID, PM_INACTIVE);
            pmData = old_pmData;
        }
    }

    return FALSE;
}                               /* end: handleChunksRetransmitted */




/**
 * Function is used to update RTT, SRTT, RTO values after chunks have been acked.
 * CHECKME : this function is called too often with RTO == 0;
 * Is there one update per RTT ?
 * @param  pathID index of the path where data was acked
 * @param  newRTT new RTT measured, when data was acked, or zero if it was retransmitted
*/
static void handleChunksAcked(short pathID, unsigned int newRTT)
{

    if (!pmData->pathData) {
        error_logi(ERROR_MAJOR, "handleChunksAcked(%d): Path Data Structures not initialized yet, returning !", pathID);
        return;
    }

    event_logii(INTERNAL_EVENT_0, "handleChunksAcked: pathID: %u, new RTT: %u msecs", pathID, newRTT);

    if (newRTT > 0) {
        /* RTO measurement done */
        /* calculate new RTO, SRTT and RTTVAR */
        if (pmData->pathData[pathID].firstRTO) {
            pmData->pathData[pathID].srtt = newRTT;
            pmData->pathData[pathID].rttvar = max(newRTT / 2, GRANULARITY);;
            pmData->pathData[pathID].rto = max(min(newRTT * 3, (unsigned int)pmData->rto_max), (unsigned int)pmData->rto_min);
            pmData->pathData[pathID].firstRTO = FALSE;
        } else {
            pmData->pathData[pathID].rttvar = (unsigned int)
                ((1. - RTO_BETA) * pmData->pathData[pathID].rttvar +
                RTO_BETA * abs(pmData->pathData[pathID].srtt - newRTT));
            pmData->pathData[pathID].rttvar = max((unsigned int)pmData->pathData[pathID].rttvar, GRANULARITY);

            pmData->pathData[pathID].srtt = (unsigned int)
                ((1. - RTO_ALPHA) * pmData->pathData[pathID].srtt + RTO_ALPHA * newRTT);

            pmData->pathData[pathID].rto = pmData->pathData[pathID].srtt +
                4 * pmData->pathData[pathID].rttvar;
            pmData->pathData[pathID].rto = max(min((unsigned int)pmData->pathData[pathID].rto, (unsigned int)pmData->rto_max), (unsigned int)pmData->rto_min);
        }
        event_logiii(INTERNAL_EVENT_0,
                     "handleChunksAcked: RTO update done: RTTVAR: %u msecs, SRTT: %u msecs, RTO: %u msecs",
                     pmData->pathData[pathID].rttvar,
                     pmData->pathData[pathID].srtt, pmData->pathData[pathID].rto);
    } else {
        event_log(INTERNAL_EVENT_0, "handleChunksAcked: chunks acked without RTO-update");
    }

    /* reset counters */
    pmData->pathData[pathID].pathRetranscount = 0;
    pmData->peerRetranscount = 0;
}                               /* end: handleChunksAcked */



/*----------------- Functions to answer peer HB requests -----------------------------------------*/

/**
  pm_heartbeat is called when a heartbeat was received from the peer.
  This function just takes that chunk, and sends it back.
  @param heartbeatChunk pointer to the heartbeat chunk
  @param source_address address we received the HB chunk from (and where it is echoed)
*/
void pm_heartbeat(SCTP_heartbeat * heartbeatChunk, unsigned int source_address)
{
    heartbeatChunk->chunk_header.chunk_id = CHUNK_HBACK;

    bu_put_Ctrl_Chunk((SCTP_simple_chunk *) heartbeatChunk, &source_address);
    bu_sendAllChunks(&source_address);
}                               /* end: pm_heartbeat */



/*------------------- Signals --------------------------------------------------------------------*/

/*------------------- Signals from the Unix-Interface --------------------------------------------*/

/**
  pm_heartbeatTimer is called by the adaption-layer when the heartbeat timer expires.
  It may set the path to inactive, or restart timer, or even cause COMM LOST
  As all timer callbacks, it takes three arguments  (two pointers to necessary data)
  @param timerID  ID of the HB timer that expired.
  @param associationIDvoid  pointer to the association-ID
  @param pathIDvoid         pointer to the path-ID
*/
void pm_heartbeatTimer(TimerID timerID, void *associationIDvoid, void *pathIDvoid)
{
    unsigned int associationID;
    unsigned int pathID;
    ChunkID heartbeatCID;
    gboolean removed_association = FALSE;

    associationID = *((unsigned int *) associationIDvoid);
    pathID = *((unsigned int *) pathIDvoid);
    if (mdi_setAssociationData(associationID)) {
        /* error log: expired timer refers to a non existent association. */
        error_logi(ERROR_MAJOR,
                   "init timer expired association %08u does not exist", associationID);
        return;
    }
    pmData = (PathmanData *) mdi_readPathMan();
    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_heartbeatTimer: mdi_readPathMan failed");
        mdi_clearAssociationData();
        return;
    }
    if (!(pathID >= 0 && pathID < (unsigned int)pmData->numberOfPaths)) {
        error_logi(ERROR_MAJOR, "pm_heartbeatTimer: invalid path ID %d", pathID);
        mdi_clearAssociationData();
        return;
    }
    event_logi(INTERNAL_EVENT_0, "Heartbeat timer expired for path %u", pathID);

    if (pmData->pathData[pathID].heartbeatSent && !pmData->pathData[pathID].heartbeatAcked) {
        /* Heartbeat has been sent and not acknowledged: handle as retransmission */
        if (pmData->pathData[pathID].state == PM_ACTIVE) {
            /* Handling of unacked heartbeats is the same as that of unacked data chunks.
               The state after calling pm_chunksRetransmitted may have changed to inactive. */
           removed_association = handleChunksRetransmitted((short)pathID);
           if (removed_association)
                event_logi(INTERNAL_EVENT_0, "Association was removed by handleChunksRetransmitted(%u)!!!!",pathID);
        } else if (pmData->pathData[pathID].state == PM_INACTIVE) {
            /* path already inactive, dont increase counter etc. */
            ;
        }

        if (!removed_association) {
            if (!pmData->pathData[pathID].timerBackoff) {
                /* Timer backoff */
                pmData->pathData[pathID].rto = min(2 * pmData->pathData[pathID].rto, (unsigned int)pmData->rto_max);
                event_logii(VERBOSE, "Backing off timer : Path %d, RTO= %u", pathID,pmData->pathData[pathID].rto);
            }
        }
    }

    if (!removed_association &&
        !pmData->pathData[pathID].chunksAcked &&
         pmData->pathData[pathID].heartbeatEnabled &&
        !pmData->pathData[pathID].chunksSent) {
        /* Remark: If commLost is detected in handleChunksRetransmitted, the current association
           is marked for deletetion. Doing so, all timers are stop. The HB-timers are
           stopped by calling pm_disableHB in mdi_deleteCurrentAssociation. This is why
           heartBeatEnabled is checked above.
         */
        /* send heartbeat if no chunks have been acked in the last HB-intervall (path is idle). */
        event_log(VERBOSE, "--------------> Sending HB");
        heartbeatCID = ch_makeHeartbeat(pm_getTime(), pathID);
        bu_put_Ctrl_Chunk(ch_chunkString(heartbeatCID), &pathID);
        bu_sendAllChunks(&pathID);
        ch_deleteChunk(heartbeatCID);
        pmData->pathData[pathID].heartbeatSent = TRUE;
    } else if (!removed_association) {
        pmData->pathData[pathID].heartbeatSent = FALSE;
    }

    if (!removed_association) {
        if (pmData->pathData[pathID].heartbeatEnabled) {
            /* heartbeat could have been disabled when the association went down after commLost
               detected in handleChunksRetransmitted */
               pmData->pathData[pathID].hearbeatTimer =
                   adl_startTimer(pmData->pathData[pathID].heartbeatIntervall +
                                    pmData->pathData[pathID].rto,
                                    &pm_heartbeatTimer,
                                    TIMER_TYPE_HEARTBEAT,
                                    (void *) &pmData->associationID,
                                    (void *) &pmData->pathData[pathID].pathID);

                   /* reset this flag, so we can check, whether the path was idle */
                   pmData->pathData[pathID].chunksSent = FALSE;

                   event_logiii(INTERNAL_EVENT_0,
                        "Heartbeat timer started with %u msecs for path %u, RTO=%u msecs",
                        (pmData->pathData[pathID].heartbeatIntervall+pmData->pathData[pathID].rto), pathID,
                        pmData->pathData[pathID].rto);
        }
    }

    if (!removed_association) {
        pmData->pathData[pathID].heartbeatAcked = FALSE;
        pmData->pathData[pathID].timerBackoff = FALSE;
        pmData->pathData[pathID].chunksAcked = FALSE;
    }
    mdi_clearAssociationData();
}                               /* end: pm_heartbeatTimer */


/**
 * simple function that sends a heartbeat chunk to the indicated address
 * @param  pathID index to the address, where HB is to be sent to
 */
int pm_doHB(gshort pathID)
{
    ChunkID heartbeatCID;
    guint32 pid;

    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_doHB: mdi_readPathMan failed");
        return SCTP_MODULE_NOT_FOUND;
    }
    if (!pmData->pathData) {
        error_logi(ERROR_MAJOR, "pm_doHB(%d): Path Data Structures not initialized yet, returning !", pathID);
        return SCTP_UNSPECIFIED_ERROR;
    }

    if (!(pathID >= 0 && pathID < pmData->numberOfPaths)) {
        error_logi(ERROR_MAJOR, "pm_doHB : invalid path ID: %d", pathID);
        return SCTP_PARAMETER_PROBLEM;
    }
    pid = (guint32)pathID;
    heartbeatCID = ch_makeHeartbeat(pm_getTime(), pathID);
    bu_put_Ctrl_Chunk(ch_chunkString(heartbeatCID),&pid);
    bu_sendAllChunks(&pid);
    ch_deleteChunk(heartbeatCID);
    pmData->pathData[pathID].heartbeatSent = TRUE;

    return SCTP_SUCCESS;
}


/**
 * pm_heartbeatAck is called when a heartbeat acknowledgement was received from the peer.
 * checks RTTs, normally resets error counters, may set path back to ACTIVE state
 * @param heartbeatChunk pointer to the received heartbeat ack chunk
 */
void pm_heartbeatAck(SCTP_heartbeat * heartbeatChunk)
{
    unsigned int roundtripTime;
    unsigned int sendingTime;
    short pathID;
    ChunkID heartbeatCID;
    PathmanData *old_pmData = NULL;
    gboolean hbSignatureOkay = FALSE;

    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_heartbeatAck: mdi_readPathMan failed");
        return;
    }
    if (!pmData->pathData) {
        error_log(ERROR_MAJOR, "pm_heartbeatAck: Path Data Structures not initialized yet, returning !");
        return;
    }

    heartbeatCID = ch_makeChunk((SCTP_simple_chunk *) heartbeatChunk);
    pathID = ch_HBpathID(heartbeatCID);
    sendingTime = ch_HBsendingTime(heartbeatCID);
    roundtripTime = pm_getTime() - sendingTime;
    event_logii(INTERNAL_EVENT_0, "HBAck for path %u, RTT = %u msecs", pathID, roundtripTime);

    hbSignatureOkay = ch_verifyHeartbeat(heartbeatCID);
    event_logi(EXTERNAL_EVENT, "HB Signature is %s", (hbSignatureOkay == TRUE)?"correct":"FALSE");

    if (hbSignatureOkay == FALSE) {
        error_log(ERROR_FATAL, "pm_heartbeatAck: FALSE SIGNATURE !!!!!!!!!!!!!!!");
        return;
    }

    ch_forgetChunk(heartbeatCID);

    if (!(pathID >= 0 && pathID < pmData->numberOfPaths)) {
        error_logi(ERROR_MAJOR, "pm_heartbeatAck: invalid path ID %d", pathID);
        return;
    }

    /* this also resets error counters */
    handleChunksAcked(pathID, roundtripTime);

    if (pmData->pathData[pathID].state == PM_INACTIVE || pmData->pathData[pathID].state == PM_PATH_UNCONFIRMED) {
        /* Handling of acked heartbeats is the simular that that of acked data chunks. */
        /* change to the active state */
        pmData->pathData[pathID].state = PM_ACTIVE;
        event_logi(INTERNAL_EVENT_0, "pathID %d changed to ACTIVE", pathID);
        old_pmData = pmData;
        mdi_networkStatusChangeNotif(pathID, PM_ACTIVE);
        pmData = old_pmData;

        /* restart timer with new RTO */
        sctp_stopTimer(pmData->pathData[pathID].hearbeatTimer);
        pmData->pathData[pathID].hearbeatTimer =
            adl_startTimer( (pmData->pathData[pathID].heartbeatIntervall + pmData->pathData[pathID].rto),
                            &pm_heartbeatTimer,
                            TIMER_TYPE_HEARTBEAT,
                            (void *) &pmData->associationID,
                            (void *) &pmData->pathData[pathID].pathID);
    }
    pmData->pathData[pathID].heartbeatAcked = TRUE;
    pmData->pathData[pathID].timerBackoff = FALSE;

}                               /* end: pm_heartbeatAck */



/*------------------- Signals from SCTP internal modules -----------------------------------------*/

/**
 * pm_chunksAcked is called by reliable transfer whenever chunks have been acknowledged.
 * @param pathID   last path-ID where chunks were sent to (and thus probably acked from)
 * @param newRTT   the newly determined RTT in milliseconds, and 0 if retransmitted chunks had been acked
 */
void pm_chunksAcked(short pathID, unsigned int newRTT)
{
    struct timeval now;

    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_chunksAcked: mdi_readPathMan failed");
        return;
    }
    if (!pmData->pathData) {
        error_logii(ERROR_MAJOR, "pm_chunksAcked(%d, %u): Path Data Structures not initialized yet, returning !",
                    pathID, newRTT);
        return;
    }

    if (!(pathID >= 0 && pathID < pmData->numberOfPaths)) {
        error_logi(ERROR_MAJOR, "pm_chunksAcked: invalid path ID: %d", pathID);
        return;
    }

    if (newRTT > (unsigned int)pmData->rto_max)
        error_logi(ERROR_MINOR, "pm_chunksAcked: Warning: RTO > RTO_MAX: %d", newRTT);

    newRTT = min(newRTT, (unsigned int)pmData->rto_max);

    if (pmData->pathData[pathID].state == PM_ACTIVE) {
        /* Update RTO only if is the first data chunk acknowldged in this RTT intervall. */
        adl_gettime(&now);
        if (timercmp(&now, &(pmData->pathData[pathID].rto_update), < )) {
            event_logiiii(VERBOSE, "pm_chunksAcked: now %lu sec, %lu usec - no update before %lu sec, %lu usec",
                        now.tv_sec, now.tv_usec,
                        pmData->pathData[pathID].rto_update.tv_sec,
                        pmData->pathData[pathID].rto_update.tv_usec);
            newRTT = 0;
        } else {
            if (newRTT != 0) {
                /* only if actually new valid RTT measurement is taking place, do update the time */
                pmData->pathData[pathID].rto_update = now;
                adl_add_msecs_totime(&(pmData->pathData[pathID].rto_update), pmData->pathData[pathID].srtt);
            }
        }
        handleChunksAcked(pathID, newRTT);
        pmData->pathData[pathID].chunksAcked = TRUE;
    } else {
        /* FIX :::::::
            we got an ACK possibly from on an inactive path */
        /* immediately send out a Heartbeat on that path, then when we get */
        /* a HB-ACK, we can set the path back to ACTIVE */
        /* when original newRTT is 0 then we got a RTX-SACK, else if we are */
        /* inactive, get ACTIVE */
        /* Nay, nay nay !   stale acknowledgement, silently discard */
        return;
    }
}                               /* end: pm_chunksAcked */


/**
 * helper function, that simply sets the chunksSent flag of this path management instance to TRUE
 * @param pathID  index of the address, where flag is set
 */
void pm_chunksSentOn(short pathID)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_chunksSentOn: mdi_readPathMan failed");
        return;
    }
    if (pmData->pathData == NULL) {
        error_logi(ERROR_MAJOR, "pm_chunksSentOn(%d): Path Data Structures not initialized yet, returning !", pathID);
        return;
    }

    if (!(pathID >= 0 && pathID < pmData->numberOfPaths)) {
        error_logi(ERROR_MAJOR, "pm_chunksSentOn: invalid path ID: %d", pathID);
        return;
    }
    event_logi(VERBOSE, "Calling pm_chunksSentOn(%d)", pathID);
    pmData->pathData[pathID].chunksSent = TRUE;

}


/**
  pm_chunksRetransmitted is called by reliable transfer whenever chunks have been retransmitted.
  @param  pathID  address index, where timeout has occurred (i.e. which caused retransmission)
*/
gboolean pm_chunksRetransmitted(short pathID)
{
    gboolean removed_association = FALSE;
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_chunksRetransmitted: mdi_readPathMan failed");
        return removed_association;
    }
    if (pmData->pathData == NULL) {
        error_logi(ERROR_MAJOR, "pm_chunksRetransmitted(%d): Path Data Structures not initialized yet, returning !", pathID);
        return removed_association;
    }

    if (!(pathID >= 0 && pathID < pmData->numberOfPaths)) {
        error_logi(ERROR_MAJOR, "pm_chunksRetransmitted: invalid path ID %d", pathID);
        return removed_association;
    }

    if (pmData->pathData[pathID].state == PM_INACTIVE) {
        /* stale acknowledgement, silently discard */
        error_logi(ERROR_MINOR,
                   "pm_chunksRetransmitted: retransmissions over inactive path %d", pathID);
        return removed_association;
    } else {
        removed_association = handleChunksRetransmitted(pathID);
    }
    return removed_association;
}                               /* end: pm_chunksRetransmitted */



/**
  pm_rto_backoff is called by reliable transfer when the T3 retransmission timer expires.
  Each call of this function may double the RTO (timer back off).
  @param pathID  index of the address where the timeout occurred
*/
void pm_rto_backoff(short pathID)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_rto_backoff: mdi_readPathMan failed");
        return;
    }
    if (pmData->pathData == NULL) {
        error_logi(ERROR_MAJOR, "pm_rto_backoff(%d): Path Data Structures not initialized yet, returning !", pathID);
        return;
    }

    if (!(pathID >= 0 && pathID < pmData->numberOfPaths)) {
        error_logi(ERROR_MAJOR, "pm_rto_backoff: invalid path ID %d", pathID);
        return;
    }

    if (pmData->pathData[pathID].state == PM_ACTIVE) {
        /* Backoff timer anyway ! */
        pmData->pathData[pathID].rto = min(2 * pmData->pathData[pathID].rto, (unsigned int)pmData->rto_max);

        event_logii(INTERNAL_EVENT_0,
                        "pm_rto_backoff called for path %u: new RTO =%d",
                        pathID, pmData->pathData[pathID].rto);
        pmData->pathData[pathID].timerBackoff = TRUE;
    } else {
        /* stale acknowledgement, silently discard */
        error_logi(ERROR_MINOR, "pm_rto_backoff: timer backoff for an inactive path %d", pathID);
    }
}                               /* end pm_rto_backoff */



/*------------------- Functions called by the ULP ------------------------------------------------*/

/**
  pm_enableHB is called when ULP wants to enable heartbeat.
  @param  pathID index of address, where we sent the HBs to
  @param  hearbeatIntervall time in msecs, that is to be added to the RTT, before sending HB
  @return error code, 0 for success, 1 for error (i.e. address index too large)
*/
int pm_enableHB(short pathID, unsigned int hearbeatIntervall)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_enableHB: mdi_readPathMan failed");
        return SCTP_MODULE_NOT_FOUND;
    }
    if (pmData->pathData == NULL) {
        error_logii(ERROR_MAJOR, "pm_enableHB(%d,%u): Path Data Structures not initialized yet, returning !",
            pathID, hearbeatIntervall);
        return SCTP_MODULE_NOT_FOUND;
    }

    if (!(pathID >= 0 && pathID < pmData->numberOfPaths)) {
        error_logi(ERROR_MAJOR, "pm_enableHB: invalid path ID %d", pathID);
        return SCTP_PARAMETER_PROBLEM;
    }

    pmData->pathData[pathID].heartbeatIntervall = hearbeatIntervall;

    event_logii(VERBOSE, "pm_enableHB(%d): chose interval %u msecs",pathID,hearbeatIntervall);


    if (!pmData->pathData[pathID].heartbeatEnabled) {
        pmData->pathData[pathID].heartbeatEnabled = TRUE;

        pmData->pathData[pathID].firstRTO = TRUE;
        pmData->pathData[pathID].pathRetranscount = 0;
        pmData->peerRetranscount = 0;

        pmData->pathData[pathID].heartbeatSent = FALSE;
        pmData->pathData[pathID].heartbeatAcked = FALSE;
        pmData->pathData[pathID].timerBackoff = FALSE;
        pmData->pathData[pathID].chunksAcked = FALSE;
        pmData->pathData[pathID].chunksSent = FALSE;

        pmData->pathData[pathID].rto = pmData->rto_initial;
        pmData->pathData[pathID].srtt = pmData->rto_initial;
        pmData->pathData[pathID].rttvar = 0;
        pmData->pathData[pathID].hearbeatTimer =
            adl_startTimer((pmData->pathData[pathID].heartbeatIntervall+pmData->pathData[pathID].rto),
                            &pm_heartbeatTimer,
                            TIMER_TYPE_HEARTBEAT,
                            (void *) &pmData->associationID,
                            (void *) &pmData->pathData[pathID].pathID);
        event_logi(VERBOSE,
                   "pm_enableHB: started timer - going off in %u msecs",
                   pmData->pathData[pathID].heartbeatIntervall+pmData->pathData[pathID].rto);
    } else {
        pmData->pathData[pathID].hearbeatTimer =
            adl_restartTimer(pmData->pathData[pathID].hearbeatTimer,
                                     (pmData->pathData[pathID].heartbeatIntervall+pmData->pathData[pathID].rto));
        pmData->pathData[pathID].chunksSent = FALSE;
        event_logi(VERBOSE,
                   "pm_enableHB: restarted timer - going off in %u msecs",
                   pmData->pathData[pathID].heartbeatIntervall+pmData->pathData[pathID].rto);

    }
    return SCTP_SUCCESS;
}                               /* end: pm_enableHB */


/**
  pm_disableAllHB is usually called on shutdown to disable all heartbeats.
*/
void pm_disableAllHB(void)
{
    short pathID;

    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_disableAllHB: mdi_readPathMan failed");
        return;
    }

    if (pmData->pathData == NULL) {
        error_log(ERROR_MAJOR, "pm_disableAllHB: no paths set");
        return;
    }

    for (pathID = 0; pathID < pmData->numberOfPaths; pathID++) {
        if (pmData->pathData[pathID].heartbeatEnabled) {
            sctp_stopTimer(pmData->pathData[pathID].hearbeatTimer);
            pmData->pathData[pathID].hearbeatTimer = 0;
            pmData->pathData[pathID].heartbeatEnabled = FALSE;
            event_logi(INTERNAL_EVENT_0, "pm_disableAllHB: path %d disabled", (unsigned int) pathID);
        }
    }
}                               /* end: pm_disableAllHB */



/**
  pm_disableHB is called to disable heartbeat for one specific path id.
  @param  pathID index of  address, where HBs should not be sent anymore
  @return error code: 0 for success, 1 for error (i.e. pathID too large)
*/
int pm_disableHB(short pathID)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_disableHB: mdi_readPathMan failed");
        return SCTP_MODULE_NOT_FOUND;
    }

    if (pmData->pathData == NULL) {
        error_logi(ERROR_MAJOR, "pm_disableHB(%d): no paths set", pathID);
        return SCTP_MODULE_NOT_FOUND;
    }

    if (!(pathID >= 0 && pathID < pmData->numberOfPaths)) {
        error_logi(ERROR_MAJOR, "pm_disableHB: invalid path ID %d", pathID);
        return SCTP_PARAMETER_PROBLEM;
    }

    if (pmData->pathData[pathID].heartbeatEnabled) {
        sctp_stopTimer(pmData->pathData[pathID].hearbeatTimer);
        pmData->pathData[pathID].hearbeatTimer = 0;
        pmData->pathData[pathID].heartbeatEnabled = FALSE;
        event_logi(INTERNAL_EVENT_0, "pm_disableHB: path %d disabled", (unsigned int) pathID);
    }
    return SCTP_SUCCESS;
}                               /* end: pm_disableHB */



/**
  pm_setPrimaryPath sets the primary path.
  @param pathID     index of the address that is to become primary path
  @return 0 if okay, else 1 if there was some error
*/
short pm_setPrimaryPath(short pathID)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_setPrimaryPath: mdi_readPathMan failed");
        return SCTP_MODULE_NOT_FOUND;
    }
    if (pmData->pathData == NULL) {
        error_logi(ERROR_MAJOR, "pm_setPrimaryPath(%d): no paths set", pathID);
        return SCTP_UNSPECIFIED_ERROR;
    }

    if (pathID >= 0 && pathID < pmData->numberOfPaths) {
        if (pmData->pathData[pathID].state == PM_ACTIVE) {
            pmData->primaryPath = pathID;
            pmData->pathData[pathID].chunksSent = FALSE;
            event_logi(INTERNAL_EVENT_0, "pm_setPrimaryPath: path %d is primary", pathID);
            return SCTP_SUCCESS;
        } else {
            event_logi(INTERNAL_EVENT_0, "pm_setPrimaryPath: path %d not ACTIVE", pathID);
            return SCTP_SPECIFIC_FUNCTION_ERROR;
        }
    } else {
        error_logi(ERROR_MAJOR, "pm_setPrimaryPath: invalid path ID %d", pathID);
        return SCTP_PARAMETER_PROBLEM;
    }
}                               /* end: pm_setPrimaryPath */



/*------------------- Functions called by ULP to read pathmanagement state info ------------------*/

/**
 * pm_readRTO returns the currently set RTO value in msecs for a certain path.
 * @param pathID    index of the address/path
 * @return  path's current RTO
 */
unsigned int pm_readRTO(short pathID)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_logi(ERROR_MAJOR, "pm_readRTO(%d): mdi_readPathMan failed", pathID);
        return 0;
    }

    if (pathID >= 0 && pathID < pmData->numberOfPaths) {
        if (pmData->pathData == NULL)
            return pmData->rto_initial;
        else
            return pmData->pathData[pathID].rto;
    } else {
        error_logi(ERROR_MAJOR, "pm_readRTO(%d): invalid path ID", pathID);
        return 0;
    }
}                               /* end: pm_readRTO */

/**
 pm_readRttVar returns the currently measured value for Round-Trip
 time variation of a certain path.
 @param pathID    index of the address/path
 @return  path's current RTTvar in msecs, 0 if it's not set, 0xffffffff on error
*/
unsigned int pm_readRttVar(short pathID)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_logi(ERROR_MAJOR, "pm_readRttVar(%d): mdi_readPathMan failed", pathID);
        return 0xffffffff;
    }
    if (!pmData->pathData) {
        error_logi(ERROR_MAJOR, "pm_readRttVAr(%d): Path Data Structures not initialized yet, returning !", pathID);
        return 0;
    }

    if (pathID >= 0 && pathID < pmData->numberOfPaths)
            return pmData->pathData[pathID].rttvar;
    else {
        error_logi(ERROR_MAJOR, "pm_readRttVar(%d): invalid path ID", pathID);
        return 0xffffffff;
    }
}                               /* end: pm_readRttVar */


/**
  pm_readSRTT returns the currently set SRTT value for a certain path.
  @param pathID    index of the address/path
  @return  path's current smoothed round trip time, or 0xffffffff on error
*/
unsigned int pm_readSRTT(short pathID)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_readSRTT: mdi_readPathMan failed");
        return 0xffffffff;
    }

    if (!pmData->pathData) {
        event_logi(VERBOSE, "pm_readSRTT(%d): Path Data Structures not initialized, return RTO_INITIAL !", pathID);
        return pmData->rto_initial;
    }

    if (pathID >= 0 && pathID < pmData->numberOfPaths)
            return pmData->pathData[pathID].srtt;
    else {
        error_logi(ERROR_MAJOR, "pm_readSRTT: invalid path ID %d", pathID);
        return 0xffffffff;
    }
}                               /* end: pm_readSRTT */


/**
  pm_readState returns the current state of the path.
  @param pathID  index of the questioned address
  @return state of path (active/inactive)
*/
short pm_readState(short pathID)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_readState: mdi_readPathMan failed");
        return -1;
    }
    if (pmData->pathData == NULL) {
        error_log(ERROR_MAJOR, "pm_readState: pathData==NULL failed");
        return -1;
    }

    if (pathID >= 0 && pathID < pmData->numberOfPaths) {
        if (pmData->pathData == NULL)
            return PM_INACTIVE;
        else
            return pmData->pathData[pathID].state;
    } else {
        error_logi(ERROR_MAJOR, "pm_readState: invalid path ID %d", pathID);
        return -1;
    }
}                               /* end: pm_readState */



/**
  pm_readPrimaryPath is used to determine the current primary path
  @return index to the primary path
*/
unsigned short pm_readPrimaryPath(void)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_readPrimaryPath: pathmanagement-instance does not exist");
        return 0xFFFF;
    } else {
        return pmData->primaryPath;
    }
}                               /* end: pm_readPrimaryPath */

/**
  pm_getMaxPathRetransmisions is used to get the current  maxPathRetransmissions
  parameter value
  @return   maxPathRetransmissions of the current instance
*/
int  pm_getMaxPathRetransmisions(void)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_getMaxPathRetransmisions(): pathmanagement-instance does not exist");
        return -1;
    } else {
        return pmData->maxPathRetransmissions;
    }
}                               /* end: pm_getMaxPathRetransmisions(void) */

/**
  pm_setMaxPathRetransmisions is used to get the current  maxPathRetransmissions
  parameter value
  @param   new_max  new value for  maxPathRetransmissions parameter
  @return   0 for success, -1 for error
*/
int  pm_setMaxPathRetransmisions(int new_max)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_setMaxPathRetransmisions(): pathmanagement-instance does not exist");
        return -1;
    } else {
        pmData->maxPathRetransmissions = new_max;
    }
    return 0;
}                               /* end: pm_setMaxPathRetransmisions(void) */

/**
  pm_getRtoInitial is used to get the current  rto_initial parameter value
  @return   rto_initial on success, -1 for error
*/
int  pm_getRtoInitial(void)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_getRtoInitial(): pathmanagement-instance does not exist");
        return -1;
    }
    return pmData->rto_initial;
}                               /* end: pm_getRtoInitial() */

/**
  pm_getRtoInitial is used to get the current  rto_initial parameter value
  @return   0 on success, -1 for error
*/
int  pm_setRtoInitial(int new_rto_initial)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_setRtoInitial(): pathmanagement-instance does not exist");
        return -1;
    }
    pmData->rto_initial = new_rto_initial;
    return 0;
}                               /* end: pm_setRtoInitial() */


int  pm_setRtoMin(int new_rto_min)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_setRtoMin(): pathmanagement-instance does not exist");
        return -1;
    }
    pmData->rto_min = new_rto_min;
    return 0;
}                               /* end: pm_setRtoMin() */

int  pm_getRtoMin(void)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_getRtoMin(): pathmanagement-instance does not exist");
        return -1;
    }
    return pmData->rto_min;
}                               /* end: pm_getRtoMin() */

int  pm_setRtoMax(int new_rto_max)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_setRtoMax(): pathmanagement-instance does not exist");
        return -1;
    }
    pmData->rto_max = new_rto_max;
    return 0;
}                               /* end: pm_setRtoMax() */

int  pm_getRtoMax(void)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_getRtoMax(): pathmanagement-instance does not exist");
        return 60000;
    }
    return pmData->rto_max;
}                               /* end: pm_getRtoMax() */


int  pm_setHBInterval(unsigned int new_interval)
{
    int count;

    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_setHBInterval(): pathmanagement-instance does not exist");
        return -1;
    }
    if (pmData->pathData == NULL) {
        event_log(ERROR_MAJOR, "pm_setHBInterval(): path structures do not exist");
        return -1;
    }
    for (count = 0; count < pmData->numberOfPaths; count++) {
        pmData->pathData[count].heartbeatIntervall = new_interval;
    }
    return 0;
}

int pm_getHBInterval(short pathID, unsigned int* current_interval)
{
    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        event_log(ERROR_MAJOR, "pm_getHBInterval(): pathmanagement-instance does not exist");
        return -1;
    }
    if (pmData->pathData == NULL) {
        event_log(ERROR_MAJOR, "pm_getHBInterval(): path structures do not exist");
        return -1;
    }
    if (pathID >= 0 && pathID < pmData->numberOfPaths) {
        *current_interval = pmData->pathData[pathID].heartbeatIntervall;
    } else {
        error_logi(ERROR_MAJOR, "pm_getHBInterval: invalid path ID %d", pathID);
        *current_interval = 0;
        return -1;
    }
    return 0;
}

/*------------------- Functions called to create, init and delete pathman-instances --------------*/

/**
   pm_setPaths modufies number of paths and sets the primary path.
   This is required for association setup, where the local ULP provides
   only one path and the peer may provide additional paths.
   This function also initializes the path structures and starts the heartbeat timer for each
   path. For this reason it is recommended to call this function when communication up is called.
   @params noOfPaths  number of paths to the destination endpoint
   @param  primaryPathID   index to the address that is to be used as primary address
*/
short pm_setPaths(short noOfPaths, short primaryPathID)
{
    PathmanData *pmData;
    int b,i,j = 0;

    pmData = (PathmanData *) mdi_readPathMan();

    if (pmData == NULL) {
        error_log(ERROR_MAJOR, "pm_setPrimaryPath: mdi_readPathMan failed");
        return 1;
    }

    pmData->pathData = (PathData *) malloc(noOfPaths * sizeof(PathData));

    if (!pmData->pathData)
        error_log(ERROR_FATAL, "pm_setPaths: out of memory");

    if (primaryPathID >= 0 && primaryPathID < noOfPaths) {
        pmData->primaryPath = primaryPathID;
        pmData->numberOfPaths = noOfPaths;
        pmData->peerRetranscount = 0;


        for (i = 0; i < noOfPaths; i++) {
            pmData->pathData[i].state = PM_PATH_UNCONFIRMED;
            if (i == primaryPathID) {
                pmData->pathData[i].state = PM_ACTIVE;
            }
            pmData->pathData[i].heartbeatEnabled = TRUE;
            pmData->pathData[i].firstRTO = TRUE;
            pmData->pathData[i].pathRetranscount = 0;
            pmData->pathData[i].rto = pmData->rto_initial;
            pmData->pathData[i].srtt = pmData->rto_initial;
            pmData->pathData[i].rttvar = 0;

            pmData->pathData[i].heartbeatSent = FALSE;
            pmData->pathData[i].heartbeatAcked = FALSE;
            pmData->pathData[i].timerBackoff = FALSE;
            pmData->pathData[i].chunksAcked = FALSE;
            pmData->pathData[i].chunksSent = FALSE;

            pmData->pathData[i].heartbeatIntervall = PM_INITIAL_HB_INTERVAL;
            pmData->pathData[i].hearbeatTimer = 0;
            pmData->pathData[i].pathID = i;

            b = mdi_getDefaultMaxBurst();

            if (i != primaryPathID) {
                j++;
                if (j < b) {
                    pmData->pathData[i].hearbeatTimer =
                        adl_startTimer(j,    /* send HB quickly on first usually four unconfirmed paths */
                                       &pm_heartbeatTimer,
                                       TIMER_TYPE_HEARTBEAT,
                                        (void *) &pmData->associationID,
                                        (void *) &pmData->pathData[i].pathID);
                } else {
                    pmData->pathData[i].hearbeatTimer =
                        adl_startTimer(pmData->pathData[i].rto * (j-b),    /* send HB more slowly on other paths */
                                       &pm_heartbeatTimer,
                                       TIMER_TYPE_HEARTBEAT,
                                       (void *) &pmData->associationID,
                                       (void *) &pmData->pathData[i].pathID);
                }
            } else {
                pmData->pathData[i].hearbeatTimer =
                    adl_startTimer(pmData->pathData[i].heartbeatIntervall+pmData->pathData[i].rto,
                                    &pm_heartbeatTimer,
                                    TIMER_TYPE_HEARTBEAT,
                                    (void *) &pmData->associationID,
                                    (void *) &pmData->pathData[i].pathID);
            }
            /* after RTO we can do next RTO update */
            adl_gettime(&(pmData->pathData[i].rto_update));

        }

        event_log(INTERNAL_EVENT_0, "pm_setPaths called ");

        return 0;
    } else {
        error_log(ERROR_MAJOR, "pm_setPaths: invalid path ID");
        return 1;
    }
}                               /* end: pm_setPaths */



/**
 * pm_newPathman creates a new instance of pathmanagement. There is one pathmanagement instance
 * per association. WATCH IT : this needs to be fixed ! pathData is NULL, but may accidentally be
 * referenced !
 * @param numberOfPaths    number of paths of the association
 * @param primaryPath      initial primary path
 * @param  sctpInstance pointer to the SCTP instance
 * @return pointer to the newly created path management instance !
 */
void *pm_newPathman(short numberOfPaths, short primaryPath, void* sctpInstance)
{
    PathmanData *pmData;

    pmData = (PathmanData *) malloc(sizeof(PathmanData));
    if (!pmData)
        error_log(ERROR_FATAL, "pm_setPaths: out of memory");
    pmData->pathData = NULL;

    pmData->primaryPath = primaryPath;
    pmData->numberOfPaths = numberOfPaths;
    pmData->associationID = mdi_readAssociationID();
    pmData->maxPathRetransmissions = mdi_getDefaultPathMaxRetransmits(sctpInstance);
    pmData->rto_initial = mdi_getDefaultRtoInitial(sctpInstance);
    pmData->rto_min = mdi_getDefaultRtoMin(sctpInstance);
    pmData->rto_max = mdi_getDefaultRtoMax(sctpInstance);
    return pmData;
}                               /* end: pm_newPathman */



/**
 * Deletes the instance pointed to by pathmanPtr.
 * @param   pathmanPtr pointer to the instance that is to be deleted
 */
void pm_deletePathman(void *pathmanPtr)
{
    int i;
    PathmanData *pmData;

    event_log(INTERNAL_EVENT_0, "deleting pathmanagement");

    pmData = (PathmanData *) pathmanPtr;

    if (pmData != NULL && pmData->pathData != NULL) {
        for (i = 0; i < pmData->numberOfPaths; i++) {
            if (pmData->pathData[i].hearbeatTimer != 0) {
                adl_stopTimer(pmData->pathData[i].hearbeatTimer);
                pmData->pathData[i].hearbeatTimer = 0;
            }
        }
    }

    event_log(VVERBOSE, "stopped timers");

    free(pmData->pathData);
    free(pmData);
}                               /* end: pm_deletePathman */
