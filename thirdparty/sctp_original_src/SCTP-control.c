/* $Id: SCTP-control.c 2199 2009-08-31 06:43:13Z dreibh $
 * --------------------------------------------------------------------------
 *
 *           //=====   //===== ===//=== //===//  //       //   //===//
 *          //        //         //    //    // //       //   //    //
 *         //====//  //         //    //===//  //       //   //===<<
 *              //  //         //    //       //       //   //    //
 *       ======//  //=====    //    //       //=====  //   //===//
 *
 * ---------------A SCTP implementation according to RFC 4960 ---------------
 *
 * Copyright (C) 2000 by Siemens AG, Munich, Germany.
 * Copyright (C) 2001-2004 Andreas Jungmaier
 * Copyright (C) 2004-2009 Thomas Dreibholz
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

#include "SCTP-control.h"

#include "distribution.h"
#include "bundling.h"
#include "adaptation.h"
#include "pathmanagement.h"
#include "reltransfer.h"
#include "recvctrl.h"
#include "chunkHandler.h"
#include "flowcontrol.h"
#include "deliverman_control.h"

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <stdio.h>
#include <errno.h>

#include "sctp.h"

 /** @name SCTP State Machine Controller

	\hline
	Used function prefixes:
	\begin{itemize}
	\item scu_ for  primitives originating from the ULP
	\item sctlr_ for primitives originating from the peer
	\item sci_ for SCTP-internal calls
	\end{itemize}
	*/

	/*@{ */

	/******************** Typedef *********************************************************************/

	/**
		 SCTP-control structure. Stores also the current state of the state-machine.
		 */
typedef struct SCTP_CONTROLDATA
{
	/*@{ */
	/** the state of this state machine */
	unsigned int association_state;
	/** stores timer-ID of init/cookie-timer, used to stop this timer */
	TimerID initTimer;
	/** */
	unsigned int initTimerDuration;
	/**  stores the association id (==tag) of this association */
	unsigned int associationID;
	/** Counter for init and cookie retransmissions */
	short initRetransCounter;
	/** pointer to the init chunk data structure (for retransmissions) */
	SCTP_init *initChunk;
	/** pointer to the cookie chunk data structure (for retransmissions) */
	cookie_echo_chunk_t *peer_cookie_chunk;
	/** my tie tag for cross initialization and other sick cases */
	unsigned int local_tie_tag;
	/** peer's tie tag for cross initialization and other sick cases */
	unsigned int peer_tie_tag;
	/** we store these here, too. Maybe better be stored with StreamEngine ? */
	unsigned short outbound_stream;
	/** we store these here, too. Maybe better be stored with StreamEngine ? */
	unsigned short inbound_stream;
	/** value for maximum retransmissions per association */
	int assocMaxRetransmissions;
	/** value for maximum initial retransmissions per association */
	int assocMaxInitRetransmissions;
	/** value for the current cookie lifetime */
	int cookieLifeTime;
	/** the sctp instance */
	void *instance;
	/*@} */
} smctrl_t;

/* -------------------- Declarations -------------------------------------------------------------*/

/*
pointer to the current controller structure. Only set when association exists.
*/
static smctrl_t *smctrl;

/* ------------------ Function Implementations ---------------------------------------------------*/

/*------------------- Internal Functions ---------------------------------------------------------*/

/*------------------- Functions called by adaption layer -----------------------------------------*/

/**
 * Defines the callback function that is called when an (INIT, COOKIE, SHUTDOWN etc.) timer expires.
 * @param timerID               ID of timer
 * @param associationIDvoid     pointer to param1, here to an Association ID value, it may be used
 *                              to identify the association, to which the timer function belongs
 * @param unused                pointer to param2 - timers have two params, by default. Not needed here.
 */
static void msm_timer_expired(TimerID timerID, void *associationIDvoid, void *unused)
{
	unsigned int state;
	ChunkID shutdownCID;
	ChunkID shutdownAckCID;
	guint primary;

	if (mdi_setAssociationData(*((unsigned int *)associationIDvoid)))
	{
		/* error log: expired timer refers to a non existent association. */
		error_logi(ERROR_MAJOR,
			"init timer expired but association %u does not exist",
			(*(unsigned int *)associationIDvoid));
		return;
	}

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log: association exist, but has no SCTP-control ? */
		error_log(ERROR_MAJOR, "Association without SCTP-control");
		return;
	}

	state = smctrl->association_state;
	primary = pm_readPrimaryPath();

	event_logiii(VERBOSE, "msm_timer_expired(AssocID=%u,  state=%u, Primary=%u",
		(*(unsigned int *)associationIDvoid), state, primary);

	switch (state)
	{
	case COOKIE_WAIT:

		event_log(EXTERNAL_EVENT, "init timer expired in state COOKIE_WAIT");

		if (smctrl->initRetransCounter < smctrl->assocMaxInitRetransmissions)
		{
			/* increase retransmissission-counter, resend init and restart init-timer */
			smctrl->initRetransCounter++;
			bu_put_Ctrl_Chunk((SCTP_simple_chunk *)smctrl->initChunk, NULL);
			bu_sendAllChunks(NULL);
			/* restart init timer after timer backoff */
			smctrl->initTimerDuration = min(smctrl->initTimerDuration * 2, (unsigned int)pm_getRtoMax());
			event_logi(INTERNAL_EVENT_0, "init timer backedoff %d msecs",
				smctrl->initTimerDuration);
			smctrl->initTimer =
				adl_startTimer(smctrl->initTimerDuration, &msm_timer_expired, TIMER_TYPE_INIT,
				(void *)&smctrl->associationID, NULL);
		}
		else
		{
			/* log error to log-file */
			event_log(EXTERNAL_EVENT,
				"init retransmission counter exeeded threshold in state COOKIE_WAIT");
			/* free memory for initChunk */
			free(smctrl->initChunk);
			smctrl->initTimer = 0;
			smctrl->initChunk = NULL;
			/* report error to ULP tbd: status */
			mdi_deleteCurrentAssociation();
			mdi_communicationLostNotif(SCTP_COMM_LOST_EXCEEDED_RETRANSMISSIONS);
		}
		break;

	case COOKIE_ECHOED:

		event_log(EXTERNAL_EVENT, "cookie timer expired in state COOKIE_ECHOED");

		if (smctrl->initRetransCounter < smctrl->assocMaxInitRetransmissions)
		{
			/* increase retransmissission-counter, resend init and restart init-timer */
			smctrl->initRetransCounter++;
			bu_put_Ctrl_Chunk((SCTP_simple_chunk *)smctrl->peer_cookie_chunk, NULL);
			bu_sendAllChunks(NULL);
			/* restart cookie timer after timer backoff */
			smctrl->initTimerDuration = min(smctrl->initTimerDuration * 2, (unsigned int)pm_getRtoMax());
			event_logi(INTERNAL_EVENT_0, "cookie timer backedoff %d msecs",
				smctrl->initTimerDuration);

			smctrl->initTimer =
				adl_startTimer(smctrl->initTimerDuration, &msm_timer_expired, TIMER_TYPE_INIT,
				(void *)&smctrl->associationID, NULL);
		}
		else
		{
			/* log error to log-file */
			event_log(EXTERNAL_EVENT,
				"init retransmission counter exeeded threshold; state: COOKIE_ECHOED");
			/* free memory for peer_cookie_chunk */
			free(smctrl->peer_cookie_chunk);
			smctrl->initTimer = 0;
			smctrl->peer_cookie_chunk = NULL;
			/* report error to ULP tbd: status */
			mdi_deleteCurrentAssociation();
			mdi_communicationLostNotif(SCTP_COMM_LOST_EXCEEDED_RETRANSMISSIONS);
		}
		break;

	case SHUTDOWNSENT:

		/* some of the variable names are missleading, because they where only used
				   for init, but are reused for shutdown after the shutdown timer was introduced
				   in the draft. */

		if (smctrl->initRetransCounter < smctrl->assocMaxRetransmissions)
		{
			/* increase retransmissission-counter */
			smctrl->initRetransCounter++;

			/* make and send shutdown again, with updated TSN (section 9.2)     */
			shutdownCID = ch_makeShutdown(rxc_read_cummulativeTSNacked());
			bu_put_Ctrl_Chunk(ch_chunkString(shutdownCID), &primary);
			bu_sendAllChunks(&primary);
			ch_deleteChunk(shutdownCID);

			/* restart shutdown timer after timer backoff */
			smctrl->initTimerDuration = min(smctrl->initTimerDuration * 2, (unsigned int)pm_getRtoMax());
			event_logi(INTERNAL_EVENT_0, "shutdown timer backed off %d msecs",
				smctrl->initTimerDuration);

			smctrl->initTimer =
				adl_startTimer(smctrl->initTimerDuration, &msm_timer_expired, TIMER_TYPE_SHUTDOWN,
				(void *)&smctrl->associationID, NULL);
		}
		else
		{
			/* mdi_communicationLostNotif() may call sctp_deleteAssociation().
					   This would invalidate smctrl and therefore smctrl->initTimer
					   has to be reset before! */
			smctrl->initTimer = 0;
			/* shut down failed, delete current association. */
			mdi_deleteCurrentAssociation();
			mdi_communicationLostNotif(SCTP_COMM_LOST_EXCEEDED_RETRANSMISSIONS);
		}
		break;

	case SHUTDOWNACKSENT:

		/* some of the variable names are missleading, because they where only used
				   for init, but are reused for shutdown */

		if (smctrl->initRetransCounter < smctrl->assocMaxRetransmissions)
		{
			/* increase retransmissission-counter */
			smctrl->initRetransCounter++;

			shutdownAckCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_ACK, FLAG_NONE);
			bu_put_Ctrl_Chunk(ch_chunkString(shutdownAckCID), &primary);
			bu_sendAllChunks(&primary);
			ch_deleteChunk(shutdownAckCID);

			/* COMMENTED OUT BECAUSE PROBABLY VERY WRONG............. */
			/* make and send shutdown_complete again */
			/* shutdown_complete_CID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_COMPLETE, FLAG_NONE); */
			/* bu_put_Ctrl_Chunk(ch_chunkString(shutdown_complete_CID)); */
			/* bu_sendAllChunks(&primary); */
			/* ch_deleteChunk(shutdown_complete_CID); */

			/* restart shutdown timer after timer backoff */
			smctrl->initTimerDuration = min(smctrl->initTimerDuration * 2, (unsigned int)pm_getRtoMax());
			event_logi(INTERNAL_EVENT_0, "shutdown timer backed off %d msecs",
				smctrl->initTimerDuration);
			smctrl->initTimer =
				adl_startTimer(smctrl->initTimerDuration, &msm_timer_expired, TIMER_TYPE_SHUTDOWN,
				(void *)&smctrl->associationID, NULL);
		}
		else
		{
			/* mdi_communicationLostNotif() may call sctp_deleteAssociation().
					   This would invalidate smctrl and therefore smctrl->initTimer
					   has to be reset before! */
			smctrl->initTimer = 0;
			mdi_deleteCurrentAssociation();
			mdi_communicationLostNotif(SCTP_COMM_LOST_EXCEEDED_RETRANSMISSIONS);
		}
		break;

	default:
		/* error log */
		error_logi(ERROR_MAJOR, "unexpected event: timer expired in state %02d", state);
		smctrl->initTimer = 0;
		break;
	}

	smctrl = NULL;
	mdi_clearAssociationData();
}

/*------------------- Functions called by the ULP via message-distribution -----------------------*/

/**
 * This function is called to initiate the setup an association.
 *
 * The local tag and the initial TSN are randomly generated.
 * Together with the parameters of the function, they are used to create the init-message.
 * This data are also stored in a newly created association-record.
 *
 * @param noOfOutStreams        number of send streams.
 * @param noOfInStreams         number of receive streams.
 */
void msm_associate(unsigned short noOfOutStreams,
	unsigned short noOfInStreams,
	union sockunion *destinationList,
	unsigned int numDestAddresses,
	bool withPRSCTP)
{
	unsigned int state;
	guint16 nlAddresses;
	union sockunion lAddresses[MAX_NUM_ADDRESSES];
	ChunkID initCID;
	unsigned int supportedTypes = 0, count;

	/* ULP has called sctp_associate at distribution.
	   Distribution has allready allocated the association data and partially initialized */

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		error_log(ERROR_MAJOR, "read SCTP-control failed");
		return;
	}

	state = smctrl->association_state;

	switch (state)
	{
	case CLOSED:
		event_log(EXTERNAL_EVENT, "event: scu_assocatiate in state CLOSED");
		/* create init chunk and write data to it -- take AssocID as tag !!! */
		initCID = ch_makeInit(mdi_read_local_tag(),
			mdi_read_rwnd(),
			noOfOutStreams, noOfInStreams, mdi_generateStartTSN());

		/* store the number of streams */
		smctrl->outbound_stream = noOfOutStreams;
		smctrl->inbound_stream = noOfInStreams;

		supportedTypes = mdi_getSupportedAddressTypes();

		/* enter enter local addresses to message. I send an Init here, so
				 * I will include all of my addresses !
				 void mdi_validate_localaddrs_before_write_to_init(union sockunion laddresses[MAX_NUM_ADDRESSES],
				 guint16 * noOfAddresses,
				 union sockunion *peerAddress,
				 unsigned int numPeerAddresses,
				 unsigned int addressTypes,
				 bool receivedFromPeer)
				 */
		mdi_validate_localaddrs_before_write_to_init(lAddresses,
			&nlAddresses,
			destinationList,
			numDestAddresses,
			supportedTypes,
			FALSE);

		event_logi(VERBOSE, "1: supportedTypes : %u", supportedTypes);

		if (withPRSCTP)
		{
			ch_enter_init_vlp(initCID, VLPARAM_UNRELIABILITY, 0, NULL);
		}

#ifdef BAKEOFF
		ch_enter_init_vlp(initCID, 0x8123, 17, (unsigned char *)smctrl);
		ch_enter_init_vlp(initCID, 0x8343, 23, (unsigned char *)smctrl);
		ch_enter_init_vlp(initCID, 0x8324, 1, (unsigned char *)smctrl);
		ch_enter_init_vlp(initCID, 0xC123, 31, (unsigned char *)smctrl);
#endif
		if (supportedTypes == SUPPORT_ADDRESS_TYPE_IPV6)
		{
			ch_enterSupportedAddressTypes(initCID, FALSE, TRUE, FALSE);
		}
		else if (supportedTypes == SUPPORT_ADDRESS_TYPE_IPV4)
		{
			ch_enterSupportedAddressTypes(initCID, TRUE, FALSE, FALSE);
		}
		else if (supportedTypes == (SUPPORT_ADDRESS_TYPE_IPV6 | SUPPORT_ADDRESS_TYPE_IPV4))
		{
			ch_enterSupportedAddressTypes(initCID, TRUE, TRUE, FALSE);
		}
		else
			error_log(ERROR_MAJOR, "CHECKME: Did not set correct SUPPORTED ADDR TYPES parram");
		//ch_enterSupportedAddressTypes(initCID, TRUE, FALSE, FALSE);

		event_logi(VERBOSE, "2: supportedTypes : %u", supportedTypes);

		if (nlAddresses > 1)
			ch_enterIPaddresses(initCID, lAddresses, nlAddresses);

		smctrl->initChunk = (SCTP_init *)ch_chunkString(initCID);
		mch_remove_simple_chunk(initCID);

		/* send init chunk */
		for (count = 0; count < numDestAddresses; count++)
		{
			bu_put_Ctrl_Chunk((SCTP_simple_chunk *)smctrl->initChunk, &count);
			bu_sendAllChunks(&count);
		}

		smctrl->peer_cookie_chunk = NULL;
		smctrl->local_tie_tag = 0;
		smctrl->peer_tie_tag = 0;

		/* start init timer */
		smctrl->initTimerDuration = pm_readRTO(pm_readPrimaryPath());

		if (smctrl->initTimer != 0)
			sctp_stopTimer(smctrl->initTimer);

		smctrl->initTimer = adl_startTimer(smctrl->initTimerDuration,
			&msm_timer_expired,
			TIMER_TYPE_INIT,
			(void *)&smctrl->associationID, NULL);

		state = COOKIE_WAIT;
		break;
	default:
		error_logi(EXTERNAL_EVENT_X, "Erroneous Event : msm_associate called in state %u", state);
		break;
	}

	smctrl->association_state = state;
	smctrl = NULL;
}

/**
 * function initiates the shutdown of this association.
 */
void scu_shutdown()
{
	unsigned int state;
	ChunkID shutdownCID;
	boolean readyForShutdown;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "read SCTP-control failed");
		return;
	}

	state = smctrl->association_state;

	switch (state)
	{
	case ESTABLISHED:
		event_log(EXTERNAL_EVENT, "event: scu_shutdown in state ESTABLISHED");

		/* disable heartbeat */
		pm_disableAllHB();

		/* stop reliable transfer and read its state */
		readyForShutdown = (rtx_get_unacked_chunks_count() == 0) &&
			(fc_get_queued_chunks_count() == 0);

		if (readyForShutdown)
		{
			/* make and send shutdown */
			shutdownCID = ch_makeShutdown(rxc_read_cummulativeTSNacked());
			bu_put_Ctrl_Chunk(ch_chunkString(shutdownCID), NULL);
			bu_sendAllChunks(NULL);
			ch_deleteChunk(shutdownCID);

			/* start shutdown timer */
			smctrl->initTimerDuration = pm_readRTO(pm_readPrimaryPath());

			if (smctrl->initTimer != 0)
				sctp_stopTimer(smctrl->initTimer);

			smctrl->initTimer =
				adl_startTimer(smctrl->initTimerDuration, &msm_timer_expired, TIMER_TYPE_SHUTDOWN,
				(void *)&smctrl->associationID, NULL);

			smctrl->initRetransCounter = 0;

			/* receive control must acknoweledge every datachunk at once after the shutdown
					   was sent. */
			rxc_send_sack_everytime();

			state = SHUTDOWNSENT;
		}
		else
		{
			/* shutdown in progress info to reliable transfer, this stopps data transmission */
			rtx_shutdown();
			/* wait for sci_allChunksAcked from reliable transfer */
			state = SHUTDOWNPENDING;
		}
		smctrl->association_state = state;
		smctrl = NULL;

		break;
	case CLOSED:
	case COOKIE_WAIT:
	case COOKIE_ECHOED: /* Siemens convention: ULP can not send datachunks
									   until it has received the communication up. */
		event_logi(EXTERNAL_EVENT, "event: scu_shutdown in state %02d --> aborting", state);
		scu_abort(ECC_USER_INITIATED_ABORT, 0, NULL);
		break;
	case SHUTDOWNSENT:
	case SHUTDOWNRECEIVED:
	case SHUTDOWNPENDING:
	case SHUTDOWNACKSENT:
		/* ignore, keep on waiting for completion of the running shutdown */
		event_logi(EXTERNAL_EVENT, "event: scu_shutdown in state %", state);
		smctrl = NULL;
		break;
	default:
		/* error logging */
		event_log(EXTERNAL_EVENT_X, "unexpected event: scu_shutdown");
		smctrl = NULL;
		break;
	}
}

void sci_add_abort_error_cause(ChunkID abortChunk,
	unsigned short etype,
	unsigned short eplen,
	unsigned char *epdata)
{

	switch (etype)
	{

	case ECC_INVALID_STREAM_ID:
	case ECC_MISSING_MANDATORY_PARAM:
	case ECC_STALE_COOKIE_ERROR:
	case ECC_OUT_OF_RESOURCE_ERROR:
	case ECC_UNRESOLVABLE_ADDRESS:
	case ECC_UNRECOGNIZED_CHUNKTYPE:
	case ECC_INVALID_MANDATORY_PARAM:
	case ECC_UNRECOGNIZED_PARAMS:
	case ECC_NO_USER_DATA:
	case ECC_COOKIE_RECEIVED_DURING_SHUTDWN:
	case ECC_RESTART_WITH_NEW_ADDRESSES:
	case ECC_USER_INITIATED_ABORT:
		ch_enterErrorCauseData(abortChunk, etype, eplen, epdata);
		break;
	default:
		break;
	}
	return;
}

/**
 * this function aborts this association. And optionally adds an error parameter
 * to the ABORT chunk that is sent out.
 */
void scu_abort(short error_type, unsigned short error_param_length, unsigned char *error_param_data)
{
	unsigned int state;
	ChunkID abortCID;
	bool removed = FALSE;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "read SCTP-control failed");
		return;
	}

	state = smctrl->association_state;

	switch (state)
	{
	case CLOSED:
		event_log(EXTERNAL_EVENT, "event: scu_abort in state CLOSED");
		/* delete all data of this association */
		mdi_deleteCurrentAssociation();
		mdi_clearAssociationData();

		break;

	case COOKIE_WAIT:
	case COOKIE_ECHOED:
	case SHUTDOWNSENT:
	case SHUTDOWNACKSENT:
		event_logi(EXTERNAL_EVENT, "event: scu_abort in state %2d --> send abort", state);

		/* make and send abort message */
		abortCID = ch_makeSimpleChunk(CHUNK_ABORT, FLAG_NONE);

		if (error_type >= 0)
		{
			sci_add_abort_error_cause(abortCID, (unsigned short)error_type, error_param_length, error_param_data);
		}
		bu_put_Ctrl_Chunk(ch_chunkString(abortCID), NULL);
		bu_sendAllChunks(NULL);
		bu_unlock_sender(NULL);
		/* free abort chunk */
		ch_deleteChunk(abortCID);
		/* stop init timer */
		if (smctrl->initTimer != 0)
		{
			sctp_stopTimer(smctrl->initTimer);
			smctrl->initTimer = 0;
		}
		/* delete all data of this association */
		mdi_deleteCurrentAssociation();
		removed = TRUE;
		break;

	case ESTABLISHED:
	case SHUTDOWNPENDING:
	case SHUTDOWNRECEIVED:

		event_logi(EXTERNAL_EVENT, "event: scu_abort in state %02d --> send abort", state);

		/* make and send abort message */
		abortCID = ch_makeSimpleChunk(CHUNK_ABORT, FLAG_NONE);

		if (error_type >= 0)
		{
			sci_add_abort_error_cause(abortCID, (unsigned short)error_type, error_param_length, error_param_data);
		}

		bu_put_Ctrl_Chunk(ch_chunkString(abortCID), NULL);
		bu_sendAllChunks(NULL);
		bu_unlock_sender(NULL);
		/* free abort chunk */
		ch_deleteChunk(abortCID);
		/* delete all data of this association */
		mdi_deleteCurrentAssociation();
		removed = TRUE;

		break;
	default:
		/* error logging */
		event_logi(EXTERNAL_EVENT_X, "scu_abort in state %02d: unexpected event", state);
		break;
	}

	if (removed == TRUE)
	{
		mdi_communicationLostNotif(SCTP_COMM_LOST_ABORTED);
		mdi_clearAssociationData();
	}
}

/*------------------- Functions called by the (de-)bundling for received control chunks ----------*/

/**
 * sctlr_init is called by bundling when a init message is received from the peer.
 * an InitAck may be returned, alongside with a cookie chunk variable parameter.
 * The following data are created and included in the init acknowledgement:
 * a COOKIE parameter.
 * @param init  pointer to the received init-chunk (including optional parameters)
 */
int sctlr_init(SCTP_init *init)
{
	/*  this function does not expect any data allocated for the new association,
	   but if there are, implementation will act according to section 5.2.1 (simultaneous
	   initialization) and section 5.2.2 (duplicate initialization)
	   */

	unsigned int state;
	guint16 nlAddresses;
	union sockunion lAddresses[MAX_NUM_ADDRESSES];
	guint16 nrAddresses;
	union sockunion rAddresses[MAX_NUM_ADDRESSES];
	union sockunion last_source;

	ChunkID initCID;
	ChunkID initCID_local;
	ChunkID initAckCID;
	ChunkID abortCID;
	ChunkID shutdownAckCID;
	unsigned short inbound_streams, outbound_streams;
	unsigned int supportedTypes = 0, peerSupportedTypes = 0;
	int process_further, result;
	int return_state = STATE_OK;

	guint primary;

	event_log(EXTERNAL_EVENT, "sctlr_init() is executed");

	initCID = mch_make_simple_chunk((SCTP_simple_chunk *)init);

	if (ch_chunkType(initCID) != CHUNK_INIT)
	{
		/* error logging */
		mch_remove_simple_chunk(initCID);
		error_log(ERROR_MAJOR, "sctlr_init: wrong chunk type");
		return return_state;
	}

	if (ch_noOutStreams(initCID) == 0 || ch_noInStreams(initCID) == 0 ||
		ch_initiateTag(initCID) == 0)
	{
		event_log(EXTERNAL_EVENT, "event: received init with zero number of streams, or zero TAG");

		/* make and send abort message */
		abortCID = ch_makeSimpleChunk(CHUNK_ABORT, FLAG_NONE);
		ch_enterErrorCauseData(abortCID, ECC_INVALID_MANDATORY_PARAM, 0, NULL);

		bu_put_Ctrl_Chunk(ch_chunkString(abortCID), NULL);
		bu_sendAllChunks(NULL);
		/* free abort chunk */
		ch_deleteChunk(abortCID);
		/* delete all data of this association */
		if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) != NULL)
		{
			bu_unlock_sender(NULL);
			mdi_deleteCurrentAssociation();
			mdi_communicationLostNotif(SCTP_COMM_LOST_INVALID_PARAMETER);
			mdi_clearAssociationData();

			return_state = STATE_STOP_PARSING_REMOVED;
		}
		return return_state;
	}

	result = mdi_readLastFromAddress(&last_source);
	if (result != 0)
	{
		if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
		{
			mdi_clearAssociationData();
			return_state = STATE_STOP_PARSING_REMOVED;
			return return_state;
		}
		if (smctrl->initTimer != 0)
		{
			sctp_stopTimer(smctrl->initTimer);
			smctrl->initTimer = 0;
		}
		bu_unlock_sender(NULL);
		mdi_deleteCurrentAssociation();
		mdi_communicationLostNotif(0);
		mdi_clearAssociationData();
		return_state = STATE_STOP_PARSING_REMOVED;
		return return_state;
	}

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		event_log(VERBOSE, " DO_5_1_B_INIT: Normal init case ");
		/* DO_5_1_B_INIT : Normal case, no association exists yet */
		/* save a-sides init-tag from init-chunk to be used as a verification tag of the sctp-
			   message carrying the initAck (required since no association is created). */
		mdi_writeLastInitiateTag(ch_initiateTag(initCID));

		/* Limit the number of sendstreams a-side requests to the max. number of input streams
			   this z-side is willing to accept.
			   */
		inbound_streams = min(ch_noOutStreams(initCID), mdi_readLocalInStreams());
		outbound_streams = min(ch_noInStreams(initCID), mdi_readLocalOutStreams());
		/* fire back an InitAck with a Cookie */
		initAckCID = ch_makeInitAck(mdi_generateTag(),
			mdi_read_rwnd(),
			outbound_streams,
			inbound_streams, mdi_generateStartTSN());

		/* retreive a-side source addresses from message */
		supportedTypes = mdi_getSupportedAddressTypes();

		nrAddresses = ch_IPaddresses(initCID, supportedTypes, rAddresses, &peerSupportedTypes, &last_source);

		if ((supportedTypes & peerSupportedTypes) == 0)
			error_log(ERROR_FATAL, "BAKEOFF: Program error, no common address types in sctlr_init()");

		/* enter variable length params initAck */
		mdi_validate_localaddrs_before_write_to_init(lAddresses, &nlAddresses, &last_source, 1, peerSupportedTypes, TRUE);
		/* enter local addresses into initAck */
		if (nlAddresses > 1)
			ch_enterIPaddresses(initAckCID, lAddresses, nlAddresses);

		/* append cookie to InitAck Chunk */
		ch_enterCookieVLP(initCID, initAckCID,
			ch_initFixed(initCID), ch_initFixed(initAckCID),
			ch_cookieLifeTime(initCID), 0, /* tie tags are both zero */
			0, lAddresses, nlAddresses, rAddresses, nrAddresses);

		process_further = ch_enterUnrecognizedParameters(initCID, initAckCID,
			supportedTypes);

		if (process_further == -1)
		{
			/*   ch_deleteChunk(initAckCID);
				   mch_remove_simple_chunk(initCID); */
			return_state = STATE_STOP_PARSING; /* to stop parsing without actually removing it */
							   /* return return_state; */
		}
		else
		{
			if (process_further == 1)
			{
				return_state = STATE_STOP_PARSING; /* to stop parsing without actually removing it */
			}
			/* send initAck */
			bu_put_Ctrl_Chunk(ch_chunkString(initAckCID), NULL);
		}
		bu_sendAllChunks(NULL);
		bu_unlock_sender(NULL);
		ch_deleteChunk(initAckCID);
		event_log(INTERNAL_EVENT_1, "event: initAck sent");
	}
	else
	{
		/* save a-sides init-tag from init-chunk to be used as a verification tag of the sctp-
			   message carrying the initAck (required since peer may have changed the verification
			   tag).
			   mdi_writeLastInitiateTag(ch_initiateTag(initCID)); */

		state = smctrl->association_state;
		event_logi(EXTERNAL_EVENT, "sctlr_init: received INIT chunk in state %02u", state);
		primary = pm_readPrimaryPath();
		supportedTypes = mdi_getSupportedAddressTypes();

		switch (state)
		{
			/* see section 5.2.1 */
		case COOKIE_WAIT:
			if ((smctrl->local_tie_tag != 0) || (smctrl->peer_tie_tag != 0))
			{
				error_logii(ERROR_FATAL, "Tie tags NOT zero in COOKIE_WAIT, but %u and %u",
					smctrl->local_tie_tag, smctrl->peer_tie_tag);
			}
			smctrl->local_tie_tag = 0;
			smctrl->peer_tie_tag = 0;

		case COOKIE_ECHOED:
			if ((state == COOKIE_ECHOED) &&
				((smctrl->local_tie_tag == 0) || (smctrl->peer_tie_tag == 0)))
			{
				error_logii(ERROR_FATAL, "Tie tags zero in COOKIE_ECHOED, local: %u, peer: %u",
					smctrl->local_tie_tag, smctrl->peer_tie_tag);
			}

			if (state == COOKIE_ECHOED)
			{
				/*
							 * For an endpoint that is in the COOKIE-ECHOED state it MUST populate
							 * its Tie-Tags with random values so that possible attackers cannot guess
							 * real tag values of the association (see Implementer's Guide > version 10)
							 */
				smctrl->local_tie_tag = mdi_generateTag();
				smctrl->peer_tie_tag = mdi_generateTag();
			}

			/* save remote  tag ?
					   mdi_writeLastInitiateTag(ch_initiateTag(initCID)); */
			inbound_streams = min(ch_noOutStreams(initCID), mdi_readLocalInStreams());

			/* Set length of chunk to HBO !! */
			initCID_local = mch_make_simple_chunk((SCTP_simple_chunk *)smctrl->initChunk);
			/* section 5.2.1 : take original parameters from first INIT chunk */
			initAckCID = ch_makeInitAck(ch_initiateTag(initCID_local),
				ch_receiverWindow(initCID_local),
				ch_noInStreams(initCID), /* peers inbound are MY outbound */
				inbound_streams,
				ch_initialTSN(initCID_local));

			/* reset length field again to NBO...and remove reference */
			ch_chunkString(initCID_local);
			mch_remove_simple_chunk(initCID_local);

			/* retreive a-side source addresses from message */
			nrAddresses = ch_IPaddresses(initCID, supportedTypes, rAddresses, &peerSupportedTypes, &last_source);

			/* the initAck (and consequently the Cookie) will contain my assocID as my local
					   tag, and the peers tag from the init we got here */
			mdi_validate_localaddrs_before_write_to_init(lAddresses, &nlAddresses, &last_source, 1, peerSupportedTypes, TRUE);
			/* enter local addresses into initAck */
			if (nlAddresses > 1)
				ch_enterIPaddresses(initAckCID, lAddresses, nlAddresses);

			ch_enterCookieVLP(initCID, initAckCID,
				ch_initFixed(initCID),
				ch_initFixed(initAckCID),
				ch_cookieLifeTime(initCID),
				smctrl->local_tie_tag, /* tie tags may be zero OR populated here */
				smctrl->peer_tie_tag,
				lAddresses, nlAddresses,
				rAddresses, nrAddresses);

			process_further = ch_enterUnrecognizedParameters(initCID, initAckCID, supportedTypes);

			if (process_further == -1)
			{
				ch_deleteChunk(initAckCID);
				mch_remove_simple_chunk(initCID);
				return_state = STATE_STOP_PARSING; /* to stop parsing without actually removing it */
				return return_state;
			}
			else if (process_further == 1)
			{
				return_state = STATE_STOP_PARSING; /* to stop parsing without actually removing it */
			}

			/* send initAck */
			bu_put_Ctrl_Chunk(ch_chunkString(initAckCID), NULL);
			bu_sendAllChunks(NULL);
			bu_unlock_sender(NULL);
			ch_deleteChunk(initAckCID);
			event_logi(INTERNAL_EVENT_1, "event: initAck sent in state %u", state);
			break;

			/* see section 5.2.2 */
		case ESTABLISHED:
		case SHUTDOWNPENDING:
		case SHUTDOWNRECEIVED:
		case SHUTDOWNSENT:
			if ((smctrl->local_tie_tag == 0) || (smctrl->peer_tie_tag == 0))
			{
				error_logiii(ERROR_MINOR, "Tie tags zero in state %u, local: %u, peer: %u --> Restart ?",
					state, smctrl->local_tie_tag, smctrl->peer_tie_tag);
			}

			inbound_streams = min(ch_noOutStreams(initCID), mdi_readLocalInStreams());

			initAckCID = ch_makeInitAck(mdi_generateTag(),
				rxc_get_local_receiver_window(),
				se_numOfSendStreams(), se_numOfRecvStreams(),
				/* TODO : check whether we take NEW TSN or leave an old one */
				mdi_generateStartTSN());

			/*
					   smctrl->local_tie_tag = mdi_generateTag();
					   smctrl->peer_tie_tag = mdi_generateTag();
					   */

					   /* retreive remote source addresses from message */
			nrAddresses = ch_IPaddresses(initCID, supportedTypes, rAddresses, &peerSupportedTypes, &last_source);

			mdi_validate_localaddrs_before_write_to_init(lAddresses, &nlAddresses, &last_source, 1, peerSupportedTypes, TRUE);

			/* enter local addresses into initAck */
			if (nlAddresses > 1)
				ch_enterIPaddresses(initAckCID, lAddresses, nlAddresses);

			ch_enterCookieVLP(initCID, initAckCID,
				ch_initFixed(initCID),
				ch_initFixed(initAckCID),
				ch_cookieLifeTime(initCID),
				smctrl->local_tie_tag,
				/* this should be different from that in Init_Ack now */
				smctrl->peer_tie_tag,
				lAddresses, nlAddresses,
				rAddresses, nrAddresses);

			process_further = ch_enterUnrecognizedParameters(initCID, initAckCID, supportedTypes);

			if (process_further == -1)
			{
				ch_deleteChunk(initAckCID);
				mch_remove_simple_chunk(initCID);
				return_state = STATE_STOP_PARSING;
				return return_state;
			}
			else if (process_further == 1)
			{
				return_state = STATE_STOP_PARSING; /* to stop parsing without actually removing it */
			}

			/* send initAck */
			bu_put_Ctrl_Chunk(ch_chunkString(initAckCID), NULL);
			bu_sendAllChunks(NULL);
			bu_unlock_sender(NULL);
			ch_deleteChunk(initAckCID);
			event_logi(INTERNAL_EVENT_1, "event: initAck sent in state %u", state);
			break;
		case SHUTDOWNACKSENT:
			/* We are supposed to discard the Init, and retransmit SHUTDOWN_ACK (9.2) */
			shutdownAckCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_ACK, FLAG_NONE);
			bu_put_Ctrl_Chunk(ch_chunkString(shutdownAckCID), NULL);
			bu_sendAllChunks(NULL);
			bu_unlock_sender(NULL);
			ch_deleteChunk(shutdownAckCID);
			break;
		default:
			error_logi(ERROR_MAJOR, "Unexpected State %02u - Program Error ???", state);
			break;
		}
	}

	/* was only treated with mch_make_simple_chunk -- it is enough to "FORGET" it */
	mch_remove_simple_chunk(initCID);
	return return_state;
}

/**
 * sctlr_initAck is called by bundling when a init acknowledgement was received from the peer.
 * The following data are retrieved from the init-data and saved for this association:
 * \begin{itemize}
 * \item remote tag from the initiate tag field
 * \item receiver window credit of the peer
 * \item number of send streams of the peer, must be lower or equal the number of receive streams
 *   this host has announced with the init-chunk
 * \item number of receive streams the peer allows the receiver of this initAck to use
 * \end{itemize}
 * The initAck must contain a cookie which is returned to the peer with the cookie acknowledgement.
 * @param initAck  pointer to received initAck-chunk including optional parameters without chunk header
 */
bool sctlr_initAck(SCTP_init *initAck)
{
	unsigned int state;
	int result;
	unsigned int index = 0;
	union sockunion destAddress;
	union sockunion dAddresses[MAX_NUM_ADDRESSES];
	unsigned int ndAddresses;
	unsigned short inbound_streams;
	unsigned short outbound_streams;

	unsigned int peerSupportedTypes = 0, supportedTypes = 0;
	int process_further = 0;
	ChunkID cookieCID;
	ChunkID initCID;
	ChunkID initAckCID;
	ChunkID errorCID, abortCID;
	SCTP_MissingParams missing_params;
	int return_state = STATE_OK;

	union sockunion preferredPrimary;
	bool preferredSet = FALSE;
	bool peerSupportsPRSCTP = FALSE;
	bool peerSupportsADDIP = FALSE;
	bool peerSupportsIPV4 = FALSE;
	bool peerSupportsIPV6 = FALSE;
	short preferredPath;

	initAckCID = mch_make_simple_chunk((SCTP_simple_chunk *)initAck);

	if (ch_chunkType(initAckCID) != CHUNK_INIT_ACK)
	{
		/* error logging */
		mch_remove_simple_chunk(initAckCID);
		error_log(ERROR_MAJOR, "sctlr_initAck: wrong chunk type");
		return return_state;
	}

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		mch_remove_simple_chunk(initAckCID);
		error_log(ERROR_MAJOR, "sctlr_initAck: read SCTP-control failed");
		return return_state;
	}

	state = smctrl->association_state;

	switch (state)
	{
	case COOKIE_WAIT:

		event_log(EXTERNAL_EVENT, "event: initAck in state COOKIE_WAIT");

		/* Set length of chunk to HBO !! */
		initCID = mch_make_simple_chunk((SCTP_simple_chunk *)smctrl->initChunk);

		/* FIXME: check also the noPeerOutStreams <= noLocalInStreams */
		if (ch_noOutStreams(initAckCID) == 0 || ch_noInStreams(initAckCID) == 0 || ch_initiateTag(initAckCID) == 0)
		{
			if (smctrl->initTimer != 0)
			{
				sctp_stopTimer(smctrl->initTimer);
				smctrl->initTimer = 0;
			}
			/* make and send abort message */
			abortCID = ch_makeSimpleChunk(CHUNK_ABORT, FLAG_NONE);
			ch_enterErrorCauseData(abortCID, ECC_INVALID_MANDATORY_PARAM, 0, NULL);
			bu_put_Ctrl_Chunk(ch_chunkString(abortCID), NULL);
			ch_deleteChunk(abortCID);

			bu_unlock_sender(NULL);
			bu_sendAllChunks(NULL);
			/* delete all data of this association */
			mdi_deleteCurrentAssociation();
			mdi_communicationLostNotif(0);
			mdi_clearAssociationData();
			return_state = STATE_STOP_PARSING_REMOVED;
			return return_state;
		}

		result = mdi_readLastFromAddress(&destAddress);
		if (result != 0)
		{
			if (smctrl->initTimer != 0)
			{
				sctp_stopTimer(smctrl->initTimer);
				smctrl->initTimer = 0;
			}
			bu_unlock_sender(NULL);
			mdi_deleteCurrentAssociation();
			mdi_communicationLostNotif(0);
			mdi_clearAssociationData();
			return_state = STATE_STOP_PARSING_REMOVED;
			return return_state;
		}

		supportedTypes = mdi_getSupportedAddressTypes();
		/* retrieve addresses from initAck */
		ndAddresses = ch_IPaddresses(initAckCID, supportedTypes, dAddresses, &peerSupportedTypes, &destAddress);
		mdi_set_channel_remoteaddrlist(dAddresses, ndAddresses);

		/* initialize rest of association with data received from peer */
		inbound_streams = min(ch_noOutStreams(initAckCID), smctrl->inbound_stream);
		outbound_streams = min(ch_noInStreams(initAckCID), smctrl->outbound_stream);

		peerSupportsPRSCTP = ch_getPRSCTPfromInitAck(initAckCID);

		mdi_initssociation(ch_receiverWindow(initAckCID), /* remotes side initial rwnd */
			inbound_streams,		  /* # of remote output/local input streams */
			outbound_streams,		  /* # of remote input/local output streams */
			ch_initialTSN(initAckCID),     /* remote initial TSN */
			ch_initiateTag(initAckCID),    /* remote init tag */
			ch_initialTSN(initCID),	/* local initial TSN for sending */
			peerSupportsPRSCTP,
			FALSE);

		event_logii(VERBOSE, "sctlr_InitAck(): called mdi_init_channel(in-streams=%u, out-streams=%u)",
			inbound_streams, outbound_streams);

		/* reset length field again to NBO... */
		ch_chunkString(initCID),
			/* free initChunk memory */
			mch_remove_simple_chunk(initCID);

		cookieCID = ch_makeCookie(ch_cookieParam(initAckCID));

		if (cookieCID < 0)
		{
			event_log(EXTERNAL_EVENT, "received a initAck without cookie");

			/* stop shutdown timer */
			if (smctrl->initTimer != 0)
			{
				sctp_stopTimer(smctrl->initTimer);
				smctrl->initTimer = 0;
			}
			missing_params.numberOfParams = htonl(1);
			missing_params.params[0] = htons(VLPARAM_COOKIE);

			scu_abort(ECC_MISSING_MANDATORY_PARAM, 6, (unsigned char *)&missing_params);
			bu_unlock_sender(NULL);
			/* delete this association */

			return_state = STATE_STOP_PARSING_REMOVED;
			smctrl->association_state = CLOSED;
			smctrl = NULL;
			return return_state;
		}

		process_further = ch_enterUnrecognizedErrors(initAckCID,
			supportedTypes,
			&errorCID,
			&preferredPrimary,
			&preferredSet,
			&peerSupportsIPV4,
			&peerSupportsIPV6,
			&peerSupportsPRSCTP,
			&peerSupportsADDIP);

		if (process_further == -1)
		{
			mch_remove_simple_chunk(initAckCID);
			ch_deleteChunk(cookieCID);
			if (errorCID != 0)
				ch_deleteChunk(errorCID);
			bu_unlock_sender(NULL);
			if (smctrl->initTimer != 0)
			{
				sctp_stopTimer(smctrl->initTimer);
				smctrl->initTimer = 0;
			}
			mdi_deleteCurrentAssociation();
			mdi_communicationLostNotif(SCTP_COMM_LOST_FAILURE);
			mdi_clearAssociationData();
			smctrl->association_state = CLOSED;
			smctrl = NULL;
			return_state = STATE_STOP_PARSING_REMOVED;
			return return_state;
		}
		else if (process_further == 1)
		{
			return_state = STATE_STOP_PARSING;
		}

		smctrl->peer_cookie_chunk = (cookie_echo_chunk_t *)ch_chunkString(cookieCID);
		/* populate tie tags -> section 5.2.1/5.2.2 */
		smctrl->local_tie_tag = mdi_read_local_tag();
		smctrl->peer_tie_tag = ch_initiateTag(initAckCID);

		smctrl->outbound_stream = outbound_streams;
		smctrl->inbound_stream = inbound_streams;

		mch_remove_simple_chunk(cookieCID);
		mch_remove_simple_chunk(initAckCID);

		/* send cookie back to the address where we got it from     */
		for (index = 0; index < ndAddresses; index++)
			if (adl_equal_address(&(dAddresses[index]), &destAddress))
				break;

		/* send cookie */
		bu_put_Ctrl_Chunk((SCTP_simple_chunk *)smctrl->peer_cookie_chunk, &index);
		if (errorCID != 0)
		{
			bu_put_Ctrl_Chunk((SCTP_simple_chunk *)ch_chunkString(errorCID), &index);
			ch_deleteChunk(errorCID);
		}

		bu_sendAllChunks(&index);
		bu_unlock_sender(&index);
		event_logi(INTERNAL_EVENT_1, "event: sent cookie echo to PATH %u", index);

		if (preferredSet == TRUE)
		{
			preferredPath = mdi_getIndexForAddress(&preferredPrimary);
			if (preferredPath != -1)
				pm_setPrimaryPath(preferredPath);
		}

		// stop init timer
		if (smctrl->initTimer != 0)
			sctp_stopTimer(smctrl->initTimer);

		/* start cookie timer */
		state = COOKIE_ECHOED;
		smctrl->initTimer = adl_startTimer(smctrl->initTimerDuration,
			&msm_timer_expired, TIMER_TYPE_INIT,
			(void *)&smctrl->associationID, NULL);
		break;

	case COOKIE_ECHOED:
		/* Duplicated initAck, ignore */
		event_log(EXTERNAL_EVENT, "event: duplicatied sctlr_initAck in state COOKIE_ECHOED");
		break;
	case CLOSED:
	case ESTABLISHED:
	case SHUTDOWNPENDING:
	case SHUTDOWNRECEIVED:
	case SHUTDOWNSENT:
		/* In this states the initAck is unexpected event. */
		event_logi(EXTERNAL_EVENT, "discarding event: sctlr_initAck in state %02d", state);
		break;
	default:
		/* error logging: unknown event */
		event_logi(EXTERNAL_EVENT, "sctlr_initAck: unknown state %02d", state);
		break;
	}

	smctrl->association_state = state;
	smctrl = NULL;
	return return_state;
}

/**
  msm_process_cookie_echo_chunk is called by bundling when a cookie echo chunk was received from  the peer.
  The following data is retrieved from the cookie and saved for this association:
  \begin{itemize}
  \item  from the init chunk:
  \begin{itemize}
  \item peers tag
  \item peers receiver window credit
  \item peers initial TSN
  \item peers network address list if multihoming is used
  \end{itemize}
  \item local tag generated before the initAck was sent
  \item my initial TSN generated before the initAck was sent
  \item number of send streams I use, must be lower or equal to peers number of receive streams from init chunk
  \item number of receive streams I use (can be lower than number of send streams the peer requested in
  the init chunk
  \end{itemiz}
  @param  cookie_echo pointer to the received cookie echo chunk
  msm_process_cookie_echo_chunk
  */
void msm_process_cookie_echo_chunk(cookie_echo_chunk_t *cookie_echo)
{
	union sockunion destAddress;
	union sockunion dAddresses[MAX_NUM_ADDRESSES];
	int ndAddresses, result;
	unsigned int state, new_state = 0xFFFFFFFF;
	unsigned int cookieLifetime;
	unsigned int mySupportedTypes;
	ChunkID cookieCID;
	ChunkID cookieAckCID;
	ChunkID initCID;
	ChunkID initAckCID;
	ChunkID shutdownAckCID;
	ChunkID errorCID;
	unsigned int cookie_local_tag, cookie_remote_tag;
	unsigned int cookie_local_tietag, cookie_remote_tietag;
	unsigned int local_tag, remote_tag;
	short primaryDestinationAddress;
	short noOfDestinationAddresses;
	bool peerSupportsPRSCTP;

	unsigned short noSuccess, restart_result;
	unsigned int peerAddressTypes;

	int SendCommUpNotification = -1;

	event_log(INTERNAL_EVENT_0, "msm_process_cookie_echo_chunk() is being executed");

	cookieCID = mch_make_simple_chunk((SCTP_simple_chunk *)cookie_echo);

	if (ch_chunkType(cookieCID) != CHUNK_COOKIE_ECHO)
	{
		/* error logging */
		mch_remove_simple_chunk(cookieCID);
		error_log(ERROR_MAJOR, "msm_process_cookie_echo_chunk: wrong chunk type");
		return;
	}
	/* section 5.2.4. 1) and 2.) */
	if (ch_goodCookie(cookieCID))
	{
		mch_remove_simple_chunk(cookieCID);
		event_log(EXTERNAL_EVENT, "event: invalidCookie received");
		return;
	}
	initCID = ch_cookieInitFixed(cookieCID);
	initAckCID = ch_cookieInitAckFixed(cookieCID);

	cookie_remote_tag = ch_initiateTag(initCID);
	cookie_local_tag = ch_initiateTag(initAckCID);

	/* these two will be zero, if association is not up yet */
	local_tag = mdi_read_local_tag();
	remote_tag = mdi_readTagRemote();

	if ((mdi_readLastInitiateTag() != cookie_local_tag) &&
		(mdi_readLastFromPort() != ch_CookieSrcPort(cookieCID)) &&
		(mdi_readLastDestPort() != ch_CookieDestPort(cookieCID)))
	{

		mch_remove_simple_chunk(cookieCID);
		ch_deleteChunk(initCID);
		ch_deleteChunk(initAckCID);
		event_log(EXTERNAL_EVENT, "event: good cookie echo received, but with incorrect verification tag");

		/* for test purposes */
		exit(-1);
		/* for test purposes */

		return;
	}

	/* section 5.2.4. 3.) */
	if ((cookieLifetime = ch_staleCookie(cookieCID)) > 0)
	{
		event_logi(EXTERNAL_EVENT, "event: staleCookie received, lifetime = %d", cookieLifetime);

		if ((cookie_local_tag != local_tag) || (cookie_remote_tag != remote_tag))
		{

			mdi_writeLastInitiateTag(cookie_remote_tag);
			/* make and send stale cookie error */
			errorCID = ch_makeSimpleChunk(CHUNK_ERROR, FLAG_NONE);
			ch_enterStaleCookieError(errorCID, (unsigned int)(1.2 * cookieLifetime));
			bu_put_Ctrl_Chunk(ch_chunkString(errorCID), NULL);
			bu_sendAllChunks(NULL);
			mch_remove_simple_chunk(cookieCID);
			ch_deleteChunk(initCID);
			ch_deleteChunk(initAckCID);
			ch_deleteChunk(errorCID);
			return;
		} /* ELSE : Case 5.2.4.E. Valid Cookie, unpack into a TCB */
	}

	result = mdi_readLastFromAddress(&destAddress);
	if (result != 0)
	{
		error_log(ERROR_MAJOR, "msm_process_cookie_echo_chunk: mdi_readLastFromAddress failed !");
		ch_deleteChunk(initCID);
		ch_deleteChunk(initAckCID);
		mch_remove_simple_chunk(cookieCID);
		return;
	}

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		noOfDestinationAddresses = 1;
		primaryDestinationAddress = 0;

		/* why is INSTANCE_NAME here zero ? */
		noSuccess = mdi_newAssociation(NULL, mdi_readLastDestPort(),
			mdi_readLastFromPort(),
			cookie_local_tag, /* this is MY tag */
			primaryDestinationAddress,
			noOfDestinationAddresses, &destAddress);

		if (noSuccess)
		{
			/* new association could not be entered in the list of associations */
			error_log(ERROR_MAJOR, "msm_process_cookie_echo_chunk: Creation of association failed");
			ch_deleteChunk(initCID);
			ch_deleteChunk(initAckCID);
			mch_remove_simple_chunk(cookieCID);
			return;
		}
	}

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		error_log(ERROR_MAJOR, "sctlr_cookie-echo: program error: SCTP-control NULL");
		ch_deleteChunk(initCID);
		ch_deleteChunk(initAckCID);
		mch_remove_simple_chunk(cookieCID);
		return;
	}

	state = smctrl->association_state;

	event_logiii(VERBOSE, "State : %u, cookie_remote_tag : %x , cookie_local_tag : %x ",
		state, cookie_remote_tag, cookie_local_tag);
	event_logii(VERBOSE, "remote_tag ; %x , local_tag : %x ", remote_tag, local_tag);

	switch (state)
	{
	case CLOSED:
		/*----------------- Normal association setup -----------------------------------------*/
		event_log(EXTERNAL_EVENT, "event: msm_process_cookie_echo_chunk in state CLOSED");
		mySupportedTypes = mdi_getSupportedAddressTypes();
		/* retrieve destination addresses from cookie */
		ndAddresses = ch_read_addrlist_from_cookie(cookieCID, mySupportedTypes, dAddresses, &peerAddressTypes, &destAddress);

		if (ndAddresses > 0)
		{
			/* save addresses if initAck contained more then zero, otherwise the source address
					   of the IP-message carrying the cookie-chunk will be used for this association. */
			event_logi(VERBOSE, "Storing %d destination addresses as paths", ndAddresses);
			mdi_set_channel_remoteaddrlist(dAddresses, ndAddresses);
		}

		peerSupportsPRSCTP = ch_getPRSCTPfromCookie(cookieCID);

		/* initialize new association from cookie data */
		mdi_init_channel(ch_receiverWindow(initCID),
			ch_noInStreams(initAckCID),
			ch_noOutStreams(initAckCID),
			ch_initialTSN(initCID), cookie_remote_tag, ch_initialTSN(initAckCID),
			peerSupportsPRSCTP, FALSE);

		smctrl->outbound_stream = ch_noOutStreams(initAckCID);
		smctrl->inbound_stream = ch_noInStreams(initAckCID);
		event_logii(VERBOSE, "Set Outbound Stream to %u, Inbound Streams to %u",
			smctrl->outbound_stream, smctrl->inbound_stream);

		/* make cookie acknowledgement */
		cookieAckCID = ch_makeSimpleChunk(CHUNK_COOKIE_ACK, FLAG_NONE);

		/* send cookie acknowledgement */
		bu_put_Ctrl_Chunk(ch_chunkString(cookieAckCID), NULL);
		bu_sendAllChunks(NULL);
		bu_unlock_sender(NULL);
		ch_deleteChunk(cookieAckCID);

		/* notification to ULP */
		SendCommUpNotification = SCTP_COMM_UP_RECEIVED_VALID_COOKIE;

		/* mdi_communicationUpNotif(SCTP_COMM_UP_RECEIVED_VALID_COOKIE); */

		new_state = ESTABLISHED;
		break;

		/* For the rest of these (pathological) cases, refer to section 5.2.4 as to what to do */

	case COOKIE_WAIT:
	case COOKIE_ECHOED:
	case ESTABLISHED:
	case SHUTDOWNPENDING:
	case SHUTDOWNSENT:
	case SHUTDOWNRECEIVED:
	case SHUTDOWNACKSENT:
		cookie_local_tietag = ch_CookieLocalTieTag(cookieCID);
		cookie_remote_tietag = ch_CookiePeerTieTag(cookieCID);

		event_logii(VERBOSE, "cookie_remote_tietag ; %x , cookie_local_tietag : %x ",
			cookie_remote_tietag, cookie_local_tietag);
		/* cookie_local_tag, cookie_remote_tag are set */
		/* local_tag, remote_tag are also set from the TCB */

		if (cookie_local_tag == local_tag)
		{ /* cases B or D */
			if (cookie_remote_tag == remote_tag)
			{ /* case D */
			/*  the endpoint should always enter the ESTABLISHED state, if it has not
		already done so. It should stop any init or cookie timers that may be
		running and send a COOKIE ACK */
				event_log(VERBOSE, "Dupl. CookieEcho, case 5.2.4.D)");
				/* stop COOKIE timers */
				if (smctrl->initTimer != 0)
				{
					sctp_stopTimer(smctrl->initTimer);
					smctrl->initTimer = 0;
				}
				/* go to ESTABLISHED state */
				new_state = ESTABLISHED;
				if (state == COOKIE_WAIT || state == COOKIE_ECHOED)
				{
					mySupportedTypes = mdi_getSupportedAddressTypes();
					ndAddresses = ch_read_addrlist_from_cookie(cookieCID, mySupportedTypes, dAddresses, &peerAddressTypes, &destAddress);
					if (ndAddresses > 0)
					{
						/* save addresses if initAck contained more then zero, otherwise the source address
										   of the IP-message carrying the cookie-chunk will be used for this association. */
						event_logi(VERBOSE, "Storing %d destination addresses as paths", ndAddresses);
						mdi_set_channel_remoteaddrlist(dAddresses, ndAddresses);
					}
					peerSupportsPRSCTP = ch_getPRSCTPfromCookie(cookieCID);

					/* initialize new association from cookie data */
					mdi_init_channel(ch_receiverWindow(initCID),
						ch_noInStreams(initAckCID),
						ch_noOutStreams(initAckCID),
						ch_initialTSN(initCID),
						cookie_remote_tag,
						ch_initialTSN(initAckCID),
						peerSupportsPRSCTP, FALSE);

					smctrl->outbound_stream = ch_noOutStreams(initAckCID);
					smctrl->inbound_stream = ch_noInStreams(initAckCID);
					event_logii(VERBOSE, "Set Outbound Stream to %u, Inbound Streams to %u",
						smctrl->outbound_stream, smctrl->inbound_stream);

					/* notification to ULP */
					SendCommUpNotification = SCTP_COMM_UP_RECEIVED_VALID_COOKIE;
				}
				/* make cookie acknowledgement */
				cookieAckCID = ch_makeSimpleChunk(CHUNK_COOKIE_ACK, FLAG_NONE);
				/* send cookie acknowledgement */
				bu_put_Ctrl_Chunk(ch_chunkString(cookieAckCID), NULL);
				bu_sendAllChunks(NULL);
				bu_unlock_sender(NULL);
				ch_deleteChunk(cookieAckCID);
			}
			else
			{ /* case B */
			/*  The endpoint should stay in or enter
					  the ESTABLISHED state but it MUST update its peer's Verification
					  Tag from the State Cookie, stop any init or cookie timers that may
					  running and send a COOKIE ACK. */
				event_log(VERBOSE, "Dupl. CookieEcho, case 5.2.4.B)");
				/* stop COOKIE timers */
				if (smctrl->initTimer != 0)
				{
					sctp_stopTimer(smctrl->initTimer);
					smctrl->initTimer = 0;
				}
				new_state = ESTABLISHED;

				if (state == COOKIE_WAIT || state == COOKIE_ECHOED)
				{
					mySupportedTypes = mdi_getSupportedAddressTypes();
					ndAddresses = ch_read_addrlist_from_cookie(cookieCID, mySupportedTypes, dAddresses, &peerAddressTypes, &destAddress);
					if (ndAddresses > 0)
					{
						/* save addresses if initAck contained more then zero, otherwise the source address
										   of the IP-message carrying the cookie-chunk will be used for this association. */
						event_logi(VERBOSE, "Storing %d destination addresses as paths", ndAddresses);
						mdi_set_channel_remoteaddrlist(dAddresses, ndAddresses);
					}
					peerSupportsPRSCTP = ch_getPRSCTPfromCookie(cookieCID);

					/* initialize new association from cookie data */
					mdi_init_channel(ch_receiverWindow(initCID),
						ch_noInStreams(initAckCID),
						ch_noOutStreams(initAckCID),
						ch_initialTSN(initCID),
						cookie_remote_tag,
						ch_initialTSN(initAckCID),
						peerSupportsPRSCTP, FALSE);

					smctrl->outbound_stream = ch_noOutStreams(initAckCID);
					smctrl->inbound_stream = ch_noInStreams(initAckCID);
					event_logii(VERBOSE, "Set Outbound Stream to %u, Inbound Streams to %u",
						smctrl->outbound_stream, smctrl->inbound_stream);

					/* notification to ULP */
					SendCommUpNotification = SCTP_COMM_UP_RECEIVED_VALID_COOKIE;
				}
				mdi_rewriteTagRemote(cookie_remote_tag);
				mdi_rewriteLocalTag(cookie_local_tag);
				/* make cookie acknowledgement */
				cookieAckCID = ch_makeSimpleChunk(CHUNK_COOKIE_ACK, FLAG_NONE);
				/* send cookie acknowledgement */
				bu_put_Ctrl_Chunk(ch_chunkString(cookieAckCID), NULL);
				bu_sendAllChunks(NULL);
				bu_unlock_sender(NULL);
				ch_deleteChunk(cookieAckCID);
			}
		}
		else
		{ /* cases A or C */
			if ((cookie_remote_tag == remote_tag) &&
				(cookie_local_tietag == 0) &&
				(cookie_remote_tietag == 0))
			{ /* is case C */
			/* section 5.2.4. action C : silently discard cookie */
				event_log(VERBOSE, "Dupl. CookieEcho, case 5.2.4.C) --> Silently discard !");
				mch_remove_simple_chunk(cookieCID);
				ch_deleteChunk(initCID);
				ch_deleteChunk(initAckCID);
				smctrl = NULL;
				return; /* process data as usual ? */
			}
			else if ((cookie_remote_tag != remote_tag) &&
				(cookie_local_tietag == smctrl->local_tie_tag) &&
				(cookie_remote_tietag == smctrl->peer_tie_tag))
			{ /* case A */
			/* section 5.2.4. action A : Possible Peer Restart  */
				if (state != SHUTDOWNACKSENT)
				{
					event_logi(VERBOSE, "Peer Restart, case 5.2.4.A, state == %u", state);

					mySupportedTypes = mdi_getSupportedAddressTypes();
					ndAddresses = ch_read_addrlist_from_cookie(cookieCID, mySupportedTypes, dAddresses, &peerAddressTypes, &destAddress);
					peerSupportsPRSCTP = ch_getPRSCTPfromCookie(cookieCID);

					restart_result = mdi_restart_channel(ch_noInStreams(initAckCID),
						ch_noOutStreams(initAckCID),
						ch_receiverWindow(initCID),
						ch_initialTSN(initCID),
						ch_initialTSN(initAckCID),
						(short)ndAddresses, 0, dAddresses,
						peerSupportsPRSCTP, FALSE); /* setting 0 as primary */
					if (restart_result == 0)
					{
						/* what happens to SCTP data chunks is implementation specific */
						mdi_rewriteTagRemote(cookie_remote_tag);
						mdi_rewriteLocalTag(cookie_local_tag);
						/* go to ESTABLISHED state */
						new_state = ESTABLISHED;
						/* make cookie acknowledgement */
						cookieAckCID = ch_makeSimpleChunk(CHUNK_COOKIE_ACK, FLAG_NONE);
						/* send cookie acknowledgement */
						bu_put_Ctrl_Chunk(ch_chunkString(cookieAckCID), NULL);
						bu_sendAllChunks(NULL);
						bu_unlock_sender(NULL);
						ch_deleteChunk(cookieAckCID);

						SendCommUpNotification = SCTP_COMM_UP_RECEIVED_COOKIE_RESTART;
						/* mdi_restartNotif(); */
					}
					else
					{ /* silently discard */
						event_log(VERBOSE, "Restart not successful, silently discarding CookieEcho");
						mch_remove_simple_chunk(cookieCID);
						ch_deleteChunk(initCID);
						ch_deleteChunk(initAckCID);
						smctrl = NULL;
						return; /* process data as usual ? */
					}
				}
				else
				{
					event_log(VERBOSE, "Peer Restart case, state == SHUTDOWN_ACK_SENT");
					/* resend SHUTDOWN_ACK */
					shutdownAckCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_ACK, FLAG_NONE);
					/* add ERROR_CHUNK with Error Cause : "Cookie Received while shutting down" */
					bu_put_Ctrl_Chunk(ch_chunkString(shutdownAckCID), NULL);
					errorCID = ch_makeErrorChunk();
					ch_enterErrorCauseData(errorCID, ECC_COOKIE_RECEIVED_DURING_SHUTDWN, 0, NULL);
					bu_put_Ctrl_Chunk(ch_chunkString(errorCID), NULL);
					/* send cookie acknowledgement */
					bu_sendAllChunks(NULL);
					bu_unlock_sender(NULL);
					ch_deleteChunk(shutdownAckCID);
					ch_deleteChunk(errorCID);
				}
			}
			else
			{ /* silently discard */
				event_log(VERBOSE, "Dupl. CookieEcho, silently discarding CookieEcho");
				mch_remove_simple_chunk(cookieCID);
				ch_deleteChunk(initCID);
				ch_deleteChunk(initAckCID);
				smctrl = NULL;
				return; /* process data as usual ? */
			}
		}
		break;
	default:
		/* error logging: unknown event */
		error_logi(EXTERNAL_EVENT_X, "msm_process_cookie_echo_chunk : unknown state %02u", state);
		break;
	}

	ch_deleteChunk(initCID);
	ch_deleteChunk(initAckCID);
	mch_remove_simple_chunk(cookieCID);

	if (new_state != 0xFFFFFFFF)
		smctrl->association_state = new_state;
	smctrl = NULL;

	if (SendCommUpNotification != -1)
	{
		if (SendCommUpNotification == SCTP_COMM_UP_RECEIVED_COOKIE_RESTART)
			mdi_restartNotif();
		else if (SendCommUpNotification == SCTP_COMM_UP_RECEIVED_VALID_COOKIE)
			mdi_communicationUpNotif(SCTP_COMM_UP_RECEIVED_VALID_COOKIE);
	}
}

/**
  sctlr_cookieAck is called by bundling when a cookieAck chunk was received from  the peer.
  The only purpose is to inform the active side that peer has received the cookie chunk.
  The association is in established state after this function is called.
  Communication up is signalled to the upper layer in this case.
  @param cookieAck pointer to the received cookie ack chunk
  */
void sctlr_cookieAck(SCTP_simple_chunk *cookieAck)
{
	unsigned int state;
	ChunkID cookieAckCID;
	int SendCommUpNotif = -1;

	cookieAckCID = mch_make_simple_chunk(cookieAck);

	if (ch_chunkType(cookieAckCID) != CHUNK_COOKIE_ACK)
	{
		/* error logging */
		error_log(ERROR_MAJOR, "sctlr_cookieAck: wrong chunk type");
		return;
	}
	mch_remove_simple_chunk(cookieAckCID);

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		error_log(ERROR_MAJOR, "sctlr_cookieAck: read SCTP-control failed");
		return;
	}

	state = smctrl->association_state;

	switch (state)
	{
	case COOKIE_ECHOED:

		event_logi(EXTERNAL_EVENT_X, "event: sctlr_cookieAck in state %02d", state);
		/* stop init timer */
		if (smctrl->initTimer != 0)
		{
			sctp_stopTimer(smctrl->initTimer);
			smctrl->initTimer = 0;
		}
		/* free  peer_cookie_chunk */
		free(smctrl->initChunk);
		free(smctrl->peer_cookie_chunk);
		smctrl->initChunk = NULL;
		smctrl->peer_cookie_chunk = NULL;
		SendCommUpNotif = SCTP_COMM_UP_RECEIVED_COOKIE_ACK;
		/* mdi_communicationUpNotif(SCTP_COMM_UP_RECEIVED_COOKIE_ACK); */

		state = ESTABLISHED;
		break;

	case ESTABLISHED:
		/* Duplicated cookie, ignore */
		break;
	case CLOSED:
	case COOKIE_WAIT:
	case SHUTDOWNPENDING:
	case SHUTDOWNRECEIVED:
	case SHUTDOWNSENT:
		/* In this states the cookie is unexpected event.Do error logging  */
		event_logi(EXTERNAL_EVENT_X, "unexpected event: sctlr_cookieAck in state %02d", state);
		break;
	default:
		/* error logging: unknown event */
		break;
	}

	smctrl->association_state = state;
	smctrl = NULL;
	if (SendCommUpNotif == SCTP_COMM_UP_RECEIVED_COOKIE_ACK)
		mdi_communicationUpNotif(SCTP_COMM_UP_RECEIVED_COOKIE_ACK);
}

/**
  sctlr_shutdown is called by bundling when a shutdown chunk was received from the peer.
  This function initiates a graceful shutdown of the association.
  @param  shutdown_chunk pointer to the received shutdown chunk
  */
int sctlr_shutdown(SCTP_simple_chunk *shutdown_chunk)
{
	unsigned int state, new_state;
	boolean readyForShutdown;
	bool removed = FALSE, sendNotification = FALSE;
	unsigned int lastFromPath;
	int return_state = STATE_OK;
	ChunkID abortCID;
	ChunkID shutdownAckCID;
	ChunkID shutdownCID;

	shutdownCID = mch_make_simple_chunk(shutdown_chunk);

	if (ch_chunkType(shutdownCID) != CHUNK_SHUTDOWN)
	{
		/* error logging */
		error_log(ERROR_MAJOR, "sctlr_cookieAck: wrong chunk type");
		mch_remove_simple_chunk(shutdownCID);
		return return_state;
	}

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sctlr_shutdown: read SCTP-control failed");
		mch_remove_simple_chunk(shutdownCID);
		return return_state;
	}

	state = smctrl->association_state;
	new_state = state;

	lastFromPath = mdi_readLastFromPath();

	switch (state)
	{
	case CLOSED:
		event_log(EXTERNAL_EVENT, "event: sctlr_shutdown in state CLOSED, send ABORT ! ");
		abortCID = ch_makeSimpleChunk(CHUNK_ABORT, FLAG_NO_TCB);
		bu_put_Ctrl_Chunk(ch_chunkString(abortCID), &lastFromPath);
		bu_sendAllChunks(&lastFromPath);
		bu_unlock_sender(&lastFromPath);
		ch_deleteChunk(abortCID);
		/* delete all data of this association */
		mdi_deleteCurrentAssociation();
		removed = TRUE;
		return_state = STATE_STOP_PARSING_REMOVED;
		break;

	case COOKIE_WAIT:
	case COOKIE_ECHOED:
	case SHUTDOWNPENDING:
		event_logi(EXTERNAL_EVENT, "event: sctlr_shutdown in state %2u -> discarding !", state);
		mch_remove_simple_chunk(shutdownCID);
		break;

	case SHUTDOWNRECEIVED:
	case SHUTDOWNACKSENT:
		event_log(EXTERNAL_EVENT, "sctlr_shutdown in state SHUTDOWN_RECEIVED/SHUTDOWN_ACK_SENT -> acking CTSNA !");
		rtx_rcv_shutdown_ctsna(ch_cummulativeTSNacked(shutdownCID));
		break;

	case ESTABLISHED:
		event_log(EXTERNAL_EVENT, "event: sctlr_shutdown in state ESTABLISHED");

		new_state = SHUTDOWNRECEIVED;

		rtx_rcv_shutdown_ctsna(ch_cummulativeTSNacked(shutdownCID));

		readyForShutdown = (rtx_get_unacked_chunks_count() == 0) &&
			(fc_get_queued_chunks_count() == 0);

		sendNotification = TRUE;

		if (readyForShutdown)
		{
			/* retransmissions are not necessary */
			/* send shutdownAck */
			event_log(VERBOSE, "We are ready for SHUTDOWN, sending SHUTDOWN_ACK !");
			shutdownAckCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_ACK, FLAG_NONE);
			bu_put_Ctrl_Chunk(ch_chunkString(shutdownAckCID), &lastFromPath);
			bu_sendAllChunks(&lastFromPath);
			ch_deleteChunk(shutdownAckCID);
			if (smctrl->initTimer != 0)
				sctp_stopTimer(smctrl->initTimer);

			smctrl->initTimer =
				adl_startTimer(smctrl->initTimerDuration, &msm_timer_expired, TIMER_TYPE_SHUTDOWN,
				(void *)&smctrl->associationID, NULL);
			new_state = SHUTDOWNACKSENT;
		}
		else
		{
			/* retrieve cummunalative TSN acked from shutdown chunk */
			rtx_shutdown();
			/* retransmissions are necessary */
			/* call reliable transfer and wait for sci_allChunksAcked */
		}
		break;

	case SHUTDOWNSENT:
		/* check wether reliable transfer is ready for shutdown */
		readyForShutdown = (rtx_get_unacked_chunks_count() == 0) &&
			(fc_get_queued_chunks_count() == 0);

		sendNotification = TRUE;

		if (readyForShutdown)
		{
			/* retransmissions are not necessary */
			/* send shutdownAck */
			shutdownAckCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_ACK, FLAG_NONE);
			bu_put_Ctrl_Chunk(ch_chunkString(shutdownAckCID), &lastFromPath);
			bu_sendAllChunks(&lastFromPath);
			ch_deleteChunk(shutdownAckCID);
			if (smctrl->initTimer != 0)
				sctp_stopTimer(smctrl->initTimer);
			smctrl->initTimer =
				adl_startTimer(smctrl->initTimerDuration, &msm_timer_expired, TIMER_TYPE_SHUTDOWN,
				(void *)&smctrl->associationID, NULL);

			new_state = SHUTDOWNACKSENT;
		}
		else
		{
			error_log(ERROR_MAJOR, "Error in Program Logic !!!");
			error_log(ERROR_MAJOR,
				"SHUTDOWN_SENT state may not be entered, if queues are not empty !!!!");
		}
		break;

	default:
		/* error logging */
		event_logi(EXTERNAL_EVENT_X, "sctlr_shutdown in state %02d: unexpected event", state);
		break;
	}
	mch_remove_simple_chunk(shutdownCID);
	if (sendNotification)
	{
		mdi_peerShutdownReceivedNotif();
	}

	smctrl->association_state = new_state;
	smctrl = NULL;
	if (removed == TRUE)
	{
		mdi_communicationLostNotif(SCTP_COMM_LOST_NO_TCB);
		mdi_clearAssociationData();
	}
	return return_state;
}

/**
  sctlr_shutdownAck is called by bundling when a shutdownAck chunk was received from the peer.
  Depending on the current state of the association, COMMUNICATION LOST is signaled to the
  Upper Layer Protocol, and the association marked for removal.
  */
int sctlr_shutdownAck()
{
	unsigned int state, new_state;
	unsigned int lastFromPath, lastTag;
	boolean tagWasZero = FALSE;
	ChunkID shdcCID;
	int return_state = STATE_OK;
	int removed = 0; /* i.e. meaning FALSE here ! */

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sctlr_shutdownAck: read SCTP-control failed");
		return return_state;
	}

	lastFromPath = mdi_readLastFromPath();
	state = smctrl->association_state;
	new_state = state;

	switch (state)
	{
	case CLOSED:
		error_log(ERROR_FATAL,
			"sctlr_shutdownAck in state CLOSED, should have been handled before ! ");
		break;
	case COOKIE_WAIT:
	case COOKIE_ECHOED:
		/* see also section 8.5.E.) treat this like OOTB packet, leave T1 timer run ! */
		event_logi(EXTERNAL_EVENT,
			"event: sctlr_shutdownAck in state %u, send SHUTDOWN_COMPLETE ! ", state);
		shdcCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_COMPLETE, FLAG_NO_TCB);

		/* make sure the shutdown_complete is written to the peer with his tag */
		if (mdi_readTagRemote() == 0)
		{
			tagWasZero = TRUE;
			lastTag = mdi_readLastInitiateTag();
			mdi_rewriteTagRemote(lastTag);
		}

		bu_put_Ctrl_Chunk(ch_chunkString(shdcCID), &lastFromPath);
		bu_sendAllChunks(&lastFromPath);
		bu_unlock_sender(&lastFromPath);
		ch_deleteChunk(shdcCID);
		return_state = STATE_OK;

		if (tagWasZero == TRUE)
		{
			mdi_rewriteTagRemote(0);
		}
		break;
	case ESTABLISHED:
		error_log(ERROR_MAJOR,
			"sctlr_shutdownAck in state ESTABLISHED, peer not standard conform ! ");
		break;
	case SHUTDOWNPENDING:
		error_log(ERROR_MAJOR,
			"sctlr_shutdownAck in state SHUTDOWNPENDING, peer not standard conform ! ");
		break;
	case SHUTDOWNRECEIVED:
		error_log(ERROR_MAJOR,
			"sctlr_shutdownAck in state SHUTDOWNRECEIVED, peer not standard conform ! ");
		break;

	case SHUTDOWNSENT:
	case SHUTDOWNACKSENT:

		if (smctrl->initTimer != 0)
		{
			sctp_stopTimer(smctrl->initTimer);
			smctrl->initTimer = 0;
		}
		else
		{
			error_log(ERROR_FATAL, "Timer not running - Error in Program Logic");
		}

		shdcCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_COMPLETE, FLAG_NONE);
		bu_put_Ctrl_Chunk(ch_chunkString(shdcCID), &lastFromPath);

		bu_sendAllChunks(&lastFromPath);
		ch_deleteChunk(shdcCID);

		bu_unlock_sender(&lastFromPath);
		/* delete all data of this association */
		return_state = STATE_STOP_PARSING_REMOVED;
		mdi_deleteCurrentAssociation();

		removed = SCTP_SHUTDOWN_COMPLETE; /* i.e. meaning SHUTDOWN_COMPLETE here */

		new_state = CLOSED;
		break;

	default:
		/* error logging */
		event_logi(EXTERNAL_EVENT_X, "sctlr_shutdownAck in state %02d: unexpected event", state);
		break;
	}

	smctrl->association_state = new_state;
	smctrl = NULL;
	if (removed != 0)
	{
		if (removed == SCTP_SHUTDOWN_COMPLETE)
		{
			mdi_shutdownCompleteNotif();
		}
		else
		{
			mdi_communicationLostNotif(SCTP_COMM_LOST_NO_TCB);
		}
		mdi_clearAssociationData();
	}
	return return_state;
}

/**
  sctlr_shutdownComplete is called by bundling when a SHUTDOWN COMPLETE chunk was received from the peer.
  COMMUNICATION LOST is signaled to the ULP, timers stopped, and the association is marked for removal.
  */
int sctlr_shutdownComplete()
{
	unsigned int state, new_state;
	unsigned int lastFromPath;
	int return_state = STATE_OK;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sctlr_shutdownComplete: read SCTP-control failed");
		return return_state;
	}

	lastFromPath = mdi_readLastFromPath();

	state = smctrl->association_state;
	new_state = state;

	switch (state)
	{
	case CLOSED:
	case COOKIE_WAIT:
	case COOKIE_ECHOED:
	case ESTABLISHED:
	case SHUTDOWNPENDING:
	case SHUTDOWNRECEIVED:
	case SHUTDOWNSENT:
		error_logi(EXTERNAL_EVENT, "sctlr_shutdownComplete in state %u -> discarding ! ", state);
		break;

	case SHUTDOWNACKSENT:
		if (smctrl->initTimer != 0)
		{
			sctp_stopTimer(smctrl->initTimer);
			smctrl->initTimer = 0;
		}
		else
		{
			error_log(ERROR_FATAL,
				"sctlr_shutdownComplete : Timer not running - problem in Program Logic!");
		}
		pm_disableAllHB();

		bu_unlock_sender(&lastFromPath);
		/* delete all data of this association */
		mdi_deleteCurrentAssociation();

		smctrl->association_state = CLOSED;

		mdi_shutdownCompleteNotif();
		mdi_clearAssociationData();

		smctrl = NULL;

		return_state = STATE_STOP_PARSING_REMOVED;

		return return_state;
		break;

	default:
		/* error logging */
		event_logi(EXTERNAL_EVENT_X, "sctlr_shutdownComplete in state %02d: unexpected event", state);
		break;
	}
	smctrl->association_state = new_state;
	smctrl = NULL;
	return return_state;
}

/**
  sctlr_abort is called by bundling when an ABORT chunk was received from  the peer.
  COMMUNICATION LOST is signalled to the ULP, timers are stopped, and the association
  is marked for removal.
  */
int sctlr_abort()
{
	unsigned int state;
	unsigned int lastFromPath;
	int return_state = STATE_OK;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sctlr_abort: read SCTP-control failed");
		return return_state;
	}

	lastFromPath = mdi_readLastFromPath();

	state = smctrl->association_state;

	switch (state)
	{
	case CLOSED:
		event_log(EXTERNAL_EVENT, "event: sctlr_abort in state CLOSED -> discard chunk");
		/* discard chunk */
		break;
	case COOKIE_WAIT:
	case COOKIE_ECHOED:
	case SHUTDOWNSENT:
		event_logi(EXTERNAL_EVENT, "event: sctlr_abort in state %2d", state);

		/* stop possible timer */
		if (smctrl->initTimer != 0)
		{
			sctp_stopTimer(smctrl->initTimer);
			smctrl->initTimer = 0;
		}
		/* delete all data of this association */

		bu_unlock_sender(&lastFromPath);

		return_state = STATE_STOP_PARSING_REMOVED;
		mdi_deleteCurrentAssociation();

		mdi_communicationLostNotif(SCTP_COMM_LOST_ABORTED);
		mdi_clearAssociationData();

		break;
	case ESTABLISHED:
	case SHUTDOWNPENDING:
	case SHUTDOWNRECEIVED:
	case SHUTDOWNACKSENT:
		event_logi(EXTERNAL_EVENT, "event: sctlr_abort in state %02d", state);
		/* delete all data of this association */
		return_state = STATE_STOP_PARSING_REMOVED;

		/* stop init timer, just in case */
		if (smctrl->initTimer != 0)
		{
			sctp_stopTimer(smctrl->initTimer);
			smctrl->initTimer = 0;
		}

		bu_unlock_sender(&lastFromPath);

		mdi_deleteCurrentAssociation();

		mdi_communicationLostNotif(SCTP_COMM_LOST_ABORTED);
		mdi_clearAssociationData();

		break;
	default:
		/* error logging */
		event_logi(EXTERNAL_EVENT_X, "sctlr_abort in state %02d: unexpected event", state);
		break;
	}
	smctrl = NULL;
	return return_state;
}

/**
   msm_read_cookie_staleness is called by bundling when a 'stale cookie' error chunk was received.
   @param error_chunk pointer to the received error chunk
   */
void msm_read_cookie_staleness(SCTP_simple_chunk *error_chunk)
{
	unsigned int state;
	ChunkID errorCID;
	ChunkID initCID;

	errorCID = mch_make_simple_chunk((SCTP_simple_chunk *)error_chunk);

	if (ch_chunkType(errorCID) != CHUNK_ERROR)
	{
		/* error logging */
		mch_remove_simple_chunk(errorCID);
		error_log(ERROR_MAJOR, "msm_read_cookie_staleness: wrong chunk type");
		return;
	}

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "msm_read_cookie_staleness: read SCTP-control failed");
		return;
	}

	state = smctrl->association_state;

	switch (state)
	{
	case COOKIE_ECHOED:

		/* make chunkHandler init chunk from stored init chunk string */
		initCID = mch_make_simple_chunk((SCTP_simple_chunk *)smctrl->initChunk);

		/* read staleness from error chunk and enter it into the cookie preserv. */
		mch_write_cookie_preservative(initCID, mch_read_cookie_staleness(errorCID));

		/* resend init */
		bu_put_Ctrl_Chunk(ch_chunkString(initCID), NULL);
		bu_sendAllChunks(NULL);
		mch_remove_simple_chunk(initCID);

		state = COOKIE_WAIT;
		break;

	default:
		/* error logging */
		event_logi(EXTERNAL_EVENT_X, "msm_read_cookie_staleness in state %02d: unexpected event", state);
		break;
	}
	smctrl->association_state = state;
	smctrl = NULL;
}

/**
   sci_getState is called by distribution to get the state of the current SCTP-control instance.
   This function also logs the state with log-level VVERBOSE.
   @return state value (0=CLOSED, 3=ESTABLISHED)
   */
unsigned int sci_getState()
{
	unsigned int state;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sci_getState: read SCTP-control failed");
		return CLOSED;
	}

	state = smctrl->association_state;

	switch (state)
	{
	case CLOSED:
		event_log(VVERBOSE, "Current state : CLOSED");
		break;
	case COOKIE_WAIT:
		event_log(VVERBOSE, "Current state :COOKIE_WAIT ");
		break;
	case COOKIE_ECHOED:
		event_log(VVERBOSE, "Current state : COOKIE_ECHOED");
		break;
	case ESTABLISHED:
		event_log(VVERBOSE, "Current state : ESTABLISHED");
		break;
	case SHUTDOWNPENDING:
		event_log(VVERBOSE, "Current state : SHUTDOWNPENDING");
		break;
	case SHUTDOWNRECEIVED:
		event_log(VVERBOSE, "Current state : SHUTDOWNRECEIVED");
		break;
	case SHUTDOWNSENT:
		event_log(VVERBOSE, "Current state : SHUTDOWNSENT");
		break;
	case SHUTDOWNACKSENT:
		event_log(VVERBOSE, "Current state : SHUTDOWNACKSENT");
		break;
	default:
		event_log(VVERBOSE, "Unknown state : return closed");
		return CLOSED;
		break;
	}

	return state;
	smctrl = NULL;
}

/*------------------- Functions called by reliable transfer --------------------------------------*/

/**
  Called by reliable transfer if all (sent !) chunks in its retransmission queue have been acked.
  This function is used to move from state SHUTDOWNPENDING to  SHUTDOWNSENT (after having sent a
  shutdown chunk) or to move from  SHUTDOWNRECEIVED to SHUTDOWNACKSENT (after having sent a
  shutdown-ack chunk)
  */
void sci_allChunksAcked()
{
	unsigned int state;
	ChunkID shutdownCID;
	ChunkID shutdownAckCID;
	smctrl_t *old_data = smctrl;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sci_allChunksAcked: read SCTP-control failed");
		return;
	}

	state = smctrl->association_state;

	switch (state)
	{
	case SHUTDOWNPENDING:

		event_log(EXTERNAL_EVENT, "event: sci_allChunksAcked in state SHUTDOWNPENDING");

		/* make and send shutdown */
		shutdownCID = ch_makeShutdown(rxc_read_cummulativeTSNacked());
		bu_put_Ctrl_Chunk(ch_chunkString(shutdownCID), NULL);
		bu_sendAllChunks(NULL);
		ch_deleteChunk(shutdownCID);

		/* start shutdown timer */
		smctrl->initTimerDuration = pm_readRTO(pm_readPrimaryPath());

		if (smctrl->initTimer != 0)
			sctp_stopTimer(smctrl->initTimer);

		smctrl->initTimer = adl_startTimer(smctrl->initTimerDuration,
			&msm_timer_expired, TIMER_TYPE_SHUTDOWN,
			(void *)&smctrl->associationID, NULL);

		smctrl->initRetransCounter = 0;

		/* receive control must acknowledge every datachunk at once after the shutdown
				   was sent. */
		rxc_send_sack_everytime();

		state = SHUTDOWNSENT;

		break;

	case SHUTDOWNRECEIVED:

		event_log(EXTERNAL_EVENT, "event: sci_allChunksAcked in state SHUTDOWNRECEIVED");

		/* send shutdownAck */
		shutdownAckCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_ACK, FLAG_NONE);
		bu_put_Ctrl_Chunk(ch_chunkString(shutdownAckCID), NULL);
		bu_sendAllChunks(NULL);
		ch_deleteChunk(shutdownAckCID);

		/* ADDED : should probably be OK */
		if (smctrl->initTimer != 0)
			sctp_stopTimer(smctrl->initTimer);

		smctrl->initTimer = adl_startTimer(smctrl->initTimerDuration, &msm_timer_expired, TIMER_TYPE_SHUTDOWN,
			(void *)&smctrl->associationID, NULL);

		state = SHUTDOWNACKSENT;
		break;

	default:
		/* error logging */
		event_logi(EXTERNAL_EVENT_X, "unexpected event: sci_allChunksAcked in state %d", state);
		break;
	}

	smctrl->association_state = state;
	smctrl = old_data;
}

/*------------------- Functions called message by distribution to create and delete --------------*/

/**
	newSCTP_control allocates data for a new SCTP-Control instance
	*/
void *msm_new(void *sctpInstance)
{
	smctrl_t *tmp = NULL;

	event_logi(INTERNAL_EVENT_0, "Create SCTP-control for Instance %x", sctpInstance);

	tmp = (smctrl_t *)malloc(sizeof(smctrl_t));

	if (tmp == NULL)
	{
		error_log(ERROR_MAJOR, " Malloc failed in msm_new()");
		return NULL;
	}

	tmp->association_state = CLOSED;
	tmp->initTimer = 0;
	tmp->initTimerDuration = RTO_INITIAL;
	tmp->initRetransCounter = 0;
	tmp->initChunk = NULL;
	tmp->peer_cookie_chunk = NULL;
	tmp->associationID = get_curr_channel_id();
	tmp->outbound_stream = mdi_readLocalOutStreams();
	tmp->inbound_stream = mdi_readLocalInStreams();
	tmp->local_tie_tag = 0;
	tmp->peer_tie_tag = 0;

	tmp->assocMaxRetransmissions = mdi_getDefaultAssocMaxRetransmits(sctpInstance);
	tmp->assocMaxInitRetransmissions = mdi_getDefaultMaxInitRetransmits(sctpInstance);
	tmp->cookieLifeTime = mdi_getDefaultValidCookieLife(sctpInstance);
	tmp->instance = sctpInstance;

	event_log(INTERNAL_EVENT_0, "event: created SCTP-control Instance");

	return (void *)tmp;
}

/**
  deleteSCTP_control frees memory allocated for a SCTP-Control instance
  */
void sci_deleteSCTP_control(void *sctpControlData)
{
	smctrl_t *sctpCD;

	event_log(INTERNAL_EVENT_0, "deleting SCTP-control");
	sctpCD = (smctrl_t *)sctpControlData;
	if (sctpCD->initTimer != 0)
	{
		sctp_stopTimer(sctpCD->initTimer);
	}
	if (sctpCD->initChunk != NULL)
		free(sctpCD->initChunk);
	if (sctpCD->peer_cookie_chunk != NULL)
		free(sctpCD->peer_cookie_chunk);
	free(sctpControlData);
}

/**
 * get current parameter value for assocMaxRetransmissions
 * @return current value, -1 on error
 */
int sci_getMaxAssocRetransmissions(void)
{
	smctrl_t *old_data = smctrl;
	int max;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sci_getMaxAssocRetransmissions(): read SCTP-control failed");
		smctrl = old_data;
		return -1;
	}
	max = smctrl->assocMaxRetransmissions;
	smctrl = old_data;
	return max;
}

/**
 * get current parameter value for assocMaxInitRetransmissions
 * @return current value, -1 on error
 */
int sci_getMaxInitRetransmissions(void)
{
	smctrl_t *old_data = smctrl;
	int max;
	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sci_getMaxInitRetransmissions(): read SCTP-control failed");
		smctrl = old_data;
		return -1;
	}
	max = smctrl->assocMaxInitRetransmissions;
	smctrl = old_data;
	return max;
}

/**
 * get current parameter value for cookieLifeTime
 * @return current value, -1 on error
 */
int sci_getCookieLifeTime(void)
{
	int max;
	smctrl_t *old_data = smctrl;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MINOR, "sci_getCookieLifeTime(): read SCTP-control failed");
		smctrl = old_data;
		return -1;
	}
	max = smctrl->cookieLifeTime;
	smctrl = old_data;
	return max;
}

/**
 * set new parameter value for assocMaxRetransmissions
 * @param new_max  new parameter value for assocMaxRetransmissions
 * @return 0 for success, -1 on error
 */
int sci_setMaxAssocRetransmissions(int new_max)
{
	smctrl_t *old_data = smctrl;
	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sci_setMaxAssocRetransmissions(): read SCTP-control failed");
		smctrl = old_data;
		return -1;
	}
	smctrl->assocMaxRetransmissions = new_max;
	smctrl = old_data;
	return 0;
}

/**
 * set new parameter value for assocMaxRetransmissions
 * @param new_max  new parameter value for assocMaxRetransmissions
 * @return 0 for success, -1 on error
 */
int sci_setMaxInitRetransmissions(int new_max)
{
	smctrl_t *old_data = smctrl;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sci_setMaxInitRetransmissions(): read SCTP-control failed");
		smctrl = old_data;
		return -1;
	}
	smctrl->assocMaxInitRetransmissions = new_max;
	smctrl = old_data;
	return 0;
}

/**
 * set new parameter value for cookieLifeTime
 * @param new_max  new parameter value for cookieLifeTime
 * @return 0 for success, -1 on error
 */
int sci_setCookieLifeTime(int new_max)
{
	smctrl_t *old_data = smctrl;

	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sci_setCookieLifeTime(): read SCTP-control failed");
		smctrl = old_data;
		return -1;
	}
	smctrl->cookieLifeTime = new_max;
	smctrl = old_data;
	return 0;
}

bool sci_shutdown_procedure_started()
{
	smctrl_t *old_data = smctrl;

	unsigned int state;
	if ((smctrl = (smctrl_t *)mdi_readSCTP_control()) == NULL)
	{
		/* error log */
		error_log(ERROR_MAJOR, "sci_readState : read SCTP-control failed");
		smctrl = old_data;
		return FALSE;
	}
	state = smctrl->association_state;
	smctrl = old_data;

	if (state == SHUTDOWNPENDING || state == SHUTDOWNRECEIVED || state == SHUTDOWNSENT || state == SHUTDOWNACKSENT)
		return TRUE;
	else
		return FALSE;
}

/*@}*/