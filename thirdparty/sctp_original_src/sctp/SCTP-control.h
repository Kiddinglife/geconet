/* $Id: SCTP-control.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef SCTP_CONTROL_H
#define SCTP_CONTROL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "globals.h"
#include "messages.h"
#include "sctp.h"

/* The states of SCTP-control */
#define CLOSED           SCTP_CLOSED
#define COOKIE_WAIT      SCTP_COOKIE_WAIT
#define COOKIE_ECHOED    SCTP_COOKIE_ECHOED
#define ESTABLISHED      SCTP_ESTABLISHED
#define SHUTDOWNPENDING  SCTP_SHUTDOWN_PENDING
#define SHUTDOWNRECEIVED SCTP_SHUTDOWN_RECEIVED
#define SHUTDOWNSENT     SCTP_SHUTDOWN_SENT
#define SHUTDOWNACKSENT  SCTP_SHUTDOWNACK_SENT

/* Return codes for a number of functions that treat incoming chunks */
/* these are used in the rbundling module !                          */
#define STATE_STOP_PARSING_REMOVED  -1
#define STATE_OK                     0
#define STATE_STOP_PARSING           1

/******************** Function Definitions ********************************************************/

/*------------------- Functions called by adaption layer -----------------------------------------*/

/* The timercallback function is only defined and implemented in SCTP-control.c */

/*------------------- Functions called by the ULP via message-distribution -----------------------*/

/* This function is called to initiate the setup an association.
   The local tag and the initial TSN are randomly generated.
   Together with the parameters of the function, they are used to create the init-message.
   This data are also stored in a newly created association-record.
   Params: noOfOutStreams:              # of send streams.
           noOfInStreams:               # of receive streams.
           primaryDestinationAddress:   primary destination address, the init message is sent to this
                                        address.
           noOfDestinationAddresses:    # of destination addresses if multihoming is used
           DestinationAddressList:      list destination addresses if multihoming is used
*/
void scu_associate(unsigned short noOfOutStreams,
                   unsigned short noOfInStreams,
                   union sockunion* destinationList,
                   unsigned int numDestAddresses,
                   gboolean withPRSCTP);


/* initiates the shutdown of this association.
*/
void scu_shutdown(void);



/* aborts this association.
*/
void scu_abort(short error_type, unsigned short error_param_length, unsigned char* error_param_data);



/*------------------- Functions called by the (de-)bundling for recieved control chunks ----------*/

/* sctlr_init is called by bundling when a init message is received from the peer.
   New data must not be allocated for this new association.
   The following data are created and included in the init acknowledgement:
   - cookie: contains init-data, local tag, initial TSN, # of send streams, # of receive streams
     and a signature.
   - local tag: randomly generated, is included in the cookie and the initiate tag field of the
                init acknowledgement.
   - inititial TSN: randomly generated, is included in the cookie and the initial TSN field of the
                    init acknowledgement.
   Params: init:    data of init-chunk including optional parameters without chunk header
*/
int sctlr_init(SCTP_init * init);



/* sctlr_initAck is called by bundling when a init acknowledgement was received from the peer.
   The following data are retrieved from the init-data and saved for this association:
   - remote tag from the initiate tag field
   - receiver window credit of the peer
   - # of send streams of the peer, must be lower or equal the # of receive streams this host
     has 'announced' with the init-chunk.
   - # of receive streams the peer allows the receiver of this initAck to use.

   The initAck must contain a cookie which is returned to the peer with the cookie acknowledgement.

   Params: initAck: data of initAck-chunk including optional parameters without chunk header
*/
int sctlr_initAck(SCTP_init * initAck);



/* sctlr_cookie_echo is called by bundling when a cookie chunk was received from  the peer.
   The following data are retrieved from the cookie and saved for this association:
   - from the init chunk: + peers tag.
                          + peers receiver window credit.
                          + peers initial TSN.
                          + peers network address list if multihoming is used.
   - local tag generated before the initAck was sent.
   - this side initial TSN generated before the initAck was sent.
   - # of send streams this side uses, must be lower or equal to peers # of receive streams from init
     chunk
   - # of receive streams this side uses, can be lower than peers # of send streams the requested in
     the init chunk.
*/
void sctlr_cookie_echo(SCTP_cookie_echo * cookie);



/* sctlr_cookieAck is called by bundling when a cookieAck chunk was received from  the peer.
   The only purpose is to inform the active side that peer has received the cookie chunk.
   The association is established after this function is called.
   StartOfDataTX is called at Flowcontrol to start transmission of data chunks.
   The ULP is informed by the communication up notification.
*/
void sctlr_cookieAck(SCTP_simple_chunk * cookieAck);



/* sctlr_shutdown is called by bundling when a shutdown chunk was received from  the peer.
   The function initiates a gracefull shutdown of the association.
   Params: cumulativeTSN_ack: highest consecutive TSN acked.
*/
int sctlr_shutdown(SCTP_simple_chunk * shutdown_chunk);



/* sctlr_shutdownAck is called by bundling when a shutdownAck chunk was received from  the peer.
   The function initiates a gracefull shutdown of the association.
*/
int sctlr_shutdownAck(void);

/* sctlr_shutdownComplete is called by bundling when a shutdownComplete chunk was received from the peer.
*/
int sctlr_shutdownComplete(void);

/* sctlr_abort is called by bundling when a abort chunk was received from  the peer.
   The association is terminated imediately.
*/
int sctlr_abort(void);



/* sctlr_staleCookie is called by bundling when a error chunk with cause 'stale cookie'
   was received from  the peer.
   Params: staleness: microseconds the cookie life time was exceeded.
*/
void sctlr_staleCookie(SCTP_simple_chunk * error_chunk);



/*------------------- Functions called by reliable transfer --------------------------------------*/

/* This function is called by reliable transfer if all sent chunks in its retransmission queue have
   been acked.
*/
void sci_allChunksAcked(void);



/*------------------- Functions called message by distribution to create and delete --------------*/

/* newSCTP_control allocates data for a new SCTP-Control instance
*/
void *sci_newSCTP_control(void* sctpInstance);



/* deleteSCTP_control allocates data for a new SCTP-Control instance
*/
void sci_deleteSCTP_control(void *sctpControlData);

/**
 * function returns the state of the current SCTP instance
 */
guint32 sci_getState(void);


int sci_getMaxAssocRetransmissions(void);

int sci_getMaxInitRetransmissions(void);

int sci_getCookieLifeTime(void);

int sci_setMaxAssocRetransmissions(int new_max);

int sci_setMaxInitRetransmissions(int new_max);

int sci_setCookieLifeTime(int new_max);

/**
 * function returns true if state of the association
 * is in the SHUTDOWNs, else FALSE
 */

gboolean sci_shutdown_procedure_started(void);

#endif
