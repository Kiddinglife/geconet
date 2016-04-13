/*
 *  $Id$
 *
 * SCTP implementation according to RFC 4960.
 * Copyright (C) 2000 by Siemens AG, Munich, Germany.
 *
 * Realized in co-operation between Siemens AG
 * and University of Essen, Institute of Computer Networking Technology.
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
 * Contact: discussion@sctp.de
 *          tuexen@fh-muenster.de
 *          ajung@iem.uni-due.de
 *
 * Purpose: Implements a few simple callback-functions for an "ULP"
 */

#ifndef MINI_ULP_H
#define MINI_ULP_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <glib.h>
#include "sctp.h"

#ifdef SOLARIS
#define timersub(tvp, uvp, vvp)                                     \
        do {                                                        \
            (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
            (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
            if ((vvp)->tv_usec < 0) {                               \
                (vvp)->tv_sec--;                                    \
               (vvp)->tv_usec += 1000000;                           \
           }                                                        \
        } while (0)
#endif



void ulp_getEndEvents(unsigned int shutdownAfter, unsigned int abortAfter);
void mulp_dosend(void);
void mulp_heartbeat(unsigned int interval);
void ulp_setChunkLength(int chunkLength);
void mulp_streamRoundRobin(void);

/* function to handle typed user commands */
/* FOR THE BAKEOFF */
void
ulp_stdin_cb(int fd, short int revents, short int* gotEvents, void * dummy);

void
ulp_socket_error(gint sin_fd,
                 unsigned char *buffer,
                 int bufferLength, unsigned char fromAddress[], unsigned short pn);


/*  indicates new data have arrived from peer (chapter 10.2.A).
      params: 1. associationID
              2. streamID
*/
void ulp_dataArriveNotif(unsigned int assoc_id, unsigned short stream_id, unsigned int len,
                        unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                        unsigned int unordered, void* dummy);

/* indicates a change of network status (chapter 10.2.C).
   params: 1.  associationID
           2.  destinationAddresses
	       3.  newState
*/
void ulp_networkStatusChangeNotif(unsigned int assoc_id, short dest_add, unsigned short new_state, void* dummy);

/* indicates a sned failure (chapter 10.2.B).
   params: 1.  associationID
           2.  pointer to data not sent
           3.  dataLength
           4.  context from sendChunk
*/
void ulp_sendFailureNotif(unsigned int assoc_id,
                          unsigned char *unsent_data, unsigned int data_len, unsigned int *context, void* dummy);


/* indicates that communication was lost to peer (chapter 10.2.E).
   params: 1.  associationID
           2.  status, type of event
*/
void ulp_communicationLostNotif(unsigned int assoc_id, unsigned short status, void* dummy);

/* indicates that a association is established (chapter 10.2.D).
   params: 1.  associationID
           2.  status, type of event
*/
void* ulp_communicationUpNotif(unsigned int assoc_id, int status,
                              unsigned int noOfDestinations,
                              unsigned short noOfInStreams, unsigned short noOfOutStreams,
                              int associationSupportsPRSCTP, void* dummy);

/* indicates that association has been gracefully shutdown (chapter 10.2.H).
   params: 1.  associationID
*/
void ulp_ShutdownCompleteNotif(unsigned int assoc_id, void* dummy);


#endif
