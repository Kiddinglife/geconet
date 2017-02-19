/* $Id: pathmanagement.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef PATHMANAGEMENT_H
#define PATHMANAGEMENT_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif


/* The states of pathmanagement, also used for network status change */
#define  PM_ACTIVE              0
#define  PM_INACTIVE            1
#define  PM_ADDED               2
#define  PM_REMOVED             3

#define  PM_PATH_UNCONFIRMED    5


#define PM_INITIAL_HB_INTERVAL  30000


/******************** Functions to answer peer HB requests ****************************************/
/**
 * Function is called to perform a on demand HB on a certain path
 */
int pm_doHB(gshort pathID);


/* pm_heartbeat is called when a heartbeat was received from the peer.
   params: heartbeatChunk: the heartbeat chunk
*/
void pm_heartbeat(SCTP_heartbeat * heartbeatChunk, unsigned int source_address);


/******************** Signals *********************************************************************/

/*------------------- Signals from the Unix-Interface --------------------------------------------*/

/* pm_heartbeatTimer is called by the adaption-layer when the heartbeat timer expires.
   params: timerID:            ID of timer
           associationIDvoid:  pointer to the association-ID
           pathIDvoid:         pointer to the path-ID
*/
void pm_heartbeatTimer(TimerID timerID, void *associationIDvoid, void *pathIDvoid);



/* pm_heartbeatAck is called when a heartbeat acknowledgement was received from the peer.
   params: heartbeatChunk: the heartbeat chunk
*/
void pm_heartbeatAck(SCTP_heartbeat * heartbeatChunk);

/*------------------- Signals from SCTP internal modules -----------------------------------------*/

/* pm_chunksAcked is called by reliable transfer whenever chunks have been acknowledged. 
   Params: pathID:      path-ID
           newRTO:      the newly determined RTO in milliseconds
                        newRTO = 0 ==> no RTO measurements done
*/
void pm_chunksAcked(short pathID, unsigned int newRTO);

/**
 * function to be called every time we send data to a path
 * to keep it from becoming "idle"
 */
void pm_chunksSentOn(short pathID);


/* pm_chunksRetransmitted is called by reliable transfer whenever chunks have been 
   retransmitted.
   Params: pathID:      path-ID 
*/
gboolean pm_chunksRetransmitted(short pathID);



/* pm_rto_backoff is called by reliable transfer when the T3 retransmission timer expires.
   Each call of this function doubles the RTO (timer back off).
   Params: pathID:      path-ID 
*/
void pm_rto_backoff(short pathID);

/*------------------- Helper Function  ----------------------------------------------------------*/

unsigned int pm_getTime(void);


/*------------------- Functions called by the ULP ------------------------------------------------*/


/* pm_enableHB is called when ULP wants to enable heartbeat.
*/
int pm_enableHB(short pathID, unsigned int hearbeatIntervall);



/* pm_disableAllHB is called when on shutdown to disable all heartbeats.
*/
void pm_disableAllHB(void);



/* pm_disableHB is called when ULP wants to disable heartbeat.
*/
int pm_disableHB(short pathID);




/* pm_setPrimaryPath sets the primary path.
   Params: primaryPathID:      path-ID
*/
short pm_setPrimaryPath(short pathID);

int  pm_getMaxPathRetransmisions(void);

int  pm_setRtoInitial(int new_rto_initial);

int  pm_getRtoInitial(void);


int  pm_setRtoMin(int new_rto_min);

int  pm_getRtoMin(void);

int  pm_setRtoMax(int new_rto_max);

int  pm_getRtoMax(void);

int  pm_setHBInterval(unsigned int new_interval);

int pm_getHBInterval(short pathID, unsigned int* current_interval);


int  pm_setMaxPathRetransmisions(int new_max);

/*------------------- Functions called by ULP to read pathmanagement state info ------------------*/


/**
 * pm_readRTO returns the currently set RTO value in msecs for a certain path.
 * @param     pathID      index of the address/path
 * @return                path's current RTO in msecs
*/
unsigned int pm_readRTO(short pathID);



/* pm_readSRTT is called by reliable transfer and sctp-control to adjust T3-timeout and
   init-timeout, respectively.
   Params: pathID:      path-ID 
           returns:     current smoothed round trip time or 0xffffffff on error
*/
unsigned int pm_readSRTT(short pathID);


unsigned int pm_readRttVar(short pathID);


/**
 * pm_readState returns the current state of the path.
 * @params pathID      index of the path that is checked for its state
 * @return  state value for this path (PM_ACTIVE, PM_INACTIVE, PM_PATH_UNCONFIRMED)
 */
short pm_readState(short pathID);



/* pm_readPrimaryPath returns the primary path.
   Params: returns      primary path, or 0xFFFF as error
*/
unsigned short pm_readPrimaryPath(void);



/*------------------- Functions called to create, init and delete pathman-instances --------------*/

/* pm_setPaths modufies number of paths and sets the primary path.
   This is required for association setup, where the local ULP provides
   only one path and the peer may provide additional paths.
   This function also initializes the path structures and starts the heartbeat timer for each
   path. For this reason it is recommended to call this function when communication up is called.
   Params: primaryPathID:      path-ID
           noOfPaths           number of paths
*/
short pm_setPaths(short noOfPaths, short primaryPathID);



/* pm_newPathman creates a new instance of pathmanagement. There is one pathmanagement instance
   par association.
   params: numberOfPaths:    # of paths of the association.
           primaryPath:      initial primary path.
*/
void *pm_newPathman(short numberOfPaths, short primaryPath, void* sctpInstance);



/* Deletes the instance pointed to by pathmanPtr.
*/
void pm_deletePathman(void *pathmanPtr);



#endif
