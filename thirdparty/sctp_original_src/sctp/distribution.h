/* $Id: distribution.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef DISTRIBUTION_H
#define DISTRIBUTION_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include  "globals.h"           /* for public association data structure */
#include  "messages.h"

/* define some important constants */
#define ASSOCIATION_MAX_RETRANS 10
#define MAX_INIT_RETRANSMITS    8
#define MAX_PATH_RETRANSMITS    5
#define VALID_COOKIE_LIFE_TIME  10000
/*
#define RWND_CONST              64000
*/
#define SACK_DELAY              200
#define RTO_INITIAL             3000
#define IPTOS_DEFAULT           0x10    /* IPTOS_LOWDELAY */
#define RTO_MIN                 1000
#define DEFAULT_MAX_SENDQUEUE   0       /* unlimited send queue */
#define DEFAULT_MAX_RECVQUEUE   0       /* unlimited recv queue - unused really */
#define DEFAULT_MAX_BURST       4       /* maximum burst parameter */
#define RTO_MAX                 60000


/******************** Function Definitions ********************************************************/

/*------------------- Functions called by the ULP ------------------------------------------------*/

/* This functions are defined in a seperate header file sctp.h in order to seperate the interface to
   the ULP and the interface to other modules within SCTP.
*/

/*------------------- Functions called by the Unix-Interface -------------------------------------*/

/**
 * \fn mdi_receiveMessage
 *  mdi_receiveMessage is the callback function of the SCTP-message distribution.
 *  It is called by the Unix-interface module when a new datagramm is received.
 *  This function also performs OOTB handling, tag verification etc.
 *  (see also RFC 4960, section 8.5.1.B)  and sends data to the bundling module of
 *  the right association
 *
 *  @param socket_fd          the socket file discriptor
 *  @param buffer             pointer to arrived datagram
 *  @param bufferlength       length of datagramm
 *  @param fromAddress        source address of DG
 *  @param portnum            bogus port number
 */
void mdi_receiveMessage(gint socket_fd, unsigned char *buffer,
                   int bufferLength, union sockunion * source_addr,
                   union sockunion * dest_addr);

/*------------------- Functions called by the SCTP bundling --------------------------------------*/

/* Used by bundling to send a SCTP-daatagramm. 
   Before calling send_message at the adaption-layer, this function does:
   - add the SCTP common header to the message
   - convert the SCTP message to a byte string
   - retrieve the socket-file descriptor of the SCTP-instance
   - retrieve the destination address
   @param SCTP_message     SCTP message (UDP-datapart) as a struct
   @param length           length of SCTP message.
   @param destAddresIndex  Index of address in the destination address list.
   @return                 Errorcode.
*/

int mdi_send_message(SCTP_message * message, unsigned int length, short destAddressIndex);



/*------------------- Functions called by the SCTP to forward primitives to ULP ------------------*/


/**
 *  indicates new data (i.e. length bytes) have arrived from peer (chapter 10.2.A).
 *  @param streamID    data has arrived for this stream
 *  @param length       number of bytes thet have arrived
 *  @param  unordered  unordered flag (TRUE==1==unordered, FALSE==0==normal,numbered chunk)
 */
void mdi_dataArriveNotif(unsigned short streamID, unsigned int length, unsigned short streamSN,
                         unsigned int tsn, unsigned int protoID, unsigned int unordered);



/* indicates a change of network status (chapter 10.2.C).
   params: 1.  destinationAddresses
           2.  newState 
*/
void mdi_networkStatusChangeNotif(short destinationAddress, unsigned short newState);


/**
 * indicates a send failure (chapter 10.2.B).
 *  params: pointer to data not sent
 *          dataLength
 *          context from sendChunk
 */
void mdi_sendFailureNotif(unsigned char *data, unsigned int dataLength, unsigned int *context);



/**
 * indicates that communication was lost to peer (chapter 10.2.E).
 *  params: status, type of event
 */
void mdi_communicationLostNotif(unsigned short status);

/*
 * indicates that peer wished to shutdown this assoc
 */
void mdi_peerShutdownReceivedNotif(void);

/*
 *indicates that communication has been gracefully terminated (10.2.H).
 */
void mdi_shutdownCompleteNotif(void);

/* indicates that a restart has occured (10.2.G.) */
void mdi_restartNotif(void);



/* indicates that a association is established (chapter 10.2.D).
   params: status, type of event
*/
void mdi_communicationUpNotif(unsigned short status);

/**
 * Function that notifies the ULP of a change in the queue status.
 * I.e. a limit may be exceeded, and therefore subsequent send-primitives will
 * fail, OR the queue length has dropped below a previously set queue length
 *
 * @param  queueType i.e. an outbound queue, stream-engine queue, per stream queue (?)
 * @param  queueId   i.e. i.e. stream id for a per stream queue
 * @param  queueLen  in bytes or in messages, depending on the queue type
 */
void mdi_queueStatusChangeNotif(int queueType, int queueId, int queueLen);


int mdi_updateMyAddressList(void);


/*------------------- Functions called by the SCTP to get current association data----------------*/

/* When processing external events from outside the SCTP (socket events, timer events and 
   function calls from the ULP), first the data of the addressed association are read
   from the list of associations and stored in a private but static datastructure.
   Elements of this association data can be read by the following functions.
*/


/* The following functions return pointer to data of modules of the SCTP. As only these
   modules know the exact type of these data structures, so the returned pointer are
   of type void.
*/


/* The following functions return pointer to data of modules of the SCTP. As only these
   modules know the exact type of these data structures, so the returned pointer are
   of type void.
*/

/*
 * returns: pointer to the flow control data structure.
 *          null in case of error.
 */
void *mdi_readFlowControl(void);



/*
 * returns: pointer to the reliable transfer data structure.
 *          null in case of error.
 */
void *mdi_readReliableTransfer(void);



/*
 * returns: pointer to the RX-control data structure.
 *          null in case of error.
 */
void *mdi_readRX_control(void);



/*
 * returns: pointer to the stream engine data structure.
 *          null in case of error.
 */
void *mdi_readStreamEngine(void);



/*
 * returns: pointer to the pathmanagement data structure.
 *          null in case of error.
 */
void *mdi_readPathMan(void);



/*
 * returns: pointer to the bundling data structure.
 *          null in case of error.
 */
void *mdi_readBundling(void);



/*
 * returns: pointer to the SCTP-control data structure.
 *          null in case of error.
 */
void *mdi_readSCTP_control(void);



/* 
 * returns: association-ID of the curent association
 *          0 means the association is not set (an error).
 */
unsigned int mdi_readAssociationID(void);



/* returns: a ID  for new association */
unsigned int mdi_generateTag(void);



unsigned int mdi_readTagRemote(void);
unsigned int mdi_readLocalTag(void);



/* returns: a the start TSN for new association */
unsigned int mdi_generateStartTSN(void);



/*------------- functions to for the cookie mechanism --------------------------------------------*/
/* each time a datagram is received, its source address, source port and destination port
   is saved. This address-info is used in the following cases:
   - z-side: for sending the initAck (no association exists from which the addresses could be read).
   - a-side: if the initAck  ??
   - z-side: if the cookie-chunk does not contain addresses of the a-side, lastFromAddress_in
             is used as the only destination address.
*/

gboolean mdi_addressListContainsLocalhost(unsigned int noOfAddresses,
                           union sockunion* addressList);


/* sets the address from which the last datagramm was received (host byte order).
    Returns 0 if successful, 1 if address could not be set !
*/
int mdi_readLastFromAddress(union sockunion* fromAddress);


/* reads the path from which the last DG was received. -1 is returned if no DG was received.
*/
short mdi_readLastFromPath(void);


/* returns the port of the sender of the last received DG.
*/
unsigned short mdi_readLastFromPort(void);


/* returns the port of the destination of the last received DG.
*/
unsigned short mdi_readLastDestPort(void);


unsigned int mdi_readLastInitiateTag(void);
/* write the initiate tag of a-side to be used as verification tag for the initAck */
void mdi_writeLastInitiateTag(unsigned int initiateTag);


/* rewrite the initiate tag of peer in case of a peer restart. */
void mdi_rewriteTagRemote(unsigned int newInitiateTag);

/* rewrite my local tag in case of a restart. */
void mdi_rewriteLocalTag(unsigned int newTag);

/**
 * Function that returns the number of incoming streams that this instance
 * is willing to handle !
 * @return maximum number of in-streams
 */
unsigned short mdi_readLocalInStreams(void);

/**
 * Function that returns the number of outgoing streams that this instance
 * is willing to handle !
 * @return maximum number of out-streams
 */
unsigned short mdi_readLocalOutStreams(void);

int mdi_getDefaultRtoInitial(void* sctpInstance);
int mdi_getDefaultValidCookieLife(void* sctpInstance);
int mdi_getDefaultAssocMaxRetransmits(void* sctpInstance);
int mdi_getDefaultPathMaxRetransmits(void* sctpInstance);
int mdi_getDefaultRtoMin(void* sctpInstance);
int mdi_getDefaultRtoMax(void* sctpInstance);
int mdi_getDefaultMaxInitRetransmits(void* sctpInstance);
int mdi_getDefaultMyRwnd(void);
int mdi_getDefaultDelay(void* sctpInstance);
int mdi_getDefaultIpTos(void* sctpInstance);
int mdi_getDefaultMaxSendQueue(void* sctpInstance);
int mdi_getDefaultMaxRecvQueue(void* sctpInstance);
int mdi_getDefaultMaxBurst(void);
	
unsigned int mdi_getSupportedAddressTypes(void);

gboolean mdi_supportsPRSCTP(void);
gboolean mdi_peerSupportsPRSCTP(void);
/*------------- functions to write and read addresses --------------------------------------------*/

void mdi_writeDestinationAddresses(union sockunion addresses[MAX_NUM_ADDRESSES], int noOfAddresses);

void mdi_readLocalAddresses(union sockunion laddresses[MAX_NUM_ADDRESSES],
                            guint16 * noOfAddresses,
                            union sockunion *peerAddress,
                            unsigned int numPeerAddresses,
                            unsigned int addressTypes,
                            gboolean receivedFromPeer);

short mdi_getIndexForAddress(union sockunion* address);

/*------------- functions to set and clear the association data ----------------------------------*/

/* Each module within SCTP that has timers implements its own timer call back
   functions. These are registered at the adaption layer when a timer is started
   and called directly at the module when the timer expires.
   setAssociation allows SCTP-modules with timers to retrieve the data of the 
   addressed association from the list of associations.
   For this purpose the association-ID must be included in one of the 
   parameters of the start_timer function of the adaption-layer.
   Params:  associationID: the ID of the association
   returns: 0 if successfull
            1 if the association does not exist in the list.
*/
unsigned short mdi_setAssociationData(unsigned int associationID);



/* Clear the global association data.
   This function must be called after the association retrieved from the list
   with setAssociationData is no longer needed. This is the case after a timer
   event has been handled.
   returns:  0 if successful.
             1 if association data have not been set.
*/
unsigned short mdi_clearAssociationData(void);


/*------------------- Functions to create and delete associations --------------------------------*/

/* This function allocates memory for a new association.
   For the active side of an association, this function is called when the associate is called from 
   the ULP.
   For the passive side this function is called when a cookie message is received.
   It also creates all the modules of an association supplying to them the data needed as far they
   they are determined at time the this module is called.
   
   If successfull, the global variable current_association points to the association structure
   created. 
*/
unsigned short mdi_newAssociation(void*  sInstance,
                                  unsigned short local_port,
                                  unsigned short remote_port,
                                  unsigned int tagLocal,
                                  short primaryDestinitionAddress,
                                  short noOfDestinationAddresses,
                                  union sockunion *destinationAddressList);



/* An association is created in two steps because data become available in two steps:
   1. associate
   2. init acknowledgement
   after calling this function, the initialisation is completed.
*/
unsigned short
mdi_initAssociation(unsigned int remoteSideReceiverWindow,
                    unsigned short noOfInStreams,
                    unsigned short noOfOutStreams,
                    unsigned int remoteInitialTSN,
                    unsigned int tagRemote, unsigned int localInitialTSN,
                    gboolean assocSupportsPRSCTP, gboolean assocSupportsADDIP);


unsigned short
mdi_restartAssociation(unsigned short noOfInStreams,
                    unsigned short noOfOutStreams,
                    unsigned int new_rwnd,
                    unsigned int remoteInitialTSN,
                    unsigned int localInitialTSN,
                    short  noOfPaths,
                    short primaryAddress,
                    union sockunion *destinationAddressList,
                    gboolean assocSupportsPRSCTP, gboolean assocSupportsADDIP);



void mdi_deleteCurrentAssociation(void);



#endif
