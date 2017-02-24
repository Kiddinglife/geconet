/* $Id: chunkHandler.h 2771 2013-05-30 09:09:07Z dreibh $
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

#include "messages.h"

typedef short ChunkID;

/******************************* external functions ***********************************************/

/******create, write into and read from init and initAck ******************************************/

/* ch_makeInit makes an init and initializes the the fixed part of init */
ChunkID ch_makeInit(unsigned int initTag,
                    unsigned int rwnd,
                    unsigned short noOutStreams,
                    unsigned short noInStreams, unsigned int initialTSN);



/* ch_makeInitAck makes an initAck and initializes the the fixed part of initAck */
ChunkID ch_makeInitAck(unsigned int initTag,
                       unsigned int rwnd,
                       unsigned short noOutStreams,
                       unsigned short noInStreams, unsigned int initialTSN);


/* function to add supported address types variable parameter */
void ch_enterSupportedAddressTypes(ChunkID chunkID, gboolean with_ipv4,
                                   gboolean with_ipv6, gboolean with_dns);

unsigned int ch_getSupportedAddressTypes(ChunkID chunkID);


/* ch_enterCookiePreservative enters a cookie preservative with the suggested cookie lifespan 
   into an init chunk.
*/
void ch_enterCookiePreservative(ChunkID chunkID, unsigned int lifespanIncrement);



/* ch_enterIPaddresses enters local IP-addresses to an init or initAck */
int ch_enterIPaddresses(ChunkID chunkID, union sockunion sock_addresses[], int noOfAddresses);



/* ch_enterCookieVLP enters the variable length params of cookie into an initAck */
int ch_enterCookieVLP(ChunkID initCID, ChunkID initAckID,
                  SCTP_init_fixed * init_fixed,
                  SCTP_init_fixed * initAck_fixed,
                  guint32 cookieLifetime,
                  guint32 local_tie_tag,
                  guint32 peer_tie_tag,
                  union sockunion local_Addresses[],
                  guint16 num_local_Addresses,
                  union sockunion peer_Addresses[], guint16 num_peer_Addresses);

/*
 * ch_enterUnrecognizedParameters enters unrecognized params from Init into initAck chunk
 * that is returned then. Returns -1 if unrecognized chunk forces termination of chunk parsing
 * without any further action, 1 for an error that stops chunk parsing, but returns error to
 * the peer and 0 for normal continuation
 */
int ch_enterUnrecognizedParameters(ChunkID initCID,ChunkID AckCID, unsigned int supportedAddressTypes);

/*
 * ch_enterUnrecognizedErrors enters unrecognized params from InitAck into an Error chunk
 * that will be appended to an CookieEcho. Iff an error chunk was created, error not will be
 * zero, else will be a new chunk id.
 * Returns -1 if unrecognized chunk forces termination of chunk parsing
 * without any further action, 1 for an error that stops chunk parsing, but returns error to
 * the peer and 0 for normal continuation
 */
int ch_enterUnrecognizedErrors(ChunkID initAckID,
                               unsigned int supportedTypes,
                               ChunkID *errorchunk,
                               union sockunion* preferredDest,
                               gboolean* destSet,
                               gboolean* peerSupportsIPV4,
                               gboolean* peerSupportsIPV6,
                               gboolean* peerSupportsPRSCTP,
                               gboolean* peerSupportsADDIP);

/* ch_initiateTag reads the initiate tag from an init or initAck */
unsigned int ch_initiateTag(ChunkID chunkID);



/* ch_receiverWindow reads the remote receiver window from an init or initAck */
unsigned int ch_receiverWindow(ChunkID chunkID);



/* ch_initialTSN reads the initial TSN from an init or initAck */
unsigned int ch_initialTSN(ChunkID chunkID);



/* ch_noOutStreams reads the number of output streams from an init or initAck */
unsigned short ch_noOutStreams(ChunkID chunkID);



/* ch_noInStreams reads the number of input streams from an init or initAck */
unsigned short ch_noInStreams(ChunkID chunkID);



/* ch_cookiePreservative returns the suggested cookie lifespan increment if a cookie 
   preservative is present in a init chunk.
*/
unsigned int ch_cookieLifeTime(ChunkID chunkID);


/**
 * functions read peer/local tie tag from a received cookie echo chunk
 */
guint32 ch_CookieLocalTieTag(ChunkID chunkID);
guint32 ch_CookiePeerTieTag(ChunkID chunkID);

/**
 * functions read src/dest port from a received cookie echo chunk
 */
guint16 ch_CookieDestPort(ChunkID chunkID);
guint16 ch_CookieSrcPort(ChunkID chunkID);


/* ch_IPaddresses reads the IP-addresses from an init or initAck */
int ch_IPaddresses(ChunkID chunkID, unsigned int mySupportedTypes, union sockunion addresses[],
                    unsigned int *supportedTypes, union sockunion* lastSource);



/* ch_cookieParam reads the cookie from an initAck */
SCTP_cookie_param *ch_cookieParam(ChunkID chunkID);



/* ch_initFixed reads the fixed part from an init or initAck as complete structure */
SCTP_init_fixed *ch_initFixed(ChunkID chunkID);



/****** create and read from cookie chunk *********************************************************/

/**
 * ch_makeCookie creates a cookie chunk.
 */
ChunkID ch_makeCookie(SCTP_cookie_param * cookieParam);



/**
 *  ch_cookieInitFixed creates an init chunk from the fixed part of an init contained in a cookie
 *  and returns its chunkID
 */
ChunkID ch_cookieInitFixed(ChunkID chunkID);



/* ch_cookieInitAckFixed creates an initAck chunk from the fixed part of an initAck contained in a 
   cookie and returns its chunkID */
ChunkID ch_cookieInitAckFixed(ChunkID chunkID);



/* ch_cookieIPaddresses reads the IP-addresses from a cookie */
int ch_cookieIPDestAddresses(ChunkID chunkID, unsigned int mySupportedTypes,
                             union sockunion addresses[],
                             unsigned int *peerSupportedAddressTypes,
                             union sockunion* lastSource);



/* ch_staleCookie checks if this is a stale cookie and returns 0 if not and staleness
   in msecs if it is. */
unsigned int ch_staleCookie(ChunkID chunkID);



/* check if this is a good cookie */
boolean ch_goodCookie(ChunkID chunkID);



/****** create and read from heartbeat chunk ******************************************************/

/* ch_makeHeartbeat creates a heartbeatchunk.
*/
ChunkID ch_makeHeartbeat(unsigned int sendingTime, unsigned int pathID);

/**
 * ch_verifyHeartbeat checks the signature of the received heartbeat.
 * @return TRUE, if HB signature was okay, else FALSE
 */
gboolean ch_verifyHeartbeat(ChunkID chunkID);


/* ch_HBsendingTime reads the sending time of a heartbeat.
*/
unsigned int ch_HBsendingTime(ChunkID chunkID);



/* ch_HBpathID reads the path heartbeat on which the heartbeat was sent.
*/
unsigned int ch_HBpathID(ChunkID chunkID);



/***** create simple chunk **********************************************************************/

/* ch_makeSimpleChunk creates a simple chunk. It can be used for parameterless chunks like
   abort, cookieAck and shutdownAck.
*/
ChunkID ch_makeSimpleChunk(unsigned char chunkType, unsigned char flag);

void
ch_addParameterToInitChunk(ChunkID initChunkID, unsigned short pCode,
                       unsigned short dataLength, unsigned char* data);

/* returns -1 if peer does not support PRSCTP, else 0 if it does, but doesn't use it
   returns > 0 if peer has unreliable streams set */
gboolean ch_getPRSCTPfromInitAck(ChunkID initAckCID);
/* returns -1 if peer does not support PRSCTP, else 0 if it does, but doesn't use it
   returns > 0 if peer has unreliable streams set */
gboolean ch_getPRSCTPfromCookie(ChunkID cookieCID);

/***** write to and read from error chunk *******************************************************/

ChunkID ch_makeErrorChunk(void);

/* adds a VLP to an error chunk. may also be zero length (i.e. no) VLP */
void ch_enterErrorCauseData(ChunkID chunkID, unsigned short code,
                       unsigned short length, unsigned char* data);

/* enters the staleness of a cookie into an error chunk. */
void ch_enterStaleCookieError(ChunkID chunkID, unsigned int staleness);



unsigned int ch_stalenessOfCookieError(ChunkID chunkID);



/***** create and read from shutdown chunk ******************************************************/

/* Creates a shutdown chunk.
*/
ChunkID ch_makeShutdown(unsigned int _cummTSNacked);



/* reads the cummulative TSN acked from a shutdown chunk.
*/
unsigned int ch_cummulativeTSNacked(ChunkID chunkID);



/****** read, make and delete generic chunk *******************************************************/

/* reads the chunks type of a chunk.
*/
unsigned char ch_chunkType(ChunkID chunkID);



/* reads the chunks length of a chunks.
*/
unsigned short ch_chunkLength(ChunkID chunkID);



/* returns a pointer to the beginning of a simple chunk.
*/
SCTP_simple_chunk *ch_chunkString(ChunkID chunkID);



/* ch_makeChunk makes a chunk from a simple chunk, which is nearly a byte string */
ChunkID ch_makeChunk(SCTP_simple_chunk * chunk);



/* ch_deleteChunk removes the chunk from the array of chunks and frees the
   memory allocated for that chunk.
*/
void ch_deleteChunk(ChunkID chunkID);



/* ch_forgetChunk removes the chunk from the array of chunks without freeing the
   memory allocated for that chunk.
   This is used in the following cases:
   - the caller wants to keep the chunk for retransmissions.
   - the chunk was created with ch_makeChunk and the pointer to the chunk points
     into an SCTP-message, which was allocated as a whole. In this case the chunk
     can not be freed here.
*/
void ch_forgetChunk(ChunkID chunkID);


