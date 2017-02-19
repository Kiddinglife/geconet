/* $Id: bundling.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef BUNDLING_H
#define BUNDLING_H


#include "globals.h"            /* for chunk struct definition */
#include "SCTP-control.h"
#include "pathmanagement.h"

void bu_init_bundling(void);
gint bu_put_Ctrl_Chunk(SCTP_simple_chunk * chunk,unsigned int * dest_index);
gint bu_put_Data_Chunk(SCTP_simple_chunk * chunk,unsigned int * dest_index);


/*
 * bu_new: Creates a new bundling instance and returns a pointer to its data. 
 */
gpointer bu_new(void);

/* 
 * bu_delete: Deletes a bundling instance
 * 
 * Params: Pointer/handle which was returned by bu_new()
 */
void bu_delete(gpointer instancePtr);

/**
 * returns a value indicating which chunks are in the packet.
 */
unsigned int rbu_scanPDU(guchar * pdu, guint len);

/*
 * rbu_datagramContains: looks for chunk_type in a newly received datagram
 * Should be called after rbu_scanPDU().
 * The chunkArray parameter is inspected. This only really checks for chunks
 * with an ID <= 30. For all other chunks, it just guesses...
 * @return true is chunk_type exists in chunkArray, false if it is not in there
 */
gboolean rbu_datagramContains(gushort chunk_type, unsigned int chunkArray);

guchar* rbu_scanInitChunkForParameter(guchar * chunk, gushort paramType);

/*
 * rbu_findChunk: looks for chunk_type in a newly received datagram
 *
 * All chunks within the datagram are looked at, until one is found
 * that equals the parameter chunk_type.
 * @return pointer to first chunk of chunk_type in SCTP datagram, else NULL
 */
guchar* rbu_findChunk(guchar * datagram, guint len, gushort chunk_type);

/*
 * rbu_scanDatagramForError : looks for Error chunk_type in a newly received datagram
 * that contains a special error cause code
 *
 * All chunks within the datagram are lookes at, until one is found
 * that equals the parameter chunk_type.
 * @return true is chunk_type exists in SCTP datagram, false if it is not in there
 */
gboolean rbu_scanDatagramForError(guchar * datagram, guint len, gushort error_cause);

/*
 * rbu_findAddress: looks for address type parameters in INIT or INIT-ACKs
 * All parameters within the chunk are looked at, and the n-th supported address is
 * copied into the provided buffer pointed to by the foundAddress parameter.
 * If there are less than n addresses, an appropriate error is
 * returned. n should be at least 1, of course.
 * @param  chunk            pointer to an INIT or INIT ACK chunk
 * @param  n                get the n-th address
 * @param  foundAddress     pointer to a buffer where an address, if found, will be copied
 * @return -1  for parameter problem, 0 for success (i.e. address found), 1 if there are not
 *             that many addresses in the chunk.
 */
gint rbu_findAddress(guchar * chunk, guint n, union sockunion* foundAddress, int supportedAddressTypes);

/*
 * rbu_rcvDatagram: Hands a lower layer datagram over to bundling (for de-bundling)
 * 
 * All chunks within the datagram are dispatched and sent to the appropriate
 * module, i.e.: control chunks are sent to sctp_control/pathmanagement, 
 * SACK chunks to reliable_transfer, and data_chunks to RX_control.
 * Those modules must get a pointer to the start of a chunk and 
 * information about its size (without padding).
 */
gint rbu_rcvDatagram(guint address_index, guchar * datagram, guint len);


void bu_lock_sender(void);
void bu_unlock_sender(guint* ad_idx);
gboolean bu_userDataOutbound(void);

/**
 * bu_put_SACK_Chunk: Called by recvcontrol, when a SACK must be piggy-backed
 *
 * @param chunk pointer to chunk, that is to be put in the bundling buffer
 * @return error value, 0 on success, -1 on error
 */
gint bu_put_SACK_Chunk(SCTP_sack_chunk * chunk, unsigned int* dest_index);


/*
 * bu_sendAllChunks: Trigger to send all chunks previously entered with putChunk.
 *
 * Return value: error value
 * Chunks sent are deleted afterwards.
 */
gint bu_sendAllChunks(guint * ad_idx);

void bu_request_sack(void);

#endif
