/* $Id: flowcontrol.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef FLOWCONTROL_H
#define FLOWCONTROL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "globals.h"
#include "reltransfer.h"

/**
 * Creates new instance of flowcontrol module and returns pointer to it
 * TODO : should parameter be unsigned short ?
 */
void *fc_new_flowcontrol(unsigned int peer_rwnd,
                         unsigned int my_iTSN,
                         unsigned int number_of_destination_addresses,
                         unsigned int maxQueueLen);

/**
 * Deletes data occupied by a flow_control data structure
 * @param fc_instance pointer to the flow_control data structure
 */
void fc_delete_flowcontrol(void *fc_instance);



/**
 * this function should be called to signal to flowcontrol, that our ULP
 * has initiated a shutdown procedure. We must only send unacked data from
 * now on ! The association is about to terminate !
 */
void fc_shutdown(void);

/**
 * this function stops all currently running timers, and may be called when
 * the shutdown is imminent
 */
void fc_stop_timers(void);

/**
 * this function stops all currently running timers, and may be called when
 * the shutdown is imminent
 */
void fc_restart(guint32 new_rwnd, unsigned int iTSN, unsigned int maxQueueLen);



/**
 * Function called by stream engine to enqueue data chunks in the flowcontrol
 * module. After function returns, we should be able to  delete the pointer
 * to the data (i.e. some lower module must have copied the data...e.g. the
 * Flowcontrol, ReliableTransfer, or Bundling
 * @param  chunk    pointer to the data chunk to be sent
 * @param destAddressIndex index to address to send data structure to...
 * @return -1 on error, 0 on success, (1 if problems occurred ?)
 */
int fc_send_data_chunk(chunk_data * chunk, short destAddressIndex, /* negative -> primary p., else path index */
                       unsigned int lifetime, /* 0xFFFFFFFF -> infinite */
                       gboolean dontBundle,
                       gpointer context);      /* FALSE==0==bundle, TRUE==1==don't bundle */


/**
 * function called by Reliable Transfer, when it requests retransmission
 * in SDL diagram this signal is called (Req_RTX, RetransChunks)
 * @param  all_data_acked indicates whether or not all data chunks have been acked
 * @param   new_data_acked indicates whether or not new data has been acked
 * @param   num_acked number of bytes that have been newly acked, else 0
 * @param   number_of_addresses so many addresses may have outstanding bytes
 *          actually that value may also be retrieved from the association struct (?)
 * @param   num_acked_per_address array of integers, that hold number of bytes acked for each address
 * @param   number_of_rtx_chunks number indicatin, how many chunks are to be retransmitted in on datagram
 * @param   chunks  array of pointers to data_chunk structures. These are to be retransmitted
 * @return   -1 on error, 0 on success, (1 if problems occurred ?)
 */
int fc_fast_retransmission(unsigned int address_index, unsigned int arwnd,unsigned int ctsna,
                         unsigned int rtx_bytes, boolean all_data_acked,
                         boolean new_data_acked, unsigned int num_acked,
                         unsigned int number_of_addresses,
                         int number_of_rtx_chunks, chunk_data ** chunks);

/**
 * function called by Reliable Transfer, after it has got a SACK chunk
 * in SDL diagram this signal is called SACK_Info
 * @param  all_data_acked indicates whether or not all data chunks have been acked
 * @param   new_data_acked indicates whether or not new data has been acked
 * @param   num_acked number of bytes that have been newly acked, else 0
 * @param   number_of_addresses so many addresses may have outstanding bytes
 *          actually that value may also be retrieved from the association struct (?)
 * @param   num_acked_per_address array of integers, that hold number of bytes acked for each address
 */
void fc_sack_info(unsigned int address_index, unsigned int arwnd, unsigned int ctsna,
                  boolean all_data_acked,
                  boolean new_data_acked,
                  unsigned int num_acked,
                  unsigned int number_of_addresses);

int fc_dequeueUnackedChunk(unsigned int tsn);

int fc_dequeue_acked_chunks(unsigned int ctsna);

int fc_dequeueOldestUnsentChunk(unsigned char *buf, unsigned int *len, unsigned int *tsn,
                                unsigned short *sID, unsigned short *sSN,unsigned int* pID,
                                unsigned char* flags, gpointer* ctx);

int fc_readNumberOfUnsentChunks(void);
/**
 * function returns number of chunks, that have been submitted from the upper layer,
 * but not yet been sent ! These are waiting in the transmission queue, not the
 * retransmission queue
 */
unsigned int fc_readNumberOfQueuedChunks(void);



/**
 * Function returns cwnd value of a certain path.
 * @param path_id    path index of which we want to know the cwnd
 * @return current cwnd value, else -1
 */
int fc_readCWND(short path_id);


/**
 * Function returns cwnd value of a certain path.
 * @param path_id    path index of which we want to know the cwnd
 * @return current cwnd2 value, else -1
 */
int fc_readCWND2(short path_id);


/**
 * Function returns ssthresh value of a certain path.
 * @param path_id    path index of which we want to know the cwnd
 * @return current ssthresh value, else -1
 */
int fc_readSsthresh(short path_id);



/**
 * Function returns mtu value of a certain path.
 * @param path_id    path index of which we want to know the mtu
 * @return current MTU value, else -1
 */
unsigned int fc_readMTU(short path_id);


/**
 * Function returns the partial bytes acked value of a certain path.
 * @param path_id    path index of which we want to know the PBA
 * @return current PBA value, else -1
 */
int fc_readPBA(short path_id);


/**
 * Function returns the outstanding byte count value of this association.
 * @return current outstanding_bytes value, else -1
 */
int fc_readOutstandingBytes(void);


int fc_get_maxSendQueue(unsigned int * queueLen);

int fc_set_maxSendQueue(unsigned int maxQueueLen);

#endif
