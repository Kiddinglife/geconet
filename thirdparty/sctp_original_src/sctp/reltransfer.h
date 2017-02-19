/* $Id: reltransfer.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef RELTRANSFER_H
#define RELTRANSFER_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "globals.h"



void *rtx_new_reltransfer(unsigned int number_of_destination_addresses, unsigned int iTSN);

void rtx_delete_reltransfer(void *rtx_instance);


/**
 * this is called by bundling, when a SACK needs to be processed
 */
int rtx_process_sack(unsigned int adr_index, void *sack_chunk, unsigned int totalLen);

/**
 * TODO : does nothing right now
 * a callback function for initiating retransmission after T3 has elapsed
 */
int rtx_timer_cb(TimerID tid, void *data1, void *data2);

/**
 * a function called by WinFlowCtrl, when chunks have been given to the bundling
 * instance, but need to be kept in the buffer until acknowledged
 * In SDL digram signal is called (RetransChunks)
 *
 * TODO : - add possibility for more than one data_chunk ????
 *
 */
int rtx_save_retrans_chunks(void *data_chunk);

/**
 * a function called by FlowCtrl, when chunk has been given to the bundling
 * instance, but is already contained in the reliable transfer list.
 * some data in that chunks must be updated.
 */
int rtx_update_retrans_chunks(void *data_chunk, unsigned int dest);

/**
 * called from flow-control to trigger retransmission of chunks that have previously
 * been sent to the address that timed out
 */
int rtx_t3_timeout(void *rtx_instance, unsigned int address,
                   unsigned int mtu, chunk_data ** rtx_chunks);



void chunk_list_debug(short event_log_level, GList * chunk_list);

/**
 * function to return the last a_rwnd value we got from our peer
 */
unsigned int rtx_read_remote_receiver_window(void);

/**
 * Function returns the number of chunks that are waiting in the queue to be acked
 */
unsigned int rtx_readNumberOfUnackedChunks(void);

/**
 * function to set the a_rwnd value we got from our peer (from INIT/INIT ACK)
 */
int rtx_set_remote_receiver_window(unsigned int new_arwnd);


/**
 * this function returns what we have got as ctsna from the peer
 */
unsigned int rtx_readLocalTSNacked(void);

gboolean rtx_is_lowest_tsn(unsigned int atsn);

int rtx_enter_fast_recovery(void);

gboolean rtx_is_in_fast_recovery(void);

/**
 * returns the current number of outstanding bytes queued in the retransmission
 * queue
 */
int rtx_get_obpa(unsigned int adIndex, unsigned int *totalInFlight);

/**
 * is called, in case we receive a Cookie in the ESTABLISHED state,
 * that indicates the peers restart -> we need to restart too
 */
void* rtx_restart_reliable_transfer(void* rtx_instance, unsigned int numOfPaths, unsigned int iTSN);

/**
 * function that is called by SCTP-Control, when ULP requests
 * shutdown in an established association
 */
int rtx_shutdown(void);


/**
 * function that is called by SCTP-Control, when peer indicates
 * shutdown and sends us his last ctsna...this function dequeues
 * all chunks, and returns the number of chunks left in the queue
 */
unsigned int rtx_rcv_shutdown_ctsna(unsigned int ctsna);

int rtx_dequeueOldestUnackedChunk(unsigned char *buf, unsigned int *len, unsigned int *tsn,
                                  unsigned short *sID, unsigned short *sSN,unsigned int* pID,
                                  unsigned char* flags, gpointer* ctx);




#endif
