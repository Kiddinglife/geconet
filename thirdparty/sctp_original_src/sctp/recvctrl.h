/* $Id: recvctrl.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef RECVCTRL_H
#define  RECVCTRL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "globals.h"



#define MAX_SACK_SIZE	1200
#define MAX_SACK_ARRAY_SIZE	1000

void *rxc_new_recvctrl(unsigned int remote_initial_TSN,
											 unsigned int number_of_destination_addresses,
											 void* sctpInstance);

void rxc_delete_recvctrl(void *rxc_instance);

/**
 * For now this function treats only one incoming data chunk
 * recvcontrol eventually passes chunk on to stream_engine !
 */
int rxc_data_chunk_rx(SCTP_data_chunk * se_chk, unsigned int ad_idx);

/**
 * Function triggered by flowcontrol, tells recvcontrol to create a SACK struct
 * and send it to bundling using bu_put_SACK_Chunk() function.
 * @param  destination_address pointer to address to send sack to  (or null for default)
 * @param  send_at_once, set by timer to send it at once....
 * @return boolean to indicate, whether a SACK was generated, and should be sent !
 */
boolean rxc_create_sack(unsigned int *destination_address, boolean force_sack);

/**
 * Function triggered by bundling (methinks), in order to signal to
 * rx control that all data chunks coming from an address have been processed,
 * and a new SACK may be generated
 */
void rxc_all_chunks_processed(boolean new_data_received);

/**
 * Function returns the current cumulative TSN, that this association has RECEIVED
 */
unsigned int rxc_read_cummulativeTSNacked(void);

/**
 * function to send SACK after ULP has read some data
 * this is to send ARWND updates...                   
 */
int rxc_start_sack_timer(unsigned int oldQueueLen);

/**
 * function called by bundling when a SACK is actually sent, to stop
 * a possibly running  timer
 */
void rxc_stop_sack_timer(void);

boolean rxc_sack_timer_is_running(void);

void rxc_send_sack_everytime(void);
void rxc_send_sack_every_second_time(void);


/**
 * returns my actual buffer size (for now a constant)
 */
unsigned int rxc_get_local_receiver_window(void);

int rxc_get_sack_delay(void);
int rxc_set_sack_delay(unsigned int new_delay);


/**
 * sets my actual buffer size
 */
int rxc_set_local_receiver_window(unsigned int new_window);

void rxc_restart_receivecontrol(unsigned int my_rwnd, unsigned int new_remote_TSN);

int rxc_process_forward_tsn(void* chunk);


#endif
