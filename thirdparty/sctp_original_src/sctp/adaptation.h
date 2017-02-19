/* $Id: adaptation.h 2771 2013-05-30 09:09:07Z dreibh $
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

/* ############################################################################## */
/* INCLUDES                                                                       */
/* ############################################################################## */

#ifndef ADAPTATION_H
#define ADAPTATION_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "sctp.h"
#include "globals.h"
#include "distribution.h"


unsigned int adl_random(void);

boolean adl_equal_address(union sockunion *one, union sockunion *two);


/**
 *  converts address-string (hex for ipv6, dotted decimal for ipv4
 *  to a sockunion structure
 *  @return 0 for success, else -1.
 */
int adl_str2sockunion(guchar * str, union sockunion *su);

int adl_sockunion2str(union sockunion *su, guchar * buf, size_t len);




/*------------------------------------------------------------------------------------------------------------------*/
/*------------------------------------------------------------------------------------------------------------------*/

/**
 * This function binds a local socket for incoming requests
 * @return socket file descriptor for the newly opened and bound socket
 * @param address (local) port to bind to
 */
gint adl_open_sctp_socket(int af, int* myRwnd);

int adl_setReceiveBufferSize(int sfd, int new_size);

gint adl_get_sctpv4_socket(void);
#ifdef HAVE_IPV6
gint adl_get_sctpv6_socket(void);
#endif


/**
 * function to be called when we get a message from a peer sctp instance in the poll loop
 * @param  sfd the socket file descriptor where data can be read...
 * @param  buf pointer to a buffer, where we data is stored
 * @param  len number of bytes to be sent, including the ip header !
 * @param  address, where data goes from
 * @param	dest_len size of the address
 * @return returns number of bytes actually sent, or error
 */
int adl_send_message(int sfd, void *buf, int len, union sockunion *dest, unsigned char tos);


/**
 * this function initializes the data of this module. It opens raw sockets for
 * capturing SCTP packets, and also opens ICMP sockets, so we can get ICMP events,
 * e.g.  for Path-MTU discovery !
 */
int adl_init_adaptation_layer(int * myRwnd);



/**
 * function add a sfd to the list of sfds we want to wait for with the poll()
 * @param sfd	        the socket file descriptor of the socket to react upon
 * @param scf           function pointer holding the callback funtion for normal events.
 * @return              the current number of sockets that are polled.
 */
int adl_register_socket_cb(gint sfd, sctp_socketCallback scf);


/**
 *	function to close a bound socket from our list of socket descriptors
 *	@param	sfd	socket file descriptor to be closed
 *	@return  0 on success, -1 for error, 1 if socket was not bound
 *    @author  ajung
 */
int adl_remove_cb(gint sfd);

/**
 * remove a sfd from the poll_list, and shift that list to the left
 * @return number of sfd's removed...
 */
int adl_remove_poll_fd(gint sfd);


/**
 * function is to return difference in msecs between time a and b (i.e. a-b)
 * @param a later time (e.g. current time)
 * @param b earlier time
 * @return -1 if a is earlier than b, else msecs that passed from b to a
 */
int adl_timediff_to_msecs(struct timeval *a, struct timeval *b);


void adl_add_msecs_totime(struct timeval *t, unsigned int msecs);

int adl_gettime(struct timeval *tv);

int adl_extendedGetEvents(void (*lock)(void* data), void (*unlock)(void* data), void* data);

int adl_registerUdpCallback(unsigned char me[],
                             unsigned short my_port,
                             sctp_socketCallback scf);

int adl_unregisterUdpCallback(int udp_sfd);

int adl_sendUdpData(int sfd, unsigned char* buf, int length,
                     unsigned char destination[], unsigned short dest_port);


int adl_registerStdinCallback(sctp_StdinCallback sdf, char* buffer, int length);
int adl_unregisterStdinCallback();

int adl_registerUserCallback(int fd, sctp_userCallback sdf, void* userData, short int eventMask);

int adl_unregisterUserCallback(int fd);

unsigned int adl_startMicroTimer(unsigned int seconds, unsigned int microseconds,
                            sctp_timerCallback timer_cb, int ttype, void *param1, void *param2);

unsigned int adl_startTimer(unsigned int milliseconds, sctp_timerCallback timer_cb,
                                 int ttype, void *param1, void *param2);

int adl_stopTimer(unsigned int tid);

unsigned int adl_restartTimer(unsigned int timer_id, unsigned int milliseconds);

unsigned int adl_restartMicroTimer(unsigned int timer_id, unsigned int seconds, unsigned int microseconds);

int adl_getEvents(void);

int adl_eventLoop();

int adl_extendedEventLoop(void (*lock)(void* data), void (*unlock)(void* data), void* data);

gboolean adl_filterInetAddress(union sockunion* newAddress, AddressScopingFlags  flags);

/*
 * this is an ugly part to code, so it was taken an adapted from the
 * SCTP reference implementation by Randy Stewart
 * see http://www.sctp.org
 * maybe I should rewrite it to use the Linux Netlink socket also
 * returns TRUE is successful, else FALSE
 */
gboolean adl_gatherLocalAddresses(union sockunion **localAddresses,
     int *numberOfNets,
     int sctp_fd,
     gboolean with_ipv6,
     int *max_mtu,
     const AddressScopingFlags  flags);


#endif
