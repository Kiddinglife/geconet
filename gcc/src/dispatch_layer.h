/*
 * dispatchlayert.h
 *
 *  Created on: 28 Apr 2016
 *      Author: jakez
 */

#ifndef INCLUDE_DISPATCHLAYERT_H_
#define INCLUDE_DISPATCHLAYERT_H_

struct dispatch_layer_t
{
    void init();
    /**
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
    void recv_dctp_packet(int socket_fd, char *buffer, int bufferLength,
            sockaddrunion * source_addr, sockaddrunion * dest_addr);
};

#endif /* DISPATCHLAYERT_H_ */
