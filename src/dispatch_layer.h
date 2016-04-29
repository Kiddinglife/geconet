/*
* Copyright (c) 2016
* Geco Gaming Company
*
* Permission to use, copy, modify, distribute and sell this software
* and its documentation for GECO purpose is hereby granted without fee,
* provided that the above copyright notice appear in all copies and
* that both that copyright notice and this permission notice appear
* in supporting documentation. Geco Gaming makes no
* representations about the suitability of this software for GECO
* purpose.  It is provided "as is" without express or implied warranty.
*
*/

/**
* Created on 22 April 2016 by Jake Zhang
*/

#ifndef __INCLUDE_DISPATCH_LAYER_H
#define __INCLUDE_DISPATCH_LAYER_H
struct dispatch_layer_t
{
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
    void recv_dctp_packet(int socket_fd, char *buffer,
        int bufferLength, union sockaddrunion * source_addr,
    union sockaddrunion * dest_addr);
};
#endif