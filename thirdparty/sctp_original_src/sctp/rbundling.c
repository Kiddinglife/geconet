/* $Id: rbundling.c 2771 2013-05-30 09:09:07Z dreibh $
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

#include "bundling.h"
#include "messages.h"
#include "recvctrl.h"
#include "reltransfer.h"
#include "errorhandler.h"
#include "streamengine.h"
#include "distribution.h"

#include <stdio.h>

#define TOTAL_SIZE(buf)		((buf)->ctrl_position+(buf)->sack_position+(buf)->data_position- 2*sizeof(SCTP_common_header))



unsigned int rbu_scanPDU(guchar * pdu, guint len)
{
    gushort processed_len = 0;
    gushort chunk_len = 0;
    unsigned int result = 0;
    guchar *current_position;
    guint pad_bytes;
    SCTP_simple_chunk *chunk;

    current_position = pdu; /* points to the first chunk in this pdu */

    while (processed_len < len) {

        event_logii(VERBOSE, "rbu_scanPDU : len==%u, processed_len == %u", len, processed_len);

        chunk = (SCTP_simple_chunk *) current_position;
        chunk_len = CHUNKP_LENGTH((SCTP_chunk_header *) chunk);

        if (chunk_len < 4 || chunk_len + processed_len > len) return result;

        if (chunk->chunk_header.chunk_id <= 30) {
            result = result | (1 << chunk->chunk_header.chunk_id);
            event_logii(VERBOSE, "rbu_scanPDU : Chunk type==%u, result == %x", chunk->chunk_header.chunk_id, result);
        } else {
            result = result | (1 << 31);
            event_logii(VERBOSE, "rbu_scanPDU : Chunk type==%u setting bit 31 --> result == %x", chunk->chunk_header.chunk_id, result);
        }
        processed_len += chunk_len;
        pad_bytes = ((processed_len % 4) == 0) ? 0 : (4 - processed_len % 4);
        processed_len += pad_bytes;
        chunk_len = (CHUNKP_LENGTH((SCTP_chunk_header *) chunk) + pad_bytes * sizeof(unsigned char));

        if (chunk_len < 4 || chunk_len + processed_len > len) return result;
        current_position += chunk_len;

    }
    return result;
}

gboolean rbu_datagramContains(gushort chunk_type, unsigned int chunkArray)
{
    unsigned int val = 0;

    if (chunk_type >= 31) {
        val = (1 << 31);
        if ((val & chunkArray) == 0) return FALSE;
        else return TRUE;    /* meaning: it could be true */
    }

    val = (1 << chunk_type);
    if ((val & chunkArray) != 0) return TRUE;
    else return FALSE;

}


guchar* rbu_scanInitChunkForParameter(guchar * chunk, gushort paramType)
{
    gushort processed_len;
    guint len = 0, parameterLength = 0;
    guchar *current_position;
    guint pad_bytes;
    SCTP_init *initChunk;
    SCTP_vlparam_header* vlp;

    initChunk = (SCTP_init *) chunk;

    if (initChunk->chunk_header.chunk_id != CHUNK_INIT &&
        initChunk->chunk_header.chunk_id != CHUNK_INIT_ACK) {
        return FALSE;
    }
    len = ntohs(initChunk->chunk_header.chunk_length);
    current_position = initChunk->variableParams;
    processed_len = (sizeof(SCTP_chunk_header)+sizeof(SCTP_init_fixed));

    while (processed_len < len) {
        event_logii(INTERNAL_EVENT_0,
                    "rbu_scanInitChunkForParameter : len==%u, processed_len == %u", len, processed_len);
        vlp = (SCTP_vlparam_header*) current_position;
        parameterLength = ntohs(vlp->param_length);

        if (parameterLength < 4 || parameterLength + processed_len > len) return NULL;

        if (ntohs(vlp->param_type) == paramType) {
            return current_position;
        }
        processed_len += parameterLength;
        pad_bytes = ((processed_len % 4) == 0) ? 0 : (4 - processed_len % 4);
        processed_len += pad_bytes;
        current_position += (parameterLength + pad_bytes * sizeof(unsigned char));
    }
    return NULL;

}


/*
 * rbu_findChunk: looks for chunk_type in a newly received datagram
 *
 * All chunks within the datagram are looked at, until one is found
 * that equals the parameter chunk_type.
 * @param  datagram     pointer to the newly received data
 * @param  len          stop after this many bytes
 * @param  chunk_type   chunk type to look for
 * @return pointer to first chunk of chunk_type in SCTP datagram, else NULL
 */
guchar* rbu_findChunk(guchar * datagram, guint len, gushort chunk_type)
{
    gushort processed_len = 0, chunk_len = 0;
    guchar *current_position;
    guint pad_bytes;
    SCTP_simple_chunk *chunk;

    current_position = datagram; /* points to the first chunk in this pdu */
    while (processed_len < len) {

        event_logii(INTERNAL_EVENT_0,
                    "rbu_findChunk : len==%u, processed_len == %u", len, processed_len);

        chunk = (SCTP_simple_chunk *) current_position;
        if (chunk->chunk_header.chunk_id == chunk_type)
            return current_position;
        else {
            chunk_len = CHUNKP_LENGTH((SCTP_chunk_header *) chunk);
            if (chunk_len < 4 || chunk_len + processed_len > len) return NULL;

            processed_len += CHUNKP_LENGTH((SCTP_chunk_header *) chunk);
            pad_bytes = ((processed_len % 4) == 0) ? 0 : (4 - processed_len % 4);
            processed_len += pad_bytes;
            chunk_len = (CHUNKP_LENGTH((SCTP_chunk_header *) chunk) + pad_bytes * sizeof(unsigned char));
            if (chunk_len < 4 || chunk_len + processed_len > len) return NULL;
            current_position += chunk_len;
        }
    }
    return NULL;
}

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
gint rbu_findAddress(guchar * chunk, guint n, union sockunion* foundAddress, int supportedAddressTypes)
{
    gushort processed_len;
    guint len = 0, parameterLength = 0;
    guchar *current_position;
    guint pad_bytes;
    SCTP_init *initChunk;
    SCTP_vlparam_header* vlp;
    SCTP_ip_address * address;
    unsigned int foundAddressNumber = 0;

    initChunk = (SCTP_init *) chunk;
    if (foundAddress == NULL || n < 1 || n > SCTP_MAX_NUM_ADDRESSES)
        return -1;
    if (initChunk->chunk_header.chunk_id != CHUNK_INIT &&
        initChunk->chunk_header.chunk_id != CHUNK_INIT_ACK) {
        return -1;
    }
    len = ntohs(initChunk->chunk_header.chunk_length);
    current_position = initChunk->variableParams;
    processed_len = (sizeof(SCTP_chunk_header)+sizeof(SCTP_init_fixed));

    while (processed_len < len) {
        event_logii(INTERNAL_EVENT_0,
                    "rbu_findAddress : len==%u, processed_len == %u", len, processed_len);
        vlp = (SCTP_vlparam_header*) current_position;
        parameterLength = ntohs(vlp->param_length);

        if (parameterLength < 4 || parameterLength + processed_len > len) return -1;

        if (ntohs(vlp->param_type) == VLPARAM_IPV4_ADDRESS &&
            supportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV4) {
            /* discard invalid addresses */
            foundAddressNumber++;
            if (foundAddressNumber == n) {
                address = (SCTP_ip_address *)current_position;
                /* copy the address over to the user buffer */
                foundAddress->sa.sa_family = AF_INET;
                foundAddress->sin.sin_port = 0;
                foundAddress->sin.sin_addr.s_addr = address->dest_addr.sctp_ipv4;
                return 0;
            }
#ifdef HAVE_IPV6
        } else if (ntohs(vlp->param_type) == VLPARAM_IPV6_ADDRESS &&
            supportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV6) {
            /* discard invalid addresses */
            foundAddressNumber++;
            if (foundAddressNumber == n) {
                address = (SCTP_ip_address *)current_position;
                /* copy the address over to the user buffer */
                foundAddress->sa.sa_family = AF_INET6;
                foundAddress->sin6.sin6_port = htons(0);
                foundAddress->sin6.sin6_flowinfo = htonl(0);
#ifdef HAVE_SIN6_SCOPE_ID
                foundAddress->sin6.sin6_scope_id = htonl(0);
#endif
                memcpy(foundAddress->sin6.sin6_addr.s6_addr,
                       address->dest_addr.sctp_ipv6, sizeof(struct in6_addr));

                return 0;
            }
#endif
        }
        processed_len += parameterLength;
        pad_bytes = ((processed_len % 4) == 0) ? 0 : (4 - processed_len % 4);
        processed_len += pad_bytes;
        current_position += (parameterLength + pad_bytes * sizeof(unsigned char));
    }
    return 1;
}

/**
 * looks for Error chunk_type in a newly received datagram
 * that contains a special error cause code
 *
 * All chunks within the datagram are lookes at, until one is found
 * that equals the parameter chunk_type.
 * @param  datagram     pointer to the newly received data
 * @param  len          stop after this many bytes
 * @param  error_cause  error cause code to look for
 * @return true is chunk_type exists in SCTP datagram, false if it is not in there
 */
gboolean rbu_scanDatagramForError(guchar * datagram, guint len, gushort error_cause)
{
    gushort processed_len = 0, param_length = 0, chunk_length = 0;
    gushort err_len = 0;

    guchar *current_position;
    guint pad_bytes;
    SCTP_simple_chunk *chunk;
    SCTP_staleCookieError *err_chunk;


    current_position = datagram; /* points to the first chunk in this pdu */
    while (processed_len < len) {

        event_logii(VERBOSE,
                    "rbu_scanDatagramForError : len==%u, processed_len == %u", len, processed_len);

        chunk = (SCTP_simple_chunk *) current_position;
        chunk_length = CHUNKP_LENGTH((SCTP_chunk_header *) chunk);
        if (chunk_length < 4 || chunk_length + processed_len > len) return FALSE;

        if (chunk->chunk_header.chunk_id == CHUNK_ERROR) {

            if (chunk_length < 4 || chunk_length + processed_len > len) return FALSE;

            event_log(INTERNAL_EVENT_0, "rbu_scanDatagramForError : Error Chunk Found");
            /* now search for error parameter that fits */
            while (err_len < chunk_length - sizeof(SCTP_chunk_header))  {
                err_chunk = (SCTP_staleCookieError *) &(chunk->simple_chunk_data[err_len]);
                if (ntohs(err_chunk->vlparam_header.param_type) == error_cause) {
                    event_logi(VERBOSE,
                               "rbu_scanDatagramForError : Error Cause %u found -> Returning TRUE",
                               error_cause);
                    return TRUE;
                }
                param_length = ntohs(err_chunk->vlparam_header.param_length);
                if (param_length < 4 || param_length + err_len > len) return FALSE;

                err_len += param_length;
                while ((err_len % 4) != 0)
                    err_len++;
            }
        }

        processed_len += chunk_length;
        pad_bytes = ((processed_len % 4) == 0) ? 0 : (4 - processed_len % 4);
        processed_len += pad_bytes;
        chunk_length = (CHUNKP_LENGTH((SCTP_chunk_header *) chunk) + pad_bytes * sizeof(unsigned char));
        if (chunk_length < 4 || chunk_length + processed_len > len) return FALSE;
        current_position += chunk_length;
    }
    event_logi(VERBOSE,
               "rbu_scanDatagramForError : Error Cause %u NOT found -> Returning FALSE",
               error_cause);
    return FALSE;
}


/**
 * Disassembles chunks from a received datagram
 *
 * FIXME : data chunks may only be parsed after control chunks.....
 *
 * All chunks within the datagram are dispatched and sent to the appropriate
 * module, i.e.: control chunks are sent to sctp_control/pathmanagement,
 * SACK chunks to reliable_transfer, and data_chunks to RX_control.
 * Those modules must get a pointer to the start of a chunk and
 * information about its size (without padding).
 * @param  address_index  index of address on which this data arrived
 * @param  datagram     pointer to first chunk of the newly received data
 * @param  len          length of payload (i.e. len of the concatenation of chunks)
 */
gint rbu_rcvDatagram(guint address_index, guchar * datagram, guint len)
{
    /* sctp common header header has been verified */
    /* tag (if association is established) and CRC is okay */
    /* get first chunk-id and length, pass pointers & len on to relevant module :
       - CHUNK_INIT, CHUNK_INIT_ACK,CHUNK_ABORT, CHUNK_SHUTDOWN,CHUNK_SHUTDOWN_ACK
       CHUNK_COOKIE_ECHO,CHUNK_COOKIE_ACK go to SCTP_CONTROL (change of association state)
       - CHUNK_HBREQ, CHUNK_HBACK go to PATH_MAN instance
       - CHUNK_SACK goes to RELIABLE_TRANSFER
       - CHUNK_ERROR probably to SCTP_CONTROL as well  (at least there !)
       - CHUNK_DATA goes to RX_CONTROL
     */
    guchar *current_position;
    gushort processed_len = 0, chunk_len;
    gushort pad_bytes;
    SCTP_simple_chunk *chunk;
    gboolean data_chunk_received = FALSE;

    int association_state = STATE_OK;
    gboolean send_it = FALSE;

    bu_lock_sender();

    current_position = datagram; /* points to the first chunk in this pdu */
    event_log(INTERNAL_EVENT_0, "Entered rbu_rcvDatagram()...... ");
    /* CHECKME : beim Empfangen leerer Chunks tritt im Bundling eine Endlosschleife auf ??? */
    while (processed_len < len) {

        chunk = (SCTP_simple_chunk *) current_position;
        chunk_len = CHUNKP_LENGTH((SCTP_chunk_header *) chunk);
        event_logiiii(INTERNAL_EVENT_0,
                     "rbu_rcvDatagram(address=%u) : len==%u, processed_len = %u, chunk_len=%u",
                     address_index, len, processed_len, chunk_len);
        if ((processed_len+chunk_len) > len || chunk_len < 4) {
            error_logiii(ERROR_MINOR, "Faulty chunklen=%u, total len=%u,processed_len=%u --> dropping packet  !",
                                    chunk_len,len,processed_len);
            /* if the association has already been removed, we cannot unlock it anymore */
            bu_unlock_sender(&address_index);
            return 1;
        }
        /*
         * TODO :   Add return values to the chunk-functions, where they can indicate what
         *          to do with the rest of the datagram (i.e. DISCARD after stale COOKIE_ECHO
         *          with tie tags that do not match the current ones)
         */
        switch (chunk->chunk_header.chunk_id) {
        case CHUNK_DATA:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received DATA chunk");
            rxc_data_chunk_rx((SCTP_data_chunk*) chunk, address_index);
            data_chunk_received = TRUE;
            break;
        case CHUNK_INIT:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received INIT chunk");
            association_state = sctlr_init((SCTP_init *) chunk);
            break;
        case CHUNK_INIT_ACK:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received INIT ACK chunk");
            association_state = sctlr_initAck((SCTP_init *) chunk);
            break;
        case CHUNK_SACK:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received SACK chunk");
            rtx_process_sack(address_index, chunk, len);
            break;
        case CHUNK_HBREQ:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received HB_REQ chunk");
            pm_heartbeat((SCTP_heartbeat *) chunk, address_index);
            break;
        case CHUNK_HBACK:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received HB_ACK chunk");
            pm_heartbeatAck((SCTP_heartbeat *) chunk);
            break;
        case CHUNK_ABORT:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received ABORT chunk");
            association_state = sctlr_abort();
            break;
        case CHUNK_SHUTDOWN:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received SHUTDOWN chunk");
            association_state = sctlr_shutdown((SCTP_simple_chunk *) chunk);
            break;
        case CHUNK_SHUTDOWN_ACK:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received SHUTDOWN ACK chunk");
            association_state = sctlr_shutdownAck();
            break;
        case CHUNK_ERROR:
            event_log(INTERNAL_EVENT_0, "Error Chunk");
            eh_recv_chunk(chunk);
            break;
        case CHUNK_COOKIE_ECHO:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received COOKIE ECHO chunk");
            sctlr_cookie_echo((SCTP_cookie_echo *) chunk);
            break;
        case CHUNK_COOKIE_ACK:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received COOKIE ACK chunk");
            sctlr_cookieAck((SCTP_simple_chunk *) chunk);
            break;
     /* case CHUNK_ECNE:
        case CHUNK_CWR:
            event_logi(INTERNAL_EVENT_0,
                       "Chunktype %u not Supported Yet !!!!!!!!", chunk->chunk_header.chunk_id);
            break;*/
        case CHUNK_SHUTDOWN_COMPLETE:
            event_log(INTERNAL_EVENT_0, "*******************  Bundling received SHUTDOWN_COMPLETE chunk");
            association_state = sctlr_shutdownComplete();
            break;
        case CHUNK_FORWARD_TSN:
            if (mdi_supportsPRSCTP() == TRUE) {
                event_log(INTERNAL_EVENT_0, "*******************  Bundling received FORWARD_TSN chunk");
                rxc_process_forward_tsn((SCTP_simple_chunk *) chunk);
                break;
            } else
                continue;
    /*    case CHUNK_ASCONF: */
            /* check that ASCONF chunks are standalone chunks, not bundled with any other
               chunks. Else ignore the ASCONF chunk (but not the others) */
/*            event_log(INTERNAL_EVENT_0, "Bundling received ASCONF chunk");
            asc_recv_asconf_chunk((SCTP_simple_chunk *) chunk);
            break;
        case CHUNK_ASCONF_ACK:
            event_log(INTERNAL_EVENT_0, "Bundling received ASCONF_ACK chunk");
            asc_recv_asconf_ack((SCTP_simple_chunk *) chunk);
            break; */
        default:
        /* 00 - Stop processing this SCTP packet and discard it, do not process
                any further chunks within it.
           01 - Stop processing this SCTP packet and discard it, do not process
                any further chunks within it, and report the unrecognized
                parameter in an 'Unrecognized Parameter Type' (in either an
                ERROR or in the INIT ACK).
           10 - Skip this chunk and continue processing.
           11 - Skip this chunk and continue processing, but report in an ERROR
                Chunk using the 'Unrecognized Chunk Type' cause of error. */
            if ((chunk->chunk_header.chunk_id & 0xC0) == 0x0) {            /* 00 */
                processed_len = len;
                event_logi(EXTERNAL_EVENT_X, "00: Unknown chunktype %u in rbundling.c", chunk->chunk_header.chunk_id);
            } else if ((chunk->chunk_header.chunk_id & 0xC0) == 0x40) {    /* 01 */
                processed_len = len;
                eh_send_unrecognized_chunktype((unsigned char*)chunk,chunk_len);
                event_logi(EXTERNAL_EVENT_X, "01: Unknown chunktype %u in rbundling.c",chunk->chunk_header.chunk_id);
            } else if ((chunk->chunk_header.chunk_id & 0xC0) == 0x80) {    /* 10 */
                /* nothing */
                event_logi(EXTERNAL_EVENT_X, "10: Unknown chunktype %u in rbundling.c",chunk->chunk_header.chunk_id);
            } else if ((chunk->chunk_header.chunk_id & 0xC0) == 0xC0) {    /* 11 */
                event_logi(EXTERNAL_EVENT_X, "11: Unknown chunktype %u in rbundling.c", chunk->chunk_header.chunk_id);
                eh_send_unrecognized_chunktype((unsigned char*)chunk,chunk_len);
            }
            break;
        }

        processed_len += chunk_len;
        pad_bytes = ((processed_len % 4) == 0) ? 0 : (4 - processed_len % 4);
        processed_len += pad_bytes;
        current_position += (chunk_len + pad_bytes) * sizeof(unsigned char);

        if (association_state != STATE_OK) processed_len = len;

        event_logiiii(VVERBOSE, "processed_len=%u, pad_bytes=%u, current_position=%u, chunk_len=%u",
            processed_len, pad_bytes, current_position,chunk_len);
    }

    if (association_state != STATE_STOP_PARSING_REMOVED) {

        if (data_chunk_received == TRUE) {
            /* update SACK structure and start SACK timer */
            rxc_all_chunks_processed(TRUE);
        } else {
            /* update SACK structure and datagram counter */
            rxc_all_chunks_processed(FALSE);
        }
        /* optionally also add a SACK chunk, at least for every second datagram
         * see section 6.2, second paragraph
         */
        if (data_chunk_received == TRUE){
            send_it = rxc_create_sack(&address_index, FALSE);
            se_doNotifications();
            if (send_it==TRUE) bu_sendAllChunks(&address_index);
        }
        /* if the association has already been removed, we cannot unlock it anymore */
        bu_unlock_sender(&address_index);
    }

    return 0;

}


