/* $Id: sbundling.c 2771 2013-05-30 09:09:07Z dreibh $
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

#include <stdio.h>

#include "bundling.h"
#include "messages.h"
#include "distribution.h"
#include "recvctrl.h"
#include "reltransfer.h"
#include "errorhandler.h"

#define TOTAL_SIZE(buf)		((buf)->ctrl_position+(buf)->sack_position+(buf)->data_position- 2*sizeof(SCTP_common_header))
#define SACK_SIZE(buf)		((buf)->ctrl_position+(buf)->data_position- sizeof(SCTP_common_header))
/**
 * this struct contains all data belonging to a bundling module
 */
typedef struct bundling_instance_struct
{
    /*@{ */
    /** buffer for control chunks */
    guchar ctrl_buf[MAX_MTU_SIZE];
    /** buffer for sack chunks */
    guchar sack_buf[MAX_MTU_SIZE];
    /** buffer for data chunks */
    guchar data_buf[MAX_MTU_SIZE];
    /* Leave some space for the SCTP common header */
    /**  current position in the buffer for control chunks */
    guint ctrl_position;
    /**  current position in the buffer for sack chunks */
    guint sack_position;
    /**  current position in the buffer for data chunks */
    guint data_position;
    /** is there data to be sent in the buffer ? */
    gboolean data_in_buffer;
    /**  is there a control chunk  to be sent in the buffer ? */
    gboolean ctrl_chunk_in_buffer;
    /**  is there a sack chunk  to be sent in the buffer ? */
    gboolean sack_in_buffer;
    /** status flag for correct sequence of actions */
    gboolean got_send_request;
    /** */
    gboolean got_send_address;
    /** */
    gboolean locked;
    /** did we receive a shutdown, either by ULP or peer ? */
    gboolean got_shutdown;
    /** */
    guint requested_destination;
    /*@} */

}
bundling_instance;

/**
 *  one static variable for a buffer that is used, if no bundling instance has been
 *  allocated and initialized yet
 */
static bundling_instance *global_buffer;


void bu_init_bundling(void)
{
    global_buffer = (bundling_instance*)bu_new();
}

/**
 * Creates a new bundling instance and returns a pointer to its data.
 * @return pointer to an instance of the bundling data
 */
gpointer bu_new(void)
{
    /* Alloc new bundling_instance data struct */
    bundling_instance *ptr;

    ptr = (bundling_instance*)malloc(sizeof(bundling_instance));
    if (!ptr) {
        error_log(ERROR_MAJOR, "Malloc failed");
        return 0;
    }
    ptr->ctrl_position = sizeof(SCTP_common_header); /* start adding data after that header ! */
    ptr->data_position = sizeof(SCTP_common_header); /* start adding data after that header ! */
    ptr->sack_position = sizeof(SCTP_common_header); /* start adding data after that header ! */

    ptr->data_in_buffer = FALSE;
    ptr->ctrl_chunk_in_buffer = FALSE;
    ptr->sack_in_buffer = FALSE;
    ptr->got_send_request = FALSE;
    ptr->got_send_address = FALSE;
    ptr->locked = FALSE;
    return ptr;
}

/**
 * Deletes a bundling instance
 *
 * @param Pointer which was returned by bu_new()
 */
void bu_delete(gpointer buPtr)
{
    event_log(INTERNAL_EVENT_0, "deleting bundling");
    free(buPtr);
}



/**
 * Keep sender from sending data right away - wait after received chunks have
 * been diassembled completely.
 */
void bu_lock_sender()
{
    bundling_instance *bu_ptr;
    event_log(VERBOSE, "bu_lock_sender() was called... ");

    bu_ptr = (bundling_instance *) mdi_readBundling();
    if (!bu_ptr) {              /* Assume that no association exists, so we take the global bundling buffer */
        event_log(VERBOSE, "Setting global bundling buffer ");
        bu_ptr = global_buffer;
    }
    bu_ptr->locked = TRUE;
    bu_ptr->got_send_request = FALSE;
}

/**
 * Enable sending again - wait after received chunks have
 * been diassembled completely.
 */
void bu_unlock_sender(guint* ad_idx)
{
    bundling_instance *bu_ptr;

    bu_ptr = (bundling_instance *) mdi_readBundling();
    if (!bu_ptr) {              /* Assume that no association exists, so we take the global bundling buffer */
        event_log(VERBOSE, "Setting global bundling buffer ");
        bu_ptr = global_buffer;
    }
    bu_ptr->locked = FALSE;
    event_logi(VERBOSE, "bu_unlock_sender() was called..and got %s send request -> processing",
       (bu_ptr->got_send_request == TRUE)?"A":"NO");

    if (bu_ptr->got_send_request == TRUE) bu_sendAllChunks(ad_idx);

}

/**
 * Called by recvcontrol, when a SACK must be piggy-backed
 * TODO : Handle multiple calls to this function between two send events
 *
 * @param chunk pointer to chunk, that is to be put in the bundling buffer
 * @return error value, 0 on success, -1 on error
 */
gint bu_put_SACK_Chunk(SCTP_sack_chunk * chunk, unsigned int * dest_index)
{
    bundling_instance *bu_ptr;
    gboolean lock;

    event_log(INTERNAL_EVENT_0, "bu_put_SACK_Chunk() was called ");

    bu_ptr = (bundling_instance *) mdi_readBundling();

    if (!bu_ptr) {              /* Assume that no association exists, so we take the global bundling buffer */
        event_log(VERBOSE, "Copying SACK to global bundling buffer ");
        bu_ptr = global_buffer;
    }

    if (SACK_SIZE(bu_ptr) + CHUNKP_LENGTH((SCTP_chunk_header *) chunk) >= MAX_SCTP_PDU) {
        lock = bu_ptr->locked;
         event_logi(VERBOSE,
                  "Chunk Length exceeded MAX_SCTP_PDU : sending chunk to address %u !",
                    (dest_index==NULL)?0:*dest_index);
        if (lock) bu_ptr->locked = FALSE;
        bu_sendAllChunks(dest_index);
        if (lock) bu_ptr->locked = TRUE;
    } else if (dest_index != NULL) {
        bu_ptr->got_send_address = TRUE;
        bu_ptr->requested_destination = *dest_index;
    }

    if (bu_ptr->sack_in_buffer == TRUE) { /* multiple calls in between */
        event_log(INTERNAL_EVENT_0,
                  "bu_put_SACK_Chunk was called a second time, deleting first chunk");
        bu_ptr->sack_position = sizeof(SCTP_common_header);
    }

    memcpy(&(bu_ptr->sack_buf[bu_ptr->sack_position]), chunk,
           CHUNKP_LENGTH((SCTP_chunk_header *) chunk));
    bu_ptr->sack_position += CHUNKP_LENGTH((SCTP_chunk_header *) chunk);
    bu_ptr->sack_in_buffer = TRUE;

    event_logii(VERBOSE, "Put SACK Chunk Length : %u , Total buffer size now: %u\n",
                CHUNKP_LENGTH((SCTP_chunk_header *) chunk), TOTAL_SIZE(bu_ptr));

    /* SACK always multiple of 32 bytes, do not care about padding */
    return 0;
}

/**
 * this function used for bundling of control chunks
 * Used by SCTP-control and Path management
 *
 * @param chunk pointer to chunk, that is to be put in the bundling buffer
 * @return TODO : error value, 0 on success
 */
gint bu_put_Ctrl_Chunk(SCTP_simple_chunk * chunk,unsigned int * dest_index)
{
    bundling_instance *bu_ptr;
    gint count;
    gboolean lock;

    event_log(INTERNAL_EVENT_0, "bu_put_Ctrl_Chunk() was called");

    bu_ptr = (bundling_instance *) mdi_readBundling();

    if (!bu_ptr) {              /* Assume that no association exists, so we take the global bundling buffer */
        event_log(VERBOSE, "Copying Control Chunk to global bundling buffer ");
        bu_ptr = global_buffer;
    }

    if (TOTAL_SIZE(bu_ptr) + CHUNKP_LENGTH((SCTP_chunk_header *) chunk) >= MAX_SCTP_PDU) {
        lock = bu_ptr->locked;
        event_logi(VERBOSE,
                  "Chunk Length exceeded MAX_SCTP_PDU : sending chunk to address %u !",
                    (dest_index==NULL)?0:*dest_index);
        if (lock) bu_ptr->locked = FALSE;
        bu_sendAllChunks(dest_index);
        if (lock) bu_ptr->locked = TRUE;
    } else if (dest_index != NULL) {
        bu_ptr->got_send_address = TRUE;
        bu_ptr->requested_destination = *dest_index;
    }

    memcpy(&(bu_ptr->ctrl_buf[bu_ptr->ctrl_position]), chunk,
           CHUNKP_LENGTH((SCTP_chunk_header *) chunk));
    bu_ptr->ctrl_position += CHUNKP_LENGTH((SCTP_chunk_header *) chunk);
    /* insert padding, if necessary */
    if ((CHUNKP_LENGTH((SCTP_chunk_header *) chunk) % 4) != 0) {
        for (count = 0; count < (4 - (CHUNKP_LENGTH((SCTP_chunk_header *) chunk) % 4)); count++) {
            bu_ptr->ctrl_buf[bu_ptr->ctrl_position] = 0;
            bu_ptr->ctrl_position++;
        }
    }
    event_logii(VERBOSE, "Put Control Chunk Length : %u , Total buffer size now (includes pad): %u\n",
                CHUNKP_LENGTH((SCTP_chunk_header *) chunk), TOTAL_SIZE(bu_ptr));

    bu_ptr->ctrl_chunk_in_buffer = TRUE;
    return 0;
}

gboolean bu_userDataOutbound(void)
{
    bundling_instance *bu_ptr;

    bu_ptr = (bundling_instance *) mdi_readBundling();
    if (!bu_ptr) {              /* Assume that no association exists, so we take the global bundling buffer */
        event_log(VERBOSE, "Setting global bundling buffer ");
        bu_ptr = global_buffer;
    }
    event_logi(VERBOSE, "bu_userDataOutbound() was called... and is %s ",(bu_ptr->data_in_buffer==TRUE)?"TRUE":"FALSE");
    return bu_ptr->data_in_buffer;
}

/**
 * this function used for putting data chunks into the buffer
 * Used only in the flow control module
 *
 * @param chunk pointer to chunk, that is to be put in the bundling buffer
 * @return TODO : error value, 0 on success
 */
gint bu_put_Data_Chunk(SCTP_simple_chunk * chunk,unsigned int * dest_index)
{
    bundling_instance *bu_ptr;
    gint count;
    gboolean lock;

    event_log(INTERNAL_EVENT_0, "bu_put_Data_Chunk() was called ");

    bu_ptr = (bundling_instance *) mdi_readBundling();

    if (!bu_ptr) {              /* Assume that no association exists, so we take the global bundling buffer */
        event_log(VERBOSE, "Copying data to global bundling buffer ");
        bu_ptr = global_buffer;
    }

    if (TOTAL_SIZE(bu_ptr) + CHUNKP_LENGTH((SCTP_chunk_header *) chunk) >= MAX_SCTP_PDU) {
        lock = bu_ptr->locked;
        event_logi(VERBOSE,
                  "Chunk Length exceeded MAX_SCTP_PDU : sending chunk to address %u !",
                    (dest_index==NULL)?0:*dest_index);
        if (lock) bu_ptr->locked = FALSE;
        bu_sendAllChunks(dest_index);
        if (lock) bu_ptr->locked = TRUE;
    } else if (dest_index != NULL) {
        bu_ptr->got_send_address = TRUE;
        bu_ptr->requested_destination = *dest_index;
    }
    memcpy(&(bu_ptr->data_buf[bu_ptr->data_position]), chunk,
           CHUNKP_LENGTH((SCTP_chunk_header *) chunk));
    bu_ptr->data_position += CHUNKP_LENGTH((SCTP_chunk_header *) chunk);


    /* insert padding, if necessary */
    if ((CHUNKP_LENGTH((SCTP_chunk_header *) chunk) % 4) != 0) {
        for (count = 0; count < (4 - (CHUNKP_LENGTH((SCTP_chunk_header *) chunk) % 4)); count++) {
            bu_ptr->data_buf[bu_ptr->data_position] = 0;
            bu_ptr->data_position++;
        }
    }
    event_logii(VERBOSE, "Put Data Chunk Length : %u , Total buffer size (incl. padding): %u\n",
                CHUNKP_LENGTH((SCTP_chunk_header *) chunk), TOTAL_SIZE(bu_ptr));

    bu_ptr->data_in_buffer = TRUE;

    /* if SACK is waiting, force sending it along */
    if (rxc_sack_timer_is_running() == TRUE) rxc_create_sack(dest_index, TRUE);

    return 0;
}

/**
 * Trigger sending of all chunks previously entered with put_Chunk functions
 *  Chunks sent are deleted afterwards.
 *
 * FIXME : special treatment for GLOBAL BUFFER, as this is not associated with
 *         any association.
 *
 *
 *  @return                 Errorcode (0 for good case: length bytes sent; 1 or -1 for error)
 *  @param   ad_idx     pointer to address index or NULL if data is to be sent to default address
 */
gint bu_sendAllChunks(guint * ad_idx)
{
    gint result, send_len = 0;
    guchar *send_buffer = NULL;
    bundling_instance *bu_ptr;
    gshort idx = 0;

    bu_ptr = (bundling_instance *) mdi_readBundling();

    event_log(INTERNAL_EVENT_0, "bu_sendAllChunks() is being executed...");

    if (!bu_ptr) {
        event_log(VERBOSE, "Sending data from global bundling buffer ");
        bu_ptr = global_buffer;
    }
    if (bu_ptr->locked == TRUE) {
        bu_ptr->got_send_request = TRUE;
        if (ad_idx) {
            bu_ptr->got_send_address = TRUE;
            bu_ptr->requested_destination = *ad_idx;
        }
        event_log(INTERNAL_EVENT_0, "bu_sendAllChunks : sender is LOCKED ---> returning ");
        return 1;
    }

    /* TODO : more intelligent path selection strategy */
    /*         should take into account PM_INACTIVE */
    if (ad_idx != NULL) {
        if (*ad_idx > 0xFFFF) {
            error_log(ERROR_FATAL, "address_index too big !");
        } else {
            idx = (short) *ad_idx;
        }
    } else {
        if (bu_ptr->got_send_address) {
            idx = (short)bu_ptr->requested_destination;
        } else {
            idx = -1; /* use last from address */
        }
    }

    event_logi(VVERBOSE, "bu_sendAllChunks : send to path %d ", idx);

    if (bu_ptr->sack_in_buffer)             send_buffer = bu_ptr->sack_buf;
    else if (bu_ptr->ctrl_chunk_in_buffer)  send_buffer = bu_ptr->ctrl_buf;
    else if (bu_ptr->data_in_buffer)        send_buffer = bu_ptr->data_buf;
    else {
        error_log(ERROR_MINOR, "Nothing to send, but bu_sendAllChunks was called !");
        return 1;
    }

    if (bu_ptr->sack_in_buffer) {
        rxc_stop_sack_timer();
        /* SACKs by default go to the last active address, from which data arrived */
        send_len = bu_ptr->sack_position; /* at least sizeof(SCTP_common_header) */
        /* at most pointing to the end of SACK chunk */
        event_logi(VVERBOSE, "bu_sendAllChunks(sack) : send_len == %d ", send_len);
        if (bu_ptr->ctrl_chunk_in_buffer) {
            memcpy(&send_buffer[send_len],
                   &(bu_ptr->ctrl_buf[sizeof(SCTP_common_header)]),
                   (bu_ptr->ctrl_position - sizeof(SCTP_common_header)));
            send_len += bu_ptr->ctrl_position - sizeof(SCTP_common_header);
            event_logi(VVERBOSE, "bu_sendAllChunks(sack+ctrl) : send_len == %d ", send_len);
        }
        if (bu_ptr->data_in_buffer) {
            memcpy(&send_buffer[send_len],
                   &(bu_ptr->data_buf[sizeof(SCTP_common_header)]),
                   (bu_ptr->data_position - sizeof(SCTP_common_header)));
            send_len += bu_ptr->data_position - sizeof(SCTP_common_header);
            event_logi(VVERBOSE, "bu_sendAllChunks(sack+data) : send_len == %d ", send_len);
        }
    } else if (bu_ptr->ctrl_chunk_in_buffer) {
        send_len = bu_ptr->ctrl_position;
        event_logi(VVERBOSE, "bu_sendAllChunks(ctrl) : send_len == %d ", send_len);
        if (bu_ptr->data_in_buffer) {
            memcpy(&send_buffer[send_len],
                   &(bu_ptr->data_buf[sizeof(SCTP_common_header)]),
                   (bu_ptr->data_position - sizeof(SCTP_common_header)));
            send_len += bu_ptr->data_position - sizeof(SCTP_common_header);
            event_logi(VVERBOSE, "bu_sendAllChunks(ctrl+data) : send_len == %d ", send_len);
        }

    } else if (bu_ptr->data_in_buffer) send_len = bu_ptr->data_position;

    event_logi(VVERBOSE, "bu_sendAllChunks(finally) : send_len == %d ", send_len);

    if (send_len > 1480) {
        fprintf(stderr, "MTU definitely exceeded (%u) - aborting\n",send_len);
        fprintf(stderr, "sack_position: %u, ctrl_position: %u, data_position: %u\n",
            bu_ptr->sack_position,bu_ptr->ctrl_position,bu_ptr->data_position);
        abort();
    }

    if ((bu_ptr->data_in_buffer) && (idx != -1)) pm_chunksSentOn(idx);

    event_logii(VERBOSE, "bu_sendAllChunks() : sending message len==%u to adress idx=%d", send_len, idx);

    result = mdi_send_message((SCTP_message *) send_buffer, send_len, idx);

    event_logi(VVERBOSE, "bu_sendAllChunks(): result == %s ", (result==0)?"OKAY":"ERROR");

    /* reset all positions */
    bu_ptr->sack_in_buffer = FALSE;
    bu_ptr->ctrl_chunk_in_buffer = FALSE;
    bu_ptr->data_in_buffer = FALSE;
    bu_ptr->got_send_request = FALSE;
    bu_ptr->got_send_address = FALSE;

    bu_ptr->data_position = sizeof(SCTP_common_header);
    bu_ptr->ctrl_position = sizeof(SCTP_common_header);
    bu_ptr->sack_position = sizeof(SCTP_common_header);

    return result;
}




