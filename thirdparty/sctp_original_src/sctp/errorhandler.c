/* $Id: errorhandler.c 2771 2013-05-30 09:09:07Z dreibh $
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

#include "globals.h"            /* for chunk struct definition */
#include "chunkHandler.h"
#include "bundling.h"
#include "SCTP-control.h"


void eh_init_errorhandler(void)
{
}

/*
 * eh_new: Create a new instance and returns a pointer to its data.
 */
void *eh_new(void)
{
   return NULL;
}

/* 
 * eh_delete: Deletes a bundling instance
 * 
 * Params: Pointer/handle which was returned by eh_new()
 */
void eh_delete(void *instancePtr)
{

}

/*
 *  eh_recv_chunk gets a pointer to an error chunk and decodes it
 *  accordingly....
 *  @return  error code, 0 for success, less than one for error
 */
int eh_recv_chunk(SCTP_simple_chunk * errchunk)
{
    SCTP_error_chunk *chunk;
    SCTP_vlparam_header *header;
    SCTP_error_cause *cause;
    unsigned char* data;

    unsigned short err_cause;
    unsigned short cause_len;
    int result = (-1);

    chunk = (SCTP_error_chunk *) errchunk;
    cause = (SCTP_error_cause *) chunk->data;
    data =  cause->cause_information;

    err_cause = ntohs(cause->cause_code);
    cause_len = ntohs(cause->cause_length);
    switch (err_cause) {
    case ECC_INVALID_STREAM_ID:
        event_logi(EXTERNAL_EVENT, "Invalid Stream Id Error with Len %u ", cause_len);
        break;
    case ECC_MISSING_MANDATORY_PARAM:
        event_logi(EXTERNAL_EVENT, "Missing Mandatory Parameter Error, Len %u ", cause_len);
        break;
    case ECC_STALE_COOKIE_ERROR:
        event_logi(EXTERNAL_EVENT, "Stale Cookie Error, Len %u ", cause_len);
        sctlr_staleCookie((SCTP_simple_chunk *) errchunk);
        result = 0;
        break;
    case ECC_OUT_OF_RESOURCE_ERROR:
        event_logi(EXTERNAL_EVENT, "Out Of Resource Error with Len %u ", cause_len);
        break;
    case ECC_UNRESOLVABLE_ADDRESS:
        event_logi(EXTERNAL_EVENT, "Unresovable Address Error with Len %u ", cause_len);
        break;
    case ECC_UNRECOGNIZED_CHUNKTYPE:
        event_logi(EXTERNAL_EVENT, "Unrecognized Chunktype Len %u ", cause_len);
        break;
    case ECC_INVALID_MANDATORY_PARAM:
        event_logi(EXTERNAL_EVENT, "Invalid Mandatory Parameter : Len %u ", cause_len);
        break;
    case ECC_UNRECOGNIZED_PARAMS:
        event_logi(EXTERNAL_EVENT, "Unrecognized Params Error with Len %u ", cause_len);
        header = (SCTP_vlparam_header*)data;
        if (ntohs(header->param_type) == VLPARAM_PRSCTP) {
            /* set peer does not understand PRSCTP - do not use it in this ASSOC ! */
            event_log(EXTERNAL_EVENT, "Unrecognized Parameter: PR_SCTP ");
        }
        break;
    case ECC_NO_USER_DATA:
        event_logi(EXTERNAL_EVENT, "No User Data Error with Len %u ", cause_len);
        break;
    case ECC_COOKIE_RECEIVED_DURING_SHUTDWN:
        event_logi(EXTERNAL_EVENT, "Error : Cookie Received During Shutdown, Len: %u ", cause_len);
        break;
    default:
        error_logii(ERROR_MINOR, "Unrecognized Error Cause %u with Len %u ", err_cause, cause_len);
    }
    return result;
}

/**
 * function to trigger sending of error chunk, after receiving an invalid stream id
 * @return error value, 0 on success, -1 on error
 */
int eh_make_invalid_streamid_error(unsigned short streamid)
{
    ChunkID errorCID;
    SCTP_InvalidStreamIdError error_info;
    
    /* build chunk */
    errorCID = ch_makeErrorChunk();

    error_info.stream_id = htons(streamid);
    error_info.reserved = htons(0);

    /* add parameters */
    ch_enterErrorCauseData(errorCID, ECC_INVALID_STREAM_ID, 4, (unsigned char*)&error_info);

    bu_put_Ctrl_Chunk(ch_chunkString(errorCID),NULL);
    ch_deleteChunk(errorCID);
    
    return 0;
}


/**
 * function to put an error_chunk with type UNKNOWN PARAMETER
 * @return error value, 0 on success, -1 on error
 */
int eh_send_unrecognized_chunktype(unsigned char* faulty_chunk, unsigned short length)
{
    ChunkID errorCID;

    /* build chunk */
    errorCID = ch_makeErrorChunk();
    /* add parameters */
    ch_enterErrorCauseData(errorCID, ECC_UNRECOGNIZED_CHUNKTYPE, length, (unsigned char*)faulty_chunk);

    bu_put_Ctrl_Chunk(ch_chunkString(errorCID),NULL);
    ch_deleteChunk(errorCID);
    
    return bu_sendAllChunks(NULL);
}

/**
 * function to trigger sending of error chunk, after mandatory parameter(s) was(were) missing
 * @return error value, 0 on success, -1 on error
 */
int eh_make_missing_mandatory_param(unsigned int number, unsigned short *param_types)
{
    return -1;
}

/**
 * function to trigger sending of error chunk, after receiving an invalid stream id
 * @param number number of pointers passed as second argument
 * @param addresses pointers (or array of pointers) to unrecognized addresses
 * @return error value, 0 on success, -1 on error
 */
int eh_send_unresolvable_address(unsigned int number, unsigned char *addresses)
{
    return -1;
}


/**
 * function to add an error chunk, after empty data chunk was received
 * @return error value, 0 on success, -1 on error
 */
int eh_make_empty_data_chunk_error(unsigned int tsn)
{
    ChunkID errorCID;

    /* build chunk */
    errorCID = ch_makeErrorChunk();

    /* add parameters */
    ch_enterErrorCauseData(errorCID, ECC_NO_USER_DATA, sizeof(unsigned int), (unsigned char*)&tsn);

    bu_put_Ctrl_Chunk(ch_chunkString(errorCID),NULL);
    ch_deleteChunk(errorCID);

    return 0;
}


