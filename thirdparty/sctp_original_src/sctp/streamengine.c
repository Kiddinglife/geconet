/* $Id: streamengine.c 2771 2013-05-30 09:09:07Z dreibh $
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

#include <assert.h>
#include "globals.h"
#include <errno.h>
#include "flowcontrol.h"
#include "streamengine.h"
#include "distribution.h"
#include "errorhandler.h"
#include "SCTP-control.h"

#include "recvctrl.h"

#include "sctp.h"

#include <glib.h>


/******************** Structure Definitions ****************************************/

typedef struct
{
    GList   *pduList;         /* list of PDUs waiting for pickup (after notification has been called) */
    GList   *prePduList;      /* list of PDUs waiting for transfer to pduList and doing mdi arrive notification */
    guint16  nextSSN;
    guint16  highestSSN;      /* used to detect Protocol violations in se_searchReadyPdu */
    gboolean highestSSNused;
    int index;
}ReceiveStream;

typedef struct
{
    unsigned int nextSSN;
}SendStream;

typedef struct
{
    unsigned int    numSendStreams;
    unsigned int    numReceiveStreams;
    ReceiveStream*  RecvStreams;
    SendStream*     SendStreams;
    gboolean*       recvStreamActivated;
    unsigned int    queuedBytes;
    gboolean        unreliable;

    GList           *List;	 /* list for all packets */
}StreamEngine;

/*
 * this stores all the data need to be delivered to the user
 */
typedef struct _delivery_data
{
    guint8  chunk_flags;
    guint16 data_length;
    guint32 tsn;
    guint16 stream_id;
    guint16 stream_sn;
    guint32 protocolId;
    guint32 fromAddressIndex;
    guchar  data[MAX_DATACHUNK_PDU_LENGTH];
}
delivery_data;


/*
 * this struct stores several chunks that can be delivered to
 * the user as one message.
 */
typedef struct _delivery_pdu
{
    guint32  number_of_chunks;
    guint32  read_position;
    guint32  read_chunk;
    guint32  chunk_position;
    guint32  total_length;
    /* one chunk pointer or an array of these */
    delivery_data** ddata;
}delivery_pdu;



/******************** Declarations *************************************************/
int se_searchReadyPdu(StreamEngine* se);
int se_deliverWaiting(StreamEngine* se, unsigned short sid);

void print_element(gpointer list_element, gpointer user_data)
{
    delivery_data * one = (delivery_data *)list_element;
    if (one) {
        event_logii (VERBOSE, "chunklist: tsn %u, SID %u",one->tsn, one->stream_id);
    } else {
        event_log (VERBOSE, "chunklist: NULL element ");
    }
}

int sort_tsn_se(delivery_data * one, delivery_data * two)
{
    if (before(one->tsn, two->tsn)) {
        return -1;
    } else if (after(one->tsn, two->tsn)) {
        return 1;
    } else                      /* one==two */
        return 0;
}

/******************** Function Definitions *****************************************/

/* This function is called to instanciate one Stream Engine for an association.
   It creates and initializes the Lists for Sending and Receiving Data.
   It is called by Message Distribution.
   returns: the pointer to the Stream Engine
*/

void* se_new_stream_engine (unsigned int numberReceiveStreams,        /* max of streams to receive */
                            unsigned int numberSendStreams,           /* max of streams to send */
                            gboolean assocSupportsPRSCTP)
{
    unsigned int i;
    StreamEngine* se;

    event_logiii (EXTERNAL_EVENT, "new_stream_engine: #inStreams=%d, #outStreams=%d, unreliable == %s",
            numberReceiveStreams,	numberSendStreams, (assocSupportsPRSCTP==TRUE)?"TRUE":"FALSE");

    se = (StreamEngine*) malloc(sizeof(StreamEngine));

    if (se == NULL) {
        error_log(ERROR_FATAL,"Out of Memory in se_new_stream_engine()");
        return NULL;
    }

    se->RecvStreams = (ReceiveStream*)malloc(numberReceiveStreams*sizeof(ReceiveStream));
    if (se->RecvStreams == NULL) {
        free(se);
        error_log(ERROR_FATAL,"Out of Memory in se_new_stream_engine()");
        return NULL;
    }
    se->recvStreamActivated = (gboolean*)malloc(numberReceiveStreams*sizeof(gboolean));
    if (se->recvStreamActivated == NULL) {
        free(se->RecvStreams);
        free(se);
        error_log(ERROR_FATAL,"Out of Memory in se_new_stream_engine()");
        return NULL;
    }

    for (i=0; i<numberReceiveStreams; i++) se->recvStreamActivated[i] = FALSE;

    se->SendStreams = (SendStream*)malloc(numberSendStreams*sizeof(SendStream));
    if (se->SendStreams == NULL) {
        free(se->RecvStreams);
				free(se->recvStreamActivated);
        free(se);
        error_log(ERROR_FATAL,"Out of Memory in se_new_stream_engine()");
        return NULL;
    }

    se->numSendStreams = numberSendStreams;
    se->numReceiveStreams = numberReceiveStreams;
    se->unreliable = assocSupportsPRSCTP;

    for (i = 0; i < numberReceiveStreams; i++) {
      (se->RecvStreams)[i].nextSSN = 0;
      (se->RecvStreams)[i].pduList = NULL;
      (se->RecvStreams)[i].prePduList = NULL;
      (se->RecvStreams)[i].index = 0; /* for ordered chunks, next ssn */
    }
    for (i = 0; i < numberSendStreams; i++)
    {
      (se->SendStreams[i]).nextSSN = 0;
    }

    se->queuedBytes = 0;
    se->List          = NULL;
    return (se);
}


/* Free all chunks in list */
static void free_delivery_pdu(gpointer list_element, gpointer user_data)
{
   delivery_pdu* d_pdu = (delivery_pdu*)list_element;
   int           i;

   if(d_pdu->ddata != NULL) {
      for (i = 0; i < (int)d_pdu->number_of_chunks; i++) {
         free(d_pdu->ddata[i]);
         d_pdu->ddata[i] = NULL;
      }
      free(d_pdu->ddata);
      free(d_pdu);
   }
}


/* Deletes the instance pointed to by streamengine.
*/
void
se_delete_stream_engine (void *septr)
{
  StreamEngine* se;
  unsigned int i;
  se = (StreamEngine*) septr;

  event_log (INTERNAL_EVENT_0, "delete streamengine: freeing send streams");
  free(se->SendStreams);

  for (i = 0; i < se->numReceiveStreams; i++) {
     event_logi (VERBOSE, "delete streamengine: freeing data for receive stream %d",i);
     /* whatever is still in these lists, delete it before freeing the lists */
     g_list_foreach(se->RecvStreams[i].pduList, &free_delivery_pdu, NULL);
     g_list_foreach(se->RecvStreams[i].prePduList, &free_delivery_pdu, NULL);
     g_list_free(se->RecvStreams[i].pduList);
     g_list_free(se->RecvStreams[i].prePduList);
  }

  event_log (INTERNAL_EVENT_0, "delete streamengine: freeing receive streams");
  free(se->RecvStreams);
  free(se->recvStreamActivated);
  free (se);
  event_log (EXTERNAL_EVENT, "deleted streamengine");
}



int
se_readNumberOfStreams (unsigned short *inStreams, unsigned short *outStreams)
{
  StreamEngine* se = (StreamEngine*) mdi_readStreamEngine ();
  if (se == NULL)
    {
      error_log(ERROR_MINOR, "Called se_readNumberOfStreams, but no Streamengine is there !");
      *inStreams = 0;
      *outStreams = 0;
      return -1;
    }
  *inStreams = se->numReceiveStreams;
  *outStreams = se->numSendStreams;
  return 0;
}


/******************** Functions for Sending *****************************************/

/**
 * This function is called to send a chunk.
 *  called from MessageDistribution
 * @return 0 for success, -1 for error (e.g. data sent in shutdown state etc.)
*/
int
se_ulpsend (unsigned short streamId, unsigned char *buffer,
            unsigned int byteCount,  unsigned int protocolId,
            short destAddressIndex, void *context, unsigned int lifetime,
            gboolean unorderedDelivery, gboolean dontBundle)
{
    StreamEngine* se=NULL;
    guint32 state;
    chunk_data*  cdata=NULL;
    SCTP_data_chunk* dchunk=NULL;
    unsigned char* bufPosition = buffer;

    unsigned int bCount = 0, maxQueueLen = 0;
    int numberOfSegments, residual;

    int i = 0;
    int result = 0, retVal;


    state = sci_getState ();
    if (sci_shutdown_procedure_started () == TRUE)
    {
        event_logi (EXTERNAL_EVENT,
        "se_ulpsend: Cannot send Chunk, Association (state==%u) in SHUTDOWN-phase", state);
        return SCTP_SPECIFIC_FUNCTION_ERROR;
    }

    event_logii (EXTERNAL_EVENT, "se_ulpsend : %u bytes for stream %u", byteCount,streamId);

    se = (StreamEngine*) mdi_readStreamEngine ();
    if (se == NULL)
    {
        error_log (ERROR_MAJOR, "se_ulpsend: StreamEngine Instance doesn't exist....Returning !");
        return SCTP_MODULE_NOT_FOUND;
    }

    if (streamId >= se->numSendStreams)
    {
        error_logii (ERROR_MAJOR, "STREAM ID OVERFLOW in se_ulpsend: wanted %u, got only %u",
            streamId, se->numSendStreams);
        mdi_sendFailureNotif (buffer, byteCount, (unsigned int*)context);
        return SCTP_PARAMETER_PROBLEM;
    }

    result = fc_get_maxSendQueue(&maxQueueLen);
    if (result != SCTP_SUCCESS) return SCTP_UNSPECIFIED_ERROR;


    retVal = SCTP_SUCCESS;

    /* if (byteCount <= fc_getMTU())          */
    if (byteCount <= SCTP_MAXIMUM_DATA_LENGTH)
    {
       if (maxQueueLen > 0) {
         if ((1 + fc_readNumberOfQueuedChunks()) > maxQueueLen) return SCTP_QUEUE_EXCEEDED;
       }

        cdata = (chunk_data*)malloc(sizeof(chunk_data));
        if (cdata == NULL) {
            return SCTP_OUT_OF_RESOURCES;
        }

        dchunk = (SCTP_data_chunk*)cdata->data;

        dchunk->chunk_id      = CHUNK_DATA;
        dchunk->chunk_flags   = (guint8)SCTP_DATA_BEGIN_SEGMENT + SCTP_DATA_END_SEGMENT;
        dchunk->chunk_length  = htons ((unsigned short)(byteCount + FIXED_DATA_CHUNK_SIZE));
        dchunk->tsn = 0;        /* gets assigned in the flowcontrol module */
        dchunk->stream_id     = htons (streamId);
        dchunk->protocolId    = protocolId;

        if (unorderedDelivery)
        {
            dchunk->stream_sn = htons (0);
            dchunk->chunk_flags += SCTP_DATA_UNORDERED;
        }
        else
        {       /* unordered flag not put */
            dchunk->stream_sn = htons ((unsigned short)(se->SendStreams[streamId].nextSSN));
            se->SendStreams[streamId].nextSSN++;
            se->SendStreams[streamId].nextSSN = se->SendStreams[streamId].nextSSN % 0x10000;
        }
        /* copy the data, but only once ! */
        memcpy (dchunk->data, buffer, byteCount);

        event_logii (EXTERNAL_EVENT, "=========> ulp sent a chunk (SSN=%u, SID=%u) to StreamEngine <=======",
                      ntohs (dchunk->stream_sn),ntohs (dchunk->stream_id));
        if (!se->unreliable) lifetime = 0xFFFFFFFF;
        result = fc_send_data_chunk (cdata, destAddressIndex, lifetime, dontBundle, context);

        if (result != SCTP_SUCCESS)	{
            error_logi (ERROR_MINOR, "se_ulpsend() failed with result %d", result);
            return result;
        }
    }
    else
    {
        /* calculate nr. of necessary chunks -> use fc_getMTU() later !!! */
      numberOfSegments = byteCount / SCTP_MAXIMUM_DATA_LENGTH;
      residual = byteCount % SCTP_MAXIMUM_DATA_LENGTH;
      if (residual != 0) {
            numberOfSegments++;
      } else {
            residual = SCTP_MAXIMUM_DATA_LENGTH;
      }

      if (maxQueueLen > 0) {
        if ((numberOfSegments + fc_readNumberOfQueuedChunks()) > maxQueueLen) return SCTP_QUEUE_EXCEEDED;
      }

      for (i = 1; i <= numberOfSegments; i++)
      {
            cdata = (chunk_data*)malloc(sizeof(chunk_data));
            if (cdata == NULL) {
                /* FIXME: this is unclean, as we have already assigned some TSNs etc, and
                 * maybe queued parts of this message in the queue, this should be cleaned
                 * up... */
                return SCTP_OUT_OF_RESOURCES;
            }

            dchunk = (SCTP_data_chunk*)cdata->data;

            if ((i != 1) && (i != numberOfSegments))
            {
                dchunk->chunk_flags = 0;
                bCount = SCTP_MAXIMUM_DATA_LENGTH;
                event_log (VERBOSE, "NEXT FRAGMENTED CHUNK -> MIDDLE");
            }
            else if (i == 1)
            {
                dchunk->chunk_flags = SCTP_DATA_BEGIN_SEGMENT;
                event_log (VERBOSE, "NEXT FRAGMENTED CHUNK -> BEGIN");
                bCount = SCTP_MAXIMUM_DATA_LENGTH;
            }
            else if (i == numberOfSegments)
            {
                dchunk->chunk_flags = SCTP_DATA_END_SEGMENT;
                event_log (EXTERNAL_EVENT, "NEXT FRAGMENTED CHUNK -> END");
                bCount = residual;
            }

        dchunk->chunk_id = CHUNK_DATA;
        dchunk->chunk_length = htons ((unsigned short)(bCount + FIXED_DATA_CHUNK_SIZE));
        dchunk->tsn = htonl (0);
        dchunk->stream_id = htons (streamId);
        dchunk->protocolId = protocolId;

        if (unorderedDelivery)
        {
            dchunk->stream_sn = 0;
            dchunk->chunk_flags += SCTP_DATA_UNORDERED;
        }
        else
        {   /* unordered flag not put */
            dchunk->stream_sn = htons ((unsigned short)(se->SendStreams[streamId].nextSSN));
            /* only after the last segment we increase the SSN */
            if (i == numberOfSegments) {
                se->SendStreams[streamId].nextSSN++;
                se->SendStreams[streamId].nextSSN = se->SendStreams[streamId].nextSSN % 0x10000;
            }
        }

        memcpy (dchunk->data, bufPosition, bCount);
        bufPosition += bCount * sizeof(unsigned char);

        event_logiii (EXTERNAL_EVENT, "======> SE sends fragment %d of chunk (SSN=%u, SID=%u) to FlowControl <======",
                        i, ntohs (dchunk->stream_sn),ntohs (dchunk->stream_id));

            if (!se->unreliable) lifetime = 0xFFFFFFFF;

            result = fc_send_data_chunk (cdata, destAddressIndex, lifetime, dontBundle, context);

            if (result != SCTP_SUCCESS) {
                error_logi (ERROR_MINOR, "se_ulpsend() failed with result %d", result);
                /* FIXME : Howto Propagate an Error here - Result gets overwritten on next Call */
                retVal = result;
            }
        }
    }
  return retVal;
}


/******************** Functions for Receiving **************************************/

/**
 * This function is called from distribution layer to receive a chunk.
 */
short se_ulpreceivefrom(unsigned char *buffer, unsigned int *byteCount,
                        unsigned short streamId, unsigned short* streamSN,
                        unsigned int * tsn, unsigned int* addressIndex, unsigned int flags)
{

  delivery_pdu  *d_pdu = NULL;
  unsigned int copiedBytes, residual, i;
  guint32 r_pos, r_chunk, chunk_pos, oldQueueLen = 0;


  StreamEngine* se = (StreamEngine *) mdi_readStreamEngine ();


  if (se == NULL)
    {
      error_log (ERROR_MAJOR, "Could not retrieve SE instance ");
      return SCTP_MODULE_NOT_FOUND;
    }
  if (buffer == NULL || byteCount == NULL)
    {
      error_log (ERROR_MAJOR, "Wrong Arguments : Pointers are NULL");
      return SCTP_PARAMETER_PROBLEM;
    }

  if (streamId >= se->numReceiveStreams)
    {
      error_log (ERROR_MINOR, "STREAM ID OVERFLOW");
      return (STREAM_ID_OVERFLOW);
    }
  else
    {
      event_logii (EXTERNAL_EVENT, "SE_ULPRECEIVE (sid: %u, numBytes: %u) CALLED",streamId,*byteCount);

      if (se->RecvStreams[streamId].pduList == NULL)
        {
            event_log (EXTERNAL_EVENT, "NO DATA AVAILABLE");
            return (NO_DATA_AVAILABLE);
        }
      else
        {
            oldQueueLen = se->queuedBytes;
            copiedBytes = 0;

            d_pdu = (delivery_pdu*)g_list_nth_data (se->RecvStreams[streamId].pduList, 0);

            r_pos       = d_pdu->read_position;
            r_chunk     = d_pdu->read_chunk;
            chunk_pos   = d_pdu->chunk_position;

            *streamSN   = d_pdu->ddata[d_pdu->read_chunk]->stream_sn;
            *tsn        = d_pdu->ddata[d_pdu->read_chunk]->tsn;
            *addressIndex = d_pdu->ddata[d_pdu->read_chunk]->fromAddressIndex;

            event_logiiii (VVERBOSE, "SE_ULPRECEIVE (read_position: %u, read_chunk: %u, chunk_position: %u, total_length: %u)",
                    r_pos,  r_chunk, chunk_pos, d_pdu->total_length);

            if (d_pdu->total_length - d_pdu->read_position < *byteCount)
                *byteCount = d_pdu->total_length-d_pdu->read_position;

            residual = *byteCount;

            while (copiedBytes < *byteCount) {

                if (d_pdu->ddata[d_pdu->read_chunk]->data_length - d_pdu->chunk_position > residual) {
                    event_logiii (VVERBOSE, "Copy in SE_ULPRECEIVE (residual: %u, copied bytes: %u, byteCount: %u)",
                        residual, copiedBytes,*byteCount);

                    memcpy (&buffer[copiedBytes],
                            &(d_pdu->ddata[d_pdu->read_chunk]->data)[d_pdu->chunk_position],
                            residual);

                    d_pdu->chunk_position += residual;
                    d_pdu->read_position  += residual;
                    copiedBytes           += residual;
                    residual = 0;
                } else {
                    event_logi (VVERBOSE, "Copy in SE_ULPRECEIVE (num: %u)",d_pdu->ddata[d_pdu->read_chunk]->data_length - d_pdu->chunk_position);

                    memcpy (&buffer[copiedBytes],
                            &(d_pdu->ddata[d_pdu->read_chunk]->data)[d_pdu->chunk_position],
                            d_pdu->ddata[d_pdu->read_chunk]->data_length - d_pdu->chunk_position);

                    d_pdu->read_position += (d_pdu->ddata[d_pdu->read_chunk]->data_length - d_pdu->chunk_position);
                    copiedBytes          += (d_pdu->ddata[d_pdu->read_chunk]->data_length - d_pdu->chunk_position);
                    residual             -= (d_pdu->ddata[d_pdu->read_chunk]->data_length - d_pdu->chunk_position);
                    d_pdu->chunk_position = 0;
                    d_pdu->read_chunk++;
                }
            }

            if (flags == SCTP_MSG_PEEK) {
                d_pdu->chunk_position   = chunk_pos;
                d_pdu->read_position    = r_pos;
                d_pdu->read_chunk       = r_chunk;
            } else {

               if (d_pdu->read_position >= d_pdu->total_length) {

                    se->queuedBytes -= d_pdu->total_length;

                    se->RecvStreams[streamId].pduList =
                        g_list_remove (se->RecvStreams[streamId].pduList,
                                       g_list_nth_data (se->RecvStreams[streamId].pduList, 0));
                    event_log (VERBOSE, "Remove PDU element from the SE list, and free associated memory");
                    for (i=0; i < d_pdu->number_of_chunks; i++) free(d_pdu->ddata[i]);
                    free(d_pdu->ddata);
                    free(d_pdu);
                    rxc_start_sack_timer(oldQueueLen);
                }
            }

        }

    }
    event_logi (EXTERNAL_EVENT, "ulp receives %u bytes from se", *byteCount);
    return (RECEIVE_DATA);
}


/*
 * function that gets chunks from the Lists, transforms them to PDUs, puts them
 * to the pduList, and calls DataArrive-Notification
 */
int se_doNotifications(void)
{
    int retVal;
    unsigned short i;

    StreamEngine* se = (StreamEngine *) mdi_readStreamEngine ();

    if (se == NULL) {
        error_log (ERROR_MAJOR, "Could not retrieve SE instance ");
        return SCTP_MODULE_NOT_FOUND;
    }

    event_log (INTERNAL_EVENT_0, " ================> se_doNotifications <=============== ");

    retVal = SCTP_SUCCESS;
    retVal = se_searchReadyPdu(se);

    for (i = 0; i < se->numReceiveStreams; i++)
    {
        if(se->RecvStreams[i].prePduList != NULL)
        {
            retVal = se_deliverWaiting(se, i);
        }
    }
    event_log (INTERNAL_EVENT_0, " ================> se_doNotifications: DONE <=============== ");
    return retVal;
}


 /*
 * This function is called from Receive Control to forward received chunks to Stream Engine.
 * returns an error chunk to the peer, when the maximum stream id is exceeded !
 */
int se_recvDataChunk (SCTP_data_chunk * dataChunk, unsigned int byteCount, unsigned int address_index)
{
    guint16 datalength;
    SCTP_InvalidStreamIdError error_info;
    delivery_data* d_chunk;
    StreamEngine* se = (StreamEngine *) mdi_readStreamEngine ();
    assert(se);

    event_log (INTERNAL_EVENT_0, "SE_RECVDATACHUNK CALLED");

    d_chunk = (delivery_data*)malloc (sizeof (delivery_data));
    if (d_chunk == NULL) return SCTP_OUT_OF_RESOURCES;

    datalength =  byteCount - FIXED_DATA_CHUNK_SIZE;
    d_chunk->stream_id =    ntohs (dataChunk->stream_id);

    if (d_chunk->stream_id >= se->numReceiveStreams) {
        /* return error, when numReceiveStreams is exceeded */
        error_info.stream_id = htons(d_chunk->stream_id);
        error_info.reserved = htons(0);

        scu_abort(ECC_INVALID_STREAM_ID, sizeof(error_info), (unsigned char*)&error_info);
        free(d_chunk);
        return SCTP_UNSPECIFIED_ERROR;
    }

    d_chunk->tsn = ntohl (dataChunk->tsn);     /* for efficiency */

    if (datalength <= 0) {
        scu_abort(ECC_NO_USER_DATA, sizeof(unsigned int), (unsigned char*)&(dataChunk->tsn));

        free(d_chunk);
        return SCTP_UNSPECIFIED_ERROR;
    }

    memcpy (d_chunk->data, dataChunk->data, datalength);
    d_chunk->data_length = datalength;
    d_chunk->chunk_flags = dataChunk->chunk_flags;
    d_chunk->stream_sn =    ntohs (dataChunk->stream_sn);
    d_chunk->protocolId =   dataChunk->protocolId;
    d_chunk->fromAddressIndex =  address_index;



    se->List = g_list_insert_sorted(se->List, d_chunk, (GCompareFunc) sort_tsn_se);
    se->queuedBytes += datalength;

    se->recvStreamActivated[d_chunk->stream_id] = TRUE;
    return SCTP_SUCCESS;
}

  int se_searchReadyPdu(StreamEngine* se)
{
    GList* tmp = g_list_first(se->List);
    GList* firstItem = NULL;
    delivery_data* d_chunk;
    delivery_pdu* d_pdu;
    guint32 firstTSN = 0;
    guint16 currentSID = 0;
    guint16 currentSSN = 0;
    guint16 nrOfChunks = 0;
    gboolean complete = FALSE;
    gboolean unordered = FALSE;
    int i = 0;
    guint32 itemPosition = 0;
    event_log (INTERNAL_EVENT_0, " ================> se_searchReadyPdu <=============== ");
    event_logi (VVERBOSE, "List has %u elements", g_list_length(se->List));
    for (i = 0; i < (int)se->numReceiveStreams; i++) {
        se->RecvStreams[i].highestSSN = 0;
        se->RecvStreams[i].highestSSNused = FALSE;
    }

    while(tmp != NULL)
    {
        d_chunk = (delivery_data*)(tmp->data);
        event_logiii(VVERBOSE, "Handling Packet with TSN: %u, SSN: %u, SID: %u", d_chunk->tsn, d_chunk->stream_sn, d_chunk->stream_id);

        currentSID = d_chunk->stream_id;
        currentSSN = d_chunk->stream_sn;
        unordered = (d_chunk->chunk_flags & SCTP_DATA_UNORDERED);

        if((se->RecvStreams[currentSID].highestSSNused) && (sAfter(se->RecvStreams[currentSID].highestSSN, currentSSN)))
        {
            error_logi(VERBOSE, "Wrong ssn and tsn order", d_chunk->stream_sn);
            scu_abort(ECC_PROTOCOL_VIOLATION, 0, NULL);
            return SCTP_UNSPECIFIED_ERROR;
        }
        if(!unordered)
        {
            se->RecvStreams[currentSID].highestSSN = currentSSN;
            se->RecvStreams[currentSID].highestSSNused = TRUE;
        }


        if(d_chunk->chunk_flags & SCTP_DATA_BEGIN_SEGMENT)
        {
            event_log (VVERBOSE, "Found Begin Segment");

            nrOfChunks = 1;
            firstItem = tmp;
            firstTSN = d_chunk->tsn;

            if((sBefore(currentSSN, se->RecvStreams[currentSID].nextSSN)) || (currentSSN == se->RecvStreams[currentSID].nextSSN) || (d_chunk->chunk_flags & SCTP_DATA_UNORDERED))
            {

                if(d_chunk->chunk_flags & SCTP_DATA_END_SEGMENT)
                {
                    event_log (VVERBOSE, "Complete PDU found");
                    complete = TRUE;
                }


                while((tmp != NULL) && (!complete))
                {
                    nrOfChunks++;
                    event_logi (VVERBOSE, "Handling chunk nr: %u", nrOfChunks);

                    tmp = g_list_next(tmp);
                    if(tmp == NULL) break;
                    d_chunk = (delivery_data*)(tmp->data);
                    event_logiii(VVERBOSE, "Handling Packet with TSN: %u, SSN: %u, SID: %u", d_chunk->tsn, d_chunk->stream_sn, d_chunk->stream_id);


                    if((d_chunk->stream_id == currentSID)
                        && ((d_chunk->stream_sn == currentSSN) || unordered)
                        && (firstTSN + nrOfChunks - 1 == d_chunk->tsn))
                    {
                        if(d_chunk->chunk_flags & SCTP_DATA_BEGIN_SEGMENT)
                        {
                            error_logi(VERBOSE, "Multiple Begins found with SSN: %u", d_chunk->stream_sn);
                            scu_abort(ECC_PROTOCOL_VIOLATION, 0, NULL);
                            return SCTP_UNSPECIFIED_ERROR;
                        }
                        else if((d_chunk->chunk_flags & SCTP_DATA_UNORDERED) != unordered)
                        {
                            error_logi(VERBOSE, "Mix Ordered and unordered Segments found with SSN: %u", d_chunk->stream_sn);
                            scu_abort(ECC_PROTOCOL_VIOLATION, 0, NULL);
                            return SCTP_UNSPECIFIED_ERROR;
                        }
                        else if(d_chunk->chunk_flags & SCTP_DATA_END_SEGMENT)
                        {
                            event_log (VVERBOSE, "Complete PDU found");
                            complete = TRUE;
                        }
                    }
                    else
                    {
                        if(firstTSN + nrOfChunks - 1 == d_chunk->tsn)
                        {
                            error_logi(VERBOSE, "Data without end segment found", d_chunk->stream_sn);
                            scu_abort(ECC_PROTOCOL_VIOLATION, 0, NULL);
                            return SCTP_UNSPECIFIED_ERROR;
                        }
                        event_log (VVERBOSE, "Abort current ssn search - Incomplete!");
                        break;
                    }


                }
                if(complete)
                {
                      event_log (VVERBOSE, "handling complete PDU");

                      d_pdu = (delivery_pdu*)malloc(sizeof(delivery_pdu));
                      if (d_pdu == NULL) {
                          return SCTP_OUT_OF_RESOURCES;
                      }
                      d_pdu->number_of_chunks = nrOfChunks;
                      d_pdu->read_position = 0;

                      d_pdu->read_chunk = 0;
                      d_pdu->chunk_position = 0;
                      d_pdu->total_length = 0;

                      d_pdu->ddata = (delivery_data**)malloc(nrOfChunks*sizeof(delivery_data*));
                      if (d_pdu->ddata == NULL) {
                          free(d_pdu);
                          return SCTP_OUT_OF_RESOURCES;
                      }

                      tmp = firstItem;
                      itemPosition = g_list_position(se->List, tmp);

                      /* get pointers to the first chunks and put them into the pduList */
                      for (i = 0; i < nrOfChunks; ++i) {
                          d_pdu->ddata[i] = (delivery_data*)(tmp->data);
                          d_pdu->total_length += d_pdu->ddata[i]->data_length;
                          tmp = g_list_next(tmp);
                      }
                      if(!unordered && (se->RecvStreams[d_pdu[0].ddata[0]->stream_id].nextSSN == currentSSN))
                           se->RecvStreams[d_pdu[0].ddata[0]->stream_id].nextSSN++;

                      se->RecvStreams[d_pdu[0].ddata[0]->stream_id].prePduList = g_list_append(se->RecvStreams[d_pdu[0].ddata[0]->stream_id].prePduList, d_pdu);
                      /* remove chunks from the list and return */
                      for (i = 1; i <= nrOfChunks; i++)
                      {
                           se->List = g_list_remove(se->List, g_list_nth_data(se->List, itemPosition ));
                           event_logiii(VERBOSE, "Removing chunk nr: %u(%u) list size after remove: %u", i,itemPosition, g_list_length(se->List));

                      }
                      tmp = g_list_nth(se->List, itemPosition);
                      nrOfChunks = 0;
                      firstItem = NULL;
                      firstTSN = 0;
                      currentSID = 0;
                      currentSSN = 0;
                      complete = FALSE;
                      continue;
                }
                else
                {
                    nrOfChunks = 0;
                    firstItem = NULL;
                    firstTSN = 0;
                    currentSID = 0;
                    currentSSN = 0;
                    continue;
                }
            }
            else
            {
                event_log (VVERBOSE, "No begin chunk!");

                nrOfChunks = 0;
                firstItem = NULL;
                firstTSN = 0;
                currentSID = 0;
                currentSSN = 0;
            }

        }
        if(tmp != NULL)
            tmp = g_list_next(tmp);
    }
    event_log (INTERNAL_EVENT_0, " ================> se_searchReadyPdu Finished <=============== ");

    return SCTP_SUCCESS;
}


int se_deliverWaiting(StreamEngine* se, unsigned short sid)
{
    GList* waitingListItem = g_list_first(se->RecvStreams[sid].prePduList);
    delivery_pdu* d_pdu;

    while(waitingListItem != NULL)
    {
        d_pdu = (delivery_pdu*)waitingListItem->data;
        se->RecvStreams[sid].pduList = g_list_append(se->RecvStreams[sid].pduList, d_pdu);
        mdi_dataArriveNotif(sid, d_pdu->total_length, d_pdu->ddata[0]->stream_sn, d_pdu->ddata[0]->tsn,
                                d_pdu->ddata[0]->protocolId, (d_pdu->ddata[0]->chunk_flags & SCTP_DATA_UNORDERED) ? 1 : 0);
        if(waitingListItem != NULL)
            waitingListItem = g_list_next(waitingListItem);
    }
    g_list_free(se->RecvStreams[sid].prePduList);
    se->RecvStreams[sid].prePduList = NULL;
    return SCTP_SUCCESS;
}



/**
 * function to return the number of chunks that can be retrieved
 * by the ULP - this function may need to be refined !!!!!!
 */
guint32 se_numOfQueuedChunks ()
{
  guint32 i, num_of_chunks = 0;
  StreamEngine* se = (StreamEngine *) mdi_readStreamEngine ();

  if (se == NULL)
    {
      error_log (ERROR_MAJOR, "Could not read StreamEngine Instance !");
      return 0xFFFFFFFF;
    }

  for (i = 0; i < se->numReceiveStreams; i++)
    {
      /* Add number of all chunks (i.e. lengths of all pduList lists of all streams */
      num_of_chunks += g_list_length (se->RecvStreams[i].pduList);
    }
  return num_of_chunks;
}



/**
 * function to return the number of streams that we may
 * send on
 */
guint16
se_numOfSendStreams ()
{
  StreamEngine* se = (StreamEngine *) mdi_readStreamEngine ();
  if (se == NULL)
    {
      error_log (ERROR_MAJOR, "Could not read StreamEngine Instance !");
      return 0;
    }
  return (guint16) (se->numSendStreams);

}

/**
 * function to return the number of streams that we are allowed to
 * receive data on
 */
guint16
se_numOfRecvStreams ()
{
  StreamEngine* se = (StreamEngine *) mdi_readStreamEngine ();
  if (se == NULL)
    {
      error_log (ERROR_MAJOR, "Could not read StreamEngine Instance !");
      return 0;
    }

  return (guint16) (se->numReceiveStreams);

}


int se_deliver_unreliably(unsigned int up_to_tsn, SCTP_forward_tsn_chunk* chk)
{
    int i;
    int numOfSkippedStreams;
    unsigned short skippedStream, skippedSSN;
    pr_stream_data* psd;
    GList* tmp;
    delivery_data  *d_chunk = NULL;

    StreamEngine* se = (StreamEngine *) mdi_readStreamEngine();
    if (se == NULL) {
        error_log (ERROR_MAJOR, "Could not read StreamEngine Instance !");
        return SCTP_MODULE_NOT_FOUND;
    }

    numOfSkippedStreams = (ntohs(chk->chunk_header.chunk_length) -
                          sizeof(unsigned int) - sizeof(SCTP_chunk_header)) / sizeof(pr_stream_data);

    if (se->unreliable == TRUE) {
        /* TODO: optimization !!!! loop through all streams */
        for (i = 0; i < numOfSkippedStreams; i++)
        {
            psd = (pr_stream_data*) &chk->variableParams[sizeof(pr_stream_data)*i];
            skippedStream = ntohs(psd->stream_id);
            skippedSSN = ntohs(psd->stream_sn);
            event_logiii (VERBOSE, "delivering dangling messages in stream %d for forward_tsn=%u, SSN=%u",
                        skippedStream, up_to_tsn, skippedSSN);
            /* if unreliable, check if messages can be  delivered */
            se->RecvStreams[skippedStream].nextSSN = skippedSSN + 1;
        }
        se_doNotifications();

        tmp = g_list_first(se->List);
        while((tmp != NULL) && (((delivery_data*)(tmp->data))->tsn <= up_to_tsn))
        {
             d_chunk = (delivery_data*)(tmp->data);

             se->List = g_list_remove (se->List, d_chunk);
             se->queuedBytes -= d_chunk->data_length;
             free(d_chunk);
             tmp = g_list_first(se->List);
        }
    }
    return SCTP_SUCCESS;
}

int se_getQueuedBytes(void)
{
    StreamEngine* se = (StreamEngine *) mdi_readStreamEngine ();
    if (se == NULL) {
        error_log (ERROR_MAJOR, "Could not read StreamEngine Instance !");
        return -1;
    }
    return (int)se->queuedBytes;
}

