/* $Id$
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
 * Copyright (C) 2004-2016 Thomas Dreibholz
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

#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>         /* for atoi() under Linux */
#include <time.h>
#include "sctp_wrapper.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define ECHO_PORT                             7
#define DISCARD_PORT                          9
#define DAYTIME_PORT                         13
#define CHARGEN_PORT                         19

#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES    10
#define MAXIMUM_NUMBER_OF_IN_STREAMS         17
#define MAXIMUM_NUMBER_OF_OUT_STREAMS        17
#define MAXIMUM_PAYLOAD_LENGTH             8192
#define BUFFER_LENGTH                      1024
#define SEND_QUEUE_SIZE                     100

#ifndef min
#define min(x,y)            (x)<(y)?(x):(y)
#endif

struct ulp_data {
    int maximumStreamID;
    int ShutdownReceived;
};

static unsigned char localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned short noOfLocalAddresses      = 0;

static int verbose                            = 0;
static int vverbose                           = 0;
static int unknownCommand                     = 0;
static int sendOOTBAborts                     = 1;
static int timeToLive                         = SCTP_INFINITE_LIFETIME;

const char *
pathStateName(unsigned int state)
{
    switch (state) {
        case SCTP_PATH_OK:
            return "REACHABLE";
            break;
        case SCTP_PATH_UNREACHABLE:
            return "UNREACHABLE";
            break;
        case SCTP_PATH_ADDED:
            return "ADDED";
            break;
        case SCTP_PATH_REMOVED:
            return "REMOVED";
            break;
        case SCTP_PATH_CONFIRMED:
            return "CONFIRMED";
            break;
        case SCTP_PATH_UNCONFIRMED:
            return "UNCONFIRMED";
            break;
        default:
            return "UNKNOWN";
            break;
    }
}

void printUsage(void)
{
    printf("Usage:   combined_server [options]\n");
    printf("options:\n");
    printf("-i       ignore OOTB packets\n");
    printf("-s       source address\n");
    printf("-t       time to live in ms\n");
    printf("-v       verbose mode\n");
    printf("-V       very verbose mode\n");
}

void getArgs(int argc, char **argv)
{
    int i;
    char *opt;

    for(i=1; i < argc ;i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'h':
                  printUsage();
                  exit(0);
                case 's':
                  if (i+1 >= argc) {
                     printUsage();
                     exit(0);
                  }
                  opt = argv[++i];
                  if ((noOfLocalAddresses < MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES) && (strlen(opt) < SCTP_MAX_IP_LEN  )) {
                     strcpy((char *)localAddressList[noOfLocalAddresses], opt);
                     noOfLocalAddresses++;
                  };
                break;
                case 'i':
                  sendOOTBAborts = 0;
                  break;
                case 't':
                  if (i+1 >= argc) {
                     printUsage();
                     exit(0);
                  }
                  opt=argv[++i];
                  timeToLive = atoi(opt);
                break;
                case 'v':
                  verbose = 1;
                break;
                case 'V':
                  verbose = 1;
                  vverbose = 1;
                break;
                default:
                  unknownCommand = 1;
                break;
         }
        }
      else
         unknownCommand = 1;
    }
}

void checkArgs(void)
{
    int abortProgram;
    int printUsageInfo;

    abortProgram = 0;
    printUsageInfo = 0;

    if (noOfLocalAddresses == 0) {
#ifdef HAVE_IPV6
        strcpy((char *)localAddressList[noOfLocalAddresses], "::0");
#else
        strcpy((char *)localAddressList[noOfLocalAddresses], "0.0.0.0");
#endif
        noOfLocalAddresses++;
    }
    if (unknownCommand ==1) {
         printf("Error:   Unkown options in command.\n");
         printUsageInfo = 1;
    }

    if (printUsageInfo == 1)
        printUsage();
    if (abortProgram == 1)
        exit(-1);
}

void echoDataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int len,
                         unsigned short streamSN, unsigned int TSN, unsigned int protoID, unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
    unsigned int length;
    unsigned short ssn;
    unsigned int tsn;

    if (vverbose) {
      fprintf(stdout, "%-8x: Data arrived (%u bytes on stream %u, %s)\n",
                      assocID, len, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
      fflush(stdout);
    }
    /* read it */
    length = MAXIMUM_PAYLOAD_LENGTH;
    SCTP_receive(assocID, streamID, chunk, &length, &ssn, &tsn, SCTP_MSG_DEFAULT);
    /* and send it */
    SCTP_send(assocID,
              (unsigned short)min(streamID, ((struct ulp_data *) ulpDataPtr)->maximumStreamID),
              chunk, length,
              protoID,
              SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive, unordered, SCTP_BUNDLING_DISABLED);
}

void dataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int len,
                     unsigned short streamSN, unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
    unsigned int length;
    unsigned short ssn;
    unsigned int tsn;

    if (vverbose) {
      fprintf(stdout, "%-8x: Data arrived (%u bytes on stream %u, %s)\n",
                      assocID, len, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
      fflush(stdout);
    }
    /* read it */
    length = MAXIMUM_PAYLOAD_LENGTH;
    SCTP_receive(assocID, streamID, chunk, &length, &ssn, &tsn, SCTP_MSG_DEFAULT);
}

void sendFailureNotif(unsigned int assocID,
                      unsigned char *unsent_data, unsigned int dataLength, unsigned int *context, void* dummy)
{
  if (verbose) {
    fprintf(stdout, "%-8x: Send failure\n", assocID);
    fflush(stdout);
  }
}

void networkStatusChangeNotif(unsigned int assocID, short affectedPathID, unsigned short newState, void* ulpDataPtr)
{
    SCTP_AssociationStatus assocStatus;
    SCTP_PathStatus pathStatus;
    unsigned short pathID;

    if (verbose) {
        SCTP_getPathStatus(assocID, affectedPathID, &pathStatus);
        fprintf(stdout, "%-8x: Network status change: path %u (towards %s) is now %s\n",
                        assocID, affectedPathID,
                        pathStatus.destinationAddress,
                        pathStateName(newState));
        fflush(stdout);
    }

    /* if the primary path has become inactive */
    if ((newState == SCTP_PATH_UNREACHABLE) &&
        (affectedPathID == SCTP_getPrimary(assocID))) {

        /* select a new one */
        SCTP_getAssocStatus(assocID, &assocStatus);
        for (pathID=0; pathID < assocStatus.numberOfAddresses; pathID++){
            SCTP_getPathStatus(assocID, pathID, &pathStatus);
            if (pathStatus.state == SCTP_PATH_OK)
                break;
        }

        /* and use it */
        if (pathID < assocStatus.numberOfAddresses) {
            SCTP_setPrimary(assocID, pathID);
        }
    }
}


void* echoCommunicationUpNotif(unsigned int assocID, int status,
                               unsigned int noOfPaths,
                               unsigned short noOfInStreams, unsigned short noOfOutStreams,
                               int associationSupportsPRSCTP, void* dummy)
{
    struct ulp_data *ulpDataPtr;
    SCTP_PathStatus pathStatus;
    unsigned int i;

    if (verbose) {
        fprintf(stdout, "%-8x: Communication up (%u paths)\n", assocID, noOfPaths);
        fflush(stdout);
    }

    if (vverbose) {
        for (i=0; i < noOfPaths; i++) {
            SCTP_getPathStatus(assocID, (short)i, &pathStatus);
            fprintf(stdout, "%-8x: Path Status of path %u (towards %s): %s.\n", assocID, i, pathStatus.destinationAddress, pathStateName(pathStatus.state));
        }
    }

    ulpDataPtr                   = (struct ulp_data*)malloc(sizeof(struct ulp_data));
    ulpDataPtr->maximumStreamID  = noOfOutStreams - 1;
    ulpDataPtr->ShutdownReceived = 0;
    return((void *) ulpDataPtr);
}

void* daytimeCommunicationUpNotif(unsigned int assocID, int status,
                                  unsigned int noOfPaths,
                                  unsigned short noOfInStreams, unsigned short noOfOutStreams,
                                  int associationSupportsPRSCTP, void* dummy)
{
    char *timeAsString;
    time_t now;
    SCTP_PathStatus pathStatus;
    unsigned int i;

    if (verbose) {
        fprintf(stdout, "%-8x: Communication up (%u paths)\n", assocID, noOfPaths);
        fflush(stdout);
    }

    if (vverbose) {
        for (i=0; i < noOfPaths; i++) {
            SCTP_getPathStatus(assocID, (short)i, &pathStatus);
            fprintf(stdout, "%-8x: Path Status of path %u (towards %s): %s.\n", assocID, i, pathStatus.destinationAddress, pathStateName(pathStatus.state));
        }
    }

    /* get the current time and convert to string */
    time(&now);
    timeAsString = ctime(&now);

    if (vverbose) {
        fprintf(stdout, "%-8x: Current Time: %s", assocID, timeAsString);
        fflush(stdout);
    }

    SCTP_send(assocID,
              0,
              (unsigned char *)timeAsString, strlen(timeAsString),
              SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
              SCTP_USE_PRIMARY, SCTP_NO_CONTEXT,
             timeToLive, SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED);

    SCTP_shutdown(assocID);

    return NULL;
}

void* chargenCommunicationUpNotif(unsigned int assocID, int status,
                                  unsigned int noOfPaths,
                                  unsigned short noOfInStreams, unsigned short noOfOutStreams,
                                  int associationSupportsPRSCTP, void* dummy)
{
    int length;
    unsigned char buffer[BUFFER_LENGTH];
    struct ulp_data *ulpDataPtr;
    SCTP_PathStatus pathStatus;
    unsigned int i;

    if (verbose) {
        fprintf(stdout, "%-8x: Communication up (%u paths)\n", assocID, noOfPaths);
        fflush(stdout);
    }

    if (vverbose) {
        for (i=0; i < noOfPaths; i++) {
            SCTP_getPathStatus(assocID, (short)i, &pathStatus);
            fprintf(stdout, "%-8x: Path Status of path %u (towards %s): %s.\n", assocID, i, pathStatus.destinationAddress, pathStateName(pathStatus.state));
        }
    }

    length = 1 + (rand() % 512);
    memset((void *)buffer, 'A', length);
    buffer[length-1] = '\n';

    while(SCTP_send(assocID, 0, buffer, length, SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                    SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive,
                    SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED) == SCTP_SUCCESS) {
      if (vverbose) {
          fprintf(stdout, "%-8x: %u bytes sent.\n", assocID, length);
          fflush(stdout);
      }
      length = 1 + (rand() % 512);
      memset(buffer, 'A', length);
      buffer[length-1] = '\n';
    }
    ulpDataPtr                   = (struct ulp_data*)malloc(sizeof(struct ulp_data));
    ulpDataPtr->maximumStreamID  = noOfOutStreams - 1;
    ulpDataPtr->ShutdownReceived = 0;
    return((void *) ulpDataPtr);
}

void* discardCommunicationUpNotif(unsigned int assocID, int status,
                                  unsigned int noOfPaths,
                                  unsigned short noOfInStreams, unsigned short noOfOutStreams,
                                  int associationSupportsPRSCTP, void* dummy)
{
    SCTP_PathStatus pathStatus;
    unsigned int i;

    if (verbose) {
        fprintf(stdout, "%-8x: Communication up (%u paths)\n", assocID, noOfPaths);
        fflush(stdout);
    }

    if (vverbose) {
        for (i=0; i < noOfPaths; i++) {
            SCTP_getPathStatus(assocID, (short)i, &pathStatus);
            fprintf(stdout, "%-8x: Path Status of path %u (towards %s): %s.\n", assocID, i, pathStatus.destinationAddress, pathStateName(pathStatus.state));
        }
    }

    return NULL;
}

void communicationLostNotif(unsigned int assocID, unsigned short status, void* ulpDataPtr)
{
    unsigned char buffer[SCTP_MAXIMUM_DATA_LENGTH];
    unsigned int bufferLength;
    unsigned short streamID, streamSN;
    unsigned int protoID;
    unsigned int tsn;

    if (verbose) {
        fprintf(stdout, "%-8x: Communication lost (status %u)\n", assocID, status);
        fflush(stdout);
    }

    /* retrieve data */
    bufferLength = sizeof(buffer);
    while (SCTP_receiveUnsent(assocID, buffer, &bufferLength, &tsn,
                              &streamID, &streamSN, &protoID) >= 0){
        if (vverbose) {
            fprintf(stdout, "%-8x: Retrieved unsent chunk with %u bytes (SSN %u, SID %u)\n", assocID,bufferLength,streamSN,streamID );
            fflush(stdout);
        }
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }

    bufferLength = sizeof(buffer);
    while (SCTP_receiveUnacked(assocID, buffer, &bufferLength, &tsn,
                               &streamID, &streamSN, &protoID) >= 0){
        /* do something with the retrieved data */
        if (vverbose) {
            fprintf(stdout, "%-8x: Retrieved unacked chunk with %u bytes (SSN %u, SID %u)\n", assocID,bufferLength,streamSN,streamID );
            fflush(stdout);
        }
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }

    /* delete the association */
    if (ulpDataPtr)
        free((struct ulp_data *) ulpDataPtr);

    SCTP_deleteAssociation(assocID);
}

void communicationErrorNotif(unsigned int assocID, unsigned short status, void* dummy)
{
  if (verbose) {
    fprintf(stdout, "%-8x: Communication error (status %u)\n", assocID, status);
    fflush(stdout);
  }
}

void chargenRestartNotif(unsigned int assocID, void* ulpDataPtr)
{
    unsigned int length;
    unsigned char buffer[BUFFER_LENGTH];

    if (verbose) {
        fprintf(stdout, "%-8x: Restart\n", assocID);
        fflush(stdout);
    }

    length = 1 + (rand() % 512);
    memset((void *) buffer, 'A', length);
    buffer[length-1] = '\n';

    while((!(((struct ulp_data *)ulpDataPtr)->ShutdownReceived)) &&
          (SCTP_send(assocID, 0, buffer, length, SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                     SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive,
                     SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED) == SCTP_SUCCESS)) {
      if (vverbose) {
          fprintf(stdout, "%-8x: %u bytes sent.\n", assocID, length);
          fflush(stdout);
      }
      length = 1 + (rand() % 512);
      memset(buffer, 'A', length);
      buffer[length-1] = '\n';
    }
}

void echoRestartNotif(unsigned int assocID, void* ulpDataPtr)
{
    SCTP_AssociationStatus assocStatus;

    if (verbose) {
        fprintf(stdout, "%-8x: Restart\n", assocID);
        fflush(stdout);
    }

    SCTP_getAssocStatus(assocID, &assocStatus);

    /* update ULP data */
    ((struct ulp_data *) ulpDataPtr)->maximumStreamID = assocStatus.outStreams - 1;
}

void restartNotif(unsigned int assocID, void* ulpDataPtr)
{
    if (verbose) {
        fprintf(stdout, "%-8x: Restart\n", assocID);
        fflush(stdout);
    }
}

void shutdownCompleteNotif(unsigned int assocID, void* ulpDataPtr)
{
  if (verbose) {
    fprintf(stdout, "%-8x: Shutdown complete\n", assocID);
    fflush(stdout);
  }
  if (ulpDataPtr)
    free((struct ulp_data *) ulpDataPtr);

  SCTP_deleteAssociation(assocID);
}

void queueStatusChangeNotif(unsigned int assocID, int queueType, int queueID, int queueLength, void* ulpDataPtr)
{
    if (vverbose) {
        fprintf(stdout, "%-8x: Queue status change notification: Type %d, ID %d, Length %d\n",
                        assocID, queueType, queueID, queueLength);
        fflush(stdout);
    }
}

void chargenQueueStatusChangeNotif(unsigned int assocID, int queueType, int queueID, int queueLength, void* ulpDataPtr)
{
    unsigned int length;
    unsigned char buffer[BUFFER_LENGTH];

    if (vverbose) {
        fprintf(stdout, "%-8x: Queue status change notification: Type %d, ID %d, Length %d\n",
                        assocID, queueType, queueID, queueLength);
        fflush(stdout);
    }

    if (queueType == SCTP_SEND_QUEUE) {
      length = 1 + (rand() % 512);
      memset((void *)buffer, 'A', length);
      buffer[length-1] = '\n';

      while((!(((struct ulp_data *)ulpDataPtr)->ShutdownReceived)) &&
            (SCTP_send(assocID, 0, buffer, length, SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                       SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive,
                       SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED) == SCTP_SUCCESS)) {
        if (vverbose) {
            fprintf(stdout, "%-8x: %u bytes sent.\n", assocID, length);
            fflush(stdout);
        }
        length = 1 + (rand() % 512);
        memset(buffer, 'A', length);
        buffer[length-1] = '\n';
      }
    }
}

void shutdownReceivedNotif(unsigned int assocID, void* ulpDataPtr)
{
    if (verbose) {
        fprintf(stdout, "%-8x: Shutdown received\n", assocID);
        fflush(stdout);
    }
    if (ulpDataPtr)
        ((struct ulp_data *)ulpDataPtr)->ShutdownReceived = 1;
}

int main(int argc, char **argv)
{
    SCTP_ulpCallbacks echoUlp, discardUlp, daytimeUlp, chargenUlp;
    SCTP_LibraryParameters params;
    SCTP_InstanceParameters instanceParameters;
    int sctpInstance;

    /* initialize the echo_ulp variable */
    echoUlp.dataArriveNotif              = &echoDataArriveNotif;
    echoUlp.sendFailureNotif             = &sendFailureNotif;
    echoUlp.networkStatusChangeNotif     = &networkStatusChangeNotif;
    echoUlp.communicationUpNotif         = &echoCommunicationUpNotif;
    echoUlp.communicationLostNotif       = &communicationLostNotif;
    echoUlp.communicationErrorNotif      = &communicationErrorNotif;
    echoUlp.restartNotif                 = &echoRestartNotif;
    echoUlp.shutdownCompleteNotif        = &shutdownCompleteNotif;
    echoUlp.queueStatusChangeNotif       = &queueStatusChangeNotif;
    echoUlp.peerShutdownReceivedNotif    = &shutdownReceivedNotif;

    /* initialize the discard_ulp variable */
    discardUlp.dataArriveNotif           = &dataArriveNotif;
    discardUlp.sendFailureNotif          = &sendFailureNotif;
    discardUlp.networkStatusChangeNotif  = &networkStatusChangeNotif;
    discardUlp.communicationUpNotif      = &discardCommunicationUpNotif;
    discardUlp.communicationLostNotif    = &communicationLostNotif;
    discardUlp.communicationErrorNotif   = &communicationErrorNotif;
    discardUlp.restartNotif              = &restartNotif;
    discardUlp.shutdownCompleteNotif     = &shutdownCompleteNotif;
    discardUlp.queueStatusChangeNotif    = &queueStatusChangeNotif;
    discardUlp.peerShutdownReceivedNotif = &shutdownReceivedNotif;

    /* initialize the daytime_ulp variable */
    daytimeUlp.dataArriveNotif           = &dataArriveNotif;
    daytimeUlp.sendFailureNotif          = &sendFailureNotif;
    daytimeUlp.networkStatusChangeNotif  = &networkStatusChangeNotif;
    daytimeUlp.communicationUpNotif      = &daytimeCommunicationUpNotif;
    daytimeUlp.communicationLostNotif    = &communicationLostNotif;
    daytimeUlp.communicationErrorNotif   = &communicationErrorNotif;
    daytimeUlp.restartNotif              = &restartNotif;
    daytimeUlp.shutdownCompleteNotif     = &shutdownCompleteNotif;
    daytimeUlp.queueStatusChangeNotif    = &queueStatusChangeNotif;
    daytimeUlp.peerShutdownReceivedNotif = &shutdownReceivedNotif;

    /* initialize the chargen_ulp variable */
    chargenUlp.dataArriveNotif           = &dataArriveNotif;
    chargenUlp.sendFailureNotif          = &sendFailureNotif;
    chargenUlp.networkStatusChangeNotif  = &networkStatusChangeNotif;
    chargenUlp.communicationUpNotif      = &chargenCommunicationUpNotif;
    chargenUlp.communicationLostNotif    = &communicationLostNotif;
    chargenUlp.communicationErrorNotif   = &communicationErrorNotif;
    chargenUlp.restartNotif              = &chargenRestartNotif;
    chargenUlp.shutdownCompleteNotif     = &shutdownCompleteNotif;
    chargenUlp.queueStatusChangeNotif    = &chargenQueueStatusChangeNotif;
    chargenUlp.peerShutdownReceivedNotif = &shutdownReceivedNotif;

    /* handle all command line options */
    getArgs(argc, argv);
    checkArgs();

    SCTP_initLibrary();
    SCTP_getLibraryParameters(&params);
    params.sendOotbAborts    = sendOOTBAborts;
    params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_CRC32C;
    SCTP_setLibraryParameters(&params);

    /* set up the "server" */
    SCTP_registerInstance(ECHO_PORT,
                          MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                          noOfLocalAddresses, localAddressList,
                          echoUlp);

    SCTP_registerInstance(DISCARD_PORT,
                          MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                          noOfLocalAddresses, localAddressList,
                          discardUlp);

    SCTP_registerInstance(DAYTIME_PORT,
                          MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                          noOfLocalAddresses, localAddressList,
                          daytimeUlp);

    sctpInstance = SCTP_registerInstance(CHARGEN_PORT,
                                         MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                                         noOfLocalAddresses, localAddressList,
                                         chargenUlp);

    SCTP_getAssocDefaults((unsigned short)sctpInstance, &instanceParameters);
    instanceParameters.maxSendQueue = SEND_QUEUE_SIZE;
    SCTP_setAssocDefaults((unsigned short)sctpInstance, &instanceParameters);

    /* run the event handler forever */
    while (1) {
        SCTP_eventLoop();
    }

    /* this will never be reached */
    exit(0);
}
