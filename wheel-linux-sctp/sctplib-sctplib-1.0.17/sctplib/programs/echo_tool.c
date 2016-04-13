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

#include "sctp_wrapper.h"

#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>         /* for atoi() under Linux */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define ECHO_PORT                             7
#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES    10
#define MAXIMUM_NUMBER_OF_ASSOCIATIONS        5
#define MAXIMUM_NUMBER_OF_IN_STREAMS         17
#define MAXIMUM_NUMBER_OF_OUT_STREAMS        17
#define MAXIMUM_PAYLOAD_LENGTH             8192

#ifndef min
#define min(x,y)            (x)<(y)?(x):(y)
#endif

struct ulp_data {
    int maximumStreamID;
    unsigned int assocID;
    unsigned long nrOfReceivedChunks;
    unsigned long nrOfReceivedBytes;
    int ShutdownReceived;
};

static struct ulp_data ulpData[MAXIMUM_NUMBER_OF_ASSOCIATIONS];
static unsigned char localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned char destinationAddress[SCTP_MAX_IP_LEN];

static unsigned short localPort               = 7;
static unsigned short remotePort              = 7;
static unsigned short noOfLocalAddresses      = 0;
static unsigned short numberOfInitialPackets  = 0;
static unsigned short chunkLength             = 512;
static unsigned char  tosByte                 = 0x10;  /* IPTOS_LOWDELAY */
static unsigned int doMeasurements            = 0;
static unsigned int doAllMeasurements         = 0;
static int verbose                            = 0;
static int vverbose                           = 0;
static int unknownCommand                     = 0;
static unsigned int deltaT                    = 1000;
static int rotateStreams                      = 0;
static int sendToAll                          = 0;
static int startAssociation                   = 0;
static int sendUnordered                      = 0;
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
    printf("usage:   echo_tool [options]\n");
    printf("options:\n");
    printf("-a                  use all streams in a round robin fashion when injecting packets\n");
    printf("-b                  send back incoming data on all existing associations\n");
    printf("-d destination_addr establish a association with the specified address\n");
    printf("-l length           number of bytes of the payload when generating traffic (default 512)\n");
    printf("-m                  print number of received bytes and chunks per period (see -p)\n");
    printf("-M                  print number of received bytes, chunks per period (see -p) and flow control info\n");
    printf("-n number           number of packets initially send out (default 0)\n");
    printf("-p period           period for the measurements in milliseconds (default 1000)\n");
    printf("-q byte             TOS byte used by all assiciations (default 0x10)\n");
    printf("-r port             remote port number (default echo port\n");
    printf("-s                  source address\n");
    printf("-t                  time to live in ms\n");
    printf("-i                  ignore OOTB packets\n");
    printf("-u                  inject the initial packets unordered\n");
    printf("-v                  verbose mode\n");
    printf("-V                  very verbose mode\n");
}

void getArgs(int argc, char **argv)
{
    int i;
    char *opt;

    for(i=1; i < argc ;i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'a':
                    rotateStreams = 1;
                    break;
                case 'b':
                    sendToAll = 1;
                    break;
                case 'd':
                    if (i+1 >= argc) {
                        printUsage();
                        exit(0);
                    }
                    opt = argv[++i];
                    if (strlen(opt) < SCTP_MAX_IP_LEN) {
                        strcpy((char *)destinationAddress, opt);
                        startAssociation = 1;
                    }
                    break;
                case 'l':
                    if (i+1 >= argc) {
                        printUsage();
                        exit(0);
                    }
                    opt = argv[++i];
                    chunkLength = min(atoi(opt),MAXIMUM_PAYLOAD_LENGTH);
                    break;
                case 'm':
                    doMeasurements = 1;
                    break;
                case 'M':
                    doMeasurements = 1;
                    doAllMeasurements = 1;
                    break;
                case 'n':
                    if (i+1 >= argc) {
                        printUsage();
                        exit(0);
                    }
                    opt = argv[++i];
                    numberOfInitialPackets = atoi(opt);
                    break;
                case 'o':
                    if (i+1 >= argc) {
                        printUsage();
                        exit(0);
                    }
                    opt = argv[++i];
                    localPort = (unsigned short)atoi(opt);
                    break;
                case 'p':
                    if (i+1 >= argc) {
                        printUsage();
                        exit(0);
                    }
                    opt = argv[++i];
                    deltaT = atoi(opt);
                    break;
                case 'q':
                    if (i+1 >= argc) {
                        printUsage();
                        exit(0);
                    }
                    opt = argv[++i];
                    tosByte = (unsigned char) atoi(opt);
                    break;
                case 'r':
                    if (i+1 >= argc) {
                        printUsage();
                        exit(0);
                    }
                    opt = argv[++i];
                    remotePort =  atoi(opt);
                    break;
                case 's':
                    if (i+1 >= argc) {
                        printUsage();
                        exit(0);
                    }
                    opt = argv[++i];
                    if ((noOfLocalAddresses < MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES) &&
                        (strlen(opt) < SCTP_MAX_IP_LEN  )) {
                        strcpy((char *)localAddressList[noOfLocalAddresses], opt);
                        noOfLocalAddresses++;
                    }
                    break;
                case 't':
                    if (i+1 >= argc) {
                        printUsage();
                        exit(0);
                    }
                    opt = argv[++i];
                    timeToLive = atoi(opt);
                    break;
                case 'i':
                    sendOOTBAborts = 0;
                    break;
                case 'u':
                    sendUnordered = 1;
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
        } else
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
         abortProgram = 1;
    }

    if (printUsageInfo == 1)
        printUsage();
    if (abortProgram == 1)
        exit(-1);
}

void dataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int len,
                     unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
    unsigned int length;
    int index=0, result;
    unsigned short ssn;
    unsigned int the_tsn;

    if (vverbose) {
      fprintf(stdout, "%-8x: Data arrived (%u bytes on stream %u, %s)\n",
                      assocID, len, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
      fflush(stdout);
    }
    /* read it */
    length = sizeof(chunk);
    SCTP_receive(assocID, streamID, chunk, &length, &ssn, &the_tsn, SCTP_MSG_DEFAULT);

    /* update counter */
    ((struct ulp_data *) ulpDataPtr)->nrOfReceivedChunks += 1;
    ((struct ulp_data *) ulpDataPtr)->nrOfReceivedBytes  += length;

    /* and send it */
    if (sendToAll) {
        for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
            if ((ulpData[index].maximumStreamID != -1)&&
                (!(ulpData[index].ShutdownReceived))) {
                result = SCTP_send(ulpData[index].assocID,
                                   (unsigned short)min(streamID, (unsigned int)(ulpData[index].maximumStreamID)),
                                   chunk, length,
                                   protoID,
                                   SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive, unordered, SCTP_BUNDLING_DISABLED);
                if (vverbose) {
                    fprintf(stdout, "%-8x: Data sent (%u bytes on stream %u, %s) Result: %d\n",
                                    ulpData[index].assocID, len, min(streamID, (unsigned int)ulpData[index].maximumStreamID),
                                    (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered", result);
                    fflush(stdout);
                }
            }
        }
    } else {
        result = SCTP_send(assocID,
                           (unsigned short)min(streamID, (unsigned int)(((struct ulp_data *) ulpDataPtr)->maximumStreamID)),
                           chunk, length,
                           protoID,
                           SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive, unordered, SCTP_BUNDLING_DISABLED);
        if (vverbose) {
            fprintf(stdout, "%-8x: Data sent (%u bytes on stream %u, %s) Result: %d\n",
                            ulpData[index].assocID, len, min(streamID, (unsigned int)(((struct ulp_data *) ulpDataPtr)->maximumStreamID)),
                            (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered", result);
            fflush(stdout);
        }
    }
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

void* communicationUpNotif(unsigned int assocID, int status,
                           unsigned int noOfPaths,
                           unsigned short noOfInStreams, unsigned short noOfOutStreams,
                           int associationSupportsPRSCTP, void* dummy)
{
    unsigned int index, packetNumber;
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
    SCTP_PathStatus pathStatus;
    unsigned short pathID;
    unsigned short streamID = 0;

    if (verbose) {
        fprintf(stdout, "%-8x: Communication up (%u paths:", assocID, noOfPaths);
        for (pathID=0; pathID < noOfPaths; pathID++){
            SCTP_getPathStatus(assocID, pathID, &pathStatus);
            fprintf(stdout, " %s", pathStatus.destinationAddress);
        }
        fprintf(stdout, ")\n");
        fprintf(stdout, "%-8x:                  %u incoming, %u outgoing streams.\n",
                assocID, noOfInStreams, noOfOutStreams);
        fflush(stdout);
    }

    /* look for a free ULP data */
    for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
        if (ulpData[index].maximumStreamID == -1)
            break;
    }

    /* if found */
    if (index < MAXIMUM_NUMBER_OF_ASSOCIATIONS) {
        /* use it */
        ulpData[index].maximumStreamID    = noOfOutStreams - 1;
        ulpData[index].assocID            = assocID;
        ulpData[index].nrOfReceivedChunks = 0;
        ulpData[index].nrOfReceivedBytes  = 0;
        ulpData[index].ShutdownReceived   = 0;

        /* send the initial packets */
        memset(chunk, 0, sizeof(chunk));
        for(packetNumber=1; packetNumber <= numberOfInitialPackets; packetNumber++) {
            SCTP_send(assocID,
                      streamID,
                      chunk, chunkLength,
                      SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                      SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive,
                      (sendUnordered)?SCTP_UNORDERED_DELIVERY:SCTP_ORDERED_DELIVERY,
                      SCTP_BUNDLING_DISABLED);
            if (rotateStreams) {
                streamID = (streamID + 1) % noOfOutStreams;
            }
        }
        return &ulpData[index];
    } else {
        /* abort assoc due to lack of resources */
        SCTP_abort(assocID);
        return NULL;
    }
}

void communicationLostNotif(unsigned int assocID, unsigned short status, void* ulpDataPtr)
{
    unsigned char buffer[MAXIMUM_PAYLOAD_LENGTH];
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
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }

    bufferLength = sizeof(buffer);
    while (SCTP_receiveUnacked(assocID, buffer, &bufferLength, &tsn,
                                   &streamID, &streamSN, &protoID) >= 0){
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }

    /* free ULP data */
    ((struct ulp_data *) ulpDataPtr)->maximumStreamID = -1;

    /* delete the association */
    SCTP_deleteAssociation(assocID);
}

void communicationErrorNotif(unsigned int assocID, unsigned short status, void* dummy)
{
  if (verbose) {
    fprintf(stdout, "%-8x: Communication error (status %u)\n", assocID, status);
    fflush(stdout);
  }
}

void restartNotif(unsigned int assocID, void* ulpDataPtr)
{
    SCTP_AssociationStatus assocStatus;

    if (verbose) {
        fprintf(stdout, "%-8x: Restart\n", assocID);
        fflush(stdout);
    }

    SCTP_getAssocStatus(assocID, &assocStatus);

    /* update ULP data */
    ((struct ulp_data *) ulpDataPtr)->maximumStreamID = assocStatus.outStreams - 1;
    ((struct ulp_data *) ulpDataPtr)->assocID         = assocID;

}

void shutdownCompleteNotif(unsigned int assocID, void* ulpDataPtr)
{
  if (verbose) {
    fprintf(stdout, "%-8x: Shutdown complete\n", assocID);
    fflush(stdout);
  }
  /* free ULP data */
  ((struct ulp_data *) ulpDataPtr)->maximumStreamID = -1;
  SCTP_deleteAssociation(assocID);

}

void shutdownReceivedNotif(unsigned int assocID, void* ulpDataPtr)
{
    if (verbose) {
        fprintf(stdout, "%-8x: Shutdown received\n", assocID);
        fflush(stdout);
    }

    ((struct ulp_data *)ulpDataPtr)->ShutdownReceived = 1;
}


void
measurementTimerRunOffFunction(unsigned int timerID, void *parameter1, void *parameter2)
{
    int index;
    SCTP_AssociationStatus assocStatus;
    SCTP_PathStatus pathStatus;
    unsigned short pathID;

    for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
        if (ulpData[index].maximumStreamID >= 0){
            if (doAllMeasurements) {
                SCTP_getAssocStatus(ulpData[index].assocID, &assocStatus);
                for (pathID=0; pathID < assocStatus.numberOfAddresses; pathID++){
                    SCTP_getPathStatus(ulpData[index].assocID, pathID, &pathStatus);
                    fprintf(stdout, "Asoc:%-8x Path:%-2u Ch:%-8lu By:%-8lu rto:%-8u srtt:%-8u qu:%-6u osb:%-8u cwnd:%-8u ssthresh:%-8u\n",
                        ulpData[index].assocID,
                        pathID,
                        ulpData[index].nrOfReceivedChunks,
                        ulpData[index].nrOfReceivedBytes,
                        pathStatus.rto,
                        pathStatus.srtt,
                        assocStatus.noOfChunksInSendQueue,
                        assocStatus.outstandingBytes,
                        pathStatus.cwnd,
                        pathStatus.ssthresh);
                }
            } else {
                fprintf(stdout, "%-8x: %-6lu Chunks, %-8lu Bytes received\n",
                        ulpData[index].assocID, ulpData[index].nrOfReceivedChunks, ulpData[index].nrOfReceivedBytes);
            }
            ulpData[index].nrOfReceivedChunks = 0;
            ulpData[index].nrOfReceivedBytes  = 0;
        }
    }
    SCTP_startTimer(deltaT, measurementTimerRunOffFunction, NULL, NULL);
}

int main(int argc, char **argv)
{
    int sctpInstance;
    SCTP_ulpCallbacks echoUlp;
    SCTP_InstanceParameters instanceParameters;
    SCTP_LibraryParameters params;
    unsigned int index;

    /* initialize ULP data */
    for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
        ulpData[index].maximumStreamID    = -1;
        ulpData[index].nrOfReceivedChunks = 0;
        ulpData[index].nrOfReceivedBytes  = 0;
        ulpData[index].ShutdownReceived   = 0;
    }

    /* initialize the echo_ulp variable */
    echoUlp.dataArriveNotif           = &dataArriveNotif;
    echoUlp.sendFailureNotif          = &sendFailureNotif;
    echoUlp.networkStatusChangeNotif  = &networkStatusChangeNotif;
    echoUlp.communicationUpNotif      = &communicationUpNotif;
    echoUlp.communicationLostNotif    = &communicationLostNotif;
    echoUlp.communicationErrorNotif   = &communicationErrorNotif;
    echoUlp.restartNotif              = &restartNotif;
    echoUlp.shutdownCompleteNotif     = &shutdownCompleteNotif;
    echoUlp.peerShutdownReceivedNotif = &shutdownReceivedNotif;

    getArgs(argc, argv);
    checkArgs();

    SCTP_initLibrary();
    SCTP_getLibraryParameters(&params);
    params.sendOotbAborts = sendOOTBAborts;
    /* params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_ADLER32; */
    params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_CRC32C;
    SCTP_setLibraryParameters(&params);

    sctpInstance=SCTP_registerInstance(localPort,
                                       MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                                       noOfLocalAddresses, localAddressList,
                                       echoUlp);

    /* set the TOS field */

    SCTP_getAssocDefaults((unsigned short)sctpInstance, &instanceParameters);
    instanceParameters.maxSendQueue = 0;
    instanceParameters.ipTos=tosByte;
    SCTP_setAssocDefaults((unsigned short)sctpInstance, &instanceParameters);

    if (startAssociation) {
        SCTP_associate((unsigned short)sctpInstance, MAXIMUM_NUMBER_OF_OUT_STREAMS, destinationAddress, remotePort, &ulpData[0]);
    }

    if (doMeasurements) {
        SCTP_startTimer(deltaT, &measurementTimerRunOffFunction, NULL, NULL);
    }

    /* run the event handler forever */
    while (1) {
        SCTP_eventLoop();
    };

    /* this will never be reached */
    exit(0);
}
