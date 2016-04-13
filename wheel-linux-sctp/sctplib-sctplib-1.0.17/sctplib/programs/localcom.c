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

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>         /* for atoi() under Linux */

#define ECHO_PORT                             7
#define CLIENT_PORT                        1000
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
};

static struct ulp_data ulpData[MAXIMUM_NUMBER_OF_ASSOCIATIONS];
static unsigned char localAddressList[1][SCTP_MAX_IP_LEN];
static unsigned char destinationAddress[SCTP_MAX_IP_LEN];

static unsigned short noOfLocalAddresses      = 1;
static unsigned short numberOfInitialPackets  = 1;
static unsigned short chunkLength             = 512;
static int unknownCommand                     = 0;
static unsigned int deltaT                    = 1000;
static int sendUnordered                      = 0;
static unsigned int ende                      = 10000;
static unsigned int chunkCount                = 0;
static int useDumpFile                        = 0;

FILE* fptr;

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
    printf("usage:   local_communication [options] \n");
    printf("options:\n");
    printf("-l length           number of bytes of the payload when generating traffic (default 512)\n");
    printf("-n number           number of packets initially send out (default 1)\n");
    printf("-u                  use unordered delivery\n");
    printf("-e number           end after that many chunks\n");
}

void getArgs(int argc, char **argv)
{
    int c;
    extern char *optarg;

    fptr = stdout;
    while ((c = getopt(argc, argv, "l:n:e:uf")) != -1)
    {
        switch (c) {
        case 'l':
            chunkLength = min(atoi(optarg),MAXIMUM_PAYLOAD_LENGTH);
            break;
        case 'n':
            numberOfInitialPackets = atoi(optarg);
            break;
        case 'u':
            sendUnordered = 1;
            break;
        case 'e':
            ende = atoi(optarg);
            break;
        case 'f':
            useDumpFile = 1;
            fptr = fopen("./l.out","w+");
            break;
        default:
            unknownCommand = 1;
            break;
        }
    }
}
void checkArgs(void)
{
    int printUsageInfo;

    printUsageInfo = 0;

    if (unknownCommand ==1) {
         printf("Error:   Unkown options in command.\n");
         printUsageInfo = 1;
    }

    if (printUsageInfo == 1)
        printUsage();
}

void serverDataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int len,
                           unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                           unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
    unsigned int length;
    unsigned short ssn;
    unsigned int the_tsn;

    /* read it */
    length = sizeof(chunk);
    SCTP_receive(assocID, streamID, chunk, &length, &ssn, &the_tsn, SCTP_MSG_DEFAULT);

    /* update counter */
    ((struct ulp_data *) ulpDataPtr)->nrOfReceivedChunks += 1;
    ((struct ulp_data *) ulpDataPtr)->nrOfReceivedBytes  += length;

    /* and send it */
    SCTP_send(assocID,
              (unsigned short)min(streamID, ((struct ulp_data *) ulpDataPtr)->maximumStreamID),
              chunk, length,
              protoID,
              SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, SCTP_INFINITE_LIFETIME, unordered, SCTP_BUNDLING_DISABLED);
}

void clientDataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int len,
                           unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                           unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
    unsigned int length;
    unsigned short ssn;
    unsigned int the_tsn;

    chunkCount++;
    length = sizeof(chunk);
    SCTP_receive(assocID, streamID, chunk, &length, &ssn, &the_tsn, SCTP_MSG_DEFAULT);
    SCTP_send(assocID,
              streamID,
              chunk, length,
              protoID,
              SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, SCTP_INFINITE_LIFETIME, unordered, SCTP_BUNDLING_DISABLED);

    if (chunkCount > ende)     SCTP_shutdown(assocID);
}

void sendFailureNotif(unsigned int assocID,
                      unsigned char *unsent_data, unsigned int dataLength, unsigned int *context, void* dummy)
{
    fprintf(fptr, "%-8x: Send failure\n", assocID);
    fflush(fptr);
}

void networkStatusChangeNotif(unsigned int assocID, short affectedPathID, unsigned short newState, void* ulpDataPtr)
{
    SCTP_AssociationStatus assocStatus;
    SCTP_PathStatus pathStatus;
    unsigned short pathID;

    SCTP_getPathStatus(assocID, affectedPathID, &pathStatus);
    fprintf(fptr, "%-8x: Network status change: path %u (towards %s) is now %s\n",
                    assocID, affectedPathID,
                    pathStatus.destinationAddress,
                    pathStateName(newState));
    fflush(fptr);

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

void* clientCommunicationUpNotif(unsigned int assocID, int status,
                           unsigned int noOfPaths,
                           unsigned short noOfInStreams, unsigned short noOfOutStreams,
                           int associationSupportsPRSCTP, void* dummy)
{
    unsigned int  packetNumber;
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];

    /* send the initial packets */
    memset(chunk, 0xFF, sizeof(chunk));
    for(packetNumber=1; packetNumber <= numberOfInitialPackets; packetNumber++) {
        SCTP_send(assocID,
                  0,
                  chunk, chunkLength,
                  SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                  SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, SCTP_INFINITE_LIFETIME,
                  (sendUnordered)?SCTP_UNORDERED_DELIVERY:SCTP_ORDERED_DELIVERY,
                  SCTP_BUNDLING_DISABLED);
    }
    return NULL;
}

void* serverCommunicationUpNotif(unsigned int assocID, int status,
                                 unsigned int noOfPaths,
                                 unsigned short noOfInStreams, unsigned short noOfOutStreams,
                                 int associationSupportsPRSCTP, void* dummy)
{
    int index;

    /* look for a free ULP data */
    for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
        if (ulpData[index].maximumStreamID == -1)
            break;
    }

    /* if found */
    if (index < MAXIMUM_NUMBER_OF_ASSOCIATIONS) {
        /* use it */
        ulpData[index].maximumStreamID = noOfOutStreams - 1;
        ulpData[index].assocID = assocID;
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

    fprintf(fptr, "%-8x: Communication lost (status %u)\n", assocID, status);
    fflush(fptr);

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
    if (ulpDataPtr) {
        ((struct ulp_data *) ulpDataPtr)->maximumStreamID = -1;
    }
    /* delete the association */
    SCTP_deleteAssociation(assocID);
    exit(0);
}

void communicationErrorNotif(unsigned int assocID, unsigned short status, void* dummy)
{
    fprintf(fptr, "%-8x: Communication error (status %u)\n", assocID, status);
    fflush(fptr);
}

void restartNotif(unsigned int assocID, void* ulpDataPtr)
{
    SCTP_AssociationStatus assocStatus;

    fprintf(fptr, "%-8x: Restart\n", assocID);
    fflush(fptr);

    /* update ULP data */
    if (ulpDataPtr) {
        SCTP_getAssocStatus(assocID, &assocStatus);
        ((struct ulp_data *) ulpDataPtr)->maximumStreamID = assocStatus.outStreams - 1;
        ((struct ulp_data *) ulpDataPtr)->assocID = assocID;
    }

}

void shutdownCompleteNotif(unsigned int assocID, void* ulpDataPtr)
{
    fprintf(fptr, "%-8x: Shutdown complete\n", assocID);
    fflush(fptr);

    /* free ULP data */
    if (ulpDataPtr)
        ((struct ulp_data *) ulpDataPtr)->maximumStreamID = -1;
    SCTP_deleteAssociation(assocID);
    exit(0);
}

void
measurementTimerRunOffFunction(unsigned int timerID, void *parameter1, void *parameter2)
{
    int index;
    SCTP_AssociationStatus assocStatus;
    SCTP_PathStatus pathStatus;

    for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
        if (ulpData[index].maximumStreamID >= 0){
            SCTP_getAssocStatus(ulpData[index].assocID, &assocStatus);
            SCTP_getPathStatus(ulpData[index].assocID, 0, &pathStatus);
            fprintf(fptr, "%-8x %-8lu %-8lu %-8u %-8u %-8u %-8u %-8u\n",
                    ulpData[index].assocID,
                    ulpData[index].nrOfReceivedChunks,
                    ulpData[index].nrOfReceivedBytes,
                    assocStatus.currentReceiverWindowSize,
                    assocStatus.noOfChunksInSendQueue,
                    assocStatus.outstandingBytes,
                    pathStatus.cwnd,
                    pathStatus.ssthresh);
            fflush(fptr);
            ulpData[index].nrOfReceivedChunks = 0;
            ulpData[index].nrOfReceivedBytes  = 0;
        }
    }
    SCTP_startTimer(deltaT, measurementTimerRunOffFunction, NULL, NULL);
}



int main(int argc, char **argv)
{
    int sctpClientInstance;
    SCTP_ulpCallbacks echoServerUlp, echoClientUlp;
    SCTP_LibraryParameters params;
    unsigned int index, version;


    /* initialize ULP data */
    for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
        ulpData[index].maximumStreamID    = -1;
        ulpData[index].nrOfReceivedChunks = 0;
        ulpData[index].nrOfReceivedBytes  = 0;
    }

    /* initialize the echo_ulp variable */
    echoServerUlp.dataArriveNotif          = &serverDataArriveNotif;
    echoServerUlp.sendFailureNotif         = &sendFailureNotif;
    echoServerUlp.networkStatusChangeNotif = &networkStatusChangeNotif;
    echoServerUlp.communicationUpNotif     = &serverCommunicationUpNotif;
    echoServerUlp.communicationLostNotif   = &communicationLostNotif;
    echoServerUlp.communicationErrorNotif  = &communicationErrorNotif;
    echoServerUlp.restartNotif             = &restartNotif;
    echoServerUlp.shutdownCompleteNotif    = &shutdownCompleteNotif;
    echoServerUlp.peerShutdownReceivedNotif = NULL;

    /* initialize the echo_ulp variable */
    echoClientUlp.dataArriveNotif          = &clientDataArriveNotif;
    echoClientUlp.sendFailureNotif         = &sendFailureNotif;
    echoClientUlp.networkStatusChangeNotif = &networkStatusChangeNotif;
    echoClientUlp.communicationUpNotif     = &clientCommunicationUpNotif;
    echoClientUlp.communicationLostNotif   = &communicationLostNotif;
    echoClientUlp.communicationErrorNotif  = &communicationErrorNotif;
    echoClientUlp.restartNotif             = &restartNotif;
    echoClientUlp.shutdownCompleteNotif    = &shutdownCompleteNotif;
    echoClientUlp.peerShutdownReceivedNotif = NULL;

    getArgs(argc, argv);
    checkArgs();

    version = sctp_getLibraryVersion();
    fprintf(fptr, "We are using sctplib version (%u) maj=%u, min=%u\n",
        version, version & 0xFFFF0000, version & 0xFFFF);
    fflush(fptr);

    SCTP_initLibrary();
    SCTP_getLibraryParameters(&params);
    params.sendOotbAborts = 0;
    params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_CRC32C;
    SCTP_setLibraryParameters(&params);


    noOfLocalAddresses = 1;
    strcpy((char *)localAddressList[0], "127.0.0.1");

    SCTP_registerInstance(ECHO_PORT,
                          MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                          noOfLocalAddresses, localAddressList,
                          echoServerUlp);

    sctpClientInstance = SCTP_registerInstance(CLIENT_PORT,
                                               MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                                               noOfLocalAddresses, localAddressList,
                                               echoClientUlp);

    strcpy((char *)destinationAddress, "127.0.0.1");


    SCTP_associate(sctpClientInstance, 1, destinationAddress, ECHO_PORT, NULL);

    SCTP_startTimer(deltaT, &measurementTimerRunOffFunction, NULL, NULL);


    /* run the event handler forever */
    while (1) {
        SCTP_eventLoop();
    };

    /* this will never be reached */
    exit(0);
}
