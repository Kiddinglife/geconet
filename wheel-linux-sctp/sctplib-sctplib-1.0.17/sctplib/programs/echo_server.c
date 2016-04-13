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
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef min
#define min(x,y)            (x)<(y)?(x):(y)
#endif

#define ECHO_PORT                             7
#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES    10
#define MAXIMUM_PAYLOAD_LENGTH             8192
#define MAXIMUM_NUMBER_OF_IN_STREAMS         17
#define MAXIMUM_NUMBER_OF_OUT_STREAMS        17

struct ulp_data {
    unsigned short maximumStreamID;
};

static unsigned char  localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned short noOfLocalAddresses = 0;

static int verbose          = 0;
static int vverbose         = 0;
static int unknownCommand   = 0;
static int sendOOTBAborts   = 1;
static int timeToLive       = SCTP_INFINITE_LIFETIME;

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
    printf("Usage:   echo_server [options]\n");
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
                   if ((noOfLocalAddresses < MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES) &&
                       (strlen(opt) < SCTP_MAX_IP_LEN)) {
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
                    opt = argv[++i];
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
    unsigned short ssn;
    unsigned int tsn;

    if (vverbose) {
      fprintf(stdout, "%-8x: Data arrived (%u bytes on stream %u, %s)\n",
                      assocID, len, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
      fflush(stdout);
    }
    /* read it */
    length = MAXIMUM_PAYLOAD_LENGTH;
    SCTP_receive(assocID, streamID, chunk, &length,&ssn, &tsn, SCTP_MSG_DEFAULT);
    /* and send it */
    SCTP_send(assocID,
              (unsigned short)min(streamID, ((struct ulp_data *) ulpDataPtr)->maximumStreamID),
              chunk, length,
              protoID,
              SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive, unordered, SCTP_BUNDLING_DISABLED);
}

void sendFailureNotif(unsigned int assocID,
                      unsigned char *unsent_data, unsigned int dataLength, unsigned int *context, void* ulpDataPtr)
{
  if (verbose) {
    fprintf(stdout, "%-8u: Send failure\n", assocID);
    fflush(stdout);
  }
}

void networkStatusChangeNotif(unsigned int assocID, short destAddrIndex, unsigned short newState, void* ulpDataPtr)
{
    SCTP_AssociationStatus assocStatus;
    SCTP_PathStatus pathStatus;
    unsigned short pathID;

    if (verbose) {
        fprintf(stdout, "%-8x: Network status change: path %u is now %s\n",
                        assocID, destAddrIndex, pathStateName(newState));
        fflush(stdout);
    }

    /* if the primary path has become inactive */
    if ((newState == SCTP_PATH_UNREACHABLE) &&
        (destAddrIndex == SCTP_getPrimary(assocID))) {

        /* select a new one */ /* should we have a sctp_get_primary()? */
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
                           unsigned int noOfDestinations,
                           unsigned short noOfInStreams, unsigned short noOfOutStreams,
                           int associationSupportsPRSCTP, void* dummy)
{
    struct ulp_data *ulpDataPtr;

    if (verbose) {
        fprintf(stdout, "%-8x: Communication up (%u In-Streams, %u Out-Streams)\n", assocID, noOfInStreams, noOfOutStreams);
        fflush(stdout);
    }

    ulpDataPtr                  = (struct ulp_data*)malloc(sizeof(struct ulp_data));
    ulpDataPtr->maximumStreamID = noOfOutStreams - 1;
    return((void *) ulpDataPtr);
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
    while (SCTP_receiveUnsent(assocID, buffer, &bufferLength,  &tsn,
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
    free((struct ulp_data *) ulpDataPtr);

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
}

void shutdownCompleteNotif(unsigned int assocID, void* ulpDataPtr)
{
  if (verbose) {
    fprintf(stdout, "%-8x: Shutdown complete\n", assocID);
    fflush(stdout);
  }
  /* free ULP data */
  free((struct ulp_data *) ulpDataPtr);
  SCTP_deleteAssociation(assocID);

}

void shutdownReceivedNotif(unsigned int assocID, void* ulpDataPtr)
{
    if (verbose) {
        fprintf(stdout, "%-8x: Shutdown received\n", assocID);
        fflush(stdout);
    }
}

int main(int argc, char **argv)
{
    SCTP_ulpCallbacks echoUlp;
    /* SCTP_InstanceParameters instanceParameters; */
    SCTP_LibraryParameters params;

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

    /* handle all command line options */
    getArgs(argc, argv);
    checkArgs();

    SCTP_initLibrary();
    SCTP_getLibraryParameters(&params);
    params.sendOotbAborts = sendOOTBAborts;
    /* params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_ADLER32; */
    params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_CRC32C;
    SCTP_setLibraryParameters(&params);

    /* set up the "server" */
    SCTP_registerInstance(ECHO_PORT,
                          MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                          noOfLocalAddresses, localAddressList,
                          echoUlp);

    /* run the event handler forever */
    while (1) {
        SCTP_eventLoop();
    }

    /* this will never be reached */
    exit(0);
}




