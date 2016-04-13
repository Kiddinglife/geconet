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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "sctp_wrapper.h"

#define DISCARD_PORT                          9
#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES    10
#define MAXIMUM_PAYLOAD_LENGTH             8192
#define MAXIMUM_NUMBER_OF_IN_STREAMS         17
#define MAXIMUM_NUMBER_OF_OUT_STREAMS         1
#define MAXIMUM_NUMBER_OF_ASSOCIATIONS        5

struct ulp_data {
    unsigned int    assocID;
    unsigned short  streams;
    unsigned int    readTimerID;
    unsigned int    printTimerID;
    int             maximumStreamID;
    unsigned long   nrOfReceivedChunks;
    unsigned long   nrOfReceivedBytes;
    int             ShutdownReceived;
};

static struct ulp_data ulpData[MAXIMUM_NUMBER_OF_ASSOCIATIONS];

static unsigned char  localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned short noOfLocalAddresses = 0;

static int verbose         = 0;
static int vverbose        = 0;
static int unknownCommand  = 0;
static int sendOOTBAborts  = 1;
static int delayReading    = 0;
static int period          = 1000;
static unsigned int myRwnd = 0;
static int myRwndSpecified = 0;

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
    printf("Usage:    discard_server [options]\n");
    printf("options:\n");
    printf("-i        ignore OOTB packets\n");
    printf("-p        period time between sucessive reads.\n");
    printf("-r        delay reading for a period of time. See the -p option.\n");
    printf("-s        source address\n");
    printf("-v        verbose mode\n");
    printf("-V        very verbose mode\n");
    printf("-w        receiver Window\n");
}

void getArgs(int argc, char **argv)  /* Irene */
{
    int i;
    char *opt;

    for(i=1; i < argc ;i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'h':
                    printUsage();
                    exit(0);
                case 'p':
                    if (i+1 >= argc) {
                        printUsage();
                    exit(0);
                }
                opt = argv[++i];
                    period = atoi(opt);
                    break;
                case 'r':
                    delayReading = 1;
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
                    };
                    break;
                case 'i':
                    sendOOTBAborts = 0;
                    break;
                case 'v':
                    verbose = 1;
                    break;
                case 'V':
                    verbose = 1;
                    vverbose = 1;
                    break;
                case 'w':
                    if (i+1 >= argc) {
                       printUsage();
                       exit(0);
                    }
                    opt = argv[++i];
                    myRwnd = atoi(opt);
                    myRwndSpecified = 1;
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

void readDataFunction(unsigned int timerID, void *parameter1, void *parameter2)
{
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
    unsigned int length;
    struct ulp_data *myUlpDataPtr;
    unsigned short streamID;
    unsigned short ssn;
    unsigned int tsn;


    myUlpDataPtr = (struct ulp_data *) parameter1;
    length = sizeof(chunk);
    for(streamID=0; streamID < myUlpDataPtr->streams; streamID++) {
        length = MAXIMUM_PAYLOAD_LENGTH;
        while (SCTP_receive(myUlpDataPtr->assocID, streamID, chunk, &length, &ssn, &tsn, SCTP_MSG_DEFAULT) == 0) {
            /* update counter */
            myUlpDataPtr->nrOfReceivedChunks += 1;
            myUlpDataPtr->nrOfReceivedBytes  += length;
            if (vverbose) {
                fprintf(stdout, "%-8x: Data read (%u bytes on stream %u, ssn %u.)\n", myUlpDataPtr->assocID, length, streamID, ssn);
                fflush(stdout);
            }
            length = sizeof(chunk);
        }
    }
    myUlpDataPtr->readTimerID = SCTP_startTimer(period, readDataFunction, parameter1, parameter2);
}

void dataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int len,
                     unsigned short streamSN, unsigned int TSN,  unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
    unsigned int length;
    unsigned short ssn;
    unsigned int tsn;

    if (vverbose) {
      fprintf(stdout, "%-8x: Data arrived (%u bytes; TSN = %u, SSN = %u, SID= %u, %s)\n",
                      assocID, len, TSN, streamSN, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
      fflush(stdout);
    }
    /* read it */
    length = MAXIMUM_PAYLOAD_LENGTH;
    if (!(delayReading)) {
        SCTP_receive(assocID, streamID, chunk, &length, &ssn, &tsn, SCTP_MSG_DEFAULT);
        if (vverbose) {
            fprintf(stdout, "%-8x: Data read (%u bytes; TSN = %u, SSN = %u, SID= %u, %s)\n",
                            assocID, len, TSN, ssn, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
            fflush(stdout);
        }
       /* update counter */
       ((struct ulp_data *) ulpDataPtr)->nrOfReceivedChunks += 1;
       ((struct ulp_data *) ulpDataPtr)->nrOfReceivedBytes  += length;

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

void networkStatusChangeNotif(unsigned int assocID, short destAddrIndex, unsigned short newState, void* ulpDataPtr)
{
    if (verbose) {
        fprintf(stdout, "%-8x: Network status change: path %u is now %s\n",
                assocID, destAddrIndex, pathStateName(newState));
        fflush(stdout);
    }
}

void* communicationUpNotif(unsigned int assocID, int status,
                           unsigned int noOfDestinations,
                           unsigned short noOfInStreams, unsigned short noOfOutStreams,
                           int associationSupportsPRSCTP, void* dummy)
{
    int index;

    if (verbose) {
        fprintf(stdout, "%-8x: Communication up (%u paths)\n", assocID, noOfDestinations);
        fflush(stdout);
    }

    /* look for a free ULP data */
    for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
        if (ulpData[index].maximumStreamID == -1)
            break;
    }
    if (index < MAXIMUM_NUMBER_OF_ASSOCIATIONS) {
        /* use it */
        ulpData[index].maximumStreamID    = noOfOutStreams - 1;
        ulpData[index].assocID = assocID;
        ulpData[index].streams = noOfInStreams;
        ulpData[index].nrOfReceivedChunks = 0;
        ulpData[index].nrOfReceivedBytes  = 0;
        ulpData[index].ShutdownReceived   = 0;
    }

    if (delayReading) {
        /* if found */
        if (index < MAXIMUM_NUMBER_OF_ASSOCIATIONS) {
            ulpData[index].readTimerID = SCTP_startTimer(period, &readDataFunction, (void *) &ulpData[index], NULL);
            return &ulpData[index];
        } else {
            /* abort assoc due to lack of resources */
            SCTP_abort(assocID);
            return NULL;
        }
    }

    if (index < MAXIMUM_NUMBER_OF_ASSOCIATIONS) {
            return &ulpData[index];
    }
    return NULL;
}



void communicationLostNotif(unsigned int assocID, unsigned short status, void* ulpDataPtr)
{
    if (verbose) {
        fprintf(stdout, "%-8x: Communication lost (status %u)\n", assocID, status);
        fflush(stdout);
    }
    if (delayReading) {
        sctp_stopTimer(((struct ulp_data *)ulpDataPtr)->readTimerID);
        ((struct ulp_data *)ulpDataPtr)->maximumStreamID = -1;
    }
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
    if (delayReading) {
        sctp_stopTimer(((struct ulp_data *)ulpDataPtr)->readTimerID);
        ((struct ulp_data *)ulpDataPtr)->maximumStreamID = -1;
    }
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

int main(int argc, char **argv)
{
    SCTP_ulpCallbacks discardUlp;
    SCTP_LibraryParameters params;
    SCTP_InstanceParameters instanceParameters;
    int sctpInstance;
    int index;

    for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
        ulpData[index].assocID = 0;
        ulpData[index].streams = 0;
        ulpData[index].readTimerID = 0;
        ulpData[index].printTimerID = 0;
        ulpData[index].maximumStreamID    = -1;
        ulpData[index].nrOfReceivedChunks = 0;
        ulpData[index].nrOfReceivedBytes  = 0;
        ulpData[index].ShutdownReceived   = 0;

    }

    /* initialize the discard_ulp variable */
    discardUlp.dataArriveNotif           = &dataArriveNotif;
    discardUlp.sendFailureNotif          = &sendFailureNotif;
    discardUlp.networkStatusChangeNotif  = &networkStatusChangeNotif;
    discardUlp.communicationUpNotif      = &communicationUpNotif;
    discardUlp.communicationLostNotif    = &communicationLostNotif;
    discardUlp.communicationErrorNotif   = &communicationErrorNotif;
    discardUlp.restartNotif              = &restartNotif;
    discardUlp.shutdownCompleteNotif     = &shutdownCompleteNotif;
    discardUlp.peerShutdownReceivedNotif = &shutdownReceivedNotif;

    /* handle all command line options */
    getArgs(argc, argv);
    checkArgs();

    SCTP_initLibrary();
    SCTP_getLibraryParameters(&params);
    params.sendOotbAborts = sendOOTBAborts;
    params.supportPRSCTP = 1;
    /* params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_ADLER32; */
    params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_CRC32C;
    SCTP_setLibraryParameters(&params);

    /* set up the "server" */
    sctpInstance = SCTP_registerInstance(DISCARD_PORT,
                                         MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                                         noOfLocalAddresses, localAddressList,
                                         discardUlp);

    SCTP_getAssocDefaults((unsigned short)sctpInstance, &instanceParameters);
    if (myRwndSpecified)
        instanceParameters.myRwnd = myRwnd;
    SCTP_setAssocDefaults((unsigned short)sctpInstance, &instanceParameters);


    /* run the event handler forever */

    while (1) {
        SCTP_eventLoop();
    }

    /* this will never be reached */
    exit(0);
}
