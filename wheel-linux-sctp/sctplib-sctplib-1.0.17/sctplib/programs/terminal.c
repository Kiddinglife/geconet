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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "sctp_wrapper.h"


#ifdef WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>         /* for atoi() under Linux */

#define ECHO_PORT                              7
#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES     10
#define MAXIMUM_NUMBER_OF_IN_STREAMS          10
#define MAXIMUM_NUMBER_OF_OUT_STREAMS         10
/*#define min(x,y)                              (x)<(y)?(x):(y)*/

#if defined SCTP_MAXIMUM_DATA_LENGTH
    #undef SCTP_MAXIMUM_DATA_LENGTH
#endif

#define SCTP_MAXIMUM_DATA_LENGTH    450

static unsigned char localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned char destinationAddress[SCTP_MAX_IP_LEN];

static unsigned short noOfLocalAddresses = 0;

static unsigned short remotePort = ECHO_PORT;
static unsigned short localPort  = 0;
static unsigned char  tosByte    = 0x10;  /* IPTOS_LOWDELAY */
static unsigned int associationID;
static int sctpInstance;
static int useAbort = 0;
static int sendOOTBAborts = 1;
static unsigned int myRwnd = 0;
static int myRwndSpecified = 0;
static int HBInterval = 30000;
static int rto_min = 1000;
static int rto_max = 60000;
static int timeToLive     = SCTP_INFINITE_LIFETIME;
static short numberOutStreams = 0;
static short currentStream = 0;

static int rotateStreams = 0;
static int verbose  = 0;
static int vverbose = 0;
static int unknownCommand = 0;
static int hasDestinationAddress = 0;



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
    printf("Usage:   terminal [options] -d destination_addr ...\n");
    printf("options:\n");
    printf("-a       use abort\n");
    printf("-c       use all streams when sending (round-robin)\n");
    printf("-h       Heartbeat Interval in ms (default = 30000)\n");
    printf("-m       RTO.min in ms (default = 1000)\n");
    printf("-M       RTO.max in ms (default = 60000)\n");
    printf("-l       local port\n");
    printf("-q       type of service\n");
    printf("-r       remote port (default echoport = %u)\n", ECHO_PORT);
    printf("-s       source address\n");
    printf("-i       ignore OOTB packets\n");
    printf("-t       time to live in ms\n");
    printf("-v       verbose mode\n");
    printf("-V       very verbose mode\n");
    printf("-w       receiver Window\n");
}

void getArgs(int argc, char **argv)
{
   int i;
   char *opt;


   for(i=1; i < argc ;i++) {
      if (argv[i][0] == '-') {
         switch (argv[i][1]) {
         case 'a':
               useAbort = 1;
               break;
         case 'c':
               rotateStreams = 1;
               break;
         case 'd':
            if (i+1 >= argc) {
               printUsage();
               exit(0);
            }
            opt=argv[++i];
            if (strlen(opt) < SCTP_MAX_IP_LEN) {
               strcpy((char *)destinationAddress, opt);
            }
            hasDestinationAddress = 1;
            break;
         case 'h':
            if (i+1 >= argc) {
               printUsage();
               exit(0);
            }
            opt=argv[++i];
            HBInterval = atoi(opt);
            break;
         case 'l':
            if (i+1 >= argc) {
               printUsage();
               exit(0);
            }
            opt=argv[++i];
            localPort = atoi(opt);
            break;
         case 'm':
            if (i+1 >= argc) {
               printUsage();
               exit(0);
            }
            opt=argv[++i];
            rto_min = atoi(opt);
            break;
         case 'M':
            if (i+1 >= argc) {
               printUsage();
               exit(0);
            }
            opt=argv[++i];
            rto_max = atoi(opt);
            break;
         case 'q':
            if (i+1 >= argc) {
               printUsage();
               exit(0);
            }
            opt=argv[++i];
            tosByte = (unsigned char) atoi(opt);
            break;
         case 'r':
            if (i+1 >= argc) {
               printUsage();
               exit(0);
            }
            opt=argv[++i];
            remotePort = atoi(opt);
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
            opt=argv[++i];
            timeToLive = atoi(opt);
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
            opt=argv[++i];
            myRwnd = atoi(opt);
            myRwndSpecified = 1;
            break;
         default:
            unknownCommand = 1;
            break;
         }
      }
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
    if (hasDestinationAddress==0) {
        printf("Error:   An destination address must be specified.\n");
        abortProgram = 1;
        printUsageInfo = 1;
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
                     unsigned short streamSN, unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[SCTP_MAXIMUM_DATA_LENGTH];
    unsigned int length;
    unsigned short ssn;
    unsigned int the_tsn;

    if (vverbose) {
      fprintf(stdout, "%-8x: Data arrived (%u bytes on stream %u, %s)\n",
                      assocID, len, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
      fflush(stdout);
    }
    /* read it */

    length = SCTP_MAXIMUM_DATA_LENGTH;
    SCTP_receive(assocID, streamID, chunk, &length, &ssn, &the_tsn, SCTP_MSG_DEFAULT);
    fprintf(stdout, "%.*s", length, chunk);
    fflush(stdout);
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
    SCTP_AssociationStatus assocStatus;
    SCTP_PathStatus pathStatus;
    unsigned short pathID;

    if (verbose) {
        SCTP_getPathStatus(assocID, destAddrIndex, &pathStatus);
        fprintf(stdout, "%-8x: Network status change: path %u (towards %s) is now %s\n",
                assocID, destAddrIndex, pathStatus.destinationAddress, pathStateName(newState));
        fflush(stdout);
    }

    /* if the primary path has become inactive */
    if ((newState == SCTP_PATH_UNREACHABLE) &&
        (destAddrIndex == SCTP_getPrimary(assocID))) {

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
                           unsigned int noOfDestinations,
                           unsigned short noOfInStreams, unsigned short noOfOutStreams,
                           int associationSupportsPRSCTP, void* dummy)
{
    SCTP_PathStatus pathStatus;
    unsigned int i;

    if (verbose) {
        fprintf(stdout, "%-8x: Communication up (%u paths, %u In-Streams, %u Out-Streams)\n", assocID, noOfDestinations, noOfInStreams, noOfOutStreams);
        fflush(stdout);
    }
    if (vverbose) {
        for (i=0; i < noOfDestinations; i++) {
            SCTP_getPathStatus(assocID, (unsigned short)i, &pathStatus);
            fprintf(stdout, "%-8x: Path Status of path %u (towards %s): %s.\n", assocID, i, pathStatus.destinationAddress, pathStateName(pathStatus.state));
            SCTP_changeHeartBeat(assocID, (short)i, 1, HBInterval);
        }
    }
    numberOutStreams = noOfOutStreams;
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
    while (SCTP_receiveUnsent(assocID, buffer, &bufferLength, &tsn, &streamID, &streamSN, &protoID) >= 0){
        if (vverbose) {
            fprintf(stdout, "%-8x: Unsent data (%u bytes) retrieved (TSN = %u, SID = %u, SSN = %u, PPI = %u): %.*s",
                            assocID, bufferLength, tsn, streamID, streamSN, protoID, bufferLength, buffer);
            fflush(stdout);
        }
        bufferLength = sizeof(buffer);
    }

    bufferLength = sizeof(buffer);
    while (SCTP_receiveUnacked(assocID, buffer, &bufferLength, &tsn, &streamID, &streamSN, &protoID) >= 0){
        if (vverbose) {
            fprintf(stdout, "%-8x: Unacked data (%u bytes) retrieved (TSN = %u, SID = %u, SSN = %u, PPI = %u): %.*s",
                            assocID, bufferLength, tsn, streamID, streamSN, protoID, bufferLength, buffer);
            fflush(stdout);
        }
        bufferLength = sizeof(buffer);
    }

    /* delete the association, instace and terminate */
    SCTP_deleteAssociation(assocID);
    SCTP_unregisterInstance((unsigned short)sctpInstance);
    exit(0);
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

    /* delete the association, instance and terminate */
    SCTP_deleteAssociation(assocID);
    SCTP_unregisterInstance((unsigned short)sctpInstance);
    exit(0);
}

void shutdownReceivedNotif(unsigned int assocID, void* ulpDataPtr)
{
    if (verbose) {
        fprintf(stdout, "%-8x: Shutdown received\n", assocID);
        fflush(stdout);
    }
}


void
stdinCallback(char *readBuffer, int length)
{
    if (length == 0) {
        SCTP_unregisterStdinCallback();
        if (useAbort) {
            SCTP_abort(associationID);
        } else {
            SCTP_shutdown(associationID);
        }
    }
    if (length > 0) {
        SCTP_send(associationID,
                  currentStream,
                  (unsigned char*)readBuffer, length,
                  SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                  SCTP_USE_PRIMARY, SCTP_NO_CONTEXT,
                  timeToLive, SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED);
    }
    if (rotateStreams) currentStream = (currentStream + 1)%numberOutStreams;
}


int main(int argc, char **argv)
{
    SCTP_ulpCallbacks terminalUlp;
    SCTP_InstanceParameters instanceParameters;
    SCTP_LibraryParameters params;
    char buffer[2000];

    /* initialize the terminal_ulp variable */
    terminalUlp.dataArriveNotif           = &dataArriveNotif;
    terminalUlp.sendFailureNotif          = &sendFailureNotif;
    terminalUlp.networkStatusChangeNotif  = &networkStatusChangeNotif;
    terminalUlp.communicationUpNotif      = &communicationUpNotif;
    terminalUlp.communicationLostNotif    = &communicationLostNotif;
    terminalUlp.communicationErrorNotif   = &communicationErrorNotif;
    terminalUlp.restartNotif              = &restartNotif;
    terminalUlp.shutdownCompleteNotif     = &shutdownCompleteNotif;
    terminalUlp.peerShutdownReceivedNotif = &shutdownReceivedNotif;

    /* handle all command line options */
    getArgs(argc, argv);
    checkArgs();

    SCTP_initLibrary();
    SCTP_getLibraryParameters(&params);
    params.sendOotbAborts    = sendOOTBAborts;
    params.supportPRSCTP     = 1;
    params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_CRC32C;
    SCTP_setLibraryParameters(&params);

    sctpInstance=SCTP_registerInstance(localPort,
                                       MAXIMUM_NUMBER_OF_IN_STREAMS,  MAXIMUM_NUMBER_OF_OUT_STREAMS,
                                       noOfLocalAddresses, localAddressList,
                                       terminalUlp);

    /* set the TOS byte */
    SCTP_getAssocDefaults((unsigned short)sctpInstance, &instanceParameters);
    instanceParameters.ipTos               = tosByte;
    instanceParameters.rtoMin              = rto_min;
    instanceParameters.rtoMax              = rto_max;
    instanceParameters.rtoInitial          = rto_min;
    if (myRwndSpecified)
      instanceParameters.myRwnd = myRwnd;
    SCTP_setAssocDefaults((unsigned short)sctpInstance, &instanceParameters);

    SCTP_registerStdinCallback(&stdinCallback, buffer, sizeof(buffer));
    associationID=SCTP_associate((unsigned short)sctpInstance, MAXIMUM_NUMBER_OF_OUT_STREAMS, destinationAddress, remotePort, NULL);

    /* run the event handler forever */
    while (1){
        SCTP_eventLoop();
    }

    /* this will never be reached */
    exit(0);
}


