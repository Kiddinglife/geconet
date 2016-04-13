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
#include <time.h>


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "sctp_wrapper.h"

#define DAYTIME_PORT                         13
#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES    10
#define MAXIMUM_PAYLOAD_LENGTH             8192
#define MAXIMUM_NUMBER_OF_IN_STREAMS          1
#define MAXIMUM_NUMBER_OF_OUT_STREAMS         1

static unsigned char  localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned short noOfLocalAddresses = 0;

static int verbose  = 0;
static int vverbose = 0;
static int unknownCommand = 0;
static int sendOOTBAborts = 1;
static int timeToLive     = SCTP_INFINITE_LIFETIME;

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
    printf("Usage:   daytime_server [options]\n");
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
                case 'i':
                    sendOOTBAborts = 0;
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
                     unsigned short streamSN, unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
    unsigned int length;
    unsigned int tsn;
    unsigned short ssn;

 
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
    char *timeAsString;
    time_t now;
 
    if (verbose) {  
        fprintf(stdout, "%-8x: Communication up (%u paths)\n", assocID, noOfDestinations);
        fflush(stdout);
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

void communicationLostNotif(unsigned int assocID, unsigned short status, void* ulpDataPtr)
{	
    if (verbose) {
        fprintf(stdout, "%-8x: Communication lost (status %u)\n", assocID, status);
        fflush(stdout);
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
    SCTP_ulpCallbacks daytimeUlp;
    SCTP_LibraryParameters params;

    /* initialize the daytime_ulp variable */
    daytimeUlp.dataArriveNotif           = &dataArriveNotif;
    daytimeUlp.sendFailureNotif          = &sendFailureNotif;
    daytimeUlp.networkStatusChangeNotif  = &networkStatusChangeNotif;
    daytimeUlp.communicationUpNotif      = &communicationUpNotif;
    daytimeUlp.communicationLostNotif    = &communicationLostNotif;
    daytimeUlp.communicationErrorNotif   = &communicationErrorNotif;
    daytimeUlp.restartNotif              = &restartNotif;
    daytimeUlp.shutdownCompleteNotif     = &shutdownCompleteNotif;
    daytimeUlp.peerShutdownReceivedNotif = &shutdownReceivedNotif;

    /* handle all command line options */
    getArgs(argc, argv);
    checkArgs();
    
    SCTP_initLibrary();
    SCTP_getLibraryParameters(&params);
    params.sendOotbAborts    = sendOOTBAborts;
    params.checksumAlgorithm = SCTP_CHECKSUM_ALGORITHM_CRC32C;
    SCTP_setLibraryParameters(&params);
    
    /* set up the "server" */
    SCTP_registerInstance(DAYTIME_PORT,
                          MAXIMUM_NUMBER_OF_IN_STREAMS, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                          noOfLocalAddresses, localAddressList,
                          daytimeUlp);

    /* run the event handler forever */
    while (1) {
        SCTP_eventLoop();
    }
    
    /* this will never be reached */
    exit(0);
}

