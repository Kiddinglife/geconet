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

/*
Example:
sudo ./testsctp -i   (Start in server mode)
sudo ./testsctp -i -T 10 -l 300 127.0.0.1   (Start in client mode, send 300 byte buffers for 10s)
*/

#include "sctp_wrapper.h"

#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>         /* for atoi() under Linux */
#include <sys/time.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define DEFAULT_LENGTH                     1024
#define DEFAULT_NUMBER_OF_MESSAGES         1024
#define DEFAULT_PORT                       5001
#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES    10
#define MAXIMUM_NUMBER_OF_ASSOCIATIONS        5
#define MAXIMUM_NUMBER_OF_IN_STREAMS         17
#define MAXIMUM_NUMBER_OF_OUT_STREAMS        17
#define MAXIMUM_PAYLOAD_LENGTH          1000000
#define SEND_QUEUE_SIZE                     100

#ifndef min
#define min(x,y)            (x)<(y)?(x):(y)
#endif

#ifndef timersub
#define timersub(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)
#endif

struct ulp_data {
    int maximumStreamID;
    unsigned int assocID;
    unsigned long nrOfReceivedChunks;
    unsigned long long nrOfReceivedBytes;
    int ShutdownReceived;
    unsigned int    stopTimerID;
    unsigned long nrOfSentChunks;
    unsigned long long nrOfSentBytes;
};

static struct ulp_data ulpData[MAXIMUM_NUMBER_OF_ASSOCIATIONS];
static unsigned char localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned char destinationAddress[SCTP_MAX_IP_LEN];

static unsigned short localPort               = DEFAULT_PORT;
static unsigned short remotePort              = DEFAULT_PORT;
static unsigned short noOfLocalAddresses      = 0;
static unsigned short numberOfInitialPackets  = DEFAULT_NUMBER_OF_MESSAGES;
static unsigned short chunkLength             = DEFAULT_LENGTH;
static unsigned char  tosByte                 = 0x10;  /* IPTOS_LOWDELAY */
static int verbose                            = 0;
static int vverbose                           = 0;
static int unknownCommand                     = 0;
static int rotateStreams                      = 0;
static int startAssociation                   = 0;
static int sendOOTBAborts                     = 1;
static int timeToLive                         = SCTP_INFINITE_LIFETIME;
static int firstLength                        = 0;
static int measurementTime                    = 0;
static unsigned int stopSending               = 0;
static unsigned int firstData                 = 0;
static struct timeval startTime;

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
   printf("usage:   testsctp [options]\n");
   printf("options:\n");
   printf("-a               use all streams in a round robin fashion when injecting packets\n");
   printf("-l               size of send/receive buffer\n");
   printf("-n number        number of messages sent (0 means infinite)/received\n");
   printf("-r port          remote port number (default echo port\n");
   printf("-L source_addr   local address\n");
   printf("-i               ignore OOTB packets\n");
   printf("-v               verbose mode\n");
   printf("-V               very verbose mode\n");
   printf("-T               time to send messages \n");
}

void getArgs(int argc, char **argv)
{
    int   i;
    int   optcount = 1;
    char *opt;

    for(i = 1;i < argc;i++) {
       if (argv[i][0] == '-') {
          switch (argv[i][1]) {
             case 'a':
                rotateStreams = 1;
                optcount++;
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
                optcount+=2;
              break;
             case 'l':
                if (i+1 >= argc) {
                   printUsage();
                   exit(0);
                }
                opt = argv[++i];
                chunkLength = min(atoi(opt),MAXIMUM_PAYLOAD_LENGTH);
                optcount+=2;
              break;
             case 'n':
                if (i+1 >= argc) {
                   printUsage();
                   exit(0);
                }
                opt = argv[++i];
                numberOfInitialPackets = atoi(opt);
                optcount+=2;
              break;
             case 'o':
                if (i+1 >= argc) {
                   printUsage();
                   exit(0);
                }
                opt = argv[++i];
                localPort = (unsigned short)atoi(opt);
                optcount+=2;
              break;
             case 'r':
                if (i+1 >= argc) {
                   printUsage();
                   exit(0);
                }
                opt = argv[++i];
                remotePort = atoi(opt);
                optcount+=2;
              break;
             case 'L':
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
                optcount+=2;
               break;
             case 'i':
                sendOOTBAborts = 0;
                optcount++;
              break;
             case 'v':
                verbose = 1;
                optcount++;
              break;
             case 'V':
                verbose = 1;
                vverbose = 1;
                optcount++;
              break;
             case 'T':
                if (i+1 >= argc) {
                   printUsage();
                   exit(0);
                }
                opt = argv[++i];
                measurementTime = atoi(opt)*1000;
                numberOfInitialPackets = 0;
                optcount+=2;
              break;
             default:
                unknownCommand = 1;
              break;
          }
      } else if (i!=argc-1) {
         unknownCommand = 1;
      }
   }

   if (optcount != argc) {
      opt = argv[optcount];
      if (strlen(opt) < SCTP_MAX_IP_LEN) {
         strcpy((char *)destinationAddress, opt);
         startAssociation = 1;
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


void
stopSendingFunction(unsigned int timerID, void *parameter1, void *parameter2)
{
   stopSending = 1;
}


void dataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int len,
                     unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
   unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
   unsigned int length;
   unsigned short ssn;
   unsigned int the_tsn;


   if (vverbose) {
      fprintf(stdout, "%-8x: Data arrived (%u bytes on stream %u, %s)\n",
                      assocID, len, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
      fflush(stdout);
   }

   /* read it */

   length = sizeof(chunk);
   if (firstLength == 0)
   firstLength = len;
   SCTP_receive(assocID, streamID, chunk, &length, &ssn, &the_tsn, SCTP_MSG_DEFAULT);

   if (firstData == 0) {
      gettimeofday(&startTime, NULL);
      firstData = 1;
   }
   /* update counter */
   ((struct ulp_data *) ulpDataPtr)->nrOfReceivedChunks += 1;
   ((struct ulp_data *) ulpDataPtr)->nrOfReceivedBytes  += length;
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
   unsigned int index;
   unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
   SCTP_PathStatus pathStatus;
   unsigned short pathID;
   unsigned short streamID = 0;
   unsigned long packetNumber;
   struct timeval now, diffTime;
   double seconds, throughput;


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
      ulpData[index].nrOfSentChunks = 0;
      ulpData[index].nrOfSentBytes  = 0;

      if (numberOfInitialPackets > 0 && startAssociation) {
         /* send the initial packets */
         memset(chunk, 0, sizeof(chunk));
         gettimeofday(&startTime, NULL);
         for(packetNumber=1; packetNumber <= numberOfInitialPackets; packetNumber++) {
         SCTP_send(assocID,
            streamID,
            chunk, chunkLength,
            SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
            SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive,
            SCTP_ORDERED_DELIVERY,
            SCTP_BUNDLING_DISABLED);
         if (rotateStreams) {
            streamID = (streamID + 1) % noOfOutStreams;
         }
         ulpData[index].nrOfSentChunks += 1;
              ulpData[index].nrOfSentBytes  += chunkLength;
         }
         SCTP_shutdown(assocID);
         if (verbose) {
            fprintf(stdout, "%ld messages of size %d sent.\n",
               packetNumber-1, chunkLength);
         }
      }
      else if (measurementTime > 0) {
         memset(chunk, 0, sizeof(chunk));
         ulpData[index].stopTimerID = SCTP_startTimer(measurementTime, &stopSendingFunction, (void *) &ulpData[index], NULL);
         gettimeofday(&startTime, NULL);
         while((SCTP_send(assocID, streamID, chunk, chunkLength, SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                          SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive,
                          SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED) == SCTP_SUCCESS) && stopSending!=1) {
            if (vverbose) {
             fprintf(stdout, "%-8x: %u bytes sent.\n", assocID, chunkLength);
             fflush(stdout);
            }
            if (rotateStreams) {
               streamID = (streamID + 1) % noOfOutStreams;
            }

            ulpData[index].nrOfSentChunks += 1;
            ulpData[index].nrOfSentBytes  += chunkLength;
         }
         if (stopSending == 1) {
            SCTP_shutdown(assocID);
            gettimeofday(&now, NULL);
            timersub(&now, &startTime, &diffTime);
            seconds = diffTime.tv_sec + (double)diffTime.tv_usec/1000000;
            fprintf(stdout, "%s of %ld messages of length %u took %f seconds.\n",
               "Sending", ulpData[index].nrOfSentChunks, chunkLength, seconds);
            throughput = (double)ulpData[index].nrOfSentChunks * (double)chunkLength / seconds / 1024.0;
            fprintf(stdout, "Throughput was %f KB/sec.\n", throughput);
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

      fprintf(stdout, "%ld messages of size %d received, (%llu bytes).\n",
               ((struct ulp_data *) ulpDataPtr)->nrOfReceivedChunks, firstLength, ((struct ulp_data *) ulpDataPtr)->nrOfReceivedBytes);
      fflush(stdout);
   }
   /* free ULP data */
   ((struct ulp_data *) ulpDataPtr)->maximumStreamID = -1;
   SCTP_deleteAssociation(assocID);
   if (startAssociation)
   exit (0);
   firstLength = 0;
}

void shutdownReceivedNotif(unsigned int assocID, void* ulpDataPtr)
{
   struct timeval now, diffTime;
   double seconds;

   if (verbose) {
      fprintf(stdout, "%-8x: Shutdown received\n", assocID);
      fflush(stdout);
   }

   stopSending = 1;

   ((struct ulp_data *)ulpDataPtr)->ShutdownReceived = 1;
   gettimeofday(&now, NULL);
   timersub(&now, &startTime, &diffTime);
   seconds = diffTime.tv_sec + (double)diffTime.tv_usec/1000000.0;
   fprintf(stdout, "%u, %lu, %lu, %lu, %llu, %f, %f\n",
           firstLength, ((struct ulp_data *)ulpDataPtr)->nrOfReceivedChunks, ((struct ulp_data *)ulpDataPtr)->nrOfReceivedChunks, ((struct ulp_data *) ulpDataPtr)->nrOfReceivedChunks, ((struct ulp_data *)ulpDataPtr)->nrOfReceivedBytes, seconds, (double)firstLength * (double)((struct ulp_data *)ulpDataPtr)->nrOfReceivedChunks / seconds / 1024.0);
   fflush(stdout);
}

void queueStatusChangeNotif(unsigned int assocID, int queueType, int queueID, int queueLength, void* ulpDataPtr)
{
   unsigned char chunk[MAXIMUM_PAYLOAD_LENGTH];
   unsigned short streamID = 0;
   struct timeval now, diffTime;
   double seconds, throughput;

   if (vverbose) {
       fprintf(stdout, "%-8x: Queue status change notification: Type %d, ID %d, Length %d\n",
                       assocID, queueType, queueID, queueLength);
       fflush(stdout);
   }

   if (queueType == SCTP_SEND_QUEUE && queueLength <= SEND_QUEUE_SIZE) {
      memset(chunk, 0, sizeof(chunk));

      while(stopSending!=1 && (!(((struct ulp_data *)ulpDataPtr)->ShutdownReceived)) &&
            (SCTP_send(assocID, streamID, chunk, chunkLength, SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                      SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, timeToLive,
                      SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED) == SCTP_SUCCESS)) {
         if (vverbose) {
            fprintf(stdout, "%-8x: %u bytes sent.\n", assocID, chunkLength);
            fflush(stdout);
         }
         if (rotateStreams) {
            streamID = (streamID + 1) % (((struct ulp_data *)ulpDataPtr)->maximumStreamID+1);
         }
         ((struct ulp_data *)ulpDataPtr)->nrOfSentChunks += 1;
         ((struct ulp_data *)ulpDataPtr)->nrOfSentBytes  += chunkLength;
      }
   }
   if ((stopSending == 1) && (queueLength == 0)) {
      SCTP_shutdown(assocID);
      gettimeofday(&now, NULL);
      timersub(&now, &startTime, &diffTime);
      seconds = diffTime.tv_sec + (double)diffTime.tv_usec/1000000;
      fprintf(stdout, "%s of %ld messages of length %u took %f seconds.\n",
         "Sending", ((struct ulp_data *)ulpDataPtr)->nrOfSentChunks, chunkLength, seconds);
      throughput = (double)((struct ulp_data *)ulpDataPtr)->nrOfSentChunks * (double)chunkLength / seconds / 1024.0;
      fprintf(stdout, "Throughput was %f KB/sec.\n", throughput);
   }
}

int main(int argc, char **argv)
{
   int sctpInstance;
   SCTP_ulpCallbacks testUlp;
   SCTP_InstanceParameters instanceParameters;
   SCTP_LibraryParameters params;
   unsigned int index;

   /* initialize ULP data */
   for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
      ulpData[index].maximumStreamID    = -1;
      ulpData[index].nrOfReceivedChunks = 0;
      ulpData[index].nrOfReceivedBytes  = 0;
      ulpData[index].ShutdownReceived   = 0;
      ulpData[index].nrOfSentChunks = 0;
      ulpData[index].nrOfSentBytes  = 0;
   }

   /* initialize the echo_ulp variable */
   testUlp.dataArriveNotif           = &dataArriveNotif;
   testUlp.sendFailureNotif          = &sendFailureNotif;
   testUlp.networkStatusChangeNotif  = &networkStatusChangeNotif;
   testUlp.communicationUpNotif      = &communicationUpNotif;
   testUlp.communicationLostNotif    = &communicationLostNotif;
   testUlp.communicationErrorNotif   = &communicationErrorNotif;
   testUlp.restartNotif              = &restartNotif;
   testUlp.shutdownCompleteNotif     = &shutdownCompleteNotif;
   testUlp.peerShutdownReceivedNotif = &shutdownReceivedNotif;
   testUlp.queueStatusChangeNotif    = &queueStatusChangeNotif;


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
                                      testUlp);
   /* set the TOS field */

   SCTP_getAssocDefaults((unsigned short)sctpInstance, &instanceParameters);
   instanceParameters.maxSendQueue = SEND_QUEUE_SIZE;
   instanceParameters.ipTos=tosByte;
   SCTP_setAssocDefaults((unsigned short)sctpInstance, &instanceParameters);

   if (startAssociation) {
      SCTP_associate((unsigned short)sctpInstance, MAXIMUM_NUMBER_OF_OUT_STREAMS, destinationAddress, remotePort, &ulpData[0]);
   }

   while (1) {
      SCTP_eventLoop();
   };

   /* this will never be reached */
   return 0;
}
