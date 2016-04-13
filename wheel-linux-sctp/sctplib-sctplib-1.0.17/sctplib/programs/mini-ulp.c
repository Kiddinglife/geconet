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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/*****************************************************************************/
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
/*****************************************************************************/
#define MAX_DATA_LENGTH    MAX_DATACHUNK_PDU_LENGTH - 4

#include "mini-ulp.h"
/* #include "globals.h" */    /* this is for log functions, but should actually disappear */

unsigned int assocID = 0;
unsigned int  timerID = 0;
unsigned int noOfPaths = 1;
unsigned int currentPath = 0;
unsigned short noInStreams = 0;
unsigned short noOutStreams = 0;

unsigned short sID1 = 0;
unsigned int csqnr = 0;
unsigned int sendNo = 0;

unsigned int chunks_received = 0;
unsigned int timeoutval= 1000;
unsigned int payload = 0;
/* global parameters, valid for all associations */
extern unsigned int localNumberOfInStreams;

extern gboolean use_unordered;

static int dosend = 0;
gboolean heartbeat = FALSE;
gboolean streamRoundRobin = FALSE;
unsigned int timeInt;
unsigned int sendEvents = 0xFFFFFFFF;
unsigned int shutdownEvent = 0xFFFFFFFF;
unsigned int abortEvent = 0xFFFFFFFF;
static int dataLength = 20;     /* length of payload data in bytes without payload prot-ID.
                                   default length is 20. */

/* variables for playing ping pong.........*/
unsigned int pingPongCount = 0;
unsigned short pingBufSize = 0;
unsigned short pingStream = 0;
unsigned char  pingBuffer[1500];
struct timeval pingstart_time;
struct timeval pongstop_time;



struct timeval start_time;
struct timeval stop_time;


gboolean start_sent = FALSE;
gboolean stop_sent = FALSE;



void timer_expired(unsigned int tID, void *associationIDvoid, void *unused);





/**
  This function prints a bytestring if Current_event_log_ is 4 (max).
   @param log_name         a short name that is printed along with the bytestring
   @param byte_string      the bytestring
   @param nbytes           the length of the bytestring
*/
void printString(char *log_name, unsigned char *byte_string, short nbytes)
{
    int i, j, linesOut;
    char buff1[64];
    char buff2[64];
    char *ptr1, *ptr2, *dptrlast, *dptr;
    char *hexes = "0123456789ABCDEF";

    fprintf(stdout, "Bytestring: %s.................................\n", log_name);

    ptr1 = buff1;
    ptr2 = buff2;
    dptrlast = dptr = (char *)byte_string;
    for (i = 0, linesOut = 0; i < nbytes; i++) {
        *ptr1++ = hexes[0x0f & ((*dptr) >> 4)];
        *ptr1++ = hexes[0x0f & (*dptr)];
        *ptr1++ = ' ';
        if ((*dptr >= 040) && (*dptr <= 0176))
            *ptr2++ = *dptr;
        else
            *ptr2++ = '.';
        dptr++;
        if (((i + 1) % 16) == 0) {
            *ptr1 = 0;
            *ptr2 = 0;
            fprintf(stdout, "%s %s\n", buff1, buff2);
            linesOut++;
            ptr1 = buff1;
            ptr2 = buff2;
            dptrlast = dptr;
        }
    }
    if ((linesOut * 16) < nbytes) {
        char spaces[64];
        int dist, sp;

        j = (linesOut * 16);
        dist = ((16 - (i - j)) * 3) + 2;
        *ptr1 = 0;
        *ptr2 = 0;
        for (sp = 0; sp < dist; sp++) {
            spaces[sp] = ' ';
        }
        spaces[sp] = 0;
        fprintf(stdout, "%s %s%s\n", buff1, spaces, buff2);
    }
    fflush(stdout);
}





void ulp_setChunkLength(int chunkLength)
{
    dataLength = chunkLength;
    fprintf(stderr, "Sendig data with chunklength = %d\n", chunkLength);
}

void ulp_getEndEvents(unsigned int shutdownAfter, unsigned int abortAfter)
{
    shutdownEvent = shutdownAfter;
    abortEvent = abortAfter;
}




void mulp_heartbeat(unsigned int interval)
{
    heartbeat = TRUE;
    timeInt = interval;
}

void mulp_dosend(void)
{
    dosend = 1;
}


void mulp_streamRoundRobin(void)
{
    streamRoundRobin = TRUE;
}

void nextPath(void)
{
    unsigned short daddr;
    int i;
    fprintf(stdout, "nextPath() : currentPath=%u, noOfPaths=%u", currentPath, noOfPaths);
    i = 0;
    do {
        currentPath = (currentPath + 1) % noOfPaths;
        daddr = currentPath;
        i++;
        if (i > noOfPaths) {
            fprintf(stderr, "ULP: no active path found: !!!! \n");
            break;
        }
    }
    while (sctp_setPrimary(assocID, daddr));

    fprintf(stdout, "ULP: changed primary path to: %u", currentPath);
    return;
}

int doPingPong(void)
{
    int i;
    /* use ascii bulk ping mode. */
    strncpy((char *)pingBuffer, "ping", 4);
    for (i = 4; i < pingBufSize; i++) {
            pingBuffer[i] = 'A' + (i % 26);
    }
    gettimeofday(&pingstart_time, NULL);
    return sctp_send(assocID, pingStream, (unsigned char *) pingBuffer,
                pingBufSize, payload, -1, 0, 0, 0, 0);
}


int handlePong(void)
{
    int secs, msecs, timediff;
    struct timeval result;

    pingPongCount--;
    if (pingPongCount <= 0) {
        /* done */
        printf("#######################################################################\n");

        gettimeofday(&pongstop_time, NULL);

        timersub(&pongstop_time, &pingstart_time, &result);
        timediff = result.tv_sec * 1000 + result.tv_usec / 1000;

        secs = timediff / 1000;
        msecs = timediff % 1000;
        printf("PingPong took %d.%d seconds to complete !!!!\n", secs, msecs);

        printf("#######################################################################\n");
        fflush(stdout);
        return -1 ;
    }
    return sctp_send(assocID, pingStream, (unsigned char *) pingBuffer,
         pingBufSize, payload, -1, 0, 0, 0, 0);
}


void ulp_stdin_cb(int fd, short int revents, short int* gotEvents, void* dummy)
{
    int lenread,i;
    SCTP_AssociationStatus status;

    char readBuffer[256];
    fgets(readBuffer, 256, stdin);
    lenread = strlen(readBuffer);

    while(lenread > 0 && (readBuffer[(lenread - 1)] == '\n' || readBuffer[(lenread - 1)] == '\r')) {
        readBuffer[(lenread - 1)] = 0;
        lenread --;
    }

    if (lenread == 0) {
        printf(">");
        fflush(stdout);
        return;
    }
    if (strcmp(readBuffer, "help") == 0) {
        printf("Available commands are:\n");
        printf(" quit - exit the program\n");
        /*
        printf(" setassoc:WWW.XXX.YYY.ZZZ - set association id for assoc with this destination\n");
        */
        printf(" setpay:payload - set the payload type\n");
        printf(" setdefstrm:num - set the default stream to\n");
        printf(" ping:size:stream:times - play ping pong\n");
        printf(" stat - print queue counts\n");
        printf(" bulk:size:stream:number - send a bulk of messages\n");
        printf(" assoc - associate with the set destination\n");
        printf(" abort - send an abort to the peer\n");
        printf(" nextpath - switch to next path\n");
        printf(" term - terminate the set destination association (graceful shutdown )\n");
        printf(" heart:on/off - Turn HB on or off  to the destination\n");
        printf(" heartdelay:time - Add number of seconds + RTO to hb interval\n");
        printf(" getrtt - print RTT on primary path\n");
        printf(" dohb:N - send a HB on path N\n");
        printf(" sendloop:N - send test script loopback request of N size\n");
        printf(" sendloopend:N - send test script loopback request of N size and terminate\n");
        printf(" timeoutval:msecs - set bulk timer to send one message every msecs\n");
        printf(" some-other-string - send this to a peer if a peer is set\n");
    } else if (strcmp(readBuffer, "quit") == 0) {
        /* add some cleanups */
        exit(0);
    } else if (strcmp(readBuffer, "nextpath") == 0) {
        nextPath();
    } else if (strcmp(readBuffer, "abort") == 0) {
        int result;
        result = sctp_abort(assocID);
        timerID = 0;
        printf("Sent an abort -> result %d\n", result);
    } else if (strncmp(readBuffer, "sendloop:", 9) == 0) {
        int x, ret = -1;
        x = (int) strtol(&readBuffer[9], NULL, 0);
        if (x == 0) {
            printf("N was 0? defaulting to 64\n");
            x = 64;
        }
        /*
        ret = sendLoopRequest(m, x);
        */
        printf("Sent loop returned %d\n", ret);
    } else if (strncmp(readBuffer, "setpay:", 7) == 0) {
        payload = strtol(&readBuffer[7], NULL, 0);
        printf("payloadtype set to %d\n", payload);
    } else if (strncmp(readBuffer, "setassoc:", 9) == 0) {
/*      this could be used when we have several assocs    */
/*         = strtol(&readBuffer[9], NULL, 0);  */
        printf("assoc ID is %u\n", assocID);
    } else if (strncmp(readBuffer, "timeoutval:", 11) == 0) {
        timeoutval = strtol(&readBuffer[11], NULL, 0);
        printf("Timeoutval set to %d msecs\n", timeoutval);
     } else if (strncmp(readBuffer, "heart:", 6) == 0) {
        if (strncmp(&readBuffer[6], "off", 3) == 0) {
            for (i = 0; i < noOfPaths; i++)
                sctp_changeHeartBeat(assocID, i, FALSE, 0);
        } else {
            for (i = 0; i < noOfPaths; i++)
                sctp_changeHeartBeat(assocID, i, TRUE, timeoutval);
        }
    } else if (strcmp(readBuffer, "getrtt") == 0) {
        /* printf("RTT of TO is %d\n", sctpGETRTTREPORT(m, &to_ip)); */
    } else if (strncmp(readBuffer, "dohb:",5) == 0) {
        int path;
        path = strtol(&readBuffer[5], NULL, 0);
        path =  sctp_requestHeartbeat(assocID, (short)path);
        printf("HB Request %s\n", (path==0)?"successfully sent":"failed");
    } else if (strncmp(readBuffer, "heartdelay:", 11) == 0) {
        int newdelay;
        newdelay = strtol(&readBuffer[11], NULL, 0);
        for (i = 0; i < noOfPaths; i++)
            sctp_changeHeartBeat(assocID, i, TRUE, newdelay);
        timeoutval =  newdelay;
        printf("HB.Intervall set to %d msecs\n", newdelay);
     } else if (strcmp("term", readBuffer) == 0) {
        sctp_shutdown(assocID);
        timerID = 0;
     } else if (strcmp("stat", readBuffer) == 0) {
        i = sctp_getAssocStatus(assocID,&status);
        if (i == 0) {
            printf(" %u chunks in SendQueue, %u chunks in RTX queue\n",
                status.noOfChunksInSendQueue, status.noOfChunksInRetransmissionQueue);
        }
    } else if (strncmp("setdefstrm:", readBuffer, 11) == 0) {
        sID1 = strtol(&readBuffer[11], NULL, 0);
    } else if (strcmp("assoc", readBuffer) == 0) {
        printf("Sorry - command not yet implemented\n");
        /*    sctpASSOCIATE(m, &to_ip, 0); */
    } else if (strncmp("ping:", readBuffer, 5) == 0) {
        char *end, *nxt;
        int skip;
        skip = 0;
        if (pingPongCount) {
            printf("Sorry ping-pong already in progress\n");
            printf(">");
            fflush(stdout);
            return;
        }
        pingBufSize = strtol(&readBuffer[5], &end, 0);
        if (end != NULL) {
            if (*end != ':') {
                skip = 1;
            }
        } else {
            skip = 1;
        }

        if (skip) {
            printf("mal-formed request at size\n");
            printf(">");
            fflush(stdout);
            return;
        }
        nxt = end;
        nxt++;
        pingStream = strtol(nxt, &end, 0);
        if (end != NULL) {
            if (*end != ':') {
                skip = 1;
            }
        } else {
            skip = 1;
        }
        if (skip) {
            printf("mal-formed request stream\n");
            printf(">");
            fflush(stdout);
            return;
        }
        nxt = end;
        nxt++;
        pingPongCount = strtol(nxt, NULL, 0);
        if (pingPongCount == 0) {
            printf("mal-formed request at times\n");
            printf(">");
            fflush(stdout);
            return;
        }
        /* prepare ping buffer */
        doPingPong();
    } else if (strncmp("bulk:", readBuffer, 5) == 0) {
        /*
        int ret;
        */
        char *end, *nxt;
        int skip;
        skip = 0;
        dataLength = strtol(&readBuffer[5], &end, 0);
        if (end != NULL) {
            if (*end != ':') {
                skip = 1;
            }
        } else {
            skip = 1;
        }

        if (skip) {
            printf("mal-formed request at size\n");
            printf(">");
            fflush(stdout);
            return;
        }
        nxt = end;
        nxt++;
        sID1 = strtol(nxt, &end, 0);
        if (end != NULL) {
            if (*end != ':') {
                skip = 1;
            }
        } else {
            skip = 1;
        }
        if (skip) {
            printf("mal-formed request stream\n");
            printf(">");
            fflush(stdout);
            return;
        }
        nxt = end;
        nxt++;
        sendEvents = strtol(nxt, NULL, 0);
        if (sendEvents == 0) {
            printf("mal-formed request at times\n");
            printf(">");
            fflush(stdout);
            sendEvents = 0;
            return;
        }
        timerID = sctp_startTimer(timeoutval/1000, (timeoutval%1000)*1000, &timer_expired, NULL, NULL);

    } else if (strcmp("inqueue", readBuffer) == 0) {
/*        printf("Outbound queue count to dest = %d\n", sctpHOWMANYINQUEUE(m, &to_ip)); */
/*        printf("Inbound queue count = %d\n", sctpHOWMANYINBOUND(m)); */
    } else {
        if (timerID != 0) {
            printf("bulk or ping might be in progress, not sending !!!\n");
        } else {
            int xsxx;
            xsxx = sctp_send(assocID, sID1, (unsigned char *)readBuffer,
                   lenread, payload, -1, 0, 0, 0, 0);
            printf("Returned %d from the send (1==association error, 0==success, -1==could not send)\n", xsxx);
        }
    }
    printf(">");
    fflush(stdout);

}

void
ulp_socket_error(gint sin_fd,
                 unsigned char *buffer,
                 int bufferLength, unsigned char fromAddress[], unsigned short pn)
{
    fprintf(stderr, "Read Error In Function ulp_socket_error !!!!!");
}


#define SEND_EVENTS_WHEN_TIMER_EXPIRES  10

void timer_expired(unsigned int tID, void *associationIDvoid, void *unused)
{
    unsigned char chunk[2000];
    int result;
    int i;
    unsigned char j;

/*
    AssociationStatus *state = NULL;
*/

/*  fprintf(stderr, "#######################################################################\n");
    fprintf(stderr, "ULP timer expired: sending next chunk\n");
    fprintf(stderr, "#######################################################################\n");
 */

    for (i = 0, j = 0; i < dataLength; i++, j++) {
        chunk[i] = j % 25 + 33; /* loop thru the letter of the alphabet */
    }

    sendNo += SEND_EVENTS_WHEN_TIMER_EXPIRES;
    if (sendNo > sendEvents) {
/*        if (stop_sent==FALSE) {
            stop_sent = TRUE;
            sctp_send(assocID, sID1,  (unsigned char*)stopmsg, 12, 0,
                           -1, 0,  0, 0, 0,SCTP_SEND_RELIABLE);
            timerID = sctp_startTimer(1,0, &timer_expired, NULL, NULL);
            return;
        }
 */
        timerID = 0;
    } else if (sendNo > shutdownEvent) {
        printf("Sending all done, starting Shutdown procedure !\n");
        sctp_shutdown(assocID);
        timerID = 0;
    } else {
        if (streamRoundRobin) {
            sID1 = (sID1 + 1) % noOutStreams;
        }
/*        if (start_sent == FALSE) {
            start_sent = TRUE;
            sctp_send(assocID, sID1,  (unsigned char*)startmsg, 12, 0,
                           -1, 0,  0, 0, 0,SCTP_SEND_RELIABLE);
            timerID = sctp_startTimer(1,0, &timer_expired, NULL, NULL);
            return;
        }
*/
            /*      send every third package unordered */
            /*                send chunk with length = datalength  */

        for (i = 0; i < SEND_EVENTS_WHEN_TIMER_EXPIRES; i++) {
           /*gettimeofday((struct timeval *) &chunk[0], NULL); */
           result = sctp_send(assocID, sID1, (unsigned char *) chunk,
                           dataLength, payload, -1, 0, 0, use_unordered, 0);
        }

        if (result == -1) {
            printf("Shutdown procedure started, stopping sending new data !\n");
            timerID=0;
        } else {
            timerID = sctp_startTimer(timeoutval/1000,(timeoutval%1000)*1000, &timer_expired, NULL, NULL);
        }
    }
}



/*   FIXME :  stream_id must be of type unsigned short !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      indicates new data have arrived from peer (chapter 9.2.A).
      params: 1. associationID
              2. streamID
*/

void ulp_dataArriveNotif(unsigned int assoc_id, unsigned short stream_id, unsigned int len,
                         unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                         unsigned int unordered, void* dummy)
{
    unsigned char chunk[5000];
    int length, i;
    unsigned int theTSN;
    unsigned short SID, SSN;
    gboolean ascii_chunk;
/*
    struct timeval *t;
*/

    fprintf(stderr, "\n#######################################################################\n");
    fprintf(stderr, "ulp_dataArriveNotif : Association ID : %u, Stream ID : %u, Length : %u, TSN: %u, ProtoID : %u\n",
        assoc_id, stream_id, len, TSN, protoID);
    fprintf(stderr, "ulp_dataArriveNotif : Unordered Flag %s\n", (unordered==0)?"not set":"set");
    fprintf(stderr, "#######################################################################\n");

    sctp_receive(assoc_id, stream_id, chunk, (unsigned int *) &length, &SSN, &theTSN, SCTP_MSG_DEFAULT);
    chunks_received++;

/*
    t = (struct timeval *) chunk;
    fprintf(stderr, "%lu.%06lu \n", t->tv_sec, t->tv_usec);
*/
    if (pingPongCount > 0) {
        if (strncmp((char *)chunk, "pong", 4) == 0) {
            i = handlePong();
            if (i==-1) {
                printf("Data not sent, SHUTDOWN-state reached, terminating Ping-Pong !\n");
                pingPongCount = 0;
            }
            return;
        }

    }

    if(strncmp((char *)chunk, "ping", 4) == 0) {
        /* it is a ping-pong message, send it back after changing
         * the first 4 bytes to pong
         */
        strncpy((char *)chunk, "pong", 4);
        SID =  stream_id;
        i = sctp_send(assoc_id, SID, (unsigned char *) chunk,
            len, protoID, -1, 0, 0, 0, 0);
        if (i==-1) {
            printf("Pong reply not sent, SHUTDOWN-state reached --> cannot send PONGs !\n");
            pingPongCount = 0;
        }
        return;
    }

    ascii_chunk = TRUE;

    for(i=0; i<length; i++){
       if(!isprint(chunk[i])) ascii_chunk = FALSE;
       if (i< length-1)
         if (chunk[i+1]==0) break;
    }

    if(ascii_chunk) {
        chunk[length] = 0;
        printf("################## text received ################################\ntext: %s\n",
              (char*)chunk);
    } else {
        printString("ULP chunk received:", chunk, length);
    }
    printf(">");
    fflush(stdout);
}



/* indicates a change of network status (chapter 9.2.C).
   params: 1.  associationID
           2.  destinationAddresses
             3.  newState
*/
void ulp_networkStatusChangeNotif(unsigned int assoc_id, short dest_add, unsigned short new_state, void* dummy)
{
    fprintf(stderr, "\n#######################################################################\n");
    fprintf(stderr, "ulp_networkStatusChangeNotif: associationID = %u, destination address = %d \n",
        assoc_id, dest_add);
    fprintf(stderr, "ulp_networkStatusChangeNotif: state = %s, noOfPaths=%u\n",
        ((new_state == 0) ? "ACTIVE" : "INACTIVE"), noOfPaths);
    fprintf(stderr, "#######################################################################\n");

    printf(">");
    fflush(stdout);
    /* if (noOfPaths > 0 && new_state) nextPath(); */
}



/* indicates a send failure (chapter 9.2.B).
   params: 1.  associationID
           2.  pointer to data not sent
           3.  dataLength
           4.  context from sendChunk
*/
void
ulp_sendFailureNotif(unsigned int assoc_id,
                     unsigned char *unsent_data, unsigned int data_len, unsigned int *context, void* dummy)
{
    fprintf(stderr, "ulp_sendFailureNotif: Association ID : %d\n", assoc_id);
}


/* indicates that communication was lost to peer (chapter 9.2.E).
   params: 1.  associationID
           2.  status, type of event
*/
void ulp_communicationLostNotif(unsigned int assoc_id, unsigned short status, void* dummy)
{
    int i, timediff, secs, msecs;
    struct timeval result;


    fprintf(stderr, "\n#######################################################################\n");
    fprintf(stderr,
            "ulp_communicationLostNotif : Association ID : %d, State: %d\n", assoc_id, status);
    fprintf(stderr, "  Information  : Total number of Chunks received : %u\n", chunks_received);
    i = sctp_deleteAssociation(assoc_id);
    fprintf(stderr, "   Deleted Association with new ULP Primitive, result : %d\n", i);
    fprintf(stderr, "#######################################################################\n");

    i = gettimeofday(&stop_time, NULL);
    timersub(&stop_time, &start_time, &result);
    timediff = result.tv_sec * 1000 + result.tv_usec / 1000;

    secs = timediff / 1000;
    msecs = timediff % 1000;
    fprintf(stderr, "ASSOCIATION was up %d.%d seconds !!!!\n", secs, msecs);

    fprintf(stderr, "#######################################################################\n");

    if (timerID)
        sctp_stopTimer(timerID);
    timerID = 0;
    printf(">");
    fflush(stdout);
/*
    exit(0);
*/
}

void ulp_ShutdownCompleteNotif(unsigned int assoc_id, void* dummy)
{
    int i, timediff, secs, msecs;
    struct timeval result;

    fprintf(stderr, "\n#######################################################################\n");
    fprintf(stderr,
            "Shutdown Complete Notification: Association ID : %d was terminated\n", assoc_id);
    fprintf(stderr, "  Information  : Total number of Chunks received : %u\n", chunks_received);
    fprintf(stderr, "#######################################################################\n");
    i = gettimeofday(&stop_time, NULL);
    timersub(&stop_time, &start_time, &result);
    timediff = result.tv_sec * 1000 + result.tv_usec / 1000;

    secs = timediff / 1000;
    msecs = timediff % 1000;
    fprintf(stderr, "ASSOCIATION was up %d.%d seconds !!!!\n", secs, msecs);

    fprintf(stderr, "#######################################################################\n");

    if (timerID)
        sctp_stopTimer(timerID);
    timerID = 0;
    printf(">");
    fflush(stdout);
}



/* indicates that a association is established (chapter 9.2.D).
   params: 1.  associationID
           2.  status, type of event
*/
void* ulp_communicationUpNotif(unsigned int assoc_id, int status,
                         unsigned int noOfDestinations, unsigned short noOfInStreams, unsigned short noOfOutStreams,
                        int associationSupportsPRSCTP, void* dummy)
{
    int i;

    assocID = assoc_id;
    noOutStreams = noOfOutStreams;
    noInStreams = noOfInStreams;

    noOfPaths = noOfDestinations;

    fprintf(stderr, "\n#######################################################################\n");
    fprintf(stderr, "ulp_communicationUpNotif: Association ID : %d, State: %d\n", assoc_id, status);
    fprintf(stderr, "Number of paths: %03u,", noOfPaths);
    fprintf(stderr, "  No. of in-streams: %05d, No. of out-streams: %05d \n",
            noInStreams, noOutStreams);
    fprintf(stderr, "#######################################################################\n");

    chunks_received = 0;

    if (dosend)
        timerID = sctp_startTimer(timeoutval/1000, (timeoutval%1000)*1000, &timer_expired, NULL, NULL);
    i = gettimeofday(&start_time,NULL);

    if (!heartbeat)
        for (i = 0; i < noOfPaths; i++)
            sctp_changeHeartBeat(assocID, i, FALSE, 0);
    else
        for (i = 0; i < noOfPaths; i++)
            sctp_changeHeartBeat(assocID, i, TRUE, timeInt);
    /* by default, HB  is with adaptive intervall enabled */
    printf(">");
    fflush(stdout);
    return NULL;
}
