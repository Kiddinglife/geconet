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

#include "sctp.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>         /* for atoi() under Linux */
#include <curses.h>
#include <signal.h>

#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008


#define DISCARD_PORT                          9
#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES    10
#define MAXIMUM_NUMBER_OF_IN_STREAMS          9
#define MAXIMUM_NUMBER_OF_OUT_STREAMS         8
#define SCTP_GENERIC_PAYLOAD_PROTOCOL_ID      0
#define min(x,y)            (x)<(y)?(x):(y)

static unsigned char localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned char destinationAddress[SCTP_MAX_IP_LEN];
static unsigned short noOfLocalAddresses = 0;
static unsigned int associationID;
static short sctpInstance;

static unsigned short remotePort    = DISCARD_PORT;
static unsigned short localPort     = 1000;
static unsigned char  tosByte       = 0x10;  /* IPTOS_LOWDELAY */
static unsigned int deltaT          = 1000;
static unsigned int periodicRefresh = 0;
static int verbose                  = 0;
static int vverbose                 = 0;

static int bufCount = 0, client = 0;
static int chosenPath = 0 , displayPathDetails = 0;
static unsigned int currInstreamID, currOutstreamID;
static char buffer[SCTP_MAXIMUM_DATA_LENGTH];
char pathInfo[1024],assocInfo[1024],statusInfo[256], receivedInfo[256];

static WINDOW *pathWin, *pathWinHeader;
static WINDOW *assocWin, *assocWinHeader;
static WINDOW *statusWin, *statusWinHeader;
static WINDOW *textWin, *textWinHeader;
static WINDOW *receivedWin, *receivedWinHeader;

static int X1,X2,assocY1,assocY2,textY1,textY2;
static int pathY1,pathY2,statusY1,statusY2,helpY1,helpY2;


typedef struct SCTP_Monitor_ToolStatus
{
  unsigned char localAddrList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
  unsigned short noOfInStreams;
  unsigned short noOfOutStreams;
  short InstreamIDList[MAXIMUM_NUMBER_OF_IN_STREAMS];
  short OutstreamIDList[MAXIMUM_NUMBER_OF_OUT_STREAMS];
} SCTP_MonitorToolStatus;

SCTP_MonitorToolStatus statusUpdate;

char *
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
    printf("usage: monitor [options] -s source_addr_1 -d destination_addr ...\n");
    printf("options:\n");
    printf("-s source_address(es) source IP address(es)\n");
    printf("-d destination_addr   establish a association with the specified address\n");
    printf("-l local port         local port number\n");
    printf("-r remote port        remote port number\n");
    printf("-p period             specify period for the measurements in milliseconds (default 1000)\n");
    printf("-m                    do periodic refresh of data specified per period (see -p)\n");
    printf("-t byte               TOS byte used by all assiciations (default 0x10)\n");
    printf("-v                    verbose mode\n");
    printf("-V                    very verbose mode\n");
}

void getArgs(int argc, char **argv)
{
    int c;
    extern char *optarg;
    extern int optind;

    while ((c = getopt(argc, argv, "d:r:s:t:l:p:mvV")) != -1)
    {
        switch (c) {
        case 'd':
            if (strlen(optarg) < SCTP_MAX_IP_LEN) {
                strcpy((char *)destinationAddress, optarg);
        client = 1;
            }
            break;
        case 'l':
            localPort = atoi(optarg);
            break;
        case 'r':
            remotePort = atoi(optarg);
            break;
        case 's':
            if ((noOfLocalAddresses < MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES) &&
                (strlen(optarg) < SCTP_MAX_IP_LEN  )) {
                strcpy((char *)localAddressList[noOfLocalAddresses], optarg);
                noOfLocalAddresses++;
            }
            break;
    case 'p':
        deltaT = atoi(optarg);
        periodicRefresh = 1;
        break;
    case 'm':
        periodicRefresh = 1;
        break;
        case 't':
            tosByte = (unsigned char) atoi(optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'V':
            verbose = 1;
            vverbose = 1;
            break;
        }
    }
}

void checkArgs(void)
{
    if (noOfLocalAddresses == 0) {
        printf("Error: at least one sourceaddress and one destination address must be specified.\n");
        printUsage();
        exit(-1);
    }
    else if (client == 0){
    printf("Error: Please specify a destination. This Monitoring tool will not work as a server.\n");
        printUsage();
        exit(-1);
    }
    else if (remotePort == 0){
        printf("Error: Please specify a remote port. For example, port of echo_tool is 7\n");
        printUsage();
        exit(-1);
    }
}


/* Function to update the monitor tool data structure */
void UpdateMonitorToolStruct(unsigned short noOfInStreams, unsigned short noOfOutStreams)
{
  int i;

  /* Update the Monitor tool status structure */
  statusUpdate.noOfInStreams            = noOfInStreams;
  statusUpdate.noOfOutStreams           = noOfOutStreams;

  /* Initialise the Contents of InStreamList and OutStreamList to -1 */
  for (i=0; i < noOfInStreams; i++)
    {
      statusUpdate.InstreamIDList[i] = -1;
    }

  for (i=0; i < noOfOutStreams; i++)
    {
      statusUpdate.OutstreamIDList[i] = -1;
    }
}


void initializecurses()
/* This function draws the windows of the monitoring tool using ncurses */

{
    int i;

    initscr();
    cbreak();
    noecho();
    nonl();

    X1 = 0;
    X2 = COLS-1;

    assocY1 = 0;
    assocY2 = (int)((LINES-14)/2)-1;

    pathY1 = (int)((LINES-14)/2);
    pathY2 = LINES-14;

    statusY1 = pathY2+1;
    statusY2 = statusY1+5;

    textY1 = statusY2+1;
    textY2 = textY1+2;

    helpY1 = textY2+1;
    helpY2 = helpY1+3;

    assocWin = newwin((assocY2-assocY1),X2,assocY1+1,0);
    pathWin = newwin((pathY2-pathY1-1),X2,pathY1+2,0);
    statusWin = newwin(5,X2,statusY1+1,0);
    textWin = newwin(2,X2,textY1+1,0);
    receivedWin = newwin(3,X2,helpY1+1,0);

    assocWinHeader = newwin(1,X2,0,0);
    pathWinHeader = newwin(2,X2,pathY1,0);
    statusWinHeader = newwin(1,X2,statusY1,0);
    textWinHeader = newwin(1,X2,textY1,0);
    receivedWinHeader = newwin(1,X2,helpY1,0);

    waddstr(assocWinHeader,"Association Status");
    for (i=18;i<COLS-1;i++)
      mvwaddch(assocWinHeader,0,i,'*');

    waddstr(pathWinHeader,"Path Status");
    for (i=11;i<COLS-1;i++)
      mvwaddch(pathWinHeader,0,i,'*');
    mvwaddstr(pathWinHeader,1,0,"[Select numbers 0-9 to display path details for the path with the corresponding Path ID]");

    waddstr(statusWinHeader,"SCTP Events Status");
    for (i=18;i<COLS-1;i++)
      mvwaddch(statusWinHeader,0,i,'*');

    waddstr(textWinHeader,"Enter text here");
    for (i=15;i<COLS-1;i++)
      mvwaddch(textWinHeader,0,i,'*');

    waddstr(receivedWinHeader,"Data(Text) received");
    for (i=19;i<COLS-1;i++)
      mvwaddch(receivedWinHeader,0,i,'*');

    waddstr(statusWin, statusInfo);

    wnoutrefresh(assocWinHeader);
    wnoutrefresh(pathWinHeader);
    wnoutrefresh(statusWinHeader);
    wnoutrefresh(textWinHeader);
    wnoutrefresh(receivedWinHeader);
    wnoutrefresh(assocWin);
    wnoutrefresh(pathWin);
    wnoutrefresh(statusWin);
    wnoutrefresh(textWin);
    wnoutrefresh(receivedWin);

    keypad(textWin,TRUE);
    (void) idlok(assocWin,TRUE);
    (void) idlok(pathWin,TRUE);
    (void) idlok(textWin,TRUE);
    (void) scrollok(assocWin,TRUE);
    (void) scrollok(pathWin,TRUE);
    (void) scrollok(statusWin,TRUE);
    (void) scrollok(textWin,TRUE);
    (void) scrollok(receivedWin,TRUE);

    doupdate();
}


/* This function reads the input from the parameters of the SCTP_PathStatus structure
   and displays the data on a window of ncurses. */
void ncurses_display_AssocStatus(unsigned int assocID)

{
  SCTP_AssociationStatus assocStatus;
  int i;
  char tstr[200];

  wclear(assocWin);
  wrefresh(assocWin);

  sctp_getAssocStatus(assocID,&assocStatus);

  sprintf(assocInfo," Association ID : %d, Local port : %d, Remote port : %d\n",
      assocID,assocStatus.sourcePort,assocStatus.destPort);

  waddstr(assocWin,assocInfo);
  wrefresh(assocWin);

  sprintf(assocInfo," Local address(es) is(are) :");

  for (i=0; i <  noOfLocalAddresses; i++)
     {
       sprintf(tstr," %s,", localAddressList[i]);
       strcat(assocInfo,tstr);
     }
  waddstr(assocWin,assocInfo);
  wrefresh(assocWin);

  sprintf(assocInfo,"\n No. of Destination address : %d,\t\t Primary destination address : %s\n Number of incoming Streams : %d,\t\t Number of outgoing streams : %d\n Primary Address Index: %d,\t\t\t Current Receiver Window Size : %d\n Outstanding bytes : %-8d,\t\t\t No. of chunks in send queue : %d\n No. of chunks in retransmission queue : %d,\t No. of chunks in reception queue : %d\n Initial Round Trip Timeout : %d (msecs),\t Minimum Round Trip Timeout : %d (msecs)\n Maximum Round Trip Timeout : %d(msecs),\t Cookie Lifetime : %d (msecs)\n Max retransmission per association : %d,\t Max retransmission per path : %d\n Max Initial Retransmission : %d,\t\t Local Receiver Window : %d\n Delay for delay acknowledge : %d (msecs),\t IP Type Of Service : %x\n Current Incoming stream ID : %d,\t\t Current Outgoing stream ID : %d ",
      assocStatus.numberOfAddresses, assocStatus.primaryDestinationAddress,
      statusUpdate.noOfInStreams, statusUpdate.noOfOutStreams, assocStatus.primaryAddressIndex,
      assocStatus.currentReceiverWindowSize, assocStatus.outstandingBytes,
      assocStatus.noOfChunksInSendQueue, assocStatus.noOfChunksInRetransmissionQueue,
      assocStatus.noOfChunksInReceptionQueue, assocStatus.rtoInitial, assocStatus.rtoMin,
      assocStatus.rtoMax, assocStatus.validCookieLife, assocStatus.assocMaxRetransmits,
      assocStatus.pathMaxRetransmits, assocStatus.maxInitRetransmits, assocStatus.myRwnd,
      assocStatus.delay, assocStatus.ipTos,
      statusUpdate.InstreamIDList[currInstreamID],
      statusUpdate.OutstreamIDList[currOutstreamID] );

  waddstr(assocWin,assocInfo);
  wrefresh(assocWin);
  wrefresh(textWin);

}


/* This function reads the input from the parameters of the SCTP_PathStatus structure
   and displays the data on a window of ncurses. */
void ncurses_display_PathStatus(unsigned int assocID)

{
    SCTP_AssociationStatus assocStatus;
    SCTP_PathStatus pathStatus;
    unsigned short pathID;
    unsigned int Rto[SCTP_MAX_NUM_ADDRESSES], HB_Interval[SCTP_MAX_NUM_ADDRESSES];
    unsigned int SRTT[SCTP_MAX_NUM_ADDRESSES],RTTVar[SCTP_MAX_NUM_ADDRESSES];
    unsigned int SlowStThres[SCTP_MAX_NUM_ADDRESSES], PartBytesAck[SCTP_MAX_NUM_ADDRESSES];
    unsigned int CongestWin[SCTP_MAX_NUM_ADDRESSES],CongestWin2[SCTP_MAX_NUM_ADDRESSES];
    unsigned int MTU[SCTP_MAX_NUM_ADDRESSES], OutBytesPerAddr[SCTP_MAX_NUM_ADDRESSES];
    short State[SCTP_MAX_NUM_ADDRESSES];
    char destaddr[SCTP_MAX_NUM_ADDRESSES][SCTP_MAX_IP_LEN];
    unsigned char IPTos[SCTP_MAX_NUM_ADDRESSES];

    wclear(pathWin);
    wrefresh(pathWin);

    sctp_getAssocStatus(assocID, &assocStatus);
    for (pathID=0; pathID < assocStatus.numberOfAddresses; pathID++)
      {
    sctp_getPathStatus(assocID, pathID, &pathStatus);
    strcpy((char *)destaddr[pathID], (const char *)pathStatus.destinationAddress);
    State[pathID] = pathStatus.state;
    Rto[pathID] = pathStatus.rto;
    HB_Interval[pathID] = pathStatus.heartbeatIntervall;
    SRTT[pathID] = pathStatus.srtt;
    RTTVar[pathID] = pathStatus.rttvar;
    SlowStThres[pathID] = pathStatus.ssthresh;
    PartBytesAck[pathID] = pathStatus.partialBytesAcked;
    CongestWin[pathID] = pathStatus.cwnd;
    CongestWin2[pathID] = pathStatus.cwnd2;
    MTU[pathID] = pathStatus.mtu;
    OutBytesPerAddr[pathID] = pathStatus.outstandingBytesPerAddress;
    IPTos[pathID] = pathStatus.ipTos;

    if (displayPathDetails == 0)
      {
        /* Check if the current path is the primary path */
        if (pathID == sctp_getPrimary(assocID))
          {
        sprintf(pathInfo," Primary Path ID : %d, state of path : %s\n",
            pathID, pathStateName(State[pathID]));
        waddstr(pathWin,pathInfo);
        wrefresh(pathWin);
          }
        else
          {
        sprintf(pathInfo," Path ID : %d, state of path : %s\n",
            pathID, pathStateName(State[pathID]));
        waddstr(pathWin,pathInfo);
        wrefresh(pathWin);
          }
      }

    else if (displayPathDetails == 1)
      {
        mvwaddstr(pathWin,0,0,"[Hit Backspace to return to main menu]\n");
        wrefresh(pathWin);

        if (pathID == chosenPath)
          {
        sprintf(pathInfo,"\n Path ID : %d, State of path : %s\t\t Destination address : %s\n Heartbeat Interval : %-8u\t\t Retransmisson time(msecs) : %-8d\n Smooth Round Trip time(msecs) : %-8d\t Round Trip time Variations(msecs) : %-8d\n Slow start threshold : %-8d\t\t Congestion Window Size : %-8d\n Outstanding Bytes per Address : %-8d\t Congestion Window Size 2 : %-8d\n Partial bytes acknowledge : %-8d\t\t IP type of service : %x\n MTU : %d bytes\n\n",
            pathID, pathStateName(State[pathID]),
            destaddr[pathID],HB_Interval[pathID],Rto[pathID],
            SRTT[pathID],RTTVar[pathID],SlowStThres[pathID],CongestWin[pathID],
            OutBytesPerAddr[pathID], CongestWin2[pathID],PartBytesAck[pathID],
            IPTos[pathID],MTU[pathID]);

        waddstr(pathWin,pathInfo);
        wrefresh(pathWin);
          }
      }
      }
    wrefresh(textWin);
    displayPathDetails = 0;
}

void periodicRefreshFunction(unsigned int timerID, void *parameter1, void *parameter2)
{
    /* Display the primary path details by default when data arrive */
    displayPathDetails = 1;
    chosenPath = sctp_getPrimary(associationID);
    ncurses_display_PathStatus(associationID);

    sctp_startTimer(deltaT/1000, (deltaT%1000)*1000,  periodicRefreshFunction, NULL, NULL);
}


void* communicationUpNotif(unsigned int assocID, int status, unsigned int noOfDestinations,
                           unsigned short noOfInStreams, unsigned short noOfOutStreams,
                           int associationSupportsPRSCTP, void* dummy)
{
  /* SCTP_AssociationStatus assocStatus; */
  int TimerID;

  initializecurses();

  sprintf(statusInfo, " Association ID =%-8x: Communication up (%u paths)\n",
      assocID, noOfDestinations);
  waddstr(statusWin,statusInfo);
  wrefresh(statusWin);

  /* Set heartbeat
  sctp_getAssocStatus(assocID,&assocStatus);

  for (pathID=0; pathID < assocStatus.numberOfAddresses; pathID++){
    if (sctp_changeHeartBeat(assocID,pathID,SCTP_HEARTBEAT_ON,10000)==0)
      sprintf(statusInfo ,"Successful in changing the heartbeat for pathID = %d\n",pathID);

    else
      sprintf(statusInfo ,"Error in changing the heartbeat for pathID = %d\n",pathID);

    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);
    }*/

  /* Modify RTO Max to 10 secs so that network status change occurs faster
  sctp_getAssocStatus(assocID, &assocStatus);
  assocStatus.rtoMax = 10000;
  if (sctp_setAssocStatus(assocID, &assocStatus)==0)
    {
      sctp_getAssocStatus(assocID, &assocStatus);
      if (assocStatus.rtoMax == 10000)
    {
      sprintf(statusInfo," Maximum Round Trip Timeout modified to %d (msecs)\n",
          assocStatus.rtoMax);
      waddstr(statusWin,statusInfo);
      wrefresh(statusWin);
    }
    } */

  /* Start Timer */
  if (periodicRefresh)
    {
      TimerID = sctp_startTimer(deltaT/1000, (deltaT%1000)*1000, &periodicRefreshFunction, NULL, NULL);
      sprintf(statusInfo," TimerID is %d\n",TimerID);
      waddstr(statusWin,statusInfo);
      wrefresh(statusWin);
    }

  /* Update the Monitor tool data structures */
  UpdateMonitorToolStruct(noOfInStreams, noOfOutStreams);

  /* Display functions */
  ncurses_display_AssocStatus(assocID);
  ncurses_display_PathStatus(assocID);

  return NULL;
}

void dataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int len,
                     unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
    char chunk[SCTP_MAXIMUM_DATA_LENGTH + 1];
    unsigned int length;
    int i;
    unsigned int InstreamID_position = 0;
    unsigned int tsn;
    unsigned short ssn;

    sprintf(statusInfo, " Association ID =%-8x: Data arrived (%u bytes on stream %u, %s)\n",
        assocID, len, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);


    /* read it */
    length = SCTP_MAXIMUM_DATA_LENGTH;
    sctp_receive(assocID, streamID, (unsigned char *)chunk, &length, &ssn, &tsn, SCTP_MSG_DEFAULT);
    chunk[length]=0;

    /* and display it */
    sprintf(receivedInfo, " Data received : %s", chunk);
    waddstr(receivedWin,receivedInfo);
    wrefresh(receivedWin);

    /* Stores the stream Id into the structure statusUpdate each time a data arrives */
    for (i=0; i <statusUpdate.noOfInStreams; i++)
      {
    if (statusUpdate.InstreamIDList[i] == -1)
      {
        statusUpdate.InstreamIDList[i] = streamID;
        InstreamID_position = i;
      }
    else if (statusUpdate.InstreamIDList[i] != -1 &&
         statusUpdate.InstreamIDList[i] != streamID)
      {
        statusUpdate.InstreamIDList[i] = streamID;
        InstreamID_position = i;
      }
    else if (statusUpdate.InstreamIDList[i] == streamID)
      {
        InstreamID_position = i;
      }
      }

    /* Update the current position of the InstreamIDList array */
    currInstreamID = InstreamID_position;

    /* Display the Association details */
    ncurses_display_AssocStatus(assocID);

    if (!periodicRefresh)
      {
      /* Display the primary path details by default when data arrive */
    displayPathDetails = 1;
    chosenPath = sctp_getPrimary(assocID);
    ncurses_display_PathStatus(assocID);
      }
}


void networkStatusChangeNotif(unsigned int assocID, short destAddrIndex, unsigned short newState, void* ulpDataPtr)

{
    SCTP_AssociationStatus assocStatus;
    SCTP_PathStatus pathStatus;
    unsigned short pathID;

    sctp_getPathStatus(assocID, destAddrIndex , &pathStatus);
    sprintf(statusInfo, " Association ID =%-8x: Network status change: path %u (towards %s) is now %s\n",
        assocID, destAddrIndex, pathStatus.destinationAddress, pathStateName(newState));
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);

    /* if the primary path has become inactive */
    if ((newState == SCTP_PATH_UNREACHABLE) &&
        (destAddrIndex == sctp_getPrimary(assocID))) {

        sctp_getAssocStatus(assocID, &assocStatus);
        for (pathID=0; pathID < assocStatus.numberOfAddresses; pathID++)
      {
            sctp_getPathStatus(assocID, pathID, &pathStatus);
            if (pathStatus.state == SCTP_PATH_OK)
          {
        break;
          }
      }

        /* and use it */
        if (pathID < assocStatus.numberOfAddresses)
      {
        sctp_setPrimary(assocID, pathID);
      }
    }

    /* Display functions */
    ncurses_display_AssocStatus(assocID);
    displayPathDetails = 0;
    ncurses_display_PathStatus(assocID);
}

void communicationLostNotif(unsigned int assocID, unsigned short status, void* ulpDataPtr)
{
    unsigned char buffer[SCTP_MAXIMUM_DATA_LENGTH];
    unsigned int bufferLength;
    unsigned short streamID, streamSN;
    unsigned int protoID;
    unsigned int tsn;
    unsigned char flags;
    void* ctx;


    sprintf(statusInfo, " Association ID =%-8x: Communication lost (status %u)\n", assocID, status);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);

    return;

    /* retrieve data */
    bufferLength = sizeof(buffer);
    while (sctp_receiveUnsent(assocID, buffer, &bufferLength, &tsn,
                              &streamID, &streamSN, &protoID, &flags, &ctx) >= 0){
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }

    bufferLength = sizeof(buffer);
    while (sctp_receiveUnacked(assocID, buffer, &bufferLength, &tsn,
                               &streamID, &streamSN, &protoID, &flags, &ctx) >= 0){
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }

    /* delete the association, instace and terminate */
    sctp_deleteAssociation(assocID);
    sctp_unregisterInstance(sctpInstance);
    exit(0);
}

void communicationErrorNotif(unsigned int assocID, unsigned short status, void* dummy)
{
    sprintf(statusInfo, " Association ID =%-8x: Communication error (status %u)\n", assocID, status);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);

    /* Display function */
    ncurses_display_PathStatus(assocID);

}

void sendFailureNotif(unsigned int assocID,
                      unsigned char *unsent_data, unsigned int dataLength, unsigned int *context, void* dummy)
{
    sprintf(statusInfo, " Association ID =%-8x: Send failure\n", assocID);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);

    ncurses_display_PathStatus(assocID);
}

void restartNotif(unsigned int assocID, void* ulpDataPtr)
{
    sprintf(statusInfo, " Association ID =%-8x: Restart\n", assocID);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);

    /* Display functions */
    ncurses_display_AssocStatus(associationID);
    ncurses_display_PathStatus(assocID);
}

void shutdownCompleteNotif(unsigned int assocID, void* ulpDataPtr)
{
    sprintf(statusInfo, " Association ID =%-8x: Shutdown complete\n", assocID);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);

    endwin();
    exit(0);

    /* delete the association, instance and terminate */
    sctp_deleteAssociation(assocID);
    sctp_unregisterInstance(sctpInstance);
    exit(0);
}


void stdinCallback(int fd, short int revents, short int* gotEvents, void* dummy)
{
/*  This function gets triggered by the ncurses library upon *any* keystroke
    from user (for handling of Ctrl-C, see function finish()) */

    int key;
    static unsigned short outstreamID = 0;
    SCTP_AssociationStatus assocStatus;

    /* call ncurses function wgetch() to read in one user keystroke.
       Did not use the wgetstr() function because it blocks until the user#
       terminates with a end-of-line (return) key. This prevents the SCTP
       library from sending out heartbeats, as well as queuing other callbacks
       waiting for this potentially long function to terminate.
    */

    key = wgetch(textWin);

    switch (key)
      {
      case ERR:
    sctp_shutdown(associationID);
    endwin();
    break;

      /* ascii code for return key is 13 */
      case 13:
      case KEY_ENTER:
    buffer[bufCount++]='\n';
    buffer[bufCount++]=0;

    /* Increment the Stream ID by 1 everytime data is sent,
       if stream ID = largest stream ID assigned, reset stream ID to 0 */
    if (outstreamID == statusUpdate.noOfOutStreams)
      outstreamID = 0;

    sctp_send(associationID, outstreamID, (unsigned char *)buffer, strlen(buffer),
                  SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                  SCTP_USE_PRIMARY, SCTP_NO_CONTEXT,
                  SCTP_INFINITE_LIFETIME, SCTP_ORDERED_DELIVERY,
          SCTP_BUNDLING_DISABLED);

    /* Update the Outstream ID list in Monitor tool structure */
    if (statusUpdate.OutstreamIDList[outstreamID] == -1)
      statusUpdate.OutstreamIDList[outstreamID] = outstreamID;

    /* Update the current position of OutstreamIDList array  */
    currOutstreamID = outstreamID;

    /* update the display */
    ncurses_display_AssocStatus(associationID);

    outstreamID ++;

    waddch(textWin,'\n');
    wrefresh(textWin);

    bufCount=0;
    break;

      case KEY_BACKSPACE:
    displayPathDetails = 0;
    ncurses_display_PathStatus(associationID);
    break;

      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
    /* ascii code for key '0' is 48, key '1' is 49 and so fro.....
     therefore, key - 48 will return the value of the Path ID chosen */
    chosenPath = key - 48;
    displayPathDetails = 1;
    sctp_getAssocStatus(associationID,&assocStatus);
    if (chosenPath < assocStatus.numberOfAddresses)
      ncurses_display_PathStatus(associationID);
    break;

      case KEY_RESIZE:
    endwin();
    initializecurses();
    wrefresh(statusWin);
    /* Display Functions*/
    ncurses_display_AssocStatus(associationID);
    ncurses_display_PathStatus(associationID);
    break;

      default:
    if (bufCount<SCTP_MAXIMUM_DATA_LENGTH);{
      buffer[bufCount++]= key;
      waddch(textWin, key);
      wrefresh(textWin);
      }
      }
}


static void finish(int sig)
{

    waddstr(statusWin," Terminating Monitoring tool...");

    /* calls sctp_shutdown() to close the association.
       waits for the receipt of the shutdown notification before terminating the program */

    if (sctp_shutdown(associationID)==0)
      waddstr(statusWin,"successful\n");
    else{
      waddstr(statusWin,"failed\n");
      /* the program should exit here as the shutdownComplete notification will
         not be produced in this case */
      endwin();
      exit(0);
    }

    wrefresh(statusWin);
}


static void resize(int sig)
{
  endwin();

  initializecurses();

  wrefresh(statusWin);
  /* Display Function */
  ncurses_display_AssocStatus(associationID);
  ncurses_display_PathStatus(associationID);
}


int main(int argc, char **argv)
{
    SCTP_ulpCallbacks terminalUlp;
    SCTP_InstanceParameters instanceParameters;

    /* trapping Ctrl-C */
    signal(SIGINT, finish);

    /* trapping resize signal */
    signal(SIGWINCH, resize);

    /* initialize the terminal_ulp variable */
    terminalUlp.dataArriveNotif          = &dataArriveNotif;
    terminalUlp.sendFailureNotif         = &sendFailureNotif;
    terminalUlp.networkStatusChangeNotif = &networkStatusChangeNotif;
    terminalUlp.communicationUpNotif     = &communicationUpNotif;
    terminalUlp.communicationLostNotif   = &communicationLostNotif;
    terminalUlp.communicationErrorNotif  = &communicationErrorNotif;
    terminalUlp.restartNotif             = &restartNotif;
    terminalUlp.shutdownCompleteNotif    = &shutdownCompleteNotif;
    terminalUlp.peerShutdownReceivedNotif = NULL;

    getArgs(argc, argv);

    checkArgs();

    sctp_initLibrary();

    /* set up the "server" */
    sctpInstance = sctp_registerInstance(localPort,
                      MAXIMUM_NUMBER_OF_IN_STREAMS,
                      MAXIMUM_NUMBER_OF_OUT_STREAMS,
                      noOfLocalAddresses, localAddressList,
                      terminalUlp);

    /* set the TOS byte */
    sctp_getAssocDefaults(sctpInstance, &instanceParameters);
    instanceParameters.ipTos=tosByte;
    sctp_setAssocDefaults(sctpInstance, &instanceParameters);

    associationID = sctp_associate(sctpInstance, MAXIMUM_NUMBER_OF_OUT_STREAMS, destinationAddress,
                                   remotePort, NULL);

    sctp_registerUserCallback(fileno(stdin), &stdinCallback, NULL, POLLIN|POLLPRI);

    /* run the event handler forever */
    while (sctp_eventLoop() >= 0);

    /* this will never be reached */
    return 0;
}
