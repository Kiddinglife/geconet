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
#include <curses.h>         /* for Ncurses display */
#include <signal.h>

#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008

#define ECHO_PORT                             7
#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES    10
#define MAXIMUM_NUMBER_OF_ASSOCIATIONS        5
#define MAXIMUM_NUMBER_OF_IN_STREAMS         17
#define MAXIMUM_NUMBER_OF_OUT_STREAMS        17

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
static unsigned char localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned char destinationAddress[SCTP_MAX_IP_LEN];

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
static int sendToAll                          = 0;                 
static int startAssociation                   = 0;
static int sendUnordered                      = 0;

static unsigned int associationID;

/* Declaration for Ncurses display */
static char mainInfo[1024], pathInfo[1024], statusInfo[256];
static WINDOW *mainWin;
static WINDOW *statusWin, *statusWinHeader;
static WINDOW *pathWin, *pathWinHeader;
static int X1,X2,mainY1,mainY2,statusY1,statusY2,pathY1,pathY2;

/* Declaration for Display menu */  
static int new_option = 0; 
unsigned int pathID = 0;
static WINDOW *allWin;
static char allInfo[1024];
unsigned int positions[MAXIMUM_NUMBER_OF_ASSOCIATIONS];

/* Structure to store and retrieve each SCTP association */
struct SCTP_Monitor_AssocStatus
{ unsigned short state;
  unsigned short localPort;
  unsigned short numberOfAddresses;
  unsigned char localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
  unsigned char primaryDestinationAddress[SCTP_MAX_IP_LEN];
  unsigned short inStreams;
  unsigned short outStreams; 
  unsigned short inStreamID;
  unsigned short outStreamID;
  unsigned short primaryAddressIndex;
  unsigned int currentReceiverWindowSize;
  unsigned int outstandingBytes;
  unsigned int noOfChunksInSendQueue;
  unsigned int noOfChunksInRetransmissionQueue;
  unsigned int noOfChunksInReceptionQueue;
  unsigned int rtoInitial;
  unsigned int rtoMin;
  unsigned int rtoMax;
  unsigned int validCookieLife;
  unsigned int assocMaxRetransmits;
  unsigned int pathMaxRetransmits;
  unsigned int maxInitRetransmits;
  unsigned int myRwnd;
  unsigned int delay;
  unsigned char ipTos;
  unsigned int maxSendQueue;
  unsigned int maxRecvQueue; 
};
static struct SCTP_Monitor_AssocStatus MonitorAssocStatus[MAXIMUM_NUMBER_OF_ASSOCIATIONS];

/* Structure to store and retrieve path specific parameters */
struct SCTP_Monitor_PathStatus
{ unsigned char destinationAddress[SCTP_MAX_NUM_ADDRESSES][SCTP_MAX_IP_LEN];
  short state[SCTP_MAX_NUM_ADDRESSES];
  unsigned int srtt[SCTP_MAX_NUM_ADDRESSES];
  unsigned int rto[SCTP_MAX_NUM_ADDRESSES];
  unsigned int rttvar[SCTP_MAX_NUM_ADDRESSES];
  unsigned int heartbeatInterval[SCTP_MAX_NUM_ADDRESSES];
  unsigned int cwnd[SCTP_MAX_NUM_ADDRESSES];
  unsigned int cwnd2[SCTP_MAX_NUM_ADDRESSES];
  unsigned int partialBytesAcked[SCTP_MAX_NUM_ADDRESSES];
  unsigned int ssthresh[SCTP_MAX_NUM_ADDRESSES];
  unsigned int outstandingBytesPerAddress[SCTP_MAX_NUM_ADDRESSES];
  unsigned int mtu[SCTP_MAX_NUM_ADDRESSES];
  unsigned char ipTos[SCTP_MAX_NUM_ADDRESSES]; 
};
static struct SCTP_Monitor_PathStatus MonitorPathStatus[MAXIMUM_NUMBER_OF_ASSOCIATIONS];

/* Structure to store and retrieve association IDs */
struct Monitor_List
{ 
  int associationID;
};
static struct Monitor_List MonitorList[MAXIMUM_NUMBER_OF_ASSOCIATIONS];


void printUsage(void)
{
  printf("usage:   echo_monitor [options] -s source_addr_1 -s source_addr_2 ...\n");
  printf("options:\n");
  printf("-b                  send back incoming data on all existing associations\n");
  printf("-d destination_addr establish a association with the specified address\n");   
  printf("-l length           number of bytes of the payload when generating traffic (default 512)\n");   
  printf("-m                  print number of received bytes and chunks per period (see -p)\n");
  printf("-M      print number of received bytes, chunks per period (see -p) and flow control info\n");    
  printf("-n number           number of packets initially send out (default 0)\n");   
  printf("-p period           period for the measurements in milliseconds (default 1000)\n");   
  printf("-t byte             TOS byte used by all assiciations (default 0x10)\n");   
  printf("-u                  inject the initial packets unordered\n");
  printf("-v                  verbose mode\n");   
  printf("-V                  very verbose mode\n");   
}

void getArgs(int argc, char **argv)
{
  int c;
  extern char *optarg;
  extern int optind;
  
  while ((c = getopt(argc, argv, "bd:l:mMn:p:s:t:uvV")) != -1)
    {
      switch (c) {
      case 'b':
	sendToAll = 1;
	break;
      case 'd':
	if (strlen(optarg) < SCTP_MAX_IP_LEN) {
	  strcpy((char *)destinationAddress, optarg);
	  startAssociation = 1;
	}
	break;
      case 'l':
	chunkLength = min(atoi(optarg), SCTP_MAXIMUM_DATA_LENGTH);
	break;
      case 'm':
	doMeasurements = 1;
	break;
      case 'M':
	doMeasurements = 1;
	doAllMeasurements = 1;
	break;
      case 'n':
	numberOfInitialPackets = atoi(optarg);
	break;
      case 'p':
	deltaT = atoi(optarg);
	break;
      case 's':
	if ((noOfLocalAddresses < MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES) &&
	    (strlen(optarg) < SCTP_MAX_IP_LEN  )) {
	  strcpy((char *)localAddressList[noOfLocalAddresses], optarg);
	  noOfLocalAddresses++;
	}
	break;  
      case 't':
	tosByte = (unsigned char) atoi(optarg);
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
    }
}

void checkArgs(void)
{
  int abortProgram;
  int printUsageInfo;
  
  abortProgram = 0;
  printUsageInfo = 0;
  
  if (noOfLocalAddresses == 0) {
    printf("Error:   At least one sourceaddress must be specified.\n");
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

void display_menu(int new_option, int assocID)
{
  unsigned int i;
  
  wclear(mainWin);
  wrefresh(mainWin);
  
  wattrset(mainWin,A_NORMAL);
  mvwaddstr(mainWin,1,20,"Echo Tool Monitoring Program\n\n");
  
  /* display all associations */
  for (i=0;i<MAXIMUM_NUMBER_OF_ASSOCIATIONS;i++)
    { 
      if (MonitorList[i].associationID != -1)
	{
	  sprintf(mainInfo, "\t\t\t Association ID = %d\n", MonitorList[i].associationID);
	  waddstr(mainWin,mainInfo);
	  wrefresh(mainWin);
	}
    } 
  
  /* set video attributes to be highlighted */
  wattrset(mainWin,A_REVERSE);
  sprintf(mainInfo, "Association ID = %d", assocID); 
  if (assocID != -1)
    mvwaddstr(mainWin,3+new_option,25,mainInfo);
  wattrset(mainWin,A_NORMAL);
  mvwaddstr(mainWin,13,3,"Use UP and DOWN Arrows to select - Enter for Association Status - Q to quit");
  wrefresh(mainWin);
}

int
display_menu_position(unsigned int assocID)
{
  int index;
  
  /* returns its position for the associated association */  
  for (index=0;index<MAXIMUM_NUMBER_OF_ASSOCIATIONS;index++)
    { 
      if (positions[index] == assocID) return index;
    }
    /* not found */
    return -1;
} 

void store_menu()
{
  unsigned int i;
  unsigned int j = 0;

  /* initialize positions array */
  for (i=0; i < MAXIMUM_NUMBER_OF_ASSOCIATIONS; i++) 
    {
      positions[i] = -1;
    } 
  
  /* stores all associations in an array for the display menu */
  for (i=0;i<MAXIMUM_NUMBER_OF_ASSOCIATIONS;i++)
    { 
      if (MonitorList[i].associationID != -1)
	{
	  positions[j] = MonitorList[i].associationID;
	  j++;	  
	}
    } 
}

void store_AssocStatus (unsigned int assocID) 
{     
  /* This function stores the Association Status of an association 
     into the global structure MonitorAssocStatus */
  SCTP_AssociationStatus assocStatus;
  unsigned int LocalAddressID = 0;
  unsigned int i = 0;
  sctp_getAssocStatus(assocID, &assocStatus);
  
  for (i=0; i < MAXIMUM_NUMBER_OF_ASSOCIATIONS; i++)
    { 
      if (MonitorList[i].associationID == -1)	
	{
	  MonitorAssocStatus[i].state               = assocStatus.state;
	  MonitorList[i].associationID              = assocID;
	  MonitorAssocStatus[i].localPort           = ECHO_PORT;
	  MonitorAssocStatus[i].numberOfAddresses   = assocStatus.numberOfAddresses;
	  for (LocalAddressID=0; LocalAddressID < noOfLocalAddresses; LocalAddressID++)
	    {
	      strcpy((char *)MonitorAssocStatus[i].localAddressList[LocalAddressID], (const char *)localAddressList[LocalAddressID]);
	    }  
	  strcpy((char *)MonitorAssocStatus[i].primaryDestinationAddress, (const char *)assocStatus.primaryDestinationAddress);
	  MonitorAssocStatus[i].inStreams = assocStatus.inStreams;
	  MonitorAssocStatus[i].outStreams = assocStatus.outStreams;
	  MonitorAssocStatus[i].primaryAddressIndex = assocStatus.primaryAddressIndex;
	  MonitorAssocStatus[i].currentReceiverWindowSize = assocStatus.currentReceiverWindowSize;
	  MonitorAssocStatus[i].outstandingBytes = assocStatus.outstandingBytes;
	  MonitorAssocStatus[i].noOfChunksInSendQueue = assocStatus.noOfChunksInSendQueue;
	  MonitorAssocStatus[i].noOfChunksInRetransmissionQueue=assocStatus.noOfChunksInRetransmissionQueue;
	  MonitorAssocStatus[i].noOfChunksInReceptionQueue = assocStatus.noOfChunksInReceptionQueue;
	  MonitorAssocStatus[i].rtoInitial = assocStatus.rtoInitial;
	  MonitorAssocStatus[i].rtoMin = assocStatus.rtoMin;
	  MonitorAssocStatus[i].rtoMax = assocStatus.rtoMax;
	  MonitorAssocStatus[i].validCookieLife = assocStatus.validCookieLife;
	  MonitorAssocStatus[i].assocMaxRetransmits = assocStatus.assocMaxRetransmits;
	  MonitorAssocStatus[i].pathMaxRetransmits = assocStatus.pathMaxRetransmits;
	  MonitorAssocStatus[i].maxInitRetransmits = assocStatus.maxInitRetransmits;
	  MonitorAssocStatus[i].myRwnd = assocStatus.myRwnd;
	  MonitorAssocStatus[i].delay = assocStatus.delay;
	  MonitorAssocStatus[i].ipTos = assocStatus.ipTos;
	  MonitorAssocStatus[i].maxSendQueue = assocStatus.maxSendQueue;
	  MonitorAssocStatus[i].maxRecvQueue = assocStatus.maxRecvQueue;
	  break;
	}
    }
}

void store_PathStatus (unsigned int assocID)
{
  /* This function stores the Path Status of an association 
     into the global structure MonitorPathStatus */
  SCTP_AssociationStatus assocStatus;
  SCTP_PathStatus pathStatus;
  unsigned short path;
  unsigned int i;
  
  sctp_getAssocStatus(assocID, &assocStatus);
  
  for (i=0; i < MAXIMUM_NUMBER_OF_ASSOCIATIONS; i++)
    {
      if (MonitorList[i].associationID == -1 || MonitorList[i].associationID == assocID)
	{
	  for (path=0; path < assocStatus.numberOfAddresses; path++)
	    {
	      sctp_getPathStatus(assocID, path, &pathStatus);
	      strcpy((char *)MonitorPathStatus[i].destinationAddress[path], (const char *)pathStatus.destinationAddress);
	      MonitorPathStatus[i].state[path] = pathStatus.state;
	      MonitorPathStatus[i].srtt[path] = pathStatus.srtt;
	      MonitorPathStatus[i].rto[path] = pathStatus.rto;
	      MonitorPathStatus[i].rttvar[path] = pathStatus.rttvar;
	      MonitorPathStatus[i].heartbeatInterval[path] = pathStatus.heartbeatIntervall;
	      MonitorPathStatus[i].cwnd[path] = pathStatus.cwnd;
	      MonitorPathStatus[i].cwnd2[path] = pathStatus.cwnd2;
	      MonitorPathStatus[i].partialBytesAcked[path] = pathStatus.partialBytesAcked;
	      MonitorPathStatus[i].ssthresh[path] = pathStatus.ssthresh;
	      MonitorPathStatus[i].outstandingBytesPerAddress[path] = pathStatus.outstandingBytesPerAddress;
	      MonitorPathStatus[i].mtu[path] = pathStatus.mtu;
	      MonitorPathStatus[i].ipTos[path] = pathStatus.ipTos;
	    }break;
	}
      
    }  
}

void initializecurses()
     /* This function draws the windows of the monitoring tool using Ncurses */
{
  int i;
  
  initscr();            /* Initialize the curses library */
  cbreak();             /* Take input chars one at a time, no wait for \n */
  noecho();             /* Don't echo input */
  nonl();               /* Tell curses not to do NL->CR/NL on output */
  
  X1 = 0;
  X2 = COLS-1;
  
  mainY1 = 0;
  mainY2 = LINES-33;
  
  pathY1 = mainY2+1;
  pathY2 = pathY1+18;
  
  statusY1 = pathY2+1;
  statusY2 = statusY1+12;
  
  mainWin = newwin((mainY2-mainY1),X2,mainY1+1,0);
  pathWin = newwin(18,X2,pathY1+1,0);
  statusWin = newwin(12,X2,statusY1+1,0);
  
  pathWinHeader = newwin(1,X2,pathY1,0);
  waddstr(pathWinHeader,"Path Status");
  for (i=12; i<COLS-1;i++)
    mvwaddch(pathWinHeader,0,i,'*');
  
  statusWinHeader = newwin(1,X2,statusY1,0);
  waddstr(statusWinHeader,"SCTP Event Status");
  for (i=18; i<COLS-1;i++)
    mvwaddch(statusWinHeader,0,i,'*');
  
  wnoutrefresh(pathWinHeader);
  wnoutrefresh(statusWinHeader);
  wnoutrefresh(mainWin);
  wnoutrefresh(pathWin);
  wnoutrefresh(statusWin);
  
  keypad(mainWin,TRUE);          /* Enable keyboard mapping */
  (void) idlok(statusWin,TRUE);
  (void) scrollok(statusWin,TRUE);
  
  doupdate();
  
}

void ncurses_display_InstanceParameters (unsigned int assocID)
{
  unsigned int i = 0;
  
  mvwaddstr(allWin,1,0, "Instance Parameters\n\n");
  for (i=0; i < MAXIMUM_NUMBER_OF_ASSOCIATIONS; i++)
    {
      if (MonitorList[i].associationID == assocID)
	{	  
	  sprintf(allInfo, " The Initial Round Trip Timeout : %d\n The Minimum RTO Timeout : %d\n The Maximum RTO Timeout : %d\n The Lifetime of a Cookie : %d\n Maximum Retransmissions per association : %d\n Maximum Retransmissions per path : %d\n Maximum Initial Retransmissions : %d\n Local Receiver Window : %d\n Delay for delayed ACK in msecs : %d\n The IP Type of Service Field : %x\n Limit for the number of Chunks queued in the Send queue : %d\n Limit for the number of Chunks queued in the Receive queue : %d\n\n\n", MonitorAssocStatus[i].rtoInitial, MonitorAssocStatus[i].rtoMin, MonitorAssocStatus[i].rtoMax, MonitorAssocStatus[i].validCookieLife, MonitorAssocStatus[i].assocMaxRetransmits, MonitorAssocStatus[i].pathMaxRetransmits, MonitorAssocStatus[i].maxInitRetransmits, MonitorAssocStatus[i].myRwnd, MonitorAssocStatus[i].delay, MonitorAssocStatus[i].ipTos, MonitorAssocStatus[i].maxSendQueue, MonitorAssocStatus[i].maxRecvQueue);
	  waddstr(allWin, allInfo);
	  wrefresh(allWin);
	}
    }
}

void ncurses_display_AssocStatus (unsigned int assocID)
{
  unsigned int LocalAddressID = 0;
  unsigned int i = 0;
  
  waddstr(allWin, "Association Status\n\n");
  
  for (i=0; i < MAXIMUM_NUMBER_OF_ASSOCIATIONS; i++)
    {
      if (MonitorList[i].associationID == assocID)
	{
	  sprintf(allInfo, " Association ID : %d\n State : %d\n Local Port : %d\n Number of Local Addresses : %d\n", MonitorList[i].associationID, MonitorAssocStatus[i].state, MonitorAssocStatus[i].localPort, MonitorAssocStatus[i].numberOfAddresses);
	  waddstr(allWin, allInfo);
	  
	  for (LocalAddressID=0; LocalAddressID < MonitorAssocStatus[i].numberOfAddresses; LocalAddressID++)
	    {
	      sprintf(allInfo," Local Address : %s\n", MonitorAssocStatus[i].localAddressList[LocalAddressID]);
	      waddstr(allWin, allInfo);
	    }
	  sprintf(allInfo, " Destination Address : %s\n Maximum number of In Streams : %d\n Maximum number of Out Streams : %d\n Data arrived on Stream ID : %d\n Data Send on Stream ID : %d\n Primary Address Index : %d\n Current Receiver Window Size : %d\n Outstanding Bytes : %d\n Number of Chunks in Send Queue : %d\n Number of Chunks in Retransmission Queue : %d\n Number of Chunks in Reception Queue : %d\n\n",  MonitorAssocStatus[i].primaryDestinationAddress,  MonitorAssocStatus[i].inStreams, MonitorAssocStatus[i].outStreams, MonitorAssocStatus[i].inStreamID, MonitorAssocStatus[i].outStreamID, MonitorAssocStatus[i].primaryAddressIndex, MonitorAssocStatus[i].currentReceiverWindowSize, MonitorAssocStatus[i].outstandingBytes, MonitorAssocStatus[i].noOfChunksInSendQueue, MonitorAssocStatus[i].noOfChunksInRetransmissionQueue, MonitorAssocStatus[i].noOfChunksInReceptionQueue);
	  waddstr(allWin, allInfo);
	  wrefresh(allWin);
	}
    }
}

void ncurses_display_PathStatus (unsigned int assocID)
{
  unsigned int i, path;
  
  wclear(pathWin);
  wrefresh(pathWin);
  
  for (i=0; i < MAXIMUM_NUMBER_OF_ASSOCIATIONS; i++)
    {
      if (MonitorList[i].associationID == assocID)
	{
	  for (path=0; path < MonitorAssocStatus[i].numberOfAddresses; path++)
	    {
	      if (path == sctp_getPrimary(assocID))
		{
		  sprintf(pathInfo," Primary Path ID : %d\t Primary Destination address : %s\t State of path : %s\n", path, MonitorPathStatus[i].destinationAddress[path], (MonitorPathStatus[i].state[path]==SCTP_PATH_OK)?"ACTIVE":"INACTIVE");
		}
	      else {
		sprintf(pathInfo," Path ID : %d\t\t Destination address : %s\t\t State of path : %s\n", path, MonitorPathStatus[i].destinationAddress[path], (MonitorPathStatus[i].state[path]==SCTP_PATH_OK)?"ACTIVE":"INACTIVE");
	      }
	      waddstr(pathWin, pathInfo);
	      wrefresh(pathWin);
	    }
	}
    }
  waddstr(pathWin, "\n\n\n Select numbers 0-9 to display Path ID's Status");
  wrefresh(pathWin);
}

void ncurses_display_PathDetails (unsigned int assocID, unsigned int path)
{
  unsigned int i;
  
  wclear(pathWin);
  wrefresh(pathWin);
  
  for (i=0; i < MAXIMUM_NUMBER_OF_ASSOCIATIONS; i++)
    {
      if (MonitorList[i].associationID == assocID)
	{
	  if (path == sctp_getPrimary(assocID))
	    {
	      sprintf(pathInfo," Primary Path ID : %d\t\t\t\t\t\t Primary Destination address : %s\n State of path : %s\t\t\t\t\t\t Smoothed Round Trip Time in msecs : %d\n Current rto value in msec : %d\t\t\t\t Round Trip Time variation in msec : %d\n Defines the rate at which heartbeats are sent : %u\t Congestion Window Size : %d\n Congestion Window Size 2 : %d\t\t\t\t\t Partial Bytes Acked : %d\n Slow Start Threshold : %d\t\t\t\t\t Outstanding Bytes per Address : %d\n Current MTU (flowcontrol) : %d\t\t\t\t The IP type of Service Field : %x\n\n\n", path, MonitorPathStatus[i].destinationAddress[path], (MonitorPathStatus[i].state[path]==SCTP_PATH_OK)?"ACTIVE":"INACTIVE", MonitorPathStatus[i].srtt[path], MonitorPathStatus[i].rto[path], MonitorPathStatus[i].rttvar[path], MonitorPathStatus[i].heartbeatInterval[path], MonitorPathStatus[i].cwnd[path], MonitorPathStatus[i].cwnd2[path], MonitorPathStatus[i].partialBytesAcked[path], MonitorPathStatus[i].ssthresh[path], MonitorPathStatus[i].outstandingBytesPerAddress[path], MonitorPathStatus[i].mtu[path], MonitorPathStatus[i].ipTos[path]);
	      waddstr(pathWin, pathInfo);
	      wrefresh(pathWin);
	    }
	  else {
	    sprintf(pathInfo," Path ID : %d\t\t\t\t\t\t\t Destination address : %s\n State of path : %s\t\t\t\t\t\t Smoothed Round Trip Time in msecs : %d\n Current rto value in msec : %d\t\t\t\t Round Trip Time variation in msec : %d\n Defines the rate at which heartbeats are sent : %u\t Congestion Window Size : %d\n Congestion Window Size 2 : %d\t\t\t\t\t Partial Bytes Acked : %d\n Slow Start Threshold : %d\t\t\t\t\t Outstanding Bytes per Address : %d\n Current MTU (flowcontrol) : %d\t\t\t\t The IP type of Service Field : %x\n\n", path, MonitorPathStatus[i].destinationAddress[path], (MonitorPathStatus[i].state[path]==SCTP_PATH_OK)?"ACTIVE":"INACTIVE", MonitorPathStatus[i].srtt[path], MonitorPathStatus[i].rto[path], MonitorPathStatus[i].rttvar[path], MonitorPathStatus[i].heartbeatInterval[path], MonitorPathStatus[i].cwnd[path], MonitorPathStatus[i].cwnd2[path], MonitorPathStatus[i].partialBytesAcked[path], MonitorPathStatus[i].ssthresh[path], MonitorPathStatus[i].outstandingBytesPerAddress[path], MonitorPathStatus[i].mtu[path], MonitorPathStatus[i].ipTos[path]);
	    waddstr(pathWin, pathInfo);
	    wrefresh(pathWin);
	  }
	}
    }
  waddstr(pathWin, "\n\n\n Press BACKSPACE to go back");
  wrefresh(pathWin);
}

void ncurses_display_AllStatus (unsigned int assocID)
{
  allWin = newpad(50,150);
  
  ncurses_display_InstanceParameters(assocID);
  ncurses_display_AssocStatus(assocID);
  
  wmove(allWin,40,1);
  wclrtoeol(allWin);
  mvwaddstr(allWin,40,1,"Press any key to go back");
  
  prefresh(allWin,0,0,0,0,45,140);
  
  keypad(allWin,TRUE);
  raw();
  wgetch(allWin);
  delwin(allWin);
}

void dataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int len,
                     unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
  unsigned char chunk[SCTP_MAXIMUM_DATA_LENGTH];
  unsigned int length;
  int index=0, result;
  unsigned int tsn;
  unsigned short ssn;
  
  if (vverbose) {
    sprintf(statusInfo, "Association ID =%-8d: Data arrived (%u bytes on stream %u, %s)\n",
	    assocID, len, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
    waddstr(statusWin,statusInfo);

  }
  
  /* read it */
  length = sizeof(chunk);
  sctp_receive(assocID, streamID, chunk, &length, &ssn, &tsn, 0);
  
  /* update counter */
  ((struct ulp_data *) ulpDataPtr)->nrOfReceivedChunks += 1;
  ((struct ulp_data *) ulpDataPtr)->nrOfReceivedBytes  += length;
  
  /* and send it */
  if (sendToAll) {
    for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
      if (ulpData[index].maximumStreamID != -1) {
	result = sctp_send(ulpData[index].assocID,
			   min(streamID, ulpData[index].maximumStreamID),
			   chunk, length,
			   protoID,
			   SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, SCTP_INFINITE_LIFETIME, unordered,
                SCTP_BUNDLING_DISABLED);
	
	if (vverbose) {
	  sprintf(statusInfo, "Association ID =%-8d: Data sent (%u bytes on stream %u, %s) Result: %d\n",ulpData[index].assocID, len, min(streamID, ulpData[index].maximumStreamID), (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered", result);
	  waddstr(statusWin,statusInfo);
	  wrefresh(statusWin);
	}
	
	/*Store Stream ID for data send into structure SCTP_Monitor_AssocStatus*/
	MonitorAssocStatus[assocID].outStreamID = min(streamID, ulpData[index].maximumStreamID);
	
	store_PathStatus(assocID);
	new_option = display_menu_position(assocID);
	pathID = sctp_getPrimary(assocID);
	ncurses_display_PathDetails(assocID,pathID);
	store_menu();
	display_menu(new_option, assocID);
      }
    }
  } else {
    result = sctp_send(assocID,
		       min(streamID, ((struct ulp_data *) ulpDataPtr)->maximumStreamID),
		       chunk, length,
		       protoID,
		       SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, SCTP_INFINITE_LIFETIME,
                unordered, SCTP_BUNDLING_DISABLED);
    
    if (vverbose) {
      sprintf(statusInfo, "Association ID =%-8d: Data sent (%u bytes on stream %u, %s) Result: %d\n",
	      ulpData[index].assocID, len, min(streamID, ((struct ulp_data *) ulpDataPtr)->maximumStreamID),
	      (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered", result);
      waddstr(statusWin,statusInfo);
      wrefresh(statusWin);
    }
    
    /*Store Stream ID for data send into structure SCTP_Monitor_AssocStatus*/
    MonitorAssocStatus[assocID].outStreamID = min(streamID, ulpData[index].maximumStreamID);
    
    store_PathStatus(assocID);
    new_option = display_menu_position(assocID); 
    pathID = sctp_getPrimary(assocID);
    ncurses_display_PathDetails(assocID,pathID);
    store_menu();
    display_menu(new_option,assocID);
  }
  
  /*Store Stream ID for data arrive into structure SCTP_Monitor_AssocStatus*/
  MonitorAssocStatus[assocID].inStreamID = streamID;
  
}


void sendFailureNotif(unsigned int assocID,
                      unsigned char *unsent_data, unsigned int dataLength, unsigned int *context, void* dummy)
{
  if (verbose) {
    sprintf(statusInfo, "Association ID =%-8d: Send failure\n", assocID);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);
  }
  
  store_PathStatus(assocID);
  new_option = display_menu_position(assocID); 
  ncurses_display_PathStatus(assocID);
  store_menu();
  display_menu(new_option,assocID);
}

void networkStatusChangeNotif(unsigned int assocID, short affectedPathID, unsigned short newState, void* ulpDataPtr)
{
  SCTP_AssociationStatus assocStatus;
  SCTP_PathStatus pathStatus;
  unsigned short pathID;
  
  if (verbose) {
    sctp_getPathStatus(assocID, affectedPathID, &pathStatus);
    sprintf(statusInfo, "Association ID =%-8d: Network status change: path %u (towards %s) is now %s\n", 
	    assocID, affectedPathID,
	    pathStatus.destinationAddress,
	    ((newState == SCTP_PATH_OK) ? "ACTIVE" : "INACTIVE"));
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);
  }
  
  /* if the primary path has become inactive */
  if ((newState == SCTP_PATH_UNREACHABLE) &&
      (affectedPathID == sctp_getPrimary(assocID))) 
    {
      
      sctp_getAssocStatus(assocID, &assocStatus);
      for (pathID=0; pathID < assocStatus.numberOfAddresses; pathID++){
	sctp_getPathStatus(assocID, pathID, &pathStatus);
	if (pathStatus.state == SCTP_PATH_OK)
	  break;
      }
      
      /* and use it */
      if (pathID < assocStatus.numberOfAddresses) {
	sctp_setPrimary(assocID, pathID);
      }
    }
  
  store_PathStatus(assocID);
  new_option = display_menu_position(assocID); 
  ncurses_display_PathStatus(assocID);
  store_menu();
  display_menu(new_option,assocID);
}

void* communicationUpNotif(unsigned int assocID, int status,
                           unsigned int noOfPaths,
                           unsigned short noOfInStreams, unsigned short noOfOutStreams,
                           int associationSupportsPRSCTP,void* dummy)
{	
  unsigned int index, packetNumber;
  unsigned char chunk[SCTP_MAXIMUM_DATA_LENGTH];
  SCTP_PathStatus pathStatus;
  /* SCTP_AssociationStatus assocStatus; */
  unsigned short pathID;
  
  if (verbose) {
    sprintf(statusInfo, "Association ID =%-8d: Communication up (%u paths:", assocID, noOfPaths);
    waddstr(statusWin,statusInfo);
  
    for (pathID=0; pathID < noOfPaths; pathID++){
      sctp_getPathStatus(assocID, pathID, &pathStatus);
      sprintf(statusInfo, " %s ", pathStatus.destinationAddress);
      waddstr(statusWin,statusInfo);
      
    }
    sprintf(statusInfo, ")\n");
    waddstr(statusWin,statusInfo);
    sprintf(statusInfo,"Association ID =%-8d:                   %u incoming, %u outgoing streams.\n",
	    assocID, noOfInStreams, noOfOutStreams);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);
  }
  
  store_AssocStatus(assocID);
  store_PathStatus(assocID);
  /* look for association to determine its cursor location */
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++)
    {
      if (MonitorList[index].associationID == assocID)
	{
	  new_option = index;
	  break;
	}
    } 
  ncurses_display_PathStatus(assocID);
  store_menu();
  display_menu(new_option,assocID);
  
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
    
    /* send the initial packets */
    memset(chunk, 0, sizeof(chunk));
    for(packetNumber=1; packetNumber <= numberOfInitialPackets; packetNumber++) {
      sctp_send(assocID,
		0,
		chunk, chunkLength,
		SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
		SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, SCTP_INFINITE_LIFETIME,
		SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED);
    }
    return &ulpData[index];       
  } else {
    /* abort assoc due to lack of resources */
    sctp_abort(assocID);
    return NULL;
  }
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

    unsigned int index;
    unsigned int count = 0;
  
    if (verbose) {
        sprintf(statusInfo, "Association ID =%-8d: Communication lost (status %u)\n", assocID, status);
        waddstr(statusWin,statusInfo);
        wrefresh(statusWin);
    }
  
    /* retrieve data */
    bufferLength = sizeof(buffer);
    while (sctp_receiveUnsent(assocID, buffer, &bufferLength, &tsn,
                              &streamID, &streamSN, &protoID, &flags,&ctx) >= 0){
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }
  
    bufferLength = sizeof(buffer);
    while (sctp_receiveUnacked(assocID, buffer, &bufferLength, &tsn,
                                &streamID, &streamSN, &protoID,&flags,&ctx) >= 0){
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }
  
  /* free ULP data */
  ((struct ulp_data *) ulpDataPtr)->maximumStreamID = -1;
  
  /* delete the association */
  sctp_deleteAssociation(assocID);
  
  /* free Association and Path data */
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) 
    {
      if (MonitorList[index].associationID == assocID)
	MonitorList[index].associationID = -1;
    }
  /* free cursor position */
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) 
    {
      if (positions[index] == assocID)
	positions[index] = -1;    
    }
  
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++)
    {
      if (positions[index] != -1)
	{
	  new_option = 0;
	  associationID = positions[index];
	  ncurses_display_PathStatus(associationID);
	  store_menu();
	  display_menu(new_option,associationID);
	  break;
	}
    }
  
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) 
    {
      if (MonitorList[index].associationID != -1)
	{
	  count++;
	}
    }
  
  if (count == 0)
    {
      new_option = 0;
      wclear(mainWin);
      wrefresh(mainWin);
      wclear(pathWin);
      wrefresh(pathWin);
    }
}

void communicationErrorNotif(unsigned int assocID, unsigned short status, void* dummy)
{
  if (verbose) {
    sprintf(statusInfo, "Association ID =%-8d: Communication error (status %u)\n", assocID, status);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);
  }
  
  store_PathStatus(assocID);
  new_option = display_menu_position(assocID); 
  ncurses_display_PathStatus(assocID);
  store_menu();
  display_menu(new_option,assocID);
  
}

void restartNotif(unsigned int assocID, void* ulpDataPtr)
{
  SCTP_AssociationStatus assocStatus;
  
  if (verbose) {  
    sprintf(statusInfo, "Association ID =%-8d: Restart\n", assocID);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);
  }  
  
  sctp_getAssocStatus(assocID, &assocStatus);
    
  /* update ULP data */
  ((struct ulp_data *) ulpDataPtr)->maximumStreamID = assocStatus.outStreams - 1;
  ((struct ulp_data *) ulpDataPtr)->assocID = assocID;
  
  store_AssocStatus(assocID);
  store_PathStatus(assocID);
  new_option = display_menu_position(assocID); 
  ncurses_display_PathStatus(assocID);
  store_menu();
  display_menu(new_option,assocID);
}

void shutdownCompleteNotif(unsigned int assocID, void* ulpDataPtr)
{
  unsigned int index;
  /* unsigned int LocalAddressID; */
  unsigned int associationID = 0;
  unsigned int count = 0;

  if (verbose) {  
    sprintf(statusInfo, "Association ID =%-8d: Shutdown complete\n", assocID);
    waddstr(statusWin,statusInfo);
    wrefresh(statusWin);
  }  
  
  /* free ULP data */
  ((struct ulp_data *) ulpDataPtr)->maximumStreamID = -1;
  sctp_deleteAssociation(assocID);
  
  /* free Association and Path data */
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) 
    {
      if (MonitorList[index].associationID == assocID)
	MonitorList[index].associationID = -1;
    }
  /* free cursor position */
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) 
    {
      if (positions[index] == assocID)
	positions[index] = -1;    
    }
  
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++)
    {
      if (positions[index] != -1)
	{
	  new_option = 0;
	  associationID = positions[index];
	  ncurses_display_PathStatus(associationID);
	  store_menu();
	  display_menu(new_option,associationID);
	  break;
	}
    }
  
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) 
    {
      if (MonitorList[index].associationID != -1)
	{
	  count++;
	}
    }
  
  if (count == 0)
    {
      new_option = 0;
      wclear(mainWin);
      wrefresh(mainWin);
      wclear(pathWin);
      wrefresh(pathWin);
    }
}

void measurementTimerRunOffFunction(unsigned int timerID, void *parameter1, void *parameter2)
{
  int index;
  SCTP_AssociationStatus assocStatus;
  
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
    if (ulpData[index].maximumStreamID >= 0){
      sprintf(statusInfo, "Association ID =%-8d: %-6lu Chunks, %-8lu Bytes received\n",
	      ulpData[index].assocID, ulpData[index].nrOfReceivedChunks, ulpData[index].nrOfReceivedBytes);
      waddstr(statusWin,statusInfo);
      wrefresh(statusWin);
      ulpData[index].nrOfReceivedChunks = 0;
      ulpData[index].nrOfReceivedBytes  = 0;
      if (doAllMeasurements) {
	sctp_getAssocStatus(ulpData[index].assocID, &assocStatus);
	sprintf(statusInfo, "Association ID =%-8d: Peers receiver window size: %-8u, my receiver window size: %-8u \n",
		ulpData[index].assocID,
		assocStatus.currentReceiverWindowSize,
		assocStatus.myRwnd);
	waddstr(statusWin,statusInfo);
	wrefresh(statusWin);
	sprintf(statusInfo, "Association ID =%-8d: Chunks in send queue: %-8u, outstanding bytes: %-8u \n",
		ulpData[index].assocID,
		assocStatus.noOfChunksInSendQueue,
		assocStatus.outstandingBytes);
	waddstr(statusWin,statusInfo);
	wrefresh(statusWin);
      }
    }
  }
  sctp_startTimer(deltaT/1000, (deltaT%1000)*1000, measurementTimerRunOffFunction, NULL, NULL);
} 

void stdinCallback (int fd, short int revents, short int* gotEvents, void* dummy)
{
  /* This function gets triggered by the ncurses library upon any keystroke from user */
  int key;
  unsigned int assocID = 0;
  unsigned int index;
  unsigned int count = 0;  
  unsigned int numOfAddr = 0;
  
  key=wgetch(mainWin);
  
  switch(key)
    {
    case 13:
    case KEY_ENTER:
      assocID = positions[new_option];
      ncurses_display_AllStatus(assocID);
      initializecurses();
      ncurses_display_PathStatus(assocID);
      display_menu(new_option,assocID);
      break;
      
    case KEY_UP:
      new_option = (new_option == 0) ? new_option : new_option-1;
      assocID = positions[new_option];
      ncurses_display_PathStatus(assocID);
      display_menu(new_option,assocID);
      break;
      
    case KEY_DOWN:
      for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) 
	{
	  if (MonitorList[index].associationID != -1)
	    {
	      count++;
	    }
	}
      new_option = (new_option == count-1) ? new_option : new_option+1;
      assocID = positions[new_option];
      ncurses_display_PathStatus(assocID);
      display_menu(new_option,assocID);
      break;
      
    case KEY_RESIZE:
      endwin();
      initializecurses();
      display_menu(new_option,assocID);
      wrefresh(mainWin);
      wrefresh(pathWin);
      wrefresh(statusWin);
      break; 
      
    case 'Q':
    case 'q':
      endwin();
      exit(0);
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
      /* ascii code for key '0' is 48, key '1' is 49 and so fro....
	 therefore, key - 48 will return the value of the PathID chosen */
      assocID = positions[new_option];
      pathID = key - 48;

      for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++)
	{
	  if (MonitorList[index].associationID == assocID)
	    numOfAddr = MonitorAssocStatus[index].numberOfAddresses;
	}
      
      if (pathID < numOfAddr)
	{
	  ncurses_display_PathDetails(assocID,pathID);
	} 
      display_menu(new_option,assocID);
      break;
      
    case KEY_BACKSPACE:
      assocID = positions[new_option];
      ncurses_display_PathStatus(assocID);
      display_menu(new_option,assocID);
      break;
      
    default:
      break;
    }
}

static void resize(int sig)
{
  endwin();
  initializecurses();
  display_menu(new_option,0);
  wrefresh(mainWin);
  wrefresh(pathWin);
  wrefresh(statusWin);
}

int main(int argc, char **argv)
{
  int sctpInstance;
  SCTP_ulpCallbacks echoUlp;
  SCTP_InstanceParameters instanceParameters;
  unsigned int index;
  
  /* Trapping Resize Signal */
  signal(SIGWINCH, resize);
    
  
  /* initialize ULP data */
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
    ulpData[index].maximumStreamID    = -1;
    ulpData[index].nrOfReceivedChunks = 0;
    ulpData[index].nrOfReceivedBytes  = 0;        
  }
  
  /* initialize Association and Path data */
  for (index=0; index < MAXIMUM_NUMBER_OF_ASSOCIATIONS; index++) {
    MonitorList[index].associationID    = -1;        
  }
  
  
    /* initialize the echo_ulp variable */
  echoUlp.dataArriveNotif          = &dataArriveNotif;
  echoUlp.sendFailureNotif         = &sendFailureNotif;
  echoUlp.networkStatusChangeNotif = &networkStatusChangeNotif;
  echoUlp.communicationUpNotif     = &communicationUpNotif;
  echoUlp.communicationLostNotif   = &communicationLostNotif;
  echoUlp.communicationErrorNotif  = &communicationErrorNotif;
  echoUlp.restartNotif             = &restartNotif;
  echoUlp.shutdownCompleteNotif    = &shutdownCompleteNotif;
  echoUlp.peerShutdownReceivedNotif = NULL;
  getArgs(argc, argv);

  checkArgs();
  
  initializecurses();
  
  sctp_initLibrary();
  
  sctpInstance = sctp_registerInstance(ECHO_PORT,
				       MAXIMUM_NUMBER_OF_IN_STREAMS,
				       MAXIMUM_NUMBER_OF_OUT_STREAMS,
                       noOfLocalAddresses, localAddressList,
				       echoUlp);
  
  /* set the TOS field */                  
  sctp_getAssocDefaults(sctpInstance, &instanceParameters);
  instanceParameters.ipTos=tosByte;
  sctp_setAssocDefaults(sctpInstance, &instanceParameters);
  
  if (startAssociation) {
    associationID = sctp_associate(sctpInstance, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                                    destinationAddress, ECHO_PORT, &ulpData[0]);
    store_AssocStatus(associationID);
  }
  
  if (doMeasurements) {
    sctp_startTimer(deltaT/1000, (deltaT%1000)*1000, &measurementTimerRunOffFunction, NULL, NULL);
    }
  
  sctp_registerUserCallback(fileno(stdin), &stdinCallback, NULL, POLLIN|POLLPRI);
  /* run the event handler forever */
  while (sctp_eventLoop() >= 0) {
  }
  
  /* this will never be reached */
  return 0;
}

/* Local Variables: *** */
/* compile-command: "gcc -o echo_monitor echo_monitor.c -I/usr/local/include -L/usr/local/lib -lglib12 -lsctp -lncurses" *** */
/* End: *** */










