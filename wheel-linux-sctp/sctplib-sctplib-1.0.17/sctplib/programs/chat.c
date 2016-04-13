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
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>         /* for atoi() under Linux */
#include <curses.h>

#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008


#define CHAT_PORT                          2345
#define MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES    10
#define MAXIMUM_NUMBER_OF_IN_STREAMS         10
#define MAXIMUM_NUMBER_OF_OUT_STREAMS        10
#define SCTP_GENERIC_PAYLOAD_PROTOCOL_ID      0

#define MAX_BUFFER_LENGTH                   1400

#ifndef min
#define min(x,y)            (x)<(y)?(x):(y)
#endif

static unsigned char localAddressList[MAXIMUM_NUMBER_OF_LOCAL_ADDRESSES][SCTP_MAX_IP_LEN];
static unsigned char destinationAddress[SCTP_MAX_IP_LEN];

static unsigned short noOfLocalAddresses = 0;

static unsigned short remotePort = CHAT_PORT;
static unsigned short localPort  = 1000;
static unsigned char  tosByte    = 0x10;  /* IPTOS_LOWDELAY */
static unsigned int associationID;

static int verbose  = 0;
static int vverbose = 0;

static int client = 0;

static WINDOW *peerWin;
static WINDOW *selfWin;
static WINDOW *peerWinStatus;
static WINDOW *selfWinStatus;
static WINDOW *statusWin;

static int selfX1,selfY1,selfX2,selfY2;
static int peerX1,peerY1,peerX2,peerY2;

static char tstr[256];
static unsigned char buf[MAX_BUFFER_LENGTH-SCTP_MAX_IP_LEN];
static int bufCount,usrid_len = 0;
static char *usrid = '\0';
static unsigned char peeraddr[SCTP_MAX_IP_LEN];

void printUsage(void)
{
    printf("usage:   chat [options] -s source_addr_1 -d destination_addr ...\n");
    printf("options:\n");
    printf("-d destination_addr establish a association with the specified address\n");
    printf("-l local port       local port number\n");
    printf("-r remote port      remote port number\n");
    printf("-u user ID          specify your own user ID, otherwise login ID will be used\n");
    printf("-t byte             TOS byte used by all assiciations (default 0x10)\n");
    printf("-v                  verbose mode\n");
    printf("-V                  very verbose mode\n");
}

void getArgs(int argc, char **argv)
{
    int c;
    extern char *optarg;
    extern int optind;

    while ((c = getopt(argc, argv, "d:r:s:t:l:u:vV")) != -1)
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
        case 'u':
            usrid = optarg;
            usrid_len =  strlen(usrid);
            break;
        default:
            printUsage();
            exit(-1);
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
	printf("Error: Please specify a destination. This test program will not work as a server.\n");
        printUsage();
        exit(-1);
    }
    /*if user ID is not entered, get user ID from environment variable,"USER"*/
    else if (usrid_len == 0){
	  usrid = getenv("USER");
	  usrid_len = strlen(usrid);
    }

}


void getDestinationIPaddr(char paddr[SCTP_MAX_IP_LEN])

/*This routine copies the IP address of the primary path into an array paddr */

{
   SCTP_PathStatus pathStatus;
   int i, pathID;

   pathID = sctp_getPrimary(associationID);
   sctp_getPathStatus(associationID, pathID, &pathStatus);
   strcpy((char *)paddr, (const char *)pathStatus.destinationAddress);

   /* refreshes the ncurses window with the new IP address */
   mvwaddstr(peerWinStatus, 0, 0, paddr);
   for (i=strlen(paddr);i<COLS-3;i++)
      mvwaddch(peerWinStatus,0,i,'-');

   wrefresh(peerWinStatus);
   wrefresh(statusWin);
}


void initializecurses()
{

  /* Ncurses initialization: specify window size and positions.
     selfWin : top window
     peerWin : bottom window
     statusWin : display for SCTP information (bottom line(s))

  */

    int i;

    initscr();
    cbreak();
    noecho();
    nonl();

    selfX1 = 0;
    selfY1 = 1;
    selfX2 = COLS-1;
    selfY2 = (int)((LINES-3)/2)-1;

    peerX1 = 0;
    peerY1 = (int)((LINES-3)/2);
    peerX2 = COLS-1;
    peerY2 = LINES-5;

    selfWin = newwin((selfY2-selfY1),selfX2,1,0);
    peerWin = newwin((peerY2-peerY1),peerX2,peerY1,0);

    statusWin = newwin(2,peerX2,peerY2+1,0);

    selfWinStatus = newwin(1,selfX2,0,0);
    peerWinStatus = newwin(1,peerX2,peerY1-1,0);

    getDestinationIPaddr((char *)peeraddr);

    waddstr(selfWinStatus,usrid);

    for (i=usrid_len;i<COLS-3;i++)
      mvwaddch(selfWinStatus,0,i,'-');

    wrefresh(selfWinStatus);

    (void) idlok(selfWin,TRUE);
    (void) idlok(peerWin,TRUE);
    (void) scrollok(selfWin,TRUE);
    (void) scrollok(peerWin,TRUE);
    (void) scrollok(statusWin,TRUE);
    (void) idlok(statusWin,TRUE);

    doupdate();

}

void dataArriveNotif(unsigned int assocID, unsigned int streamID, unsigned int len,
                     unsigned short streamSN,unsigned int TSN, unsigned int protoID, unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[SCTP_MAXIMUM_DATA_LENGTH];
    unsigned int length;
    unsigned int tsn;
    unsigned short ssn;

    if (vverbose) {
      sprintf(tstr, "%-8x: Data arrived (%u bytes on stream %u, %s)\n",
                      assocID, len, streamID, (unordered==SCTP_ORDERED_DELIVERY)?"ordered":"unordered");
      waddstr(statusWin,tstr);
      wrefresh(statusWin);

    }
    /* read it */
    length = sizeof(chunk);
    sctp_receive(assocID, streamID, chunk, &length, &ssn, &tsn, SCTP_MSG_DEFAULT);
    if (!(len>length)) {
      chunk[len] = 0;
    }
    waddstr(peerWin, (char *)chunk);
    wrefresh(peerWin);

}

void sendFailureNotif(unsigned int assocID,
                      unsigned char *unsent_data, unsigned int dataLength, unsigned int *context, void* dummy)
{
  if (verbose) {
    sprintf(tstr, "%-8x: Send failure\n", assocID);
    waddstr(statusWin,tstr);
    wrefresh(statusWin);
  }
}

void networkStatusChangeNotif(unsigned int assocID, short destAddrIndex, unsigned short newState, void* ulpDataPtr)
{
    SCTP_AssociationStatus assocStatus;
    SCTP_PathStatus pathStatus;
    unsigned short pathID;

    if (verbose) {
        sprintf(tstr, "%-8x: Network status change: path %u is now %s\n",
        assocID, destAddrIndex, ((newState == SCTP_PATH_OK) ? "ACTIVE" : "INACTIVE"));
        waddstr(statusWin,tstr);
	wrefresh(statusWin);
    }

    /* if the primary path has become inactive */
    if ((newState == SCTP_PATH_UNREACHABLE) &&
        (destAddrIndex == sctp_getPrimary(assocID))) {

        /* select a new one */
        sctp_getAssocStatus(assocID, &assocStatus);
        for (pathID=0; pathID < assocStatus.numberOfAddresses; pathID++){
            sctp_getPathStatus(assocID, pathID, &pathStatus);
            if (pathStatus.state == SCTP_PATH_OK)
                break;
        }

        /* and use it */
        if (pathID < assocStatus.numberOfAddresses) {
            sctp_setPrimary(assocID, pathID);
	    getDestinationIPaddr((char *)peeraddr);

        }
    }
}

void* communicationUpNotif(unsigned int assocID, int status,
                           unsigned int noOfDestinations,
                           unsigned short noOfInStreams, unsigned short noOfOutStreams,
                           int associationSupportsPRSCTP,void* dummy)
{

    associationID=assocID;

    initializecurses();

    return NULL;
}

void communicationLostNotif(unsigned int assocID, unsigned short status, void* ulpDataPtr)
{
    unsigned char buffer[SCTP_MAXIMUM_DATA_LENGTH];
    unsigned int bufferLength;
    unsigned short streamID, streamSN;
    unsigned int protoID;
    unsigned int tsn;
    unsigned char flags;
    void * ctx;

    if (verbose) {
        sprintf(tstr, "%-8x: Communication lost (status %u)\n", assocID, status);
        waddstr(statusWin,tstr);
    }
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

    /* delete the association */
    sctp_deleteAssociation(assocID);
}

void communicationErrorNotif(unsigned int assocID, unsigned short status, void* dummy)
{
  if (verbose) {
    sprintf(tstr, "%-8x: Communication error (status %u)\n", assocID, status);
    waddstr(statusWin,tstr);
    wrefresh(statusWin);
  }
}

void restartNotif(unsigned int assocID, void* ulpDataPtr)
{
    SCTP_AssociationStatus assocStatus;

    if (verbose) {
        sprintf(tstr, "%-8x: Restart\n", assocID);
        waddstr(statusWin,tstr);
    }
    sctp_getAssocStatus(assocID, &assocStatus);
}

void shutdownCompleteNotif(unsigned int assocID, void* ulpDataPtr)
{
    if (verbose)
    {
      sprintf(tstr, "%-8x: Shutdown complete\n", assocID);
      waddstr(statusWin,tstr);
      wrefresh(statusWin);
    }

    /* delete the association */
    sctp_deleteAssociation(assocID);

    /* program terminates at this point upon the proper shutdown of the
       association. */
    endwin();
    exit(0);


}

void stdinCallback(int fd,short int revent, short int* gotEvents, void* dummy)
{
/*   this function gets triggered by the ncurses library upon *any* keystroke
     from user (for handling of Ctrl-C and Ctrl-\ see function finish()) */

    static int t;
    unsigned char c;
    char buffer[MAX_BUFFER_LENGTH];

    /* call ncurses function wgetch() to read in one user keystroke.
       Did not use the wgetstr() function because it blocks until the user#
       terminates with a end-of-line (return) key. This prevents the SCTP
       library from sending out heartbeats, as well as queuing other callbacks
       waiting for this potentially long function to terminate.
    */

    c=wgetch(selfWin);

    switch (c) {
      case ERR:
	sctp_shutdown(associationID);
	endwin();
	break;

      /* ascii code for return key is 13 */
      case 13:
	buf[bufCount++]='\n';
	buf[bufCount++]=0;
	strcpy(buffer,usrid);        /* adds the user ID into buffer */
	buffer[usrid_len] = '\0';
	strcat(buffer,"# ");
	strcat(buffer, (char *)buf);          /* adds the contents of buf into buffer */
	sctp_send(associationID,
                  0,
                  (unsigned char *)buffer, strlen(buffer),
                  SCTP_GENERIC_PAYLOAD_PROTOCOL_ID,
                  SCTP_USE_PRIMARY, SCTP_NO_CONTEXT,
                  SCTP_INFINITE_LIFETIME, SCTP_ORDERED_DELIVERY,
                  SCTP_BUNDLING_DISABLED);
	bufCount=0;
	waddch(selfWin,'\n');
	wrefresh(selfWin);
	t=0;
	break;

      default:

	if (bufCount<MAX_BUFFER_LENGTH);
	{
	  buf[bufCount++]=c;

	  waddch(selfWin,c);
	  wrefresh(selfWin);
	}
    }


}

static void finish(int sig)
{

    waddstr(statusWin,"Terminating chat session...");

    /* calls sctp_shutdown() to close the association.
       waits for the receipt of the shutdown notification before terminating
       the program */

    if (sctp_shutdown(associationID)==0)
      waddstr(statusWin,"successful\n");
    else
    {
      waddstr(statusWin,"failed\n");
      /* the program should exit here as the shutdownComplete contification will
	 not be produced in this case */
      endwin();
      exit(0);
    }

    wrefresh(statusWin);


}


int main(int argc, char **argv)
{
    int sctpInstance;
    SCTP_ulpCallbacks terminalUlp;
    SCTP_InstanceParameters instanceParameters;

    sctp_initLibrary();

    /* trapping Ctrl-C */
    signal(SIGINT, finish);

    /* trapping Ctrl-backslash */
    signal (SIGQUIT, finish);

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

    /* handle all command line options */
    getArgs(argc, argv);

    checkArgs();

    if (client) {
      sctpInstance = sctp_registerInstance(localPort,
					  MAXIMUM_NUMBER_OF_IN_STREAMS,
					  MAXIMUM_NUMBER_OF_OUT_STREAMS,
					  noOfLocalAddresses, localAddressList,
					  terminalUlp);

      /* set the TOS byte */
      sctp_getAssocDefaults(sctpInstance, &instanceParameters);
      instanceParameters.ipTos=tosByte;
      sctp_setAssocDefaults(sctpInstance, &instanceParameters);

      associationID = sctp_associate(sctpInstance, MAXIMUM_NUMBER_OF_OUT_STREAMS,
                                     destinationAddress, remotePort,  NULL);


    }

    sctp_registerUserCallback(fileno(stdin),&stdinCallback, NULL, POLLIN|POLLPRI);

    /* run the event handler forever */
    while (sctp_eventLoop() >= 0);

    /* this will never be reached */
    return 0;
}
