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
 * Copyright (C) 2001 by Andreas Lang
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
 * Contact: anla@gmx.net
 */

/* payload lengths */
#define MIN_PAYLOAD_LENGTH   20
#define MAX_PAYLOAD_LENGTH  494
#define HEADER_LENGTH  6

/* constants used by processScriptCommand() */
#define CHECK_SCRIPT  0
#define RUN_SCRIPT    1

/* receive mode constants */
#define RECEIVE_DISCARD  0
#define RECEIVE_MIRROR   1

/* constants used by getIntParam() and getStrParam() */
#define OPTIONAL   1
#define MANDATORY  0
#define DECIMAL      10
#define HEXADECIMAL  16

/* results returned by getScriptCommand() */
#define PARSE_OK           0
#define END_OF_FILE        1
#define PARSE_ERROR       -1

/* constants for sctptest_scriptCommand */
#define MAX_NUM_OF_PARAMS   10
#define MAX_WORD_LENGTH   1000      /* (this includes the terminating '\0' character) */



/**
 * This structure is used to hold the data that is extracted from a script command by the parser.
 * The variables in this structure are set by the function getScriptCommand()
 */
struct sctptest_scriptCommand
{
    /* the number of parameters that are passed along with this command */
    unsigned int numOfParams;

    /* the command string */
    char command[MAX_WORD_LENGTH];

    /* an array of structs containing the parameters; */
    /* each parameter consists of a key and a value */
    struct {
        char key[MAX_WORD_LENGTH];
        char value[MAX_WORD_LENGTH];
    } param[MAX_NUM_OF_PARAMS];
};



/* FUNCTION DECLARATIONS */

int sctptest_start(char *, int);

int getScriptCommand(FILE *, struct sctptest_scriptCommand *, unsigned int *, unsigned int *, int mode);

/* only for testing... */
void printCommand(struct sctptest_scriptCommand *, unsigned int);

int processScriptCommand(struct sctptest_scriptCommand *, unsigned int, int);

char *getStrParam(struct sctptest_scriptCommand *, const char *, unsigned int *, int, unsigned int);

unsigned long getIntParam(struct sctptest_scriptCommand *, const char *, unsigned long,
                          unsigned long, int, unsigned int *, int, unsigned int);

void doReceive(unsigned int);

char *getTimeString();



/* ULP CALLBACK FUNCTIONS */

void timerCallback(unsigned int, void *, void *);

void dataArriveNotif(unsigned int assocID, unsigned short streamID, unsigned int length,
                     unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void *ulpData);

void sendFailureNotif(unsigned int assocID, unsigned char *unsentData, unsigned int dataLength,
                         unsigned int *context, void *ulpData);

void networkStatusChangeNotif(unsigned int assocID, short destinAddr,
                                   unsigned short newState, void *ulpData);

void* communicationUpNotif(unsigned int assocID, int status, unsigned int noOfDestinAddrs,
                           unsigned short instreams, unsigned short outstreams,
                           int associationSupportsPRSCTP, void *ulpData);

void communicationLostNotif(unsigned int assocID, unsigned short status, void *ulpData);

void communicationErrorNotif(unsigned int assocID, unsigned short status, void *ulpData);

void restartNotif(unsigned int assocID, void *ulpData);

void shutdownCompleteNotif(unsigned int assocID, void *ulpData);

