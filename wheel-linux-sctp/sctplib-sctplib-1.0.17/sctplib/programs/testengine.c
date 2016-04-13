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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sctp.h"
#include "sctptest.h"



/* payload: header (6 bytes) and body (initially 26 bytes) */
char payloadContents[MAX_PAYLOAD_LENGTH] = "\0\0\0\0\0\0ABCDEFGHIJKLMNOPQRSTUVWXYZ";
unsigned int payloadLength = HEADER_LENGTH + 26;

/* receiver state */
int receiveEnabled = 1;
int receiveMode = RECEIVE_DISCARD;
unsigned int unreceivedChunks = 0;

/* instance and association IDs (0 indicates that no instance is registered / no association is established) */
short instanceID = 0;
unsigned int assocID = 0;

/* association parameters */
unsigned short noOfInStreams;
unsigned short noOfOutStreams;
char localIP[SCTP_MAX_IP_LEN];   /* this is only used in event log messages */

/* Timer ID (0 indicates that the timer isn't running) */
unsigned int pauseTimerID = 0;



/**
 * Execute the script.
 * @param filename
 *          The name of the script file.
 * @param mode
 *          For this parameter, use constants CHECK_SCRIPT and RUN_SCRIPT (defined in sctptest.h)
 *          If mode is CHECK_SCRIPT, the script is only checked for errors, but commands are not executed.
 *          This is very useful, because in RUN_SCIPT mode, an error is not detected before the incorrect
 *          command is reached in the script file.
 *
 * @return  The number of errors that were detected in the script file.
 */
int sctptest_start(char *filename, int mode)
{
    FILE *scriptFile;
    unsigned int lineNum = 0, colNum = 0, loopIndex = 0, err = 0;
    int parseResult, stopParsing = 0, initialized = 0;
    struct sctptest_scriptCommand scriptCommand;
    struct loopData {
        unsigned int currentExec;
        unsigned int totalExecs;
        long filePos;
        unsigned int lineNum;
    } loop[100];


    /* open script file */
    if ((scriptFile = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "File not found: %s\n", filename);
        exit(1);
    }


    while (!stopParsing)
    {
        parseResult = getScriptCommand(scriptFile, &scriptCommand, &lineNum, &colNum, mode);

        switch (parseResult)
        {
            case PARSE_ERROR:
                 fprintf(stderr, "Line %u, column %u: Parse error\n", lineNum, colNum);
                 err++;
                 stopParsing = 1;
                 break;

            case END_OF_FILE:
                 stopParsing = 1;
                 break;

            case PARSE_OK:
                 /* check if INITIALIZE is the first command */
                 if (initialized == 0) {
                     if (strcmp(scriptCommand.command, "INITIALIZE") != 0) {
                         fprintf(stderr, "Line %u: INITIALIZE expected at beginning of script file.\n", lineNum);
                         err++;
                     }
                     initialized = 1;
                 }

                 /* handle loops */
                 if (strcmp(scriptCommand.command, "LOOP") == 0)
                 {
                     if (loopIndex > 99) {
                         fprintf(stderr, "Line %u: Loop stack overflow.\n", lineNum);
                         err++;
                         break;
                     }

                     loop[loopIndex].totalExecs = getIntParam(&scriptCommand, "TIMES", 1, 0, DECIMAL,
                                                              &err, MANDATORY, lineNum);
                     loop[loopIndex].currentExec = 1;
                     loop[loopIndex].filePos = ftell(scriptFile);
                     loop[loopIndex].lineNum = lineNum;
                     loopIndex++;
                 }

                 else if (strcmp(scriptCommand.command, "ENDLOOP") == 0)
                 {
                     if (loopIndex == 0) {
                         fprintf(stderr, "Line %u: ENDLOOP without LOOP\n", lineNum);
                         err++;
                         break;
                     }

                     if ((loop[loopIndex-1].currentExec >= loop[loopIndex-1].totalExecs) || (mode != RUN_SCRIPT)) {
                         loopIndex--;
                         break;
                     } else {
                         loop[loopIndex-1].currentExec++;
                         fseek(scriptFile, loop[loopIndex-1].filePos, SEEK_SET);
                         lineNum = loop[loopIndex-1].lineNum;
                         break;
                     }
                 }

                 /* process script command */
                 else {
                     err += processScriptCommand(&scriptCommand, lineNum, mode);
                     break;
                 }
        }
    }

    fclose(scriptFile);
    return err;
}


/**
 * Process a script command.
 * @param sc
 *          pointer to the sctptest_scriptCommand structure
 * @param lineNum
 *          the line number that is to be printed in error and event messages
 * @param mode
 *          see the description at sctptest_start()
 *
 * @return  the number of script errors that were detected by this function (0 if successful)
 */
int processScriptCommand(struct sctptest_scriptCommand *sc, unsigned int lineNum, int mode)
{
    unsigned int errors = 0;

    /* nur zum Testen... */
    /* printCommand(sc, lineNum); */

    /* Of course, a hashtable would be much more elegant... ;-) */

    /* INITIALIZE */
    if (strcmp(sc->command, "INITIALIZE") == 0)
    {
        unsigned char ip[1][SCTP_MAX_IP_LEN], *ipStr;
        unsigned short port, instreams, outstreams;

        ipStr = (unsigned char *)getStrParam(sc, "IP", &errors, MANDATORY, lineNum);
        if (strlen((char *)ipStr) > SCTP_MAX_IP_LEN - 1) {
            fprintf(stderr, "Line %u: Invalid IP-Address\n", lineNum);
            errors++;
        }

        port = (unsigned short) getIntParam(sc, "PORT", 1, 0xFFFF, DECIMAL, &errors, MANDATORY, lineNum);
        instreams = (unsigned short) getIntParam(sc, "INSTREAMS", 1, 0, DECIMAL, &errors, MANDATORY, lineNum);
        outstreams = (unsigned short) getIntParam(sc, "OUTSTREAMS", 1, 0, DECIMAL, &errors, MANDATORY, lineNum);

        if (errors == 0 && mode == RUN_SCRIPT) {
            SCTP_ulpCallbacks ulpCallbacks;

            printf("\n%s ---> INITIALIZE in line %u\n", getTimeString(), lineNum);

            if (instanceID != 0) {
                printf("Exception in line %u: INITIALIZE: SCTP instance already initialized\n", lineNum);
                return 0;
            }

            strcpy((char *)ip[0], (const char *)ipStr);

            ulpCallbacks.dataArriveNotif          = &dataArriveNotif;
            ulpCallbacks.sendFailureNotif         = &sendFailureNotif;
            ulpCallbacks.networkStatusChangeNotif = &networkStatusChangeNotif;
            ulpCallbacks.communicationUpNotif     = &communicationUpNotif;
            ulpCallbacks.communicationLostNotif   = &communicationLostNotif;
            ulpCallbacks.communicationErrorNotif  = &communicationErrorNotif;
            ulpCallbacks.restartNotif             = &restartNotif;
            ulpCallbacks.shutdownCompleteNotif    = &shutdownCompleteNotif;
            ulpCallbacks.peerShutdownReceivedNotif = NULL;

            instanceID = sctp_registerInstance(port, instreams, outstreams, 1, ip, ulpCallbacks);

            if (instanceID > 0) {
                printf("SCTP instance successfully initialized\n");
                strcpy((char *)localIP, (const char *)ipStr);
            } else {
                fprintf(stderr, "Initialize FAILED. Please check your parameters!\n");
                exit(1);
            }
        }
    }


    /* WAIT_FOR_ASSOC */
    else if (strcmp(sc->command, "WAIT_FOR_ASSOC") == 0)
    {
        if (mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> WAIT_FOR_ASSOC in line %u\n", getTimeString(), localIP, lineNum);

            if (assocID != 0) {
                printf("Exception in line %u: WAIT_FOR_ASSOC: Association already exists\n", lineNum);
                return 0;
            }

            while (assocID == 0)
                sctp_eventLoop();
        }
    }


    /* SHUTDOWN */
    else if (strcmp(sc->command, "SHUTDOWN") == 0)
    {
        if (mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> SHUTDOWN in line %u\n", getTimeString(), localIP, lineNum);

            if (assocID == 0) {
                printf("Exception in line %u: SHUTDOWN: Association does not exist!\n",
                        lineNum);
                return 0;
            }
            sctp_shutdown(assocID);
        }
    }


    /* ABORT */
    else if (strcmp(sc->command, "ABORT") == 0)
    {
        if (mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> ABORT in line %u\n", getTimeString(), localIP, lineNum);

            if (assocID == 0) {
                printf("Exception in line %u: ABORT: Association does not exist!\n",
                        lineNum);
                return 0;
            }
            sctp_abort(assocID);
        }
    }


    /* SET_PAYLOAD_HEADER */
    else if (strcmp(sc->command, "SET_PAYLOAD_HEADER") == 0)
    {
        unsigned short type;
        unsigned char mbu, mch, jc1, jc2;

        type = (unsigned short) getIntParam(sc, "TYPE", 0, 0xFFFF, HEXADECIMAL, &errors, MANDATORY, lineNum);
        mbu = (unsigned char) getIntParam(sc, "MBU", 0, 0xFF, HEXADECIMAL, &errors, MANDATORY, lineNum);
        mch = (unsigned char) getIntParam(sc, "MCH", 0, 0xFF, HEXADECIMAL, &errors, MANDATORY, lineNum);
        jc1 = (unsigned char) getIntParam(sc, "JC1", 0, 0xFF, HEXADECIMAL, &errors, MANDATORY, lineNum);
        jc2 = (unsigned char) getIntParam(sc, "JC2", 0, 0xFF, HEXADECIMAL, &errors, MANDATORY, lineNum);

        if (errors == 0 && mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> SET_PAYLOAD_HEADER in line %u\n", getTimeString(), localIP, lineNum);

            payloadContents[0] = (type & 0xFF00) >> 8;
            payloadContents[1] = (type & 0x00FF);
            payloadContents[2] = mbu;
            payloadContents[3] = mch;
            payloadContents[4] = jc1;
            payloadContents[5] = jc2;

            printf("Payload header changed: TYPE=%04X, MBU=%02X, MCH=%02X, JC1=%02X, JC2=%02X\n",
                    type, mbu, mch, jc1, jc2);
        }
    }


    /* SET_PAYLOAD_BODY */
    else if (strcmp(sc->command, "SET_PAYLOAD_BODY") == 0)
    {
        char *contentsStr, contentsBuf[MAX_WORD_LENGTH];
        unsigned int length, i, j, contentsStrLen;
        unsigned char asciichar, asciival[3];
        char *endp;

        contentsStr = getStrParam(sc, "CONTENTS", &errors, MANDATORY, lineNum);
        length = (unsigned int) getIntParam(sc, "LENGTH", MIN_PAYLOAD_LENGTH - HEADER_LENGTH,
                                     MAX_PAYLOAD_LENGTH - HEADER_LENGTH, DECIMAL, &errors, MANDATORY, lineNum);

        contentsStrLen = strlen(contentsStr);
        for (i = j = 0; i < contentsStrLen; i++) {
            if (contentsStr[i] == '\\') {
                asciival[0] = contentsStr[++i];
                asciival[1] = contentsStr[++i];
                asciival[2] = '\0';
                asciichar = (unsigned char) strtoul((char *)asciival, &endp, 16);
                if (*endp != '\0') {
                    fprintf(stderr, "Error in line %u: ASCII code expected after '\\'\n", lineNum);
                    return (++errors);
                }
                contentsBuf[j++] = asciichar;
            } else {
                contentsBuf[j++] = contentsStr[i];
            }
        }

        contentsStrLen = j;
        for (i = 0; j < length; ) {
            contentsBuf[j++] = contentsBuf[i++];
            if (i == contentsStrLen)
                i = 0;
        }

        contentsBuf[j] = '\0';
        length = j;

        if (errors == 0 && mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> SET_PAYLOAD_BODY in line %u\n", getTimeString(), localIP, lineNum);

            for (i = 0; (i < length) && (i < MAX_PAYLOAD_LENGTH); i++) {
                payloadContents[HEADER_LENGTH + i] = contentsBuf[i];
            }
            payloadLength = HEADER_LENGTH + i;

            printf("Payload body changed.\n");
        }
    }

    /* SET_PAYLOAD_BODY */
    else if (strcmp(sc->command, "SET_PAYLOAD") == 0)
    {
        char *contentsStr, contentsBuf[MAX_WORD_LENGTH];
        unsigned int length, i, j, contentsStrLen;
        unsigned char asciichar, asciival[3];
        char *endp;

        contentsStr = getStrParam(sc, "CONTENTS", &errors, MANDATORY, lineNum);
        length = (unsigned int) getIntParam(sc, "LENGTH", MIN_PAYLOAD_LENGTH - HEADER_LENGTH,
                                     MAX_PAYLOAD_LENGTH - HEADER_LENGTH, DECIMAL, &errors, MANDATORY, lineNum);

        contentsStrLen = strlen(contentsStr);
        for (i = j = 0; i < contentsStrLen; i++) {
            if (contentsStr[i] == '\\') {
                asciival[0] = contentsStr[++i];
                asciival[1] = contentsStr[++i];
                asciival[2] = '\0';
                asciichar = (unsigned char) strtoul((char *)asciival, &endp, 16);
                if (*endp != '\0') {
                    fprintf(stderr, "Error in line %u: ASCII code expected after '\\'\n", lineNum);
                    return (++errors);
                }
                contentsBuf[j++] = asciichar;
            } else {
                contentsBuf[j++] = contentsStr[i];
            }
        }

        contentsStrLen = j;
        for (i = 0; j < length; ) {
            contentsBuf[j++] = contentsBuf[i++];
            if (i == contentsStrLen)
                i = 0;
        }

        contentsBuf[j] = '\0';
        length = j;

        if (errors == 0 && mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> SET_PAYLOAD in line %u\n", getTimeString(), localIP, lineNum);

            for (i = 0; (i < length) && (i < MAX_PAYLOAD_LENGTH); i++) {
                payloadContents[i] = contentsBuf[i];
            }
            payloadLength = i;

            printf("Payload changed.\n");
        }
    }
    /* DISABLE_RECEIVE */
    else if (strcmp(sc->command, "DISABLE_RECEIVE") == 0)
    {
        if (mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> DISABLE_RECEIVE in line %u\n", getTimeString(), localIP, lineNum);
            receiveEnabled = 0;
        }
    }


    /* ENABLE_RECEIVE */
    else if (strcmp(sc->command, "ENABLE_RECEIVE") == 0)
    {
        if (mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> ENABLE_RECEIVE in line %u\n", getTimeString(), localIP, lineNum);

            receiveEnabled = 1;

            if (unreceivedChunks > 0)
                doReceive(assocID);
        }
    }


    /* PAUSE */
    else if (strcmp(sc->command, "PAUSE") == 0)
    {
        unsigned int delay;

        delay = (unsigned int) getIntParam(sc, "TIME", 1, 0, DECIMAL, &errors, MANDATORY, lineNum);

        if (errors == 0 && mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> PAUSE in line %u (%u msec)\n", getTimeString(), localIP, lineNum, delay);

            pauseTimerID = sctp_startTimer(delay/1000, (delay%1000)*1000, &timerCallback, NULL, NULL);
            while(pauseTimerID != 0)
                sctp_eventLoop();
        }
    }

    /* SEND_CHUNKS */
    else if (strcmp(sc->command, "SEND_CHUNKS") == 0)
    {
        unsigned int num, delay;
        unsigned short stream;

        num = (unsigned int) getIntParam(sc, "NUM", 1, 0, DECIMAL, &errors, MANDATORY, lineNum);
        delay = (unsigned int) getIntParam(sc, "DELAY", 0, 0, DECIMAL, &errors, OPTIONAL, lineNum);
        stream = (unsigned short) getIntParam(sc, "STREAM", 0, 0, DECIMAL, &errors, OPTIONAL, lineNum);

        if (errors == 0 && mode == RUN_SCRIPT)
        {
            int sendRes;
            unsigned int n = 1;

            printf("\n%s (%s) ---> SEND_CHUNKS in line %u (%u chunks, %u msec delay, stream %u)\n",
                   getTimeString(), localIP, lineNum, num, delay, stream);

            if (assocID == 0) {
                printf("Exception in line %u: SEND_CHUNKS: Association does not exist!\n",
                       lineNum);
                return 0;
            }


            while (n <= num)
            {
                sendRes = sctp_send(assocID, stream, (unsigned char *)payloadContents, payloadLength, /*protoID*/ 0,
                                    SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, SCTP_INFINITE_LIFETIME,
                                    SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED);
                n++;

                /* handle sctp_send errors */
                if (sendRes == 1)
                    printf("Exception in line %u: sctp_send returned association error\n", lineNum);
                else if (sendRes == -1)
                    printf("Exception in line %u: sctp_send returned send error\n", lineNum);

                /* start delay timer */
                if (delay > 0) {
                    pauseTimerID = sctp_startTimer(delay/1000, (delay%1000)*1000, &timerCallback, NULL, NULL);
                    while (pauseTimerID != 0)
                        sctp_eventLoop();
                }
                /* unn�tig(?) sctp_getEvents(); */
            }
        }
    }

#ifdef BAKEOFF
    /* SEND_RAWDATA */
    else if (strcmp(sc->command, "SEND_RAWDATA") == 0)
    {
        short pathId;

        pathId = (short) getIntParam(sc, "PATH", 0, 20, DECIMAL, &errors, OPTIONAL, lineNum);

        if (errors == 0 && mode == RUN_SCRIPT)
        {
            int sendRes;
            printf("\n%s (%s) ---> SEND_RAWDATA in line %u)\n", getTimeString(), localIP, lineNum);

            if (assocID == 0) {
                printf("Exception in line %u: SEND_RAWDATA: Association does not exist!\n", lineNum);
                return 0;
            }

            sendRes = sctp_sendRawData(assocID, pathId, payloadContents, payloadLength);

            /* handle sctp_send errors */
            if (sendRes == 1)
                    printf("Exception in line %u: sctp_sendRawData returned association error\n", lineNum);
             else if (sendRes == -1)
                    printf("Exception in line %u: sctp_sendRawData returned send error\n", lineNum);
        }
    }
#endif

    /* SET_RWND */
    else if (strcmp(sc->command, "SET_RWND") == 0)
    {
        unsigned int rwnd;

        rwnd = (unsigned int) getIntParam(sc, "SIZE", 0, 0, DECIMAL, &errors, MANDATORY, lineNum);

        if (errors == 0 && mode == RUN_SCRIPT) {
            SCTP_InstanceParameters iparams;
            SCTP_AssociationStatus astatus;

            printf("\n%s (%s) ---> SET_RWND in line %u (new size: %u bytes)\n",
                   getTimeString(), localIP, lineNum, rwnd);

            sctp_getAssocDefaults(instanceID, &iparams);
            iparams.myRwnd = rwnd;
            sctp_setAssocDefaults(instanceID, &iparams);

            if (assocID != 0) {
                sctp_getAssocStatus(assocID, &astatus);
                astatus.myRwnd = rwnd;
                sctp_setAssocStatus(assocID, &astatus);
            }
        }
    }



    /* SET_RECV_QUEUE */
    else if (strcmp(sc->command, "SET_RECV_QUEUE") == 0)
    {
        unsigned int recvQueue;

        recvQueue = (unsigned int) getIntParam(sc, "SIZE", 0, 0, DECIMAL, &errors, MANDATORY, lineNum);

        if (errors == 0 && mode == RUN_SCRIPT) {
            SCTP_InstanceParameters iparams;
            SCTP_AssociationStatus astatus;

            printf("\n%s (%s) ---> SET_RECV_QUEUE in line %u (%u chunks)\n",
                   getTimeString(), localIP, lineNum, recvQueue);

            sctp_getAssocDefaults(instanceID, &iparams);
            iparams.maxRecvQueue = recvQueue;
            sctp_setAssocDefaults(instanceID, &iparams);

            if (assocID != 0) {
                sctp_getAssocStatus(assocID, &astatus);
                astatus.maxRecvQueue = recvQueue;
                sctp_setAssocStatus(assocID, &astatus);
            }
        }
    }



    /* SET_ACK_DELAY */
    else if (strcmp(sc->command, "SET_ACK_DELAY") == 0)
    {
        unsigned int ackDelay;

        ackDelay = (unsigned int) getIntParam(sc, "DELAY", 0, 0, DECIMAL, &errors, MANDATORY, lineNum);

        if (errors == 0 && mode == RUN_SCRIPT) {
            SCTP_InstanceParameters iparams;
            SCTP_AssociationStatus astatus;

            printf("\n%s (%s) ---> SET_ACK_DELAY in line %u (%u msec)\n",
                   getTimeString(), localIP, lineNum, ackDelay);

            sctp_getAssocDefaults(instanceID, &iparams);
            iparams.delay = ackDelay;
            sctp_setAssocDefaults(instanceID, &iparams);

            if (assocID != 0) {
                sctp_getAssocStatus(assocID, &astatus);
                astatus.delay = ackDelay;
                sctp_setAssocStatus(assocID, &astatus);
            }
        }
    }



    /* SET_HEARTBEAT */
    else if (strcmp(sc->command, "SET_HEARTBEAT") == 0)
    {
        unsigned int time;
        int res;

        time = (unsigned int) getIntParam(sc, "TIMEINTERVAL", 0, 0, DECIMAL, &errors, MANDATORY, lineNum);

        if (errors == 0 && mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> SET_HEARTBEAT in line %u (timeinterval = %u msec)\n",
                   getTimeString(), localIP, lineNum, time);

            res = sctp_changeHeartBeat(assocID, SCTP_USE_PRIMARY,
                                       (time > 0) ? SCTP_HEARTBEAT_ON : SCTP_HEARTBEAT_OFF, time);
            if (res != 0)
                printf("Exception in line %u: SET_HEARTBEAT failed.\n", lineNum);
        }
    }



    /* SET_RECEIVE_MODE */
    else if (strcmp(sc->command, "SET_RECEIVE_MODE") == 0)
    {
        char *recModeStr;
        int recMode=RECEIVE_DISCARD;

        recModeStr = getStrParam(sc, "MODE", &errors, MANDATORY, lineNum);

        if (strcmp(recModeStr, "DISCARD") == 0)
            recMode = RECEIVE_DISCARD;
        else if (strcmp(recModeStr, "MIRROR") == 0)
            recMode = RECEIVE_MIRROR;
        else {
            fprintf(stderr, "Error in line %u: Parameter MODE must be either MIRROR or DISCARD\n", lineNum);
            errors++;
        }

        if (errors == 0 && mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> SET_RECEIVE_MODE in line %u (-> %s)\n", getTimeString(), localIP,
                   lineNum, (recMode == RECEIVE_MIRROR) ? "MIRROR" : "DISCARD");

            receiveMode = recMode;
        }
    }

    /* ASSOCIATE */
    else if (strcmp(sc->command, "ASSOCIATE") == 0)
    {
        char *ip;
        unsigned short port, outstreams;

        ip = getStrParam(sc, "IP", &errors, MANDATORY, lineNum);
        port = (unsigned short) getIntParam(sc, "PORT", 1, 0xFFFF, DECIMAL, &errors, MANDATORY, lineNum);
        outstreams = (unsigned short) getIntParam(sc, "OUTSTREAMS", 1, 0, DECIMAL, &errors, MANDATORY, lineNum);

        if (strlen(ip) > SCTP_MAX_IP_LEN - 1) {
            fprintf(stderr, "Line %u: Invalid IP-Address", lineNum);
            errors++;
        }

        if (errors == 0 && mode == RUN_SCRIPT) {
            printf("\n%s (%s) ---> ASSOCIATE in line %u (Destination: %s)\n",
                   getTimeString(), localIP, lineNum, ip);

            if (assocID != 0) {
                printf("Exception in line %u: Association already exists\n", lineNum);
                return 0;
            }

            if (sctp_associate(instanceID, outstreams, (unsigned char *)ip, port, NULL) == 0) {
                printf("Exception in line %u: ASSOCIATE failed.\n", lineNum);
            }

            /* wait until assoc is established */
            while(assocID == 0)
                sctp_eventLoop();
        }
    }


    /* Unknown Command */
    else {
        fprintf(stderr, "Line %u: Unknown command\n", lineNum);
        errors++;
    }


    /* Get outstanding events */
    if (mode == RUN_SCRIPT)
        sctp_getEvents();

    return errors;
}


/**
 * Retrieve a string parameter from an sctptest_scriptCommand structure
 * @param sc
 *          pointer to the sctptest_scriptCommand structure
 * @param key
 *          the key that belongs to the parameter that shall be retrieved
 * @param err
 *          pointer to an integer variable. This variable is increased when an error occurs,
 *          i.e. when the structure does not contain the specified (mandatory) parameter
 * @param paramType
 *          use the constants MANDATORY and OPTIONAL (defined in sctptest.h)
 *          If the parameter is OPTIONAL, no error message is printed and *err is not increased when
 *          the parameter does not exist
 * @param lineNum
 *          The line number that is to be printed in error messages
 *
 * @return  a pointer to the string that contains the parameter value,
 *          or NULL if the parameter does not exist
 */
char *getStrParam(struct sctptest_scriptCommand *sc, const char *key, unsigned int *err,
                  int paramType, unsigned int lineNum)
{
    int i;
    for (i = 0; i < (int)sc->numOfParams; i++)
        if (strcmp(sc->param[i].key, key) == 0)
            return sc->param[i].value;

    if (paramType == MANDATORY) {
        fprintf(stderr, "Line %u: Command %s requires parameter %s\n", lineNum, sc->command, key);
        (*err)++;
    }
    return NULL;
}


/**
 * Retrieve an integer parameter from an sctptest_scriptCommand structure
 * @param sc
 *          pointer to the sctptest_scriptCommand structure
 * @param key
 *          the key that belongs to the parameter that shall be retrieved
 * @param lowLimit
 *          If the parameter value is less than "lowLimit", an error message is printed,
 *          and *err is increased.
 * @param highLimit
 *          If the parameter value is greater than "highLimit", an error message is printed,
 *          and *err is increased.
 *          If "highLimit" equals or is lower than "lowLimit", it is ignored. This is useful
 *          if no upper limit shall be specified.
 * @param base
 *          The base of the integer parameter, which can be either DECIMAL or HEXADECIMAL (these constants
 *          are defined in sctptest.h) If the parameter is not written in that base or if it is no integer
 *          at all, an error message is printed and *err is increased.
 * @param err
 *          pointer to an integer variable which is increased when an error occurs.
 * @param paramType
 *          use the constants MANDATORY and OPTIONAL (defined in sctptest.h)
 *          If the parameter is OPTIONAL, no error message is printed and *err is not increased when
 *          the parameter does not exist
 * @param lineNum
 *          The line number that is to be printed in error messages
 *
 * @return  the retrieved parameter value, or 0 in case of errors
 *
 */
unsigned long getIntParam(struct sctptest_scriptCommand *sc, const char *key, unsigned long lowLimit,
                 unsigned long highLimit, int base, unsigned int *err, int paramType, unsigned int lineNum)
{
    /* Maybe there should be a parameter for the (default) value that */
    /* shall be returned if an optional parameter has been omitted */

    char *str, *endp;
    unsigned long res;

    str = getStrParam(sc, key, err, paramType, lineNum);

    if (str == NULL)
        return 0;

    res = strtoul(str, &endp, (base == DECIMAL) ? 10 : 16);

    if (*endp != '\0') {
        fprintf(stderr, "Line %u: Parameter %s must have an integer value%s.\n",
                lineNum, key, (base == HEXADECIMAL) ? " in hexadecimal format" : "");
        (*err)++;
        return 0;
    }
    else if (res < lowLimit) {
        fprintf(stderr, "Line %u: The value of parameter %s must be greater than %lu\n",
                lineNum, key, lowLimit - 1);
        (*err)++;
        return 0;
    }
    else if ((res > highLimit) && (highLimit > lowLimit)) {
        fprintf(stderr, "Line %u: The value of parameter %s cannot be greater than %lu\n",
                lineNum, key, highLimit);
        (*err)++;
        return 0;
    }

    return res;
}



void doReceive(unsigned int assoc)
{
    char chunk[MAX_PAYLOAD_LENGTH];
    unsigned int length = MAX_PAYLOAD_LENGTH;
    unsigned short seqno;
    unsigned int tsn;

    while (unreceivedChunks > 0) {
        sctp_receive(assoc, /*stream*/ 0, (unsigned char *)chunk, &length, &seqno, &tsn, SCTP_MSG_DEFAULT);
        unreceivedChunks--;
        printf("Data received (%u bytes) -- %u chunks in receive queue\n", length, unreceivedChunks);
        length = MAX_PAYLOAD_LENGTH;
    }
}



char *getTimeString()
{
    static char timeStr[9];
    time_t t1;
    struct tm *t;

    t1 = time(NULL);
    t = localtime(&t1);
    sprintf(timeStr, "%02d:%02d:%02d", t->tm_hour, t->tm_min, t->tm_sec);

    return timeStr;
}




/* ----- CALLBACK FUNCTIONS ----- */


void timerCallback(unsigned int timerID, void *ptr1, void *ptr2)
{
    if (timerID == pauseTimerID)
        pauseTimerID = 0;
}


void dataArriveNotif(unsigned int assoc, unsigned short stream, unsigned int len,
                     unsigned short streamSN,unsigned int TSN, unsigned int protoID,
                     unsigned int unordered, void* ulpDataPtr)
{
    unsigned char chunk[MAX_PAYLOAD_LENGTH];
    unsigned int length = MAX_PAYLOAD_LENGTH;
    unsigned short seqno;
    unsigned int tsn;

    /* if data unexpectedly arrives on a stream > 0 */
    if (stream != 0) {
        printf("%s (%s) - Data arrived on stream %u -- receiving %u bytes\n",
               getTimeString(), localIP, stream, len);
        sctp_receive(assoc, stream, chunk, &length, &seqno, &tsn, SCTP_MSG_DEFAULT);
        return;
    }

    unreceivedChunks++;

    printf("%s (%s) - Data arrived (%u bytes %s) -- %u chunks in receive queue\n", getTimeString(), localIP,
           len, (unordered == SCTP_ORDERED_DELIVERY) ? "ordered" : "unordered", unreceivedChunks);

    if (receiveEnabled)
        doReceive(assoc);

    if (receiveMode == RECEIVE_MIRROR) {
        int sendRes;
        sendRes = sctp_send(assocID, stream, (unsigned char *)payloadContents, (unsigned int)payloadLength, /*protoID*/ 0,
                            SCTP_USE_PRIMARY, SCTP_NO_CONTEXT, SCTP_INFINITE_LIFETIME,
                            SCTP_ORDERED_DELIVERY, SCTP_BUNDLING_DISABLED);

        /* handle sctp_send errors */
        if (sendRes == 1)
            printf("Exception in mirror process: sctp_send returned association error\n");
        else if (sendRes == -1)
            printf("Exception in mirror process: sctp_send returned send error\n");
    }
}


void sendFailureNotif(unsigned int assoc, unsigned char *unsentData,
                      unsigned int dataLength, unsigned int *context, void *dummy)
{
    printf("%s (%s) - Send failure\n", getTimeString(), localIP);
}


void networkStatusChangeNotif(unsigned int assoc, short destAddrIndex,
                              unsigned short newState, void *ulpDataPtr)
{
    printf("%s (%s) - Network status change: path %u is now %s\n", getTimeString(), localIP,
           destAddrIndex, ((newState == SCTP_PATH_OK) ? "ACTIVE" : "INACTIVE"));
}


void *communicationUpNotif(unsigned int assoc, int status, unsigned  int noOfDestinations,
                           unsigned short instreams, unsigned short outstreams,
                           int associationSupportsPRSCTP, void *dummy)
{
    /* abort if association already exists */
    if (assocID != 0) {
        printf("%s (%s) - Communication up notification arrived -> sending ABORT (only one association allowed)",
               getTimeString(), localIP);
        sctp_abort(assoc);
        return NULL;
    }

    printf("%s (%s) - Communication up: %u path(s), %u in-stream(s), %u out-stream(s)\n",
           getTimeString(), localIP, noOfDestinations, instreams, outstreams);
    noOfInStreams = instreams;
    noOfOutStreams = outstreams;
    assocID = assoc;
    return NULL;

}


void communicationLostNotif(unsigned int assoc, unsigned short status, void *ulpDataPtr)
{
    unsigned char buffer[MAX_PAYLOAD_LENGTH];
    unsigned int bufferLength = sizeof(buffer);
    unsigned short streamID, streamSN;
    unsigned int protoID;
    unsigned int tsn;
    unsigned char flags;
    void* ctx;

    printf("%s (%s) - Communication lost (status %u)\n", getTimeString(), localIP, status);

    /* retrieve data */
    while (sctp_receiveUnsent(assoc, buffer, &bufferLength, &tsn,
                              &streamID, &streamSN, &protoID, &flags, &ctx) >= 0) {
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }

    while (sctp_receiveUnacked(assoc, buffer, &bufferLength, &tsn,
                                &streamID, &streamSN, &protoID,&flags, &ctx) >= 0) {
        /* do something with the retrieved data */
        /* after that, reset bufferLength */
        bufferLength = sizeof(buffer);
    }

    if (unreceivedChunks > 0) {
        printf("Receiving chunks from receive queue before association is deleted\n");
        doReceive(assoc);
    }

    /* delete the association */
    sctp_deleteAssociation(assoc);
    noOfInStreams = 0;
    noOfOutStreams = 0;
    assocID = 0;
}


void communicationErrorNotif(unsigned int assoc, unsigned short status, void *dummy)
{
    printf("%s (%s) - Communication error (status %u)\n", getTimeString(), localIP, status);
}


void restartNotif(unsigned int assoc, void *ulpDataPtr)
{
    printf("%s (%s) - Association restarted\n", getTimeString(), localIP);
}


void shutdownCompleteNotif(unsigned int assoc, void *ulpDataPtr)
{
    printf("%s (%s) - Shutdown complete\n", getTimeString(), localIP);
    if (unreceivedChunks > 0) {
        printf("Receiving chunks from receive queue before association is deleted\n");
        doReceive(assoc);
    }
    sctp_deleteAssociation(assoc);
    noOfInStreams = 0;
    noOfOutStreams = 0;
    assocID = 0;
}
