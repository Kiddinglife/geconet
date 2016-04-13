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
#include <ctype.h>
#include "sctptest.h"


/**
 * This function reads one command from the script file.
 * @param scriptFile
 *          the file pointer that belongs to the script file. The parser starts to read at
 *          the current file position. After the function returns, the new file position is at the
 *          character that follows the last character that has been read. This means, if the file
 *          position is not changed outside of this function, subsequent calls of this function
 *          will get the script commands one after another.
 * @param scriptCommand
 *          pointer to an sctptest_scriptCommand structure that will be filled with the data
 *          extracted from the script command.
 *          Please see the description of "struct sctptest_scriptCommand" in "sctptest.h" for more details
 * @param line
 *          pointer to an integer variable that is used to count lines in the script file. If this
 *          pointer is non-NULL, the variable is increased by one when a new-line character occurs
 *          in the script file.
 *          If this integer variable is set to zero before the first call of getScriptCommand(), it
 *          always contains the line number that corresponds to the current file position, unless
 *          the file position or the variable are changed outside of this function.
 * @param column
 *          pointer to an integer variable that (if the pointer is not NULL) is used to hold the number
 *          of the column that corresponds with the current file position.
 *          If this integer variable is set to zero before the first call of getScriptCommand(), it
 *          always contains the correct column number, unless the file position or the variable
 *          are changed outside of this function.
 *          NOTE: this variable actually does not count columns but characters. For example, a tab
 *          character increases the variable by one, although it usually covers more than one column
 *          in an editor.
 * @param mode
 *          If "mode" is RUN_SCRIPT, comments in the script file are echoed on "stdout".
 *          See function sctptest_start() for more details.
 *
 * @return  The parse result, which can have the following values (defined in sctptest.h)
 *          PARSE_OK        -  if the command has been successfully parsed
 *          END_OF_FILE     -  if the end of the script file has been reached
 *          PARSE_ERROR     -  if an error occured during parsing the script command
 */
int getScriptCommand(FILE *scriptFile, struct sctptest_scriptCommand *scriptCommand,
                     unsigned int *line, unsigned int *column, int mode)
{
    int i, termExp;
    int ch;
    char termCh, wordBuffer[MAX_WORD_LENGTH];
    enum { COMMAND, PARAM_KEY, PARAM_VALUE, PARAM_VALUE_STRING } state;


    /* Initialization */
    if ((line != NULL) && (*line == 0))
        *line = 1;
    for (i = 0; i < MAX_NUM_OF_PARAMS; i++) {
        *scriptCommand->param[i].key = '\0';
        *scriptCommand->param[i].value = '\0';
    }
    scriptCommand->numOfParams = 0;
    *wordBuffer = '\0';
    state = COMMAND;
    termCh = ':';
    termExp = 0;


    /* enter scan/parse loop */
    while (1)
    {
        ch = fgetc(scriptFile);

        if (state == PARAM_VALUE_STRING) {
            (*column)++;
            if (ch == '"') {
                termExp = 1;
                state = PARAM_VALUE;
                continue;
            }
            else if (!isprint(ch) || strlen(wordBuffer) >= MAX_WORD_LENGTH-1) {
                return PARSE_ERROR;
            }
            else {
                int length = strlen(wordBuffer);
                wordBuffer[length] = ch;
                wordBuffer[length+1] = '\0';
                continue;
            }
        }

        if (ch == '#') {
            int printComment;
            ch = fgetc(scriptFile);
            printComment = ((ch != '#') && (mode == RUN_SCRIPT));
            if (printComment)
                printf("\n#");
            while ((ch != '\n') && (ch != EOF)) {
                if (printComment && isprint(ch))
                    printf("%c", ch);
                ch = fgetc(scriptFile);
            }
            if (printComment)
                printf("\n");
        }

        ch = toupper(ch);

        if (ch == '\n') {
            if (line != NULL)
                (*line)++;
            if (column != NULL)
                *column = 0;
        } else
            if (column != NULL)
                (*column)++;

        if (ch == EOF) {
            if ((*wordBuffer == '\0') && (state == COMMAND))
                return END_OF_FILE;
            else
                return PARSE_ERROR;
        }

        else if (termExp) {

            if (isspace(ch))
                continue;

            else if ((ch == termCh) || ( (ch == ';') && (state == COMMAND || state == PARAM_VALUE) )) {

                if (state == PARAM_KEY)
                    if (++scriptCommand->numOfParams > MAX_NUM_OF_PARAMS)
                        return PARSE_ERROR;

                switch (state) {
                    case COMMAND:
                        strcpy(scriptCommand->command, wordBuffer);
                        state = PARAM_KEY;
                        termCh = '=';
                        break;
                    case PARAM_KEY:
                        strcpy(scriptCommand->param[scriptCommand->numOfParams - 1].key, wordBuffer);
                        state = PARAM_VALUE;
                        termCh = ',';
                        break;
                    case PARAM_VALUE:
                        strcpy(scriptCommand->param[scriptCommand->numOfParams - 1].value, wordBuffer);
                        state = PARAM_KEY;
                        termCh = '=';
                        break;
                    case PARAM_VALUE_STRING:
                        /* just to avoid compiler warnings */
                        break;
                    default:
                        break;
                }

                *wordBuffer = '\0';
                termExp = 0;

                if (ch == ';')
                    return PARSE_OK;
                else
                    continue;
            }

            else
                return PARSE_ERROR;
        }

        else {   /* (if !termExp) */

            if (isspace(ch)) {
                if (*wordBuffer != '\0')
                    termExp = 1;
                continue;
            }

            else if (ch == '"') {
                if ((state == PARAM_VALUE) && (*wordBuffer == '\0')) {
                    state = PARAM_VALUE_STRING;
                    continue;
                } else {
                    return PARSE_ERROR;
                }
            }


            else if ((ch == termCh) || ( (ch == ';') && (state == COMMAND || state == PARAM_VALUE) )) {

                if (*wordBuffer == '\0')
                    return PARSE_ERROR;

                if (state == PARAM_KEY)
                    if (++scriptCommand->numOfParams > MAX_NUM_OF_PARAMS)
                        return PARSE_ERROR;

                switch (state) {
                    case COMMAND:
                        strcpy(scriptCommand->command, wordBuffer);
                        state = PARAM_KEY;
                        termCh = '=';
                        break;
                    case PARAM_KEY:
                        strcpy(scriptCommand->param[scriptCommand->numOfParams - 1].key, wordBuffer);
                        state = PARAM_VALUE;
                        termCh = ',';
                        break;
                    case PARAM_VALUE:
                        strcpy(scriptCommand->param[scriptCommand->numOfParams - 1].value, wordBuffer);
                        state = PARAM_KEY;
                        termCh = '=';
                        break;
                    case PARAM_VALUE_STRING:
                        /* just to avoid compiler warnings */
                        break;
                    default:
                        break;
                }

                *wordBuffer = '\0';
                termExp = 0;

                if (ch == ';')
                    return PARSE_OK;
                else
                    continue;
            }

            else if ((!isalnum(ch) && (ch != '_') && (ch != '.')) || strlen(wordBuffer) >= MAX_WORD_LENGTH-1)
                return PARSE_ERROR;

            else {
                int length = strlen(wordBuffer);
                wordBuffer[length] = ch;
                wordBuffer[length+1] = '\0';
            }

        }
    }
}



/* ONLY FOR TESTING */
void printCommand(struct sctptest_scriptCommand *sc, unsigned int lineNum)
{
    int i;

    printf("\n\nLine %u:\n", lineNum);
    printf("COMMAND: %s  with %d params\n", sc->command, sc->numOfParams);

    for (i = 0; i < (int)sc->numOfParams; i++)
        printf("KEY: %s   VALUE: %s\n", sc->param[i].key, sc->param[i].value);
}


