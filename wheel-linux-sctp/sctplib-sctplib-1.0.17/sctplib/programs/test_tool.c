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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sctp_wrapper.h"
#include "sctptest.h"
#include "sctp.h"

#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008

/**
 * Callback function used to terminate the programm. It is invoked when
 * the user hits the "return" key after the end of the script file was reached.
 */
void exitCallback(int fd, short int revents, short int* gotEvents, void * dummy)
{
    /* clear stdin buffer */
    while(getchar() != 10);

    exit(0);
}


/**
 * Main function
 * Reads the script file name from the command line, checks if there are any errors
 * in the script, and if there are none, the script is started. After the script has
 * been completely executed, the program stays in the event loop (thus listens for
 * arriving chunks etc.) until the user hits the "return" key.
 */
int main(int argc, char *argv[])
{
    SCTP_LibraryParameters params;
    unsigned int           numOfErrors = 0;
    int                    i;

    /* check if there is exactly one command line parameter */
    if (argc < 2) {
        fprintf(stderr, "SCTPTest by Andreas Lang\n");
        fprintf(stderr, "Usage: sctptest <scriptfile> <options>\n");
        fprintf(stderr, "options:\n");
        fprintf(stderr, "-i       ignore OOTB packets\n");
        exit(1);
    }

    sctp_initLibrary();
    SCTP_getLibraryParameters(&params);
    for(i = 2; i < argc; i++) {
        if(strcmp(argv[i], "-i") == 0) {
           params.sendOotbAborts = 0;
        }
    }
    SCTP_setLibraryParameters(&params);

    /* check script for errors */
    if ((numOfErrors = sctptest_start(argv[1], CHECK_SCRIPT)) != 0) {
        fprintf(stderr, "\n%u error(s) in script file!\n", numOfErrors);
        exit(1);
    }

    /* run script */
    sctptest_start(argv[1], RUN_SCRIPT);

    fprintf(stderr, "\nReached end of script file. Press RETURN to exit.\n");
    sctp_registerUserCallback(fileno(stdin), &exitCallback, NULL, POLLPRI|POLLIN);

    while (sctp_eventLoop() >= 0);

    /* this will never be reached */
    return 0;
}
