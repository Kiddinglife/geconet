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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h> /* needed for getopt() */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#ifdef HAVE_SYS_POLL_H
    #include <sys/poll.h>
#else
    #define POLLIN     0x001
    #define POLLPRI    0x002
    #define POLLOUT    0x004
    #define POLLERR    0x008
#endif


#include "sctp.h"
#include "mini-ulp.h"


static unsigned char destinAddrs[10][SCTP_MAX_IP_LEN];
static unsigned char sourceAddrs[10][SCTP_MAX_IP_LEN];
static unsigned short noOfdestinAddrs = 0;
static unsigned short noOfsourceAddrs = 0;

static unsigned short myPort = 0;
static unsigned short remotPort = 0;

static unsigned short doTransmit;
static gboolean useLocalPort;
unsigned short localNumberOfOutStreams = 15;
unsigned short localNumberOfInStreams = 15; /* Our default number of streams.
                                               This is forwarded to SCTP with the
                                               sctp_associate primitive. For z-side, SCTP-control
                                               imports this in order to limit number of
                                               in-streams a-side requests. */
static gboolean streamRobin = FALSE; /* By default all data are transmitted over one stream */
gboolean use_unordered = FALSE;


/* this one is global, as we want to know, whether to enable ipv6 calls, even if it may be compiled in */
gboolean support_ipv6;
int sctp_instance,sctp_instance2,sctp_instance3;
unsigned short ulpPort = 0;


static unsigned int abortAfter = 0xFFFFFFFF;
static unsigned int shutdownAfter = 0xFFFFFFFF;
int droppkts = 0;                /* tells sender to drop every droppkts-th frame without sending it, imported
                                   by the adaptation layer. */


void getArgs(int argc, char **argv)
{
    int c;
    extern char *optarg;
    extern int optind;
    int i;
    int tflg = 0;               /* transmit data */
    int sflg = 0;               /* source address */
#ifdef HAVE_IPV6
    int sv6flg = 0;
    int dv6flg = 0;
#endif

    int dflg = 0;               /* destination address */
    int hflg = 0;               /* print help */
    int lflg = 0;               /* local port */
    int rflg = 0;               /* remote port */
    int uflg = 0;               /* use local port */
    int bflg = 0;               /* heartbeat on */
    int aflg = 0;               /* abort after */
    int nflg = 0;               /* shutdown after */
    int xflg = 0;               /* read all above from a file */
    int cflg = 0;               /* define chunk length (without ULP prot-ID) */
    int mflg = 0;               /* number of streams */
    int oflg = 0;               /* use all streams in round robin manner */
    int vflg = 0;               /* use all streams in round robin manner */
    int errflg = 0;
    char sources[500];
    char destins[SCTP_MAX_NUM_ADDRESSES][100];
#ifdef HAVE_IPV6
    char v6_sources[5000];
    char v6_destins[SCTP_MAX_NUM_ADDRESSES][200];
#endif
    char cfgFile[50];
    char *tokens_str;
    char *tokstr;
    int chunkLength = 20;
    unsigned int zlocalPort;
    unsigned int zremotPort;
    unsigned int HB_time = 0;

    zlocalPort = 0;
    zremotPort = 0;

    support_ipv6 = FALSE;
#ifdef HAVE_IPV6
    while ((c = getopt(argc, argv, "htuovb:s:l:d:r:x:a:n:p:c:m:6:z:")) != EOF)
#else
    while ((c = getopt(argc, argv, "htuovb:s:l:d:r:x:a:n:p:c:m:")) != EOF)
#endif
    {
        printf("%c ", c);
        switch (c) {
        case 'u':
            if (uflg)
                errflg++;
            else
                uflg++;
            break;
        case 't':
            if (tflg)
                errflg++;
            else
                tflg++;
            break;
        case 'b':
            if (bflg)
                errflg++;
            else {
                bflg++;
                HB_time = atoi(optarg);
            }
            break;
        case 'r':
            if (rflg)
                errflg++;
            else {
                zremotPort = atoi(optarg);
                if (zremotPort > 0xFFFF)
                    errflg++;
                rflg++;
            }
            break;
        case 'l':
            if (lflg)
                errflg++;
            else {
                zlocalPort = atoi(optarg);
                if (zlocalPort > 0xFFFF)
                    errflg++;
                lflg++;
            }
            break;
        case 's':
            if (sflg)
                errflg++;
            else {
                strcpy(sources, optarg);
                sflg++;
            }
            break;
#ifdef HAVE_IPV6
        case '6':
            if (sv6flg)
                errflg++;
            else {
                strcpy(v6_sources, optarg);
                sv6flg++;
            }
            break;
        case 'z':
            if (dv6flg > 4) {
                errflg++;
                break;
            }
            strcpy(v6_destins[dv6flg], optarg);
            dv6flg++;
            break;
#endif
        case 'd':
            if (dflg > 4) {
                errflg++;
                break;
            }
            strcpy(destins[dflg], optarg);
            dflg++;
            break;
        case 'a':
            if (aflg)
                errflg++;
            else {
                aflg++;
                abortAfter = atoi(optarg);
            }
            break;
        case 'n':
            if (nflg)
                errflg++;
            else {
                nflg++;
                shutdownAfter = atoi(optarg);
            }
            break;
        case 'p':
            if (droppkts)
                errflg++;
            else {
                droppkts = atoi(optarg);
            }
            break;
        case 'x':
            if (xflg)
                errflg++;
            else {
                xflg++;
                strcpy(cfgFile, optarg);
            }
            break;
        case 'c':
            if (cflg)
                errflg++;
            else {
                cflg++;
                chunkLength = atoi(optarg);
            }
            break;
        case 'm':
            if (mflg)
                errflg++;
            else {
                mflg++;
                localNumberOfInStreams = atoi(optarg);
            }
            break;
        case 'o':
            if (oflg)
                errflg++;
            else {
                oflg++;
            }
            break;
        case 'v':
            if (vflg)
                errflg++;
            else {
                vflg++;
            }
            break;
        case 'h':
            hflg++;
            break;
        case '?':
            errflg++;
        }
    }

    if (hflg) {
        printf("usage: sctp [-htu] -s sourceaddr1,sourceaddr2,... -l localSCTPPort     \\ \n");
        printf("            [-d destaddr1 -d destaddr2 ....-r remotePort] [-p n]    \\ \n");
        printf("            [-b HBinterval] [-a #of datachunks] [-n #of datachunks]\n");
#ifdef HAVE_IPV6
        printf("            [-6 ipv6-sourceaddr1,...] [-z ipv6-destaddr1 -d ipv6-destaddr2 ...]\n");
        printf("use -6 option to define source address(es) as IPv6 numerical (hex) addresses.\n");
        printf
            ("use -z option to define destination address(es) as IPv6 numerical (hex) addresses.\n");
#endif
        printf("use -s option to define the source address(es).\n");
        printf("use -l option to define the local port where inits are accepted.\n");
        printf("use -d option to define the destination address.\n");
        printf("use -r option to define the remote port where init is sent to.\n");
        printf("use -t option to activate data transmission\n");
        printf("use -u option to use the local listening port as source port in init\n");
        printf("use -b 'HBinterval' to switch on heartbeat every (RTO+HB.interval) msecs\n");
        printf("use -p n option to drop every n-th frame without sending it (for testing) \n");
        printf("use -a '#of datachunks' to abort after transmission of '#of datachunks'\n");
        printf("use -n '#of datachunks' to shutdown after transmission of '#of datachunks'\n");
        printf("use -c '#of bytes of userdata' to modify chunklength, default is 20 bytes\n");
        printf("use -m '#of streams' enter number of streams, default is 15 streams\n");
        printf("use -o 'to use all streams in round robin manner\n");
        printf("use -v 'to do also unordered transmission\n");

        printf("for multihoming multiple source addresses can be entered after the -s option.\n");
        printf("They must be separated by commas.\n");
        printf
            ("To establish more than one association, the -d option can be entered n-times, each\n");
        printf("followed by a destination address to which the init is sent.\n");
        printf("-d can be ommitted to start a sctp that listens only for incoming inits\n");
        printf("   if -d is present -r is mantadory\n");
        exit(0);
    }


    if (errflg || optind < argc || ((
#ifdef HAVE_IPV6
                                        ((dflg || dv6flg) && !rflg) ||
#else
                                        (dflg && !rflg) ||
#endif
                                        (uflg && !lflg) ||
                                        ((aflg || nflg) && !tflg) || (!dflg && !lflg) ||
#ifdef HAVE_IPV6
                                        (!sflg && !sv6flg)
#else
                                        (!sflg)
#endif
                                    ))) {
        printf("usage: sctp [-hu] -s sourceaddr1,sourceaddr2,... -l localSCTPPort      \\ \n");
        printf("            [-d destaddr1 -d destaddr2 ....-r remotePort]           \\ \n");
        printf("            [-b HBinterval] [-a #of datachunks] [-n #of datachunks]\n");
#ifdef HAVE_IPV6
        printf("            [-6 ipv6-sourceaddr1,...] [-z ipv6-destaddr1 -d ipv6-destaddr2 ...]\n");
#endif
        printf("use sctp -h for help\n");
        exit(2);
    }


    if (zlocalPort == 0 && !dflg) {
        printf("Local port equal to zero is allowed only for clients\n");
        exit(2);
    }

    if (tflg) {
        printf("transmission of data is activated\n");
        ulp_setChunkLength(chunkLength);
        doTransmit = 1;
    } else {
        printf("data transmissions is deactivated\n");
        doTransmit = 0;
    }

    if (uflg)
        useLocalPort = TRUE;
    else
        useLocalPort = FALSE;

    if (vflg) {
        use_unordered = TRUE;
        printf("some chunks are transmitted unordered\n");
    }

    noOfsourceAddrs = 0;

    if (sflg) {
        printf("sourceaddresses: %s\n", sources);
        tokens_str = sources;

        while ((tokstr = strtok(tokens_str, ",")) != NULL) {
            tokens_str = NULL;
            printf("sourceaddresses separated: %s\n", tokstr);
            strncpy((char *)sourceAddrs[noOfsourceAddrs], tokstr, 16);
            noOfsourceAddrs++;
        }
    }
#ifdef HAVE_IPV6
    if (sv6flg) {
        printf("IPv6 sourceaddresses: %s\n", v6_sources);
        tokens_str = v6_sources;

        while ((tokstr = strtok(tokens_str, ",")) != NULL) {
            tokens_str = NULL;
            printf("IPv6 sourceaddresses separated: %s\n", tokstr);
            strncpy((char *)sourceAddrs[noOfsourceAddrs], tokstr, SCTP_MAX_IP_LEN);
            noOfsourceAddrs++;
        }
    }
#endif

    myPort = zlocalPort;
    printf("Local Port = %hd\n", myPort);

    for (i = 0; i < dflg; i++) {
        printf("Destinationaddress to Host%d: %s\n", i, destins[i]);
        strncpy((char *)destinAddrs[noOfdestinAddrs], destins[i], 16);
        noOfdestinAddrs++;
    }
#ifdef HAVE_IPV6
    for (i = 0; i < dv6flg; i++) {
        printf("Destinationaddress to Host%d: %s\n", i, v6_destins[i]);
        strncpy((char *)destinAddrs[noOfdestinAddrs], v6_destins[i], SCTP_MAX_IP_LEN);
        noOfdestinAddrs++;
    }

#endif
    remotPort = zremotPort;
    printf("Remote Port = %hd\n", remotPort);

    if (bflg) {
        mulp_heartbeat(HB_time);
        printf("heartbeat on with heartbeat intervall %u msecs!!\n", HB_time);
    } else {
        printf("heartbeat disabled !!\n");
    }

    if (oflg)
        streamRobin = TRUE;

    ulp_getEndEvents(shutdownAfter, abortAfter);

    printf("number of streams = %u\n", localNumberOfInStreams);

    if (streamRobin) {
        mulp_streamRoundRobin();
        printf("all streams are use in round robin manner\n");
    }

    if (doTransmit)
        mulp_dosend();
}




int main(int argc, char **argv)
{
    int result;
    SCTP_ulpCallbacks my_ulp;
    int i;



    my_ulp.dataArriveNotif = &ulp_dataArriveNotif;
    my_ulp.networkStatusChangeNotif = &ulp_networkStatusChangeNotif;
    my_ulp.sendFailureNotif = &ulp_sendFailureNotif;
    my_ulp.communicationLostNotif = &ulp_communicationLostNotif;
    my_ulp.communicationUpNotif = &ulp_communicationUpNotif;
    my_ulp.shutdownCompleteNotif = &ulp_ShutdownCompleteNotif;
    my_ulp.peerShutdownReceivedNotif = NULL;

    getArgs(argc, argv);

    sctp_initLibrary();

    if (noOfsourceAddrs > 0) {
            sctp_instance =
                sctp_registerInstance(myPort, localNumberOfInStreams,localNumberOfOutStreams,
                                noOfsourceAddrs, sourceAddrs, my_ulp);
            printf("------ SCTP-initialized: Instance name : %d -------\n", sctp_instance);
/*            sctp_instance2 = sctp_registerInstance(myPort+1,localNumberOfInStreams,
                                    localNumberOfOutStreams, 0, NULL, 0,NULL,  my_ulp);
            printf("------ SCTP-initialized 2 without sourceaddresses: Instance name : %d ----\n",
                       sctp_instance2); */

        } else {
            sctp_instance = sctp_registerInstance(myPort,localNumberOfInStreams,
                                localNumberOfOutStreams,0, NULL, my_ulp);
            printf("------ SCTP-initialized without sourceaddresses: Instance name : %d ----\n",
                       sctp_instance);
/*            sctp_instance2 = sctp_registerInstance(myPort,localNumberOfInStreams,
                                            localNumberOfOutStreams, 0, NULL, my_ulp);
            printf("------ SCTP-initialized 2 without sourceaddresses: Instance name : %d ----\n",
                       sctp_instance2); */

        }

    if (sctp_instance == 0) {
            printf("Error after calling sctp_registerInstance(), aborting !\n");
            exit(1);
    }

    if (ulpPort == 0) {         /* then we start the association, if we are told so */

        if (noOfdestinAddrs > 0) {
            for (i = 0; i < noOfdestinAddrs; i++) {
                printf("-------> Calling sctp_associate() <---------- \n");
                result =    sctp_associate(sctp_instance, localNumberOfOutStreams,
                                   destinAddrs[i], remotPort, NULL);
            }

        }
    }

    sctp_registerUserCallback(fileno(stdin), &ulp_stdin_cb, NULL, POLLIN|POLLPRI);

    printf("******* Main : Entering Event Loop !  ************ \n");

    if (noOfdestinAddrs == 0) {
    	printf(">");
	    fflush(stdout);
    }

    while (sctp_eventLoop() >= 0);

    return EXIT_SUCCESS;
}
