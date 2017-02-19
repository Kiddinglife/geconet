/* $Id: chunkHandler.c 2771 2013-05-30 09:09:07Z dreibh $
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
 * Copyright (C) 2004-2013 Thomas Dreibholz
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

#ifdef HAVE_CONpm_heartbeatFIG_H
#include <config.h>
#endif

#include <errno.h>

#include "sctp.h"
#include "globals.h"
#include "auxiliary.h"
#include "adaptation.h"
#include "chunkHandler.h"
#include "SCTP-control.h"
#include "pathmanagement.h"
#include "md5.h"


#define MAX_CHUNKS 8

#ifndef IN_EXPERIMENTAL
#define  IN_EXPERIMENTAL(a)   ((((gint) (a)) & 0xf0000000) == 0xf0000000)
#endif

#ifndef IN_BADCLASS
#define  IN_BADCLASS(a)    IN_EXPERIMENTAL((a))
#endif

/* Other constants */


static unsigned short      writeCursor[MAX_CHUNKS];
static SCTP_simple_chunk*  chunks[MAX_CHUNKS];
static boolean             chunkCompleted[MAX_CHUNKS];

static ChunkID freeChunkID = 0;

void ch_addUnrecognizedParameter(unsigned char* pos, ChunkID cid,
                                 unsigned short length, unsigned char* data);

/******************************* internal functions ***********************************************/
/*
 * computes a cookie signature.
 * TODO: replace this by something safer than MD5
 */
static int
signCookie(unsigned char *cookieString, unsigned short cookieLength,
           unsigned char *start_of_signature)
{
    int i;
    MD5_CTX ctx;
    SCTP_our_cookie *cookie;
    unsigned char * key;

    if (cookieString == NULL)
        return -1;
    if (start_of_signature == NULL)
        return -1;
    if (cookieLength == 0)
        return -1;
    key =  key_operation(KEY_READ);
    if (key == NULL)
        return -1;

    cookie = (SCTP_our_cookie *) cookieString;
    memset(cookie->hmac, 0, HMAC_LEN);

    MD5Init(&ctx);
    MD5Update(&ctx, cookieString, cookieLength);
    MD5Update(&ctx, key, SECRET_KEYSIZE);
    MD5Final(start_of_signature, &ctx);

    event_log(INTERNAL_EVENT_0, "Computed MD5 signature : ");
    for (i = 0; i < 4; i++) {
        event_logiiii(VERBOSE, "%2.2x %2.2x %2.2x %2.2x",
                      start_of_signature[i * 4], start_of_signature[i * 4 + 1],
                      start_of_signature[i * 4 + 2], start_of_signature[i * 4 + 3]);
    }

    return 0;
}


/**
 * retrieveVLParamFromString scans for a parameter of a certain type in a message string.
 * The message string must point to a parameter header. The function can also be used
 * to find parameters within a parameter (e.g. addresses within a cookie).
 * @param paramType type of paramter to scan for,
 * @param mstring   pointer to the first parameter header, from which we start scanning
 * @param length    maximum length of parameter field, that may be scanned.
 * @return          position of first parameter occurence, relative to where mstring pointed to
 *                  i.e. 0 returned, when mstring points to the parameter we scan for.
 *                  OR -1 if not found !!!!!!!
 */
static gint32 retrieveVLParamFromString(guint16 paramType, guchar * mstring, guint16 length)
{
    guint16 curs;
    guint16 pType;
    SCTP_vlparam_header *param_header;

    curs = 0;

    /* TODO : add support for all Error Cause Codes ? ECC_XXXXXXXX */
    while (curs < length) {
        param_header = (SCTP_vlparam_header *) & mstring[curs];
        pType = ntohs(param_header->param_type);

        if (ntohs(param_header->param_length) < 4) {
            error_log(ERROR_MINOR, "Program/Peer implementation problem : parameter length 0");
            return -1;
        }

        if (pType == paramType) {
            return curs;
        }
            else if (pType == VLPARAM_IPV4_ADDRESS ||
                     pType == VLPARAM_IPV6_ADDRESS ||
                     pType == VLPARAM_COOKIE ||
                     pType == VLPARAM_COOKIE_PRESERV ||
                     pType == ECC_STALE_COOKIE_ERROR ||
                     pType == VLPARAM_SUPPORTED_ADDR_TYPES ||
                     pType == VLPARAM_PRSCTP||
                     pType == VLPARAM_SET_PRIMARY||
                     pType == VLPARAM_ADAPTATION_LAYER_IND) {
            curs += ntohs(param_header->param_length);
            /* take care of padding */
            while ((curs % 4) != 0)
                curs++;
        } else if (pType == VLPARAM_ECN_CAPABLE || pType == VLPARAM_HOST_NAME_ADDR) {
            event_logi(INTERNAL_EVENT_1, "parameter type %d not supported", pType);
            curs += ntohs(param_header->param_length);
            /* take care of padding here */
            while ((curs % 4) != 0)
                curs++;
        } else {
            error_logi(ERROR_MINOR, "unknown parameter type %u in message", pType);
            /* try to continue parsing */
            if ((ntohs(param_header->param_length) + curs) <= length) {
                curs += ntohs(param_header->param_length);
                while ((curs % 4) != 0) curs++;
            } else
                return -1;
            /* take care of padding here */
            while ((curs % 4) != 0)
                curs++;
        }
    }
    return -1;
}


/**
 * setIPAddresses finds all IP addresses in a message string.
 * TODO : check for maximum number of addresses, there may possibly be an overflow
 * @param   mstring     pointer to the beginning of the message string
 * @param   length      maximum length of the message that is scanned for addresses
 * @param   addresses   field in which we may return addresses
 * @return  number of IPv4 addresses found
*/
static gint32
setIPAddresses(unsigned char *mstring, guint16 length, union sockunion addresses[],
                unsigned int* peerTypes, unsigned int myTypes, union sockunion* lastSource,
                gboolean ignore_dups, gboolean ignoreLast)
{
    gint32 cursabs = 0;
    gint32 cursrel = 0;
    union sockunion tmpAddr;
    SCTP_ip_address *address;
    int nAddresses = 0, v4found = 0, idx;
#ifdef HAVE_IPV6
    int v6found = 0;
    union sockunion tmp_su;
    AddressScopingFlags filterFlags;
    gboolean localHostFound=FALSE, linkLocalFound = FALSE, siteLocalFound = FALSE;
#endif
    gboolean discard = FALSE, last_found = FALSE, new_found;

    event_logii(VERBOSE, "setIPAddresses : length = %u, my supp. AddrTypes=%d", length, myTypes);

    (*peerTypes) = 0;
    if (myTypes & SUPPORT_ADDRESS_TYPE_IPV4) {

        while ((cursrel = retrieveVLParamFromString(VLPARAM_IPV4_ADDRESS,
                                                    &mstring[cursabs],
                                                    (guint16)(length - cursabs)) ) >= 0) {

            address = (SCTP_ip_address *) & mstring[cursabs + cursrel];

            if (IS_IPV4_ADDRESS_PTR_NBO(address)) {
                discard  = FALSE;
                /* FIXME : either NBO or HBO -- do not mix these */
                if (IN_CLASSD(ntohl(address->dest_addr.sctp_ipv4))) discard = TRUE;
                if (IN_EXPERIMENTAL(ntohl(address->dest_addr.sctp_ipv4))) discard = TRUE;
                if (IN_BADCLASS(ntohl(address->dest_addr.sctp_ipv4))) discard = TRUE;
                if (INADDR_ANY == ntohl(address->dest_addr.sctp_ipv4)) discard = TRUE;
                if (INADDR_BROADCAST == ntohl(address->dest_addr.sctp_ipv4)) discard = TRUE;
                /*
                if (INADDR_LOOPBACK == ntohl(address->dest_addr.sctp_ipv4)) discard = TRUE;
                */
                event_logii(VVERBOSE, "Got IPv4 address %x, discard: %s !",
                                        ntohl(address->dest_addr.sctp_ipv4), (discard==TRUE)?"TRUE":"FALSE");
                if(nAddresses >= MAX_NUM_ADDRESSES) {
                   error_log(ERROR_MINOR, "Too many addresses found during IPv4 reading");
                   discard = TRUE;
                }

                if (discard == FALSE) {
                    new_found = TRUE;
                    tmpAddr.sa.sa_family = AF_INET;
                    tmpAddr.sin.sin_port = 0;
                    tmpAddr.sin.sin_addr.s_addr = address->dest_addr.sctp_ipv4;

                    if (ignore_dups == TRUE) {
                        for (idx = 0; idx < v4found; idx++)
                             if (adl_equal_address(&tmpAddr, &addresses[idx]) == TRUE) new_found = FALSE;
                    }

                    if (new_found == TRUE) {
                        addresses[v4found].sa.sa_family = AF_INET;
                        addresses[v4found].sin.sin_port = 0;
                        addresses[v4found].sin.sin_addr.s_addr = address->dest_addr.sctp_ipv4;
                        nAddresses++; v4found++;
                        (*peerTypes) |= SUPPORT_ADDRESS_TYPE_IPV4;
                        event_logi(VERBOSE, "Found NEW IPv4 Address = %x", ntohl(address->dest_addr.sctp_ipv4));
                    } else {
                        event_log(VERBOSE, "IPv4 was in the INIT or INIT ACK chunk more than once");
                    }
                }
            } else {
                error_log(ERROR_MAJOR, "parameter problem, abort scanning in setIPAddresses");
                break;
            }
            cursabs += cursrel;
            cursabs += 8;
            if (cursabs >= length) break;
        }   /* end : while */
        event_logi(VERBOSE, "Found %u NEW IPv4 Addresses - now starting to look for IPv6", v4found);

    } /* end: myTypes & SUPPORT_ADDRESS_TYPE_IPV4 */

#ifdef HAVE_IPV6
    if (myTypes & SUPPORT_ADDRESS_TYPE_IPV6) {
        /* and scan again from the very beginning................. */
        cursabs = 0;
        cursrel = 0;

        localHostFound = mdi_addressListContainsLocalhost(1, lastSource);
        linkLocalFound = !( adl_filterInetAddress(lastSource, flag_HideLinkLocal));
        siteLocalFound = !( adl_filterInetAddress(lastSource, flag_HideSiteLocal));

        if (localHostFound == FALSE) {
            /* this is from a normal address, get all except loopback */
            if (linkLocalFound) {
                filterFlags = (AddressScopingFlags)(flag_Default|flag_HideLoopback);
            } else if (siteLocalFound) {
                filterFlags = (AddressScopingFlags)(flag_Default|flag_HideLinkLocal|flag_HideLoopback);
            } else {
                filterFlags = (AddressScopingFlags)(flag_Default|flag_HideLocal);
            }
        } else  /* if localHostFound == TRUE) */ {
             /* this is from a loopback, get all */
             filterFlags = flag_Default;
        }
        event_logiii(VERBOSE, "localHostFound: %d,  linkLocalFound: %d, siteLocalFound: %d",
               localHostFound, linkLocalFound,  siteLocalFound);

        while ((cursrel =
                retrieveVLParamFromString(VLPARAM_IPV6_ADDRESS, &mstring[cursabs],
                                          length - cursabs)) >= 0) {
            address = (SCTP_ip_address *) & mstring[cursabs + cursrel];

            if (IS_IPV6_ADDRESS_PTR_NBO(address)) {
                discard  = FALSE;
                tmp_su.sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
                tmp_su.sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif                          /* SIN6_LEN */
                memcpy(&(tmp_su.sin6.sin6_addr.s6_addr),&(address->dest_addr.sctp_ipv6), 16);
                /* Bugfix: just copy 16 bytes of the address, not sizeof(struct sockaddr_in6)! */

#if defined (LINUX)
                if (IN6_IS_ADDR_UNSPECIFIED(&(address->dest_addr.sctp_ipv6))) discard = TRUE;
                if (IN6_IS_ADDR_MULTICAST(&(address->dest_addr.sctp_ipv6))) discard = TRUE;
                if (IN6_IS_ADDR_V4COMPAT(&(address->dest_addr.sctp_ipv6))) discard = TRUE;
#else
                if (IN6_IS_ADDR_UNSPECIFIED((struct in6_addr*)&(address->dest_addr.sctp_ipv6))) discard = TRUE;
                if (IN6_IS_ADDR_MULTICAST((struct in6_addr*)&(address->dest_addr.sctp_ipv6))) discard = TRUE;
                if (IN6_IS_ADDR_V4COMPAT((struct in6_addr*)&(address->dest_addr))) discard = TRUE;
#endif
                if (adl_filterInetAddress(&tmp_su, filterFlags) == FALSE) {
                   discard = TRUE;
                }
                if(nAddresses >= MAX_NUM_ADDRESSES) {
                   error_log(ERROR_MINOR, "Too many addresses found during IPv6 reading");
                   discard = TRUE;
                }
                event_logiii(VERBOSE, "Found IPv6 Address - discard=%s - #v4=%d - #v6=%d !",
                             (discard==TRUE)?"TRUE":"FALSE", v4found, v6found);
                if (discard == FALSE) {
                    new_found = TRUE;

                    if (ignore_dups == TRUE) {
                        for (idx = v4found; idx < v4found+v6found; idx++)
                            if (adl_equal_address(&tmp_su, &addresses[idx]) == TRUE) {
                                new_found = FALSE;
#if defined (LINUX)
                                event_logiiiiiiii(VERBOSE, "Found OLD IPv6 Address %x:%x:%x:%x:%x:%x:%x:%x!",
                                                  ntohs(tmp_su.sin6.sin6_addr.s6_addr16[0]),
                                                  ntohs(tmp_su.sin6.sin6_addr.s6_addr16[1]),
                                                  ntohs(tmp_su.sin6.sin6_addr.s6_addr16[2]),
                                                  ntohs(tmp_su.sin6.sin6_addr.s6_addr16[3]),
                                                  ntohs(tmp_su.sin6.sin6_addr.s6_addr16[4]),
                                                  ntohs(tmp_su.sin6.sin6_addr.s6_addr16[5]),
                                                  ntohs(tmp_su.sin6.sin6_addr.s6_addr16[6]),
                                                  ntohs(tmp_su.sin6.sin6_addr.s6_addr16[7]));
#endif
                            }
                    }

                    if (new_found == TRUE) {
                        addresses[nAddresses].sa.sa_family = AF_INET6;
                        addresses[nAddresses].sin6.sin6_port = htons(0);
                        addresses[nAddresses].sin6.sin6_flowinfo = htonl(0);
#ifdef HAVE_SIN6_SCOPE_ID
                        addresses[nAddresses].sin6.sin6_scope_id = htonl(0);
#endif

                        memcpy(addresses[nAddresses].sin6.sin6_addr.s6_addr,
                               address->dest_addr.sctp_ipv6, sizeof(struct in6_addr));
                        nAddresses++; v6found++;
                        (*peerTypes) |= SUPPORT_ADDRESS_TYPE_IPV6;
#if defined (LINUX)
                        event_logiiiiiiii(VERBOSE, "Found NEW IPv6 Address %x:%x:%x:%x:%x:%x:%x:%x!",
                                          ntohs(tmp_su.sin6.sin6_addr.s6_addr16[0]),
                                          ntohs(tmp_su.sin6.sin6_addr.s6_addr16[1]),
                                          ntohs(tmp_su.sin6.sin6_addr.s6_addr16[2]),
                                          ntohs(tmp_su.sin6.sin6_addr.s6_addr16[3]),
                                          ntohs(tmp_su.sin6.sin6_addr.s6_addr16[4]),
                                          ntohs(tmp_su.sin6.sin6_addr.s6_addr16[5]),
                                          ntohs(tmp_su.sin6.sin6_addr.s6_addr16[6]),
                                          ntohs(tmp_su.sin6.sin6_addr.s6_addr16[7]));
#endif

                    }
                }
            } else {
                error_log(ERROR_MAJOR, "parameter problem, abort scanning in setIPAddresses");
                break;
            }
            cursabs += cursrel;
            cursabs += 20;
            if (cursabs >= length)
                break;
        }

    }
#endif  /* HAVE_IPV6 */

    if (ignoreLast == FALSE) {
        for (idx = 0; idx < nAddresses; idx++)
            if (adl_equal_address(lastSource, &addresses[idx]) == TRUE) last_found = TRUE;

        if (last_found == FALSE) {
            memcpy(&addresses[nAddresses], lastSource, sizeof(union sockunion));
            event_log(VERBOSE, "Added also lastFromAddress to the addresslist !");
            switch(sockunion_family(lastSource)) {
                case AF_INET : (*peerTypes) |= SUPPORT_ADDRESS_TYPE_IPV4; break;
#ifdef HAVE_IPV6
                case AF_INET6 : (*peerTypes) |= SUPPORT_ADDRESS_TYPE_IPV6; break;
#endif
                default: break;
            }
            nAddresses++;
        }
    }
    return nAddresses;
}


static void enterChunk(SCTP_simple_chunk * chunk, const char *log_text)
{
    unsigned int cid;

    freeChunkID = (freeChunkID + 1) % MAX_CHUNKS;

    cid = freeChunkID;
    event_logi(INTERNAL_EVENT_0, log_text, cid);

    chunks[freeChunkID] = chunk;
    writeCursor[freeChunkID] = 0;
    chunkCompleted[freeChunkID] = FALSE;
}

/******************************* external functions ***********************************************/

/*****  create, write into and read from init and initAck ******************************************/

/* ch_makeInit makes an init and initializes the the fixed part of init */
ChunkID ch_makeInit(unsigned int initTag, unsigned int rwnd, unsigned short noOutStreams,
                    unsigned short noInStreams, unsigned int initialTSN)
{
    SCTP_init *initChunk;

    /* creat init chunk */
    initChunk = (SCTP_init *) malloc(sizeof(SCTP_init));

    if (initChunk == NULL) error_log_sys(ERROR_FATAL, (short)errno);

    memset(initChunk, 0, sizeof(SCTP_init));


    /* enter fixed part of init */
    initChunk->chunk_header.chunk_id = CHUNK_INIT;
    initChunk->chunk_header.chunk_flags = 0x00;
    initChunk->chunk_header.chunk_length = sizeof(SCTP_chunk_header) + sizeof(SCTP_init_fixed);
    initChunk->init_fixed.init_tag = htonl(initTag);
    initChunk->init_fixed.rwnd = htonl(rwnd);
    initChunk->init_fixed.outbound_streams = htons(noOutStreams);
    initChunk->init_fixed.inbound_streams = htons(noInStreams);
    initChunk->init_fixed.initial_tsn = htonl(initialTSN);

    enterChunk((SCTP_simple_chunk *) initChunk, "created init %u ");

    return freeChunkID;
}



/* ch_makeInitAck makes an initAck and initializes the the fixed part of initAck */
ChunkID
ch_makeInitAck(unsigned int initTag,
               unsigned int rwnd,
               unsigned short noOutStreams, unsigned short noInStreams, unsigned int initialTSN)
{
    SCTP_init *initAckChunk = NULL;

    /* creat init chunk */
    initAckChunk = (SCTP_init *) malloc(sizeof(SCTP_init));
    if (initAckChunk == NULL)
        error_log_sys(ERROR_FATAL, (short)errno);

    memset(initAckChunk, 0, sizeof(SCTP_init));

    /* enter fixed part of init */
    initAckChunk->chunk_header.chunk_id = CHUNK_INIT_ACK;
    initAckChunk->chunk_header.chunk_flags = 0x00;
    initAckChunk->chunk_header.chunk_length = sizeof(SCTP_chunk_header) + sizeof(SCTP_init_fixed);
    initAckChunk->init_fixed.init_tag = htonl(initTag);
    initAckChunk->init_fixed.rwnd = htonl(rwnd);
    initAckChunk->init_fixed.outbound_streams = htons(noOutStreams);
    initAckChunk->init_fixed.inbound_streams = htons(noInStreams);
    initAckChunk->init_fixed.initial_tsn = htonl(initialTSN);

    enterChunk((SCTP_simple_chunk *) initAckChunk, "created initAckChunk %u ");

    return freeChunkID;
}




void
ch_enterSupportedAddressTypes(ChunkID chunkID,
                              gboolean with_ipv4, gboolean with_ipv6, gboolean with_dns)
{
    SCTP_supported_addresstypes *param = NULL;
    guint16 num_of_types = 0, position = 0;
    guint16 total_length = 0;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
    }

    if (chunkCompleted[chunkID]) {
        error_log(ERROR_MAJOR, " ch_enterSupportedAddressTypes : chunk already completed");
        return;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        if (with_ipv4) num_of_types++ ;
        if (with_ipv6) num_of_types++;
        if (with_dns)  num_of_types++;

        /* append the new parameter */
        param = (SCTP_supported_addresstypes *) & ((SCTP_init *)
                                     chunks[chunkID])->variableParams[writeCursor[chunkID]];
        /* _might_ be overflow here, at some time... */
        if (num_of_types == 0)
            error_log(ERROR_FATAL, " No Supported Address Types -- Program Error");

        total_length = sizeof(SCTP_vlparam_header) + num_of_types * sizeof(guint16);

        writeCursor[chunkID] += total_length;
        if ((total_length % 4) != 0)
            writeCursor[chunkID] += 2;

        /* enter cookie preservative */
        param->vlparam_header.param_type = htons(VLPARAM_SUPPORTED_ADDR_TYPES);
        param->vlparam_header.param_length = htons(total_length);
        if (with_ipv4) {
            param->address_type[position] = htons(VLPARAM_IPV4_ADDRESS);
            position++;
        }
        if (with_ipv6) {
            param->address_type[position] = htons(VLPARAM_IPV6_ADDRESS);
            position++;
        }
        if (with_dns) {
            param->address_type[position] = htons(VLPARAM_HOST_NAME_ADDR);
            position++;
        }
        /* take care of padding */
        if (position == 1 || position == 3)
            param->address_type[position] = htons(0);

    } else {
        error_log(ERROR_MAJOR, "ch_enterSupportedAddressTypes : chunk type not init");
    }
}


/**
 * ch_enterCookiePreservative appends a cookie preservative with the suggested
 * cookie lifespan to an init chunk.
 */
void ch_enterCookiePreservative(ChunkID chunkID, unsigned int lifespanIncrement)
{
    SCTP_cookie_preservative *preserv;
    gint32 vl_param_curs;
    guint16 vl_param_total_length;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");

    }

    if (chunkCompleted[chunkID]) {
        error_log(ERROR_MAJOR, "ch_enterCookiePreservative : chunk already completed");
        return;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        /* check if init chunk already contains a cookie preserv. */
        vl_param_total_length =
            ((SCTP_init *) chunks[chunkID])->chunk_header.chunk_length -
            sizeof(SCTP_chunk_header) - sizeof(SCTP_init_fixed);

        vl_param_curs = retrieveVLParamFromString(VLPARAM_COOKIE_PRESERV, &((SCTP_init *)
                                                                            chunks
                                                                            [chunkID])->
                                                  variableParams[0], vl_param_total_length);
        if (vl_param_curs >= 0) {
            /* simply overwrite this cookie preserv. */
            preserv = (SCTP_cookie_preservative *) & ((SCTP_init *)
                                                      chunks[chunkID])->variableParams
                [vl_param_curs];
        } else {
            /* append the new parameter */
            preserv = (SCTP_cookie_preservative *) & ((SCTP_init *)
                                 chunks[chunkID])->variableParams[writeCursor[chunkID]];
            /* _might_ be overflow here, at some time... */
            writeCursor[chunkID] += sizeof(SCTP_cookie_preservative);
        }

        /* enter cookie preservative */
        preserv->vlparam_header.param_type = htons(VLPARAM_COOKIE_PRESERV);
        preserv->vlparam_header.param_length = htons(sizeof(SCTP_cookie_preservative));
        preserv->cookieLifetimeInc = htonl(lifespanIncrement);

    } else {
        error_log(ERROR_MAJOR, "ch_enterCookiePreservative: chunk type not init");
    }
}



/**
 *  ch_enterIPaddresses appends local IP addresses to a chunk, usually an init or initAck
 */
int ch_enterIPaddresses(ChunkID chunkID, union sockunion sock_addresses[], int noOfAddresses)
{
    unsigned char *mstring;
    int i,length;
    SCTP_ip_address *address;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return -1;
    }

    if (chunkCompleted[chunkID]) {
        error_log(ERROR_MAJOR, "ch_enterIPaddresses: chunk already completed");
        return 1;
    }

    length = 0;

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {

        mstring = &((SCTP_init *) chunks[chunkID])->variableParams[writeCursor[chunkID]];
    } else {
        mstring = &((SCTP_asconf*)chunks[chunkID])->variableParams[writeCursor[chunkID]];
    }

    for (i = 0; i < noOfAddresses; i++) {

        address = (SCTP_ip_address *) & mstring[length];

        switch (sockunion_family(&(sock_addresses[i]))) {
            case AF_INET:
                address->vlparam_header.param_type = htons(VLPARAM_IPV4_ADDRESS);
                address->vlparam_header.param_length = htons(8);
                address->dest_addr.sctp_ipv4 = sock2ip(&(sock_addresses[i]));
                length += 8;
                break;
#ifdef HAVE_IPV6
            case AF_INET6:
                address->vlparam_header.param_type = htons(VLPARAM_IPV6_ADDRESS);
                address->vlparam_header.param_length = htons(20);
                memcpy(address->dest_addr.sctp_ipv6,
                       &(sock2ip6(&(sock_addresses[i]))), sizeof(struct in6_addr));
                length += 20;
                break;
#endif
            default:
                error_logi(ERROR_MAJOR, "Unsupported Address Family %d",
                           sockunion_family(&(sock_addresses[i])));
                break;

        }   /* switch */
    }       /* for */
    writeCursor[chunkID] += length;

    return 0;
}

int ch_enterECNchunk(ChunkID initAckID, ChunkID initCID)
{
    return 0;
}

gboolean ch_getPRSCTPfromCookie(ChunkID cookieCID)
{
    gboolean result = FALSE;
    SCTP_vlparam_header *vl_Ptr = NULL;
    guint16 curs;
    guint16 pType;
    guint16 pLen;
    guint16 vlp_totalLength;
    unsigned char* the_string=NULL;

   if (chunks[cookieCID] == NULL) {
        error_log(ERROR_FATAL, "Invalid Cookie chunk ID");
        return FALSE;
    }
    vlp_totalLength =
            ((SCTP_cookie_echo *) chunks[cookieCID])->chunk_header.chunk_length -
            COOKIE_FIXED_LENGTH - sizeof(SCTP_chunk_header);

    curs = 0;
    the_string =  &((SCTP_cookie_echo *)chunks[cookieCID])->vlparams[0];

    while (curs < vlp_totalLength) {
        vl_Ptr = (SCTP_vlparam_header *) & the_string[curs];
        pType =  ntohs(vl_Ptr->param_type);
        pLen  =  ntohs(vl_Ptr->param_length);
        event_logiii(VERBOSE, "Scan variable parameters in cookie: Got type %u, len: %u, position %u",pType, pLen, curs);

        /* peer error - ignore - should send an error notification */
        if (pLen < 4) return FALSE;

        if (pType == VLPARAM_PRSCTP) {
            /* ha, we got one ! */

            if (pLen >= 4){
                 event_log(VERBOSE, "Peer Supports PRSCTP");
                 result = TRUE; /* peer supports it  */
            }
            break;
        }
        curs += pLen;
        while ((curs % 4) != 0) curs++;
    }
    return result;
}


gboolean ch_getPRSCTPfromInitAck(ChunkID initAckCID)
{
    gboolean result = FALSE;
    SCTP_vlparam_header *vl_Ptr = NULL;
    guint16 curs;
    guint16 pType;
    guint16 pLen;
    guint16 vlp_totalLength;
    unsigned char* ack_string;

   if (chunks[initAckCID] == NULL) {
        error_log(ERROR_FATAL, "Invalid initAck chunk ID");
        return -1;
    }
    vlp_totalLength = ((SCTP_init *)chunks[initAckCID])->chunk_header.chunk_length -
                        sizeof(SCTP_chunk_header) - sizeof(SCTP_init_fixed);

    event_logi(VERBOSE, "Scan initAckChunk for PRSCTP parameter: len %u", vlp_totalLength);

    curs = 0;
    ack_string =  &((SCTP_init *)chunks[initAckCID])->variableParams[0];

    while (curs < vlp_totalLength) {
        vl_Ptr = (SCTP_vlparam_header *) & ack_string[curs];
        pType =  ntohs(vl_Ptr->param_type);
        pLen  =  ntohs(vl_Ptr->param_length);

        if (pLen < 4) return  FALSE; /* peer error - ignore - should send an error notification */

        event_logiii(VERBOSE, "Scan variable parameters: Got type %u, len: %u, position %u",pType, pLen, curs);

        if (pType == VLPARAM_PRSCTP) {
            /* ha, we got one ! */

            if (pLen >= 4) result = TRUE; /* peer supports it */
            break;
        }
        curs += pLen;
        while ((curs % 4) != 0) curs++;
    }
    return result;
}

int ch_enterPRSCTPfromInit(ChunkID initAckCID, ChunkID initCID)
{
    int result = -1;
    SCTP_vlparam_header *vl_initPtr = NULL;
    guint16 curs;
    guint16 pType;
    guint16 pLen;
    guint16 vlp_totalLength;
    unsigned char* init_string;
    unsigned char* ack_string;

   if (chunks[initCID] == NULL || chunks[initAckCID] == NULL) {
        error_log(ERROR_FATAL, "Invalid init or initAck chunk ID");
        return -1;
    }
    vlp_totalLength = ((SCTP_init *)chunks[initCID])->chunk_header.chunk_length -
                        sizeof(SCTP_chunk_header) - sizeof(SCTP_init_fixed);

    event_logi(VERBOSE, "Scan initChunk for PRSCTP parameter: len %u", vlp_totalLength);

    curs = 0;
    init_string =  &((SCTP_init *)chunks[initCID])->variableParams[0];

    while (curs < vlp_totalLength) {
        ack_string =  &((SCTP_init *)chunks[initAckCID])->variableParams[writeCursor[initAckCID]];
        vl_initPtr = (SCTP_vlparam_header *) & init_string[curs];
        pType =  ntohs(vl_initPtr->param_type);
        pLen  =  ntohs(vl_initPtr->param_length);

        if (pLen < 4) return -1; /* peer error - ignore - should send an error notification */

        event_logiii(VERBOSE, "Scan variable parameters: Got type %u, len: %u, position %u",pType, pLen, curs);

        if (pType == VLPARAM_PRSCTP) {
            /* ha, we got one ! */

            if (pLen == 4) result = 0; /* peer supports it, but doesn't send anything unreliably  */
            if (pLen > 4)  result = 1; /* peer supports it, and does send some */
            memcpy(ack_string, vl_initPtr, pLen);
            writeCursor[initAckCID] += pLen;
        }
        curs += pLen;
        while ((curs % 4) != 0) curs++;
    }
    return result;
}

int ch_enterADDIP(ChunkID initAckID, ChunkID initCID)
{
    return 0;
}



int ch_enterSetPrimary(ChunkID initAckID, ChunkID initCID)
{
    return 0;

}



/* ch_enterCookieVLP adds the variable length cookie param to an initAck */
int
ch_enterCookieVLP(ChunkID initCID, ChunkID initAckID,
                  SCTP_init_fixed * init_fixed,
                  SCTP_init_fixed * initAck_fixed,
                  guint32 cookieLifetime,
                  guint32 local_tie_tag,
                  guint32 peer_tie_tag,
                  union sockunion local_Addresses[],
                  guint16 num_local_Addresses,
                  union sockunion peer_Addresses[], guint16 num_peer_Addresses)
{
    SCTP_cookie_param *cookie;
    unsigned short wCurs;
    int result, count;
    guint16 no_local_ipv4_addresses = 0;
    guint16 no_remote_ipv4_addresses = 0;
    guint16 no_local_ipv6_addresses = 0;
    guint16 no_remote_ipv6_addresses = 0;

    if (chunks[initAckID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return -1;
    }

    if (chunks[initAckID]->chunk_header.chunk_id == CHUNK_INIT_ACK) {
        if (chunkCompleted[initAckID]) {
            error_log(ERROR_MAJOR, "ch_enterCookieVLP: chunk already completed");
            return -1;
        }

        /* enter fixed length params into cookie (which is variable part of initAck) */
        cookie = (SCTP_cookie_param *)
            & ((SCTP_init *) chunks[initAckID])->variableParams[writeCursor[initAckID]];
        cookie->vlparam_header.param_type = htons(VLPARAM_COOKIE);

        /* these contain the CURRENT tags ! */
        cookie->ck.z_side_initAck = *initAck_fixed;
        cookie->ck.a_side_init = *init_fixed;

        cookie->ck.local_tie_tag = htonl(local_tie_tag);
        cookie->ck.peer_tie_tag  = htonl(peer_tie_tag);

        cookie->ck.src_port = mdi_readLastFromPort();
        cookie->ck.dest_port = mdi_readLastDestPort();

        for (count = 0; count <  num_local_Addresses; count++) {
            switch(sockunion_family(&(local_Addresses[count]))) {
                case AF_INET :
                    no_local_ipv4_addresses++;

                    break;
#ifdef HAVE_IPV6
                case AF_INET6 :
                    no_local_ipv6_addresses++;
                    break;
#endif
                default :
                    error_log(ERROR_MAJOR, "ch_enterCookieVLP: Address Type Error !");
                    break;
            }
        }
        for (count = 0; count <  num_peer_Addresses; count++) {
            switch(sockunion_family(&(peer_Addresses[count]))) {
                case AF_INET :
                    no_remote_ipv4_addresses++;

                    break;
#ifdef HAVE_IPV6
                case AF_INET6 :
                    no_remote_ipv6_addresses++;
                    break;
#endif
                default :
                    error_log(ERROR_MAJOR, "ch_enterCookieVLP: Address Type Error !");
                    break;
            }

        }
        cookie->ck.no_local_ipv4_addresses  = htons(no_local_ipv4_addresses);
        cookie->ck.no_remote_ipv4_addresses = htons(no_remote_ipv4_addresses);

        /* TODO : IPv6 Fixes */

        cookie->ck.no_local_ipv6_addresses  = htons(no_local_ipv6_addresses);
        cookie->ck.no_remote_ipv6_addresses = htons(no_remote_ipv6_addresses);

        wCurs = writeCursor[initAckID];

        writeCursor[initAckID] += sizeof(SCTP_cookie_param);

        event_logii(VERBOSE, "Building Cookie with %u local, %u peer addresses",
                    num_local_Addresses, num_peer_Addresses);

        ch_enterIPaddresses(initAckID, local_Addresses, num_local_Addresses);
        ch_enterIPaddresses(initAckID, peer_Addresses, num_peer_Addresses);

        /* add peers PRSCTP field to COOKIE parameter */
        result = ch_enterPRSCTPfromInit(initAckID, initCID);

        /* check if endpoint is ADD-IP capable, store result, and put HIS chunk in cookie */
        if (ch_enterADDIP(initAckID, initCID) > 0) {
            /* check for set primary chunk ? Maybe add this only after Cookie Chunk ! */
            ch_enterSetPrimary(initAckID, initCID);
        }

        cookie->vlparam_header.param_length = htons((unsigned short)(writeCursor[initAckID] - wCurs));

        cookie->ck.sendingTime    = pm_getTime();
        cookie->ck.cookieLifetime = cookieLifetime;

        cookie->ck.hmac[0] = 0;
        cookie->ck.hmac[1] = 0;
        cookie->ck.hmac[2] = 0;
        cookie->ck.hmac[3] = 0;

        while ((writeCursor[initAckID] % 4) != 0) writeCursor[initAckID]++;

        signCookie((unsigned char *) &(cookie->ck.z_side_initAck),
                            (unsigned short)(ntohs(cookie->vlparam_header.param_length) - 4), cookie->ck.hmac);

        ch_enterECNchunk(initAckID, initCID);
        event_logi(VERBOSE, "ch_enterCookieVLP: PRSCTP support: %d", result);

        /* if both support PRSCTP, enter our PRSCTP parameter to INIT ACK chunk */
        if ((result >= 0) && (mdi_supportsPRSCTP() == TRUE)){
            ch_addParameterToInitChunk(initAckID, VLPARAM_PRSCTP, 0, NULL);
        }

    } else {
        error_log(ERROR_MAJOR, "ch_enterCookieVLP: chunk type not initAck");
    }

    return 0;
}

/*
 * return -1 if we have to stop processing the data because of an unknown parameter
 * and do not return anything to the peer.
 * return 1 when we send back error, but stop chunk parsing
 * return 0 if normal processing
 */
int ch_enterUnrecognizedParameters(ChunkID initCID, ChunkID AckCID, unsigned int supportedAddressTypes)
{
    SCTP_vlparam_header *vl_initPtr = NULL;
    guint16 curs;
    guint16 pType;
    guint16 pLen;
    guint16 vlp_totalLength;
    gboolean with_ipv4=FALSE, with_ipv6=FALSE;
    unsigned char* init_string;
    unsigned char* ack_string;

    if (chunks[initCID] == NULL) {
        error_log(ERROR_FATAL, "Invalid init chunk ID");
        return -1;
    }
    if (chunks[AckCID] == NULL) {
        error_log(ERROR_FATAL, "Invalid init ack chunk ID");
        return -1;
    }
    /* scan init chunk for unrecognized parameters ! */
    if ((supportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV4) == 0)
        with_ipv4 = FALSE;
    else

        with_ipv4 = TRUE;

    if ((supportedAddressTypes & SUPPORT_ADDRESS_TYPE_IPV6) == 0)
        with_ipv6 = FALSE;
    else
        with_ipv6 = TRUE;

    vlp_totalLength = ((SCTP_init *)chunks[initCID])->chunk_header.chunk_length -
                    sizeof(SCTP_chunk_header) - sizeof(SCTP_init_fixed);

    event_logiii(VERBOSE, "Scan initk for Errors -- supported types = %u, IPv4: %s, IPv6: %s",
            supportedAddressTypes, (with_ipv4 == TRUE)?"TRUE":"FALSE", (with_ipv6 == TRUE)?"TRUE":"FALSE");

    curs = 0;
    init_string =  &((SCTP_init *)chunks[initCID])->variableParams[0];

    while (curs < vlp_totalLength) {

        ack_string =  &((SCTP_init *)chunks[AckCID])->variableParams[writeCursor[AckCID]];
        vl_initPtr = (SCTP_vlparam_header *) & init_string[curs];
        pType = ntohs(vl_initPtr->param_type);
        pLen  = ntohs(vl_initPtr->param_length);

        if (pLen < 4)  return -1;

        event_logiii(VERBOSE, "Scan variable parameters: type %u, len: %u, position %u",pType, pLen, curs);

        if (pType == VLPARAM_COOKIE_PRESERV ||
            pType == VLPARAM_SUPPORTED_ADDR_TYPES ||
            pType == VLPARAM_IPV4_ADDRESS ||
            pType == VLPARAM_IPV6_ADDRESS ||
            pType == VLPARAM_PRSCTP) {

            curs += pLen;
            /* take care of padding */
            while ((curs % 4) != 0) curs++;
        } else if (pType == VLPARAM_HOST_NAME_ADDR) {
            scu_abort(ECC_UNRESOLVABLE_ADDRESS, pLen, (unsigned char*)vl_initPtr);
            return -1;
        } else {
            event_logii(VERBOSE, "found unknown parameter type %u len %u in message", pType, pLen);

            if (STOP_PARAM_PROCESSING(pType)) return 1;

            if (STOP_PARAM_PROCESSING_WITH_ERROR(pType)){

                ch_addUnrecognizedParameter(ack_string, AckCID, pLen, (unsigned char*)vl_initPtr);
                return 1;
            }
            if (SKIP_PARAM_WITH_ERROR(pType)) {
                ch_addUnrecognizedParameter(ack_string, AckCID, pLen, (unsigned char*)vl_initPtr);
            }
            /* finally: simple SKIP_PARAM ! */
            curs += pLen;
            /* take care of padding */
            while ((curs % 4) != 0) curs++;

        }
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------------------*/
int ch_enterUnrecognizedErrors(ChunkID initAckID,
                               unsigned int supportedTypes,
                               ChunkID *errorchunk,
                               union sockunion* preferredDest,
                               gboolean* destSet,
                               gboolean* peerSupportsIPV4,
                               gboolean* peerSupportsIPV6,
                               gboolean* peerSupportsPRSCTP,
                               gboolean* peerSupportsADDIP)
{
    SCTP_vlparam_header *vl_ackPtr = NULL;
    SCTP_vlparam_header *vl_optionsPtr = NULL;
    ChunkID cid = 0;

    guint16 curs;
    guint16 pType, oType;
    guint16 pLen;
    guint16 vlp_totalLength;
    gboolean with_ipv4 = FALSE, with_ipv6=FALSE;
    SCTP_ip_address* address = NULL;
    unsigned char* ack_string;
    int result;

    *peerSupportsPRSCTP = FALSE;
    *peerSupportsADDIP = FALSE;

    /* this is the default */
    *peerSupportsIPV4 = TRUE;
    *peerSupportsIPV6 = TRUE;

    if (chunks[initAckID] == NULL) {
        error_log(ERROR_FATAL, "Invalid init ack chunk ID");
    }
    if (errorchunk == NULL) {
        error_log(ERROR_FATAL, "Null pointer in ch_enterUnrecognizedErrors()");
    }
    *destSet = FALSE;
    /* scan init chunk for unrecognized parameters ! */

    if ((supportedTypes & SUPPORT_ADDRESS_TYPE_IPV4) == 0)
        with_ipv4 = FALSE;
    else
        with_ipv4 = TRUE;

    if ((supportedTypes & SUPPORT_ADDRESS_TYPE_IPV6) == 0)
        with_ipv6 = FALSE;
    else
        with_ipv6 = TRUE;

    event_logiii(VERBOSE, "Scan initAck for Errors supported types = %u, IPv4: %s, IPv6: %s",
            supportedTypes, (with_ipv4 == TRUE)?"TRUE":"FALSE", (with_ipv6 == TRUE)?"TRUE":"FALSE");

    vlp_totalLength = ((SCTP_init *)chunks[initAckID])->chunk_header.chunk_length -
                    sizeof(SCTP_chunk_header) - sizeof(SCTP_init_fixed);

    curs = 0;
    ack_string =  &((SCTP_init *)chunks[initAckID])->variableParams[0];

    while (curs < vlp_totalLength) {
        vl_ackPtr = (SCTP_vlparam_header *) & ack_string[curs];

        pType = ntohs(vl_ackPtr->param_type);
        pLen =   ntohs(vl_ackPtr->param_length);
        event_logiii(VERBOSE, "Scan variable parameters: type %u, len: %u, position %u",pType, pLen, curs);

        if (pLen < 4) return -1;

        if (pType == VLPARAM_COOKIE_PRESERV || pType == VLPARAM_COOKIE ||
            pType == VLPARAM_SUPPORTED_ADDR_TYPES) {

            curs += pLen;

            /* take care of padding */
            while ((curs % 4) != 0) curs++;

        } else if (pType == VLPARAM_UNRECOGNIZED_PARAM) {
            vl_optionsPtr = (SCTP_vlparam_header *) & ack_string[curs+sizeof(SCTP_vlparam_header)];
            oType = ntohs(vl_optionsPtr->param_type);

            if (oType ==  VLPARAM_PRSCTP) {
                *peerSupportsPRSCTP = FALSE;
                curs += pLen;
                /* take care of padding */
                while ((curs % 4) != 0) curs++;
            } else if (oType ==  VLPARAM_ADDIP) {
                *peerSupportsADDIP = FALSE;
                curs += pLen;
                /* take care of padding */
                while ((curs % 4) != 0) curs++;

            } else if (oType == VLPARAM_IPV4_ADDRESS) {
                *peerSupportsIPV4 = FALSE;
                curs += pLen;
                /* take care of padding */
                while ((curs % 4) != 0) curs++;
            } else if (oType == VLPARAM_IPV6_ADDRESS) {
                *peerSupportsIPV6 = FALSE;
                curs += pLen;
                /* take care of padding */
                while ((curs % 4) != 0) curs++;
            } else { /* this is an unknown unknwon parameter....very strange...ignore it */
          /* this is probably a bakeoff test.... :-)   */
                curs += pLen;
                /* take care of padding */
                while ((curs % 4) != 0) curs++;
                event_logi(EXTERNAL_EVENT, "Encountered Unrecognized Param %u: stop parsing and return: stop !", oType);
            }
        } else if (pType == VLPARAM_IPV4_ADDRESS) {
            if (with_ipv4 != TRUE) {
                if (cid == 0)
                    cid = ch_makeErrorChunk();
                ch_enterErrorCauseData(cid, ECC_UNRESOLVABLE_ADDRESS,pLen,(unsigned char*)vl_ackPtr);

            }
            curs += pLen;
            /* take care of padding */

            while ((curs % 4) != 0) curs++;
        } else if (pType == VLPARAM_IPV6_ADDRESS) {
            if (with_ipv6 != TRUE) {
                if (cid == 0)
                    cid = ch_makeErrorChunk();
                ch_enterErrorCauseData(cid, ECC_UNRESOLVABLE_ADDRESS,pLen,(unsigned char*)vl_ackPtr);

            }
            curs += pLen;
            /* take care of padding */
            while ((curs % 4) != 0) curs++;

        } else if (pType == VLPARAM_SET_PRIMARY) {
            result = retrieveVLParamFromString(VLPARAM_IPV4_ADDRESS, (guchar*)vl_ackPtr, pLen);
            if (result < 0) {
#ifdef HAVE_IPV6
                result = retrieveVLParamFromString(VLPARAM_IPV6_ADDRESS, (guchar*)vl_ackPtr, pLen);
                if (result < 0) {
                    if (cid == 0) cid = ch_makeErrorChunk();
                    ch_enterErrorCauseData(cid, ECC_UNRECOGNIZED_PARAMS, pLen,(unsigned char*)vl_ackPtr);
                    curs += pLen;
                    /* take care of padding */
                    while ((curs % 4) != 0) curs++;
                    continue;
                } else {
                    event_logi(VERBOSE, "Found an IPv6 Address parameter at offset %i",result);
                    *destSet = TRUE;
                    /* we got an IPv6 address */
                    address = (SCTP_ip_address *) &ack_string[curs+sizeof(SCTP_vlparam_header)];
                    preferredDest->sa.sa_family = AF_INET6;
                    preferredDest->sin6.sin6_port = htons(0);
                    preferredDest->sin6.sin6_flowinfo = htonl(0);
#ifdef HAVE_SIN6_SCOPE_ID
                    preferredDest->sin6.sin6_scope_id = htonl(0);
#endif
                    memcpy(&preferredDest->sin6.sin6_addr.s6_addr,
                           address->dest_addr.sctp_ipv6, sizeof(struct in6_addr));
                    /* FIXME: check if we got the correct address ! */
                }
#else
                if (cid == 0) cid = ch_makeErrorChunk();
                ch_enterErrorCauseData(cid, ECC_UNRECOGNIZED_PARAMS, pLen,(unsigned char*)vl_ackPtr);
                curs += pLen;
                /* take care of padding */
                while ((curs % 4) != 0) curs++;
                continue;
#endif
            } else {
                *destSet = TRUE;
                /* we got an IPv4 address */
                address = (SCTP_ip_address *) &ack_string[curs+sizeof(SCTP_vlparam_header)];
                preferredDest->sa.sa_family = AF_INET;
                preferredDest->sin.sin_port = 0;
                preferredDest->sin.sin_addr.s_addr = address->dest_addr.sctp_ipv4;
                /* FIXME: check if we got the correct address ! */
            }
            curs += pLen;
            /* take care of padding */
            while ((curs % 4) != 0) curs++;

        } else if (pType == VLPARAM_PRSCTP) {
            event_log(EXTERNAL_EVENT, "found PRSCTP parameter - skipping it !");
            *peerSupportsPRSCTP = TRUE;
            curs += pLen;
            /* take care of padding */
            while ((curs % 4) != 0) curs++;
            continue;
        } else if (pType == VLPARAM_ADDIP) {
            event_log(EXTERNAL_EVENT, "found ADDIP parameter - skipping it !");
            *peerSupportsADDIP = TRUE;
            if (cid == 0) cid = ch_makeErrorChunk();
            ch_enterErrorCauseData(cid, ECC_UNRECOGNIZED_PARAMS, pLen,(unsigned char*)vl_ackPtr);
            curs += pLen;
            /* take care of padding */
            while ((curs % 4) != 0) curs++;
            continue;
        } else {
            event_logii(VERBOSE, "found unknown parameter type %u len %u in message",pType,pLen);

            if (STOP_PARAM_PROCESSING(pType)) {
                *errorchunk = cid;
                event_log(EXTERNAL_EVENT, "Encountered STOP Param: Stop Parsing and return !");
                return -1;
            }

            if (STOP_PARAM_PROCESSING_WITH_ERROR(pType)){
                 if (cid == 0) cid = ch_makeErrorChunk();
                 ch_enterErrorCauseData(cid,VLPARAM_UNRECOGNIZED_PARAM ,pLen,(unsigned char*)vl_ackPtr);
                 *errorchunk = cid;
                 return 1;
            }
            if (SKIP_PARAM_WITH_ERROR(pType)) {
                if (cid == 0) cid = ch_makeErrorChunk();
                ch_enterErrorCauseData(cid,VLPARAM_UNRECOGNIZED_PARAM ,pLen,(unsigned char*)vl_ackPtr);
            }
            /* finally: simple SKIP_PARAM ! */
            curs += pLen;
            /* take care of padding */
            while ((curs % 4) != 0) curs++;
        }
    }
    *errorchunk = cid;
    event_logi(EXTERNAL_EVENT, "Processed InitAck Chunk: error chunk : %u", cid);
    return 0;
}


/* ch_initiateTag reads the initiate tag from an init or initAck */
unsigned int ch_initiateTag(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");

        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        return ntohl(((SCTP_init *) chunks[chunkID])->init_fixed.init_tag);
    } else {
        error_log(ERROR_MAJOR, "ch_initiateTag: chunk type not init or initAck");
        return 0;

    }
}



/* ch_receiverWindow reads the remote receiver window from an init or initAck */
unsigned int ch_receiverWindow(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        return ntohl(((SCTP_init *) chunks[chunkID])->init_fixed.rwnd);
    } else {
        error_log(ERROR_MAJOR, "ch_receiverWindow: chunk type not init or initAck");
        return 0;
    }
}



/* ch_initialTSN reads the initial TSN from an init or initAck */
unsigned int ch_initialTSN(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        return ntohl(((SCTP_init *) chunks[chunkID])->init_fixed.initial_tsn);
    } else {
        error_log(ERROR_MAJOR, "ch_initialTSN: chunk type not init or initAck");
        return 0;
    }
}



/* ch_noOutStreams reads the number of output streams from an init or initAck */
unsigned short ch_noOutStreams(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        return ntohs(((SCTP_init *) chunks[chunkID])->init_fixed.outbound_streams);
    } else {
        error_log(ERROR_MAJOR, "ch_noOutStreams: chunk type not init or initAck");
        return 0;
    }
}



/* ch_noInStreams reads the number of input streams from an init or initAck */
unsigned short ch_noInStreams(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        return ntohs(((SCTP_init *) chunks[chunkID])->init_fixed.inbound_streams);
    } else {
        error_log(ERROR_MAJOR, "ch_noInStreams: chunk type not init or initAck");
        return 0;
    }
}


/**
 *  ch_cookieLifeTime returns the suggested cookie lifespan increment if a cookie
 *  preservative is present in a init chunk.
 */
unsigned int ch_cookieLifeTime(ChunkID chunkID)
{
    gint32 vl_param_curs;
    guint16 vl_param_total_length;
    SCTP_cookie_preservative *preserv;


    if (chunks[chunkID] == NULL) {

        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        vl_param_total_length =
            ((SCTP_init *) chunks[chunkID])->chunk_header.chunk_length -
            sizeof(SCTP_chunk_header) - sizeof(SCTP_init_fixed);

        vl_param_curs = retrieveVLParamFromString(VLPARAM_COOKIE_PRESERV, &((SCTP_init *)
                                                                            chunks
                                                                            [chunkID])->
                                                  variableParams[0], vl_param_total_length);
        if (vl_param_curs >= 0) {
            /* found cookie preservative */
            preserv = (SCTP_cookie_preservative *) & ((SCTP_init *)
                                                      chunks[chunkID])->variableParams[vl_param_curs];
            return (ntohl(preserv->cookieLifetimeInc) + sci_getCookieLifeTime());
        } else {
            return sci_getCookieLifeTime();
        }
    } else {
        error_log(ERROR_MAJOR, "ch_cookieLifeTime: chunk type not init");
        return 0;
    }
}

/**
 *  ch_getSupportedAddressTypes() processes a INIT or INIT-ACK chunk and
 *  returns a value that indicates, which address types are supported by the peer.
 */
unsigned int ch_getSupportedAddressTypes(ChunkID chunkID)
{
    gint32 vl_param_curs;
    guint16 vl_param_total_length, pos=0, num=0, pLen = 0;
    SCTP_supported_addresstypes *param = NULL;

    guint32 result=0;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if ((chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) ||
        (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK)) {
        vl_param_total_length =
            ((SCTP_init *) chunks[chunkID])->chunk_header.chunk_length -
            sizeof(SCTP_chunk_header) - sizeof(SCTP_init_fixed);

        vl_param_curs = retrieveVLParamFromString(VLPARAM_SUPPORTED_ADDR_TYPES, &((SCTP_init *)
                                                  chunks[chunkID])->variableParams[0], vl_param_total_length);

        if (vl_param_curs >= 0) {
            /* found supported address types parameter */
            param = (SCTP_supported_addresstypes*)
                        &((SCTP_init *)chunks[chunkID])->variableParams[vl_param_curs];

            pLen = ntohs(param->vlparam_header.param_length);

            if (pLen < 4 || pLen > 12) return result;

            while(pos < pLen) {
                if (ntohs(param->address_type[num]) == VLPARAM_IPV4_ADDRESS)
                    result |= SUPPORT_ADDRESS_TYPE_IPV4;
                else if (ntohs(param->address_type[num]) == VLPARAM_IPV6_ADDRESS)
                    result |= SUPPORT_ADDRESS_TYPE_IPV6;
                else if (ntohs(param->address_type[num]) == VLPARAM_HOST_NAME_ADDR)
                    result |= SUPPORT_ADDRESS_TYPE_DNS;


                num++;
                pos += sizeof(guint16);
            }
            return result;
        }
        return (SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6 | SUPPORT_ADDRESS_TYPE_DNS);
    } else {
        error_log(ERROR_MAJOR, "ch_getSupportedAddressTypes(): Wrong chunk type !");
        return 0;
    }
}



/* ch_IPaddresses reads the IP-addresses from an init or initAck */
int ch_IPaddresses(ChunkID chunkID, unsigned int mySupportedTypes, union sockunion addresses[],
                    unsigned int *supportedTypes, union sockunion* lastSource)
{
    int noOfAddresses;

    short vl_param_total_length;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        vl_param_total_length =
            ((SCTP_init *) chunks[chunkID])->chunk_header.chunk_length -
            sizeof(SCTP_chunk_header) - sizeof(SCTP_init_fixed);

        /* retrieve addresses from initAck */
        noOfAddresses = setIPAddresses(&((SCTP_init *)chunks[chunkID])->variableParams[0],
                                                      vl_param_total_length, addresses, supportedTypes,
                                                      mySupportedTypes, lastSource, TRUE, FALSE);
        event_logii(VERBOSE, "Found %d addresses in %s chunk !", noOfAddresses,
                    ((chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) ? "INIT" : "INIT ACK"));

        return noOfAddresses;
    } else {
        error_log(ERROR_MINOR, "ch_IPaddresses: chunk type not init or initAck");
        return 0;
    }
}



/*
 * ch_cookieParam reads the cookie variable length parameter from an initAck
 */
SCTP_cookie_param *ch_cookieParam(ChunkID chunkID)
{
    short vl_param_curs;
    short vl_param_total_length;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return NULL;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK) {
        vl_param_total_length =
            ((SCTP_init *) chunks[chunkID])->chunk_header.chunk_length -
            sizeof(SCTP_chunk_header) - sizeof(SCTP_init_fixed);

        vl_param_curs = retrieveVLParamFromString(VLPARAM_COOKIE,
                                                  &((SCTP_init *)chunks[chunkID])->variableParams[0],
                                                  vl_param_total_length);
        if (vl_param_curs >= 0) {
            /* found cookie */
            return (SCTP_cookie_param *) & ((SCTP_init *)chunks[chunkID])->variableParams[vl_param_curs];
        } else {
            /* ignore initAck message, init timer will abort */
            error_log(ERROR_MAJOR, "initAck without cookie received, message discarded");
            return NULL;
        }
    } else {
        error_log(ERROR_MINOR, "ch_cookieParam: chunk type not init or initAck");
        return NULL;
    }
}



/* ch_initFixed reads the fixed part of an init or initAck as complete structure */
SCTP_init_fixed *ch_initFixed(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return NULL;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT_ACK ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_INIT) {
        return &((SCTP_init *) chunks[chunkID])->init_fixed;
    } else {
        error_log(ERROR_MAJOR, "ch_noInStreams: chunk type not init or initAck");
        return NULL;
    }
}



/****** create and read from cookie chunk *********************************************************/

/**
 * ch_makeCookie creates a cookie chunk.
 */
ChunkID ch_makeCookie(SCTP_cookie_param * cookieParam)
{
    SCTP_cookie_echo *cookieChunk;

    /* create cookie chunk */
    cookieChunk = (SCTP_cookie_echo *) malloc(sizeof(SCTP_cookie_echo));

    if (cookieChunk == NULL) {
        error_log(ERROR_MAJOR, "Malloc Failed in ch_makeCookie, returning -1 !");
        return -1;
    }
    if (cookieParam == NULL) {
        error_log(ERROR_MAJOR, "ch_makeCookie: NULL parameter passed (InitAck without Cookie ???");
        free(cookieChunk);
        return -1;
    }

    memset(cookieChunk, 0, sizeof(SCTP_cookie_echo));

    cookieChunk->chunk_header.chunk_id = CHUNK_COOKIE_ECHO;
    cookieChunk->chunk_header.chunk_flags = 0x00;
    cookieChunk->chunk_header.chunk_length = ntohs(cookieParam->vlparam_header.param_length);

    enterChunk((SCTP_simple_chunk *) cookieChunk, "created cookieChunk %u ");


    /*  copy cookie parameter EXcluding param-header into chunk            */
    /*  z_side_initAck is the first struct/data part in our cookie         */

    memcpy(&(cookieChunk->cookie), &(cookieParam->ck.z_side_initAck),
           ntohs(cookieParam->vlparam_header.param_length) - sizeof(SCTP_vlparam_header));

    while ((writeCursor[freeChunkID] % 4) != 0) writeCursor[freeChunkID]++;

    return freeChunkID;
}


/*
 * ch_cookieInitFixed creates an init chunk from the fixed part of an init contained in a cookie
 *  and returns its chunkID
 */
ChunkID ch_cookieInitFixed(ChunkID chunkID)
{
    SCTP_init *initChunk;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    /* creat init chunk from init data< in cookie */
    initChunk = (SCTP_init *) malloc(sizeof(SCTP_init));
    if (initChunk == NULL)
        error_log_sys(ERROR_FATAL, (short)errno);

    memset(initChunk, 0, sizeof(SCTP_init));

    /* enter fixed part of init */
    initChunk->chunk_header.chunk_id = CHUNK_INIT;
    initChunk->chunk_header.chunk_flags = 0x00;
    initChunk->chunk_header.chunk_length = sizeof(SCTP_chunk_header) + sizeof(SCTP_init_fixed);
    initChunk->init_fixed = ((SCTP_cookie_echo *) chunks[chunkID])->cookie.a_side_init;

    enterChunk((SCTP_simple_chunk *) initChunk, "created initChunk from cookie %u ");

    return freeChunkID;
}



/* ch_cookieInitAckFixed creates an initAck chunk from the fixed part of an initAck contained in a
   cookie and returns its chunkID */
ChunkID ch_cookieInitAckFixed(ChunkID chunkID)
{
    SCTP_init *initAckChunk;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    /* creat initAck chunk from init data in cookie */
    initAckChunk = (SCTP_init *) malloc(sizeof(SCTP_init));
    if (initAckChunk == NULL)
        error_log_sys(ERROR_FATAL, (short)errno);

    memset(initAckChunk, 0, sizeof(SCTP_init));

    /* enter fixed part of init */
    initAckChunk->chunk_header.chunk_id = CHUNK_INIT_ACK;
    initAckChunk->chunk_header.chunk_flags = 0x00;
    initAckChunk->chunk_header.chunk_length = sizeof(SCTP_chunk_header) + sizeof(SCTP_init_fixed);
    initAckChunk->init_fixed = ((SCTP_cookie_echo *) chunks[chunkID])->cookie.z_side_initAck;

    enterChunk((SCTP_simple_chunk *) initAckChunk, "created initAckChunk %u  from cookie");

    return freeChunkID;
}



/* ch_cookieIPaddresses reads the IP-addresses from a cookie */
int ch_cookieIPDestAddresses(ChunkID chunkID, unsigned int mySupportedTypes,
                             union sockunion addresses[],
                             unsigned int *peerSupportedAddressTypes,
                             union sockunion* lastSource)
{
    int nAddresses;
    int vl_param_total_length;
    guint16 no_loc_ipv4_addresses, no_remote_ipv4_addresses;
    guint16 no_loc_ipv6_addresses, no_remote_ipv6_addresses;

    union sockunion temp_addresses[MAX_NUM_ADDRESSES];

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_COOKIE_ECHO) {
        no_loc_ipv4_addresses =
            ntohs(((SCTP_cookie_echo *) chunks[chunkID])->cookie.no_local_ipv4_addresses);
        no_remote_ipv4_addresses =
            ntohs(((SCTP_cookie_echo *) chunks[chunkID])->cookie.no_remote_ipv4_addresses);
        no_loc_ipv6_addresses =
            ntohs(((SCTP_cookie_echo *) chunks[chunkID])->cookie.no_local_ipv6_addresses);
        no_remote_ipv6_addresses =
            ntohs(((SCTP_cookie_echo *) chunks[chunkID])->cookie.no_remote_ipv6_addresses);

        vl_param_total_length =
            ((SCTP_cookie_echo *) chunks[chunkID])->chunk_header.chunk_length -
            COOKIE_FIXED_LENGTH - sizeof(SCTP_chunk_header);

        event_logi(VVERBOSE, " Computed total length of vparams : %d", vl_param_total_length);
        event_logii(VVERBOSE, " Num of local/remote IPv4 addresses %u / %u",
                    no_loc_ipv4_addresses, no_remote_ipv4_addresses);
        event_logii(VVERBOSE, " Num of local/remote IPv6 addresses %u / %u",
                    no_loc_ipv6_addresses, no_remote_ipv6_addresses);

        /* retrieve destination addresses from cookie */
        /* TODO: FIX this    vl_param_total_length parameter, so that later addresses are not
           retrieved as well ! */
        nAddresses = setIPAddresses(&((SCTP_cookie_echo *)chunks[chunkID])->vlparams[0],
                                                   (guint16)vl_param_total_length, temp_addresses,
                                                   peerSupportedAddressTypes, mySupportedTypes,
                                                   lastSource, FALSE, TRUE);
        if (nAddresses !=
            no_loc_ipv4_addresses + no_remote_ipv4_addresses +
            no_loc_ipv6_addresses + no_remote_ipv6_addresses) {
            error_log(ERROR_FATAL, "Found more or less addresses than should be in the cookie !");
        }

        memcpy(addresses, &temp_addresses[no_loc_ipv4_addresses],
               no_remote_ipv4_addresses * sizeof(union sockunion));

        if (no_remote_ipv6_addresses != 0)
            memcpy(&addresses[no_remote_ipv4_addresses],
                   &temp_addresses[no_loc_ipv4_addresses +
                                   no_remote_ipv4_addresses +
                                   no_loc_ipv6_addresses],
                   no_remote_ipv6_addresses * sizeof(union sockunion));


        return (no_remote_ipv4_addresses+no_remote_ipv6_addresses);
    } else {
        error_log(ERROR_MAJOR, "ch_cookieIPaddresses: chunk type not cookie");
        return 0;
    }
}



/* ch_staleCookie checks if this is a stale cookie and returns 0 if not and lifetime
   in msecs if it is. */
unsigned int ch_staleCookie(ChunkID chunkID)
{
    SCTP_cookie_echo *cookie_echo_chunk;
    SCTP_our_cookie *cookie_param;
    unsigned int lifetime;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return FALSE;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_COOKIE_ECHO) {
        cookie_echo_chunk = (SCTP_cookie_echo *) chunks[chunkID];
        cookie_param = &(cookie_echo_chunk->cookie);
        lifetime = pm_getTime() - cookie_param->sendingTime;
        event_logi(INTERNAL_EVENT_0, "ch_staleCookie: lifetime = %u msecs", lifetime);

        if (lifetime > cookie_param->cookieLifetime) {
            return lifetime;
        } else
            return 0;
    } else {
        error_log(ERROR_MAJOR, "ch_staleCookie: chunk type not cookie");
        return FALSE;
    }
}

/**
 * function reads local tie tag from a received cookie echo chunk
 */
guint32 ch_CookieLocalTieTag(ChunkID chunkID)
{

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_COOKIE_ECHO) {
        return (ntohl(((SCTP_cookie_echo *) chunks[chunkID])->cookie.local_tie_tag));
    } else {
        error_log(ERROR_MAJOR, "ch_CookieLocalTieTag : Not a CookieEcho chunk !");
        return 0;
    }
}

/**
 * function reads peer tie tag from a received cookie echo chunk
 */
guint32 ch_CookiePeerTieTag(ChunkID chunkID)
{

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_COOKIE_ECHO) {
        return (ntohl(((SCTP_cookie_echo *) chunks[chunkID])->cookie.peer_tie_tag));
    } else {
        error_log(ERROR_MAJOR, "ch_CookiePeerTieTag : Not a CookieEcho chunk !");
        return 0;
    }
}

/**
 * function reads local port from a received cookie echo chunk
 */
guint16 ch_CookieSrcPort(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_COOKIE_ECHO) {
        return (ntohs(((SCTP_cookie_echo *) chunks[chunkID])->cookie.src_port));
    } else {
        error_log(ERROR_MAJOR, "ch_CookieLocalPort : Not a CookieEcho chunk !");
        return 0;
    }
}

/**
 * function reads local port from a received cookie echo chunk
 */
guint16 ch_CookieDestPort(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_COOKIE_ECHO) {
        return (ntohs(((SCTP_cookie_echo *) chunks[chunkID])->cookie.dest_port));
    } else {
        error_log(ERROR_MAJOR, "ch_CookieLocalPort : Not a CookieEcho chunk !");
        return 0;
    }
}



/**
 *    check if this is a good cookie, i.e. verify HMAC signature
 *      @return TRUE when signature is correct, else false (-1,1)
 */
boolean ch_goodCookie(ChunkID chunkID)
{
    SCTP_cookie_echo *cookie_chunk;
    SCTP_our_cookie *cookie;
    guchar cookieSignature[HMAC_LEN];
    guchar ourSignature[HMAC_LEN];
    guint16 chunklen;
    guint32 i;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return FALSE;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_COOKIE_ECHO) {
        /* this is a bit messy -- should do some cleanups here */
        cookie_chunk = (SCTP_cookie_echo *) chunks[chunkID];
        cookie = &(cookie_chunk->cookie);
        /* store HMAC */
        memcpy(cookieSignature, cookie->hmac, HMAC_LEN);

        chunklen = cookie_chunk->chunk_header.chunk_length - sizeof(SCTP_chunk_header);
        event_logi(VVERBOSE, "Got Cookie with %u bytes (incl. vlparam_header)! ", chunklen);

        signCookie((unsigned char *) cookie, chunklen, ourSignature);

        event_log(VVERBOSE, "Transmitted MD5 signature (in order to verify) : ");
        for (i = 0; i < 4; i++) {
            event_logiiii(VERBOSE, "%2.2x %2.2x %2.2x %2.2x",
                          cookieSignature[i * 4], cookieSignature[i * 4 + 1],
                          cookieSignature[i * 4 + 2], cookieSignature[i * 4 + 3]);
        }

        return (memcmp(cookieSignature, ourSignature, HMAC_LEN));

    } else {
        error_log(ERROR_MAJOR, "ch_goodCookie: chunk type not cookie");
        return FALSE;
    }
}



/****** create and read from heartbeat chunk ******************************************************/

/**
 * ch_makeHeartbeat creates a heartbeatchunk.
 */
ChunkID ch_makeHeartbeat(unsigned int sendingTime, unsigned int pathID)
{

    SCTP_heartbeat *heartbeatChunk;
    unsigned char * key;
    int i;
    MD5_CTX ctx;

    /* creat Heartbeat chunk */
    heartbeatChunk = (SCTP_heartbeat *) malloc(sizeof(SCTP_simple_chunk));
    if (heartbeatChunk == NULL)
        error_log_sys(ERROR_FATAL, (short)errno);

    memset(heartbeatChunk, 0, sizeof(SCTP_simple_chunk));

    heartbeatChunk->chunk_header.chunk_id = CHUNK_HBREQ;
    heartbeatChunk->chunk_header.chunk_flags = 0;
    heartbeatChunk->chunk_header.chunk_length = sizeof(SCTP_heartbeat);
    heartbeatChunk->HB_Info.param_type = htons(VLPARAM_HB_INFO);
    heartbeatChunk->HB_Info.param_length = htons(sizeof(SCTP_heartbeat) - 4);
    heartbeatChunk->pathID = htonl((unsigned int) pathID);
    heartbeatChunk->sendingTime = htonl(sendingTime);

    key =  key_operation(KEY_READ);
    if (key == NULL) abort();
    memset(heartbeatChunk->hmac, 0, HMAC_LEN);

    MD5Init(&ctx);
    MD5Update(&ctx,(unsigned char*)(&heartbeatChunk->HB_Info) , sizeof(SCTP_heartbeat)-sizeof(SCTP_chunk_header));
    MD5Update(&ctx, key, SECRET_KEYSIZE);
    MD5Final(heartbeatChunk->hmac, &ctx);

    for (i = 0; i < 4; i++) {
        event_logiiii(VERBOSE, "%2.2x %2.2x %2.2x %2.2x",
                      heartbeatChunk->hmac[i * 4], heartbeatChunk->hmac[i * 4 + 1],
                      heartbeatChunk->hmac[i * 4 + 2], heartbeatChunk->hmac[i * 4 + 3]);
    }

    enterChunk((SCTP_simple_chunk *) heartbeatChunk, "created heartbeatChunk %u ");

    return freeChunkID;
}

/**
 * ch_verifyHeartbeat checks the signature of the received heartbeat.
 * @return TRUE, if HB signature was okay, else FALSE
 */
gboolean ch_verifyHeartbeat(ChunkID chunkID)
{
    guchar hbSignature[HMAC_LEN];
    gboolean res = FALSE;
    int i;

    SCTP_heartbeat *heartbeatChunk;
    unsigned char * key;

    MD5_CTX ctx;


    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return FALSE;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_HBACK) {
        heartbeatChunk =  (SCTP_heartbeat *)chunks[chunkID];
        key =  key_operation(KEY_READ);
        if (key == NULL) abort();
        /* store HMAC */
        memcpy(hbSignature, heartbeatChunk->hmac, HMAC_LEN);

        event_log(VERBOSE, "Got signature: ");

        for (i = 0; i < 4; i++) {
            event_logiiii(VERBOSE, "%2.2x %2.2x %2.2x %2.2x",
                      heartbeatChunk->hmac[i * 4], heartbeatChunk->hmac[i * 4 + 1],
                      heartbeatChunk->hmac[i * 4 + 2], heartbeatChunk->hmac[i * 4 + 3]);
        }

        memset(heartbeatChunk->hmac, 0, HMAC_LEN);

        MD5Init(&ctx);
        MD5Update(&ctx,(unsigned char*)(&heartbeatChunk->HB_Info), sizeof(SCTP_heartbeat)-sizeof(SCTP_chunk_header));
        MD5Update(&ctx, key, SECRET_KEYSIZE);
        MD5Final(heartbeatChunk->hmac, &ctx);

        event_log(VERBOSE, "Computed signature: ");

        for (i = 0; i < 4; i++) {
            event_logiiii(VERBOSE, "%2.2x %2.2x %2.2x %2.2x",
                      heartbeatChunk->hmac[i * 4], heartbeatChunk->hmac[i * 4 + 1],
                      heartbeatChunk->hmac[i * 4 + 2], heartbeatChunk->hmac[i * 4 + 3]);
        }
        if (memcmp(hbSignature, heartbeatChunk->hmac, HMAC_LEN) == 0) res = TRUE;
        else res = FALSE;

        return res;

    } else {
        error_log(ERROR_MINOR, "ch_verifyHeartbeat: chunk type not okay");
        return FALSE;
    }

}

/* ch_HBsendingTime reads the sending time of a heartbeat.
*/
unsigned int ch_HBsendingTime(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_HBREQ ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_HBACK) {
        return ntohl(((SCTP_heartbeat *) chunks[chunkID])->sendingTime);
    } else {
        error_log(ERROR_MINOR, "ch_HBsendingTime: chunk type not heartbeat or heartbeatAck");
        return 0;
    }
}



/* ch_HBpathID reads the path heartbeat on which the heartbeat was sent.
*/
unsigned int ch_HBpathID(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_HBREQ ||
        chunks[chunkID]->chunk_header.chunk_id == CHUNK_HBACK) {
        return ntohl(((SCTP_heartbeat *) chunks[chunkID])->pathID);
    } else {
        error_log(ERROR_MINOR, "ch_HBsendingTime: chunk type not heartbeat or heartbeatAck");
        return 0;
    }
}



/***** create simple chunk **********************************************************************/

/* ch_makeSimpleChunk creates a simple chunk. It can be used for parameterless chunks like
   abort, cookieAck and shutdownAck. It can also be used for chunks that have only variable
   length parameters like the error chunks
*/
ChunkID ch_makeSimpleChunk(unsigned char chunkType, unsigned char flag)
{
    SCTP_simple_chunk *simpleChunk;

    /* creat simple chunk (used for abort, shutdownAck and cookieAck) */
    simpleChunk = (SCTP_simple_chunk *) malloc(sizeof(SCTP_simple_chunk));
    if (simpleChunk == NULL)
        error_log_sys(ERROR_FATAL, (short)errno);

    memset(simpleChunk, 0, sizeof(SCTP_simple_chunk));

    simpleChunk->chunk_header.chunk_id = chunkType;
    simpleChunk->chunk_header.chunk_flags = flag;
    simpleChunk->chunk_header.chunk_length = 0x0004;

    enterChunk(simpleChunk, "created simpleChunk %u ");

    return freeChunkID;
}



/***** write to and read from error chunk *******************************************************/
/* ch_makeErrorChunk makes an error chunk */
ChunkID
ch_makeErrorChunk(void)
{
    SCTP_error_chunk *errorChunk;

    /* creat init chunk */
    errorChunk = (SCTP_error_chunk *) malloc(sizeof(SCTP_error_chunk));

    if (errorChunk == NULL) error_log_sys(ERROR_FATAL, (short)errno);

    memset(errorChunk, 0, sizeof(SCTP_error_chunk));

    /* enter fixed part of init */
    errorChunk->chunk_header.chunk_id = CHUNK_ERROR;
    errorChunk->chunk_header.chunk_flags = 0x00;
    errorChunk->chunk_header.chunk_length = sizeof(SCTP_chunk_header);

    enterChunk((SCTP_simple_chunk *) errorChunk, "created errorChunk %u ");

    return freeChunkID;
}

void
ch_addUnrecognizedParameter(unsigned char* pos, ChunkID cid,
                            unsigned short length, unsigned char* data)

{
    SCTP_error_cause * ec;

    if (pos == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
    }
    ec = (SCTP_error_cause*) pos;
    ec->cause_code = htons(VLPARAM_UNRECOGNIZED_PARAM);
    ec->cause_length = htons((unsigned short)(length+2*sizeof(unsigned short)));
    if (length > 0) {
        memcpy(&ec->cause_information, data, length);
    }
    writeCursor[cid] += (length + 2*sizeof(unsigned short));
    while ((writeCursor[cid] % 4) != 0) writeCursor[cid]++;
}




void
ch_addParameterToInitChunk(ChunkID initChunkID, unsigned short pCode,
                           unsigned short dataLength, unsigned char* data)
{
    SCTP_UnrecognizedParams *vlPtr = NULL;
    unsigned short index;

    if (chunks[initChunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return;
    }
    if (chunkCompleted[initChunkID]) {
        error_log(ERROR_MAJOR, " ch_addParameterToInit : chunk already completed");
        return;
    }
    index = writeCursor[initChunkID];
    vlPtr = (SCTP_UnrecognizedParams*) &(chunks[initChunkID]->simple_chunk_data[sizeof(SCTP_init_fixed)+index]);

    vlPtr->vlparam_header.param_type = htons(pCode);
    vlPtr->vlparam_header.param_length = htons((unsigned short)(dataLength+sizeof(SCTP_vlparam_header)));
    if (dataLength>0) memcpy(vlPtr->the_params, data, dataLength);
    writeCursor[initChunkID] += (dataLength + 2*sizeof(unsigned short));
    while ((writeCursor[initChunkID] % 4) != 0) writeCursor[initChunkID]++;

}


void
ch_enterErrorCauseData(ChunkID chunkID, unsigned short code,
                       unsigned short length, unsigned char* data)
{
    SCTP_error_cause * ec;
    unsigned short index;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return;
    }
    if (chunkCompleted[chunkID]) {
        error_log(ERROR_MAJOR, " ch_enterErrorCauseData : chunk already completed");
        return;
    }
    if (chunks[chunkID]->chunk_header.chunk_id != CHUNK_ERROR && chunks[chunkID]->chunk_header.chunk_id != CHUNK_ABORT) {
        error_log(ERROR_MAJOR, " ch_enterErrorCauseData : Wrong chunk type");
        return;
    }
    index = writeCursor[chunkID];
    ec = (SCTP_error_cause*) &(chunks[chunkID]->simple_chunk_data[index]);
    ec->cause_code = htons(code);
    ec->cause_length = htons((unsigned short)(length+2*sizeof(unsigned short)));
    if (length > 0) {
        memcpy(&ec->cause_information, data, length);
    }
    writeCursor[chunkID] += (length + 2*sizeof(unsigned short));
    while ((writeCursor[chunkID] % 4) != 0) writeCursor[chunkID]++;

}

/* enters the staleness of a cookie into an error chunk. */
void ch_enterStaleCookieError(ChunkID chunkID, unsigned int staleness)
{
    SCTP_staleCookieError *staleCE;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_ERROR) {
        if (chunkCompleted[chunkID]) {
            error_log(ERROR_MAJOR, "ch_enterStaleCookieError: chunk already completed");
            return;
        }


        staleCE =
            (SCTP_staleCookieError *) & chunks[chunkID]->simple_chunk_data[writeCursor[chunkID]];

        staleCE->vlparam_header.param_type = htons(ECC_STALE_COOKIE_ERROR);
        staleCE->vlparam_header.param_length =
            htons((unsigned short) sizeof(SCTP_staleCookieError));
        staleCE->staleness = htonl(staleness);

        writeCursor[chunkID] += (unsigned short) sizeof(SCTP_staleCookieError);

        while ((writeCursor[chunkID] % 4) != 0) writeCursor[chunkID]++;

    } else {
        error_log(ERROR_MAJOR, "ch_enterStaleCookieError: chunk type not error");
    }

    return;
}




/* reads the staleness of a cookie from an error chunk. */
unsigned int ch_stalenessOfCookieError(ChunkID chunkID)
{
    short vl_param_curs;
    short vl_param_total_length;
    SCTP_staleCookieError *staleCE;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_ERROR) {
        vl_param_total_length =
            ((SCTP_simple_chunk *) chunks[chunkID])->chunk_header.chunk_length -
            sizeof(SCTP_chunk_header);

        vl_param_curs = retrieveVLParamFromString(ECC_STALE_COOKIE_ERROR, &((SCTP_simple_chunk *)
                                                                            chunks
                                                                            [chunkID])->

                                                  simple_chunk_data[0], vl_param_total_length);

        if (vl_param_curs >= 0) {
            /* found cookie staleness of cookie */
            staleCE = (SCTP_staleCookieError *) & chunks[chunkID]->simple_chunk_data[vl_param_curs];
            return ntohl(staleCE->staleness);
        } else {
            /* return 0, no effect on cookie lifetime */
            error_log(ERROR_MAJOR,
                      "ch_stalenessOfCookieError: error chunk does not contain a cookie stalenes");
            return 0;
        }
    } else {
        error_log(ERROR_MAJOR, "ch_stalenessOfCookieError: chunk type not error");
        return 0;
    }
}


/***** create and read from shutdown chunk ******************************************************/


/* Creates a shutdown chunk.
*/
ChunkID ch_makeShutdown(unsigned int _cummTSNacked)
{
    SCTP_simple_chunk *shutdown_chunk;
    unsigned int *cummTSNacked;

    /* creat Shutdown chunk */
    shutdown_chunk = (SCTP_simple_chunk *) malloc(sizeof(SCTP_simple_chunk));
    if (shutdown_chunk == NULL)
        error_log_sys(ERROR_FATAL, (short)errno);

    memset(shutdown_chunk, 0, sizeof(SCTP_simple_chunk));

    shutdown_chunk->chunk_header.chunk_id = CHUNK_SHUTDOWN;
    shutdown_chunk->chunk_header.chunk_flags = 0x00;
    shutdown_chunk->chunk_header.chunk_length = 0x0008;
    cummTSNacked = (unsigned int *) (&(shutdown_chunk->simple_chunk_data[0]));
    *cummTSNacked = htonl(_cummTSNacked);

    enterChunk(shutdown_chunk, "created shutdown_chunk %u ");

    return freeChunkID;
}




/* reads the cummulative TSN acked from a shutdown chunk.
*/
unsigned int ch_cummulativeTSNacked(ChunkID chunkID)
{
    unsigned int *cummTSNacked;

    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    if (chunks[chunkID]->chunk_header.chunk_id == CHUNK_SHUTDOWN) {
        cummTSNacked =
            (unsigned int *) (&((SCTP_simple_chunk *) chunks[chunkID])->simple_chunk_data[0]);
        return ntohl(*cummTSNacked);
    } else {
        error_log(ERROR_MAJOR, "ch_cummulativeTSNacked: chunk type not init or initAck");
        return 0;
    }
}



/****** read from, make and delete generic chunk **************************************************/

/* reads the chunks type of a chunk.
*/
unsigned char ch_chunkType(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    return chunks[chunkID]->chunk_header.chunk_id;
}



/* reads the chunks length of a chunks.
*/
unsigned short ch_chunkLength(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return 0;
    }

    return chunks[chunkID]->chunk_header.chunk_length;
}



/* returns a pointer to the beginning of a simple chunk.
*/
SCTP_simple_chunk *ch_chunkString(ChunkID chunkID)
{
    if (chunks[chunkID] == NULL) {
        error_log(ERROR_MAJOR, "Invalid chunk ID");
        return NULL;
    }

    chunks[chunkID]->chunk_header.chunk_length =
        htons((unsigned short)(chunks[chunkID]->chunk_header.chunk_length + writeCursor[chunkID]));
    chunkCompleted[chunkID] = TRUE;

    return chunks[chunkID];
}



/*
 * swaps length INSIDE the packet !!!!!!!!!!! Phew ! and puts chunk pointer
 * into the current array of chunks -- does not need ch_deleteChunk !!
 */
ChunkID ch_makeChunk(SCTP_simple_chunk * chunk)
{

    /*
     * swaps length INSIDE the packet !!!!!!!!!!! Phew ! and enters chunk
     * into the current list
     */
    chunk->chunk_header.chunk_length = ntohs(chunk->chunk_header.chunk_length);

    enterChunk(chunk, "created chunk from string %u ");

    return freeChunkID;
}


/* ch_deleteChunk removes the chunk from the array of chunks and frees the
   memory allocated for that chunk.
*/
void ch_deleteChunk(ChunkID chunkID)
{
    unsigned int cid;

    cid = chunkID;

    if (chunks[chunkID] != NULL) {
        event_logi(INTERNAL_EVENT_0, "freed chunk %u", cid);
        free(chunks[chunkID]);
        chunks[chunkID] = NULL;
    } else {
        error_log(ERROR_MAJOR, "chunk already freed");
    }
}



/* ch_forgetChunk removes the chunk from the array of chunks without freeing the
   memory allocated for that chunk.
   This is used in the following cases:
   - the caller wants to keep the chunk for retransmissions.
   - the chunk was created with ch_makeChunk and the pointer to the chunk points
     into an SCTP-message, which was allocated as a whole. In this case the chunk
     can not be freed here.
*/
void ch_forgetChunk(ChunkID chunkID)
{
    unsigned int cid;

    cid = chunkID;

    if (chunks[chunkID] != NULL) {
        chunks[chunkID] = NULL;
        event_logi(INTERNAL_EVENT_0, "forgot chunk %u", cid);
    } else {
        error_log(ERROR_MAJOR, "chunk already forgotten");
    }
}
