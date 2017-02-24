/* $Id: distribution.c 2771 2013-05-30 09:09:07Z dreibh $
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include  "sctp.h"              /* ULP-interface definitions */
#include  "distribution.h"      /* SCTP-internal interfaces to message distribution */
#include  "adaptation.h"        /* interfaces to adaptation layer */
#include  "bundling.h"          /* interfaces to bundling */
#include  "SCTP-control.h"      /* interfaces to SCTP-control */
#include  "auxiliary.h"
#include  "streamengine.h"      /* interfaces to streamengine */
#include  "flowcontrol.h"       /* interfaces to flowcontrol */
#include  "recvctrl.h"          /* interfaces to receive-controller */
#include  "chunkHandler.h"

#include  <sys/types.h>
#include  <errno.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include  <arpa/inet.h>         /* for inet_ntoa() under both SOLARIS/LINUX */
#endif

#ifndef IN_EXPERIMENTAL
#define	IN_EXPERIMENTAL(a)	((((int) (a)) & 0xf0000000) == 0xf0000000)
#endif

#ifndef IN_BADCLASS
#define	IN_BADCLASS(a)		IN_EXPERIMENTAL((a))
#endif


/*------------------------ Default Definitions --------------------------------------------------*/
static int      myRWND                      = 0x7FFF;
static union    sockunion *myAddressList    = NULL;
static unsigned int myNumberOfAddresses     = 0;
static gboolean sendAbortForOOTB            = TRUE;
static int      checksumAlgorithm           = SCTP_CHECKSUM_ALGORITHM_CRC32C;
static gboolean librarySupportsPRSCTP         = TRUE;
static gboolean supportADDIP                = FALSE;
/*------------------------Structure Definitions --------------------------------------------------*/

/**
 * This struct stores data of SCTP-instances.
 * Each SCTP-instances is related to one port and to
 * one SCTP adaption-layer. This may change soon !
 */
typedef struct SCTPINSTANCE
{
    /*@{ */
    /** The name of this SCTP-instance, used as key. */
    unsigned short sctpInstanceName;
    /** The local port of this instance, or zero for don't cares.
        Once assigned this should not be changed !   */
    unsigned short localPort;
    guint16 noOfLocalAddresses;
    union sockunion *localAddressList;
    unsigned char* localAddressStrings;
    gboolean    has_INADDR_ANY_set;
    gboolean    has_IN6ADDR_ANY_set;
    gboolean    uses_IPv4;
    gboolean    uses_IPv6;
    /** set of callback functions that were registered by the ULP */
    SCTP_ulpCallbacks ULPcallbackFunctions;
    /** maximum number of incoming streams that this instance will take */
    unsigned short noOfInStreams;
    /** maximum number of outgoingng streams that this instance will take */
    unsigned short noOfOutStreams;
    /** here follow default parameters for instance initialization */
    unsigned int default_rtoInitial;
    unsigned int default_validCookieLife;
    unsigned int default_assocMaxRetransmits;
    unsigned int default_pathMaxRetransmits;
    unsigned int default_maxInitRetransmits;
    unsigned int default_myRwnd;
    unsigned int default_delay;
    unsigned char default_ipTos;
    unsigned int default_rtoMin;
    unsigned int default_rtoMax;
    unsigned int default_maxSendQueue;
    unsigned int default_maxRecvQueue;
    unsigned int default_maxBurst;
    unsigned int supportedAddressTypes;
    gboolean    supportsPRSCTP;
    gboolean    supportsADDIP;
   /*@}*/
}
SCTP_instance;


/**
 * This struct contains all data of an association. As far as other modules must know elements
 * of this struct, read functions are provided. No other module has write access to this structure.
 */
typedef struct ASSOCIATION
{
    /*@{*/
    /** The current ID of this association,
        it is used as a key to find a association in the list,
        and never changes in the  live of the association  */
    unsigned int assocId;
    /** The local tag of this association. */
    unsigned int tagLocal;
    /** The tag of remote side of this association */
    unsigned int tagRemote;
    /** Pointer to the SCTP-instance this association
        belongs to. It is equal to the wellknown port
        number of the ULP that uses this instance. */
    SCTP_instance*  sctpInstance;
    /** the local port number of this association. */
    unsigned short localPort;
    /** the remote port number of this association. */
    unsigned short remotePort;
    /** number of destination networks (paths) */
    short noOfNetworks;
    /** array of destination addresses */
    union sockunion *destinationAddresses;
    /** number of own addresses */
    unsigned int noOfLocalAddresses;
    /** array of local addresses */
    union sockunion *localAddresses;
    /** pointer to flowcontrol structure */
    void *flowControl;
    /** pointer to reliable-transfer structure */
    void *reliableTransfer;
    /** pointer to receive-control structure */
    void *rx_control;
    /** pointer to stream structure */
    void *streamengine;
    /** pointer to pathmanagement structure */
    void *pathMan;
    /** pointer to bundling structure */
    void *bundling;
    /** pointer to SCTP-control */
    void *sctp_control;
    /** marks an association for deletion */
    boolean deleted;
    /** transparent pointer to some upper layer data */
    void * ulp_dataptr;
    /** IP TOS value per association */
    unsigned char ipTos;
    unsigned int supportedAddressTypes;
    unsigned int maxSendQueue;
    unsigned int maxRecvQueue;
    gboolean    had_INADDR_ANY_set;
    gboolean    had_IN6ADDR_ANY_set;
    /* do I support the SCTP extensions ? */
    gboolean    supportsPRSCTP;
    gboolean    supportsADDIP;
    /* and these values for our peer */
    gboolean    peerSupportsPRSCTP;
    gboolean    peerSupportsADDIP;
    /*@}*/
} Association;


/******************** Declarations ****************************************************************/
static gboolean sctpLibraryInitialized = FALSE;
/*
    Keyed list of SCTP-instances with the instanceName as key
*/
/**
 * Keyed list of associations with the association-ID as key
 */
static GList* AssociationList = NULL;

/**
 * Whenever an external event (ULP-call, socket-event or timer-event) this variable must
 * contain the addressed sctp instance.
 * This pointer must be reset to null after the event  has been handled.
 */
static SCTP_instance *sctpInstance;

/**
 * Keyed list of SCTP instances with the instance name as key
 */
static GList* InstanceList = NULL;
static unsigned int ipv4_users = 0;
#ifdef HAVE_IPV6
    static unsigned int ipv6_users = 0;
#endif
/**
 * Whenever an external event (ULP-call, socket-event or timer-event) this variable must
 * contain the addressed association.
 * Read functions for 'global data' read data from the association pointed to by this pointer.
 * This pointer must be reset to null after the event  has been handled.
 */
static Association *currentAssociation;
static Association tmpAssoc;
static union sockunion tmpAddress;


/* If firstSCTP_instance is true, a seed is generated by
   use of (current time). After the first SCTP-instance was created, firstSCTP_instance
   is set to false.
*/
static unsigned short lastSCTP_instanceName = 1;
/*
   AssociationIDs are counted up, and if a new one is needed, they are checked for wraps
 */
static unsigned int nextAssocId = 1;

/**
   initAck is sent to this address
   In this case, SCTP-control reads this address on reception of the cookie echo
   (which consequently also does not contain an addresslist) to initialize the new association.
 */
static union sockunion *lastFromAddress;
static union sockunion *lastDestAddress;

static short lastFromPath;
static unsigned short lastFromPort;
static unsigned short lastDestPort;
static unsigned int lastInitiateTag;

/**
  Descriptor of socket used by all associations and SCTP-instances.
 */
static gint sctp_socket;

#ifdef HAVE_IPV6
static gint ipv6_sctp_socket;
#endif

/* port management array */
static unsigned char portsSeized[0x10000];
static unsigned int numberOfSeizedPorts;


/* ---------------------- Internal Function Prototypes ------------------------------------------- */
unsigned short mdi_getUnusedInstanceName(void);


/* ------------------------- Function Implementations --------------------------------------------- */

/*------------------- Internal Functions ---------------------------------------------------------*/

#define CHECK_LIBRARY           if(sctpLibraryInitialized == FALSE) return SCTP_LIBRARY_NOT_INITIALIZED
#define ZERO_CHECK_LIBRARY      if(sctpLibraryInitialized == FALSE) return 0

#ifdef LIBRARY_DEBUG
 #define ENTER_LIBRARY(fname)	printf("Entering sctplib  (%s)\n", fname); fflush(stdout);
 #define LEAVE_LIBRARY(fname)	printf("Leaving  sctplib  (%s)\n", fname); fflush(stdout);
 #define ENTER_CALLBACK(fname)	printf("Entering callback (%s)\n", fname); fflush(stdout);
 #define LEAVE_CALLBACK(fname)	printf("Leaving  callback (%s)\n", fname); fflush(stdout);
#else
 #define ENTER_LIBRARY(fname)
 #define LEAVE_LIBRARY(fname)
 #define ENTER_CALLBACK(fname)
 #define LEAVE_CALLBACK(fname)
#endif
/*------------------- Internal LIST Functions ----------------------------------------------------*/



/*
 * return 1 or -1 if instances have different port,
 * return 0 if same ports and one address is in set of second instances addresses
 */
gint CheckForAddressInInstance(gconstpointer a, gconstpointer b)
{
    int acount,bcount;
    gboolean found;
    SCTP_instance* ai = (SCTP_instance*)a;
    SCTP_instance* bi = (SCTP_instance*)b;

    event_logii(VVERBOSE, "DEBUG: CheckForAddressInInstance, comparing instance a port %u, instance b port %u",
        ai->localPort, bi->localPort);

    if (ai->localPort < bi->localPort) return -1;
    else if (ai->localPort > bi->localPort) return 1;

    else {
        /* one has IN(6)ADDR_ANY : return equal ! */
        if (ai->has_IN6ADDR_ANY_set && bi->has_IN6ADDR_ANY_set) return 0;
        if (ai->has_INADDR_ANY_set && bi->has_INADDR_ANY_set) return 0;
        if (ai->has_INADDR_ANY_set && bi->has_IN6ADDR_ANY_set) return 0;
        if (ai->has_IN6ADDR_ANY_set && bi->has_INADDR_ANY_set) return 0;
        if ((ai->has_IN6ADDR_ANY_set || ai->has_INADDR_ANY_set) &&
            !(bi->has_IN6ADDR_ANY_set || bi->has_INADDR_ANY_set)) return 0;
        if (!(ai->has_IN6ADDR_ANY_set || ai->has_INADDR_ANY_set) &&
            (bi->has_IN6ADDR_ANY_set || bi->has_INADDR_ANY_set)) return 0;
        /* both do not have an INADDR_ANY : use code below */
        found = FALSE;
        for (acount = 0; acount < ai->noOfLocalAddresses; acount++) {
            for (bcount = 0; bcount < bi->noOfLocalAddresses; bcount++) {
                /* if addresses are equal: set found TRUE and break; */
                if (adl_equal_address
                    ( &(ai->localAddressList[acount]), &(bi->localAddressList[bcount])) == TRUE) found = TRUE;

                event_logiii(VVERBOSE, "DEBUG: CheckForAddressInInstance, acount %u, bcount %u, found = %s",
                    acount, bcount, (found==TRUE)?"TRUE":"FALSE");

                if (found == TRUE) break;
            }
            if (found == TRUE) break;
        }
        /* if address was not found, it is not in this instance */
        if (found == FALSE) return -1; /* to continue search */
    }
    return 0;

}


gint CompareInstanceNames(gconstpointer a, gconstpointer b)
{
    if ((((SCTP_instance*)a)->sctpInstanceName) < ((SCTP_instance*)b)->sctpInstanceName) return -1;
    else if ((((SCTP_instance*)a)->sctpInstanceName) > ((SCTP_instance*)b)->sctpInstanceName) return 1;
    else return 0;
}


/**
  * Retrieve instance.
  *
  * @param instance_name Instance name.
  * @return SCTP_instance or NULL if not found.
  */
SCTP_instance* retrieveInstance(unsigned short instance_name)
{
    SCTP_instance* instance;
    SCTP_instance  temporary;
    GList*         result = NULL;

    event_logi(INTERNAL_EVENT_0, "retrieving instance %u from list", instance_name);

    temporary.sctpInstanceName = instance_name;
    result = g_list_find_custom(InstanceList, &temporary, &CompareInstanceNames);
    if (result != NULL) {
       instance = (SCTP_instance*)result->data;
    }
    else {
       event_logi(INTERNAL_EVENT_0, "instance %u not in list", instance_name);
       instance = NULL;
    }

    return(instance);
}


/**
 *  compareAssociationIDs compares the association ID's of two associations and returns 0
 *  if they are equal. This is a call back function called by List Functions whenever two
 *  association need to be compared.
 *  @param a  pointer to association struct 1
 *  @param b  pointer to association struct 2
 *  @return    0 if a->assocId equals b->assocId, 1 if bigger, -1 if smaller
 */
gint compareAssociationIDs(gconstpointer a, gconstpointer b)
{
    /* two associations are equal if there local tags (in this implementation also used as
       association ID) are equal. */
    if (((Association*)a)->assocId == ((Association*)b)->assocId)
        return 0;
    else if (((Association*)a)->assocId < ((Association*)b)->assocId)
        return -1;
    else
        return 1;
}



/**
 *  equalAssociations compares two associations and returns 0 if they are equal. In contrast to
 *  function compareAssociationIDs, equal here means the two associations belong to the same
 *  SCTP-instance and have at least one destinationaddress in common.
 *  This is a call back function called by GList-functions whenever two association need to be compared.
 *  @param i1  association data 1
 *  @param i2  association data 2
 *  @return 0 if il1 and il2 are equal according to above definition, 1 else
 */
gint equalAssociations(gconstpointer a, gconstpointer b)
{
    int i,j;

    event_logii(VVERBOSE, "equalAssociations: checking assoc A[id=%d] and assoc B[id=%d]",
        ((Association*)a)->assocId,((Association*)b)->assocId);

    /* two associations are equal if their remote and local ports are equal and at least
       one of their remote addresses are equal. This is like in TCP, where a connection
       is identified by the transport address, i.e. the IP-address and port of the peer. */

    if ( (((Association *)a)->remotePort == ((Association *)b)->remotePort) &&
         (((Association *)a)->localPort == ((Association *)b)->localPort) ){
        for (i = 0; i < ((Association *)a)->noOfNetworks; i++)
            for (j = 0; j < ((Association *)b)->noOfNetworks; j++) {
                event_logii(VVERBOSE, "equalAssociations: checking address A[%d] address B[%d]",i,j);
                if (adl_equal_address
                    (&(((Association *)a)->destinationAddresses[i]),
                     &(((Association *)b)->destinationAddresses[j])) == TRUE) {
                    if ( (((Association *)b)->deleted == FALSE) && (((Association *)a)->deleted == FALSE)) {
                        event_log(VVERBOSE, "equalAssociations: found TWO equal assocs !");
                        return 0;
                    } else {
                        event_log(VVERBOSE, "equalAssociations: found NO equal assocs !");
                        return 1;
                    }
                }
            }
       event_log(VVERBOSE, "equalAssociations: found NO equal assocs !");
       return 1;
    }
    event_log(VVERBOSE, "equalAssociations: found NO equal assocs !");
    return 1;
}


/**
 * retrieveAssociation retrieves a association from the list using the id as key.
 * Returns NULL also if the association is marked "deleted" !
 * @param assocID  association ID
 * @return  pointer to the retrieved association, or NULL
 */
Association *retrieveAssociation(unsigned int assocID)
{
    Association *assoc;
    Association *assocFindP;
    GList* result = NULL;

    event_logi(INTERNAL_EVENT_0, "retrieving association %08x from list", assocID);

    tmpAssoc.assocId = assocID;
    tmpAssoc.deleted = FALSE;
    assocFindP = &tmpAssoc;
    assoc = NULL;

    result = g_list_find_custom(AssociationList, assocFindP, &compareAssociationIDs);
    if (result != NULL) {

        assoc = (Association *)result->data;

        if (assoc->deleted) {
            assoc = NULL;
        }
    } else {
        event_logi(INTERNAL_EVENT_0, "association %08x not in list", assocID);
        assoc = NULL;
    }
    return assoc;
}

/**
 * retrieveAssociationForced retrieves an association from the list using
 * assoc id as key. Returns also associations marked "deleted" !
 * @param assocID  association ID
 * @return  pointer to the retrieved association, or NULL
 */
Association *retrieveAssociationForced(unsigned int assocID)
{
    Association *assoc;
    Association *assocFindP;
    GList* result = NULL;

    event_logi(INTERNAL_EVENT_0, "forced retrieval of association %08x from list", assocID);

    tmpAssoc.assocId = assocID;
    assocFindP = &tmpAssoc;
    assoc = NULL;
    result = g_list_find_custom(AssociationList, assocFindP, &compareAssociationIDs);
    if (result != NULL) {
       assoc = (Association *)result->data;
    } else {
        event_logi(INTERNAL_EVENT_0, "association %08x not in list", assocID);
        assoc = NULL;
    }
    return assoc;
}


/**
 *   retrieveAssociation retrieves a association from the list using the transport address as key.
 *   Returns NULL also if the association is marked "deleted" !
 *   CHECKME : Must return NULL, if no Address-Port combination does not occur in ANY existing assoc.
 *             If it occurs in one of these -> return it
 *
 *   @param  fromAddress address from which data arrived
 *   @param  fromPort SCTP port from which data arrived
 *   @return pointer to the retrieved association, or NULL
 */
Association *retrieveAssociationByTransportAddress(union sockunion * fromAddress,
                                                   unsigned short fromPort,
                                                   unsigned short toPort)
{

    Association *assocr;
    Association *assocp;
    GList* result = NULL;

    tmpAssoc.noOfNetworks = 1;
    tmpAssoc.destinationAddresses = &tmpAddress;

    switch (sockunion_family(fromAddress)) {
    case AF_INET:
        event_logi(INTERNAL_EVENT_0,
                   "Looking for IPv4 Address %x (in NBO)", sock2ip(fromAddress));
        tmpAssoc.destinationAddresses[0].sa.sa_family = AF_INET;
        tmpAssoc.destinationAddresses[0].sin.sin_addr.s_addr = sock2ip(fromAddress);
        tmpAssoc.remotePort = fromPort;
        tmpAssoc.localPort = toPort;
        tmpAssoc.deleted = FALSE;
        break;
#ifdef HAVE_IPV6
    case AF_INET6:
        tmpAssoc.destinationAddresses[0].sa.sa_family = AF_INET6;
        memcpy(&(tmpAssoc.destinationAddresses[0].sin6.sin6_addr.s6_addr),
               (sock2ip6(fromAddress)), sizeof(struct in6_addr));
        event_logi(INTERNAL_EVENT_0, "Looking for IPv6 Address %x, check NTOHX() ! ",
                    tmpAssoc.destinationAddresses[0].sin6.sin6_addr.s6_addr);
        tmpAssoc.remotePort = fromPort;
        tmpAssoc.localPort = toPort;
        tmpAssoc.deleted = FALSE;
        break;
#endif
    default:
        error_logi(ERROR_FATAL,
                   "Unsupported Address Type %d in retrieveAssociationByTransportAddress()",
                   sockunion_family(fromAddress));
        break;

    }

    assocp = &tmpAssoc;

    event_log(INTERNAL_EVENT_0, "retrieving association by transport address from list");

    result = g_list_find_custom(AssociationList, assocp, equalAssociations);

    if (result != NULL){
        assocr = (Association *)result->data;
        if (assocr->deleted) {
            event_logi(VERBOSE, "Found assoc that should be deleted, with id %u",assocr->assocId);
            assocr= NULL;
        }
        if (assocr != NULL)
            event_logi(VERBOSE, "Found valid assoc assoc with id %u",assocr->assocId);
        return assocr;
    } else {
        event_log(INTERNAL_EVENT_0, "association indexed by transport address not in list");
    }
    return NULL;
}



/**
 *  checkForExistingAssociations checks wether a given association is already in the list using
 *  the equality condition given by function equalAssociations.
 *  TODO : this must still be implemented. Where is it used ??????????????
 *
 *  @param assoc_new the association to be compared with the association in the list.
 *  @return      1 if was association found, else  0
 */
static short checkForExistingAssociations(Association * assoc_new)
{
    GList* result = NULL;

    if (AssociationList == NULL) {
        event_logi(VERBOSE, "checkForExistingAssociations(new_assoc = %u) AssocList not set",
            assoc_new->assocId);

        return 0;
    }

    result = g_list_find_custom(AssociationList, assoc_new, equalAssociations);

    if (result) /* then one of addresses of assoc A was in set of addresses of B */
        return 1;
    else
        return 0;
}



/*------------------- Internal port management Functions -----------------------------------------*/

/**
 * allocatePort Allocate a given port.
 * @return Allocated port or 0 if port is occupied.
 */
static unsigned short allocatePort(unsigned short port)
{
   if(portsSeized[port] == 0) {
      portsSeized[port] = 1;
      numberOfSeizedPorts++;
      return(port);
   }
   return(0);
}


/**
 * seizePort return a free port number.
 * @return free port.
 */
static unsigned short seizePort(void)
{
    unsigned short seizePort = 0;

    /* problem: no more available ports ?! */
    if (numberOfSeizedPorts >= 0xFBFF)
        return 0x0000;

    seizePort = (unsigned short)(adl_random() % 0xFFFF);

    while (portsSeized[seizePort] || seizePort < 0x0400) {
        seizePort = (unsigned short)(adl_random() % 0xFFFF);
    }

    numberOfSeizedPorts++;
    portsSeized[seizePort] = 1;

    return seizePort;
}


/**
 * releasePort frees a previously used port.
 * @param portSeized port that is to be freed.
 */
static void releasePort(unsigned short portSeized)
{
    if (portsSeized[portSeized] == 0 || portSeized == 0){
        error_log(ERROR_MINOR, "Warning: release of port that is not seized");
	return;
    }

    numberOfSeizedPorts--;
    portsSeized[portSeized] = 0;
}



/*------------------- Other Internal Functions ---------------------------------------------------*/

/**
 * deleteAssociation removes the association from the list of associations, frees all data allocated
 *  for it and <calls moduleprefix>_delete*(...) function at all modules.
 *  @param assoc  pointer to the association to be deleted.
 */
static void mdi_removeAssociationData(Association * assoc)
{
    if (assoc != NULL) {
        event_logi(INTERNAL_EVENT_0, "Deleting association %08x ", assoc->assocId);

        /* free module data */
        if (assoc->tagRemote != 0) {
            /* association init was already completed */
            if(assoc->flowControl) {
               fc_delete_flowcontrol(assoc->flowControl);
               assoc->flowControl = NULL;
            }
            if(assoc->reliableTransfer) {
               rtx_delete_reltransfer(assoc->reliableTransfer);
               assoc->reliableTransfer = NULL;
            }
            if(assoc->rx_control) {
               rxc_delete_recvctrl(assoc->rx_control);
               assoc->rx_control = NULL;
            }
            if(assoc->streamengine) {
               se_delete_stream_engine(assoc->streamengine);
               assoc->streamengine = NULL;
            }
        }

        pm_deletePathman(assoc->pathMan);
        bu_delete(assoc->bundling);
        sci_deleteSCTP_control(assoc->sctp_control);

        assoc->pathMan = NULL;
        assoc->bundling = NULL;
        assoc->sctp_control = NULL;

        /* free association data */
        free(assoc->destinationAddresses);
        free(assoc->localAddresses);
        assoc->destinationAddresses = NULL;
        assoc->localAddresses = NULL;
        free(assoc);
    } else {
        error_log(ERROR_MAJOR, "mdi_removeAssociationData: association does not exist");
    }

    return;

}                               /* end: mdi_deleteAssociation */


/*
 * after   sctpInstance and  currentAssociation have been set for an
 * incoming packet, this function will return, if a packet may be processed
 * or if it is not destined for this instance
 */
boolean mdi_destination_address_okay(union sockunion * dest_addr)
{
    unsigned int i;
    gboolean found = FALSE;
    gboolean any_set = FALSE;

    /* this case will be specially treated after the call to mdi_destination_address_okay() */
    if (sctpInstance == NULL && currentAssociation == NULL) return TRUE;

    /*
    if (sctpInstance == NULL && currentAssociation == NULL) return FALSE;
    */
    if (currentAssociation != NULL) {
        /* search through the _association_ list */
        /* and accept or decline */
        for (i=0; i< currentAssociation->noOfLocalAddresses; i++) {
            event_logii(VVERBOSE, "mdi_destination_address_okay: Checking addresses Dest %x, local %x",
                sock2ip(dest_addr), sock2ip(&(currentAssociation->localAddresses[i])));
            if(adl_equal_address(dest_addr, &(currentAssociation->localAddresses[i])) == TRUE) {
                found = TRUE;
                break;
            }
        }
        return found;
    } else {
        /* check whether _instance_ has INADDR_ANY */
        if (sctpInstance->has_INADDR_ANY_set == TRUE) {
            any_set = TRUE;
            /* if so, accept */
            switch(sockunion_family(dest_addr)) {
                case AF_INET:
                    return TRUE;
                    break;
#ifdef HAVE_IPV6
                case AF_INET6:
                    return FALSE;
                    break;
#endif
                default:
                    break;

            }
        }
        if (sctpInstance->has_IN6ADDR_ANY_set == TRUE) {
            any_set = TRUE;
            /* if so, accept */
            switch(sockunion_family(dest_addr)) {
                case AF_INET:
                    return TRUE;
                    break;
#ifdef HAVE_IPV6
                case AF_INET6:
                    return TRUE;
                    break;
#endif
                default:
                    break;

            }
        }
        if (any_set == TRUE) return FALSE;
        /* if not, search through the list */
        for (i=0; i< sctpInstance->noOfLocalAddresses; i++) {
            if(adl_equal_address(dest_addr, &(sctpInstance->localAddressList[i])) == TRUE) {
                found = TRUE;
                break;
            }
        }
        /* and accept or decline */
    }
    return found;
}


/*------------------- Functions called by the Unix-Interface -------------------------------------*/
void
mdi_dummy_callback(gint socket_fd,
                   unsigned char *buffer,
                   int bufferLength,
                   unsigned char *hoststring,
                   unsigned short fromAddressLength)
{
    error_log(ERROR_FATAL, "DUMMY CALLBACK should never be EXECUTED !");
}


/**
 *  mdi_receiveMessage is the callback function of the SCTP-message distribution.
 *  It is called by the Unix-interface module when a new datagramm is received.
 *  This function also performs OOTB handling, tag verification etc.
 *  (see also RFC 4960, section 8.5.1.B)  and sends data to the bundling module of
 *  the right association
 *
 *  @param socket_fd          the socket file discriptor
 *  @param buffer             pointer to arrived datagram
 *  @param bufferlength       length of datagramm
 *  @param fromAddress        source address of DG
 *  @param portnum            bogus port number
 */
void
mdi_receiveMessage(gint socket_fd,
                   unsigned char *buffer,
                   int bufferLength,
                   union sockunion * source_addr,
                   union sockunion * dest_addr)
{
    SCTP_message *message;
    SCTP_init_fixed *initChunk = NULL;
    guchar* initPtr = NULL;
    guchar source_addr_string[SCTP_MAX_IP_LEN];
    guchar dest_addr_string[SCTP_MAX_IP_LEN];
    SCTP_vlparam_header* vlptr = NULL;

    union sockunion alternateFromAddress;
    int i = 0;
    unsigned int len, state, chunkArray = 0;
    boolean sourceAddressExists = FALSE;
    boolean sendAbort = FALSE;
    boolean discard = FALSE;
    unsigned int addressType = 0;
    int retval = 0, supportedAddressTypes = 0;

    boolean initFound = FALSE, cookieEchoFound = FALSE, abortFound = FALSE;

    short shutdownCompleteCID;
    short abortCID;

    SCTP_instance temporary;
    GList* result = NULL;

    /* FIXME:  check this out, if it works at all :-D */
    lastFromAddress = source_addr;
    lastDestAddress = dest_addr;

    lastFromPath = 0;

    message = (SCTP_message *) buffer;

    if (!validate_datagram(buffer, bufferLength)) {
        event_log(INTERNAL_EVENT_0, "received corrupted datagramm");
        lastFromAddress = NULL;
        lastDestAddress = NULL;
        return;
    }

    len = bufferLength - sizeof(SCTP_common_header);

    /* save from address for response if a remote address is not available otherwise.
       For instance initAck or cookieAck. */
    lastFromPort = ntohs(message->common_header.src_port);
    lastDestPort = ntohs(message->common_header.dest_port);

    if (lastFromPort == 0 || lastDestPort == 0) {
        error_log(ERROR_MINOR, "received DG with invalid (i.e. 0) ports");
        lastFromAddress = NULL;
        lastDestAddress = NULL;
        lastFromPort = 0;
        lastDestPort = 0;
        return;
    }

    if (sockunion_family(dest_addr) == AF_INET) {
        addressType = SUPPORT_ADDRESS_TYPE_IPV4;
        event_log(VERBOSE, "mdi_receiveMessage: checking for correct IPV4 addresses");
        if (IN_CLASSD(ntohl(dest_addr->sin.sin_addr.s_addr))) discard = TRUE;
        if (IN_EXPERIMENTAL(ntohl(dest_addr->sin.sin_addr.s_addr))) discard = TRUE;
        if (IN_BADCLASS(ntohl(dest_addr->sin.sin_addr.s_addr))) discard = TRUE;
        if (INADDR_ANY == ntohl(dest_addr->sin.sin_addr.s_addr)) discard = TRUE;
        if (INADDR_BROADCAST == ntohl(dest_addr->sin.sin_addr.s_addr)) discard = TRUE;

        if (IN_CLASSD(ntohl(source_addr->sin.sin_addr.s_addr))) discard = TRUE;
        if (IN_EXPERIMENTAL(ntohl(source_addr->sin.sin_addr.s_addr))) discard = TRUE;
        if (IN_BADCLASS(ntohl(source_addr->sin.sin_addr.s_addr))) discard = TRUE;
        if (INADDR_ANY == ntohl(source_addr->sin.sin_addr.s_addr)) discard = TRUE;
        if (INADDR_BROADCAST == ntohl(source_addr->sin.sin_addr.s_addr)) discard = TRUE;

        /*  if ((INADDR_LOOPBACK != ntohl(source_addr->sin.sin_addr.s_addr)) &&
            (source_addr->sin.sin_addr.s_addr == dest_addr->sin.sin_addr.s_addr)) discard = TRUE;
         */

    } else
#ifdef HAVE_IPV6
    if (sockunion_family(dest_addr) == AF_INET6) {
        addressType = SUPPORT_ADDRESS_TYPE_IPV6;
        event_log(VERBOSE, "mdi_receiveMessage: checking for correct IPV6 addresses");
#if defined (LINUX)
        if (IN6_IS_ADDR_UNSPECIFIED(&(dest_addr->sin6.sin6_addr.s6_addr))) discard = TRUE;
        if (IN6_IS_ADDR_MULTICAST(&(dest_addr->sin6.sin6_addr.s6_addr))) discard = TRUE;
        /* if (IN6_IS_ADDR_V4COMPAT(&(dest_addr->sin6.sin6_addr.s6_addr))) discard = TRUE; */

        if (IN6_IS_ADDR_UNSPECIFIED(&(source_addr->sin6.sin6_addr.s6_addr))) discard = TRUE;
        if (IN6_IS_ADDR_MULTICAST(&(source_addr->sin6.sin6_addr.s6_addr))) discard = TRUE;
        /*  if (IN6_IS_ADDR_V4COMPAT(&(source_addr->sin6.sin6_addr.s6_addr))) discard = TRUE; */
        /*
        if ((!IN6_IS_ADDR_LOOPBACK(&(source_addr->sin6.sin6_addr.s6_addr))) &&
            IN6_ARE_ADDR_EQUAL(&(source_addr->sin6.sin6_addr.s6_addr),
                               &(dest_addr->sin6.sin6_addr.s6_addr))) discard = TRUE;
        */
#else
        if (IN6_IS_ADDR_UNSPECIFIED(&(dest_addr->sin6.sin6_addr))) discard = TRUE;
        if (IN6_IS_ADDR_MULTICAST(&(dest_addr->sin6.sin6_addr))) discard = TRUE;
        /* if (IN6_IS_ADDR_V4COMPAT(&(dest_addr->sin6.sin6_addr))) discard = TRUE; */

        if (IN6_IS_ADDR_UNSPECIFIED(&(source_addr->sin6.sin6_addr))) discard = TRUE;
        if (IN6_IS_ADDR_MULTICAST(&(source_addr->sin6.sin6_addr))) discard = TRUE;
        /* if (IN6_IS_ADDR_V4COMPAT(&(source_addr->sin6.sin6_addr))) discard = TRUE; */
        /*
        if ((!IN6_IS_ADDR_LOOPBACK(&(source_addr->sin6.sin6_addr))) &&
             IN6_ARE_ADDR_EQUAL(&(source_addr->sin6.sin6_addr),
                                &(dest_addr->sin6.sin6_addr))) discard = TRUE;
        */
#endif
    } else
#endif
    {
        error_log(ERROR_FATAL, "mdi_receiveMessage: Unsupported AddressType Received !");
        discard = TRUE;
    }
    adl_sockunion2str(source_addr, source_addr_string, SCTP_MAX_IP_LEN);
    adl_sockunion2str(dest_addr, dest_addr_string, SCTP_MAX_IP_LEN);

    event_logiiiii(EXTERNAL_EVENT,
                  "mdi_receiveMessage : len %d, sourceaddress : %s, src_port %u,dest: %s, dest_port %u",
                  bufferLength, source_addr_string, lastFromPort, dest_addr_string,lastDestPort);

    if (discard == TRUE) {
        lastFromAddress = NULL;
        lastDestAddress = NULL;
        lastFromPort = 0;
        lastDestPort = 0;
        sctpInstance = NULL;
        currentAssociation = NULL;
        event_logi(INTERNAL_EVENT_0, "mdi_receiveMessage: discarding packet for incorrect address %s",
                   dest_addr_string);
        return;
    }


    /* Retrieve association from list  */
    currentAssociation = retrieveAssociationByTransportAddress(lastFromAddress, lastFromPort,lastDestPort);

    if (currentAssociation != NULL) {
        /* meaning we MUST have an instance with no fixed port */
        sctpInstance = currentAssociation->sctpInstance;
        supportedAddressTypes = 0;
    } else {
        /* OK - if this packet is for a server, we will find an SCTP instance, that shall
           handle it (i.e. we have the SCTP instance's localPort set and it matches the
           packet's destination port */
        temporary.localPort = lastDestPort;
        temporary.noOfLocalAddresses = 1;
        temporary.has_INADDR_ANY_set = FALSE;
        temporary.has_IN6ADDR_ANY_set = FALSE;
        temporary.localAddressList = dest_addr;
        temporary.supportedAddressTypes = addressType;

        result = g_list_find_custom(InstanceList, &temporary, &CheckForAddressInInstance);

        if (result == NULL) {
            event_logi(VERBOSE, "Couldn't find SCTP Instance for Port %u and Address in List !",lastDestPort);
            /* may be an an association that is a client (with instance port 0) */
            sctpInstance = NULL;
#ifdef HAVE_IPV6
            supportedAddressTypes = SUPPORT_ADDRESS_TYPE_IPV6 | SUPPORT_ADDRESS_TYPE_IPV4;
#else
            supportedAddressTypes = SUPPORT_ADDRESS_TYPE_IPV4;
#endif
        } else {
            sctpInstance = (SCTP_instance*)result->data;
            supportedAddressTypes = sctpInstance->supportedAddressTypes;
            event_logii(VERBOSE, "Found an SCTP Instance for Port %u and Address in the list, types: %d !",
                                lastDestPort, supportedAddressTypes);
        }
    }

    if (mdi_destination_address_okay(dest_addr) == FALSE) {
         event_log(VERBOSE, "mdi_receiveMsg: this packet is not for me, DISCARDING !!!");
         lastFromAddress = NULL;
         lastDestAddress = NULL;
         lastFromPort = 0;
         lastDestPort = 0;
         sctpInstance = NULL;
         currentAssociation = NULL;
         return;
    }

    lastInitiateTag = ntohl(message->common_header.verification_tag);

    chunkArray = rbu_scanPDU(message->sctp_pdu, len);



    if (currentAssociation == NULL) {
        if ((initPtr = rbu_findChunk(message->sctp_pdu, len, CHUNK_INIT)) != NULL) {
            event_log(VERBOSE, "mdi_receiveMsg: Looking for source address in INIT CHUNK");
            retval = 0; i = 1;
            do {
                retval = rbu_findAddress(initPtr, i, &alternateFromAddress, supportedAddressTypes);
                if (retval == 0) {
                    currentAssociation = retrieveAssociationByTransportAddress(&alternateFromAddress,
                                                                               lastFromPort,lastDestPort);
                }
                i++;
            } while (currentAssociation == NULL && retval == 0);
        }
        if ((initPtr = rbu_findChunk(message->sctp_pdu, len, CHUNK_INIT_ACK)) != NULL) {
            event_log(VERBOSE, "mdi_receiveMsg: Looking for source address in INIT_ACK CHUNK");
            retval = 0; i = 1;
            do {
                retval = rbu_findAddress(initPtr, i, &alternateFromAddress, supportedAddressTypes);
                if (retval == 0) {
                    currentAssociation = retrieveAssociationByTransportAddress(&alternateFromAddress,
                                                                               lastFromPort,lastDestPort);
                }
                i++;
            } while (currentAssociation == NULL && retval == 0);
        }
        if (currentAssociation != NULL) {
            event_log(VERBOSE, "mdi_receiveMsg: found association from INIT (ACK) CHUNK");
            sourceAddressExists = TRUE;
        } else {
            event_log(VERBOSE, "mdi_receiveMsg: found NO association from INIT (ACK) CHUNK");
        }
    }

    /* check whether chunk is illegal or not (see section 3.1 of RFC 4960) */
    if ( ((rbu_datagramContains(CHUNK_INIT, chunkArray) == TRUE) && (chunkArray != (1 << CHUNK_INIT))) ||
         ((rbu_datagramContains(CHUNK_INIT_ACK, chunkArray) == TRUE) && (chunkArray != (1 << CHUNK_INIT_ACK))) ||
         ((rbu_datagramContains(CHUNK_SHUTDOWN_COMPLETE, chunkArray) == TRUE) && (chunkArray != (1 << CHUNK_SHUTDOWN_COMPLETE)))
       ){

        error_log(ERROR_MINOR, "mdi_receiveMsg: discarding illegal packet....... :-)");

        /* silently discard */
         lastFromAddress = NULL;
         lastDestAddress = NULL;
         lastFromPort = 0;
         lastDestPort = 0;
         sctpInstance = NULL;
         currentAssociation = NULL;
         return;
    }

    /* check if sctp-message belongs to an existing association */
    if (currentAssociation == NULL) {
         event_log(VVERBOSE, "mdi_receiveMsg: currentAssociation==NULL, start scanning !");
         /* This is not very elegant, but....only used when assoc is being build up, so :-D */
         if (rbu_datagramContains(CHUNK_ABORT, chunkArray) == TRUE) {
            event_log(INTERNAL_EVENT_0, "mdi_receiveMsg: Found ABORT chunk, discarding it !");
            lastFromAddress = NULL;
            lastDestAddress = NULL;
            lastFromPort = 0;
            lastDestPort = 0;
            sctpInstance = NULL;
            currentAssociation = NULL;
            return;
         }
         if (rbu_datagramContains(CHUNK_SHUTDOWN_ACK, chunkArray) == TRUE) {
            event_log(INTERNAL_EVENT_0,
                        "mdi_receiveMsg: Found SHUTDOWN_ACK chunk, send SHUTDOWN_COMPLETE !");
            /* section 8.4.5 : return SHUTDOWN_COMPLETE with peers veri-tag and T-Bit set */
            shutdownCompleteCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_COMPLETE, FLAG_NO_TCB);
            bu_put_Ctrl_Chunk(ch_chunkString(shutdownCompleteCID), NULL);
            bu_unlock_sender(NULL);
            /* should send it to last address */
            bu_sendAllChunks(NULL);
            /* free abort chunk */
            ch_deleteChunk(shutdownCompleteCID);

            /* send an ABORT with peers veri-tag, set T-Bit */
            event_log(VERBOSE, "mdi_receiveMsg: sending CHUNK_SHUTDOWN_COMPLETE  ");
            lastFromPort = 0;
            lastDestPort = 0;
            lastDestAddress = NULL;
            lastFromAddress = NULL;
            sctpInstance = NULL;
            currentAssociation = NULL;
            return;
        }
        if (rbu_datagramContains(CHUNK_SHUTDOWN_COMPLETE, chunkArray) == TRUE) {
            event_log(INTERNAL_EVENT_0,
                     "mdi_receiveMsg: Found SHUTDOWN_COMPLETE chunk, discarding it !");
            lastFromPort = 0;
            lastDestPort = 0;
            lastDestAddress = NULL;
            lastFromAddress = NULL;
            sctpInstance = NULL;
            currentAssociation = NULL;
            return;
        }
        if (rbu_datagramContains(CHUNK_COOKIE_ACK, chunkArray) == TRUE) {
            event_log(INTERNAL_EVENT_0, "mdi_receiveMsg: Found COOKIE_ACK chunk, discarding it !");
            lastFromPort = 0;
            lastDestPort = 0;
            lastDestAddress = NULL;
            lastFromAddress = NULL;
            sctpInstance = NULL;
            currentAssociation = NULL;
            return;
        }

        /* section 8.4.7) : Discard the datagram, if it contains a STALE-COOKIE ERROR */
        if (rbu_scanDatagramForError(message->sctp_pdu, len, ECC_STALE_COOKIE_ERROR) == TRUE) {
            event_log(INTERNAL_EVENT_0,
                          "mdi_receiveMsg: Found STALE COOKIE ERROR, discarding packet !");
            lastFromPort = 0;
            lastDestPort = 0;
            lastDestAddress = NULL;
            lastFromAddress = NULL;
            sctpInstance = NULL;
            currentAssociation = NULL;
            return;
        }

        if ((initPtr = rbu_findChunk(message->sctp_pdu, len, CHUNK_INIT)) != NULL) {
            if (sctpInstance != NULL) {
                if (lastDestPort != sctpInstance->localPort || sctpInstance->localPort == 0) {
                    /* destination port is not the listening port of this this SCTP-instance. */
                    event_log(INTERNAL_EVENT_0,
                              "mdi_receiveMsg: got INIT Message, but dest. port does not fit -> ABORT");
                    sendAbort = TRUE;
                    /* as per section 5.1 :
                       If an endpoint receives an INIT, INIT ACK, or COOKIE ECHO chunk but
                       decides not to establish the new association due to missing mandatory
                       parameters in the received INIT or INIT ACK, invalid parameter values,
                       or lack of local resources, it MUST respond with an ABORT chunk */
                } else {
                     event_log(INTERNAL_EVENT_0, "mdi_receiveMsg: INIT Message - processing it !");
                }
                initChunk = ((SCTP_init_fixed *) & ((SCTP_init *) message->sctp_pdu)->init_fixed);
                lastInitiateTag = ntohl(initChunk->init_tag);
                event_logi(VERBOSE, "setting lastInitiateTag to %x ", lastInitiateTag);

                if ((vlptr = (SCTP_vlparam_header*)rbu_scanInitChunkForParameter(initPtr, VLPARAM_HOST_NAME_ADDR)) != NULL) {
                    sendAbort = TRUE;
                }

            } else {    /* we do not have an instance up listening on that port-> ABORT him */
                event_log(INTERNAL_EVENT_0,
                         "mdi_receiveMsg: got INIT Message, but no instance found -> IGNORE");

                sendAbort = TRUE;
                initChunk = ((SCTP_init_fixed *) & ((SCTP_init *) message->sctp_pdu)->init_fixed);
                lastInitiateTag = ntohl(initChunk->init_tag);
                event_logi(VERBOSE, "setting lastInitiateTag to %x ", lastInitiateTag);
            }

        } else if (rbu_datagramContains(CHUNK_COOKIE_ECHO, chunkArray) == TRUE) {
            if (sctpInstance != NULL) {
                if (lastDestPort != sctpInstance->localPort || sctpInstance->localPort == 0) {
                    /* destination port is not the listening port of this this SCTP-instance. */
                    event_log(INTERNAL_EVENT_0,
                              "mdi_receiveMsg: COOKIE_ECHO ignored, dest. port does not fit");
                    sendAbort = TRUE;
                } else {
                    event_log(INTERNAL_EVENT_0,
                              "mdi_receiveMsg: COOKIE_ECHO Message - processing it !");
                }
            } else { /* sctpInstance == NULL */
                event_log(INTERNAL_EVENT_0,
                         "mdi_receiveMsg: got COOKIE ECHO Message, but no instance found -> IGNORE");
                lastFromPort = 0;
                lastDestPort = 0;
                lastDestAddress = NULL;
                lastFromAddress = NULL;
                sctpInstance = NULL;
                currentAssociation = NULL;
                return;
            }
        } else {
            /* section 8.4.8) send an ABORT with peers veri-tag, set T-Bit */
                event_log(INTERNAL_EVENT_0,
                          "mdi_receiveMsg: send ABORT -> message ignored (OOTB - see section 8.4.8) ");
                sendAbort = TRUE;
        }


    } else { /* i.e. if(currentAssociation != NULL) */

        /* If the association exists, both ports of the message must be equal to the ports
           of the association and the source address must be in the addresslist of the peer
           of this association */
        /* check src- and dest-port and source address */
        if (lastFromPort != currentAssociation->remotePort || lastDestPort != currentAssociation->localPort) {
            error_logiiii(ERROR_FATAL,
                          "port mismatch in received DG (lastFromPort=%u, assoc->remotePort=%u, lastDestPort=%u, assoc->localPort=%u ",   lastFromPort, currentAssociation->remotePort,                          lastDestPort, currentAssociation->localPort);
            currentAssociation = NULL;
            sctpInstance = NULL;
            lastFromAddress = NULL;
            lastDestAddress = NULL;
            lastFromPort = 0;
            lastDestPort = 0;
            return;
        }

        if (sctpInstance == NULL) {
            sctpInstance = currentAssociation->sctpInstance;
            if (sctpInstance == NULL) {
                error_log(ERROR_FATAL, "We have an Association, but no Instance, FIXME !");
            }
        }

        /* check if source address is in address list of this association.
           tbd: check the draft if this is correct. */
        if (sourceAddressExists == FALSE) {
            for (i = 0; i < currentAssociation->noOfNetworks; i++) {
                if (adl_equal_address
                    (&(currentAssociation->destinationAddresses[i]), lastFromAddress) == TRUE) {
                    sourceAddressExists = TRUE;
                    break;
                }
            }
        }

        if (!sourceAddressExists) {
            error_log(ERROR_MINOR,
                      "source address of received DG is not in the destination addresslist");
            currentAssociation = NULL;
            sctpInstance = NULL;
            lastFromPort = 0;
            lastDestPort = 0;
            lastDestAddress = NULL;
            lastFromAddress = NULL;
            return;
        }

        if (sourceAddressExists) lastFromPath = i;

        /* check for verification tag rules --> see section 8.5 */
        if ((initPtr = rbu_findChunk(message->sctp_pdu, len, CHUNK_INIT)) != NULL) {
            /* check that there is ONLY init */
            initFound = TRUE;
            if (lastInitiateTag != 0) {
                currentAssociation = NULL;
                sctpInstance = NULL;
                lastFromPort = 0;
                lastDestPort = 0;
                lastDestAddress = NULL;
                lastFromAddress = NULL;
                event_log(VERBOSE, "mdi_receiveMsg: scan found INIT, lastInitiateTag!=0, returning");
                return;
            }
            initChunk = ((SCTP_init_fixed *) & ((SCTP_init *) message->sctp_pdu)->init_fixed);
            /* make sure, if you send an ABORT later on (i.e. when peer requests 0 streams),
             * you pick the right tag */
            lastInitiateTag = ntohl(initChunk->init_tag);
            event_logi(VVERBOSE, "Got an INIT CHUNK with initiation-tag %u", lastInitiateTag);

            if ((vlptr = (SCTP_vlparam_header*)rbu_scanInitChunkForParameter(initPtr, VLPARAM_HOST_NAME_ADDR)) != NULL) {
                sendAbort = TRUE;
            }
        }
        if (rbu_datagramContains(CHUNK_ABORT, chunkArray) == TRUE) {
            /* accept my-tag or peers tag, else drop packet */
            if ((lastInitiateTag != currentAssociation->tagLocal &&
                 lastInitiateTag != currentAssociation->tagRemote) || initFound == TRUE) {
                currentAssociation = NULL;
                sctpInstance = NULL;
                lastFromPort = 0;
                lastDestPort = 0;
                lastDestAddress = NULL;
                lastFromAddress = NULL;
                return;
            }
            abortFound = TRUE;
        }
        if (rbu_datagramContains(CHUNK_SHUTDOWN_COMPLETE, chunkArray) == TRUE) {
            /* accept my-tag or peers tag, else drop packet */
            /* TODO : make sure that if it is the peer's tag also T-Bit is set */
            if ((lastInitiateTag != currentAssociation->tagLocal &&
                 lastInitiateTag != currentAssociation->tagRemote) || initFound == TRUE) {
                currentAssociation = NULL;
                sctpInstance = NULL;
                lastFromPort = 0;
                lastDestPort = 0;
                lastDestAddress = NULL;
                lastFromAddress = NULL;
                return;
            }
        }
        if (rbu_datagramContains(CHUNK_SHUTDOWN_ACK, chunkArray) == TRUE) {
            if (initFound == TRUE) {
                currentAssociation = NULL;
                sctpInstance = NULL;
                lastFromPort = 0;
                lastDestPort = 0;
                lastDestAddress = NULL;
                lastFromAddress = NULL;
                return;
            }
            state = sci_getState();
            if (state == COOKIE_ECHOED || state == COOKIE_WAIT) {
                /* see also section 8.5.E.) treat this like OOTB packet */
                event_logi(EXTERNAL_EVENT,
                           "mdi_receive_message: shutdownAck in state %u, send SHUTDOWN_COMPLETE ! ",
                           state);
                shutdownCompleteCID = ch_makeSimpleChunk(CHUNK_SHUTDOWN_COMPLETE, FLAG_NO_TCB);
                bu_put_Ctrl_Chunk(ch_chunkString(shutdownCompleteCID),NULL);
                bu_sendAllChunks(NULL);
                ch_deleteChunk(shutdownCompleteCID);
                currentAssociation = NULL;
                sctpInstance = NULL;
                lastFromPort = 0;
                lastDestPort = 0;
                lastDestAddress = NULL;
                lastFromAddress = NULL;
                return;
            }
        }
        if (rbu_datagramContains(CHUNK_COOKIE_ECHO, chunkArray) == TRUE) {
               cookieEchoFound = TRUE;
        }

        if ((initPtr = rbu_findChunk(message->sctp_pdu, len, CHUNK_INIT_ACK)) != NULL) {

            if ((vlptr = (SCTP_vlparam_header*)rbu_scanInitChunkForParameter(initPtr, VLPARAM_HOST_NAME_ADDR)) != NULL) {
                    /* actually, this does not make sense...anyway: kill assoc, and notify user */
                    scu_abort(ECC_UNRECOGNIZED_PARAMS, ntohs(vlptr->param_length), (guchar*)vlptr);
                    currentAssociation = NULL;
                    sctpInstance = NULL;
                    lastFromPort = 0;
                    lastDestPort = 0;
                    lastDestAddress = NULL;
                    lastFromAddress = NULL;
                    return;
            }
        }

        if (!cookieEchoFound && !initFound && !abortFound && lastInitiateTag != currentAssociation->tagLocal) {
            event_logii(EXTERNAL_EVENT,
                        "Tag mismatch in receive DG, received Tag = %u, local Tag = %u -> discarding",
                        lastInitiateTag, currentAssociation->tagLocal);
            currentAssociation = NULL;
            sctpInstance = NULL;
            lastFromPort = 0;
            lastDestPort = 0;
            lastDestAddress = NULL;
            lastFromAddress = NULL;
            return;

        }

    }

    if (sendAbort == TRUE) {
        if (sendAbortForOOTB == FALSE) {
            event_log(VERBOSE, "mdi_receiveMsg: sendAbortForOOTB==FALSE -> Discarding MESSAGE: not sending ABORT");
            lastFromAddress = NULL;
            lastDestAddress = NULL;
            lastFromPort = 0;
            lastDestPort = 0;
            currentAssociation = NULL;
            sctpInstance = NULL;
            /* and discard that packet */
            return;
        }
        /* make and send abort message */
        if (currentAssociation == NULL) {
            abortCID = ch_makeSimpleChunk(CHUNK_ABORT, FLAG_NO_TCB);
        } else {
            abortCID = ch_makeSimpleChunk(CHUNK_ABORT, FLAG_NONE);
        }
        bu_put_Ctrl_Chunk(ch_chunkString(abortCID),NULL);
        /* should send it to last address */
        bu_unlock_sender(NULL);
        bu_sendAllChunks(NULL);
        /* free abort chunk */
        ch_deleteChunk(abortCID);
        /* send an ABORT with peers veri-tag, set T-Bit */
        event_log(VERBOSE, "mdi_receiveMsg: sending ABORT with T-Bit");
        lastFromAddress = NULL;
        lastDestAddress = NULL;
        lastFromPort = 0;
        lastDestPort = 0;
        currentAssociation = NULL;
        sctpInstance = NULL;
        /* and discard that packet */
        return;
    }

    /* forward DG to bundling */
    rbu_rcvDatagram(lastFromPath, message->sctp_pdu, bufferLength - sizeof(SCTP_common_header));

    lastInitiateTag = 0;
    currentAssociation = NULL;
    sctpInstance = NULL;
    lastDestAddress = NULL;
    lastFromAddress = NULL;
    lastFromPath = -1;          /* only valid for functions called via mdi_receiveMessage */

}                               /* end: mdi_receiveMessage */




/*------------------- Functions called by the ULP ------------------------------------------------*/
/*------------------- Prototypes are defined in sctp.h -------------------------------------------*/


/**
 * Function returns coded library version as result. This unsigned integer
 * contains the major version in the upper 16 bits, and the minor version in
 * the lower 16 bits.
 * @return library version, or 0 (i.e. zero) as error !
 */
unsigned int sctp_getLibraryVersion(void)
{
    return (unsigned int)(SCTP_MAJOR_VERSION << 16 | SCTP_MINOR_VERSION);
}

/**
 * Function that needs to be called in advance to all library calls.
 * It initializes all file descriptors etc. and sets up some variables
 * @return 0 for success, 1 for adaptation level error, -9 for already called
 * (i.e. the function has already been called), -2 for insufficient rights.
 */
int sctp_initLibrary(void)
{
    int i, result, sfd = -1, maxMTU=0;
    /* initialize the output of event/error-log functions */
    ENTER_LIBRARY("sctp_initLibrary");
    if (sctpLibraryInitialized == TRUE) {
        LEAVE_LIBRARY("sctp_initLibrary");
        return SCTP_LIBRARY_ALREADY_INITIALIZED;
    }
    read_tracelevels();

#if defined(HAVE_GETEUID)
    /* check privileges. Must be root or setuid-root for now ! */
    if (geteuid() != 0) {
        error_log(ERROR_MAJOR, "You must be root to use the SCTPLIB-functions (or make your program SETUID-root !).");
        LEAVE_LIBRARY("sctp_initLibrary");
        return SCTP_INSUFFICIENT_PRIVILEGES;
    }
#endif


    event_log(EXTERNAL_EVENT, "sctp_initLibrary called");
    result = adl_init_adaptation_layer(&myRWND);

    if (result != 0) {
        LEAVE_LIBRARY("sctp_initLibrary");
        return SCTP_SPECIFIC_FUNCTION_ERROR;
    }

    /* Create list for associations - old, used to be here - now removed ! */

    /* initialize ports seized -- see comments above !!! */
    for (i = 0; i < 0x10000; i++) portsSeized[i] = 0;
    numberOfSeizedPorts = 0x00000000;

    /* initialize bundling, i.e. the common buffer for sending chunks when no association
          exists. */
    bu_init_bundling();

    /* this block is to be executed only once for the lifetime of sctp-software */
    key_operation(KEY_INIT);

    /* we might need to replace this socket !*/
    sfd = adl_get_sctpv4_socket();

    if (adl_gatherLocalAddresses(&myAddressList, (int *)&myNumberOfAddresses,sfd,TRUE,&maxMTU,flag_Default) == FALSE) {
        LEAVE_LIBRARY("sctp_initLibrary");
        return SCTP_SPECIFIC_FUNCTION_ERROR;
    }

    sctpLibraryInitialized = TRUE;
    LEAVE_LIBRARY("sctp_initLibrary");
    return SCTP_SUCCESS;
}


int mdi_updateMyAddressList(void)
{
    int sfd;
    int maxMTU;

    /* we might need to replace this socket !*/
    sfd = adl_get_sctpv4_socket();
    free(myAddressList);

    if (adl_gatherLocalAddresses(&myAddressList, (int *)&myNumberOfAddresses,sfd,TRUE,&maxMTU,flag_Default) == FALSE) {
        return SCTP_SPECIFIC_FUNCTION_ERROR;
    }

    return SCTP_SUCCESS;
}

gboolean mdi_addressListContainsLocalhost(unsigned int noOfAddresses,
                           union sockunion* addressList)
{
    gboolean result = FALSE;
    unsigned int counter;
    unsigned int ii;
    for (ii=0; ii< noOfAddresses; ii++) {
        switch(sockunion_family(&(addressList[ii]))) {
            case AF_INET:
                if (ntohl(sock2ip(&(addressList[ii]))) == INADDR_LOOPBACK) {
                    event_logi(VVERBOSE, "Found IPv4 loopback address ! Num: %u", noOfAddresses);
                    result = TRUE;
                }
                break;
#ifdef HAVE_IPV6
            case AF_INET6:
  #if defined (LINUX)
                if ( IN6_IS_ADDR_LOOPBACK( sock2ip6(&(addressList[ii])))) {
  #else
                if ( IN6_IS_ADDR_LOOPBACK(&sock2ip6addr(&(addressList[ii]))) ) {
  #endif
                    event_logi(VVERBOSE, "Found IPv6 loopback address ! Num: %u", noOfAddresses);
                    result = TRUE;
                }
                break;
#endif
            default:
                break;
        }
        if (sctpInstance) {
            if (sctpInstance->noOfLocalAddresses > 0){
                for (counter = 0; counter < sctpInstance->noOfLocalAddresses; counter++) {
                    if (adl_equal_address(&(addressList[ii]), &(sctpInstance->localAddressList[counter])) == TRUE) result =
TRUE;                }
            } else {
                if (sctpInstance->has_INADDR_ANY_set) {
                    for (counter = 0; counter < myNumberOfAddresses; counter++) {
                        if (sockunion_family(&myAddressList[counter]) == AF_INET) {
                            if (adl_equal_address(&(addressList[ii]), &(myAddressList[counter])) == TRUE) result = TRUE;
                        }
                    }
                }
                if (sctpInstance->has_IN6ADDR_ANY_set) {
                    for (counter = 0; counter < myNumberOfAddresses; counter++) {
                        if (adl_equal_address(&(addressList[ii]), &(myAddressList[counter])) == TRUE) result = TRUE;
                    }
                }
            }
        }
    }
    event_logi(VVERBOSE, "Found loopback address returns %s", (result == TRUE)?"TRUE":"FALSE");

    return result;
}

gboolean mdi_checkForCorrectAddress(union sockunion* su)
{
    gboolean found = FALSE;
    unsigned int counter;

    /* make sure, if IN(6)ADDR_ANY is specified, it is the only specified address */
    switch(sockunion_family(su)) {
        case AF_INET:
            if (sock2ip(su) == INADDR_ANY) return FALSE;
            break;
#ifdef HAVE_IPV6
        case AF_INET6:
  #if defined (LINUX)
            if (IN6_IS_ADDR_UNSPECIFIED(sock2ip6(su))) return FALSE;
  #else
            if (IN6_IS_ADDR_UNSPECIFIED(&sock2ip6addr(su))) return FALSE;
  #endif
            break;
#endif
        default:
            return FALSE;
            break;
    }

    for (counter = 0; counter < myNumberOfAddresses; counter++) {
        if (adl_equal_address(su, &(myAddressList[counter])) == TRUE) found = TRUE;
    }
    return found;
}

/*
static void printAssocList()
{
   Association* assoc;
   GList*       iterator;
   iterator = g_list_first(AssociationList);
   puts("AssocList:");
   while(iterator) {
      assoc = (Association *)iterator->data;
      printf("   #%d: I=%u, deleted=%d\n", assoc->assocId, assoc->sctpInstance->sctpInstanceName, assoc->deleted);
      iterator = g_list_next(iterator);
   }
}
*/

/**
 *  sctp_registerInstance is called to initialize one SCTP-instance.
 *  Each Adaption-Layer of the ULP must create its own SCTP-instance, and
 *  define and register appropriate callback functions.
 *  An SCTP-instance may define an own port, or zero here ! Servers and clients
 *  that care for their source port must chose a port, clients that do not really
 *  care which source port they use, chose ZERO, and have the implementation chose
 *  a free source port.
 *
 *  @param port                   wellknown port of this sctp-instance
 *  @param noOfLocalAddresses     number of local addresses
 *  @param localAddressList       local address list (pointer to a string-array)
 *  @param ULPcallbackFunctions   call back functions for primitives passed from sctp to ULP
 *  @return     instance name of this SCTP-instance or 0 in case of errors, or error code
 */
int
sctp_registerInstance(unsigned short port,
                           unsigned short noOfInStreams,
                           unsigned short noOfOutStreams,
                           unsigned int noOfLocalAddresses,
                           unsigned char localAddressList[][SCTP_MAX_IP_LEN],
                           SCTP_ulpCallbacks ULPcallbackFunctions)
{

    unsigned int i;
    int adl_rscb_code;
    union sockunion su;
    gboolean with_ipv4 = FALSE;
    unsigned short result;
    GList* list_result = NULL;

#ifdef HAVE_IPV6
    gboolean with_ipv6 = FALSE;
#endif
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_registerInstance");
    ZERO_CHECK_LIBRARY;

    event_log(EXTERNAL_EVENT, "sctp_registerInstance called");

    if ((noOfInStreams==0) || (noOfOutStreams == 0) ||
        (noOfLocalAddresses == 0) || (localAddressList == NULL)) {
            error_log(ERROR_MAJOR, "Parameter Problem in sctp_registerInstance - Error !");
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_registerInstance");
            return SCTP_PARAMETER_PROBLEM;
    }

    if(port == 0) {
        port = seizePort();
    }
    else {
        port = allocatePort(port);
    }
    if(port == 0) {
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        error_log(ERROR_MAJOR, "User gave incorrect address !");
        LEAVE_LIBRARY("sctp_registerInstance");
        return SCTP_WRONG_ADDRESS;
    }


    for (i=0; i< noOfLocalAddresses; i++) {
        if (adl_str2sockunion((localAddressList[i]), &su) < 0) {
            error_logi(ERROR_MAJOR, "Address Error in sctp_registerInstance(%s)", (localAddressList[i]));
            releasePort(port);
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_registerInstance");
            return SCTP_PARAMETER_PROBLEM;
        } else {
            if (su.sa.sa_family == AF_INET) with_ipv4 = TRUE;

#ifdef HAVE_IPV6
            if (su.sa.sa_family == AF_INET6) with_ipv6 = TRUE;
#endif
        }
    }

    event_logi(VERBOSE, "sctp_registerInstance : with_ipv4 : %s ",(with_ipv4==TRUE)?"TRUE":"FALSE" );
    /* if not IPv6 callback must be registered too ! */
#ifdef HAVE_IPV6
    event_logi(VERBOSE, "sctp_registerInstance : with_ipv6: %s ",(with_ipv6==TRUE)?"TRUE":"FALSE" );
#endif

    if ((with_ipv4 != TRUE)
#ifdef HAVE_IPV6
            && (with_ipv6 != TRUE)
#endif
                              ) {
            error_log(ERROR_MAJOR, "No valid address in sctp_registerInstance()");
            releasePort(port);
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_registerInstance");
            return SCTP_PARAMETER_PROBLEM;
    }

    i = mdi_updateMyAddressList();
    if (i != SCTP_SUCCESS) {
            error_log(ERROR_MAJOR, "Could not update my local addresses...");
            releasePort(port);
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_registerInstance");
            return SCTP_UNSPECIFIED_ERROR;
    }

    sctpInstance = (SCTP_instance *) malloc(sizeof(SCTP_instance));
    if (!sctpInstance) {
        error_log_sys(ERROR_MAJOR, (short)errno);
        releasePort(port);
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        LEAVE_LIBRARY("sctp_registerInstance");
        return SCTP_OUT_OF_RESOURCES;
    }

    sctpInstance->localPort = port;
    sctpInstance->noOfInStreams = noOfInStreams;
    sctpInstance->noOfOutStreams = noOfOutStreams;
    sctpInstance->has_INADDR_ANY_set = FALSE;
    sctpInstance->has_IN6ADDR_ANY_set = FALSE;
    sctpInstance->uses_IPv4 = FALSE;
    sctpInstance->uses_IPv6 = TRUE;
    sctpInstance->supportsPRSCTP = librarySupportsPRSCTP;
    sctpInstance->supportsADDIP = supportADDIP;


    if (noOfLocalAddresses == 1) {
        adl_str2sockunion((localAddressList[0]), &su);
        switch(sockunion_family(&su)) {
            case AF_INET:
                if (sock2ip(&su) == INADDR_ANY){
                    sctpInstance->has_INADDR_ANY_set = TRUE;
                    with_ipv4 = TRUE;
                }
                break;
#ifdef HAVE_IPV6
            case AF_INET6:
  #if defined (LINUX)
                if (IN6_IS_ADDR_UNSPECIFIED(sock2ip6(&su))) {
  #else
                if (IN6_IS_ADDR_UNSPECIFIED(&sock2ip6addr(&su))) {
  #endif
                    with_ipv4 = TRUE;
                    with_ipv6 = TRUE;
                    sctpInstance->has_IN6ADDR_ANY_set = TRUE;
                }
                break;
#endif
            default:
                releasePort(port);
                free(sctpInstance);
                sctpInstance = old_Instance;
                currentAssociation = old_assoc;
                error_log(ERROR_MAJOR, "Program Error -> Returning error !");
                LEAVE_LIBRARY("sctp_registerInstance");
                return SCTP_PARAMETER_PROBLEM;
                break;
        }
    }

    sctpInstance->supportedAddressTypes = 0;
    if (with_ipv4) sctpInstance->supportedAddressTypes |= SUPPORT_ADDRESS_TYPE_IPV4;
#ifdef HAVE_IPV6
    if (with_ipv6) sctpInstance->supportedAddressTypes |= SUPPORT_ADDRESS_TYPE_IPV6;
#endif

    if (sctpInstance->has_INADDR_ANY_set == FALSE && sctpInstance->has_IN6ADDR_ANY_set == FALSE) {

        sctpInstance->localAddressList =
                (union sockunion *) malloc(noOfLocalAddresses * sizeof(union sockunion));
        for (i=0; i< noOfLocalAddresses; i++) {
            adl_str2sockunion(localAddressList[i], &(sctpInstance->localAddressList[i]));
            if (mdi_checkForCorrectAddress(&(sctpInstance->localAddressList[i])) == FALSE){
                releasePort(port);
                free (sctpInstance->localAddressList);
                free(sctpInstance);
                sctpInstance = old_Instance;
                currentAssociation = old_assoc;
                error_log(ERROR_MAJOR, "User gave incorrect address !");
                LEAVE_LIBRARY("sctp_registerInstance");
                return SCTP_WRONG_ADDRESS;
            }
        }

        sctpInstance->noOfLocalAddresses = noOfLocalAddresses;
    } else {
        sctpInstance->localAddressList   = NULL;
        sctpInstance->noOfLocalAddresses = 0;
    }


    list_result = g_list_find_custom(InstanceList, sctpInstance, &CheckForAddressInInstance);

    if (list_result) {
        releasePort(port);
        free(sctpInstance->localAddressList);
        free(sctpInstance);
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        error_log(ERROR_MAJOR, "Instance already existed ! Returning error !");
        LEAVE_LIBRARY("sctp_registerInstance");
        return 0;
    }

#ifdef HAVE_IPV6
    if (with_ipv6 && ipv6_sctp_socket==0) {
         ipv6_sctp_socket = adl_get_sctpv6_socket();
         if (!ipv6_sctp_socket)
            error_log(ERROR_FATAL, "IPv6 socket creation failed");
        /*
         * here some operating system specialties may kick in (i.e. opening only ONE
         * socket MIGHT be enough, provided IPv6 socket implicitly reveives IPv4 packets, too
         */
         adl_rscb_code = adl_register_socket_cb(ipv6_sctp_socket,&mdi_dummy_callback);
         if (!adl_rscb_code)
             error_log(ERROR_FATAL, "register ipv6 socket call back function failed");
     }
    if (with_ipv6 == TRUE) {
        ipv6_users++;
        sctpInstance->uses_IPv6 = TRUE;
    } else {
        sctpInstance->uses_IPv6 = FALSE;
    }
#endif
    if (with_ipv4 && sctp_socket==0) {
         sctp_socket = adl_get_sctpv4_socket();
         if (!sctp_socket)
            error_log(ERROR_FATAL, "IPv4 socket creation failed");

         adl_rscb_code = adl_register_socket_cb(sctp_socket,&mdi_dummy_callback);
         if (!adl_rscb_code)
             error_log(ERROR_FATAL, "registration of IPv4 socket call back function failed");
    }
    if (with_ipv4 == TRUE) {
        ipv4_users++;
        sctpInstance->uses_IPv4 = TRUE;
    } else {
        sctpInstance->uses_IPv4 = FALSE;
    }


    sctpInstance->sctpInstanceName = mdi_getUnusedInstanceName();
    if(sctpInstance->sctpInstanceName == 0) {
        releasePort(port);
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        LEAVE_LIBRARY("sctp_registerInstance");
        return SCTP_OUT_OF_RESOURCES;
    }

    sctpInstance->ULPcallbackFunctions = ULPcallbackFunctions;

    sctpInstance->default_rtoInitial = RTO_INITIAL;
    sctpInstance->default_validCookieLife = VALID_COOKIE_LIFE_TIME;
    sctpInstance->default_assocMaxRetransmits = ASSOCIATION_MAX_RETRANS;
    sctpInstance->default_pathMaxRetransmits = MAX_PATH_RETRANSMITS ;
    sctpInstance->default_maxInitRetransmits = MAX_INIT_RETRANSMITS;
    /* using the static variable defined after initialization of the adaptation layer */
    sctpInstance->default_myRwnd = myRWND/2;
    sctpInstance->default_delay = SACK_DELAY;
    sctpInstance->default_ipTos = IPTOS_DEFAULT;
    sctpInstance->default_rtoMin = RTO_MIN;
    sctpInstance->default_rtoMax = RTO_MAX;
    sctpInstance->default_maxSendQueue = DEFAULT_MAX_SENDQUEUE;
    sctpInstance->default_maxRecvQueue = DEFAULT_MAX_RECVQUEUE;
    sctpInstance->default_maxBurst = DEFAULT_MAX_BURST;

    InstanceList = g_list_insert_sorted(InstanceList, sctpInstance, &CompareInstanceNames);

    result = sctpInstance->sctpInstanceName;

    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_registerInstance");
    return (int)result;

}                               /* end: sctp_registerInstance */



int sctp_unregisterInstance(unsigned short instance_name)
{
    /* Look through the instance list, and delete instance, when
       found, else return error. */
    Association* assoc;
    GList* assocIterator = NULL;
    SCTP_instance temporary;
    SCTP_instance* instance;
    guint32 fds;
    GList* result = NULL;
    gboolean with_ipv4=FALSE;
#ifdef HAVE_IPV6
    gboolean with_ipv6=FALSE;
#endif

    ENTER_LIBRARY("sctp_unregisterInstance");

    CHECK_LIBRARY;

    event_logi(INTERNAL_EVENT_0, "Removing SCTP Instance %u from list", instance_name);

    temporary.sctpInstanceName = instance_name;
    result = g_list_find_custom(InstanceList, &temporary, &CompareInstanceNames);
    if (result != NULL) {
        instance  = (SCTP_instance*)result->data;
        with_ipv4 = instance->uses_IPv4;
#ifdef HAVE_IPV6
        with_ipv6 = instance->uses_IPv6;
#endif
        event_logi(INTERNAL_EVENT_0, "sctp_unregisterInstance: SCTP Instance %u found !!!", instance_name);
#ifdef HAVE_IPV6
        event_logi(VERBOSE, "sctp_unregisterInstance : with_ipv6: %s ",(with_ipv6==TRUE)?"TRUE":"FALSE" );
        if (with_ipv6 == TRUE) ipv6_users--;
        event_logi(VERBOSE, "sctp_unregisterInstance : ipv6_users: %u ",ipv6_users);
#endif
        if (with_ipv4 == TRUE) ipv4_users--;
        event_logi(VERBOSE, "sctp_unregisterInstance : with_ipv4: %s ",(with_ipv4==TRUE)?"TRUE":"FALSE" );
        event_logi(VERBOSE, "sctp_unregisterInstance : ipv4_users: %u ",ipv4_users);

        assocIterator = g_list_first(AssociationList);
        while(assocIterator) {
           assoc = (Association*)assocIterator->data;
           if(assoc->sctpInstance == instance) {
              event_logi(ERROR_MINOR, "sctp_unregisterInstance : instance still used by assoc %u !!!",
                         assoc->assocId);
              return SCTP_INSTANCE_IN_USE;
           }
           assocIterator = g_list_next(assocIterator);
        }

        if (sctp_socket != 0 &&  ipv4_users == 0) {
            fds = adl_remove_poll_fd(sctp_socket);
            event_logi(VVERBOSE, "sctp_unregisterInstance : Removed IPv4 cb, registered FDs: %u ",fds);
            /* if there are no ipv4_users, deregister callback for ipv4-socket, if it was registered ! */
            sctp_socket = 0;
        }

#ifdef HAVE_IPV6
        if (ipv6_sctp_socket != 0 &&  ipv6_users == 0) {
            fds = adl_remove_poll_fd(ipv6_sctp_socket);
           /* if there are no ipv6_users, deregister callback for ipv6-socket, if it was registered ! */
            event_logi(VVERBOSE, "sctp_unregisterInstance : Removed IPv4 cb, registered FDs: %u ",fds);
            ipv6_sctp_socket = 0;
        }
#endif

        if (instance->has_INADDR_ANY_set == FALSE) {
            event_log(VVERBOSE, "sctp_unregisterInstance : INADDR_ANY == FALSE");
        }
        if (instance->has_INADDR_ANY_set == TRUE) {
            event_log(VVERBOSE, "sctp_unregisterInstance : INADDR_ANY == TRUE");
        }
#ifdef HAVE_IPV6
        if (instance->has_IN6ADDR_ANY_set == FALSE)
            event_log(VVERBOSE, "sctp_unregisterInstance : IN6ADDR_ANY == FALSE");
#endif
        if (instance->noOfLocalAddresses > 0) {
            free(instance->localAddressList);
        }
        event_log(VVERBOSE, "sctp_unregisterInstance : freeing instance ");
        releasePort(instance->localPort);
        free(instance);
        InstanceList = g_list_remove(InstanceList, result->data);
        LEAVE_LIBRARY("sctp_unregisterInstance");
        return SCTP_SUCCESS;
    } else {
        event_logi(INTERNAL_EVENT_0, "SCTP Instance %u not in list", instance_name);
    }
    LEAVE_LIBRARY("sctp_unregisterInstance");
    return SCTP_INSTANCE_NOT_FOUND;

}


/**
 * This function should be called AFTER an association has indicated a
 * COMMUNICATION_LOST or a SHUTDOWN_COMPLETE, and the upper layer has
 * retrieved all data it is interested in (possibly using the currently
 * not implemented functions  sctp_receive_unsent() or sctp_receive_unacked())
 * it really removes all data belonging to the association, and removes the
 * association instance from the list, on explicit upper layer instruction !
 * @param  associationID the association ID of the assoc that shall be removed
 * @return error_code  0 for success, 1 if assoc is already gone, -1 if assocs
 *         deleted flag is not set (then assoc should be in a state different from CLOSED)
 */
int sctp_deleteAssociation(unsigned int associationID)
{
    Association *assocFindP;
    GList* result = NULL;

    ENTER_LIBRARY("sctp_deleteAssociation");

    CHECK_LIBRARY;

    event_logi(INTERNAL_EVENT_0, "sctp_deleteAssociation: getting assoc %08x from list", associationID);

    tmpAssoc.assocId = associationID;
    tmpAssoc.deleted = FALSE;
    assocFindP = &tmpAssoc;
    currentAssociation = NULL;

    result = g_list_find_custom(AssociationList, assocFindP, &compareAssociationIDs);
    if (result != NULL) {
        currentAssociation = (Association *)result->data;
        if (!currentAssociation->deleted) {
            currentAssociation = NULL;
            error_log(ERROR_MAJOR, "Deleted-Flag not set, returning from sctp_deleteAssociation !");
            LEAVE_LIBRARY("sctp_deleteAssociation");
            return SCTP_SPECIFIC_FUNCTION_ERROR;
        }
        /* remove the association from the list */
        AssociationList = g_list_remove(AssociationList, currentAssociation);
        event_log(INTERNAL_EVENT_0, "sctp_deleteAssociation: Deleted Association from list");
        /* free all association data */
        mdi_removeAssociationData(currentAssociation);
        currentAssociation = NULL;
        LEAVE_LIBRARY("sctp_deleteAssociation");
        return SCTP_SUCCESS;
    } else {
        event_logi(INTERNAL_EVENT_0, "association %08x not in list", associationID);
        LEAVE_LIBRARY("sctp_deleteAssociation");
        return SCTP_ASSOC_NOT_FOUND;
    }
    /* should not be reached */
    LEAVE_LIBRARY("sctp_deleteAssociation");
    return SCTP_SUCCESS;
}


/**
 * This function is called to setup an association.
 *  The ULP must specify the SCTP-instance to which this association belongs to.
 *  @param SCTP_InstanceName     the SCTP instance this association belongs to.
 *                               if the local port of this SCTP instance is zero, we will get a port num,
                                 else we will use the one from the SCTP instance !
 *  @param noOfOutStreams        number of output streams the ULP would like to have
 *  @param destinationAddress    destination address
 *  @param destinationPort       destination port
 *  @param ulp_data             pointer to an ULP data structure, will be passed with callbacks !
 *  @return association ID of this association, 0 in case of failures
 */
unsigned int sctp_associatex(unsigned int SCTP_InstanceName,
                             unsigned short noOfOutStreams,
                             unsigned char  destinationAddresses[SCTP_MAX_NUM_ADDRESSES][SCTP_MAX_IP_LEN],
                             unsigned int   noOfDestinationAddresses,
                             unsigned int   maxSimultaneousInits,
                             unsigned short destinationPort,
                             void* ulp_data)

{
    unsigned int assocID, count;
    unsigned short zlocalPort;
    union sockunion dest_su[SCTP_MAX_NUM_ADDRESSES];
    gboolean withPRSCTP;
	AddressScopingFlags filterFlags = flag_Default;
    SCTP_instance temporary;
    GList* result = NULL;

    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_associatex");

    ZERO_CHECK_LIBRARY;

    if (destinationPort == 0) {
            error_log(ERROR_MAJOR, "sctp_associate: destination port is zero....this is not allowed");
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_associate");
            return 0;
    }

    for (count = 0; count <  noOfDestinationAddresses; count++) {
        if (adl_str2sockunion(destinationAddresses[count], &dest_su[count]) < 0) {
            error_log(ERROR_MAJOR, "sctp_associate: destination adress not good !");
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_associate");
            return 0;
        } else if(adl_filterInetAddress(&dest_su[count], filterFlags) == FALSE) {
            error_log(ERROR_MAJOR, "sctp_associate: destination adress not good !");
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_associate");
            return 0;
        }
    }

    event_log(EXTERNAL_EVENT, "sctp_associatex called");
    event_logi(VERBOSE, "Looking for SCTP Instance %u in the list", SCTP_InstanceName);

    temporary.sctpInstanceName =  SCTP_InstanceName;
    result = g_list_find_custom(InstanceList, &temporary, &CompareInstanceNames);
    if (result == NULL) {
        error_log(ERROR_MAJOR, "sctp_associate: SCTP instance not in the list !!!");
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        LEAVE_LIBRARY("sctp_associate");
        return 0;
    }
    sctpInstance = (SCTP_instance*)result->data;

    if (((SCTP_instance*)result->data)->localPort == 0)
       zlocalPort = seizePort();
    else
       zlocalPort = ((SCTP_instance*)result->data)->localPort;

    event_logi(VERBOSE, "Chose local port %u for associate !", zlocalPort);

    withPRSCTP = librarySupportsPRSCTP;

    /* Create new association */
    if (mdi_newAssociation(sctpInstance,
                           zlocalPort, /* local client port */
                           destinationPort, /* remote server port */
                           mdi_generateTag(),
                           0,
                           (short)noOfDestinationAddresses,
                           dest_su)) {
        error_log(ERROR_MAJOR, "Creation of association failed");
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        LEAVE_LIBRARY("sctp_associate");
        return 0;
    }
    currentAssociation->ulp_dataptr = ulp_data;

    /* call associate at SCTP-control */
    scu_associate(noOfOutStreams,
                  ((SCTP_instance*)result->data)->noOfInStreams,
                  dest_su,
                  noOfDestinationAddresses,
                  withPRSCTP);

    assocID = currentAssociation->assocId;

    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_associate");
    return assocID;

}                               /* end: sctp_associatex */


unsigned int
sctp_associate(unsigned int SCTP_InstanceName,
               unsigned short noOfOutStreams,
               unsigned char destinationAddress[SCTP_MAX_IP_LEN],
               unsigned short destinationPort,
               void* ulp_data)
{
    unsigned char dAddress[1][SCTP_MAX_IP_LEN];

    event_log(EXTERNAL_EVENT, "sctp_associate called");
    memcpy(dAddress, destinationAddress, SCTP_MAX_IP_LEN);

    return   sctp_associatex(SCTP_InstanceName,
                             noOfOutStreams,
                             dAddress,
                             1,
                             1,
                             destinationPort,
                             ulp_data);


}

/**
 * sctp_shutdown initiates the shutdown of the specified association.
 *  @param    associationID  the ID of the addressed association.
 *  @return   0 for success, 1 for error (assoc. does not exist)
 */
int sctp_shutdown(unsigned int associationID)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_shutdown");

    CHECK_LIBRARY;

    /* Retrieve association from list  */
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        /* Forward shutdown to the addressed association */
        scu_shutdown();
    } else {
        event_log(VERBOSE, "sctp_shutdown: addressed association does not exist");
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        LEAVE_LIBRARY("sctp_shutdown");
        return SCTP_ASSOC_NOT_FOUND;
    }

    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_shutdown");
    return SCTP_SUCCESS;

}                               /* end: sctp_shutdown */



/**
 * sctp_abort initiates the abort of the specified association.
 * @param    associationID  the ID of the addressed association.
 * @return   0 for success, 1 for error (assoc. does not exist)
 */
int sctp_abort(unsigned int associationID)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;
    /* Retrieve association from list  */
    ENTER_LIBRARY("sctp_abort");

    CHECK_LIBRARY;

    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        /* Forward shutdown to the addressed association */
        scu_abort(ECC_USER_INITIATED_ABORT, 0, NULL);
    } else {
        error_log(ERROR_MAJOR, "sctp_abort: addressed association does not exist");
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        LEAVE_LIBRARY("sctp_abort");
        return SCTP_ASSOC_NOT_FOUND;
    }

    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_abort");
    return SCTP_SUCCESS;

}                               /* end: sctp_abort */



/**
 * sctp_send is used by the ULP to send data chunks.
 *
 *  @param    associationID  the ID of the addressed association.
 *  @param    streamID       identifies the stream on which the chunk is sent.
 *  @param    buffer         chunk data.
 *  @param    length         length of chunk data.
 *  @param    protocolId     the payload protocol identifier
 *  @param    path_id        index of destination address, if different from primary pat, negative for primary
 *  @param    context        ULP context, i.e. a pointer that will may be retunred with certain callbacks.
                             (in case of send errors).
 *  @param    lifetime       maximum time of chunk in send queue in msecs, 0 for infinite
 *  @param    unorderedDelivery chunk is delivered to peer without resequencing, if true (==1), else ordered (==0).
 *  @param    dontBundle     chunk must not be bundled with other data chunks.
 *                           boolean, 0==normal bundling, 1==do not bundle message
 *  @return   error code     -1 for send error, 1 for association error, 0 if successful
 */
int sctp_send_private(unsigned int associationID, unsigned short streamID,
                      unsigned char *buffer, unsigned int length, unsigned int protocolId, short path_id,
                      void*  context, /* optional (=SCTP_NO_CONTEXT=NULL if none) */
                      unsigned int lifetime, /* optional (zero -> infinite) */
                      int unorderedDelivery, /* boolean, 0==ordered, 1==unordered */
                      int dontBundle)      /* boolean, 0==normal bundling, 1==do not bundle message */
{
    int result = SCTP_SUCCESS;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;
    ENTER_LIBRARY("sctp_send");

    CHECK_LIBRARY;

    /* Retrieve association from list  */
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;

        if ((path_id >= -1) && (path_id < currentAssociation->noOfNetworks)) {
            event_log(INTERNAL_EVENT_1, "sctp_send: sending chunk");
            /* Forward chunk to the addressed association */
            result = se_ulpsend(streamID, buffer, length, protocolId, path_id,
                      context, lifetime, unorderedDelivery, dontBundle);
        } else {
            error_logi(ERROR_MAJOR, "sctp_send: invalid destination address %d", path_id);
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_send");
            return SCTP_PARAMETER_PROBLEM;
        }
    } else {
        error_log(ERROR_MAJOR, "sctp_send: addressed association does not exist");
        result = SCTP_ASSOC_NOT_FOUND ;
    }

    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_send");
    return result;
}                               /* end: sctp_send */



/**
 * sctp_setPrimary changes the primary path of an association.
 * @param  associationID     ID of assocation.
 * @param  destAddressIndex  index to the new primary path
 * @return error code
 */
short sctp_setPrimary(unsigned int associationID, short path_id)
{
    short rv;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_setPrimary");

    CHECK_LIBRARY;
    /* Retrieve association from list  */
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        if (sci_getState() != SCTP_ESTABLISHED) {
            LEAVE_LIBRARY("sctp_setPrimary");
            return SCTP_SPECIFIC_FUNCTION_ERROR;
        }
        sctpInstance = currentAssociation->sctpInstance;
        /* Forward shutdown to the addressed association */
        rv = pm_setPrimaryPath(path_id);
    } else {
        error_log(ERROR_MAJOR, "sctp_setPrimary: addressed association does not exist");
        rv =  SCTP_ASSOC_NOT_FOUND;
    }

    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_setPrimary");
    return rv;

}                               /* end: sctp_setPrimary */

/**
 * sctp_receive is called in response to the dataArriveNotification to
 * get the received data.
 * The stream engine must copy the chunk data from a received  SCTP datagram to
 * a new byte string, because the SCTP datagram is overwritten when the next datagram
 * is received and the lifetime of a chunk in the streamengine might outlast the
 *  the reception of several SCTP datagrams.
 *  For this reasons and to avoid repeated copying of byte strings, a pointer to
 *  the byte string of chunkdata allocated by the streamengine is returned.
 *  According to the standard, the chunkdata should be copied to to a buffer provided
 *  by the ULP.
 *  @param   associationID  ID of association.
 *  @param   streamID       the stream on which the data chunk is received.
 *  @param   buffer         pointer to where payload data of arrived chunk will be copied
 *  @param   length         length of chunk data.
 *  @return  SCTP_SUCCESS if okay, 1==SCTP_SPECIFIC_FUNCTION_ERROR if there was no data
*/
int sctp_receive(unsigned int associationID,
                 unsigned short streamID,
                 unsigned char  *buffer,
                 unsigned int *length,
                 unsigned short *streamSN,
                 unsigned int * tsn,
                 unsigned int flags)
{
    unsigned int addressIndex;
    return (sctp_receivefrom(associationID,streamID, buffer, length,
                                streamSN, tsn, &addressIndex, flags));

}


/**
 * sctp_receivefrom does the same thing as sctp_receive(), and additionally returns the
 * addressIndex, indicating where the chunks was received from.
 *  @param   associationID  ID of association.
 *  @param   streamID       the stream on which the data chunk is received.
 *  @param   buffer         pointer to where payload data of arrived chunk will be copied
 *  @param   length         length of chunk data.
 *  @return  SCTP_SUCCESS if okay, 1==SCTP_SPECIFIC_FUNCTION_ERROR if there was no data
*/
int sctp_receivefrom(unsigned int associationID,
                    unsigned short streamID,
                    unsigned char  *buffer,
                    unsigned int *length,
                    unsigned short *streamSN,
                    unsigned int * tsn,
                    unsigned int *addressIndex,
                    unsigned int flags)
{
    int result;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_receive");

    CHECK_LIBRARY;

    if (buffer == NULL) {
        LEAVE_LIBRARY("sctp_receive");
        return SCTP_PARAMETER_PROBLEM;
    }
    if (length == NULL) {
        LEAVE_LIBRARY("sctp_receive");
        return SCTP_PARAMETER_PROBLEM;
    }
    /* Retrieve association from list, as long as the data is not actually gone ! */
    currentAssociation = retrieveAssociationForced(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;

        /* retrieve data from streamengine instance */
        result = se_ulpreceivefrom(buffer, length, streamID, streamSN, tsn, addressIndex, flags);
    } else {
        error_log(ERROR_MAJOR, "sctp_receive: addressed association does not exist");
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        LEAVE_LIBRARY("sctp_receive");
        return SCTP_ASSOC_NOT_FOUND;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    if (result == 0) {
        LEAVE_LIBRARY("sctp_receive");
        return SCTP_SUCCESS;
    }
    else if (result == 1) {
        LEAVE_LIBRARY("sctp_receive");
        return SCTP_PARAMETER_PROBLEM;
    }
    else if (result == SCTP_MODULE_NOT_FOUND) {
        LEAVE_LIBRARY("sctp_receive");
        return SCTP_MODULE_NOT_FOUND;
    }
    /* else result == 2, i.e. no data available */
    LEAVE_LIBRARY("sctp_receive");
    return SCTP_SPECIFIC_FUNCTION_ERROR;
}                               /* end: sctp_receive */



/**
 * sctp_changeHeartBeat turns the hearbeat on a path of an association on or
 * off, or modifies the interval
 * @param  associationID   ID of assocation.
 * @param  path_id         index of the path where to do heartbeat
 * @param  heartbeatON     turn heartbeat on or off
 * @param  timeIntervall   heartbeat time intervall in milliseconds
 * @return error code,     SCTP_LIBRARY_NOT_INITIALIZED, SCTP_SUCCESS, SCTP_PARAMETER_PROBLEM,
 *                         SCTP_MODULE_NOT_FOUND, SCTP_ASSOC_NOT_FOUND
 */
int
sctp_changeHeartBeat(unsigned int associationID,
                     short path_id, gboolean heartbeatON, unsigned int timeIntervall)
{
    int result;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;
    ENTER_LIBRARY("sctp_changeHeartbeat");

    CHECK_LIBRARY;

    /* Retrieve association from list  */
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        /* Forward change HB to the addressed association */
        if (heartbeatON) {
            result = pm_enableHB(path_id, timeIntervall);
            event_logiii(VERBOSE,
                        "Setting HB interval for address %d to %u msecs, result: %d !",
                        path_id, timeIntervall, result);
        } else
            result = pm_disableHB(path_id);
            event_logii(VERBOSE,
                        "Disabling HB for address %d, result: %d !",
                        path_id, result);
    } else {
        error_log(ERROR_MAJOR, "sctp_changeHeartBeat: addressed association does not exist");
        result = SCTP_ASSOC_NOT_FOUND;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_changeHeartbeat");
    return result;
}                               /* end: sctp_changeHeartBeat */



/**
 * sctp_requestHeartbeat sends a heartbeat to the given address of an association.
 * @param  associationID  ID of assocation.
 * @param  path_id        destination address to which the heartbeat is sent.
 * @return error code (SCTP_SUCCESS, SCTP_ASSOC_NOT_FOUND, SCTP_MODULE_NOT_FOUND, SCTP_LIBRARY_NOT_INITIALIZED,
                        SCTP_UNSPECIFIED_ERROR)
 */
int sctp_requestHeartbeat(unsigned int associationID, short path_id)
{
    int result;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_requestHeartbeat");

    CHECK_LIBRARY;

    /* Retrieve association from list  */
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        result = pm_doHB(path_id);
        event_logi(VERBOSE, "Sending HB on user request to path ID: %u !",path_id);
    } else {
        error_log(ERROR_MAJOR, "sctp_requestHeartbeat: addressed association does not exist");
        result = SCTP_ASSOC_NOT_FOUND;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_requestHeartbeat");
    return result;
}                               /* sctp_requestHeartbeat */

/**
 * sctp_getSrttReport returns a smoothed RTT value for a path to a given address
 * @param  associationID    ID of assocation.
 * @param  destAddressIndex destination address where to get SRTT from
 * @return SRTT of the address in msecs, negative on error
 */
int sctp_getSrttReport(unsigned int associationID, short path_id)
{
    unsigned int srtt;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_getSrttReport");

    CHECK_LIBRARY;

    /* Retrieve association from list  */
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        srtt = pm_readSRTT(path_id);
        event_logiii(VERBOSE, "sctp_getSrttReport(asoc=%u, address=%d) result: %u !",
                        associationID, path_id, srtt);
        sctpInstance = old_Instance;
        currentAssociation = old_assoc;
        if (srtt==0xffffffff) {
            LEAVE_LIBRARY("sctp_getSrttReport");
            return SCTP_PARAMETER_PROBLEM;
        } else {
            LEAVE_LIBRARY("sctp_getSrttReport");
            return (int)srtt;
        }
    } else {
        error_log(ERROR_MAJOR, "sctp_getSrttReport: addressed association does not exist");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_getSrttReport");
    return  SCTP_ASSOC_NOT_FOUND;

}


/**
 *  sctp_setFailureThreshold is used to set the threshold for retransmissions on the given
 *  address of an association. If the threshold is exeeded, the the destination address is
 *  considered as  unreachable.
 *  @param  associationID :            ID of assocation.
 *  @param  destAddressIndex :         destination address that gets a new failure threshold.
 *  @param  pathMaxRetransmissions :   threshold for retransmissions.
 *  @return
 */
int
sctp_setFailureThreshold(unsigned int associationID, unsigned short pathMaxRetransmissions)
{
    guint16 result;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_setFailureThreshold");

    CHECK_LIBRARY;

    event_logii(VERBOSE, "sctp_setFailureThreshold: Association %u, pathMaxRetr. %u", associationID,
pathMaxRetransmissions);
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        pm_setMaxPathRetransmisions(pathMaxRetransmissions);
        result = SCTP_SUCCESS;
    } else {
        error_logi(ERROR_MAJOR, "sctp_setFailureThreshold : association %u does not exist", associationID);
        result = SCTP_ASSOC_NOT_FOUND;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_setFailureThreshold");
    return result;

}                               /* end:  sctp_setFailureThreshold */



/**
 * sctp_getPathStatus : IP_TOS support is still missing !
 * Can be used to get path specific parameters in an existing association.
 *mdi_readLocalInStreams
 *  @param  associationID   ID of assocation.
 *  @param  path_id         path for which to get parameters
 *  @param  status      pointer to new parameters
 *  @return 0 for success, not zero for error
 */
int sctp_getPathStatus(unsigned int associationID, short path_id, SCTP_PathStatus* status)
{
    guint16 result;
    guint32 assocState;
    unsigned int totalBytesInFlight;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_getPathStatus");

    CHECK_LIBRARY;

    event_logii(VERBOSE, "sctp_getPathStatus: Association %u, Path %u", associationID, path_id);

    if (status == NULL) {
        LEAVE_LIBRARY("sctp_getPathStatus");
        return SCTP_PARAMETER_PROBLEM;
    }
    currentAssociation = retrieveAssociation(associationID);

    /* TODO: error handling for these two events should be separated - return two different errors */
    if (currentAssociation != NULL && path_id >= 0 && path_id< currentAssociation->noOfNetworks) {
        assocState = sci_getState();
        if (assocState < ESTABLISHED) {
            result = SCTP_ASSOC_NOT_FOUND;
        } else {
            sctpInstance = currentAssociation->sctpInstance;
            adl_sockunion2str(&(currentAssociation->destinationAddresses[path_id]),
                              &(status->destinationAddress[0]), SCTP_MAX_IP_LEN);
            status->state = pm_readState(path_id);
            status->srtt = pm_readSRTT(path_id);
            status->rto = pm_readRTO(path_id);
            status->rttvar = pm_readRttVar(path_id);
            pm_getHBInterval(path_id, &(status->heartbeatIntervall));
            status->cwnd = fc_readCWND(path_id);
            status->cwnd2 = fc_readCWND2(path_id);
            status->partialBytesAcked = fc_readPBA(path_id);
            status->ssthresh = fc_readSsthresh(path_id);
            status->outstandingBytesPerAddress = rtx_get_obpa((unsigned int)path_id, &totalBytesInFlight);
            status->mtu = fc_readMTU(path_id);
            status->ipTos = currentAssociation->ipTos;
            result = SCTP_SUCCESS;
        }
    } else {
        error_logi(ERROR_MAJOR, "sctp_getPathStatus : association %u does not exist", associationID);
        result = SCTP_ASSOC_NOT_FOUND;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_getPathStatus");
    return result;
}

/**
 * sctp_setPathStatus is currently NOT implemented !
 * Can be used to set path specific parameters in an existing association.
 *
 *  @param  associationID   ID of assocation.
 *  @param  path_id         path for which to set parameters
 *  @param  new_status      pointer to new parameters
 *  @return -1
 */
int sctp_setPathStatus(unsigned int associationID, short path_id, SCTP_PathStatus* new_status)
{
    CHECK_LIBRARY;
    ENTER_LIBRARY("sctp_setPathStatus");

    error_log(ERROR_MAJOR, "sctp_setPathStatus : unimplemented function");
    LEAVE_LIBRARY("sctp_setPathStatus");
    return SCTP_UNSPECIFIED_ERROR;
}


/**
 * sctp_setAssocStatus allows for setting a number of association parameters.
 * _Not_ all values that the corresponding sctp_getAssocStatus-function returns
 * may be SET here !
 * Will set protocol parameters per SCTP association
 *
 *  @param  associationID   ID of assocation.
 *  @param  new_status      pointer to new parameters
 *  @return -1
*/
int sctp_setAssocStatus(unsigned int associationID, SCTP_AssociationStatus* new_status)
{
    guint16 result;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_setAssocStatus");

    CHECK_LIBRARY;

    if (new_status == NULL) {
        LEAVE_LIBRARY("sctp_setAssocStatus");
        return SCTP_PARAMETER_PROBLEM;
    }
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        event_logi(VERBOSE, "sctp_setAssocStatus: Association %u", associationID);
        if (pm_setPrimaryPath(new_status->primaryAddressIndex)) {
            error_logi(ERROR_MINOR, "pm_setPrimary(%u) returned error", new_status->primaryAddressIndex);
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_setAssocStatus");
            return SCTP_PARAMETER_PROBLEM;
        }
        if (pm_setRtoInitial(new_status->rtoInitial)) {
            error_logi(ERROR_MINOR, "pm_setRtoInitial(%u) returned error", new_status->rtoInitial);
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_setAssocStatus");
            return SCTP_PARAMETER_PROBLEM;
        }
        if (pm_setRtoMin(new_status->rtoMin)) {
            error_logi(ERROR_MINOR, "pm_setRtoMin(%u) returned error", new_status->rtoMin);
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_setAssocStatus");
            return SCTP_PARAMETER_PROBLEM;
        }
        if (pm_setRtoMax(new_status->rtoMax)) {
            error_logi(ERROR_MINOR, "pm_setRtoMax(%u) returned error", new_status->rtoMax);
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_setAssocStatus");
            return SCTP_PARAMETER_PROBLEM;
        }
        if(pm_setMaxPathRetransmisions(new_status->pathMaxRetransmits)) {
            error_logi(ERROR_MINOR, "pm_getMaxPathRetransmisions(%u) returned error", new_status->pathMaxRetransmits);
            sctpInstance = old_Instance;
            currentAssociation = old_assoc;
            LEAVE_LIBRARY("sctp_setAssocStatus");
            return SCTP_PARAMETER_PROBLEM;
        }
        sci_setCookieLifeTime(new_status->validCookieLife);

        sci_setMaxAssocRetransmissions(new_status->assocMaxRetransmits);
        sci_setMaxInitRetransmissions(new_status->maxInitRetransmits);

        rxc_set_local_receiver_window(new_status->myRwnd);
        rxc_set_sack_delay(new_status->delay);
        currentAssociation->ipTos = new_status->ipTos;
        result = fc_set_maxSendQueue(new_status->maxSendQueue);

        result = SCTP_SUCCESS;

    } else {
        error_logi(ERROR_MAJOR, "sctp_getAssocStatus : association %u does not exist", associationID);
        result = SCTP_ASSOC_NOT_FOUND;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_setAssocStatus");
    return result;
}                               /* end: sctp_setAssocStatus */

/**
 * Will get the protocol parameters per SCTP association
 *
 *  @param  associationID   ID of assocation.
 *  @return  pointer to a structure containing association parameters
*/
int sctp_getAssocStatus(unsigned int associationID, SCTP_AssociationStatus* status)
{
    guint16 result;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_getAssocStatus");

    CHECK_LIBRARY;

    if (status == NULL) {
        LEAVE_LIBRARY("sctp_getAssocStatus");
        return SCTP_PARAMETER_PROBLEM;
    }
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        event_logi(VERBOSE, "sctp_getAssocStatus: Association %u", associationID);
        status->state = sci_getState();
        status->numberOfAddresses = currentAssociation->noOfNetworks;
        status->sourcePort =currentAssociation->localPort;
        status->destPort = currentAssociation->remotePort;
        status->primaryAddressIndex = pm_readPrimaryPath();

        adl_sockunion2str(&(currentAssociation->destinationAddresses[status->primaryAddressIndex]),
                          &(status->primaryDestinationAddress[0]),SCTP_MAX_IP_LEN);

        se_readNumberOfStreams(&(status->inStreams), &(status->outStreams));
        status->currentReceiverWindowSize =  rtx_read_remote_receiver_window();
        status->outstandingBytes = fc_readOutstandingBytes();
        status->noOfChunksInSendQueue = fc_readNumberOfQueuedChunks();
        status->noOfChunksInRetransmissionQueue = rtx_readNumberOfUnackedChunks();
        status->noOfChunksInReceptionQueue = se_numOfQueuedChunks();
        status->rtoInitial = pm_getRtoInitial();
        status->rtoMin = pm_getRtoMin();
        status->rtoMax = pm_getRtoMax();
        status->validCookieLife = sci_getCookieLifeTime();
        status->assocMaxRetransmits = sci_getMaxAssocRetransmissions();
        status->pathMaxRetransmits = pm_getMaxPathRetransmisions();
        status->maxInitRetransmits = sci_getMaxInitRetransmissions();
        status->myRwnd = rxc_get_local_receiver_window();
        status->delay = rxc_get_sack_delay();
        result = fc_get_maxSendQueue(&(status->maxSendQueue));
        status->maxRecvQueue = 0;
        status->ipTos = 0;
        result = SCTP_SUCCESS;

    } else {
        error_logi(ERROR_MAJOR, "sctp_getAssocStatus : association %u does not exist", associationID);
        result = SCTP_ASSOC_NOT_FOUND;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_getAssocStatus");
    return result;
}                               /* end: sctp_getAssocStatus */

/**
 * sctp_setAssocDefaults allows for setting a few association default parameters !
 * Will set protocol default parameters per given SCTP instance
 *
 *  @param  SCTP_InstanceName   instance for which to set the parameters
 *  @param  params       pointer to parameter data structure
 *  @return -1
*/
int sctp_setAssocDefaults(unsigned short SCTP_InstanceName, SCTP_InstanceParameters* params)
{
    SCTP_instance temporary;
    SCTP_instance* instance;
    GList* result = NULL;

    ENTER_LIBRARY("sctp_setAssocDefaults");

    CHECK_LIBRARY;

    event_logi(VERBOSE, "sctp_setInstanceParams: Instance %u", SCTP_InstanceName);

    temporary.sctpInstanceName = SCTP_InstanceName;
    result = g_list_find_custom(InstanceList, &temporary, &CompareInstanceNames);
    if (result != NULL) {
        instance = (SCTP_instance*)result->data;
    } else {
        error_logi(ERROR_MINOR, "sctp_setAssocDefaults : Did not find Instance Number %u", SCTP_InstanceName);
        LEAVE_LIBRARY("sctp_setAssocDefaults");
        return SCTP_INSTANCE_NOT_FOUND;
    }
    if (params == NULL) {
        error_log(ERROR_MINOR, "sctp_setAssocDefaults : Passed NULL Pointer !");
        LEAVE_LIBRARY("sctp_setAssocDefaults");
        return SCTP_PARAMETER_PROBLEM;
    }
    instance->default_rtoInitial =  params->rtoInitial;
    instance->default_rtoMin = params->rtoMin;
    instance->default_rtoMax = params->rtoMax;
    instance->default_validCookieLife = params->validCookieLife;
    instance->default_assocMaxRetransmits =  params->assocMaxRetransmits;
    instance->default_pathMaxRetransmits = params->pathMaxRetransmits;
    instance->default_maxInitRetransmits =  params->maxInitRetransmits;
    instance->default_myRwnd =  params->myRwnd;
    instance->default_delay = params->delay;
    instance->default_ipTos = params->ipTos;
    instance->default_maxSendQueue = params->maxSendQueue;
    instance->default_maxRecvQueue = params->maxRecvQueue;
    instance->noOfInStreams = params->inStreams;
    instance->noOfOutStreams = params->outStreams;
    LEAVE_LIBRARY("sctp_setAssocDefaults");
    return SCTP_SUCCESS;
}                               /* end: sctp_setInstanceParams */

/**
 * sctp_getInstanceParams returns a struct with default parameter values !
 * Will get protocol parameters per given SCTP instance
 *
 *  @param  SCTP_InstanceName   instance for which to set the parameters
 *  @param  params       pointer to parameter data
 *  @return -1
*/
int sctp_getAssocDefaults(unsigned short SCTP_InstanceName, SCTP_InstanceParameters* params)
{
    SCTP_instance temporary;
    SCTP_instance* instance;
    unsigned int numOfAddresses=0, count=0;

    GList* result = NULL;

    ENTER_LIBRARY("sctp_getAssocDefaults");

    CHECK_LIBRARY;

    event_logi(VERBOSE, "sctp_getInstanceParams: Instance %u", SCTP_InstanceName);

    temporary.sctpInstanceName = SCTP_InstanceName;
    result = g_list_find_custom(InstanceList, &temporary, &CompareInstanceNames);
    if (result != NULL) {
        instance = (SCTP_instance*)result->data;
    } else {
        error_logi(ERROR_MINOR, "sctp_getAssocDefaults : Did not find Instance Number %u", SCTP_InstanceName);
        LEAVE_LIBRARY("sctp_getAssocDefaults");
        return SCTP_INSTANCE_NOT_FOUND;
    }
    if (params == NULL) {
        error_log(ERROR_MINOR, "sctp_getAssocDefaults : Passed NULL Pointer !");
        LEAVE_LIBRARY("sctp_getAssocDefaults");
        return SCTP_PARAMETER_PROBLEM;
    }
    if (instance->noOfLocalAddresses > SCTP_MAX_NUM_ADDRESSES)
        numOfAddresses = SCTP_MAX_NUM_ADDRESSES;
    else  numOfAddresses = instance->noOfLocalAddresses;

    if (numOfAddresses == 0) {
        params->noOfLocalAddresses = myNumberOfAddresses;
        for (count = 0; count < myNumberOfAddresses; count++) {
            adl_sockunion2str(&(myAddressList[count]), params->localAddressList[count], SCTP_MAX_IP_LEN);
        }
    } else {
        params->noOfLocalAddresses = numOfAddresses;
        for (count = 0; count < numOfAddresses; count++) {
            adl_sockunion2str(&(instance->localAddressList[count]), params->localAddressList[count], SCTP_MAX_IP_LEN);
        }
    }
    params->rtoInitial = instance->default_rtoInitial;
    params->rtoMin  = instance->default_rtoMin;
    params->rtoMax  = instance->default_rtoMax;
    params->validCookieLife = instance->default_validCookieLife;
    params->assocMaxRetransmits = instance->default_assocMaxRetransmits;
    params->pathMaxRetransmits = instance->default_pathMaxRetransmits;
    params->maxInitRetransmits = instance->default_maxInitRetransmits;
    params->myRwnd = instance->default_myRwnd;
    params->delay = instance->default_delay ;
    params->ipTos = instance->default_ipTos ;
    params->maxSendQueue = instance->default_maxSendQueue;
    params->maxRecvQueue = instance->default_maxRecvQueue;
    params->inStreams = instance->noOfInStreams;
    params->outStreams = instance->noOfOutStreams;

    LEAVE_LIBRARY("sctp_getAssocDefaults");
    return SCTP_SUCCESS;
}                               /* end: sctp_getAssocDefaults */


int sctp_setLibraryParameters(SCTP_LibraryParameters *params)
{
    ENTER_LIBRARY("sctp_setLibraryParameters");

    CHECK_LIBRARY;
    if (params == NULL) {
        LEAVE_LIBRARY("sctp_setLibraryParameters");
        return SCTP_PARAMETER_PROBLEM;
    }

    event_logi(VERBOSE, "sctp_setLibraryParameters: Parameter sendAbortForOOTB is %s",
                        (sendAbortForOOTB==TRUE)?"TRUE":"FALSE");
    if (params->sendOotbAborts == 0) {
        sendAbortForOOTB = FALSE;
    } else if (params->sendOotbAborts == 1) {
        sendAbortForOOTB = TRUE;
    } else {
        LEAVE_LIBRARY("sctp_setLibraryParameters");
        return SCTP_PARAMETER_PROBLEM;
    }
    if (params->checksumAlgorithm == SCTP_CHECKSUM_ALGORITHM_CRC32C ||
        params->checksumAlgorithm == SCTP_CHECKSUM_ALGORITHM_ADLER32) {
        if (checksumAlgorithm != params->checksumAlgorithm) {
            checksumAlgorithm = params->checksumAlgorithm;
            set_checksum_algorithm(checksumAlgorithm);
        } /* else nothing changes */
    } else {
        LEAVE_LIBRARY("sctp_setLibraryParameters");
        return SCTP_PARAMETER_PROBLEM;
    }

    if (params->supportPRSCTP == 0) {
        librarySupportsPRSCTP = FALSE;
    } else if (params->supportPRSCTP == 1) {
        librarySupportsPRSCTP = TRUE;
    } else {
        LEAVE_LIBRARY("sctp_setLibraryParameters");
        return SCTP_PARAMETER_PROBLEM;
    }
    if (params->supportADDIP == 0) {
        supportADDIP = FALSE;
    } else if (params->supportADDIP == 1) {
        supportADDIP = TRUE;
    } else {
        LEAVE_LIBRARY("sctp_setLibraryParameters");
        return SCTP_PARAMETER_PROBLEM;
    }

    event_logi(INTERNAL_EVENT_0, "sctp_setLibraryParameters: Set Parameter sendAbortForOOTB to %s",
                                  (sendAbortForOOTB==TRUE)?"TRUE":"FALSE");
    event_logi(INTERNAL_EVENT_0, "sctp_setLibraryParameters: Checksum Algorithm is now %s",
                                  (checksumAlgorithm==SCTP_CHECKSUM_ALGORITHM_CRC32C)?"CRC32C":"ADLER32");
    event_logi(INTERNAL_EVENT_0, "sctp_setLibraryParameters: Support of PRSCTP is now %s",
                                  (params->supportPRSCTP==TRUE)?"ENABLED":"DISABLED");
    event_logi(INTERNAL_EVENT_0, "sctp_setLibraryParameters: Support of ADDIP is now %s",
                                  (params->supportADDIP==TRUE)?"ENABLED":"DISABLED");

    LEAVE_LIBRARY("sctp_setLibraryParameters");
    return SCTP_SUCCESS;

}

int sctp_getLibraryParameters(SCTP_LibraryParameters *params)
{
    ENTER_LIBRARY("sctp_getLibraryParameters");

    CHECK_LIBRARY;
    if (params == NULL) {
        LEAVE_LIBRARY("sctp_getLibraryParameters");
        return SCTP_PARAMETER_PROBLEM;
    }

    event_logi(VERBOSE, "sctp_getLibraryParameters: Parameter sendAbortForOOTB is currently %s",
                        (sendAbortForOOTB==TRUE)?"TRUE":"FALSE");

    params->sendOotbAborts = sendAbortForOOTB;
    params->checksumAlgorithm = checksumAlgorithm;
    params->supportPRSCTP = (librarySupportsPRSCTP == TRUE) ? 1 : 0;
    params->supportADDIP = (supportADDIP == TRUE) ? 1 : 0;
    event_logi(INTERNAL_EVENT_0, "sctp_getLibraryParameters: Checksum Algorithm is currently %s",
                                  (checksumAlgorithm==SCTP_CHECKSUM_ALGORITHM_CRC32C)?"CRC32C":"ADLER32");

    LEAVE_LIBRARY("sctp_getLibraryParameters");
    return SCTP_SUCCESS;

}

/**
 * sctp_receive_unsent returns messages that have not been sent before the termination of an association
 *
 *  @param  associationID       ID of assocation.
 *  @param  buffer              pointer to a buffer that the application needs to pass. Data is copied there.
 *  @param  length              pointer to size of the buffer passed by application, contains actual length
 *                              of the copied chunk after the function call.
 *  @param  streamID            pointer to the stream id, where data should have been sent
 *  @param  streamSN            pointer to stream sequence number of the data chunk that was not sent
 *  @param  protocolID          pointer to the protocol ID of the unsent chunk
 *  @return number of unsent chunks still in the queue, else error code as  SCTP_NO_CHUNKS_IN_QUEUE, or
 *  SCTP_PARAMETER_PROBLEM, SCTP_WRONG_STATE, SCTP_ASSOC_NOT_FOUND, SCTP_LIBRARY_NOT_INITIALIZED
 */
int sctp_receiveUnsent(unsigned int associationID, unsigned char *buffer, unsigned int *length,
                       unsigned int *tsn, unsigned short *streamID, unsigned short *streamSN,
                       unsigned int* protocolId, unsigned char* flags, void** context)
{
    int result;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_receiveUnsent");

    CHECK_LIBRARY;

    if (buffer == NULL || length == NULL || tsn==NULL || streamID == NULL || streamSN == NULL || protocolId == NULL) {
        LEAVE_LIBRARY("sctp_receiveUnsent");
        return SCTP_PARAMETER_PROBLEM;
    }
    currentAssociation = retrieveAssociationForced(associationID);

    if (currentAssociation != NULL) {
        if (currentAssociation->deleted == FALSE) {
            result =  SCTP_WRONG_STATE;
        } else if (fc_readNumberOfUnsentChunks() == 0) {
            result = SCTP_NO_CHUNKS_IN_QUEUE;
        } else {
            result = fc_dequeueOldestUnsentChunk(buffer, length, tsn, streamID, streamSN, protocolId, flags,context);
        }
    } else {
        error_logi(ERROR_MAJOR, "sctp_receiveUnsent : association %u does not exist", associationID);
        result = SCTP_ASSOC_NOT_FOUND;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_receiveUnsent");
    return result;

}

/**
 * sctp_receive_unacked returns messages that were already put on the wire, but have not been
 * acknowledged by the peer before termination of the association
 *
 *  @param  associationID       ID of assocation.
 *  @param  buffer              pointer to a buffer that the application needs to pass. Data is copied there.
 *  @param  length              pointer to size of the buffer passed by application, contains actual length
 *                              of the copied chunk after the function call.
 *  @param  streamID            pointer to the stream id, where data should have been sent
 *  @param  streamSN            pointer to stream sequence number of the data chunk that was not acked
 *  @param  protocolID          pointer to the protocol ID of the unacked chunk
 *  @return number of unacked chunks still in the queue, else SCTP_NO_CHUNKS_IN_QUEUE if no chunks there, else
 *  appropriate error code:  SCTP_PARAMETER_PROBLEM, SCTP_WRONG_STATE, SCTP_ASSOC_NOT_FOUND, SCTP_LIBRARY_NOT_INITIALIZED
*/
int sctp_receiveUnacked(unsigned int associationID, unsigned char *buffer, unsigned int *length,
                        unsigned int *tsn, unsigned short *streamID, unsigned short *streamSN,
                        unsigned int* protocolId,unsigned char* flags, void** context)
{
    int result;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_receiveUnacked");

    CHECK_LIBRARY;

    if (buffer == NULL || length == NULL || tsn==NULL || streamID == NULL || streamSN == NULL || protocolId == NULL) {
        LEAVE_LIBRARY("sctp_receiveUnacked");
        return SCTP_PARAMETER_PROBLEM;
    }
    currentAssociation = retrieveAssociationForced(associationID);

    if (currentAssociation != NULL) {
        if (currentAssociation->deleted == FALSE) {
            result =  SCTP_WRONG_STATE;
        } else if (rtx_readNumberOfUnackedChunks() == 0) {
            result = SCTP_NO_CHUNKS_IN_QUEUE;
        } else {
            result = rtx_dequeueOldestUnackedChunk(buffer, length, tsn, streamID, streamSN, protocolId, flags,context);
        }
    } else {
        error_logi(ERROR_MAJOR, "sctp_receiveUnacked : association %u does not exist", associationID);
        result = SCTP_ASSOC_NOT_FOUND;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_receiveUnacked");
    return result;



}


/**
 * sctp_getPrimary returns the index of the current primary path
 * @param  associationID       ID of assocation.
 * @return  the index of the current primary path, or -1 on error
 */
short sctp_getPrimary(unsigned int associationID)
{
    short primary;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    ENTER_LIBRARY("sctp_getPrimary");

    CHECK_LIBRARY;

    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        event_logi(VERBOSE, "sctp_getPrimary: Association %u", associationID);
        primary = pm_readPrimaryPath();
    }else{
        error_logi(ERROR_MAJOR, "sctp_getPrimary : association %u does not exist", associationID);
        primary = SCTP_ASSOC_NOT_FOUND;
    }

    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_getPrimary");
    return primary;
}

int sctp_getInstanceID(unsigned int associationID, unsigned short* instanceID)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;
    int result=0;

    ENTER_LIBRARY("sctp_getInstanceID");

    CHECK_LIBRARY;
    if (instanceID == NULL) {
        LEAVE_LIBRARY("sctp_getInstanceID");
        return -1;
    }
    currentAssociation = retrieveAssociationForced(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        event_logii(VERBOSE, "sctp_getInstanceID: Association %u, Instance %u",
            associationID, sctpInstance->sctpInstanceName);
        (*instanceID) =  sctpInstance->sctpInstanceName;
    }else{
        error_logi(ERROR_MINOR, "sctp_getInstanceID: association %u does not exist", associationID);
        result = 1;
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    LEAVE_LIBRARY("sctp_getInstanceID");
    return result;
}

/* ----------------------------------------------------------------------------------------*/
/* ------------------------------------ HELPER FUNCTIONS from adaptation ------------------*/
/* ----------------------------------------------------------------------------------------*/
#ifndef WIN32
int sctp_registerUdpCallback(unsigned char me[],
                             unsigned short my_port,
                             sctp_socketCallback scf)
{
    int result;

    ENTER_LIBRARY("sctp_registerUdpCallback");

    CHECK_LIBRARY;
    result = adl_registerUdpCallback(me,my_port,scf);

    LEAVE_LIBRARY("sctp_registerUdpCallback");
    return result;
}

int sctp_unregisterUdpCallback(int udp_sfd)
{
    int result;

    ENTER_LIBRARY("sctp_unregisterUdpCallback");
    CHECK_LIBRARY;
    result = adl_unregisterUdpCallback(udp_sfd);
    LEAVE_LIBRARY("sctp_unregisterUdpCallback");
    return result;
}

int sctp_sendUdpData(int sfd, unsigned char* buf, int length,
                     unsigned char destination[], unsigned short dest_port)
{
    int result;

    ENTER_LIBRARY("sctp_sendUdpData");
    CHECK_LIBRARY;
    result = adl_sendUdpData(sfd, buf, length, destination, dest_port);
    LEAVE_LIBRARY("sctp_sendUdpData");
    return result;
}
#endif

int sctp_registerStdinCallback(sctp_StdinCallback sdf, char* buffer, int length)
{
    int result;

    ENTER_LIBRARY("sctp_registerStdinCallback");
    CHECK_LIBRARY;
    result = adl_registerStdinCallback(sdf, buffer, length);
    LEAVE_LIBRARY("sctp_registerStdinCallback");
    return result;
}

int sctp_unregisterStdinCallback()
{
    int result;

    ENTER_LIBRARY("sctp_unregisterStdinCallback");
    CHECK_LIBRARY;
    result = adl_unregisterStdinCallback();
    LEAVE_LIBRARY("sctp_registerStdinCallback");
    return result;

}

#ifndef WIN32
int sctp_registerUserCallback(int fd, sctp_userCallback sdf, void* userData, short int eventMask)
{
    int result;

    ENTER_LIBRARY("sctp_registerUserCallback");
    CHECK_LIBRARY;
    result = adl_registerUserCallback(fd, sdf, userData, eventMask);
    LEAVE_LIBRARY("sctp_registerUserCallback");
    return result;
}

int sctp_unregisterUserCallback(int fd)
{
    int result;

    ENTER_LIBRARY("sctp_unregisterUserCallback");
    CHECK_LIBRARY;
    result = adl_unregisterUserCallback(fd);
    LEAVE_LIBRARY("sctp_registerUserCallback");
    return result;

}
#endif

unsigned int sctp_startTimer(unsigned int seconds , unsigned int microseconds,
                        sctp_timerCallback timer_cb, void *param1, void *param2)
{
    unsigned int result;

    ENTER_LIBRARY("sctp_startTimer");
    CHECK_LIBRARY;
    result = adl_startMicroTimer(seconds, microseconds, timer_cb,TIMER_TYPE_USER, param1, param2);
    LEAVE_LIBRARY("sctp_startTimer");
    return result;
}

int sctp_stopTimer(unsigned int tid)
{
    int result;

    ENTER_LIBRARY("sctp_stopTimer");
    CHECK_LIBRARY;
    result = adl_stopTimer(tid);
    LEAVE_LIBRARY("sctp_stopTimer");
    return result;

}

unsigned int sctp_restartTimer(unsigned int timer_id, unsigned int seconds, unsigned int microseconds)
{
    int result;

    ENTER_LIBRARY("sctp_restartTimer");
    CHECK_LIBRARY;
    result = adl_restartMicroTimer(timer_id, seconds, microseconds);
    LEAVE_LIBRARY("sctp_restartTimer");
    return result;
}

int sctp_getEvents(void)
{
    int result;

    ENTER_LIBRARY("sctp_getEvents");
    CHECK_LIBRARY;
    result = adl_getEvents();
    LEAVE_LIBRARY("sctp_getEvents");
    return result;
}

int sctp_eventLoop(void)
{
    int result;

    ENTER_LIBRARY("sctp_eventLoop");
    CHECK_LIBRARY;
    result = adl_eventLoop();
    LEAVE_LIBRARY("sctp_eventLoop");
    return result;
}

int sctp_extendedEventLoop(void (*lock)(void* data), void (*unlock)(void* data), void* data)
{
    int result;

    ENTER_LIBRARY("sctp_extendedEventLoop");
    CHECK_LIBRARY;
    result = adl_extendedEventLoop(lock, unlock, data);
    LEAVE_LIBRARY("sctp_extendedEventLoop");
    return result;
}


#ifdef BAKEOFF
int sctp_sendRawData(unsigned int associationID, short path_id,
                     unsigned char *buffer, unsigned int length)
{
    int result = 0;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    if (sctpLibraryInitialized == FALSE) return -1;


    /* Retrieve association from list  */
    currentAssociation = retrieveAssociation(associationID);

    if (currentAssociation != NULL) {
        sctpInstance = currentAssociation->sctpInstance;
        if (path_id >= 0) {
            if (path_id >= currentAssociation->noOfNetworks) {
                error_log(ERROR_MAJOR, "sctp_sendRawData: invalid destination address");
                sctpInstance = old_Instance;
                currentAssociation = old_assoc;
                return 1;
            }
        }
        event_logiii(INTERNAL_EVENT_1, "sctp_sendRawData(assoc:%u, path: %d): send %u bytes",associationID,
path_id,length);
        /* Forward chunk to the addressed association */
        result = mdi_send_message((SCTP_message *) buffer, length, path_id);

    } else {
        error_log(ERROR_MAJOR, "sctp_send: addressed association does not exist");
        result = 1;
    }

    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
    return result;
}                               /* end: sctp_send */
#endif

/*------------------- Functions called by the SCTP bundling --------------------------------------*/

/**
 * Used by bundling to send a SCTP-datagramm.
 *
 * Bundling passes a static pointer and leaves space for common header, so
 * we can fill that header in up front !
 * Before calling send_message at the adaption-layer, this function does:
 * \begin{itemize}
 * \item add the SCTP common header to the message
 * \item convert the SCTP message to a byte string
 * \item retrieve the socket-file descriptor of the SCTP-instance
 * \item retrieve the destination address
 * \item retrieve destination port ???
 * \end{itemize}
 *
 *  @param SCTP_message     SCTP message as a struct (i.e. common header and chunks)
 *  @param length           length of complete SCTP message.
 *  @param destAddresIndex  Index of address in the destination address list.
 *  @return                 Errorcode (0 for good case: length bytes sent; 1 or -1 for error)
*/
int mdi_send_message(SCTP_message * message, unsigned int length, short destAddressIndex)
{
    union sockunion dest_su, *dest_ptr;
    SCTP_simple_chunk *chunk;
    unsigned char tos = 0;
    unsigned short dIdx;
    int txmit_len = 0;
    guchar hoststring[SCTP_MAX_IP_LEN];


    if (message == NULL) {
        error_log(ERROR_MINOR, "mdi_send_message: no message to send !!!");
        return 1;
    }

    chunk = (SCTP_simple_chunk *) & message->sctp_pdu[0];

    if (currentAssociation == NULL) {
        /* possible cases : initAck, no association exists yet, and OOTB packets
           use last from address as destination address */

        if (lastFromAddress == NULL) {
            error_log(ERROR_MAJOR, "mdi_send_message: lastFromAddress does not exist for initAck");
            return 1;
        } else {
            /* only if the sctp-message received before contained an init-chunk */
            memcpy(&dest_su, lastFromAddress, sizeof(union sockunion));
            dest_ptr = &dest_su;
            message->common_header.verification_tag = htonl(lastInitiateTag);
            /* write invalid tag value to lastInitiateTag (reset it) */
            lastInitiateTag = 0;
            /* swap ports */
            message->common_header.src_port = htons(mdi_readLastDestPort());
            message->common_header.dest_port = htons(mdi_readLastFromPort());
            event_logiii(VVERBOSE,
                         "mdi_send_message (I) : tag = %x, src_port = %u , dest_port = %u",
                         lastInitiateTag, mdi_readLastDestPort(), mdi_readLastFromPort());

            if (sctpInstance != NULL)
                tos = sctpInstance->default_ipTos;
            else
                tos = IPTOS_DEFAULT;
        }
    } else {

        if (destAddressIndex < -1 || destAddressIndex >= currentAssociation->noOfNetworks) {
            error_log(ERROR_MAJOR, "mdi_send_message: invalid destination address");
            return 1;
        }

        if (destAddressIndex != -1) {
            /* Use given destination address from current association */
            dest_ptr = &(currentAssociation->destinationAddresses[destAddressIndex]);
        } else { /* use last from address */
            if (lastFromAddress == NULL) {
                dIdx = pm_readPrimaryPath();
                event_logii(VVERBOSE,  "mdi_send_message : sending to primary with index %u (with %u paths)",
                    dIdx, currentAssociation->noOfNetworks);

                if ((dIdx == 0xFFFF)|| (dIdx >= currentAssociation->noOfNetworks)) {
                    error_log(ERROR_MAJOR, "mdi_send_message: could not get primary address");
                    return 1;
                }
                dest_ptr = &(currentAssociation->destinationAddresses[dIdx]);
            } else {
                event_log(VVERBOSE,  "mdi_send_message : last From Address was not NULL");
                memcpy(&dest_su, lastFromAddress, sizeof(union sockunion));
                dest_ptr = &dest_su;
            }
        }

        if (isInitAckChunk(chunk)) {
            /* is true in case of an init-collision, normally when an initAck is sent
               no association exist and the last lastInitiateTag is used in the initAck. This
               is handled in the case above, where no association exists.
               Or when we respond to SHUTDOWN_ACK, see section 8.4.5)
             */
            if (lastInitiateTag == 0) {
                error_log(ERROR_MAJOR, "mdi_send_message: No verification tag");
                return 1;
            }

            message->common_header.verification_tag = htonl(lastInitiateTag);
        } else {
            message->common_header.verification_tag = htonl(currentAssociation->tagRemote);
        }

        message->common_header.src_port = htons(currentAssociation->localPort);
        message->common_header.dest_port = htons(currentAssociation->remotePort);

        event_logiii(VVERBOSE,
                     "mdi_send_message (II): tag = %x, src_port = %u , dest_port = %u",
                     ntohl(message->common_header.verification_tag),
                     currentAssociation->localPort, currentAssociation->remotePort);
        tos = currentAssociation->ipTos;
    }

    /* calculate and insert checksum */
    aux_insert_checksum((unsigned char *) message, length);

    switch (sockunion_family(dest_ptr)) {
    case AF_INET:
        txmit_len = adl_send_message(sctp_socket, message, length, dest_ptr, tos);
        break;
#ifdef HAVE_IPV6
    case AF_INET6:
        txmit_len = adl_send_message(ipv6_sctp_socket, message, length, dest_ptr, tos);
        break;
#endif
    default:
        error_log(ERROR_MAJOR, "mdi_send_message: Unsupported AF_TYPE");
        break;
    }

    adl_sockunion2str(dest_ptr, hoststring, SCTP_MAX_IP_LEN);
    event_logiii(INTERNAL_EVENT_0, "sent SCTP message of %d bytes to %s, result was %d",
                    length, hoststring, txmit_len);

    return (txmit_len == (int)length) ? 0 : -1;

}                               /* end: mdi_send_message */



/*------------------- Functions called by the SCTP to forward primitives to ULP ------------------*/


/**
 *  indicates new data has arrived from peer (chapter 10.2.) destined for the ULP
 *
 *  @param streamID  received data belongs to this stream
 *  @param  length   so many bytes have arrived (may be used to reserve space)
 *  @param  protoID  the protocol ID of the arrived payload
 *  @param  unordered  unordered flag (TRUE==1==unordered, FALSE==0==normal,numbered chunk)
 */
void mdi_dataArriveNotif(unsigned short streamID, unsigned int length, unsigned short streamSN,
                         unsigned int tsn, unsigned int protoID, unsigned int unordered)
{

    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    if (currentAssociation != NULL) {

        event_logiiii(INTERNAL_EVENT_0, "mdi_dataArriveNotif(assoc %u, streamID %u, length %u, tsn %u)",
               currentAssociation->assocId, streamID,  length, tsn);
        /* Forward dataArriveNotif to the ULP */
        if (sctpInstance->ULPcallbackFunctions.dataArriveNotif) {
            ENTER_CALLBACK("dataArriveNotif");
            sctpInstance->ULPcallbackFunctions.dataArriveNotif(currentAssociation->assocId,
                                                               streamID,
                                                               length,
                                                               streamSN,
                                                               tsn,
                                                               protoID,
                                                               unordered,
                                                               currentAssociation->ulp_dataptr);
            LEAVE_CALLBACK("dataArriveNotif");
        }
    } else {
        error_log(ERROR_MAJOR, "mdi_dataArriveNotif: association not set");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
}                               /* end: mdi_dataArriveNotif */



/**
 * indicates a change of network status (chapter 10.2.C). Calls the respective ULP callback function.
 * @param  destinationAddress   index to address that has changed
 * @param  newState             state to which indicated address has changed (PM_ACTIVE/PM_INACTIVE)
 */
void mdi_networkStatusChangeNotif(short destinationAddress, unsigned short newState)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;
    if (currentAssociation != NULL) {

        event_logiii(INTERNAL_EVENT_0, "mdi_networkStatusChangeNotif(assoc %u, path-id %d, state %u)",
               currentAssociation->assocId, destinationAddress,newState);
        if (sctpInstance->ULPcallbackFunctions.networkStatusChangeNotif) {
            ENTER_CALLBACK("networkStatusChangeNotif");
            sctpInstance->ULPcallbackFunctions.networkStatusChangeNotif(currentAssociation->assocId,
                                                                        destinationAddress, newState,
                                                                        currentAssociation->ulp_dataptr);
            LEAVE_CALLBACK("networkStatusChangeNotif");
        }
    } else {
        error_log(ERROR_MAJOR, "mdi_networkStatusChangeNotif: association not set");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
}                               /* end: mdi_networkStatusChangeNotif */



/**
 * indicates a send failure (chapter 10.2.B). Calls the respective ULP callback function.
 * @param data          pointer to the data that has not been sent
 * @param dataLength    length of the data that has not been sent
 * @param context       from sendChunk (CHECKME : may be obsolete ?)
 */
void mdi_sendFailureNotif(unsigned char *data, unsigned int dataLength, unsigned int *context)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;
    if (currentAssociation != NULL) {
        if(sctpInstance->ULPcallbackFunctions.sendFailureNotif) {
            ENTER_CALLBACK("sendFailureNotif");
            sctpInstance->ULPcallbackFunctions.sendFailureNotif(currentAssociation->assocId,
                                                                data, dataLength, context,
                                                                currentAssociation->ulp_dataptr);
            LEAVE_CALLBACK("sendFailureNotif");
        }
    } else {
        error_log(ERROR_MAJOR, "mdi_sendFailureNotif: association not set");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
}                               /* end: mdi_sendFailureNotif */


/**
 * indicates that association has been gracefully shut down (chapter 10.2.H).
 * Calls the respective ULP callback function.
 */
void mdi_peerShutdownReceivedNotif(void)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;
    if (currentAssociation != NULL) {

        event_logi(INTERNAL_EVENT_0, "mdi_peerShutdownReceivedNotif(assoc %u)", currentAssociation->assocId);
        if(sctpInstance->ULPcallbackFunctions.peerShutdownReceivedNotif) {
            ENTER_CALLBACK("shutdownCompleteNotif");
            sctpInstance->ULPcallbackFunctions.peerShutdownReceivedNotif(currentAssociation->assocId,
                                                                         currentAssociation->ulp_dataptr);
            LEAVE_CALLBACK("peerShutdownReceivedNotif");
        }
    } else {
        error_log(ERROR_MAJOR, "mdi_peerShutdownReceivedNotif: association not set");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
}


/**
 * indicates that association has been gracefully shut down (chapter 10.2.H).
 * Calls the respective ULP callback function.
 */
void mdi_shutdownCompleteNotif(void)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;
    if (currentAssociation != NULL) {

        event_logi(INTERNAL_EVENT_0, "mdi_shutdownCompleteNotif(assoc %u)", currentAssociation->assocId);
        if(sctpInstance->ULPcallbackFunctions.shutdownCompleteNotif) {
            ENTER_CALLBACK("shutdownCompleteNotif");
            sctpInstance->ULPcallbackFunctions.shutdownCompleteNotif(currentAssociation->assocId,
                                                                     currentAssociation->ulp_dataptr);
            LEAVE_CALLBACK("shutdownCompleteNotif");
        }
    } else {
        error_log(ERROR_MAJOR, "mdi_shutdownCompleteNotif: association not set");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
}


/**
 * indicates that a restart has occured(chapter 10.2.G).
 * Calls the respective ULP callback function.
 */
void mdi_restartNotif(void)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;
    if (currentAssociation != NULL) {

        event_logi(INTERNAL_EVENT_0, "mdi_restartNotif(assoc %u)", currentAssociation->assocId);

        if(sctpInstance->ULPcallbackFunctions.restartNotif) {
            ENTER_CALLBACK("restartNotif");
            sctpInstance->ULPcallbackFunctions.restartNotif(currentAssociation->assocId,
                                                            currentAssociation->ulp_dataptr);
            LEAVE_CALLBACK("restartNotif");
        }
    } else {
        error_log(ERROR_MAJOR, "mdi_restartNotif: association not set");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
}



/**
 * indicates that communication was lost to peer (chapter 10.2.E). Calls the respective ULP callback function.
 *
 * @param  status  type of event, that has caused the association to be terminated
 */
void mdi_communicationLostNotif(unsigned short status)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    if (currentAssociation != NULL) {

        event_logii(INTERNAL_EVENT_0, "mdi_communicationLostNotif(assoc %u, status %u)",
            currentAssociation->assocId, status);
        if(sctpInstance->ULPcallbackFunctions.communicationLostNotif) {
            ENTER_CALLBACK("communicationLostNotif");
            sctpInstance->ULPcallbackFunctions.communicationLostNotif(currentAssociation->assocId,
                                                                      status,
                                                                      currentAssociation->ulp_dataptr);
            LEAVE_CALLBACK("communicationLostNotif");
        }
    } else {
        error_log(ERROR_MAJOR, "mdi_communicationLostNotif: association not set");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
}                               /* end: mdi_communicationLostNotif */



/**
 * indicates that an association is established (chapter 10.2.D).
 *
 * @param status     type of event that caused association to come up;
 *                   either SCTP_COMM_UP_RECEIVED_VALID_COOKIE, SCTP_COMM_UP_RECEIVED_COOKIE_ACK
 *                   or SCTP_COMM_UP_RECEIVED_COOKIE_RESTART
 */
void mdi_communicationUpNotif(unsigned short status)
{
    union sockunion lastAddress;
    int result, pathNum;
    short primaryPath;
    unsigned short noOfInStreams;
    unsigned short noOfOutStreams;
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    if (currentAssociation != NULL) {
        /* Find primary path */
        result = mdi_readLastFromAddress(&lastAddress);

        if (result != 1) {

            for (primaryPath = 0; primaryPath < currentAssociation->noOfNetworks; primaryPath++) {
                if (adl_equal_address
                    (&(currentAssociation->destinationAddresses[primaryPath]), &lastAddress)) {
                    break;
                }
            }
        } else {
            primaryPath = 0;
        }
        if (primaryPath >= currentAssociation->noOfNetworks) primaryPath = 0;

        /* set number of paths and primary path at pathmanegement and start heartbeat */
        pm_setPaths(currentAssociation->noOfNetworks, primaryPath);

        se_readNumberOfStreams(&noOfInStreams, &noOfOutStreams);


        event_logiii(VERBOSE,
                     "Distribution: COMM-UP, assocId: %u, status: %u, noOfNetworks: %u",
                     currentAssociation->assocId, status, currentAssociation->noOfNetworks);
        event_logii(VERBOSE, "noOfInStreams: %u,noOfOutStreams  %u", noOfInStreams, noOfOutStreams);
        /* FIXME (???) : retreive sctp-instance from list */

        /* Forward mdi_communicationup Notification to the ULP */
        if(sctpInstance->ULPcallbackFunctions.communicationUpNotif) {
            ENTER_CALLBACK("communicationUpNotif");
            currentAssociation->ulp_dataptr = sctpInstance->ULPcallbackFunctions.communicationUpNotif(
                                                                currentAssociation->assocId,
                                                                status,
                                                                currentAssociation->noOfNetworks,
                                                                noOfInStreams, noOfOutStreams,
                                                                currentAssociation->supportsPRSCTP,
                                                                currentAssociation->ulp_dataptr);
            LEAVE_CALLBACK("communicationUpNotif");
            if (currentAssociation != NULL) {
                for (pathNum = 0; pathNum < currentAssociation->noOfNetworks; pathNum++) {
		    if (pm_readState((short)pathNum) == PM_ACTIVE) {
			mdi_networkStatusChangeNotif((short)pathNum, PM_ACTIVE);
		    }
		}
	    }
        } else {
            currentAssociation->ulp_dataptr = NULL;
        }
    } else {
        error_log(ERROR_MAJOR, "mdi_communicationUpNotif: association not set");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
}                               /* end: mdi_communicationLostNotif */


/**
 * Function that notifies the ULP of a change in the queue status.
 * I.e. a limit may be exceeded, and therefore subsequent send-primitives will
 * fail, OR the queue length has dropped below a previously set queue length
 *
 * @param  queueType i.e. an outbound queue, stream-engine queue, per stream queue (?)
 * @param  queueId   i.e. i.e. stream id for a per stream queue
 * @param  queueLen  in bytes or in messages, depending on the queue type
 */
void mdi_queueStatusChangeNotif(int queueType, int queueId, int queueLen)
{
    SCTP_instance *old_Instance = sctpInstance;
    Association *old_assoc = currentAssociation;

    if (currentAssociation != NULL) {

        event_logiiii(INTERNAL_EVENT_0, "mdi_queueStatusChangeNotif(assoc %u, queueType %d, queueId %d, len: %d)",
            currentAssociation->assocId, queueType,queueId,queueLen);
        if (sctpInstance->ULPcallbackFunctions.queueStatusChangeNotif) {
            ENTER_CALLBACK("queueStatusChangeNotif");
            sctpInstance->ULPcallbackFunctions.queueStatusChangeNotif(currentAssociation->assocId,
                                                                      queueType, queueId, queueLen,
                                                                      currentAssociation->ulp_dataptr);
            LEAVE_CALLBACK("queueStatusChangeNotif");
        }
    } else {
        error_log(ERROR_MAJOR, "mdi_queueuStatusChangeNotif: association not set");
    }
    sctpInstance = old_Instance;
    currentAssociation = old_assoc;
}                               /* end: mdi_queueStatusChangeNotif */


/*------------------- Functions called by the SCTP to get current association data----------------*/

/* When processing external events from outside the SCTP (socket events, timer events and
   function calls from the ULP), first the data of the addressed association are read
   from the list of associations and stored in a private but static datastructure.
   Elements of this association data can be read by the following functions.
*/


/* The following functions return pointer to data of modules of the SCTP. As only these
   modules know the exact type of these data structures, so the returned pointer are
   of type void.
*/

/**
 * function to return a pointer to the flow control module of this association
 * @return pointer to the flow control data structure,  null in case of error.
 */
void *mdi_readFlowControl(void)
{
    if (currentAssociation == NULL) {
        event_log(VVERBOSE, "mdi_readFlowControl: association not set");
        return NULL;
    } else {
        return currentAssociation->flowControl;
    }
}



/**
 * function to return a pointer to the reliable transfer-module of this association
 * @return pointer to the reliable transfer data structure, null in case of error.
 */
void *mdi_readReliableTransfer(void)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_readReliableTransfer: association not set");
        return NULL;
    } else {
/*        event_logii(VVERBOSE, "setting RelTransfer MemoryAddress %x, for association %u",
              currentAssociation->reliableTransfer, currentAssociation->assocId); */
        return currentAssociation->reliableTransfer;
    }
}



/**
 * function to return a pointer to the receiver module of this association
 * @return pointer to the RX-control data structure, null in case of error.
 */
void *mdi_readRX_control(void)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_readRX_control: association not set");
        return NULL;
    } else {
        return currentAssociation->rx_control;
    }
}



/**
 * function to return a pointer to the stream-engine module of this association
 * @return pointer to the stream engine data structure, null in case of error.
 */
void *mdi_readStreamEngine(void)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_readStreamEngine: association not set");
        return NULL;
    } else {
        event_logii(VVERBOSE, "setting StreamEngine MemoryAddress %x, for association %u",
              currentAssociation->streamengine, currentAssociation->assocId);
        return currentAssociation->streamengine;
    }
}



/**
 * function to return a pointer to the path management module of this association
 * @return  pointer to the pathmanagement data structure, null in case of error.
 */
void *mdi_readPathMan(void)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_readPathMan: association not set");
        return NULL;
    } else {
        return currentAssociation->pathMan;
    }
}


/**
 * function to return a pointer to the bundling module of this association
 * @return   pointer to the bundling data structure, null in case of error.
 */
void *mdi_readBundling(void)
{
    if (currentAssociation == NULL) {
        /*
        error_log(ERROR_MINOR, "mdi_readBundling: association not set");
        */
        return NULL;
    } else {
        return currentAssociation->bundling;
    }
}



/**
 * function to return a pointer to the state machine controller of this association
 * @return pointer to the SCTP-control data structure, null in case of error.
 */
void *mdi_readSCTP_control(void)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_readSCTP_control: association not set");
        return NULL;
    }
    return currentAssociation->sctp_control;
}


/**
 * function to read the association id of the current association
 * @return   association-ID of the current association;
 *           0 means the association is not set (an error).
 */
unsigned int mdi_readAssociationID(void)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_readAssociationID: association not set");
        return 0;
    } else {
        return currentAssociation->assocId;
    }
}

/**
 * function to read the current local tag of the current association
 * @return   association-ID of the current association;
 *           0 means the association is not set (an error).
 */
unsigned int mdi_readLocalTag(void)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_readLocalTag: association not set");
        return 0;
    } else {
        return currentAssociation->tagLocal;
    }
}



/**
 * function to read the tag that the peer within the current association uses
 * @return   tag value of the peer within the current association;
 *           CHECKME: can tag legally be 0 ?
 *           0 means the association is not set (an error).
 */
unsigned int mdi_readTagRemote(void)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_readAssociationID: association not set");
        return 0;
    } else {
        return currentAssociation->tagRemote;
    }
}

unsigned int mdi_getUnusedAssocId(void)
{
    Association * tmp = NULL;
    unsigned int newId;

    do {
        if(nextAssocId == 0) {
           nextAssocId++;
        }
        newId = nextAssocId;
        tmp   = retrieveAssociation(newId);
        nextAssocId++;
    } while (tmp != NULL);

    return newId;
}

unsigned short mdi_getUnusedInstanceName(void)
{
    SCTP_instance* tmp = NULL;
    unsigned short newId;
    unsigned int   i;

    for(i = 0;i < 65536;i++) {
        if(lastSCTP_instanceName == 0) {
           lastSCTP_instanceName++;
        }
        newId = lastSCTP_instanceName;
        tmp   = retrieveInstance(newId);
        lastSCTP_instanceName++;
        if(tmp == NULL) {
           return(newId);
        }
    }

    return(0);
}

/**
 * generates a random tag value for a new association, but not 0
 * @return   generates a random tag value for a new association, but not 0
 */
unsigned int mdi_generateTag(void)
{
    unsigned int tag;

    while ((tag = adl_random()) == 0);

    return tag;
}



/**
 * generates a random tsn value for a new association (may also be 0)
 * @return   generates a random tsn value for a new association (may also be 0)
 */
unsigned int mdi_generateStartTSN(void)
{
    return adl_random();
}



/*------------- functions for the cookie mechanism --------------------------------------------*/

/**
 * sets the address from which the last datagramm was received (host byte order).
 * @returns  0 if successful, 1 if address could not be set !
 */
int mdi_readLastFromAddress(union sockunion* fromAddress)
{
    if (lastFromAddress == NULL) {
        error_log(ERROR_FATAL, "mdi_readLastFromAddress: no last from address");
    } else {
        memcpy(fromAddress, lastFromAddress, sizeof(union sockunion));
        return 0;
    }
    return 1;
}

/**
 * sets the address from which the last datagramm was received (host byte order).
 * @returns  0 if successful, 1 if address could not be set !
 */
int mdi_readLastDestAddress(union sockunion* destAddress)
{
    if (lastDestAddress == NULL) {
        error_log(ERROR_MAJOR, "mdi_readLastDestAddress: no last dest address");
    } else {
        memcpy(destAddress, lastDestAddress, sizeof(union sockunion));
        return 0;
    }
    return 1;
}


/**
 * read the index of the path from which the last DG was received (-1 if no DG was received)
 * @return index of the path from which the last DG was received (-1 if no DG was received)
 */
short mdi_readLastFromPath(void)
{
    return lastFromPath;
}

/**
 * read the port of the sender of the last received DG (host byte order)
 * @return the port of the sender of the last received DG (host byte order)
 */
unsigned short mdi_readLastFromPort(void)
{
    if (lastFromAddress == NULL) {
        error_log(ERROR_MINOR, "readLastFromPort: no last from address");
        return 0;
    } else {
        return lastFromPort;
    }
}


/**
 * read the port of the destination of the last received DG (host byte order)
 * @return the port of the destination of the last received DG (host byte order)
 */
unsigned short mdi_readLastDestPort(void)
{
    if (lastFromAddress == NULL) {
        error_log(ERROR_MINOR, "readLastDestPort: no last from address");

        return 0;
    } else {
        return lastDestPort;
    }
}

/* write the initiate tag of a-side to be used as verification tag for the initAck */
void mdi_writeLastInitiateTag(unsigned int initiateTag)
{
    lastInitiateTag = initiateTag;
}

/* write the initiate tag of a-side to be used as verification tag for the initAck */
unsigned int mdi_readLastInitiateTag(void)
{
    return lastInitiateTag;
}

/* rewrite the initiate tag of peer in case of a peer reset. */
void mdi_rewriteTagRemote(unsigned int newInitiateTag)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_rewriteRemoteTag: association not set");
    } else {
        currentAssociation->tagRemote = newInitiateTag;
    }
}

/* rewrite the initiate tag of peer in case of a peer reset. */
void mdi_rewriteLocalTag(unsigned int newTag)
{
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_rewriteLocalTag: association not set");
    } else {
        currentAssociation->tagLocal = newTag;
    }
}


/*------------- functions to write and read addresses --------------------------------------------*/

short mdi_getIndexForAddress(union sockunion* address)
{
    short index = 0;

    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_getIndexForAddress: association not set");
        return -1;
    } else {
        if (currentAssociation->destinationAddresses == NULL) {
            error_log(ERROR_MINOR, "mdi_getIndexForAddress: addresses not set");
            return -1;
        }
                /* send cookie back to the address where we got it from     */
        for (index = 0; index < currentAssociation->noOfNetworks; index++)
            if (adl_equal_address(&(currentAssociation->destinationAddresses[index]),address)) break;
        if (index == currentAssociation->noOfNetworks) /* not found */
            return -1;

    }
    return index;

}

/**
 * copies destination addresses from the array passed as parameter to  the current association
 * @param addresses array that will hold the destination addresses after returning
 * @param noOfAddresses number of addresses that the peer has (and sends along in init/initAck)
 */
void mdi_writeDestinationAddresses(union sockunion addresses[MAX_NUM_ADDRESSES], int noOfAddresses)
{

    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_writeDestinationAddresses: association not set");
        return;
    } else {
        if (currentAssociation->destinationAddresses != NULL) {
            free(currentAssociation->destinationAddresses);
        }

        currentAssociation->destinationAddresses =
            (union sockunion *) malloc(noOfAddresses * sizeof(union sockunion));

        if (currentAssociation->destinationAddresses == NULL)
            error_log(ERROR_FATAL, "mdi_writeDestinationAddresses: out of memory");

        memcpy(currentAssociation->destinationAddresses, addresses,
               noOfAddresses * sizeof(union sockunion));

        currentAssociation->noOfNetworks = noOfAddresses;

        return;
    }
}


/**
 * Function that returns the number of incoming streams that this instance
 * is willing to handle !
 * @return maximum number of in-streams
 */
unsigned short mdi_readLocalInStreams(void)
{
    SCTP_instance temporary;
    GList* result = NULL;

    if (currentAssociation == NULL) {
        /* retrieve SCTP-instance with last destination port */
        lastDestPort = mdi_readLastDestPort();
        event_logi(VERBOSE, "mdi_readLocalInStreams(): Searching for SCTP Instance with Port %u ", lastDestPort);
        temporary.supportedAddressTypes = 0;
        temporary.has_INADDR_ANY_set = FALSE;
        temporary.has_IN6ADDR_ANY_set = FALSE;
        temporary.localPort = lastDestPort;
        temporary.noOfLocalAddresses = 1;
        if (lastDestAddress)
            temporary.localAddressList = lastDestAddress;
        else
            error_log(ERROR_FATAL, "lastDestAddress NULL in mdi_readLocalInStreams() - FIXME !");

        result = g_list_find_custom(InstanceList, &temporary, &CheckForAddressInInstance);
        if (result == NULL) {
            error_logi(ERROR_FATAL, "Could not find SCTP Instance for Port %u in List, FIXME !",lastDestPort);
        }
        sctpInstance = (SCTP_instance*)result->data;
    } else {
        /* retrieve SCTP-instance with SCTP-instance name in current association */
        temporary.sctpInstanceName = currentAssociation->sctpInstance->sctpInstanceName;
        event_logi(VERBOSE, "Searching for SCTP Instance with Name %u ", currentAssociation->sctpInstance->sctpInstanceName);
        result = g_list_find_custom(InstanceList, &temporary, &CompareInstanceNames);
        if (result == NULL) {
            error_logi(ERROR_FATAL, "Could not find SCTP Instance with name %u in List, FIXME !",
                currentAssociation->sctpInstance->sctpInstanceName);
        }
        sctpInstance = (SCTP_instance*)result->data;
    }
    return  sctpInstance->noOfInStreams;
}

/**
 * Function that returns the number of incoming streams that this instance
 * is willing to handle !
 * @return maximum number of in-streams
 */
unsigned short mdi_readLocalOutStreams(void)
{
    SCTP_instance temporary;
    GList* result = NULL;

    if (currentAssociation == NULL) {
        /* retrieve SCTP-instance with last destination port */
        lastDestPort = mdi_readLastDestPort();
        event_logi(VERBOSE, "Searching for SCTP Instance with Port %u ", lastDestPort);
        temporary.supportedAddressTypes = 0;
        temporary.localPort = lastDestPort;
        temporary.has_INADDR_ANY_set = FALSE;
        temporary.has_IN6ADDR_ANY_set = FALSE;
        temporary.noOfLocalAddresses = 1;
        if (lastDestAddress)
            temporary.localAddressList = lastDestAddress;
        else
            error_log(ERROR_FATAL, "lastDestAddress NULL in mdi_readLocalInStreams() - FIXME !");

        result = g_list_find_custom(InstanceList, &temporary, &CheckForAddressInInstance);
        if (result == NULL) {
            error_logi(ERROR_FATAL, "Could not find SCTP Instance for Port %u in List, FIXME !",lastDestPort);
        }
        sctpInstance = (SCTP_instance*)result->data;
    } else {
        /* retrieve SCTP-instance with SCTP-instance name in current association */
        temporary.sctpInstanceName = currentAssociation->sctpInstance->sctpInstanceName;
        event_logi(VERBOSE, "Searching for SCTP Instance with Name %u ", currentAssociation->sctpInstance->sctpInstanceName);
        result = g_list_find_custom(InstanceList, &temporary, &CompareInstanceNames);
        if (result == NULL) {
            error_logi(ERROR_FATAL, "Could not find SCTP Instance with name %u in List, FIXME !",
                       currentAssociation->sctpInstance->sctpInstanceName);
        }
        sctpInstance = (SCTP_instance*)result->data;
    }
    return  sctpInstance->noOfOutStreams;
}


/**
 * Copies local addresses of this instance into the array passed as parameter
 * CHECKME : does this function work in all circumstances ?
 * --> Under what conditions can we NOT find the SCTP instance ?
 *
 * @param addresses array that will hold the local host's addresses after returning
 * @param noOfAddresses number of addresses that local host/current association has
 */
void mdi_readLocalAddresses(union sockunion laddresses[MAX_NUM_ADDRESSES],
                            guint16 * noOfAddresses,
                            union sockunion *peerAddress,
                            unsigned int numPeerAddresses,
                            unsigned int addressTypes,
                            gboolean receivedFromPeer)
{

    unsigned int        count = 0, tmp;
    AddressScopingFlags filterFlags = (AddressScopingFlags)0;
    gboolean localHostFound=FALSE, linkLocalFound = FALSE, siteLocalFound = FALSE;


    if ((currentAssociation == NULL) && (sctpInstance == NULL)) {
        error_log(ERROR_FATAL, "mdi_readLocalAddresses: neither assoc nor instance set - error !");
        *noOfAddresses = 0;
        return;
    }
    if (sctpInstance == NULL) {
        error_log(ERROR_MAJOR, "mdi_readLocalAddresses: instance not set - program error");
        sctpInstance = currentAssociation->sctpInstance;
    }

    for (count = 0; count <  numPeerAddresses; count++)  {
        localHostFound |= mdi_addressListContainsLocalhost(1, &peerAddress[count]);
        linkLocalFound |= !( adl_filterInetAddress(&peerAddress[count], flag_HideLinkLocal));
        siteLocalFound |= !( adl_filterInetAddress(&peerAddress[count], flag_HideSiteLocal));
    }

    /* if (receivedFromPeer == FALSE) I send an INIT with my addresses to the peer */
    if ((receivedFromPeer == FALSE) && (localHostFound == TRUE)) {
        /* if paddress == loopback then add my loopback */
        filterFlags = flag_Default;
    } else if ((receivedFromPeer == FALSE) && (localHostFound == FALSE)) {
        /* only add loopback, if sending to a loopback */
        filterFlags = (AddressScopingFlags)(flag_Default|flag_HideLoopback);

    /* if (receivedFromPeer == TRUE) I got an INIT with addresses from the peer */
    } else if ((receivedFromPeer == TRUE) && (localHostFound == FALSE)) {
        /* this is from a normal address, get all except loopback */
        if (linkLocalFound) {
            filterFlags = (AddressScopingFlags)(flag_Default|flag_HideLoopback);
        } else if (siteLocalFound) {
            filterFlags = (AddressScopingFlags)(flag_Default| flag_HideLinkLocal|flag_HideLoopback);
        } else {
            filterFlags = (AddressScopingFlags)(flag_Default|flag_HideLocal);
        }
    } else  /* if ((receivedFromPeer == TRUE) && (localHostFound == TRUE)) */ {
        /* this is from a loopback, get all loopbacks */
        filterFlags = flag_Default;
    }

    count = 0;

    if (sctpInstance->has_INADDR_ANY_set == TRUE) {
        for (tmp = 0; tmp < myNumberOfAddresses; tmp++) {
            switch(sockunion_family( &(myAddressList[tmp]))) {
                case AF_INET :
                    if ((addressTypes & SUPPORT_ADDRESS_TYPE_IPV4) != 0) {
                        if ( adl_filterInetAddress(&(myAddressList[tmp]), filterFlags) == TRUE) {
                            memcpy(&(laddresses[count]), &(myAddressList[tmp]),sizeof(union sockunion));
                            count++;
                        }
                    }
                    break;
                default: break;
            }
        }
        event_logii(VERBOSE, "mdi_readLocalAddresses: found %u local addresses from INADDR_ANY (from %u)",
count,myNumberOfAddresses );    } else if (sctpInstance->has_IN6ADDR_ANY_set == TRUE) {
        for (tmp = 0; tmp < myNumberOfAddresses; tmp++) {
            switch(sockunion_family( &(myAddressList[tmp]))) {
                case AF_INET :
                    if ((addressTypes & SUPPORT_ADDRESS_TYPE_IPV4) != 0) {
                        if ( adl_filterInetAddress(&(myAddressList[tmp]), filterFlags) == TRUE) {
                            memcpy(&(laddresses[count]), &(myAddressList[tmp]),sizeof(union sockunion));
                            count++;
                        }
                    }
                    break;
#ifdef HAVE_IPV6
                case AF_INET6 :
                    if ((addressTypes & SUPPORT_ADDRESS_TYPE_IPV6) != 0) {
                        if ( adl_filterInetAddress(&(myAddressList[tmp]), filterFlags) == TRUE) {
                            memcpy(&(laddresses[count]), &(myAddressList[tmp]),sizeof(union sockunion));
                            count++;
                        }
                    }
                    break;
#endif
                default: break;
            }
        }
        event_logii(VERBOSE, "mdi_readLocalAddresses: found %u local addresses from IN6ADDR_ANY (from %u)", count,
myNumberOfAddresses);
    } else {
        for (tmp = 0; tmp < sctpInstance->noOfLocalAddresses; tmp++) {
            switch(sockunion_family( &(sctpInstance->localAddressList[tmp]))) {
                case AF_INET :
                    if ((addressTypes & SUPPORT_ADDRESS_TYPE_IPV4) != 0) {
                        if ( adl_filterInetAddress(&(sctpInstance->localAddressList[tmp]), filterFlags) == TRUE) {
                            memcpy(&(laddresses[count]), &(sctpInstance->localAddressList[tmp]),
                                    sizeof(union sockunion));
                            count++;
                        }
                    }
                    break;
#ifdef HAVE_IPV6
                case AF_INET6 :
                    if ((addressTypes & SUPPORT_ADDRESS_TYPE_IPV6) != 0) {
                        if ( adl_filterInetAddress(&(sctpInstance->localAddressList[tmp]), filterFlags) == TRUE) {
                            memcpy(&(laddresses[count]), &(sctpInstance->localAddressList[tmp]),
                                    sizeof(union sockunion));
                            count++;
                        }
                    }
                    break;
#endif
                default: break;
            }
        }
        event_logii(VERBOSE, "mdi_readLocalAddresses: found %u local addresses from instance (from %u)", count,
            sctpInstance->noOfLocalAddresses);
    }
    event_logi(INTERNAL_EVENT_0, "mdi_readLocalAddresses() : returning %u addresses !",count);
    /*
    if (count == 0) abort();
    */

    *noOfAddresses = count;
}



gboolean mdi_supportsPRSCTP(void)
{
    if (currentAssociation != NULL) {
        return  (currentAssociation->supportsPRSCTP && currentAssociation->peerSupportsPRSCTP);
    }
    if (sctpInstance != NULL) {
        return   sctpInstance->supportsPRSCTP;
    }
    return (librarySupportsPRSCTP);
}

gboolean mdi_peerSupportsPRSCTP(void)
{
    if (currentAssociation == NULL)
        return FALSE;
    return currentAssociation->peerSupportsPRSCTP;
}


int mdi_getDefaultRtoInitial(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_rtoInitial;
}
int mdi_getDefaultValidCookieLife(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_validCookieLife;
}
int mdi_getDefaultAssocMaxRetransmits(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_assocMaxRetransmits;
}
int mdi_getDefaultPathMaxRetransmits(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_pathMaxRetransmits;
}
int mdi_getDefaultMaxInitRetransmits(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_maxInitRetransmits;
}
int mdi_getDefaultMyRwnd()
{
    if (sctpInstance == NULL) return -1;
    else {
        event_logi(VVERBOSE, " mdi_getDefaultMyRwnd is %u", sctpInstance->default_myRwnd);
        return ((SCTP_instance*)sctpInstance)->default_myRwnd;
    }
}
int mdi_getDefaultRtoMin(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_rtoMin;
}

int mdi_getDefaultRtoMax(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_rtoMax;
}

int mdi_getDefaultMaxBurst(void)
{
    if (sctpInstance == NULL) return DEFAULT_MAX_BURST;
    else if (currentAssociation == NULL) return DEFAULT_MAX_BURST;
    else
	return (currentAssociation->sctpInstance->default_maxBurst);
}

int mdi_getDefaultDelay(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_delay;
}

int mdi_getDefaultIpTos(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_ipTos;
}
int mdi_getDefaultMaxSendQueue(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_maxSendQueue;
}
int mdi_getDefaultMaxRecvQueue(void* sctpInstance)
{
    if (sctpInstance == NULL) return -1;
    else
        return ((SCTP_instance*)sctpInstance)->default_maxRecvQueue;
}

unsigned int mdi_getSupportedAddressTypes(void)
{
    if (sctpInstance == NULL) return -1;
    else
        return sctpInstance->supportedAddressTypes;
}

/*------------- functions to set and clear the association data ----------------------------------*/

/**
 * Each module within SCTP that has timers implements its own timer call back
 *  functions. These are registered at the adaption layer when a timer is started
 *  and called directly at the module when the timer expires.
 *  setAssociationData allows SCTP-modules with timers to retrieve the data of the
 *  addressed association from the list of associations.
 *  For this purpose the association-ID must be included in one of the
 *  parameters of the start_timer function of the adaption-layer.
 *
 *  @param  associationID    the ID of the association
 *  @return 0 if successful, 1 if the association does not exist in the list
*/
unsigned short mdi_setAssociationData(unsigned int associationID)
{
    if (currentAssociation != NULL)
        error_log(ERROR_MINOR, "mdi_setAssociationData: previous assoc not cleared");

    /* retrieve association from list */
    currentAssociation = retrieveAssociation(associationID);
    if (currentAssociation == NULL) {
        error_log(ERROR_MINOR, "mdi_setAssociationData: association does not exist");
        return 1;
    }
    sctpInstance =  currentAssociation->sctpInstance;
    return 0;
}



/**
 * Clear the global association data.
 *  This function must be called after the association retrieved from the list
 *  with setAssociationData is no longer needed. This is the case after a time
 *  event has been handled.
 *
 *  @param  associationID    the ID of the association
 *  @return  0 if successful, 1 if association data has not been set, 2 wrong associationID
 */
unsigned short mdi_clearAssociationData(void)
{
    currentAssociation = NULL;
    sctpInstance = NULL;
    return 0;
}


/*------------------- Functions to create and delete associations --------------------------------*/

/**
 *  This function allocates memory for a new association.
 *  For the active side of an association, this function is called when ULP calls Associate
 *  For the passive side this function is called when a valid cookie message is received.
 *  It also creates all the modules path management, bundling and SCTP-control.
 *  The rest of the modules are created with mdi_initAssociation.
 *  The created association is put into the list of associations.
 *
 *  @param SCTP_InstanceName    identifier for an SCTP instance (if there are more)
 *  @param  local_port          src port (which this association listens to)
 *  @param  remote_port         destination port (peers source port)
 *  @param   tagLocal           randomly generated tag belonging to this association
 *  @param  primaryDestinitionAddress   index of the primary address
 *  @param  noOfDestinationAddresses    number of addresses the peer has
 *  @param  destinationAddressList      pointer to the array of peer's addresses
 *  @return 0 for success, else 1 for failure
 */
unsigned short
mdi_newAssociation(void*  sInstance,
                   unsigned short local_port,
                   unsigned short remote_port,
                   unsigned int tagLocal,
                   short primaryDestinitionAddress,
                   short noOfDestinationAddresses,
                   union sockunion *destinationAddressList)
{
    SCTP_instance*  instance = NULL;
    unsigned int ii;
    int result;

    if (sInstance == NULL) {
        if (sctpInstance == NULL) {
            error_logi(ERROR_FATAL, "SCTP Instance for Port %u were all NULL, call sctp_registerInstance FIRST !",local_port);
            return 1;
       } else {
            instance = sctpInstance;
        }
    } else {
        instance = (SCTP_instance*)sInstance;
    }

    if (!instance) error_log(ERROR_MAJOR, "instance is NULL ! Segfault !");

    event_logiiiii(VERBOSE," mdi_newAssociation: Instance: %u, local port %u, rem.port: %u, local tag: %u, primary: %d",
           instance->sctpInstanceName, local_port,  remote_port, tagLocal, primaryDestinitionAddress);


    /* Do plausi checks on the addresses. */
    if (noOfDestinationAddresses <= 0 || destinationAddressList == NULL) {
        error_log(ERROR_MAJOR, "No destination address suppllied for new association");
        return 1;

    } else if (primaryDestinitionAddress < 0
                 || primaryDestinitionAddress >= noOfDestinationAddresses) {
        error_log(ERROR_MAJOR, "Invalid primary destination address for new association");
        return 1;
    }

    if (currentAssociation) {
        error_log(ERROR_MINOR, "current association not cleared");
    }

    currentAssociation = (Association *) malloc(sizeof(Association));

    if (!currentAssociation) {
        error_log_sys(ERROR_FATAL, (short)errno);
        return 1;
    }

    currentAssociation->sctpInstance = instance;
    currentAssociation->localPort = local_port;
    currentAssociation->remotePort = remote_port;
    currentAssociation->tagLocal = tagLocal;
    currentAssociation->assocId = mdi_getUnusedAssocId();
    currentAssociation->tagRemote = 0;
    currentAssociation->deleted = FALSE;

    currentAssociation->ulp_dataptr = NULL;
    currentAssociation->ipTos = instance->default_ipTos;
    currentAssociation->maxSendQueue = instance->default_maxSendQueue;

    result = mdi_updateMyAddressList();
    if (result != SCTP_SUCCESS) {
        error_log(ERROR_MAJOR, "Could not update my address list. Unable to initiate new association.");
        return 1;
    }

    if (instance->has_IN6ADDR_ANY_set) {
        /* get ALL addresses */
        currentAssociation->noOfLocalAddresses =  myNumberOfAddresses;
        currentAssociation->localAddresses =
            (union sockunion *) calloc(myNumberOfAddresses, sizeof(union sockunion));
        memcpy(currentAssociation->localAddresses, myAddressList,
                myNumberOfAddresses* sizeof(union sockunion));
        event_logi(VERBOSE," mdi_newAssociation: Assoc has has_IN6ADDR_ANY_set, and %d addresses",myNumberOfAddresses);
    } else if (instance->has_INADDR_ANY_set) {
        /* get all IPv4 addresses */
        currentAssociation->noOfLocalAddresses = 0;
        for (ii = 0; ii <  myNumberOfAddresses; ii++) {
            if (sockunion_family(&(myAddressList[ii])) == AF_INET) {
                currentAssociation->noOfLocalAddresses++;
            }
        }
        currentAssociation->localAddresses =
            (union sockunion *) calloc(currentAssociation->noOfLocalAddresses, sizeof(union sockunion));
        currentAssociation->noOfLocalAddresses = 0;
        for (ii = 0; ii <  myNumberOfAddresses; ii++) {
            if (sockunion_family(&(myAddressList[ii])) == AF_INET) {
                memcpy(&(currentAssociation->localAddresses[currentAssociation->noOfLocalAddresses]),
                       &(myAddressList[ii]),sizeof(union sockunion));
                currentAssociation->noOfLocalAddresses++;
            }
        }
        event_logi(VERBOSE," mdi_newAssociation: Assoc has has_INADDR_ANY_set, and %d addresses",currentAssociation->noOfLocalAddresses);
    } else {        /* get all specified addresses */
        currentAssociation->noOfLocalAddresses = instance->noOfLocalAddresses;
        currentAssociation->localAddresses =
            (union sockunion *) malloc(instance->noOfLocalAddresses * sizeof(union sockunion));
        memcpy(currentAssociation->localAddresses, instance->localAddressList,
               instance->noOfLocalAddresses * sizeof(union sockunion));

    }

    currentAssociation->had_IN6ADDR_ANY_set = instance->has_IN6ADDR_ANY_set;
    currentAssociation->had_INADDR_ANY_set = instance->has_INADDR_ANY_set;

    currentAssociation->noOfNetworks = noOfDestinationAddresses;
    currentAssociation->destinationAddresses =
        (union sockunion *) malloc(noOfDestinationAddresses * sizeof(union sockunion));
    memcpy(currentAssociation->destinationAddresses, destinationAddressList,
         noOfDestinationAddresses * sizeof(union sockunion));

    /* check if newly created association already exists. */
    if (checkForExistingAssociations(currentAssociation) == 1) {
        error_log(ERROR_MAJOR, "tried to establish an existing association");
        /* FIXME : also free bundling, pathmanagement,sctp_control */
        free(currentAssociation->localAddresses);
        free(currentAssociation->destinationAddresses);
        free(currentAssociation);
        currentAssociation = NULL;
        return 1;
    }

    /* initialize pointer to other modules of SCTP */
    currentAssociation->flowControl = NULL;
    currentAssociation->reliableTransfer = NULL;
    currentAssociation->rx_control = NULL;
    currentAssociation->streamengine = NULL;

    /* only pathman, bundling and sctp-control are created at this point, the rest is created
       with mdi_initAssociation */
    currentAssociation->bundling = bu_new();
    currentAssociation->pathMan = pm_newPathman(noOfDestinationAddresses,
                                                primaryDestinitionAddress, instance);
    currentAssociation->sctp_control = sci_newSCTP_control(instance);

    currentAssociation->supportsPRSCTP = instance->supportsPRSCTP;
    currentAssociation->peerSupportsPRSCTP = instance->supportsPRSCTP;

    currentAssociation->supportsADDIP = FALSE;
    currentAssociation->peerSupportsADDIP = FALSE;


    event_logii(INTERNAL_EVENT_1, "new Association created ID=%08x, local tag=%08x",
        currentAssociation->assocId, currentAssociation->tagLocal);

    /* Enter association into list */
    event_logi(INTERNAL_EVENT_0, "entering association %08x into list", currentAssociation->assocId);

    AssociationList = g_list_insert_sorted(AssociationList,currentAssociation, &compareAssociationIDs);

    return 0;
}                               /* end: mdi_newAssociation */


/**
 * This is the second function needed to fully create and initialize an association (after
 * mdi_newAssociation()) THe association is created in two steps because data become available
 * at the a-side in two steps
 * \begin{enumerate}
 * \item associate
 * \item init acknowledgement
 * \end{enumerate}
 * At the z-side, with the cookie message all data is available at once. So mdi_newAssociation
 * and mdi_initAssociation must be called when the initAck with valid Cookie is received.
 *
 * @param  remoteSideReceiverWindow  rwnd size that the peer allowed in this association
 * @param  noOfInStreams  number of incoming (receive) streams after negotiation
 * @param  noOfOutStreams number of outgoing (send) streams after negotiation
 * @param  remoteInitialTSN     initial  TSN of the peer
 * @param  tagRemote            tag of the peer
 * @param  localInitialTSN      my initial TSN, needed for initializing my flow control
 * @return 0 for success, else 1 for error
*/
unsigned short
mdi_initAssociation(unsigned int remoteSideReceiverWindow,
                    unsigned short noOfInStreams,
                    unsigned short noOfOutStreams,
                    unsigned int remoteInitialTSN,
                    unsigned int tagRemote, unsigned int localInitialTSN,
                    gboolean assocSupportsPRSCTP, gboolean assocSupportsADDIP)
{
    gboolean withPRSCTP;

    if (!currentAssociation) {
        error_log(ERROR_MAJOR,
                  "mdi_initAssociation: current association does not exist, can not initialize");
        return 1;
    }

    /* if  mdi_initAssociation has already be called, delete modules and make new ones
       with possibly new data. Multiple calls of of mdi_initAssociation can occur on the
       a-side in the case of stale cookie errors. */
    if (currentAssociation->tagRemote != 0) {
        event_log(INTERNAL_EVENT_1,
                  "Deleting Modules in mdi_initAssociation() -- then recreating them !!!!");
        /* association init was already completed */
        fc_delete_flowcontrol(currentAssociation->flowControl);
        rtx_delete_reltransfer(currentAssociation->reliableTransfer);
        rxc_delete_recvctrl(currentAssociation->rx_control);
        se_delete_stream_engine(currentAssociation->streamengine);
    }

    /* TODO : check number of input and output streams (although that should be fixed now) */

    currentAssociation->tagRemote = tagRemote;

    withPRSCTP =  assocSupportsPRSCTP && currentAssociation->supportsPRSCTP;
    currentAssociation->peerSupportsPRSCTP = withPRSCTP;
    currentAssociation->supportsPRSCTP = withPRSCTP;

    currentAssociation->reliableTransfer =
        (void *) rtx_new_reltransfer(currentAssociation->noOfNetworks, localInitialTSN);
    currentAssociation->flowControl =
        (void *) fc_new_flowcontrol(remoteSideReceiverWindow, localInitialTSN,
                                    currentAssociation->noOfNetworks, currentAssociation->maxSendQueue);

    currentAssociation->rx_control = (void *) rxc_new_recvctrl(remoteInitialTSN,currentAssociation->noOfNetworks,
                                                               currentAssociation->sctpInstance);
    currentAssociation->streamengine = (void *) se_new_stream_engine(noOfInStreams,
                                                                     noOfOutStreams,
                                                                     withPRSCTP);

    event_logii(INTERNAL_EVENT_1, "second step of association initialisation performed ID=%08x, local tag=%08x",
               currentAssociation->assocId, currentAssociation->tagLocal);

    return 0;

}                               /* end: mdi_initAssociation */


unsigned short
mdi_restartAssociation(unsigned short noOfInStreams,
                    unsigned short noOfOutStreams,
                    unsigned int new_rwnd,
                    unsigned int remoteInitialTSN,
                    unsigned int localInitialTSN,
                    short  noOfPaths,
                    short primaryAddress,
                    union sockunion *destinationAddressList,
                    gboolean assocSupportsPRSCTP, gboolean assocSupportsADDIP)
{
    int result;
    gboolean withPRSCTP;

    if (!currentAssociation) {
        error_log(ERROR_MAJOR, "mdi_restartAssociation: current association is NULL !");
        return 1;
    }
    if (!sctpInstance) {
        error_log(ERROR_MAJOR, "mdi_restartAssociation: sctpInstance is NULL !");
        return 1;
    }
    if (noOfPaths > currentAssociation->noOfNetworks) {
            error_log(ERROR_MAJOR, "mdi_restartAssociation tries to increase number of paths !");
            /* discard silently */
            return -1;
    }
    event_logiiii(INTERNAL_EVENT_0, "ASSOCIATION RESTART: in streams: %u, out streams: %u, rwnd: %u, paths: %u",
                noOfInStreams,noOfOutStreams,new_rwnd,noOfPaths);
    event_logii(INTERNAL_EVENT_0, "ASSOCIATION RESTART: remote initial TSN:  %u, local initial TSN",
                remoteInitialTSN, localInitialTSN);

    currentAssociation->reliableTransfer = rtx_restart_reliable_transfer(currentAssociation->reliableTransfer,
        noOfPaths, localInitialTSN);
    fc_restart(new_rwnd, localInitialTSN, currentAssociation->maxSendQueue);
    rxc_restart_receivecontrol(mdi_getDefaultMyRwnd(), remoteInitialTSN);

    withPRSCTP =  assocSupportsPRSCTP && currentAssociation->supportsPRSCTP;
    currentAssociation->peerSupportsPRSCTP = withPRSCTP;
    currentAssociation->supportsPRSCTP     = withPRSCTP;

    if(currentAssociation->streamengine) {
       se_delete_stream_engine(currentAssociation->streamengine);
    }
    else {
       error_log(ERROR_MAJOR, "mdi_restartAssociation: currentAssociation->streamengine is NULL !");
    }
    currentAssociation->streamengine = (void *) se_new_stream_engine(noOfInStreams,
                                                                     noOfOutStreams,withPRSCTP);

    if(currentAssociation->pathMan) {
       pm_deletePathman(currentAssociation->pathMan);
       currentAssociation->pathMan = NULL;
    }
    else {
       error_log(ERROR_MAJOR, "mdi_restartAssociation: currentAssociation->pathMan is NULL !");
    }

    /* frees old address-list before assigning new one */
    mdi_writeDestinationAddresses(destinationAddressList, noOfPaths);

    currentAssociation->pathMan = pm_newPathman(noOfPaths, primaryAddress, sctpInstance);

    if (!currentAssociation->pathMan) {
        error_log(ERROR_FATAL, "Error 1 in RESTART --> Fix implementation");
        return -1;
    }

    event_logii(VERBOSE, "ASSOCIATION RESTART: calling pm_setPaths(%u, %u)",noOfPaths,primaryAddress);

    result = pm_setPaths(noOfPaths,primaryAddress);
    if (result != 0) {
        error_log(ERROR_FATAL, "Error 2 in RESTART --> Fix implementation");
        return -1;
    }

    return 0;
}


/**
 *  mdi_deleteCurrentAssociation deletes the current association.
 *
 *  The association will not be deleted at once, but is only marked for deletion. This is done in
 *  this way to allow other modules to finish their current activities. To prevent them to start
 *  new activities, the currentAssociation pointer is set to NULL.
 */
void mdi_deleteCurrentAssociation(void)
{
    short pathID;

    if (currentAssociation != NULL) {
        if (currentAssociation->tagRemote != 0) {
            /* stop timers */
            for (pathID = 0; pathID < currentAssociation->noOfNetworks; pathID++)
                pm_disableHB(pathID);

            fc_stop_timers();
            rxc_stop_sack_timer();
            /* stop SCTP control timers */
        }

        /* mark association as deleted, it will be deleted when retrieveAssociation(..) encounters
           a "deleted" association. */
        currentAssociation->deleted = TRUE;
        event_logi(INTERNAL_EVENT_1, "association ID=%08x marked for deletion", currentAssociation->assocId);
    } else {
        error_log(ERROR_MAJOR,
                  "mdi_deleteAssociation: current association does not exist, can not delete");
    }
}


#ifdef TD_DEBUG
#undef calloc
#undef malloc
#undef free
void* calloc(size_t nmemb, size_t size);
void* malloc(size_t size);
void free(void* p);

void* my_calloc(size_t nmemb, size_t size)
{
   void* ptr = my_malloc(nmemb * size);
   if(ptr) {
      memset(ptr, 0, nmemb * size);
   }
   return(ptr);
}

void* my_malloc(size_t size)
{
   size_t* ptr = malloc(size + sizeof(size_t));
   if(ptr) {
      memset(ptr, 0xef, size + sizeof(size_t));
      ptr[0] = size + sizeof(size_t);
      return((void*)&ptr[1]);
   }
   return(NULL);
}

void my_free(void* p)
{
   size_t* ptr;
   size_t  l;
   if(p != NULL) {
      ptr = &((size_t*)p)[-1];
      l   = ptr[0];
      memset(ptr, 0xba, l);
      free(ptr);
   }
}
#endif
