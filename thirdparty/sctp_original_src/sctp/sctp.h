/* $Id: sctp.h 2771 2013-05-30 09:09:07Z dreibh $
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

#ifndef SCTP_H
#define SCTP_H


/* Some important definitions for usage of reentrant versions. */
#ifndef _REENTRANT
    #define _REENTRANT
#endif
#ifndef _THREAD_SAFE
    #define _THREAD_SAFE
#endif
#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif
#ifndef USE_PTHREADS
    #define USE_PTHREADS
#endif


#ifdef __cplusplus
extern "C" {
#endif

#define SCTP_MAJOR_VERSION      1
#define SCTP_MINOR_VERSION      0
#define SCTP_TINY_VERSION       8

/* the maximum length of an IP address string (IPv4 or IPv6, NULL terminated) */
/* see RFC 1884 (mixed IPv6/Ipv4 addresses)   */
#define SCTP_MAX_IP_LEN           46        /* ==  INET6_ADDRSTRLEN      */

/** this parameter specifies the maximum number of addresses that an endpoint may have */
#define SCTP_MAX_NUM_ADDRESSES      20

/* reasonable sized SACK, SCTP and IP header + one data chunk should be less than MTU */
/* this is for ethernet..... ;-) */
#define SCTP_MAXIMUM_DATA_LENGTH     1400
/******************** Defines *********************************************************************/
/* the possible 7 states of an association */
#define SCTP_CLOSED                     0
#define SCTP_COOKIE_WAIT                1
#define SCTP_COOKIE_ECHOED              2
#define SCTP_ESTABLISHED                3
#define SCTP_SHUTDOWN_PENDING           4
#define SCTP_SHUTDOWN_RECEIVED          5
#define SCTP_SHUTDOWN_SENT              6
#define SCTP_SHUTDOWNACK_SENT           7

/* Pathstatus, used with networkstatus primitives */
#define SCTP_PATH_OK                    0
#define SCTP_PATH_UNREACHABLE           1
#define SCTP_PATH_ADDED                 2
#define SCTP_PATH_REMOVED               3
#define SCTP_PATH_CONFIRMED             4
#define SCTP_PATH_UNCONFIRMED           5


/* for use in  sctp_changeHeartBeat */
#define SCTP_HEARTBEAT_ON               1
#define SCTP_HEARTBEAT_OFF              0

#define SCTP_UNORDERED_DELIVERY         1
#define SCTP_ORDERED_DELIVERY           0

/* boolean, 0==normal bundling, 1==do not bundle message */
#define SCTP_BUNDLING_ENABLED           0
#define SCTP_BUNDLING_DISABLED          1

/* these are also for sctp_send() */
#define SCTP_USE_PRIMARY                    -1
#define SCTP_INFINITE_LIFETIME              0xFFFFFFFF
#define SCTP_NO_RETRANSMISSION              0
#define SCTP_SEND_RELIABLE                  SCTP_INFINITE_LIFETIME
#define SCTP_NO_CONTEXT                     NULL
#define SCTP_GENERIC_PAYLOAD_PROTOCOL_ID    0
/* these are for sctp_receive() */
#define SCTP_MSG_DEFAULT                    0x00
#define SCTP_MSG_PEEK                       0x02

#define SCTP_CHECKSUM_ALGORITHM_CRC32C      0x1
#define SCTP_CHECKSUM_ALGORITHM_ADLER32     0x2

/* Here are some error codes that are returned by some functions         */
/* this list may be enhanced or become more extensive in future releases */
#define SCTP_SUCCESS                        0
#define SCTP_LIBRARY_NOT_INITIALIZED        -1
#define SCTP_INSTANCE_NOT_FOUND             -2
#define SCTP_ASSOC_NOT_FOUND                -3
#define SCTP_PARAMETER_PROBLEM              -4
#define SCTP_MODULE_NOT_FOUND               -5
#define SCTP_OUT_OF_RESOURCES               -6
#define SCTP_NOT_SUPPORTED                  -7
#define SCTP_INSUFFICIENT_PRIVILEGES        -8
#define SCTP_LIBRARY_ALREADY_INITIALIZED    -9
#define SCTP_UNSPECIFIED_ERROR              -10
#define SCTP_QUEUE_EXCEEDED                 -11
#define SCTP_WRONG_ADDRESS                  -12
#define SCTP_WRONG_STATE                    -13
#define SCTP_BUFFER_TOO_SMALL               -14
#define SCTP_NO_CHUNKS_IN_QUEUE             -15
#define SCTP_INSTANCE_IN_USE                -16
#define SCTP_SPECIFIC_FUNCTION_ERROR        1

/* some constants for return codes from COMMUNICATION LOST or COMMUNICATION UP callbacks */
#define SCTP_COMM_LOST_ABORTED                   1
#define SCTP_COMM_LOST_ENDPOINT_UNREACHABLE      2
#define SCTP_COMM_LOST_EXCEEDED_RETRANSMISSIONS  3
#define SCTP_COMM_LOST_NO_TCB                    4
/* maybe some others............. */
#define SCTP_COMM_LOST_INVALID_PARAMETER         8
/* called if peer does not recognize some of our parameters */
#define SCTP_COMM_LOST_FAILURE                   9
#define SCTP_SHUTDOWN_COMPLETE                  10

#define SCTP_COMM_UP_RECEIVED_VALID_COOKIE       1
#define SCTP_COMM_UP_RECEIVED_COOKIE_ACK         2
#define SCTP_COMM_UP_RECEIVED_COOKIE_RESTART     3

#define SCTP_SEND_QUEUE                         1


/******************** Structure Definitions *******************************************************/


typedef
/**
   This struct containes the pointers to ULP callback functions.
   Each SCTP-instance can have its own set of callback functions.
   The callback functions of each SCTP-instance can be found by
   first reading the datastruct of an association from the list of
   associations. The datastruct of the association contains the name
   of the SCTP instance to which it belongs. With the name of the SCTP-
   instance its datastruct can be read from the list of SCTP-instances.
*/
struct SCTP_ulp_Callbacks
{
    /* @{ */
    /**
     * indicates that new data arrived from peer (chapter 10.2.A).
     *  @param 1 associationID
     *  @param 2 streamID
     *  @param 3 length of data
     *  @param 4 stream sequence number
     *  @param 5 tsn of (at least one) chunk belonging to the message
     *  @param 6 protocol ID
     *  @param 7 unordered flag (TRUE==1==unordered, FALSE==0==normal, numbered chunk)
     *  @param 8 pointer to ULP data
     */
    void (*dataArriveNotif) (unsigned int, unsigned short, unsigned int, unsigned short, unsigned int, unsigned int, unsigned int,   void*);
    /**
     * indicates a send failure (chapter 10.2.B).
     *  @param 1 associationID
     *  @param 2 pointer to data not sent
     *  @param 3 dataLength
     *  @param 4 pointer to context from sendChunk
     *  @param 5 pointer to ULP data
     */
    void (*sendFailureNotif) (unsigned int, unsigned char *, unsigned int, unsigned int *, void*);
    /**
     * indicates a change of network status (chapter 10.2.C).
     *  @param 1 associationID
     *  @param 2 destinationAddresses
     *  @param 3 newState
     *  @param 4 pointer to ULP data
     */
    void (*networkStatusChangeNotif) (unsigned int, short, unsigned short, void*);
    /**
     * indicates that a association is established (chapter 10.2.D).
     *  @param 1 associationID
     *  @param 2 status, type of event
     *  @param 3 number of destination addresses
     *  @param 4 number input streamns
     *  @param 5 number output streams
     *  @param 6 int  supportPRSCTP (0=FALSE, 1=TRUE)
     *  @param 7 pointer to ULP data, usually NULL
     *  @return the callback is to return a pointer, that will be transparently returned with every callback
     */
    void* (*communicationUpNotif) (unsigned int, int, unsigned int,
                                   unsigned short, unsigned short,
                                   int, void*);
    /**
     * indicates that communication was lost to peer (chapter 10.2.E).
     *  @param 1 associationID
     *  @param 2 status, type of event
     *  @param 3 pointer to ULP data
     */
    void (*communicationLostNotif) (unsigned int, unsigned short, void*);
    /**
     * indicates that communication had an error. (chapter 10.2.F)
     * Currently not implemented !?
     *  @param 1 associationID
     *  @param 2 status, type of error
     *  @param 3 pointer to ULP data
     */
    void (*communicationErrorNotif) (unsigned int, unsigned short, void*);
    /**
     * indicates that a RESTART has occurred. (chapter 10.2.G)
     *  @param 1 associationID
     *  @param 2 pointer to ULP data
     */
    void (*restartNotif) (unsigned int, void*);
    /**
     * indicates that a SHUTDOWN has been received by the peer. Tells the
     * application to stop sending new data.
     *  @param 0 instanceID
     *  @param 1 associationID
     *  @param 2 pointer to ULP data
     */
    void (*peerShutdownReceivedNotif) (unsigned int, void*);
    /**
     * indicates that a SHUTDOWN has been COMPLETED. (chapter 10.2.H)
     *  @param 0 instanceID
     *  @param 1 associationID
     *  @param 2 pointer to ULP data
     */
    void (*shutdownCompleteNotif) (unsigned int, void*);
    /**
     * indicates that a queue length has exceeded (or length has dropped
     * below) a previously determined limit
     *  @param 0 associationID
     *  @param 1 queue type (in-queue, out-queue, stream queue etc.)
     *  @param 2 queue identifier (maybe for streams ? 0 if not used)
     *  @param 3 queue length (either bytes or messages - depending on type)
     *  @param 4 pointer to ULP data
     */
    void (*queueStatusChangeNotif) (unsigned int, int, int, int, void*);
    /**
     * indicates that a ASCONF request from the ULP has succeeded or failed.
     *  @param 0 associationID
     *  @param 1 correlation ID
     *  @param 2 result (int, negative for error)
     *  @param 3 pointer to a temporary, request specific structure (NULL if not needed)
     *  @param 4 pointer to ULP data
     */
    void (*asconfStatusNotif) (unsigned int, unsigned int, int, void*, void*);
    /* @} */
}SCTP_ulpCallbacks;


typedef
/**
 * This struct contains parameters that may be set globally with
 * sctp_setLibraryParams(). For now, it only contains one flag.
 */
struct SCTP_Library_Parameters {
    /**
     * flag that controls whether an implementation will send
     * ABORT chunks for OOTB SCTP packets, or whether it will
     * silently discard these. In the later case, you will be
     * able to run the implementation twice on one machine, without
     * the two interfering with each other (also for tests on localhost)
     * By default, this variable is set to TRUE (==1)
     * Allowed values are 0 (==FALSE) or 1, else function will fail !!
     */
    int sendOotbAborts;
    /**
     * This allows for globally setting the used checksum algorithm
     * may be either
     * - SCTP_CHECKSUM_ALGORITHM_CRC32C   (0x1, default) or
     * - SCTP_CHECKSUM_ALGORITHM_ADLER32  (0x2)
     */
    int checksumAlgorithm;
    /*
     * Allowed values are 0 (==FALSE) or 1 (== TRUE)
     */
    int supportPRSCTP;
    /*
     * Allowed values are 0 (==FALSE) or 1 (== TRUE)
     */
    int supportADDIP;


}SCTP_LibraryParameters;



typedef
/**
 * This struct contains some parameters that may be set or
 * got with the sctp_getAssocDefaults()/sctp_setAssocDefaults()
 * functions. So these may also be specified/retrieved for
 * servers, before an association is established !
 */
struct SCTP_Instance_Parameters {
    /* @{ */
    /* this is read-only (get) */
    unsigned int   noOfLocalAddresses;
    /* this is read-only (get) */
    unsigned char  localAddressList[SCTP_MAX_NUM_ADDRESSES][SCTP_MAX_IP_LEN];
    /** the initial round trip timeout */
    unsigned int rtoInitial;
    /** the minimum timeout value */
    unsigned int rtoMin;
    /** the maximum timeout value */
    unsigned int rtoMax;
    /** the lifetime of a cookie */
    unsigned int validCookieLife;
    /**  (get/set) */
    unsigned short outStreams;
    /**  (get/set) */
    unsigned short inStreams;
    /** does the instance by default signal unreliable streams (as a server) no==0, yes==1 */
    unsigned int supportUnreliableStreams;
    /** does the instance by default signal unreliable streams (as a server) no==0, yes==1 */
    unsigned int supportADDIP;
    /** maximum retransmissions per association */
    unsigned int assocMaxRetransmits;
    /** maximum retransmissions per path */
    unsigned int pathMaxRetransmits;
    /** maximum initial retransmissions */
    unsigned int maxInitRetransmits;
    /** from recvcontrol : my receiver window */
    unsigned int myRwnd;
    /** recvcontrol: delay for delayed ACK in msecs */
    unsigned int delay;
    /** per instance: for the IP type of service field. */
    unsigned char ipTos;
    /** limit the number of chunks queued in the send queue */
    unsigned int maxSendQueue;
    /** currently unused, may limit the number of chunks queued in the receive queue later.
     *  Is this really needed ? The protocol limits the receive queue with
     *  window advertisement of arwnd==0  */
    unsigned int maxRecvQueue;
    /**
     * maximum number of associations we want. Is this limit greater than 0,
     * implementation will automatically send ABORTs to incoming INITs, when
     * there are that many associations !
     */
    unsigned int maxNumberOfAssociations;
    /* @} */
} SCTP_InstanceParameters;


typedef
/**
 *  This struct contains the data to be returned to the ULP with the
 *  sctp_getAssocStatus() function primitive. It is marked whether data
 *  may only be retrieved using the  sctp_getAssocStatus() function, or
 *  also set using the  sctp_setAssocStatus() function.
 */
struct SCTP_Association_Status
{
    /* @{ */
    /** (get)  */
    unsigned short state;
    /**  (get) */
    unsigned short numberOfAddresses;
    /**  (get) */
    unsigned char  primaryDestinationAddress[SCTP_MAX_IP_LEN];
    /**  (get) */
    unsigned short sourcePort;
    /**  (get) */
    unsigned short destPort;
    /**  (get) */
    unsigned short outStreams;
    /**  (get) */
    unsigned short inStreams;
    /** does the assoc support unreliable streams  no==0, yes==1 */
    unsigned int supportUnreliableStreams;
    /** does the assoc support adding/deleting IP addresses no==0, yes==1 */
    unsigned int supportADDIP;
    /**  (get/set) */
    unsigned short primaryAddressIndex;
    /**  (get) */
    unsigned int   currentReceiverWindowSize;
    /**  (get) */
    unsigned int   outstandingBytes;
    /**  (get) */
    unsigned int   noOfChunksInSendQueue;
    /**  (get) */
    unsigned int   noOfChunksInRetransmissionQueue;
    /**  (get) */
    unsigned int   noOfChunksInReceptionQueue;
    /** (get/set) the initial round trip timeout */
    unsigned int   rtoInitial;
    /** (get/set) the minimum RTO timeout */
    unsigned int   rtoMin;
    /** (get/set) the maximum RTO timeout */
    unsigned int   rtoMax;
    /** (get/set) the lifetime of a cookie */
    unsigned int   validCookieLife;
    /** (get/set) maximum retransmissions per association */
    unsigned int   assocMaxRetransmits;
    /** (get/set) maximum retransmissions per path */
    unsigned int   pathMaxRetransmits;
    /** (get/set) maximum initial retransmissions */
    unsigned int   maxInitRetransmits;
    /** (get/set) from recvcontrol : my receiver window */
    unsigned int myRwnd;
    /** (get/set) recvcontrol: delay for delayed ACK in msecs */
    unsigned int delay;
    /** (get/set) per instance: for the IP type of service field. */
    unsigned char ipTos;
    /**  limit the number of chunks queued in the send queue */
    unsigned int maxSendQueue;
    /** currently unused, may limit the number of chunks queued in the receive queue later.
     *  Is this really needed ? The protocol limits the receive queue with
     *  window advertisement of arwnd==0  */
    unsigned int maxRecvQueue;
    /* @} */
} SCTP_AssociationStatus;


typedef
/**
 * this struct contains path specific parameters, so these
 * values can only be retrieved/set, when the association
 * already exists !
 */
struct SCTP_Path_Status
{
    /* @{ */
    /**   */
    unsigned char destinationAddress[SCTP_MAX_IP_LEN];
    /**  SCTP_PATH_ACTIVE  0, SCTP_PATH_INACTIVE   1    */
    short state;
    /** smoothed round trip time in msecs */
    unsigned int srtt;
    /** current rto value in msecs */
    unsigned int rto;
    /** round trip time variation, in msecs */
    unsigned int rttvar;
    /** defines the rate at which heartbeats are sent */
    unsigned int heartbeatIntervall;
    /**  congestion window size (flowcontrol) */
    unsigned int cwnd;
    /**  congestion window size 2 (flowcontrol) */
    unsigned int cwnd2;
    /**  Partial Bytes Acked (flowcontrol) */
    unsigned int partialBytesAcked;
    /**  Slow Start Threshold (flowcontrol) */
    unsigned int ssthresh;
    /**  from flow control */
    unsigned int outstandingBytesPerAddress;
    /**  Current MTU (flowcontrol) */
    unsigned int mtu;
    /** per path ? per instance ? for the IP type of service field. */
    unsigned char ipTos;
    /* @} */
}SCTP_PathStatus;


/******************** Function Definitions ********************************************************/

/**
 * Function that needs to be called in advance to all library calls.
 * It initializes all file descriptors etc. and sets up some variables
 * @return 0 for success, 1 for adaptation level error, -1 if already called
 * (i.e. the function has already been called before), -2 for insufficient rights
 * (you need root-rights to open RAW sockets !).
 */
int sctp_initLibrary(void);


/**
 * Function returns coded library version as result. This unsigned integer
 * contains the major version in the upper 16 bits, and the minor version in
 * the lower 16 bits.
 * @return library version, or 0 (i.e. zero) as error !
 */
unsigned int sctp_getLibraryVersion(void);


int sctp_registerInstance(unsigned short localPort,
                          unsigned short noOfInStreams,
                          unsigned short noOfOutStreams,
                          unsigned int   noOfLocalAddresses,
                          unsigned char  localAddressList[SCTP_MAX_NUM_ADDRESSES][SCTP_MAX_IP_LEN],
                          SCTP_ulpCallbacks ULPcallbackFunctions);

int sctp_unregisterInstance(unsigned short instance_name);




unsigned int sctp_associate(unsigned int SCTP_InstanceName,
                            unsigned short noOfOutStreams,
                            unsigned char  destinationAddress[SCTP_MAX_IP_LEN],
                            unsigned short destinationPort,
                            void* ulp_data);


unsigned int sctp_associatex(unsigned int SCTP_InstanceName,
                             unsigned short noOfOutStreams,
                             unsigned char  destinationAddresses[][SCTP_MAX_IP_LEN],
                             unsigned int   noOfDestinationAddresses,
                             unsigned int   maxSimultaneousInits,
                             unsigned short destinationPort,
                             void* ulp_data);


int sctp_shutdown(unsigned int associationID);

int sctp_abort(unsigned int associationID);

#ifndef SCTP_SOCKET_API
#define sctp_send sctp_send_private
#endif
int sctp_send_private(unsigned int associationID,
                      unsigned short streamID,
                      unsigned char *buffer,
                      unsigned int length,
                      unsigned int protocolId,
                      short path_id,         /* -1 for primary path, else address index to be taken */
                      void * context,        /* SCTP_NO_CONTEXT */
                      unsigned int lifetime, /* 0xFFFFFFFF-> infinite, 0->no retransmit, else msecs */
                      int unorderedDelivery, /* use constants SCTP_ORDERED_DELIVERY, SCTP_UNORDERED_DELIVERY */
                      int dontBundle);  /* use constants SCTP_BUNDLING_ENABLED, SCTP_BUNDLING_DISABLED */


/*
 *  sctp_receive() now returns SCTP_SUCCESS if data was received okay,
 *  also reports back a tsn value (at least one belonging to a fragment)
 *  SCTP_NO_CHUNKS_IN_QUEUE if there was no new data to be received,
 *  SCTP_PARAMETER_PROBLEM,SCTP_ASSOC_NOT_FOUND, SCTP_MODULE_NOT_FOUND if there was an error
 */
int sctp_receive(unsigned int associationID, unsigned short streamID, unsigned char  *buffer,
                 unsigned int *length, unsigned short *streamSN, unsigned int * tsn, unsigned int flags);


int sctp_receivefrom(unsigned int associationID, unsigned short streamID, unsigned char  *buffer,
                     unsigned int *length, unsigned short *streamSN, unsigned int * tsn,
                     unsigned int *addressIndex, unsigned int flags);



/*----------------------------------------------------------------------------------------------*/
/*  These are the new function for getting/setting parameters per instance, association or path */
/*----------------------------------------------------------------------------------------------*/
int sctp_setLibraryParameters(SCTP_LibraryParameters *params);
int sctp_getLibraryParameters(SCTP_LibraryParameters *params);

int sctp_setAssocDefaults(unsigned short SCTP_InstanceName, SCTP_InstanceParameters* params);

int sctp_getAssocDefaults(unsigned short SCTP_InstanceName, SCTP_InstanceParameters* params);


int sctp_getAssocStatus(unsigned int associationID, SCTP_AssociationStatus* status);

int sctp_setAssocStatus(unsigned int associationID, SCTP_AssociationStatus* new_status);

int sctp_getPathStatus(unsigned int associationID, short path_id, SCTP_PathStatus* status);
int sctp_setPathStatus(unsigned int associationID, short path_id, SCTP_PathStatus *new_status);
/*----------------------------------------------------------------------------------------------*/
/*
 * These _could_ be build up from the above functions, but for the sake of a
 * complete API according to RFC 4960, section 10, we have the following
 * six functions  here, explicitly
 */

short sctp_setPrimary(unsigned int associationID, short path_id);
short sctp_getPrimary(unsigned int associationID);

int sctp_getSrttReport(unsigned int associationID, short path_id);
int sctp_changeHeartBeat(unsigned int associationID,
                         short path_id, int heartbeatON, unsigned int timeIntervall);


int sctp_requestHeartbeat(unsigned int associationID, short path_id);

int sctp_setFailureThreshold(unsigned int associationID,
                             unsigned short pathMaxRetransmissions);

/*
 * this function can be used to get an instance ID of an association
 * with the specified assocID
 * @param associationID the association for which to get an instance id
 * @param instanceID pointer to the instance ID value, contains valid value after
 *        a successful function call
 * @return 0 for success, 1 if assoc does not exists, -1 for error (i.e.
 *           library not initialized, pointer Null, etc.
 */
int sctp_getInstanceID(unsigned int associationID, unsigned short* instanceID);
/*----------------------------------------------------------------------------------------------*/

int sctp_receiveUnsent(unsigned int associationID, unsigned char *buffer, unsigned int *length,
                       unsigned int *tsn, unsigned short *streamID, unsigned short *streamSN,
                       unsigned int* protocolId, unsigned char* flags, void** context);

int sctp_receiveUnacked(unsigned int associationID, unsigned char *buffer, unsigned int *length,
                        unsigned int *tsn, unsigned short *streamID, unsigned short *streamSN,
                        unsigned int* protocolId,unsigned char* flags, void** context);



int sctp_deleteAssociation(unsigned int associationID);


/* Defines the callback function that is called when an event occurs
   on an internal SCTP or UDP socket
   Params: 1. file-descriptor of the socket
           2. pointer to the datagram data, if any was received
           3. length of datagram data, if any was received
           4. source Address  (as string, may be IPv4 or IPv6 address string, in numerical format)
           5. source port number for UDP sockets, 0 for SCTP raw sockets
*/
typedef void (*sctp_socketCallback) (int, unsigned char *, int, unsigned char[] , unsigned short);

/* Defines the callback function that is called when an event occurs
   on a user file-descriptor
   Params: 1. file-descriptor
   Params: 2. received events mask
   Params: 3. pointer to registered events mask. It may be changed by the callback function.
   Params: 4. user data
*/
typedef void (*sctp_userCallback) (int, short int, short int*, void*);

/**
 * this function is supposed to open and bind a UDP socket listening on a port
 * to incoming udp pakets on a local interface (a local union sockunion address)
 * @param  me   local address string (IPv4 or IPv6, numerical format), if it receives UDP data
 *              it will trigger callback
 * @param  my_port  port to receive data on (will bind that port !)
 * @param  scf  callback funtion that is called when data has arrived
 * @return new UDP socket file descriptor, or -1 if error ocurred
 */
#ifndef WIN32
int sctp_registerUdpCallback(unsigned char me[],
                             unsigned short my_port,
                             sctp_socketCallback scf);

int sctp_unregisterUdpCallback(int udp_sfd);

int sctp_sendUdpData(int sfd, unsigned char* buf, int length,
                     unsigned char destination[], unsigned short dest_port);
#endif

typedef void (*sctp_StdinCallback) (char*, int);

int sctp_registerStdinCallback(sctp_StdinCallback sdf,
                                 char* buffer, int length);

int sctp_unregisterStdinCallback();

/**
 * this function registers a callback function for catching
 * activity on a Unix file descriptor. We expect this to be useful
 * in test programs mainly, so it is provided here for convenience.
 * @param  fd   file-descriptor
 * @param  scf  callback funtion that is called (when return is hit)
 * @return 0, or -1 if error ocurred (i.e. already used)
 */
#ifndef WIN32
int sctp_registerUserCallback(int fd, sctp_userCallback sdf, void* userData, short int eventMask);
int sctp_unregisterUserCallback(int fd);
#endif

/* Defines the callback function that is called when an timer expires.
   Params: 1. ID of timer
           2. pointer to param1
           3. pointer to param2
              param1 and param2 are transparent data from the caller of start_timer,
              that are returned to it when the timer expires.
*/
typedef void (*sctp_timerCallback) (unsigned int, void *, void *);


/**
 *      This function adds a callback that is to be called some time from now. It realizes
 *      the timer (in an ordered list).
 *      @param      milliseconds  action is to be started in milliseconds ms from now
 *      @param      timer_cb      pointer to a function to be executed, when timer expires
 *      @param      param1        pointer to be returned to the caller when timer expires
 *      @param      param2        pointer to be returned to the caller when timer expires
 *      @return     returns an id value, that can be used to cancel a timer
 *      @author     ajung
 */
unsigned int sctp_startTimer(unsigned int seconds , unsigned int microseconds,
                        sctp_timerCallback timer_cb, void *param1, void *param2);


/**
 *      This function stops a previously started timer.
 *      @param      tid        timer-id of timer to be removed
 *      @return     returns 0 on success, 1 if tid not in the list, -1 on error
 *      @author     ajung
 */
int sctp_stopTimer(unsigned int tid);

/**
 *      Restarts a timer currently running
 *      @param      timer_id   the value returned by set_timer for a certain timer
 *      @param      milliseconds  action is to be started in milliseconds ms from now
 *      @return     new timer id , zero when there is an error (i.e. no timer)
 *      @author     ajung
 */
unsigned int sctp_restartTimer(unsigned int timer_id, unsigned int seconds, unsigned int microseconds);



int sctp_getEvents(void);

int sctp_eventLoop(void);

int sctp_extendedEventLoop(void (*lock)(void* data), void (*unlock)(void* data), void* data);

/**
 *  these next funtions are unused. They should either be implemented, or removed :-)
 *  Maybe we should ask Thomas...
 */
int sctp_getNumberOfLocalAddresses(unsigned int associationID);

unsigned char* sctp_getLocalAddress(unsigned int associationID, int index);


#ifdef BAKEOFF
/* buffer points to a buffer that includes SCTP header.
   This header will be overwritten by the function, and
   insert correct data for an existing association */
int sctp_sendRawData(unsigned int associationID, short path_id,
                     unsigned char *buffer, unsigned int length);

#endif

#ifdef TD_DEBUG
#warning Using memory allocation debugging functions!
#include <sys/types.h>
void* my_calloc(size_t nmemb, size_t size);
void* my_malloc(size_t size);
void my_free(void* p);
#define calloc my_calloc
#define malloc my_malloc
#define free my_free
#endif

#ifdef __cplusplus
}
#endif


#endif
