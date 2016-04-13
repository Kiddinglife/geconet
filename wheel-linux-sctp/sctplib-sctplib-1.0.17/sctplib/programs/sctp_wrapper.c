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

#include "sctp_wrapper.h"

#define POLLIN     0x001
#define POLLPRI    0x002
#define POLLOUT    0x004
#define POLLERR    0x008

#include <stdio.h>
#include <stdlib.h>

int 
SCTP_setLibraryParameters(SCTP_LibraryParameters *params)
{
    int result;
    
    if ((result =  sctp_setLibraryParameters(params)) != SCTP_SUCCESS) {
      if (result == SCTP_PARAMETER_PROBLEM) {
        fprintf(stderr, "sctp_setLibraryParameters: parameter problem.\n");
      } else 
      if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
        fprintf(stderr, "sctp_setLibraryParameters: Library not initialized.\n");
      } else {
        fprintf(stderr, "sctp_setLibraryParameters: unknown value (%i) returned.\n", result);
      }
      fflush(stderr);
      exit(result);
    }
    return result;
}

int 
SCTP_getLibraryParameters(SCTP_LibraryParameters *params)
{
    int result;
    
    if ((result =  sctp_getLibraryParameters(params)) != SCTP_SUCCESS) {
      if (result == SCTP_PARAMETER_PROBLEM) {
        fprintf(stderr, "sctp_getLibraryParameters: parameter problem.\n");
      } else 
      if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
        fprintf(stderr, "sctp_getLibraryParameters: Library not initialized.\n");
      } else {
        fprintf(stderr, "sctp_getLibraryParameters: unknown value (%i) returned.\n", result);
      }
      fflush(stderr);
      exit(result);
    }
    return result;
}

int
SCTP_initLibrary(void)
{
    int result;

    if ((result = sctp_initLibrary()) != SCTP_SUCCESS) {
        if (result == SCTP_LIBRARY_ALREADY_INITIALIZED) {
            fprintf(stderr, "sctp_initLibrary: called muliple times.\n");
        } else 
        if (result == SCTP_INSUFFICIENT_PRIVILEGES) {
            fprintf(stderr, "sctp_initLibrary: could not open raw socket for SCTP. You must have root provileges !\n");
        } else
        if (result == SCTP_SPECIFIC_FUNCTION_ERROR) {
            fprintf(stderr, "sctp_initLibrary: Unknown error in Adaptation-Module !\n");
        } else {
            fprintf(stderr, "sctp_initLibrary: unknown value (%i) returned.\n", result);
        }
        fflush(stderr);
        exit(result);
    }
    return result;
}

int
SCTP_registerInstance(unsigned short port,
                      unsigned short noOfInStreams,
                      unsigned short noOfOutStreams,
                      unsigned int noOfLocalAddresses,
                      unsigned char localAddressList[][SCTP_MAX_IP_LEN],
                      SCTP_ulpCallbacks ULPcallbackFunctions)
{
    int result;
    
    result = sctp_registerInstance(port, noOfInStreams, noOfOutStreams,
                                   noOfLocalAddresses, localAddressList,
                                   ULPcallbackFunctions);
    if (result == SCTP_PARAMETER_PROBLEM) {
        fprintf(stderr, "sctp_registerInstance: an error occured.\n");
        fflush(stderr);
        exit(result);
    } else if (result == SCTP_WRONG_ADDRESS) {
        fprintf(stderr, "sctp_registerInstance: you passed an invalid/wrong address.\n");
        fflush(stderr);
        exit(result);
    } else if (result == SCTP_OUT_OF_RESOURCES) {
        fprintf(stderr, "sctp_registerInstance: you passed an invalid/wrong address.\n");
        fflush(stderr);
        exit(result);
    }
    return result;
}

int SCTP_unregisterInstance(unsigned short instance_name)
{
    int result;
    
    if ((result = sctp_unregisterInstance(instance_name)) != 0) {
        fprintf(stderr, "sctp_unregisterInstance: an error occured.\n");
        fflush(stderr);        
    }
    return result;
}

int
SCTP_deleteAssociation(unsigned int associationID)
{
    int result;
    
    if ((result = sctp_deleteAssociation(associationID))!=0) {
        if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
            fprintf(stderr, "sctp_deleteAssociation: library not initialized:\n");
        } else
        if (result == SCTP_SPECIFIC_FUNCTION_ERROR) {
            fprintf(stderr, "sctp_deleteAssociation: assoc not ready for deletion or lib not initialized:\n");
        } else
        if (result == SCTP_ASSOC_NOT_FOUND) {
            fprintf(stderr, "sctp_deleteAssociation: assoc does not exists.\n");
        }
        fflush(stderr);
    }
    return result;
}

int 
SCTP_send(unsigned int associationID, unsigned short streamID,
          unsigned char *buffer, unsigned int length, unsigned int protocolId, short path_id,
          void*  context, 
          unsigned int lifetime,
          int unorderedDelivery, 
          int dontBundle)     
{
    int result;
    
    if ((result = sctp_send(associationID, streamID,
                           buffer, length, protocolId, path_id,
                           context, 
                           lifetime,
                           unorderedDelivery, 
                           dontBundle))!= SCTP_SUCCESS) {
        if (result == SCTP_QUEUE_EXCEEDED) {
/*          fprintf(stderr, "sctp_send: Queue size exceeded.\n");*/
        } else
        if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
            fprintf(stderr, "sctp_send: library not initialized.\n");
        } else
        if (result == SCTP_ASSOC_NOT_FOUND) {
            fprintf(stderr, "sctp_send: association not found.\n");
        } else
        if (result == SCTP_SPECIFIC_FUNCTION_ERROR) {
            fprintf(stderr, "sctp_send: association in shutdown state - don't send any more data !\n");
        } else
        if (result == SCTP_MODULE_NOT_FOUND) {
            fprintf(stderr, "sctp_send: internal error !\n");
        } else
        if (result == SCTP_PARAMETER_PROBLEM) {
            fprintf(stderr, "sctp_send: Parameter Problem (invalid path or stream id).\n");
        } else {
            fprintf(stderr, "sctp_send: unkown result (%i) returned.\n", result);
        }
        fflush(stderr);
    }
    return result;
}

int
SCTP_receive(unsigned int associationID, unsigned short streamID, unsigned char *buffer, 
			unsigned int *length, unsigned short* streamSN, unsigned int * tsn, unsigned int flags)
{
    int result;

    if ((result = sctp_receive(associationID, streamID, buffer, length, streamSN, tsn, flags))!=0) {
        if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
            fprintf(stderr, "sctp_receive: library not initialized.\n");
        } else
        if (result == SCTP_ASSOC_NOT_FOUND) {
            fprintf(stderr, "sctp_receive: association not found.\n");
        } else
        if (result == SCTP_MODULE_NOT_FOUND) {
            fprintf(stderr, "sctp_receive: internal error.\n");
        } else
        if (result == SCTP_SPECIFIC_FUNCTION_ERROR) {
            /* fprintf(stderr, "sctp_receive: NO DATA AVAILABLE.\n"); */
        } else
        if (result == SCTP_PARAMETER_PROBLEM) {
            fprintf(stderr, "sctp_receive: parameter problem (Null-Pointers, PathID ?)\n");
        }
        fflush(stderr);
    }
    return result;
}

int
SCTP_shutdown(unsigned int associationID)
{
    int result;
    
    if ((result = sctp_shutdown(associationID))!= SCTP_SUCCESS) {
        if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
            fprintf(stderr, "sctp_shutdown: library not initialized.\n");
        } else
        if (result == SCTP_ASSOC_NOT_FOUND) {
            fprintf(stderr, "sctp_shutdown: association not found.\n");
        }
        fflush(stderr);
    }
    return result;
}

int 
SCTP_abort(unsigned int associationID)
{
    int result;
    
    if ((result = sctp_abort(associationID)) != SCTP_SUCCESS) {
        if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
            fprintf(stderr, "sctp_abort: library not initialized.\n");
        } else
        if (result == SCTP_ASSOC_NOT_FOUND) {
            fprintf(stderr, "sctp_abort: association not found.\n");
        }
        fflush(stderr);
    }
    return result;
}

int SCTP_getAssocStatus(unsigned int associationID, SCTP_AssociationStatus* status)
{
    int result;
    
    if ((result = sctp_getAssocStatus(associationID, status)) != SCTP_SUCCESS) {
        if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
            fprintf(stderr, "sctp_getAssocStatus: library not initialized.\n");
        } else
        if (result == SCTP_ASSOC_NOT_FOUND) {
            fprintf(stderr, "sctp_getAssocStatus: association not found.\n");
        } else 
        if (result == SCTP_PARAMETER_PROBLEM) {
            fprintf(stderr, "sctp_getAssocStatus: parameter problem (NULL pointer ?)\n");
        } else {
            fprintf(stderr, "sctp_getAssocStatus: unknown value (%i) returned.\n", result);
        }
        fflush(stderr);
    }
    return result;
}

int
SCTP_receiveUnacked(unsigned int associationID, unsigned char *buffer, unsigned int *length, unsigned int* tsn,
                    unsigned short *streamID, unsigned short *streamSN,unsigned int* protocolId)
{
    int result;
    unsigned char flags;
    void* ctx;
    
    if ((result = sctp_receiveUnacked(associationID, buffer, length, tsn,
                                      streamID, streamSN, protocolId, &flags, &ctx)) < 0) {

        if (result == SCTP_WRONG_STATE) {
            fprintf(stderr, "SCTP_receiveUnacked: Association is not in state CLOSED. \n");
        }else if (result ==SCTP_ASSOC_NOT_FOUND){
            fprintf(stderr, "SCTP_receiveUnacked: Association not found \n");
        }else if (result == SCTP_NO_CHUNKS_IN_QUEUE){
            /* fprintf(stderr, "SCTP_receiveUnacked: Queue is already empty.\n"); */
        }else if (result == SCTP_LIBRARY_NOT_INITIALIZED){
            fprintf(stderr, "SCTP_receiveUnacked: Library not Initialized \n");
        }else if (result == SCTP_PARAMETER_PROBLEM){
            fprintf(stderr, "SCTP_receiveUnacked: parameter problem, NULL pointer passed ?\n");
        } else {
            fprintf(stderr, "SCTP_receiveUnacked: unknown value (%i) returned.\n", result);
        }
        fflush(stderr);
    }
    return result;
}

int
SCTP_receiveUnsent(unsigned int associationID, unsigned char *buffer, unsigned int *length, unsigned int* tsn,
                   unsigned short *streamID, unsigned short *streamSN,unsigned int* protocolId)
{
    int result;
    unsigned char flags;
    void* ctx;

    if ((result = sctp_receiveUnsent(associationID, buffer, length, tsn,
                                     streamID, streamSN, protocolId, &flags, &ctx)) < 0) {
        if (result == SCTP_WRONG_STATE) {
            fprintf(stderr, "sctp_receiveUnsent: Association is not in state CLOSED. \n");
        }else if (result ==SCTP_ASSOC_NOT_FOUND){
            fprintf(stderr, "sctp_receiveUnsent: Association not found \n");
        }else if (result == SCTP_PARAMETER_PROBLEM){
            fprintf(stderr, "sctp_receiveUnsent: parameter problem, NULL pointer passed ?\n");
        }else if (result == SCTP_LIBRARY_NOT_INITIALIZED){
            fprintf(stderr, "sctp_receiveUnsent: Library not Initialized.\n");
        }else if (result == SCTP_NO_CHUNKS_IN_QUEUE){
            /* fprintf(stderr, "sctp_receiveUnsent: Queue is already empty.\n"); */
        } else {
            fprintf(stderr, "sctp_receiveUnsent: unknown value (%i) returned.\n", result);
        }
        fflush(stderr);
    }
    return result;
}

short
SCTP_setPrimary(unsigned int associationID, short path_id)
{
    int result;
    
    if ((result = sctp_setPrimary(associationID, path_id)) != 0) {
        if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
            fprintf(stderr, "sctp_setPrimary: library not initialized.\n");
        } else
        if (result == SCTP_ASSOC_NOT_FOUND) {
            fprintf(stderr, "sctp_setPrimary: association not found.\n");
        } else 
        if (result == SCTP_MODULE_NOT_FOUND) {
            fprintf(stderr, "sctp_setPrimary: internal error.\n");
        } else
        if (result == SCTP_UNSPECIFIED_ERROR) {
            fprintf(stderr, "sctp_setPrimary: internal error (data structure not yet allocated).\n");
        } else
        if (result == SCTP_PARAMETER_PROBLEM) {
            fprintf(stderr, "sctp_setPrimary: Path Id invalid.\n");
        } else
        if (result == SCTP_SPECIFIC_FUNCTION_ERROR) {
            fprintf(stderr, "sctp_setPrimary: association is not in state established, or primary path inactive\n");
        }
        fflush(stderr);
    }
    return result;
}

short
SCTP_getPrimary(unsigned int associationID)
{
    int result;
    
    if ((result = sctp_getPrimary(associationID)) < 0) {
        fprintf(stderr, "sctp_setPrimary: error value (%i) returned.\n", result);
        fflush(stderr);
    }
    return result;
}

int
SCTP_eventLoop(void)
{
    int result;
    
    if ((result = sctp_eventLoop()) < 0) {
        if (result == -1) {
            fprintf(stderr, "sctp_eventLoop: an error occured.\n");
        } else {
            fprintf(stderr, "sctp_eventLoop: unknown value (%i) returned.\n", result);
        }
        fflush(stderr);
    }
    return result;
}

int 
SCTP_getPathStatus(unsigned int associationID, short path_id, SCTP_PathStatus* status)
{
    int result;
    
    if ((result = sctp_getPathStatus(associationID, path_id, status)) != 0) {
        if (result == SCTP_LIBRARY_NOT_INITIALIZED) {
            fprintf(stderr, "sctp_getP: library not initialized.\n");
        } else
        if (result == SCTP_ASSOC_NOT_FOUND) {
            fprintf(stderr, ": association not found.\n");
        } else
        if (result == SCTP_PARAMETER_PROBLEM) {
            fprintf(stderr, ": Path Id invalid.\n");
        } else {
            fprintf(stderr, "sctp_getPathStatus: error value (%i) returned.\n", result);
            fflush(stderr);
        }
    }
    return result;
}

unsigned int
SCTP_associate(unsigned short SCTP_InstanceName,
               unsigned short noOfOutStreams,
               unsigned char destinationAddress[],
               unsigned short destinationPort,
               void* ulp_data)
{
    unsigned short result;
    
    if ((result = sctp_associate(SCTP_InstanceName, 
                                 noOfOutStreams,
                                 destinationAddress,
                                 destinationPort,
                                 ulp_data)) == 0) {
        fprintf(stderr, "sctp_associate: an error occured.\n");
        fflush(stderr);        
    }
    return result;
}


int SCTP_changeHeartBeat(unsigned int associationID,
                         short path_id, int heartbeatON, unsigned int timeInterval)
{
    int result;
    
    if ((result = sctp_changeHeartBeat(associationID, path_id, heartbeatON, timeInterval)) < 0) {
        fprintf(stderr, "sctp_changeHeartBeat: an error occured.\n");
        fflush(stderr);        
    }
    return result;        
}

int
SCTP_registerStdinCallback(sctp_StdinCallback sdf, char* buffer, int length)
{
    int result;
    
    if ((result = sctp_registerStdinCallback(sdf, buffer, length)) < 0) {
        fprintf(stderr, "sctp_registerStdinCallback: error value (%i) returned.\n", result);
        fflush(stderr);
    }
    return result;
}

int SCTP_unregisterStdinCallback()
{
    int result;
    
    if ((result = sctp_unregisterStdinCallback()) < 0) {
        fprintf(stderr, "sctp_unregisterStdinCallback: error value (%i) returned.\n", result);
        fflush(stderr);
    }
    return result;
}

#ifndef WIN32
int
SCTP_registerUserCallback(int fd, sctp_userCallback sdf, void* userData)
{
    int result;
    
    if ((result = sctp_registerUserCallback(fd, sdf, userData, POLLIN|POLLPRI)) < 0) {
        fprintf(stderr, "sctp_registerUserCallback: error value (%i) returned.\n", result);
        fflush(stderr);
    }
    return result;
}
#endif

int 
SCTP_getAssocDefaults(unsigned short SCTP_InstanceName, SCTP_InstanceParameters* params)
{
    int result;
    
    if ((result = sctp_getAssocDefaults(SCTP_InstanceName, params)) != 0) {
        fprintf(stderr, "sctp_getAssocDefaults: error value (%i) returned.\n", result);
        fflush(stderr);
    }
    return result;
}

int 
SCTP_setAssocDefaults(unsigned short SCTP_InstanceName, SCTP_InstanceParameters* params)
{
    int result;
    
    if ((result = sctp_setAssocDefaults(SCTP_InstanceName, params)) != 0) {
        fprintf(stderr, "sctp_setAssocDefaults: error value (%i) returned.\n", result);
        fflush(stderr);
    }
    return result;
}

unsigned int
SCTP_startTimer(unsigned int milliseconds, sctp_timerCallback timer_cb,
                void *param1, void *param2)
{    
     return sctp_startTimer(milliseconds/1000, (milliseconds%1000)*1000, timer_cb, param1, param2);
}

