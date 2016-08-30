/*
 * config.h
 *
 *  Created on: 13 Apr 2016
 *      Author: jakez
 */

#ifndef MY_CONFIG_H_
#define MY_CONFIG_H_

//#define USED_UDP_PORT 9899
//#define HAVE_SIN_LEN
//#define HAVE_IPV6_RECVPKTINFO
//#define USE_UDP

//comment those macros before running unit tests
//uncomment those macros after running unit tests
//otherwise these functions will never be invoked
#define enable_mock_dispatcher_disassemle_curr_geco_packet 1
#define enable_mock_dispatch_send_geco_packet 1

#define _DEBUG //uncommnet this in release version
#define GECO_ASSERTIONS
#define GECO_PRINTS
#define CURR_EVENT_LOG_LEVEL 8 // = VERBOSE
#endif /* MY_CONFIG_H_ */
