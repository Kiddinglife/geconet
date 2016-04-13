/*
 * globals.h
 *
 *  Created on: 12 Apr 2016
 *      Author: jakez
 */

#ifndef MY_GLOBALS_H_
#define MY_GLOBALS_H_

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

 #ifdef  HAVE_SYS_TIME_H
  #include <sys/time.h>
  #ifdef TIME_WITH_SYS_TIME
   #include <time.h>
  #endif
 #endif
 #ifdef  HAVE_UNISTD_H
  #include <unistd.h>
 #endif

#ifdef WIN32
#include <winsock2.h>
#include <time.h>
#endif

#ifdef FreeBSD
#include <netinet/in_systm.h>
#include <sys/types.h>
#endif

#ifdef SOLARIS
#include <netinet/in_systm.h>
#include <stdarg.h>
#endif

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#endif


#endif /* MY_GLOBALS_H_ */
