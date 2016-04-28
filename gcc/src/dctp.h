/*
 * dctp.h
 *
 *  Created on: 28 Apr 2016
 *      Author: jakez
 */

#ifndef INCLUDE_DCTP_H_
#define INCLUDE_DCTP_H_

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

#define SCTP_MAJOR_VERSION      1
#define SCTP_MINOR_VERSION      0
#define SCTP_TINY_VERSION       8

/* this parameter specifies the maximum number of addresses
 * that an endpoint may have. */
#define DCTP_MAX_NUM_ADDRESSES      20

/* reasonable sized SACK, SCTP and IP header + one data chunk should be
 * less than MTU, this is for ethernet..... ;-) */
#define SCTP_MAXIMUM_DATA_LENGTH     1400
#endif /* DCTP_H_ */
