/*
 * CHANNEL-ip-stack.h
 *
 *  Created on: 20 May 2016
 *      Author: jakez
 */

#ifndef SRC_IP_STACK_H_
#define SRC_IP_STACK_H_

/* the possible 8 states of a channel */
#define CLOSED                     0
#define COOKIE_WAIT                1
#define COOKIE_ECHOED              2
#define ESTABLISHED                3
#define SHUTDOWN_PENDING           4
#define SHUTDOWN_RECEIVED          5
#define SHUTDOWN_SENT              6
#define SHUTDOWNACK_SENT           7

#endif /* SRC_IP_STACK_H_ */
