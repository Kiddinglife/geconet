/*
 *
 * SCTP test tool stt.
 *
 * Copyright (C) 2002-2003 by Michael Tuexen
 *
 * Realized in co-operation between Siemens AG and the University of
 * Applied Sciences, Muenster.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * There are two mailinglists available at http://www.sctp.de which should be
 * used for any discussion related to this implementation.
 *
 * Contact: discussion@sctp.de
 *          tuexen@fh-muenster.de
 *
 */

#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)
#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP          132
#endif
#define TOS                   0
#ifdef TT_HAVE_SOCKADDR_STORAGE
#define ADDRESS_SIZE          (sizeof(struct sockaddr_storage))
#else
#define ADDRESS_SIZE          (sizeof(struct sockaddr_in))
#endif

#define DATA_CHUNK_TYPE              0x00
#define INIT_CHUNK_TYPE              0x01
#define INIT_ACK_CHUNK_TYPE          0x02
#define SACK_CHUNK_TYPE              0x03
#define HEARTBEAT_CHUNK_TYPE         0x04
#define HEARTBEAT_ACK_CHUNK_TYPE     0x05
#define ABORT_CHUNK_TYPE             0x06
#define SHUTDOWN_CHUNK_TYPE          0x07
#define SHUTDOWN_ACK_CHUNK_TYPE      0x08
#define ERROR_CHUNK_TYPE             0x09
#define COOKIE_ECHO_CHUNK_TYPE       0x0a
#define COOKIE_ACK_CHUNK_TYPE        0x0b
#define ECNE_CHUNK_TYPE              0x0c
#define CWR_CHUNK_TYPE               0x0d
#define SHUTDOWN_COMPLETE_CHUNK_TYPE 0x0e
#define FORWARD_TSN_CHUNK_TYPE       0xc0
#define ASCONF_CHUNK_TYPE            0xc1
#define ASCONF_ACK_CHUNK_TYPE        0x80

#define HEARTBEAT_PARAMETER_TYPE                 0x0001
#define IPV4_ADDRESS_PARAMETER_TYPE              0x0005
#define IPV6_ADDRESS_PARAMETER_TYPE              0x0006
#define COOKIE_PARAMETER_TYPE                    0x0007
#define UNRECOGNIZED_PARAMETER_PARAMETER_TYPE    0x0008
#define COOKIE_PRESERVATIVE_PARAMETER_TYPE       0x0009
#define HOSTNAME_PARAMETER_TYPE                  0x000b
#define SUPPORTED_ADDRESS_TYPE_PARAMETER_TYPE    0x000c
#define ECN_CAPABLE_PARAMETER_TYPE               0x8000
#define FORWARD_TSN_SUPPORTED_PARAMETER_TYPE     0xC000
#define ADD_IP_ADDRESS_PARAMETER_TYPE            0xC001
#define DELETE_IP_ADDRESS_PARAMETER_TYPE         0xC002
#define ERROR_CAUSE_INDICATION_PARAMETER_TYPE    0xC003
#define SET_PRIMARY_ADDRESS_PARAMETER_TYPE       0xC004
#define SUCCESS_INDICATION_PARAMETER_TYPE        0xC005
#define ADAPTION_LAYER_INDICATION_PARAMETER_TYPE 0xC006


#define COMMON_HEADER_LENGTH       12
#define CHUNK_HEADER_LENGTH        4
#define PARAMETER_HEADER_LENGTH    4
#define CAUSE_HEADER_LENGTH        4
#define MAX_IP_PACKET_LENGTH       (1<<16)
#define MIN_IP_HEADER_LENGTH       20
#define MAX_SCTP_PACKET_LENGTH     (MAX_IP_PACKET_LENGTH - MIN_IP_HEADER_LENGTH)
#define MAX_CHUNK_LENGTH           (MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH)
#define MAX_PARAMETER_LENGTH       (MAX_CHUNK_LENGTH - CHUNK_HEADER_LENGTH)
#define MAX_CAUSE_LENGTH           (MAX_CHUNK_LENGTH - CHUNK_HEADER_LENGTH)
#define MAX_CHUNK_DATA_LENGTH      (MAX_CHUNK_LENGTH - CHUNK_HEADER_LENGTH)
#define MAX_PARAMETER_VALUE_LENGTH (MAX_PARAMETER_LENGTH - PARAMETER_HEADER_LENGTH)
#define MAX_CAUSE_INFO_LENGTH      (MAX_CAUSE_LENGTH - CAUSE_HEADER_LENGTH)

struct cause {
  unsigned short code;
  unsigned short length;
  unsigned char  info[0];
};

struct parameter {
  unsigned short type;
  unsigned short length;
  unsigned char  value[0];
};

struct chunk {
  unsigned char  type;
  unsigned char  flags;
  unsigned short length;
  unsigned char  data[0];
};
