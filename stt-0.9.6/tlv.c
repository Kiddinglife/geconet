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

#include <string.h>
#if defined LINUX
#include <netinet/in.h>
#elif defined CYGWIN
#include <sys/types.h>
#include <arpa/inet.h>
#elif defined DARWIN
#include <arpa/inet.h>
#elif defined FREEBSD
#include <sys/param.h>
#endif
#include <libguile.h>
#include "common.h"

struct tlv {
  unsigned short unused;
  unsigned short length;
};

#define TLV_LENGTH(x) (ntohs(((struct tlv *)(x))->length))
#define TLV_HEADER_LENGTH 4

/* 
 * scan_tlv_list checks that the first arg is a vector of elements 
 * of scheme objects with tag given as the second arg. If this
 * is not the case the last arg plus one is returned. 
 * scan_tlv_list returns the number between 0 and the last arg which
 * gives the amount of memory needed to pack the first arg in memory
 * with put_tlv_list. If more memory than the last arg is needed,
 * one plus the last arg is returned.
 */
 
unsigned short
scan_tlv_list (SCM s_tlvs, scm_bits_t tag, unsigned short max_length)
{
    unsigned short number_of_tlvs, tlv_number, length, total_length;
    SCM s_tlv;
    struct tlv *tlv;

    number_of_tlvs = SCM_VECTOR_LENGTH (s_tlvs);
    total_length   = 0;
    for(tlv_number = 0; tlv_number < number_of_tlvs; tlv_number++) {
        s_tlv   = SCM_VELTS(s_tlvs)[tlv_number];
        if ((SCM_IMP(s_tlv)) || (SCM_CELL_TYPE (s_tlv) != tag))
            return (max_length + 1);
        tlv     = (struct tlv *) SCM_SMOB_DATA (s_tlv);
        length  = ADD_PADDING(TLV_LENGTH (tlv));
        if ((length <= max_length) && (total_length <= max_length - length))
            total_length += length;
        else
            return (max_length + 1);
    }
    return total_length;
}

void
put_tlv_list (unsigned char *buffer, SCM s_tlvs)
{
    unsigned short number_of_tlvs, tlv_number, offset, length;
    struct tlv *tlv;
    
    number_of_tlvs = SCM_VECTOR_LENGTH (s_tlvs);
    offset         = 0;

    for(tlv_number = 0; tlv_number < number_of_tlvs; tlv_number++) {
        tlv     = (struct tlv *) SCM_SMOB_DATA (SCM_VELTS(s_tlvs)[tlv_number]);
        length  = ADD_PADDING(TLV_LENGTH (tlv));
        memcpy((void *)buffer + offset, (const void *)tlv, length);
        offset += length;
    }
    return;
}

SCM
get_tlv_list (unsigned char *list, unsigned short length, const char *type_name, scm_bits_t tag)
{
  unsigned short offset, tlv_length, total_length, number_of_tlvs, tlv_number;
  long remaining_length;
  
  SCM s_tlv, s_tlvs;
  struct tlv *tlv;
  
  remaining_length = length;
  offset           = 0;
  number_of_tlvs   = 0;
  while (remaining_length >= TLV_HEADER_LENGTH) {
    tlv_length   = TLV_LENGTH(list + offset);
    total_length = ADD_PADDING(tlv_length);
    if (tlv_length > remaining_length)
      return SCM_BOOL_F;
    remaining_length -= total_length;
    offset           += total_length;
    number_of_tlvs++;
  }
  s_tlvs = scm_make_vector(scm_ushort2num(number_of_tlvs), SCM_UNSPECIFIED);
  
  offset = 0;
  for(tlv_number = 0; tlv_number < number_of_tlvs; tlv_number++) {
    tlv_length   = TLV_LENGTH(list + offset);
    total_length = ADD_PADDING(tlv_length);
    tlv          = (struct tlv *) scm_must_malloc (total_length, type_name);
    memset((void *) tlv, 0, total_length);
    memcpy((void *) tlv, (const void *) (list + offset), tlv_length);
    SCM_NEWSMOB (s_tlv, tag, tlv);
    scm_vector_set_x(s_tlvs, scm_ushort2num(tlv_number), s_tlv);
    offset       += total_length;
  }
  return s_tlvs;
}
