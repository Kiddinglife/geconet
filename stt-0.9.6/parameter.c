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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
#include <string.h>
#include <libguile.h>
#include "common.h"
#include "tlv.h"

#define IPV4_ADDRESS_PARAMETER_LENGTH          8
#define IPV6_ADDRESS_PARAMETER_LENGTH          20
#define ECN_CAPABLE_PARAMETER_LENGTH           4
#define COOKIE_PRESERVATIVE_PARAMETER_LENGTH   8
#define ECN_CAPABLE_PARAMETER_LENGTH           4
#define FORWARD_TSN_SUPPORTED_PARAMETER_LENGTH 4
#define CORRELATION_ID_LENGTH                  4
#define CODE_POINT_LENGTH                      4

extern scm_bits_t address_tag;
extern scm_bits_t cause_tag;

scm_bits_t parameter_tag;

struct ipv4_address_parameter {
  unsigned short type;
  unsigned short length;
  unsigned long  address;
};

struct ipv6_address_parameter {
  unsigned short type;
  unsigned short length;
  unsigned long  address[16];
};

struct cookie_preservative_parameter {
  unsigned short type;
  unsigned short length;
  unsigned long  life;
};

struct supported_address_type_parameter {
  unsigned short type;
  unsigned short length;
  unsigned short address_type[0];
};

struct modify_ip_address_parameter {
  unsigned short type;
  unsigned short length;
  unsigned long  correlation_id;
  unsigned long  address[0];
};

struct adaption_layer_indication_parameter {
  unsigned short type;
  unsigned short length;
  unsigned long  code_point;
};

struct success_indication_parameter {
  unsigned short type;
  unsigned short length;
  unsigned long  correlation_id;
};

struct error_cause_indication_parameter {
  unsigned short type;
  unsigned short length;
  unsigned long  correlation_id;
  unsigned char error_causes[0];
};

static SCM
make_tlv_parameter (unsigned short parameter_type, const char *proc_name, SCM s_value)
{
  struct parameter *parameter;
  SCM s_e;
  unsigned short parameter_length, total_length, e, i;
  
  if (SCM_VECTOR_LENGTH (s_value) > MAX_PARAMETER_VALUE_LENGTH)
      scm_out_of_range(proc_name, s_value);
  parameter_length       = PARAMETER_HEADER_LENGTH + SCM_VECTOR_LENGTH (s_value);
  total_length           = ADD_PADDING(parameter_length);
  parameter = (struct parameter *) scm_must_malloc (total_length, "parameter");
  memset((void *) parameter, 0, total_length);

  parameter->type   = htons(parameter_type);
  parameter->length = htons(parameter_length);  
  for(i = 0; i < SCM_VECTOR_LENGTH (s_value); i++) {
    s_e = SCM_VELTS(s_value)[i];
    e   =  scm_num2ushort(s_e, SCM_ARGn, proc_name);
    if (e > 255) 
      scm_out_of_range(proc_name, s_e);
    parameter->value[i] = (unsigned char) e;
  }
  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_heartbeat_parameter (SCM s_info)
{
  SCM_ASSERT (SCM_VECTORP (s_info), s_info, SCM_ARG1, "make-heartbeat-parameter");
  return make_tlv_parameter(HEARTBEAT_PARAMETER_TYPE, "make-heartbeat-parameter", s_info);
}

static SCM
get_heartbeat_info (SCM parameter_smob)
{
  struct parameter *parameter;
  SCM s_info;
  unsigned short i, length;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob) , parameter_smob, SCM_ARG1, "get-heartbeat-info");
  parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->type) != HEARTBEAT_PARAMETER_TYPE)
    scm_syserror_msg ("get-heartbeat-info", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH)
    scm_syserror_msg ("get-heartbeat-info", "incorrect parameter length", parameter_smob, 0);
  length = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH;
  s_info = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
  for(i=0; i < length; i++) 
    scm_vector_set_x(s_info, scm_ushort2num(i), scm_ushort2num(parameter->value[i]));    
  return s_info;
}

static SCM
make_ipv4_address_parameter(SCM s_addr)
{
  struct ipv4_address_parameter *parameter;
  struct sockaddr_in *addr;
    
  SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_addr) , s_addr, SCM_ARG1, "make-ipv4-address-parameter");
  addr = (struct sockaddr_in *) SCM_SMOB_DATA (s_addr);
  if (addr->sin_family != AF_INET)
    scm_syserror_msg ("make-ipv4-address-parameter", "incorrect address type", s_addr, 0);
  parameter          = (struct ipv4_address_parameter *) scm_must_malloc (IPV4_ADDRESS_PARAMETER_LENGTH, "parameter");
  memset((void *) parameter, 0, IPV4_ADDRESS_PARAMETER_LENGTH);

  parameter->type    = htons(IPV4_ADDRESS_PARAMETER_TYPE);
  parameter->length  = htons(IPV4_ADDRESS_PARAMETER_LENGTH);
  memcpy((void *)&(parameter->address), (const void *) &(addr->sin_addr), sizeof(struct in_addr));
  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_ipv4_address (SCM parameter_smob)
{
  struct ipv4_address_parameter *parameter;
  struct sockaddr_in *address;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get-ipv4-address");
  parameter = (struct ipv4_address_parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->type) != IPV4_ADDRESS_PARAMETER_TYPE)
    scm_syserror_msg ("get-ipv4-address", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) != IPV4_ADDRESS_PARAMETER_LENGTH)
    scm_syserror_msg ("get-ipv4-address", "incorrect parameter length", parameter_smob, 0);
  address = (struct sockaddr_in *) scm_must_malloc (ADDRESS_SIZE, "address");
  memset((void *) address, 0, ADDRESS_SIZE);
#ifdef TT_HAVE_SIN_LEN
  address->sin_len    = sizeof(struct sockaddr_in);
#endif
  address->sin_family = AF_INET;
  address->sin_port   = 0;
  memcpy((void *) &(address->sin_addr), (const void *) &(parameter->address), sizeof(struct sockaddr_in));
  SCM_RETURN_NEWSMOB(address_tag, address);
}

static SCM
make_ipv6_address_parameter(SCM s_addr)
{
  struct ipv6_address_parameter *parameter;
  struct sockaddr_in6 *addr;
    
  SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_addr) , s_addr, SCM_ARG1, "make-ipv6-address-parameter");
  addr = (struct sockaddr_in6 *) SCM_SMOB_DATA (s_addr);
  if (addr->sin6_family != AF_INET6)
    scm_syserror_msg ("make_ipv6_address_parameter", "incorrect address type", s_addr, 0);
  parameter          = (struct ipv6_address_parameter *) scm_must_malloc (IPV6_ADDRESS_PARAMETER_LENGTH, "parameter");
  memset((void *) parameter, 0, IPV6_ADDRESS_PARAMETER_LENGTH);

  parameter->type    = htons(IPV6_ADDRESS_PARAMETER_TYPE);
  parameter->length  = htons(IPV6_ADDRESS_PARAMETER_LENGTH);
  memcpy((void *)(parameter->address), (const void *) &(addr->sin6_addr), sizeof(struct in6_addr));
  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_ipv6_address (SCM parameter_smob)
{
  struct ipv6_address_parameter *parameter;
  struct sockaddr_in6 *address;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get-ipv6-address");
  parameter = (struct ipv6_address_parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->type) != IPV6_ADDRESS_PARAMETER_TYPE)
    scm_syserror_msg ("get-ipv6-address", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) != IPV6_ADDRESS_PARAMETER_LENGTH)
    scm_syserror_msg ("get-ipv6-address", "incorrect parameter length", parameter_smob, 0);
  address = (struct sockaddr_in6 *) scm_must_malloc (ADDRESS_SIZE, "address");
  memset((void *) address, 0, ADDRESS_SIZE);
#ifdef TT_HAVE_SIN6_LEN
  address->sin6_len      = sizeof(struct sockaddr_in6);
#endif
  address->sin6_family   = AF_INET6;
  address->sin6_port     = 0;
  address->sin6_flowinfo = 0;
  memcpy((void *) &(address->sin6_addr), (const void *) (parameter->address), sizeof(struct sockaddr_in6));
  SCM_RETURN_NEWSMOB(address_tag, address);
}

static SCM
make_cookie_parameter (SCM s_info)
{
  SCM_ASSERT (SCM_VECTORP (s_info), s_info, SCM_ARG1, "make-cookie-parameter");
  return make_tlv_parameter(COOKIE_PARAMETER_TYPE, "make-cookie-parameter", s_info);
}

static SCM
get_cookie_parameter_cookie (SCM parameter_smob)
{
  struct parameter *parameter;
  SCM s_cookie;
  unsigned short i, length;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get-cookie-parameter-cookie");
  parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->type) != COOKIE_PARAMETER_TYPE)
    scm_syserror_msg ("get-cookie-parameter-cookie", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH)
    scm_syserror_msg ("get-cookie-parameter-cookie", "incorrect parameter length", parameter_smob, 0);
  length    = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH;
  s_cookie  = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
  for(i=0; i < length; i++) 
    scm_vector_set_x(s_cookie, scm_ushort2num(i), scm_ushort2num(parameter->value[i]));    
  return s_cookie;
}

static SCM
make_unrecognized_parameter_parameter (SCM s_unrecognized_parameter)
{
  struct parameter *parameter, *unrecognized_parameter;
  unsigned short length, parameter_length, total_length;
   
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, s_unrecognized_parameter),
              s_unrecognized_parameter, SCM_ARG1, "make-unrecognized-parameter-parameter");
  unrecognized_parameter = (struct parameter *) SCM_SMOB_DATA (s_unrecognized_parameter);
  length                 = ntohs(unrecognized_parameter->length);
  
  if (length > MAX_PARAMETER_VALUE_LENGTH)
      scm_out_of_range("make-unrecognized-parameter-parameter", s_unrecognized_parameter);

  parameter_length       = length + PARAMETER_HEADER_LENGTH;
  total_length           = ADD_PADDING(parameter_length);
  parameter              = (struct parameter *) scm_must_malloc (total_length, "parameter");
  memset((void *) parameter, 0, total_length);
  parameter->type        = htons(UNRECOGNIZED_PARAMETER_PARAMETER_TYPE);
  parameter->length      = htons(parameter_length);
  memcpy((void *)parameter->value, (const void *) unrecognized_parameter, length);
  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_unrecognized_parameter (SCM parameter_smob)
{
  struct parameter *parameter, *unrecognized_parameter;
  unsigned short length, total_length;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get-unrecognized-parameter");
  parameter    = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->type) != UNRECOGNIZED_PARAMETER_PARAMETER_TYPE)
    scm_syserror_msg ("get-unrecognized-parameter", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH)
    scm_syserror_msg ("get-unrecognized-parameter", "incorrect parameter length", parameter_smob, 0);
  length       = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH;
  total_length = ADD_PADDING(length); 
  unrecognized_parameter = (struct parameter *) scm_must_malloc (total_length, "parameter");
  memset((void *) unrecognized_parameter, 0, total_length);
  memcpy((void *) unrecognized_parameter, (const void *) parameter->value, length);
  SCM_RETURN_NEWSMOB (parameter_tag, unrecognized_parameter);
}

static SCM
make_cookie_preservative_parameter(SCM s_life)
{
  struct cookie_preservative_parameter *parameter;
  unsigned long life;
  
  life = scm_num2ulong(s_life, SCM_ARG1, "make-cookie-preservative-parameter");
  parameter = (struct cookie_preservative_parameter *) scm_must_malloc (COOKIE_PRESERVATIVE_PARAMETER_LENGTH, "parameter");
  memset((void *) parameter, 0, COOKIE_PRESERVATIVE_PARAMETER_LENGTH);

  parameter->type   = htons(COOKIE_PRESERVATIVE_PARAMETER_TYPE);
  parameter->length = htons(COOKIE_PRESERVATIVE_PARAMETER_LENGTH);
  parameter->life   = htonl(life);
  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_life_time (SCM parameter_smob)
{
  struct cookie_preservative_parameter *parameter;

  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get_life_time");
  parameter = (struct cookie_preservative_parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->type) != COOKIE_PRESERVATIVE_PARAMETER_TYPE)
    scm_syserror_msg ("get-life-time", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) != COOKIE_PRESERVATIVE_PARAMETER_LENGTH)
    scm_syserror_msg ("get-life-time", "incorrect parameter length", parameter_smob, 0);
  parameter = (struct cookie_preservative_parameter *) SCM_SMOB_DATA (parameter_smob);
  return scm_ulong2num(ntohl(parameter->life));
}

static SCM
make_hostname_parameter(SCM s_name)
{
  struct parameter *parameter;
  unsigned short parameter_length, total_length, i;
  
  SCM_ASSERT (SCM_STRINGP (s_name), s_name, SCM_ARG1, "make-hostname-parameter");
  
  if (SCM_STRING_LENGTH(s_name) > MAX_PARAMETER_VALUE_LENGTH)
      scm_out_of_range("make_hostname_parameter", s_name);

  parameter_length = PARAMETER_HEADER_LENGTH + SCM_STRING_LENGTH(s_name);
  total_length     = ADD_PADDING(parameter_length);
  parameter = (struct parameter *) scm_must_malloc (total_length, "parameter");
  memset((void *) parameter, 0, total_length);

  parameter->type   = htons(HOSTNAME_PARAMETER_TYPE);
  parameter->length = htons(parameter_length);
  for (i=0; i < SCM_STRING_LENGTH(s_name); i++)
    parameter->value[i] = SCM_CHAR(scm_string_ref(s_name, scm_ushort2num(i)));
  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_hostname (SCM parameter_smob)
{
  struct parameter *parameter;

  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get_hostname");
  parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->type) != HOSTNAME_PARAMETER_TYPE)
    scm_syserror_msg ("get-hostname", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH)
    scm_syserror_msg ("get-hostname", "incorrect parameter length", parameter_smob, 0);
  return scm_mem2string(parameter->value, ntohs(parameter->length) - PARAMETER_HEADER_LENGTH);
}

static SCM
make_supported_address_type_parameter(SCM s_types)
{
  struct supported_address_type_parameter *parameter;
  SCM s_type;
  unsigned short parameter_value_length, parameter_length, total_length, type, i;
  
  SCM_ASSERT (SCM_VECTORP (s_types), s_types, SCM_ARG1, "make-supported-address-type-parameter");
  if (SCM_VECTOR_LENGTH(s_types) > (MAX_PARAMETER_VALUE_LENGTH / 2)) 
      scm_out_of_range("make-supported-address-type-parameter", s_types);
  parameter_value_length = 2 * SCM_VECTOR_LENGTH (s_types);
  parameter_length       = PARAMETER_HEADER_LENGTH + parameter_value_length;
  total_length           = ADD_PADDING(parameter_length);
  parameter = (struct supported_address_type_parameter *) scm_must_malloc (total_length, "parameter");
  memset((void *) parameter, 0, total_length);
  parameter->type   = htons(SUPPORTED_ADDRESS_TYPE_PARAMETER_TYPE);
  parameter->length = htons(parameter_length);  
  for(i = 0; i < SCM_VECTOR_LENGTH (s_types); i++) {
    s_type                     = SCM_VELTS(s_types)[i];
    type                       = scm_num2ushort(s_type, SCM_ARGn, "make-supported-address-type-parameter");
    parameter->address_type[i] = htons(type);
  }
  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_supported_address_types (SCM parameter_smob)
{
  struct supported_address_type_parameter *parameter;
  SCM s_types;
  unsigned short type_number, number_of_types;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob) , parameter_smob, SCM_ARG1, "get-supported-address-types");
  parameter = (struct supported_address_type_parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->type) != SUPPORTED_ADDRESS_TYPE_PARAMETER_TYPE)
    scm_syserror_msg ("get-supported-address-types", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH)
    scm_syserror_msg ("get-supported-address-types", "incorrect parameter length", parameter_smob, 0);
  number_of_types = (ntohs(parameter->length) - PARAMETER_HEADER_LENGTH) / 2;
  
  s_types = scm_make_vector(scm_ushort2num(number_of_types), SCM_UNSPECIFIED);
  for(type_number = 0; type_number < number_of_types; type_number++)
    scm_vector_set_x(s_types, scm_ushort2num(type_number), scm_ushort2num(ntohs(parameter->address_type[type_number])));
  return s_types;
}

static SCM
make_ecn_capable_parameter ()
{
  struct parameter *parameter = (struct parameter *) scm_must_malloc (ECN_CAPABLE_PARAMETER_LENGTH, "parameter");
  
  memset((void *) parameter, 0, ECN_CAPABLE_PARAMETER_LENGTH);
  parameter->type   = htons(ECN_CAPABLE_PARAMETER_TYPE);
  parameter->length = htons(ECN_CAPABLE_PARAMETER_LENGTH);
  
  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_forward_tsn_supported_parameter ()
{
  struct parameter *parameter = (struct parameter *) scm_must_malloc (FORWARD_TSN_SUPPORTED_PARAMETER_LENGTH, "parameter");
  
  memset((void *) parameter, 0, FORWARD_TSN_SUPPORTED_PARAMETER_LENGTH);
  parameter->type   = htons(FORWARD_TSN_SUPPORTED_PARAMETER_TYPE);
  parameter->length = htons(FORWARD_TSN_SUPPORTED_PARAMETER_LENGTH);
  
  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_add_ip_address_parameter (SCM s_correlation_id, SCM s_address_parameter)
{
  struct parameter *address_parameter;
  struct modify_ip_address_parameter *parameter;
  unsigned long correlation_id;
  unsigned short address_parameter_length, parameter_length, total_length;
  
  correlation_id = scm_num2ulong(s_correlation_id, SCM_ARG1, "make-add-ip-address-parameter");
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, s_address_parameter), s_address_parameter, SCM_ARG2, "make-add-ip-address-parameter");

  address_parameter         = (struct parameter *) SCM_SMOB_DATA (s_address_parameter);
  address_parameter_length  = ntohs(address_parameter->length);
  parameter_length          = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + address_parameter_length;
  total_length              = ADD_PADDING(parameter_length);
  
  parameter = (struct modify_ip_address_parameter *) scm_must_malloc(total_length, "parameter");
  memset((void *) parameter, 0, total_length);
  parameter->type           = htons(ADD_IP_ADDRESS_PARAMETER_TYPE);
  parameter->length         = htons(parameter_length);
  parameter->correlation_id = htonl(correlation_id);
  memcpy((void *) parameter->address, (const void *) address_parameter, address_parameter_length);

  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_correlation_id (SCM parameter_smob)
{
  struct modify_ip_address_parameter *parameter;

  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get-correlation-id");
  parameter = (struct modify_ip_address_parameter *) SCM_SMOB_DATA (parameter_smob);
  if ((ntohs(parameter->type) != ADD_IP_ADDRESS_PARAMETER_TYPE) &&
      (ntohs(parameter->type) != DELETE_IP_ADDRESS_PARAMETER_TYPE) &&
      (ntohs(parameter->type) != SET_PRIMARY_ADDRESS_PARAMETER_TYPE) &&
      (ntohs(parameter->type) != ERROR_CAUSE_INDICATION_PARAMETER_TYPE) &&
      (ntohs(parameter->type) != SUCCESS_INDICATION_PARAMETER_TYPE))
    scm_syserror_msg ("get-correlation-id", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH)
    scm_syserror_msg ("get-correlation-id", "incorrect parameter length", parameter_smob, 0);
  return scm_ulong2num(ntohl(parameter->correlation_id));
}

static SCM
get_address_parameter (SCM parameter_smob)
{
  struct modify_ip_address_parameter *parameter;
  struct parameter *address_parameter;
  unsigned short address_parameter_length, address_parameter_total_length;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get-address-parameter");
  parameter = (struct modify_ip_address_parameter *) SCM_SMOB_DATA (parameter_smob);
  if ((ntohs(parameter->type) != ADD_IP_ADDRESS_PARAMETER_TYPE) &&
      (ntohs(parameter->type) != DELETE_IP_ADDRESS_PARAMETER_TYPE) &&
      (ntohs(parameter->type) != SET_PRIMARY_ADDRESS_PARAMETER_TYPE))
    scm_syserror_msg ("get-address-parameter", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) < 2 * PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH)
    scm_syserror_msg ("get-address-parameter", "incorrect parameter length", parameter_smob, 0);
  address_parameter_length = ntohs(((struct parameter *)parameter->address)->length);
  if (address_parameter_length > ntohs(parameter->length) - PARAMETER_HEADER_LENGTH - CORRELATION_ID_LENGTH)
    scm_syserror_msg ("get-address-parameter", "incorrect address parameter", parameter_smob, 0);
  address_parameter_total_length = ADD_PADDING(address_parameter_length);
  address_parameter = (struct parameter *)scm_must_malloc (address_parameter_total_length, "parameter");
  memset((void *) address_parameter, 0, address_parameter_total_length);
  memcpy((void *) address_parameter, (const void *) parameter->address, address_parameter_length);
  SCM_RETURN_NEWSMOB (parameter_tag, address_parameter);
}

static SCM
make_delete_ip_address_parameter (SCM s_correlation_id, SCM s_address_parameter)
{
  struct parameter *address_parameter;
  struct modify_ip_address_parameter *parameter;
  unsigned long correlation_id;
  unsigned short address_parameter_length, parameter_length, total_length;
  
  correlation_id = scm_num2ulong(s_correlation_id, SCM_ARG1, "make-delete-ip-address-parameter");
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, s_address_parameter), s_address_parameter, SCM_ARG2, "make-delete-ip_address-parameter");

  address_parameter         = (struct parameter *) SCM_SMOB_DATA (s_address_parameter);
  address_parameter_length  = ntohs(address_parameter->length);
  parameter_length          = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + address_parameter_length;
  total_length              = ADD_PADDING(parameter_length);
  
  parameter = (struct modify_ip_address_parameter *) scm_must_malloc(total_length, "parameter");
  memset((void *) parameter, 0, total_length);
  parameter->type           = htons(DELETE_IP_ADDRESS_PARAMETER_TYPE);
  parameter->length         = htons(parameter_length);
  parameter->correlation_id = htonl(correlation_id);
  memcpy((void *) parameter->address, (const void *) address_parameter, address_parameter_length);

  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_set_primary_address_parameter (SCM s_correlation_id, SCM s_address_parameter)
{
  struct parameter *address_parameter;
  struct modify_ip_address_parameter *parameter;
  unsigned long correlation_id;
  unsigned short address_parameter_length, parameter_length, total_length;

  correlation_id = scm_num2ulong(s_correlation_id, SCM_ARG1, "make-set-primary-address-parameter");
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, s_address_parameter), s_address_parameter, SCM_ARG2, "make-set-primary-address-parameter");

  address_parameter         = (struct parameter *) SCM_SMOB_DATA (s_address_parameter);
  address_parameter_length  = ntohs(address_parameter->length);
  parameter_length          = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + address_parameter_length;
  total_length              = ADD_PADDING(parameter_length);

  parameter = (struct modify_ip_address_parameter *) scm_must_malloc(total_length, "parameter");
  memset((void *) parameter, 0, total_length);
  parameter->type           = htons(SET_PRIMARY_ADDRESS_PARAMETER_TYPE);
  parameter->length         = htons(parameter_length);
  parameter->correlation_id = htonl(correlation_id);
  memcpy((void *) parameter->address, (const void *) address_parameter, address_parameter_length);

  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_adaption_layer_indication_parameter (SCM s_code_point)
{
  struct adaption_layer_indication_parameter *parameter;
  unsigned long code_point;
  unsigned short parameter_length, total_length;
  
  code_point                = scm_num2ulong(s_code_point, SCM_ARG1, "make-adaption-layer-indication-parameter");
  parameter_length          = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + CODE_POINT_LENGTH;
  total_length              = ADD_PADDING(parameter_length);
  parameter = (struct adaption_layer_indication_parameter *) scm_must_malloc(total_length, "parameter");
  memset((void *) parameter, 0, total_length);
  parameter->type           = htons(ADAPTION_LAYER_INDICATION_PARAMETER_TYPE);
  parameter->length         = htons(parameter_length);
  parameter->code_point     = htonl(code_point);

  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_code_point (SCM parameter_smob)
{
  struct adaption_layer_indication_parameter *parameter;

  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get-code-point");
  parameter = (struct adaption_layer_indication_parameter *) SCM_SMOB_DATA (parameter_smob);
  if ((ntohs(parameter->type) != ADAPTION_LAYER_INDICATION_PARAMETER_TYPE))
    scm_syserror_msg ("get-code-point", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) != PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH)
    scm_syserror_msg ("get-code-point", "incorrect parameter length", parameter_smob, 0);
  parameter = (struct adaption_layer_indication_parameter *) SCM_SMOB_DATA (parameter_smob);
  return scm_ulong2num(ntohl(parameter->code_point));
}


static SCM
make_success_indication_parameter (SCM s_correlation_id)
{
  struct success_indication_parameter *parameter;
  unsigned long correlation_id;
  unsigned short parameter_length, total_length;
  
  correlation_id            = scm_num2ulong(s_correlation_id, SCM_ARG1, "make-success-indication-parameter");
  parameter_length          = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH;
  total_length              = ADD_PADDING(parameter_length);
  parameter = (struct success_indication_parameter *) scm_must_malloc(total_length, "parameter");
  memset((void *) parameter, 0, total_length);
  parameter->type           = htons(SUCCESS_INDICATION_PARAMETER_TYPE);
  parameter->length         = htons(parameter_length);
  parameter->correlation_id = htonl(correlation_id);

  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_error_cause_indication_parameter (SCM s_correlation_id, SCM s_causes)
{
  struct error_cause_indication_parameter *parameter;
  unsigned long correlation_id;
  unsigned short parameter_length, total_length, error_causes_length;
  
  correlation_id            = scm_num2ulong(s_correlation_id, SCM_ARG1, "make-success-indication-parameter");
  if (!SCM_UNBNDP(s_causes)) {
    SCM_ASSERT (SCM_VECTORP (s_causes) , s_causes, SCM_ARG2, "make-abort-chunk");  
    error_causes_length = scan_tlv_list(s_causes, cause_tag, MAX_CAUSE_LENGTH - CORRELATION_ID_LENGTH);
    if (error_causes_length > MAX_CAUSE_LENGTH) 
      scm_syserror_msg ("make-error-cause-indication-chunk", "error causes too long", s_causes, 0);
  } else
    error_causes_length = 0;
    
  parameter_length          = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + error_causes_length;
  total_length              = ADD_PADDING(parameter_length);
  parameter = (struct error_cause_indication_parameter *) scm_must_malloc(total_length, "parameter");
  memset((void *) parameter, 0, total_length);
  parameter->type           = htons(ERROR_CAUSE_INDICATION_PARAMETER_TYPE);
  parameter->length         = htons(parameter_length);
  parameter->correlation_id = htonl(correlation_id);
  if (!SCM_UNBNDP(s_causes))  
    put_tlv_list (parameter->error_causes, s_causes);

  SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_asconf_error_causes (SCM parameter_smob)
{
  struct error_cause_indication_parameter *parameter;  
  unsigned short error_causes_length;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob), parameter_smob, SCM_ARG1, "get-asconf-error-causes");
  parameter = (struct error_cause_indication_parameter *) SCM_SMOB_DATA (parameter_smob);
  if ((parameter->type != ERROR_CAUSE_INDICATION_PARAMETER_TYPE))
     scm_syserror_msg ("get-asconf-error-causes", "incorrect parameter type", parameter_smob, 0);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH)
     scm_syserror_msg ("get-asconf-error-causes", "incorrect parameter length", parameter_smob, 0);
  error_causes_length = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH - CORRELATION_ID_LENGTH;
  return get_tlv_list(parameter->error_causes, error_causes_length, "cause", cause_tag);
}

static SCM
make_parameter (SCM s_type, SCM s_value)
{
  unsigned short type;
  const char proc_name[] = "make-parameter";
  
  type = scm_num2ushort(s_type, SCM_ARG1, "make-parameter");
  SCM_ASSERT (SCM_VECTORP (s_value), s_value, SCM_ARG2, "make-parameter");
  
  return make_tlv_parameter(type, proc_name, s_value);
}

static SCM
get_parameter_type (SCM parameter_smob)
{
  struct parameter *parameter;
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob) , parameter_smob, SCM_ARG1, "get-parameter-type");
  parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH)
    scm_syserror_msg ("get-parameter-type", "incorrect parameter length", parameter_smob, 0);
  return scm_ushort2num(ntohs(parameter->type));
}
  
static SCM
get_parameter_length (SCM parameter_smob)
{
  struct parameter *parameter;
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob) , parameter_smob, SCM_ARG1, "get-parameter-length");
  parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH)
    scm_syserror_msg ("get-parameter-length", "incorrect parameter length", parameter_smob, 0);
  return scm_ushort2num(ntohs(parameter->length));
}

static SCM
get_parameter_value (SCM parameter_smob)
{
  struct parameter *parameter;
  SCM s_value;
  unsigned short i, length;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (parameter_tag, parameter_smob) , parameter_smob, SCM_ARG1, "get-parameter-value");
  parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
  if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH)
    scm_syserror_msg ("get-parameter-value", "incorrect parameter length", parameter_smob, 0);
  length = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH;
  s_value = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
  for(i=0; i < length; i++) 
    scm_vector_set_x(s_value, scm_ushort2num(i), scm_ushort2num(parameter->value[i]));
    
  return s_value;
}

static SCM
parameter_p (SCM smob)
{
  if (SCM_SMOB_PREDICATE (parameter_tag, smob))
    return SCM_BOOL_T;
  else
    return SCM_BOOL_F;
}

/*

static int
print_heartbeat_parameter (SCM parameter_smob, SCM port, scm_print_state *pstate)
{
  struct parameter *parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);

  scm_puts("#<heartbeat: ", port);
  scm_display(scm_ushort2num(ntohs(parameter->length) - 4), port);
  scm_puts (" bytes heartbeat info>", port);
  return 1;
}


static int
print_ipv4_address_parameter (SCM parameter_smob, SCM port, scm_print_state *pstate)
{
  struct ipv4_address_parameter *parameter = (struct ipv4_address_parameter *) SCM_SMOB_DATA (parameter_smob);
  struct in_addr addr;
  char   addr_string[INET_ADDRSTRLEN];
  
  addr.s_addr = parameter->address;
  inet_ntop(AF_INET, (const void *)&addr, addr_string, INET_ADDRSTRLEN);
  
  scm_puts("#<IPv4: ", port);
  scm_puts(addr_string, port);
  scm_puts (">", port);
  return 1;
}

static int
print_cookie_parameter (SCM parameter_smob, SCM port, scm_print_state *pstate)
{
  struct parameter *parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);

  scm_puts("#<cookie: ", port);
  scm_display(scm_ushort2num(ntohs(parameter->length) - 4), port);
  scm_puts (" bytes state cookie>", port);
  return 1;
}

static int
print_unrecognized_parameter_parameter (SCM parameter_smob, SCM port, scm_print_state *pstate)
{
  struct parameter *parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);

  scm_puts("#<unrecognized parameter: ", port);
  scm_puts("type:", port);
  scm_display(scm_ushort2num(ntohs(parameter->type)), port);
  scm_puts(", length:", port);
  scm_display(scm_ushort2num(ntohs(parameter->length)), port);
  scm_puts(">", port);
  return 1;
}



static int
print_cookie_preservative_parameter (SCM parameter_smob, SCM port, scm_print_state *pstate)
{
  struct cookie_preservative_parameter *parameter = (struct cookie_preservative_parameter *) SCM_SMOB_DATA (parameter_smob);
  
  scm_puts("cookie preservative: ", port);
  scm_puts("life: ", port);
  scm_display(scm_ulong2num(ntohl(parameter->life)), port);
  scm_puts (">", port);
  return 1;
}


static int
print_hostname_parameter (SCM parameter_smob, SCM port, scm_print_state *pstate)
{
  unsigned short name_length, i;
  struct parameter *parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);

  name_length = parameter->length - 4;
  scm_puts("<hostname: ", port);
  for(i=0; i < name_length; i++) 
    scm_display(SCM_MAKE_CHAR(parameter->value[i]), port);
  scm_puts (">", port);
  return 1;
}


static int
print_supported_address_type_parameter (SCM parameter_smob, SCM port, scm_print_state *pstate)
{
  struct supported_address_type_parameter *parameter = (struct supported_address_type_parameter *) SCM_SMOB_DATA (parameter_smob); ;
  unsigned short i, nr_of_types;
  
  scm_puts("supported address types: ", port);
  nr_of_types = (parameter->length - 4) >> 1;
  for (i = 0; i < nr_of_types - 1; i++) {
    scm_display(scm_ushort2num(ntohl(parameter->address_type[i])), port);
    scm_puts(", ", port);
  }
  if (nr_of_types > 0)
    scm_display(scm_ushort2num(ntohl(parameter->address_type[nr_of_types])), port);
  scm_puts(">", port);
  return 1;
}



static int
print_ecn_capable_parameter (SCM parameter_smob, SCM port, scm_print_state *pstate)
{
  scm_puts("#<ecn capable>", port);
  return 1;
}
*/

static SCM
mark_parameter (SCM parameter_smob)
{
   return SCM_BOOL_F;
}

static size_t
free_parameter (SCM parameter_smob)
{
  struct parameter *parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
  unsigned short total_length;
  
  total_length = ADD_PADDING(ntohs(parameter->length));
  free (parameter);
  return (total_length);
}

static int
print_parameter (SCM parameter_smob, SCM port, scm_print_state *pstate)
{
  struct parameter *parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);

  scm_puts("#<parameter: ", port);
  if (ntohs(parameter->length < PARAMETER_HEADER_LENGTH))
    scm_puts("bad formatted>", port);
  else {
    scm_puts("type=", port);
    scm_display(scm_ushort2num(ntohs(parameter->type)), port);
    scm_puts(", length=", port);
    scm_display(scm_ushort2num(ntohs(parameter->length)), port);
    scm_puts (">", port);
  }
  return 1;
}

static SCM
equalp_parameter (SCM parameter_1_smob, SCM parameter_2_smob)
{
  unsigned short length;
  struct parameter *parameter_1 = (struct parameter *) SCM_SMOB_DATA (parameter_1_smob);
  struct parameter *parameter_2 = (struct parameter *) SCM_SMOB_DATA (parameter_2_smob);

  if (parameter_1->type != parameter_2->type)
    return SCM_BOOL_F;
    
  if (parameter_1->length != parameter_2->length)
    return SCM_BOOL_F;

  length = ntohs(parameter_1->length);
  
  if (length < PARAMETER_HEADER_LENGTH)
    scm_syserror_msg ("equalp_parameter", "incorrect parameter length", parameter_1_smob, 0);
  
  if (memcmp((const void *) parameter_1->value,
             (const void *) parameter_2->value, length - PARAMETER_HEADER_LENGTH))
    return SCM_BOOL_F;
  else
    return SCM_BOOL_T;
}

void
init_parameters (void)
{
  parameter_tag = scm_make_smob_type ("parameter", 0);

  scm_set_smob_mark  (parameter_tag, mark_parameter);
  scm_set_smob_free  (parameter_tag, free_parameter);
  scm_set_smob_print (parameter_tag, print_parameter);
  scm_set_smob_equalp(parameter_tag, equalp_parameter);

  scm_c_define_gsubr ("make-parameter",                           2, 0, 0, make_parameter);
  scm_c_define_gsubr ("parameter?",                               1, 0, 0, parameter_p);
  scm_c_define_gsubr ("get-parameter-type",                       1, 0, 0, get_parameter_type);
  scm_c_define_gsubr ("get-parameter-length",                     1, 0, 0, get_parameter_length);
  scm_c_define_gsubr ("get-parameter-value",                      1, 0, 0, get_parameter_value);

  scm_c_define_gsubr ("make-heartbeat-parameter",                 1, 0, 0, make_heartbeat_parameter);
  scm_c_define_gsubr ("get-heartbeat-info",                       1, 0, 0, get_heartbeat_info);
  scm_c_define_gsubr ("make-ipv4-address-parameter",              1, 0, 0, make_ipv4_address_parameter);
  scm_c_define_gsubr ("get-ipv4-address",                         1, 0, 0, get_ipv4_address);
  scm_c_define_gsubr ("make-ipv6-address-parameter",              1, 0, 0, make_ipv6_address_parameter);
  scm_c_define_gsubr ("get-ipv6-address",                         1, 0, 0, get_ipv6_address);
  scm_c_define_gsubr ("make-cookie-parameter",                    1, 0, 0, make_cookie_parameter);
  scm_c_define_gsubr ("get-cookie-parameter-cookie",              1, 0, 0, get_cookie_parameter_cookie);
  scm_c_define_gsubr ("make-unrecognized-parameter-parameter",    1, 0, 0, make_unrecognized_parameter_parameter);
  scm_c_define_gsubr ("get-unrecognized-parameter",               1, 0, 0, get_unrecognized_parameter);
  scm_c_define_gsubr ("make-cookie-preservative-parameter",       1, 0, 0, make_cookie_preservative_parameter);
  scm_c_define_gsubr ("get-life-time",                            1, 0, 0, get_life_time);
  scm_c_define_gsubr ("make-hostname-parameter",                  1, 0, 0, make_hostname_parameter);
  scm_c_define_gsubr ("get-hostname",                             1, 0, 0, get_hostname);
  scm_c_define_gsubr ("make-supported-address-type-parameter",    1, 0, 0, make_supported_address_type_parameter);
  scm_c_define_gsubr ("get-supported-address-types",              1, 0, 0, get_supported_address_types);
  scm_c_define_gsubr ("make-ecn-capable-parameter",               0, 0, 0, make_ecn_capable_parameter);
  scm_c_define_gsubr ("make-forward-tsn-supported-parameter",     0, 0, 0, make_forward_tsn_supported_parameter);
  scm_c_define_gsubr ("make-add-ip-address-parameter",            2, 0, 0, make_add_ip_address_parameter);
  scm_c_define_gsubr ("get-correlation-id",                       1, 0, 0, get_correlation_id);
  scm_c_define_gsubr ("get-address-parameter",                    1, 0, 0, get_address_parameter);
  scm_c_define_gsubr ("make-delete-ip-address-parameter",         2, 0, 0, make_delete_ip_address_parameter);
  scm_c_define_gsubr ("make-set-primary-address-parameter",       2, 0, 0, make_set_primary_address_parameter);
  scm_c_define_gsubr ("make-adaption-layer-indication-parameter", 1, 0, 0, make_adaption_layer_indication_parameter);
  scm_c_define_gsubr ("get-code-point",                           1, 0, 0, get_code_point);
  scm_c_define_gsubr ("make-success-indication-parameter",        1, 0, 0, make_success_indication_parameter);
  scm_c_define_gsubr ("make-error-cause-indication-parameter",    1, 1, 0, make_error_cause_indication_parameter);
  scm_c_define_gsubr ("get-asconf-error-causes",                  1, 0, 0, get_asconf_error_causes);
}
