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
#include <arpa/inet.h>
#include <string.h>
#include <libguile.h>

#include <common.h>

scm_bits_t address_tag;

static SCM
make_ipv4_address (SCM s_address)
{
  struct sockaddr_in *addr;
  struct in_addr sin_addr;
  
  SCM_ASSERT (SCM_STRINGP (s_address) , s_address, SCM_ARG1, "make-ipv4-address");
#ifdef TT_HAVE_INET_PTON    
  if (inet_pton(AF_INET, SCM_STRING_CHARS(s_address), &sin_addr) == 1) {
#else
  if (inet_aton(SCM_STRING_CHARS(s_address), &sin_addr) == 1) {
#endif
    addr = (struct sockaddr_in *) scm_must_malloc (ADDRESS_SIZE, "address");
    memset((void *) addr, 0, ADDRESS_SIZE);
#ifdef TT_HAVE_SIN_LEN
    addr->sin_len    = sizeof(struct sockaddr_in);
#endif
    addr->sin_family = AF_INET;
    addr->sin_port   = 0;
    addr->sin_addr   = sin_addr;
    SCM_RETURN_NEWSMOB (address_tag, addr);
  } else
    return SCM_BOOL_F;
}

static SCM
make_ipv6_address (SCM s_address)
{
#if ((defined TT_HAVE_SOCKADDR_IN6) && (defined TT_HAVE_INET_PTON) && (defined TT_HAVE_AF_INET6))
  struct sockaddr_in6 *addr;
  struct in6_addr sin6_addr;
#endif
  
  SCM_ASSERT (SCM_STRINGP (s_address) , s_address, SCM_ARG1, "make-ipv6-address");
#if ((defined TT_HAVE_SOCKADDR_IN6) && (defined TT_HAVE_INET_PTON) && (defined TT_HAVE_AF_INET6)) 
  if (inet_pton(AF_INET6, SCM_STRING_CHARS(s_address), &sin6_addr) == 1) {
    addr = (struct sockaddr_in6 *) scm_must_malloc (ADDRESS_SIZE, "address");
    memset((void *) addr, 0, ADDRESS_SIZE);
#ifdef TT_HAVE_SIN6_LEN
    addr->sin6_len      = sizeof(struct sockaddr_in6);
#endif
    addr->sin6_family   = AF_INET6;
    addr->sin6_port     = 0;
    addr->sin6_flowinfo = 0;
    memcpy((void *) &(addr->sin6_addr), (const void *) &sin6_addr, sizeof(struct in6_addr));
    
    SCM_RETURN_NEWSMOB (address_tag, addr);
  } else
     return SCM_BOOL_F;
#endif
  return SCM_BOOL_F;
}

static SCM
mark_address (SCM address_smob)
{
   return SCM_BOOL_F;
}

static size_t
free_address (SCM address_smob)
{  
#ifdef TT_HAVE_SOCKADDR_STORAGE
  free ((struct sockaddr_storage *)SCM_SMOB_DATA (address_smob));
#else
  free ((struct sockaddr_in *)SCM_SMOB_DATA (address_smob));
#endif
  return (ADDRESS_SIZE);
}

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

static int
print_address (SCM address_smob, SCM port, scm_print_state *pstate)
{
#ifdef TT_HAVE_SOCKADDR_STORAGE
  struct sockaddr_storage *address = (struct sockaddr_storage *) SCM_SMOB_DATA (address_smob);
  char address_string[INET6_ADDRSTRLEN];
#else
  struct sockaddr_in *address = (struct sockaddr_in *) SCM_SMOB_DATA (address_smob);
  char address_string[INET_ADDRSTRLEN];
#endif

  scm_puts("#<address: ", port);
#ifdef TT_HAVE_SOCKADDR_STORAGE
  switch (address->ss_family) {
#else
  switch (address->sin_family) {
#endif
    case AF_INET:
#ifdef TT_HAVE_INET_NTOP
      inet_ntop(AF_INET, &(((struct sockaddr_in *)address)->sin_addr), address_string, INET_ADDRSTRLEN);
#else
      strcpy(address_string, inet_ntoa(((struct sockaddr_in *)address)->sin_addr));
#endif
      break;
#if ((defined TT_HAVE_AF_INET6) && (TT_HAVE_INET_NTOP))
    case AF_INET6:
       inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)address)->sin6_addr), address_string, INET6_ADDRSTRLEN);
#endif
     break;
  }
  scm_puts(address_string, port);
  scm_puts (">", port);
  return 1;
}

static SCM
equalp_address (SCM address_1_smob, SCM address_2_smob)
{
     
  if (memcmp((const void *) SCM_SMOB_DATA (address_1_smob),
             (const void *) SCM_SMOB_DATA (address_2_smob), ADDRESS_SIZE))
    return SCM_BOOL_F;
  else
    return SCM_BOOL_T;
}

void
init_addresses (void)
{
  address_tag = scm_make_smob_type ("address", ADDRESS_SIZE);

  scm_set_smob_mark  (address_tag, mark_address);
  scm_set_smob_free  (address_tag, free_address);
  scm_set_smob_print (address_tag, print_address);
  scm_set_smob_equalp(address_tag, equalp_address);

  scm_c_define_gsubr ("make-ipv4-address",  1, 0, 0, make_ipv4_address);
  scm_c_define_gsubr ("make-ipv6-address",  1, 0, 0, make_ipv6_address);
}
