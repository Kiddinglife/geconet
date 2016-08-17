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
#include "common_header.h"

 
scm_bits_t common_header_tag;

// make_geco_packet_fixed
static SCM
make_common_header (SCM s_source_port, SCM s_destination_port, SCM s_verification_tag)
{
  struct common_header *common_header;
  unsigned short source_port, destination_port;
  unsigned long  verification_tag, checksum;
    
  source_port      = scm_num2ushort (s_source_port,      SCM_ARG1, "make-common-header");
  destination_port = scm_num2ushort (s_destination_port, SCM_ARG2, "make-common-header");
  verification_tag = scm_num2ulong  (s_verification_tag, SCM_ARG3, "make-common-header");
  checksum         = 0L;
  
  common_header = (struct common_header *) scm_must_malloc (sizeof (struct common_header), "common_header");
  memset((void *) common_header, 0, sizeof (struct common_header));
  
  common_header->source_port      = htons(source_port);
  common_header->destination_port = htons(destination_port);
  common_header->verification_tag = htonl(verification_tag);
  common_header->checksum         = htonl(checksum);
  
  SCM_RETURN_NEWSMOB (common_header_tag, common_header);
}

static SCM
common_header_p (SCM chunk_smob)
{
  if (SCM_SMOB_PREDICATE (common_header_tag, chunk_smob))
    return SCM_BOOL_T;
  else
    return SCM_BOOL_F;
}


SCM
get_source_port (SCM common_header_smob)
{
  struct common_header *common_header;

  SCM_ASSERT (SCM_SMOB_PREDICATE (common_header_tag, common_header_smob), common_header_smob, SCM_ARG1, "get-source-port");
  common_header = (struct common_header *) SCM_SMOB_DATA (common_header_smob);
  return scm_ushort2num(ntohs(common_header->source_port));
}

SCM
get_destination_port (SCM common_header_smob)
{
  struct common_header *common_header;

  SCM_ASSERT (SCM_SMOB_PREDICATE (common_header_tag, common_header_smob), common_header_smob, SCM_ARG1, "get-destination-port");
  common_header = (struct common_header *) SCM_SMOB_DATA (common_header_smob);
  return scm_ushort2num(ntohs(common_header->destination_port));
}

SCM
get_verification_tag (SCM common_header_smob)
{
  struct common_header *common_header;

  SCM_ASSERT (SCM_SMOB_PREDICATE (common_header_tag, common_header_smob), common_header_smob, SCM_ARG1, "get-verification-tag");
  common_header = (struct common_header *) SCM_SMOB_DATA (common_header_smob);
  return scm_ulong2num(ntohl(common_header->verification_tag));
}

static SCM
mark_common_header (SCM common_header_smob)
{
   return SCM_BOOL_F;
}

static size_t
free_common_header (SCM common_header_smob)
{
  struct common_header *common_header = (struct common_header *) SCM_SMOB_DATA (common_header_smob);

  free (common_header);
  return (sizeof(struct common_header));
}

static int
print_common_header (SCM common_header_smob, SCM port, scm_print_state *pstate)
{
  struct common_header *common_header = (struct common_header *) SCM_SMOB_DATA (common_header_smob);

  scm_puts ("#<common_header: src=", port);
  scm_display (scm_ushort2num(ntohs(common_header->source_port)), port);
  scm_puts (", dst=", port);
  scm_display (scm_ushort2num(ntohs(common_header->destination_port)), port);
  scm_puts (", tag=", port);
  scm_display (scm_ulong2num(ntohl(common_header->verification_tag)), port);
  scm_puts (">", port);

  /* non-zero means success */
  return 1;
}

/* 
   Two common headers are equalp iff their ports and the verification
   tags are equal. The checksum is not taken into account
*/
static SCM
equalp_common_header (SCM common_header_1_smob, SCM common_header_2_smob)
{
  struct common_header *common_header_1 = (struct common_header *) SCM_SMOB_DATA (common_header_1_smob);
  struct common_header *common_header_2 = (struct common_header *) SCM_SMOB_DATA (common_header_2_smob);
	
	if (common_header_1->source_port != common_header_2->source_port)
		return SCM_BOOL_F;
		
	if (common_header_1->destination_port != common_header_2->destination_port)
		return SCM_BOOL_F;

	if (common_header_1->verification_tag != common_header_2->verification_tag)
		return SCM_BOOL_F;
  
  return SCM_BOOL_T;
}

void
init_common_header_type (void)
{
  common_header_tag = scm_make_smob_type ("common_header", 0);
  scm_set_smob_mark   (common_header_tag, mark_common_header);
  scm_set_smob_free   (common_header_tag, free_common_header);
  scm_set_smob_print  (common_header_tag, print_common_header);
  scm_set_smob_equalp (common_header_tag, equalp_common_header);
  
  scm_c_define_gsubr ("make-common-header",   3, 0, 0, make_common_header);
  scm_c_define_gsubr ("common-header?",       1, 0, 0, common_header_p);
  scm_c_define_gsubr ("get-source-port",      1, 0, 0, get_source_port);
  scm_c_define_gsubr ("get-destination-port", 1, 0, 0, get_destination_port);
  scm_c_define_gsubr ("get-verification-tag", 1, 0, 0, get_verification_tag);
}
