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

scm_bits_t cause_tag;

static SCM
make_cause (SCM s_code, SCM s_info)
{
  struct cause *cause;
  SCM s_e;
  unsigned short code, cause_length, total_length, e, i;
  
  code = scm_num2ushort(s_code, SCM_ARG1, "make-cause");
  SCM_ASSERT (SCM_VECTORP (s_info), s_info, SCM_ARG2, "make-cause");
  
  if (SCM_VECTOR_LENGTH (s_info) > MAX_CAUSE_INFO_LENGTH)
      scm_out_of_range("make-cause", s_info);
  cause_length       = CAUSE_HEADER_LENGTH + SCM_VECTOR_LENGTH (s_info);
  total_length       = ADD_PADDING(cause_length);
  cause = (struct cause *) scm_must_malloc (total_length, "cause");
  memset((void *) cause, 0, total_length);

  cause->code   = htons(code);
  cause->length = htons(cause_length);  
  for(i = 0; i < SCM_VECTOR_LENGTH (s_info); i++) {
    s_e = SCM_VELTS(s_info)[i];
    e   =  scm_num2ushort(s_e, SCM_ARGn, "make-cause");
    if (e > 255) 
      scm_out_of_range("make-cause", s_e);
    cause->info[i] = (unsigned char) e;
  }
  SCM_RETURN_NEWSMOB (cause_tag, cause);
}

static SCM
cause_p (SCM smob)
{
  if (SCM_SMOB_PREDICATE (cause_tag, smob))
    return SCM_BOOL_T;
  else
    return SCM_BOOL_F;
}

static SCM
get_cause_code (SCM cause_smob)
{
    struct cause *cause;
    SCM_ASSERT (SCM_SMOB_PREDICATE (cause_tag, cause_smob) , cause_smob, SCM_ARG1, "get-cause-code");
    cause = (struct cause *) SCM_SMOB_DATA (cause_smob);
    if (ntohs(cause->length) < CAUSE_HEADER_LENGTH)
        scm_syserror_msg ("get-cause-code", "incorrect cause length", cause_smob, 0);
    return scm_ushort2num(ntohs(cause->code));
}
	
static SCM
get_cause_length (SCM cause_smob)
{
    struct cause *cause;
    SCM_ASSERT (SCM_SMOB_PREDICATE (cause_tag, cause_smob) , cause_smob, SCM_ARG1, "get-cause-length");
    cause = (struct cause *) SCM_SMOB_DATA (cause_smob);
    if (ntohs(cause->length) < CAUSE_HEADER_LENGTH)
        scm_syserror_msg ("get-cause-length", "incorrect cause length", cause_smob, 0);
    return scm_ushort2num(ntohs(cause->length));
}

static SCM
get_cause_info (SCM cause_smob)
{
  struct cause *cause;
  SCM s_value;
  unsigned short i, length;
  
  SCM_ASSERT (SCM_SMOB_PREDICATE (cause_tag, cause_smob) , cause_smob, SCM_ARG1, "get-cause-info");
  cause = (struct cause *) SCM_SMOB_DATA (cause_smob);
  if (ntohs(cause->length) < CAUSE_HEADER_LENGTH)
     scm_syserror_msg ("get-cause-info", "incorrect cause length", cause_smob, 0);
  length = ntohs(cause->length) - CAUSE_HEADER_LENGTH;
  s_value = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
  for(i=0; i < length; i++) 
    scm_vector_set_x(s_value, scm_ushort2num(i), scm_ushort2num(cause->info[i]));
    
  return s_value;
}

static SCM
mark_cause (SCM cause_smob)
{
   return SCM_BOOL_F;
}

static size_t
free_cause (SCM cause_smob)
{
  struct cause *cause = (struct cause *) SCM_SMOB_DATA (cause_smob);
  unsigned short total_length;
  
  total_length = ADD_PADDING(ntohs(cause->length));
  free (cause);
  return (total_length);
}

static int
print_cause (SCM cause_smob, SCM port, scm_print_state *pstate)
{
  struct cause *cause = (struct cause *) SCM_SMOB_DATA (cause_smob);

  scm_puts("#<cause: ", port);
  if (ntohs(cause->length) < CAUSE_HEADER_LENGTH)
    scm_puts(" bad formatted>", port);
  else {
    scm_puts("code=", port);
	  scm_display(scm_ushort2num(ntohs(cause->code)), port);
    scm_puts(", length=", port);
    scm_display(scm_ushort2num(ntohs(cause->length)), port);
    scm_puts (">", port);
  }
  return 1;
}

static SCM
equalp_cause (SCM cause_1_smob, SCM cause_2_smob)
{
    unsigned short length;
    struct cause *cause_1 = (struct cause *) SCM_SMOB_DATA (cause_1_smob);
    struct cause *cause_2 = (struct cause *) SCM_SMOB_DATA (cause_2_smob);
	
    if (cause_1->code != cause_2->code)
        return SCM_BOOL_F;
		
    if (cause_1->length != cause_2->length)
        return SCM_BOOL_F;
 
    length = ntohs(cause_1->length);
  
    if (length < CAUSE_HEADER_LENGTH)
        scm_syserror_msg ("equalp_cause", "incorrect cause length", cause_1_smob, 0);
    
    if (memcmp((const void *) cause_1->info,
               (const void *) cause_2->info, length - CAUSE_HEADER_LENGTH))
        return SCM_BOOL_F;
    else
        return SCM_BOOL_T;
}

void
init_causes (void)
{
  cause_tag = scm_make_smob_type ("cause", 0);

  scm_set_smob_mark  (cause_tag, mark_cause);
  scm_set_smob_free  (cause_tag, free_cause);
  scm_set_smob_print (cause_tag, print_cause);
  scm_set_smob_equalp(cause_tag, equalp_cause);

  scm_c_define_gsubr ("make-cause",       2, 0, 0, make_cause);
  scm_c_define_gsubr ("cause?",           1, 0, 0, cause_p);
  scm_c_define_gsubr ("get-cause-code",   1, 0, 0, get_cause_code);
  scm_c_define_gsubr ("get-cause-length", 1, 0, 0, get_cause_length);
  scm_c_define_gsubr ("get-cause-info",   1, 0, 0, get_cause_info);

}
