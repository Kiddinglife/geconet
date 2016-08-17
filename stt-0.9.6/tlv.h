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

unsigned short
scan_tlv_list (SCM s_tlvs, scm_bits_t tag, unsigned short max_length);

void
put_tlv_list (unsigned char *buffer, SCM s_tlvs);

SCM
get_tlv_list (unsigned char *list, unsigned short length, const char *type_name, scm_bits_t tag);
