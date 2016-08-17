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
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <stdio.h>
#include <libguile.h>
#include <string.h>
#include <errno.h>

#include "common.h"
#include "parameter.h"
#include "cause.h"
#include "chunk.h"
#include "checksum.h"
#include "common_header.h"
#include "addresses.h"
#include "tlv.h"

extern scm_bits_t address_tag;
extern scm_bits_t common_header_tag;
extern scm_bits_t chunk_tag;
/*
 * TODO before release as 1.0
 * - Documentation
 * - add IPv6 support
 * - add AddIP support
 * TODO after 1.0
 * - add error causes
 * - add print routines
 * - Fix bugs, add user requested featues
 */

static unsigned char packet [IP_MAXPACKET];

static int sctpv4_fd;
#ifdef TT_HAVE_AF_INET6
static int sctpv6_fd;
#endif
#if (defined TT_HAVE_AF_INET6) && (defined TT_HAVE_SOCKADDR_IN6) && (defined TT_HAVE_SOCKADDR_STORAGE)
static struct sockaddr_storage address_any_v4;
static struct sockaddr_storage address_any_v6;
#else
static struct sockaddr_in address_any_v4;
#endif

static SCM 
sctp_send_v4 (struct sockaddr_in *to_address, struct sockaddr_in *from_address, unsigned short length)
{
#ifdef TT_HAVE_IP_HDRINCL
#ifdef LINUX
    struct iphdr *ip_header = (struct iphdr *) packet;
#else
    struct ip *ip_header    = (struct ip *) packet;
#endif 

#ifdef LINUX
    ip_header->version    = IPVERSION;
    ip_header->ihl        = sizeof(struct iphdr) >> 2;
    ip_header->tos        = TOS;
    ip_header->tot_len    = htons(length + sizeof(*ip_header));
    ip_header->id         = 0;               /* filled in by the kernel */
    ip_header->frag_off   = 0;               /* filled in by the kernel */
    ip_header->ttl        = IPDEFTTL;
    ip_header->protocol   = IPPROTO_SCTP;
    ip_header->check      = 0;               /* calculated and filled in by the kernel */

    memcpy((void *) &(ip_header->daddr), (const void *) &(to_address->sin_addr),   sizeof(struct in_addr));
    memcpy((void *) &(ip_header->saddr), (const void *) &(from_address->sin_addr), sizeof(struct in_addr));
#else
    ip_header->ip_v          = IPVERSION;
    ip_header->ip_hl         = sizeof(struct ip) >> 2;
    ip_header->ip_tos        = TOS;
    ip_header->ip_len        = length + sizeof(*ip_header);
    ip_header->ip_id         = 0;               /* filled in by the kernel */
    ip_header->ip_off        = 0;               /* filled in by the kernel */
    ip_header->ip_ttl        = IPDEFTTL;
    ip_header->ip_p          = IPPROTO_SCTP;
    ip_header->ip_sum        = 0;               /* calculated and filled in by the kernel */

    memcpy((void *) &(ip_header->ip_dst), (const void *) &(to_address->sin_addr),   sizeof(struct in_addr));
    memcpy((void *) &(ip_header->ip_src), (const void *) &(from_address->sin_addr), sizeof(struct in_addr));
#endif

    if ((short)(length + sizeof(*ip_header)) == sendto(sctpv4_fd, packet, length + sizeof(*ip_header), 0, (const struct sockaddr *) to_address, sizeof(struct sockaddr_in)))
#else
    if (length == sendto(sctpv4_fd, packet, length, 0, (const struct sockaddr *) to_address, sizeof(struct sockaddr_in)))
#endif
        return SCM_BOOL_T;
    else 
        return SCM_BOOL_F;
}

#if (defined TT_HAVE_SOCKADDR_STORAGE) && (defined TT_HAVE_AF_INET6) && (defined TT_HAVE_SOCKADDR_IN6)
static SCM 
sctp_send_v6 (struct sockaddr_in6 *to_address, unsigned short length)
{
    if ((sctpv6_fd > 0) && 
        (length == sendto(sctpv6_fd, packet, length, 0, (const struct sockaddr *) to_address, sizeof(struct sockaddr_in6))))
        return SCM_BOOL_T;
    else
        return SCM_BOOL_F;
}
#endif

static SCM 
sctp_send_with_crc32c (SCM s_common_header, SCM s_chunks, SCM s_to_address, SCM s_from_address)
{
#ifdef TT_HAVE_SOCKADDR_STORAGE
    struct sockaddr_storage *to_address, *from_address;
#else
    struct sockaddr_in *to_address, *from_address;
#endif
    unsigned short length;
    unsigned char *sctp_packet;
    unsigned long crc32c;
  
    SCM_ASSERT (SCM_SMOB_PREDICATE (common_header_tag, s_common_header), s_common_header, SCM_ARG1, "sctp-send-with-crc32c");
    SCM_ASSERT (SCM_VECTORP (s_chunks),                                  s_chunks,        SCM_ARG2, "sctp-send-with-crc32c");
    SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_to_address),          s_to_address,    SCM_ARG3, "sctp-send-with-crc32c");
    if (!(SCM_UNBNDP(s_from_address)))
        SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_from_address),    s_from_address,  SCM_ARG4, "sctp-send-with-crc32c");

#ifdef TT_HAVE_SOCKADDR_STORAGE
    to_address   = (struct sockaddr_storage *) SCM_SMOB_DATA (s_to_address);
#else
    to_address   = (struct sockaddr_in *) SCM_SMOB_DATA (s_to_address);
#endif
    from_address = NULL;
#ifdef TT_HAVE_SOCKADDR_STORAGE
    switch(to_address->ss_family) {
#else
    switch(to_address->sin_family) {
#endif
        case AF_INET:
            if SCM_UNBNDP(s_from_address)
                from_address = &address_any_v4;
            else
#ifdef TT_HAVE_SOCKADDR_STORAGE
                from_address = (struct sockaddr_storage *) SCM_SMOB_DATA (s_from_address);
            if (from_address->ss_family != AF_INET)
#else
                from_address = (struct sockaddr_in *) SCM_SMOB_DATA (s_from_address);
            if (from_address->sin_family != AF_INET)
#endif
                return (SCM_BOOL_F);
            break;
#ifdef TT_HAVE_AF_INET6
        case AF_INET6:
            if (!(SCM_UNBNDP(s_from_address)))
                return (SCM_BOOL_F);
            break;
#endif
    }
  
    memset(packet, 0, sizeof(packet));
#ifdef TT_HAVE_IP_HDRINCL
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
#ifdef LINUX
        sctp_packet = packet + sizeof(struct iphdr);
#else
        sctp_packet = packet + sizeof(struct ip);
#endif
    else
        sctp_packet = packet;
#else
    sctp_packet = packet;
#endif

    length = scan_tlv_list(s_chunks, chunk_tag, (unsigned short) MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH);
    if (length > (unsigned short) (MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH))
        return(SCM_BOOL_F);
        
    memcpy(sctp_packet, (struct common_header *) SCM_SMOB_DATA (s_common_header), COMMON_HEADER_LENGTH);

    put_tlv_list(sctp_packet + COMMON_HEADER_LENGTH, s_chunks);
   
    crc32c = initialize_crc32c();
    crc32c = update_crc32c(crc32c, sctp_packet, length + COMMON_HEADER_LENGTH);
    crc32c = finalize_crc32c(crc32c);
    ((struct common_header *)(sctp_packet))->checksum = htonl(crc32c);
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
        return sctp_send_v4((struct sockaddr_in *)to_address, (struct sockaddr_in *)from_address, length + COMMON_HEADER_LENGTH);
#if ((defined TT_HAVE_SOCKADDR_STORAGE) && (defined TT_HAVE_AF_INET6) && (defined TT_HAVE_SOCKADDR_IN6))
    else if(to_address->ss_family == AF_INET6)
        return sctp_send_v6((struct sockaddr_in6 *)to_address, length + COMMON_HEADER_LENGTH);
#endif
    else 
        return SCM_BOOL_F;
}

static SCM 
sctp_send_with_adler32 (SCM s_common_header, SCM s_chunks, SCM s_to_address, SCM s_from_address)
{
#ifdef TT_HAVE_SOCKADDR_STORAGE
    struct sockaddr_storage *to_address, *from_address;
#else
    struct sockaddr_in *to_address, *from_address;
#endif
    unsigned short length;
    unsigned char *sctp_packet;
    unsigned long adler;
  
    SCM_ASSERT (SCM_SMOB_PREDICATE (common_header_tag, s_common_header), s_common_header, SCM_ARG1, "sctp-send-with-adler32");
    SCM_ASSERT (SCM_VECTORP (s_chunks),                                  s_chunks,        SCM_ARG2, "sctp-send-with-adler32");
    SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_to_address),          s_to_address,    SCM_ARG3, "sctp-send-with-adler32");
    if (!(SCM_UNBNDP(s_from_address)))
        SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_from_address),    s_from_address,  SCM_ARG4, "sctp-send-with-adler32");

#ifdef TT_HAVE_SOCKADDR_STORAGE
    to_address   = (struct sockaddr_storage *) SCM_SMOB_DATA (s_to_address);
#else
    to_address   = (struct sockaddr_in *) SCM_SMOB_DATA (s_to_address);
#endif
    from_address = NULL;
#ifdef TT_HAVE_SOCKADDR_STORAGE
    switch(to_address->ss_family) {
#else
    switch(to_address->sin_family) {
#endif
        case AF_INET:
            if SCM_UNBNDP(s_from_address)
                from_address = &address_any_v4;
            else
#ifdef TT_HAVE_SOCKADDR_STORAGE
                from_address = (struct sockaddr_storage *) SCM_SMOB_DATA (s_from_address);
            if (from_address->ss_family != AF_INET)
#else
                from_address = (struct sockaddr_in *) SCM_SMOB_DATA (s_from_address);
            if (from_address->sin_family != AF_INET)
#endif
                return (SCM_BOOL_F);
            break;
#ifdef TT_HAVE_AF_INET6
        case AF_INET6:
            if (!(SCM_UNBNDP(s_from_address)))
                return (SCM_BOOL_F);
            break;
#endif
    }
  
    memset(packet, 0, sizeof(packet));
#ifdef TT_HAVE_IP_HDRINCL
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
#ifdef LINUX
        sctp_packet = packet + sizeof(struct iphdr);
#else
        sctp_packet = packet + sizeof(struct ip);
#endif
    else
        sctp_packet = packet;
#else
    sctp_packet = packet;
#endif

    length = scan_tlv_list(s_chunks, chunk_tag, (unsigned short) MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH);
    if (length > (unsigned short) (MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH))
        return(SCM_BOOL_F);
        
    memcpy(sctp_packet, (struct common_header *) SCM_SMOB_DATA (s_common_header), COMMON_HEADER_LENGTH);

    put_tlv_list(sctp_packet + COMMON_HEADER_LENGTH, s_chunks);
   
    adler = initialize_adler32();
    adler = update_adler32(adler, sctp_packet, length + COMMON_HEADER_LENGTH);
    adler = finalize_adler32(adler);
    ((struct common_header *)(sctp_packet))->checksum = htonl(adler);
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
        return sctp_send_v4((struct sockaddr_in *)to_address, (struct sockaddr_in *)from_address, length + COMMON_HEADER_LENGTH);
#if ((defined TT_HAVE_SOCKADDR_STORAGE) && (defined TT_HAVE_AF_INET6) && (defined TT_HAVE_SOCKADDR_IN6))
    else if(to_address->ss_family == AF_INET6)
        return sctp_send_v6((struct sockaddr_in6 *)to_address, length + COMMON_HEADER_LENGTH);
#endif
    else 
        return SCM_BOOL_F;
}

static SCM 
sctp_send_raw_with_crc32c (SCM s_common_header, SCM s_bytes, SCM s_to_address, SCM s_from_address)
{
#ifdef TT_HAVE_SOCKADDR_STORAGE
    struct sockaddr_storage *to_address, *from_address;
#else
    struct sockaddr_in *to_address, *from_address;
#endif
    unsigned short length, i, e;
    unsigned char *sctp_packet, *sctp_payload;
    unsigned long crc32c;
    SCM s_e;

    SCM_ASSERT (SCM_SMOB_PREDICATE (common_header_tag, s_common_header), s_common_header, SCM_ARG1, "sctp-send-raw-with-crc32c");
    SCM_ASSERT (SCM_VECTORP (s_bytes),                                   s_bytes,         SCM_ARG2, "sctp-send-raw-with-crc32c");
    SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_to_address),          s_to_address,    SCM_ARG3, "sctp-send-raw-with-crc32c");
    if (!(SCM_UNBNDP(s_from_address)))
        SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_from_address),    s_from_address,  SCM_ARG4, "sctp-send-raw-with-crc32c");

#ifdef TT_HAVE_SOCKADDR_STORAGE
    to_address   = (struct sockaddr_storage *) SCM_SMOB_DATA (s_to_address);
#else
    to_address   = (struct sockaddr_in *) SCM_SMOB_DATA (s_to_address);
#endif
    from_address = NULL;
#ifdef TT_HAVE_SOCKADDR_STORAGE
    switch(to_address->ss_family) {
#else
    switch(to_address->sin_family) {
#endif
        case AF_INET:
            if SCM_UNBNDP(s_from_address)
                from_address = &address_any_v4;
            else
#ifdef TT_HAVE_SOCKADDR_STORAGE
                from_address = (struct sockaddr_storage *) SCM_SMOB_DATA (s_from_address);
            if (from_address->ss_family != AF_INET)
#else
                from_address = (struct sockaddr_in *) SCM_SMOB_DATA (s_from_address);
            if (from_address->sin_family != AF_INET)
#endif
                return (SCM_BOOL_F);
            break;
#ifdef TT_HAVE_AF_INET6
        case AF_INET6:
            if (!(SCM_UNBNDP(s_from_address)))
                return (SCM_BOOL_F);
            break;
#endif
    }
  
    memset(packet, 0, sizeof(packet));
#ifdef TT_HAVE_IP_HDRINCL
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
#ifdef LINUX
        sctp_packet = packet + sizeof(struct iphdr);
#else
        sctp_packet = packet + sizeof(struct ip);
#endif
    else
        sctp_packet = packet;
#else
    sctp_packet = packet;
#endif

    length = SCM_VECTOR_LENGTH (s_bytes);
    if (length > (unsigned short) (MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH))
        return(SCM_BOOL_F);

    memcpy(sctp_packet, (struct common_header *) SCM_SMOB_DATA (s_common_header), COMMON_HEADER_LENGTH);
    sctp_payload = sctp_packet + COMMON_HEADER_LENGTH;
    
    for(i = 0; i < length; i++) {
        s_e = SCM_VELTS(s_bytes)[i];
        e   =  scm_num2ushort(s_e, SCM_ARGn, "sctp-send-raw-with-crc32c");
        if (e > 255) 
            scm_out_of_range("sctp-send-raw-with-crc32c", s_e);
        sctp_payload[i] = (unsigned char) e;
    }

    crc32c = initialize_crc32c();
    crc32c = update_crc32c(crc32c, sctp_packet, length + COMMON_HEADER_LENGTH);
    crc32c = finalize_crc32c(crc32c);
    ((struct common_header *)(sctp_packet))->checksum = htonl(crc32c);
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
        return sctp_send_v4((struct sockaddr_in *)to_address, (struct sockaddr_in *)from_address, length + COMMON_HEADER_LENGTH);
#if ((defined TT_HAVE_SOCKADDR_STORAGE) && (defined TT_HAVE_AF_INET6) && (defined TT_HAVE_SOCKADDR_IN6))
    else if(to_address->ss_family == AF_INET6)
        return sctp_send_v6((struct sockaddr_in6 *)to_address, length + COMMON_HEADER_LENGTH);
#endif
    else 
        return SCM_BOOL_F;
}

static SCM 
sctp_send_raw_with_adler32 (SCM s_common_header, SCM s_bytes, SCM s_to_address, SCM s_from_address)
{
#ifdef TT_HAVE_SOCKADDR_STORAGE
    struct sockaddr_storage *to_address, *from_address;
#else
    struct sockaddr_in *to_address, *from_address;
#endif
    unsigned short length, i, e;
    unsigned char *sctp_packet, *sctp_payload;
    unsigned long adler;
    SCM s_e;

    SCM_ASSERT (SCM_SMOB_PREDICATE (common_header_tag, s_common_header), s_common_header, SCM_ARG1, "sctp-send-raw-with-adler32");
    SCM_ASSERT (SCM_VECTORP (s_bytes),                                   s_bytes,         SCM_ARG2, "sctp-send-raw-with-adler32");
    SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_to_address),          s_to_address,    SCM_ARG3, "sctp-send-raw-with-adler32");
    if (!(SCM_UNBNDP(s_from_address)))
        SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_from_address),    s_from_address,  SCM_ARG4, "sctp-send-raw-with-adler32");

#ifdef TT_HAVE_SOCKADDR_STORAGE
    to_address   = (struct sockaddr_storage *) SCM_SMOB_DATA (s_to_address);
#else
    to_address   = (struct sockaddr_in *) SCM_SMOB_DATA (s_to_address);
#endif
    from_address = NULL;
#ifdef TT_HAVE_SOCKADDR_STORAGE
    switch(to_address->ss_family) {
#else
    switch(to_address->sin_family) {
#endif
        case AF_INET:
            if SCM_UNBNDP(s_from_address)
                from_address = &address_any_v4;
            else
#ifdef TT_HAVE_SOCKADDR_STORAGE
                from_address = (struct sockaddr_storage *) SCM_SMOB_DATA (s_from_address);
            if (from_address->ss_family != AF_INET)
#else
                from_address = (struct sockaddr_in *) SCM_SMOB_DATA (s_from_address);
            if (from_address->sin_family != AF_INET)
#endif
                return (SCM_BOOL_F);
            break;
#ifdef TT_HAVE_AF_INET6
        case AF_INET6:
            if (!(SCM_UNBNDP(s_from_address)))
                return (SCM_BOOL_F);
            break;
#endif
    }
  
    memset(packet, 0, sizeof(packet));
#ifdef TT_HAVE_IP_HDRINCL
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
#ifdef LINUX
        sctp_packet = packet + sizeof(struct iphdr);
#else
        sctp_packet = packet + sizeof(struct ip);
#endif
    else
        sctp_packet = packet;
#else
    sctp_packet = packet;
#endif

    length = SCM_VECTOR_LENGTH (s_bytes);
    if (length > (unsigned short) (MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH))
        return(SCM_BOOL_F);

    memcpy(sctp_packet, (struct common_header *) SCM_SMOB_DATA (s_common_header), COMMON_HEADER_LENGTH);
    sctp_payload = sctp_packet + COMMON_HEADER_LENGTH;
    
    for(i = 0; i < length; i++) {
        s_e = SCM_VELTS(s_bytes)[i];
        e   =  scm_num2ushort(s_e, SCM_ARGn, "sctp-send-raw-with-adler32");
        if (e > 255) 
            scm_out_of_range("sctp-send-raw-with-adler32", s_e);
        sctp_payload[i] = (unsigned char) e;
    }

    adler = initialize_adler32();
    adler = update_adler32(adler, sctp_packet, length + COMMON_HEADER_LENGTH);
    adler = finalize_adler32(adler);
    ((struct common_header *)(sctp_packet))->checksum = htonl(adler);
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
        return sctp_send_v4((struct sockaddr_in *)to_address, (struct sockaddr_in *)from_address, length + COMMON_HEADER_LENGTH);
#if ((defined TT_HAVE_SOCKADDR_STORAGE) && (defined TT_HAVE_AF_INET6) && (defined TT_HAVE_SOCKADDR_IN6))
    else if(to_address->ss_family == AF_INET6)
        return sctp_send_v6((struct sockaddr_in6 *)to_address, length + COMMON_HEADER_LENGTH);
#endif
    else 
        return SCM_BOOL_F;
}

static SCM 
sctp_send_without_crc (SCM s_common_header, SCM s_chunks, SCM s_to_address, SCM s_from_address)
{
#ifdef TT_HAVE_SOCKADDR_STORAGE
    struct sockaddr_storage *to_address, *from_address;
#else
    struct sockaddr_in *to_address, *from_address;
#endif
    unsigned short length;
    unsigned char *sctp_packet;
  
    SCM_ASSERT (SCM_SMOB_PREDICATE (common_header_tag, s_common_header), s_common_header, SCM_ARG1, "sctp-send-without-crc");
    SCM_ASSERT (SCM_VECTORP (s_chunks),                                  s_chunks,        SCM_ARG2, "sctp-send-without-crc");
    SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_to_address),          s_to_address,    SCM_ARG3, "sctp-send-without-crc");
    if (!(SCM_UNBNDP(s_from_address)))
        SCM_ASSERT (SCM_SMOB_PREDICATE (address_tag, s_from_address),    s_from_address,  SCM_ARG4, "sctp-send-without-crc");

#ifdef TT_HAVE_SOCKADDR_STORAGE
    to_address   = (struct sockaddr_storage *) SCM_SMOB_DATA (s_to_address);
#else
    to_address   = (struct sockaddr_in *) SCM_SMOB_DATA (s_to_address);
#endif
    from_address = NULL;
#ifdef TT_HAVE_SOCKADDR_STORAGE
    switch(to_address->ss_family) {
#else
    switch(to_address->sin_family) {
#endif
        case AF_INET:
            if SCM_UNBNDP(s_from_address)
                from_address = &address_any_v4;
            else
#ifdef TT_HAVE_SOCKADDR_STORAGE
                from_address = (struct sockaddr_storage *) SCM_SMOB_DATA (s_from_address);
            if (from_address->ss_family != AF_INET)
#else
                from_address = (struct sockaddr_in *) SCM_SMOB_DATA (s_from_address);
            if (from_address->sin_family != AF_INET)
#endif
                return (SCM_BOOL_F);
            break;
#ifdef TT_HAVE_AF_INET6
        case AF_INET6:
            if (!(SCM_UNBNDP(s_from_address)))
                return (SCM_BOOL_F);
            break;
#endif
    }
  
    memset(packet, 0, sizeof(packet));
#ifdef TT_HAVE_IP_HDRINCL
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
#ifdef LINUX
        sctp_packet = packet + sizeof(struct iphdr);
#else
        sctp_packet = packet + sizeof(struct ip);
#endif
    else
        sctp_packet = packet;
#else
    sctp_packet = packet;
#endif

    length = scan_tlv_list(s_chunks, chunk_tag, (unsigned short) MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH);
    if (length > (unsigned short) (MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH))
        return(SCM_BOOL_F);
        
    memcpy(sctp_packet, (struct common_header *) SCM_SMOB_DATA (s_common_header), COMMON_HEADER_LENGTH);

    put_tlv_list(sctp_packet + COMMON_HEADER_LENGTH, s_chunks);
   
    ((struct common_header *)(sctp_packet))->checksum = htonl(0);
#ifdef TT_HAVE_SOCKADDR_STORAGE
    if(to_address->ss_family == AF_INET)
#else
    if(to_address->sin_family == AF_INET)
#endif
        return sctp_send_v4((struct sockaddr_in *)to_address, (struct sockaddr_in *)from_address, length + COMMON_HEADER_LENGTH);
#if ((defined TT_HAVE_SOCKADDR_STORAGE) && (defined TT_HAVE_AF_INET6) && (defined TT_HAVE_SOCKADDR_IN6))
    else if(to_address->ss_family == AF_INET6)
        return sctp_send_v6((struct sockaddr_in6 *)to_address, length + COMMON_HEADER_LENGTH);
#endif
    else 
        return SCM_BOOL_F;
}

static SCM 
sctp_receive_v4()
{
    SCM s_source, s_destination, s_header, s_chunks;
    unsigned short sctp_packet_length, ip_packet_length, ip_header_length;
    struct common_header *common_header;
#ifdef LINUX
    struct iphdr *ip_header;
#else
    struct ip *ip_header;
#endif
    struct sockaddr_in *addr;

    ip_packet_length   = recv(sctpv4_fd, packet, sizeof(packet), 0);

#ifdef LINUX
    ip_header          = (struct iphdr *) packet;
    ip_header_length   = (ip_header->ihl << 2);
#else
    ip_header          = (struct ip *) packet;
    ip_header_length   = ip_header->ip_hl << 2;
#endif
    sctp_packet_length = ip_packet_length - ip_header_length;

    addr = (struct sockaddr_in *) scm_must_malloc (ADDRESS_SIZE, "address");
    memset((void *) addr, 0, ADDRESS_SIZE);
#ifdef TT_HAVE_SIN_LEN
    addr->sin_len    = sizeof(struct sockaddr_in);
#endif
    addr->sin_family = AF_INET;
    addr->sin_port   = 0;
#ifdef LINUX
    memcpy((void *) &addr->sin_addr, (const void *) &ip_header->saddr, sizeof(struct in_addr));
#else
    memcpy((void *) &addr->sin_addr, (const void *) &ip_header->ip_src, sizeof(struct in_addr));
#endif
    SCM_NEWSMOB (s_source, address_tag, addr); 

    addr = (struct sockaddr_in *) scm_must_malloc (ADDRESS_SIZE, "address");
    memset((void *) addr, 0, ADDRESS_SIZE);
#ifdef TT_HAVE_SIN_LEN
    addr->sin_len    = sizeof(struct sockaddr_in);
#endif
    addr->sin_family = AF_INET;
    addr->sin_port   = 0;
#ifdef LINUX
    memcpy((void *) &addr->sin_addr, (const void *) &ip_header->daddr, sizeof(struct in_addr));
#else
    memcpy((void *) &addr->sin_addr, (const void *) &ip_header->ip_dst, sizeof(struct in_addr));
#endif
    SCM_NEWSMOB (s_destination, address_tag, addr); 

    if (sctp_packet_length >= COMMON_HEADER_LENGTH) {
      common_header = (struct common_header *) scm_must_malloc (COMMON_HEADER_LENGTH, "common_header");
      memset((void *) common_header, 0, COMMON_HEADER_LENGTH);
      memcpy((void *) common_header, (const void *) (packet + ip_header_length), COMMON_HEADER_LENGTH);
      SCM_NEWSMOB (s_header, common_header_tag, common_header);
      s_chunks = get_tlv_list(packet + ip_header_length + COMMON_HEADER_LENGTH, sctp_packet_length - COMMON_HEADER_LENGTH, "chunks", chunk_tag);
    } else {
      s_header = SCM_BOOL_F;
      s_chunks = SCM_BOOL_F;
    }
    return scm_list_4(s_header, s_chunks, s_destination, s_source);
}

#if ((defined TT_HAVE_AF_INET6))
static SCM 
sctp_receive_v6()
{
    return scm_list_4(SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F);
}
#endif

static SCM 
sctp_receive(SCM s_ms)
{
    unsigned long time_to_wait;
    struct timeval timeval;
    struct timeval *timevalptr;
    int maxfd;
    fd_set rset;
  
    if (SCM_UNBNDP(s_ms))
        timevalptr = NULL;
    else {
        time_to_wait    = scm_num2ulong(s_ms, SCM_ARG1, "sctp-receive");
        timeval.tv_sec  = time_to_wait / 1000;
        timeval.tv_usec = 1000 * (time_to_wait % 1000);
        timevalptr      = & timeval;
    }
  
#ifdef TT_HAVE_AF_INET6
    maxfd = MAX(sctpv4_fd, sctpv6_fd) + 1;
#else
    maxfd = sctpv4_fd + 1;
#endif
    FD_ZERO(&rset);
    FD_SET(sctpv4_fd, &rset);
#ifdef TT_HAVE_AF_INET6
    if (sctpv6_fd > 0)
        FD_SET(sctpv6_fd, &rset);
#endif
    if (select(maxfd, &rset, NULL, NULL, timevalptr) < 0) {
        if (errno != EINTR) {
            perror("select");
            exit(-1);
        } else
            return scm_list_4(SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F);
    }
    if (FD_ISSET(sctpv4_fd, &rset))
        return sctp_receive_v4();
#ifdef TT_HAVE_AF_INET6
    else if ((sctpv6_fd > 0) && (FD_ISSET(sctpv6_fd, &rset)))
        return sctp_receive_v6();
#endif
    else
        return scm_list_4(SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F);
}

static void
close_sockets()
{
    if (close(sctpv4_fd) < 0) {
        perror("close");
        exit(-1);
    }
#ifdef TT_HAVE_AF_INET6
    if (sctpv6_fd > 0) {
        if (close(sctpv6_fd) < 0) {
            perror("close");
            exit(-1);
        }
    }
#endif
}

static void
open_sockets()
{
#ifdef TT_HAVE_IP_HDRINCL
    const int on = 1;
#endif
    
    if ((sctpv4_fd = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP)) < 0) {
        perror("socket");
        exit(-1);
    }
#ifdef TT_HAVE_IP_HDRINCL
    if (setsockopt(sctpv4_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        exit(-1);
    }
#endif
#ifdef TT_HAVE_AF_INET6
    if ((sctpv6_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_SCTP)) < 0) {
#ifdef LINUX
        if (sctpv6_fd != -EPERM) { /* the man page says EINVAL, but... */
#endif
            perror("socket");
            exit(-1);
#ifdef LINUX
        }
#endif
    }
#endif
}

static SCM
sctp_reset ()
{
    close_sockets();
    open_sockets();
    return SCM_BOOL_T;
}

static void
register_send_receive(void)
{
    scm_c_define_gsubr ("sctp-send-with-crc32c",      3, 1, 0, sctp_send_with_crc32c);
    scm_c_define_gsubr ("sctp-send-with-adler32",     3, 1, 0, sctp_send_with_adler32);
    scm_c_define_gsubr ("sctp-send-without-crc",      3, 1, 0, sctp_send_without_crc);
    scm_c_define_gsubr ("sctp-send-raw-with-crc32c",  3, 1, 0, sctp_send_raw_with_crc32c);
    scm_c_define_gsubr ("sctp-send-raw-with-adler32", 3, 1, 0, sctp_send_raw_with_adler32);
    scm_c_define_gsubr ("sctp-receive",               0, 1, 0, sctp_receive);
    scm_c_define_gsubr ("sctp-reset",                 0, 0, 0, sctp_reset);
}


#define SYSTEMCONFIGFILENAME    "/usr/local/share/stt/init.scm"
#define USERCONFIGFILENAME      ".stt.scm"
#define DIRECTORYSEPARATOR      "/"

static void
read_system_config_file(void)
{
    scm_c_primitive_load(SYSTEMCONFIGFILENAME);
}

static void
read_user_config_file(void)
{
    char *homedir;
    char *filename;
    homedir = getenv("HOME");
    if (homedir == NULL) return;
    filename = (char *)malloc(strlen(homedir) + strlen(USERCONFIGFILENAME) + strlen(DIRECTORYSEPARATOR) + 1);
    if (filename == NULL) return;
        sprintf(filename, "%s%s%s", homedir, DIRECTORYSEPARATOR, USERCONFIGFILENAME);
    scm_c_primitive_load(filename);
    free(filename);
}

static void 
inner_main(void *closure, int argc, char **argv)
{
    register_send_receive();
    init_addresses();
    init_common_header_type();
    init_parameters();
    init_chunks();
    init_causes();
    read_system_config_file();
    read_user_config_file();
    scm_shell (argc, argv);    
}

int
main(int argc, char *argv[])
{	  
    memset((void *) &address_any_v4, 0, ADDRESS_SIZE);
#ifdef TT_HAVE_SIN_LEN
    ((struct sockaddr_in*)&address_any_v4)->sin_len         = sizeof(struct sockaddr_in);
#endif
    ((struct sockaddr_in*)&address_any_v4)->sin_family      = AF_INET;
    ((struct sockaddr_in*)&address_any_v4)->sin_port        = 0;
    ((struct sockaddr_in*)&address_any_v4)->sin_addr.s_addr = htonl(INADDR_ANY);
    
#if (defined TT_HAVE_AF_INET6) && (defined TT_HAVE_SOCKADDR_IN6) && (defined TT_HAVE_SOCKADDR_STORAGE)
    memset((void *) &address_any_v6, 0, ADDRESS_SIZE);
#ifdef TT_HAVE_SIN6_LEN
    ((struct sockaddr_in6*)&address_any_v6)->sin6_len       = sizeof(struct sockaddr_in6);
#endif
    ((struct sockaddr_in6*)&address_any_v6)->sin6_family    = AF_INET6;
    ((struct sockaddr_in6*)&address_any_v6)->sin6_port      = 0;
    ((struct sockaddr_in6*)&address_any_v6)->sin6_flowinfo  = 0;
    ((struct sockaddr_in6*)&address_any_v6)->sin6_addr      = in6addr_any;
#endif
    open_sockets();
    scm_boot_guile (argc, argv, inner_main, 0);
    return(0); 
}
