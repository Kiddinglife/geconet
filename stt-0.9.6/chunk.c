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
#include "tlv.h"

extern scm_bits_t parameter_tag;
extern scm_bits_t cause_tag;
scm_bits_t chunk_tag;

struct data_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned long tsn;
    unsigned short sid;
    unsigned short ssn;
    unsigned long ppi;
    unsigned char user_data[0];
};

struct init_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned long initiate_tag;
    unsigned long a_rwnd;
    unsigned short mos;
    unsigned short mis;
    unsigned long initial_tsn;
    unsigned char parameter[0];
};

struct init_ack_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned long initiate_tag;
    unsigned long a_rwnd;
    unsigned short mos;
    unsigned short mis;
    unsigned long initial_tsn;
    unsigned char parameter[0];
};

struct sack_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned long cum_tsn_ack;
    unsigned long a_rwnd;
    unsigned short nr_of_gaps;
    unsigned short nr_of_dups;
    unsigned char tsns[0];
};

struct shutdown_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned long cumulative_tsn_ack;
};

struct cookie_echo_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned char state_cookie[0];
};

struct ecn_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned long lowest_tsn;
};

struct error_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned char error_causes[0];
};

struct abort_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned char error_causes[0];
};

struct forward_tsn_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned long cum_tsn;
    unsigned char stream_info[0];
};

struct asconf_chunk
{
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned long serial;
    unsigned char parameters[0];
};

#define UNORDERED_BIT 0x04
#define BEGIN_BIT     0x02
#define END_BIT       0x01
#define T_BIT         0x01

#define DATA_CHUNK_HEADER_LENGTH        16
#define INIT_CHUNK_HEADER_LENGTH        20
#define INIT_ACK_CHUNK_HEADER_LENGTH    20
#define MIN_SACK_CHUNK_LENGTH           16
#define ABORT_CHUNK_HEADER_LENGTH       4
#define SHUTDOWN_ACK_CHUNK_LENGTH       4
#define COOKIE_ACK_CHUNK_LENGTH         4
#define SHUTDOWN_CHUNK_LENGTH           8
#define SHUTDOWN_COMPLETE_CHUNK_LENGTH  4
#define ERROR_CHUNK_HEADER_LENGTH       4
#define ECNE_CHUNK_LENGTH               8
#define CWR_CHUNK_LENGTH                8
#define FORWARD_TSN_CHUNK_LENGTH        8
#define ASCONF_CHUNK_HEADER_LENGTH      8

static SCM make_data_chunk(SCM s_tsn, SCM s_sid, SCM s_ssn, SCM s_ppi, SCM s_user_data, SCM s_unordered, SCM s_begin,
        SCM s_end)
{
    struct data_chunk *data_chunk;
    unsigned short sid, ssn;
    unsigned long tsn, ppi;
    unsigned long user_data_length;
    unsigned short total_length;
    SCM s_e;
    unsigned short i, e;

    if SCM_UNBNDP(s_unordered)
    s_unordered = SCM_BOOL_F;
    if SCM_UNBNDP(s_begin)
    s_begin = SCM_BOOL_T;
    if SCM_UNBNDP(s_end)
    s_end = SCM_BOOL_T;
    tsn = scm_num2ulong(s_tsn, SCM_ARG1, "make-data-chunk");
    sid = scm_num2ushort(s_sid, SCM_ARG2, "make-data-chunk");
    ssn = scm_num2ushort(s_ssn, SCM_ARG3, "make-data-chunk");
    ppi = scm_num2ulong(s_ppi, SCM_ARG4, "make-data-chunk");
    SCM_ASSERT(SCM_VECTORP(s_user_data), s_user_data, SCM_ARG5, "make-data-chunk");
    SCM_ASSERT(SCM_BOOLP(s_unordered), s_unordered, SCM_ARG6, "make-data-chunk");
    SCM_ASSERT(SCM_BOOLP(s_begin), s_begin, SCM_ARG7, "make-data-chunk");
    SCM_ASSERT(SCM_BOOLP(s_end), s_end, SCM_ARGn, "make-data-chunk");

    user_data_length = SCM_VECTOR_LENGTH(s_user_data);
    if (user_data_length > (MAX_CHUNK_LENGTH - DATA_CHUNK_HEADER_LENGTH)) scm_num_overflow("make-data-chunk");
    total_length = ADD_PADDING(DATA_CHUNK_HEADER_LENGTH + user_data_length);
    data_chunk = (struct data_chunk *) scm_must_malloc(total_length, "chunk");
    memset((void *) data_chunk, 0, total_length);

    data_chunk->type = DATA_CHUNK_TYPE;
    data_chunk->flags = 0;
    if (SCM_EQ_P(s_unordered, SCM_BOOL_T)) data_chunk->flags |= UNORDERED_BIT;
    if (SCM_EQ_P(s_begin, SCM_BOOL_T)) data_chunk->flags |= BEGIN_BIT;
    if (SCM_EQ_P(s_end, SCM_BOOL_T)) data_chunk->flags |= END_BIT;
    data_chunk->length = htons(DATA_CHUNK_HEADER_LENGTH + user_data_length);
    data_chunk->tsn = htonl(tsn);
    data_chunk->sid = htons(sid);
    data_chunk->ssn = htons(ssn);
    data_chunk->ppi = htonl(ppi);

    for (i = 0; i < user_data_length; i++)
    {
        s_e = SCM_VELTS(s_user_data)[i];
        e = scm_num2ushort(s_e, SCM_ARGn, "make-data-chunk");
        if (e > 255) scm_out_of_range("make-data-chunk", s_e);
        data_chunk->user_data[i] = (unsigned char) e;
    }

    SCM_RETURN_NEWSMOB(chunk_tag, data_chunk);
}

static SCM get_tsn(SCM chunk_smob)
{
    struct data_chunk *data_chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-tsn");
    data_chunk = (struct data_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (data_chunk->type != DATA_CHUNK_TYPE) scm_syserror_msg("get-tsn", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(data_chunk->length) < DATA_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-tsn", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ulong2num(ntohl(data_chunk->tsn));
}

static SCM get_sid(SCM chunk_smob)
{
    struct data_chunk *data_chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-sid");
    data_chunk = (struct data_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (data_chunk->type != DATA_CHUNK_TYPE) scm_syserror_msg("get-sid", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(data_chunk->length) < DATA_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-sid", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ushort2num(ntohl(data_chunk->sid));
}

static SCM get_ssn(SCM chunk_smob)
{
    struct data_chunk *data_chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-ssn");
    data_chunk = (struct data_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (data_chunk->type != DATA_CHUNK_TYPE) scm_syserror_msg("get-ssn", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(data_chunk->length) < DATA_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-ssn", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ushort2num(ntohl(data_chunk->ssn));
}

static SCM get_ppi(SCM chunk_smob)
{
    struct data_chunk *data_chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-ppi");
    data_chunk = (struct data_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (data_chunk->type != DATA_CHUNK_TYPE) scm_syserror_msg("get-ppi", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(data_chunk->length) < DATA_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-ppi", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ulong2num(ntohl(data_chunk->ppi));
}

static SCM get_user_data(SCM chunk_smob)
{
    struct data_chunk *data_chunk;
    SCM s_user_data;
    unsigned short i, length;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-user-data");
    data_chunk = (struct data_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (data_chunk->type != DATA_CHUNK_TYPE) scm_syserror_msg("get-user-data", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(data_chunk->length) < DATA_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-user-data",
            "incorrect chunk length", chunk_smob, 0);
    length = ntohs(data_chunk->length) - 16;
    s_user_data = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
    for (i = 0; i < length; i++)
        scm_vector_set_x(s_user_data, scm_ushort2num(i), scm_ushort2num(data_chunk->user_data[i]));
    
    return s_user_data;
}

static SCM get_u_bit(SCM chunk_smob)
{
    struct chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-u-bit");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if (chunk->type != DATA_CHUNK_TYPE) scm_syserror_msg("get-u-bit", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < DATA_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-u-bit", "incorrect chunk length",
            chunk_smob, 0);
    if ((chunk->flags) & UNORDERED_BIT) return SCM_BOOL_T;
    else
        return SCM_BOOL_F;
}

static SCM get_e_bit(SCM chunk_smob)
{
    struct chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-e-bit");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if (chunk->type != DATA_CHUNK_TYPE) scm_syserror_msg("get-e-bit", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < DATA_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-e-bit", "incorrect chunk length",
            chunk_smob, 0);
    if ((chunk->flags) & END_BIT) return SCM_BOOL_T;
    else
        return SCM_BOOL_F;
}

static SCM get_b_bit(SCM chunk_smob)
{
    struct chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-b-bit");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if (chunk->type != DATA_CHUNK_TYPE) scm_syserror_msg("get-b-bit", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < DATA_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-b-bit", "incorrect chunk length",
            chunk_smob, 0);
    if ((chunk->flags) & BEGIN_BIT) return SCM_BOOL_T;
    else
        return SCM_BOOL_F;
}

SCM make_init_chunk(SCM s_init_tag, SCM s_a_rwnd, SCM s_MOS, SCM s_MIS, SCM s_init_TSN, SCM s_parameters)
{
    struct init_chunk *init_chunk;
    unsigned short mos, mis;
    unsigned long initiate_tag, a_rwnd, initial_tsn;
    unsigned short number_of_parameters, parameter_number;
    unsigned short chunk_length, total_length, length, parameter_length, offset;
    SCM s_parameter;

    initiate_tag = scm_num2ulong(s_init_tag, SCM_ARG1, "make-init-chunk");
    a_rwnd = scm_num2ulong(s_a_rwnd, SCM_ARG2, "make-init-chunk");
    mos = scm_num2ushort(s_MOS, SCM_ARG3, "make-init-chunk");
    mis = scm_num2ushort(s_MIS, SCM_ARG4, "make-init-chunk");
    initial_tsn = scm_num2ulong(s_init_TSN, SCM_ARG5, "make-init-chunk");

    chunk_length = INIT_CHUNK_HEADER_LENGTH;
    SCM_ASSERT(SCM_VECTORP(s_parameters), s_parameters, SCM_ARG6, "make-init-chunk");

    parameter_length = 0;
    number_of_parameters = SCM_VECTOR_LENGTH(s_parameters);
    for (parameter_number = 0; parameter_number < number_of_parameters; parameter_number++)
    {
        if (parameter_number > 0) chunk_length += ADD_PADDING(parameter_length);
        s_parameter = SCM_VELTS(s_parameters)[parameter_number];
        SCM_ASSERT(SCM_SMOB_PREDICATE(parameter_tag, s_parameter), s_parameter, SCM_ARGn, "make-init-chunk");
        parameter_length = ntohs(((struct parameter *) SCM_SMOB_DATA(s_parameter))->length);
        if ((MAX_CHUNK_DATA_LENGTH - chunk_length) < parameter_length) scm_out_of_range("make-init-chunk", s_parameter);
    }
    chunk_length += parameter_length;
    total_length = ADD_PADDING(chunk_length);
    init_chunk = (struct init_chunk *) scm_must_malloc(total_length, "chunk");
    memset((void *) init_chunk, 0, total_length);

    init_chunk->type = INIT_CHUNK_TYPE;
    init_chunk->flags = 0;
    init_chunk->length = htons(chunk_length);
    init_chunk->initiate_tag = htonl(initiate_tag);
    init_chunk->a_rwnd = htonl(a_rwnd);
    init_chunk->mos = htons(mos);
    init_chunk->mis = htons(mis);
    init_chunk->initial_tsn = htonl(initial_tsn);

    offset = 0;
    for (parameter_number = 0; parameter_number < number_of_parameters; parameter_number++)
    {
        s_parameter = SCM_VELTS(s_parameters)[parameter_number];
        length = ADD_PADDING(ntohs(((struct parameter * ) SCM_SMOB_DATA(s_parameter))->length));
        memcpy((void *) (init_chunk->parameter + offset), (const void *) (SCM_SMOB_DATA(s_parameter)), length);
        offset += length;
    }

    SCM_RETURN_NEWSMOB(chunk_tag, init_chunk);
}

SCM make_init_ack_chunk(SCM s_init_tag, SCM s_a_rwnd, SCM s_MOS, SCM s_MIS, SCM s_init_TSN, SCM s_parameters)
{
    struct init_ack_chunk *init_ack_chunk;
    unsigned short mos, mis;
    unsigned long initiate_tag, a_rwnd, initial_tsn;
    unsigned short number_of_parameters, parameter_number;
    unsigned short chunk_length, total_length, length, parameter_length, offset;
    SCM s_parameter;

    initiate_tag = scm_num2ulong(s_init_tag, SCM_ARG1, "make-init-ack-chunk");
    a_rwnd = scm_num2ulong(s_a_rwnd, SCM_ARG2, "make-init-ack-chunk");
    mos = scm_num2ushort(s_MOS, SCM_ARG3, "make-init-ack-chunk");
    mis = scm_num2ushort(s_MIS, SCM_ARG4, "make-init-ack-chunk");
    initial_tsn = scm_num2ulong(s_init_TSN, SCM_ARG5, "make-init-ack-chunk");

    chunk_length = INIT_ACK_CHUNK_HEADER_LENGTH;
    SCM_ASSERT(SCM_VECTORP(s_parameters), s_parameters, SCM_ARG6, "make-init-ack-chunk");

    parameter_length = 0;
    number_of_parameters = SCM_VECTOR_LENGTH(s_parameters);
    for (parameter_number = 0; parameter_number < number_of_parameters; parameter_number++)
    {
        if (parameter_number > 0) chunk_length += ADD_PADDING(parameter_length);
        s_parameter = SCM_VELTS(s_parameters)[parameter_number];
        SCM_ASSERT(SCM_SMOB_PREDICATE(parameter_tag, s_parameter), s_parameter, SCM_ARGn, "make-init-ack-chunk");
        parameter_length = ntohs(((struct parameter *) SCM_SMOB_DATA(s_parameter))->length);
        if ((MAX_CHUNK_DATA_LENGTH - chunk_length) < parameter_length) scm_out_of_range("make-init-ack-chunk",
                s_parameter);
    }
    chunk_length += parameter_length;
    total_length = ADD_PADDING(chunk_length);
    init_ack_chunk = (struct init_ack_chunk *) scm_must_malloc(total_length, "chunk");
    memset((void *) init_ack_chunk, 0, total_length);

    init_ack_chunk->type = INIT_ACK_CHUNK_TYPE;
    init_ack_chunk->flags = 0;
    init_ack_chunk->length = htons(chunk_length);
    init_ack_chunk->initiate_tag = htonl(initiate_tag);
    init_ack_chunk->a_rwnd = htonl(a_rwnd);
    init_ack_chunk->mos = htons(mos);
    init_ack_chunk->mis = htons(mis);
    init_ack_chunk->initial_tsn = htonl(initial_tsn);

    offset = 0;
    for (parameter_number = 0; parameter_number < number_of_parameters; parameter_number++)
    {
        s_parameter = SCM_VELTS(s_parameters)[parameter_number];
        length = ADD_PADDING(ntohs(((struct parameter * ) SCM_SMOB_DATA(s_parameter))->length));
        memcpy((void *) (init_ack_chunk->parameter + offset), (const void *) (SCM_SMOB_DATA(s_parameter)), length);
        offset += length;
    }

    SCM_RETURN_NEWSMOB(chunk_tag, init_ack_chunk);
}

static SCM get_initiate_tag(SCM chunk_smob)
{
    struct init_chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-initiate-tag");
    chunk = (struct init_chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != INIT_CHUNK_TYPE) && (chunk->type != INIT_ACK_CHUNK_TYPE)) scm_syserror_msg("get-initiate-tag",
            "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < INIT_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-initiate-tag", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ulong2num(ntohl(chunk->initiate_tag));
}

static SCM get_a_rwnd(SCM chunk_smob)
{
    struct init_chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-a-rwnd");
    chunk = (struct init_chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != INIT_CHUNK_TYPE) && (chunk->type != INIT_ACK_CHUNK_TYPE) && (chunk->type != SACK_CHUNK_TYPE)) scm_syserror_msg(
            "get-a-rwnd", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < INIT_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-a-rwnd", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ulong2num(ntohl(chunk->a_rwnd));
}

static SCM get_mos(SCM chunk_smob)
{
    struct init_chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-mos");
    chunk = (struct init_chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != INIT_CHUNK_TYPE) && (chunk->type != INIT_ACK_CHUNK_TYPE)) scm_syserror_msg("get-mos",
            "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < INIT_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-mos", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ushort2num(ntohs(chunk->mos));
}

static SCM get_mis(SCM chunk_smob)
{
    struct init_chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-mis");
    chunk = (struct init_chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != INIT_CHUNK_TYPE) && (chunk->type != INIT_ACK_CHUNK_TYPE)) scm_syserror_msg("get-mis",
            "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < INIT_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-mis", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ushort2num(ntohs(chunk->mis));
}

static SCM get_initial_tsn(SCM chunk_smob)
{
    struct init_chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-initial-tsn");
    chunk = (struct init_chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != INIT_CHUNK_TYPE) && (chunk->type != INIT_ACK_CHUNK_TYPE)) scm_syserror_msg("get-initial-tsn",
            "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < INIT_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-initial-tsn", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ulong2num(ntohl(chunk->initial_tsn));
}

static SCM get_parameters(SCM chunk_smob)
{
    struct chunk *chunk;
    unsigned short parameters_length;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-parameters");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != INIT_CHUNK_TYPE) && (chunk->type != INIT_ACK_CHUNK_TYPE) && (chunk->type != ASCONF_CHUNK_TYPE)
            && (chunk->type != ASCONF_ACK_CHUNK_TYPE)) scm_syserror_msg("get-parameters", "incorrect chunk type",
            chunk_smob, 0);
    if ((chunk->type = INIT_CHUNK_TYPE) || (chunk->type = INIT_CHUNK_TYPE))
    {
        if (ntohs(chunk->length) < INIT_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-parameters",
                "incorrect chunk length", chunk_smob, 0);
        parameters_length = ntohs(chunk->length) - INIT_CHUNK_HEADER_LENGTH;
        return get_tlv_list(((struct init_chunk *) chunk)->parameter, parameters_length, "parameter", parameter_tag);
    }
    else
    {
        if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH + 4) scm_syserror_msg("get-parameters", "incorrect chunk length",
                chunk_smob, 0);
        parameters_length = ntohs(chunk->length) - CHUNK_HEADER_LENGTH - 4;
        return get_tlv_list(((struct asconf_chunk *) chunk)->parameters, parameters_length, "parameter", parameter_tag);
    }
}

static SCM make_sack_chunk(SCM s_cum_tsn_ack, SCM s_a_rwnd, SCM s_gaps, SCM s_dup_tsns, SCM s_nr_of_gaps,
        SCM s_nr_of_dups)
{
    struct sack_chunk *sack_chunk;
    unsigned long cum_tsn_ack, a_rwnd, length, dup;
    unsigned short nr_of_gaps, nr_of_dups, start, end, offset, i;
    SCM s_block, s_start, s_end, s_dup;

    cum_tsn_ack = scm_num2ulong(s_cum_tsn_ack, SCM_ARG1, "make-sack-chunk");
    a_rwnd = scm_num2ulong(s_a_rwnd, SCM_ARG2, "make-sack-chunk");
    SCM_ASSERT(SCM_VECTORP(s_gaps), s_gaps, SCM_ARG3, "make-sack-chunk");
    SCM_ASSERT(SCM_VECTORP(s_dup_tsns), s_dup_tsns, SCM_ARG4, "make-sack-chunk");
    if SCM_UNBNDP(s_nr_of_gaps)
    nr_of_gaps = SCM_VECTOR_LENGTH(s_gaps);
    else
    nr_of_gaps = scm_num2ushort(s_nr_of_gaps, SCM_ARG5, "make-sack-chunk");
    if SCM_UNBNDP(s_nr_of_dups)
    nr_of_dups = SCM_VECTOR_LENGTH(s_dup_tsns);
    else
    nr_of_dups = scm_num2ushort(s_nr_of_dups, SCM_ARG6, "make-sack-chunk");

    length = 16 + 4 * (SCM_VECTOR_LENGTH(s_gaps) + SCM_VECTOR_LENGTH(s_dup_tsns));
    sack_chunk = (struct sack_chunk *) scm_must_malloc(length, "chunk");
    memset((void *) sack_chunk, 0, length);

    sack_chunk->type = SACK_CHUNK_TYPE;
    sack_chunk->flags = 0;
    sack_chunk->length = htons(length);
    sack_chunk->cum_tsn_ack = htonl(cum_tsn_ack);
    sack_chunk->a_rwnd = htonl(a_rwnd);
    sack_chunk->nr_of_gaps = htons(nr_of_gaps);
    sack_chunk->nr_of_dups = htons(nr_of_dups);

    offset = 0;
    for (i = 0; i < SCM_VECTOR_LENGTH(s_gaps); i++)
    {
        s_block = SCM_VELTS(s_gaps)[i];
        SCM_ASSERT(SCM_VECTORP(s_block), s_block, SCM_ARGn, "make-sack-chunk");
        if (SCM_VECTOR_LENGTH(s_block) != 2) scm_out_of_range("make-sack-chunk", s_block);
        s_start = SCM_VELTS(s_block)[0];
        s_end = SCM_VELTS(s_block)[1];
        start = htons(scm_num2ushort(s_start, SCM_ARGn, "make-sack-chunk"));
        end = htons(scm_num2ushort(s_end, SCM_ARGn, "make-sack-chunk"));
        memcpy((void *) (sack_chunk->tsns + offset), (const void *) &start, 2);
        offset += 2;
        memcpy((void *) (sack_chunk->tsns + offset), (const void *) &end, 2);
        offset += 2;
    }

    for (i = 0; i < SCM_VECTOR_LENGTH(s_dup_tsns); i++)
    {
        s_dup = SCM_VELTS(s_dup_tsns)[i];
        dup = htonl(scm_num2ulong(s_dup, SCM_ARGn, "make-sack-chunk"));
        memcpy((void *) (sack_chunk->tsns + offset), (const void *) &dup, 4);
        offset += 4;
    }
    
    SCM_RETURN_NEWSMOB(chunk_tag, sack_chunk);
}

static SCM get_cumulative_tsn_ack(SCM chunk_smob)
{
    struct shutdown_chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-cumulative-tsn-ack");
    chunk = (struct shutdown_chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != SACK_CHUNK_TYPE) && (chunk->type != SHUTDOWN_CHUNK_TYPE)) scm_syserror_msg(
            "get-cumulative-tsn-ack", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < SHUTDOWN_CHUNK_LENGTH) scm_syserror_msg("get-cumulative-tsn-ack",
            "incorrect chunk length", chunk_smob, 0);
    return scm_ulong2num(ntohl(chunk->cumulative_tsn_ack));
}

static SCM get_nr_of_gaps(SCM chunk_smob)
{
    struct sack_chunk *sack_chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-nr-of-gaps");
    sack_chunk = (struct sack_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (sack_chunk->type != SACK_CHUNK_TYPE) scm_syserror_msg("get-number-of-gaps", "incorrect chunk type", chunk_smob,
            0);
    if (ntohs(sack_chunk->length) < MIN_SACK_CHUNK_LENGTH) scm_syserror_msg("get-number-of-gaps",
            "incorrect chunk length", chunk_smob, 0);
    return scm_ushort2num(ntohs(sack_chunk->nr_of_gaps));
}

static SCM get_nr_of_dups(SCM chunk_smob)
{
    struct sack_chunk *sack_chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-nr-of-dups");
    sack_chunk = (struct sack_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (sack_chunk->type != SACK_CHUNK_TYPE) scm_syserror_msg("get-number-of-dups", "incorrect chunk type", chunk_smob,
            0);
    if (ntohs(sack_chunk->length) < MIN_SACK_CHUNK_LENGTH) scm_syserror_msg("get-number-of-dups",
            "incorrect chunk length", chunk_smob, 0);
    return scm_ushort2num(ntohs(sack_chunk->nr_of_dups));
}

static SCM get_gaps(SCM chunk_smob)
{
    struct sack_chunk *sack_chunk;
    SCM s_gaps, s_block;
    unsigned short i, length, start, end;
    unsigned long offset;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-gaps");
    sack_chunk = (struct sack_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (sack_chunk->type != SACK_CHUNK_TYPE) scm_syserror_msg("get-gaps", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(sack_chunk->length)
            != MIN_SACK_CHUNK_LENGTH + 4 * (ntohs(sack_chunk->nr_of_gaps) + ntohs(sack_chunk->nr_of_dups))) scm_syserror_msg(
            "get-gaps", "incorrect chunk length", chunk_smob, 0);
    length = ntohs(sack_chunk->nr_of_gaps);
    offset = 0;

    s_gaps = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
    for (i = 0; i < length; i++)
    {
        s_block = scm_make_vector(scm_ushort2num(2), SCM_UNSPECIFIED);
        memcpy((void *) &start, (const void *) (sack_chunk->tsns + offset), 2);
        offset += 2;
        memcpy((void *) &end, (const void *) (sack_chunk->tsns + offset), 2);
        offset += 2;
        scm_vector_set_x(s_block, scm_ushort2num(0), scm_ushort2num(ntohs(start)));
        scm_vector_set_x(s_block, scm_ushort2num(1), scm_ushort2num(ntohs(end)));
        scm_vector_set_x(s_gaps, scm_ushort2num(i), s_block);
    }
    return s_gaps;
}

static SCM get_dups(SCM chunk_smob)
{
    struct sack_chunk *sack_chunk;
    SCM s_dups;
    unsigned short i, length;
    unsigned long tsn, offset;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-dups");
    sack_chunk = (struct sack_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (sack_chunk->type != SACK_CHUNK_TYPE) scm_syserror_msg("get-dups", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(sack_chunk->length)
            != MIN_SACK_CHUNK_LENGTH + 4 * (ntohs(sack_chunk->nr_of_gaps) + ntohs(sack_chunk->nr_of_dups))) scm_syserror_msg(
            "get-dups", "incorrect chunk length", chunk_smob, 0);
    length = ntohs(sack_chunk->nr_of_dups);
    offset = 4 * ntohs(sack_chunk->nr_of_gaps);

    s_dups = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
    for (i = 0; i < length; i++)
    {
        memcpy((void *) &tsn, (const void *) (sack_chunk->tsns + offset), 4);
        scm_vector_set_x(s_dups, scm_ushort2num(i), scm_ulong2num(ntohl(tsn)));
    }
    return s_dups;
}

static SCM make_heartbeat_chunk(SCM s_parameter)
{
    struct chunk *chunk;
    struct parameter *parameter;
    unsigned short parameter_length, chunk_length, total_length;

    SCM_ASSERT(SCM_SMOB_PREDICATE(parameter_tag, s_parameter), s_parameter, SCM_ARG1, "make-heartbeat-chunk");
    parameter = (struct parameter *) SCM_SMOB_DATA(s_parameter);
    parameter_length = ntohs(parameter->length);
    chunk_length = parameter_length + PARAMETER_HEADER_LENGTH;
    total_length = ADD_PADDING(chunk_length);

    chunk = (struct chunk *) scm_must_malloc(total_length, "chunk");
    memset((void *) chunk, 0, total_length);

    chunk->type = HEARTBEAT_CHUNK_TYPE;
    chunk->flags = 0;
    chunk->length = htons(chunk_length);
    memcpy((void *) chunk->data, (const void *) parameter, parameter_length);

    SCM_RETURN_NEWSMOB(chunk_tag, chunk);
}

static SCM make_heartbeat_ack_chunk(SCM s_parameter)
{
    struct chunk *chunk;
    struct parameter *parameter;
    unsigned short parameter_length, chunk_length, total_length;

    SCM_ASSERT(SCM_SMOB_PREDICATE(parameter_tag, s_parameter), s_parameter, SCM_ARG1, "make-heartbeat-ack-chunk");
    parameter = (struct parameter *) SCM_SMOB_DATA(s_parameter);
    parameter_length = ntohs(parameter->length);
    chunk_length = parameter_length + PARAMETER_HEADER_LENGTH;
    total_length = ADD_PADDING(chunk_length);

    chunk = (struct chunk *) scm_must_malloc(total_length, "chunk");
    memset((void *) chunk, 0, total_length);

    chunk->type = HEARTBEAT_ACK_CHUNK_TYPE;
    chunk->flags = 0;
    chunk->length = htons(chunk_length);
    memcpy((void *) chunk->data, (const void *) parameter, parameter_length);

    SCM_RETURN_NEWSMOB(chunk_tag, chunk);
}

static SCM get_heartbeat_parameter(SCM chunk_smob)
{
    struct chunk *chunk;
    struct parameter *parameter;
    unsigned short length, total_length;
    unsigned char type;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-heartbeat-parameter");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    type = chunk->type;
    if ((type != HEARTBEAT_CHUNK_TYPE) && (type != HEARTBEAT_ACK_CHUNK_TYPE)) scm_syserror_msg(
            "get-heartbeat-parameter", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH + PARAMETER_HEADER_LENGTH) scm_syserror_msg(
            "get-heartbeat-parameter", "incorrect chunk length", chunk_smob, 0);
    length = ntohs(chunk->length) - CHUNK_HEADER_LENGTH;
    total_length = ADD_PADDING(length);
    parameter = (struct parameter *) scm_must_malloc(total_length, "parameter");
    memset((void *) parameter, 0, total_length);
    memcpy((void *) parameter, (const void *) chunk->data, length);
    SCM_RETURN_NEWSMOB(parameter_tag, parameter);
}

static SCM make_abort_chunk(SCM s_t_flag, SCM s_causes)
{
    struct abort_chunk *chunk;
    unsigned short chunk_length, error_causes_length;

    SCM_ASSERT(SCM_BOOLP(s_t_flag), s_t_flag, SCM_ARG1, "make-abort-chunk");
    if (!SCM_UNBNDP(s_causes))
    {
        SCM_ASSERT(SCM_VECTORP(s_causes), s_causes, SCM_ARG2, "make-abort-chunk");
        error_causes_length = scan_tlv_list(s_causes, cause_tag, MAX_CAUSE_LENGTH);
        if (error_causes_length > MAX_CAUSE_LENGTH) scm_syserror_msg("make-abort-chunk", "error causes too long",
                s_causes, 0);
    }
    else
        error_causes_length = 0;

    chunk_length = ABORT_CHUNK_HEADER_LENGTH + error_causes_length;
    chunk = (struct abort_chunk *) scm_must_malloc(chunk_length, "chunk");
    memset((void *) chunk, 0, chunk_length);

    chunk->type = ABORT_CHUNK_TYPE;
    if (SCM_EQ_P(s_t_flag, SCM_BOOL_T)) chunk->flags = 1;
    else
        chunk->flags = 0;
    chunk->length = htons(ABORT_CHUNK_HEADER_LENGTH);
    if (!SCM_UNBNDP(s_causes)) put_tlv_list(chunk->error_causes, s_causes);
    
    SCM_RETURN_NEWSMOB(chunk_tag, chunk);
}

static SCM get_t_bit(SCM chunk_smob)
{
    struct chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-t-bit");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != ABORT_CHUNK_TYPE) && (chunk->type != SHUTDOWN_COMPLETE_CHUNK_TYPE)) scm_syserror_msg(
            "get-t-bit", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH) scm_syserror_msg("get-t-bit", "incorrect chunk length", chunk_smob,
            0);

    if ((chunk->flags) & T_BIT) return SCM_BOOL_T;
    else
        return SCM_BOOL_F;
}

static SCM make_shutdown_chunk(SCM s_cum_tsn)
{
    struct shutdown_chunk *shutdown_chunk;
    unsigned long cumulative_tsn_ack;

    cumulative_tsn_ack = scm_num2ulong(s_cum_tsn, SCM_ARG1, "make-shutdown-chunk");
    shutdown_chunk = (struct shutdown_chunk *) scm_must_malloc(SHUTDOWN_CHUNK_LENGTH, "chunk");
    memset((void *) shutdown_chunk, 0, SHUTDOWN_CHUNK_LENGTH);

    shutdown_chunk->type = SHUTDOWN_CHUNK_TYPE;
    shutdown_chunk->flags = 0;
    shutdown_chunk->length = htons(SHUTDOWN_CHUNK_LENGTH);
    shutdown_chunk->cumulative_tsn_ack = htonl(cumulative_tsn_ack);

    SCM_RETURN_NEWSMOB(chunk_tag, shutdown_chunk);
}

static SCM make_shutdown_ack_chunk()
{
    struct chunk *shutdown_ack_chunk;

    shutdown_ack_chunk = (struct chunk *) scm_must_malloc(SHUTDOWN_ACK_CHUNK_LENGTH, "chunk");
    memset((void *) shutdown_ack_chunk, 0, SHUTDOWN_ACK_CHUNK_LENGTH);

    shutdown_ack_chunk->type = SHUTDOWN_ACK_CHUNK_TYPE;
    shutdown_ack_chunk->flags = 0;
    shutdown_ack_chunk->length = htons(SHUTDOWN_ACK_CHUNK_LENGTH);
    
    SCM_RETURN_NEWSMOB(chunk_tag, shutdown_ack_chunk);
}

static SCM make_error_chunk(SCM s_causes)
{
    struct error_chunk *chunk;
    unsigned short chunk_length, error_causes_length;

    if (!SCM_UNBNDP(s_causes))
    {
        SCM_ASSERT(SCM_VECTORP(s_causes), s_causes, SCM_ARG1, "make-error-chunk");
        error_causes_length = scan_tlv_list(s_causes, cause_tag, MAX_CAUSE_LENGTH);
        if (error_causes_length > MAX_CAUSE_LENGTH) scm_syserror_msg("make-error-chunk", "error causes too long",
                s_causes, 0);
    }
    else
        error_causes_length = 0;
    
    chunk_length = ERROR_CHUNK_HEADER_LENGTH + error_causes_length;
    chunk = (struct error_chunk *) scm_must_malloc(chunk_length, "chunk");
    memset((void *) chunk, 0, chunk_length);
    chunk->type = ERROR_CHUNK_TYPE;
    chunk->flags = 0;
    chunk->length = htons(chunk_length);
    if (!SCM_UNBNDP(s_causes)) put_tlv_list(chunk->error_causes, s_causes);
    SCM_RETURN_NEWSMOB(chunk_tag, chunk);
}

static SCM get_causes(SCM chunk_smob)
{
    struct chunk *chunk;
    unsigned short remaining_length;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-causes");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != ABORT_CHUNK_TYPE) && (chunk->type != ERROR_CHUNK_TYPE)) scm_syserror_msg("get-causes",
            "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < ABORT_CHUNK_HEADER_LENGTH) scm_syserror_msg("get-causes", "incorrect chunk length",
            chunk_smob, 0);
    remaining_length = ntohs(chunk->length) - ABORT_CHUNK_HEADER_LENGTH;
    return get_tlv_list(chunk->data, remaining_length, "cause", cause_tag);
}

static SCM make_cookie_echo_chunk(SCM s_state_cookie)
{
    struct cookie_echo_chunk *cookie_echo_chunk;
    SCM s_e;
    unsigned short e;
    unsigned long cookie_length, total_length;
    unsigned short i;

    SCM_ASSERT(SCM_VECTORP(s_state_cookie), s_state_cookie, SCM_ARG1, "make-cookie-echo-chunk");
    cookie_length = SCM_VECTOR_LENGTH(s_state_cookie);
    if (cookie_length > ((2 << 16) - 4)) scm_num_overflow("cookie_echo_chunk");
    total_length = ADD_PADDING(4 + cookie_length);
    cookie_echo_chunk = (struct cookie_echo_chunk *) scm_must_malloc(total_length, "cookie_echo_chunk");
    memset((void *) cookie_echo_chunk, 0, total_length);

    cookie_echo_chunk->type = COOKIE_ECHO_CHUNK_TYPE;
    cookie_echo_chunk->flags = 0;
    cookie_echo_chunk->length = htons(cookie_length + 4);
    for (i = 0; i < SCM_VECTOR_LENGTH(s_state_cookie); i++)
    {
        s_e = SCM_VELTS(s_state_cookie)[i];
        e = scm_num2ushort(s_e, SCM_ARGn, "make-cookie-echo-chunk");
        if (e > 255) scm_out_of_range("make-cookie-echo-chunk", s_e);
        cookie_echo_chunk->state_cookie[i] = (unsigned char) e;
    }
    SCM_RETURN_NEWSMOB(chunk_tag, cookie_echo_chunk);
}

static SCM get_cookie_echo_chunk_cookie(SCM chunk_smob)
{
    struct chunk *chunk;
    SCM s_cookie;
    unsigned short i, length;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-cookie-echo-chunk-cookie");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if (chunk->type != COOKIE_ECHO_CHUNK_TYPE) scm_syserror_msg("get-cookie-echo-chunk-cookie", "incorrect chunk type",
            chunk_smob, 0);
    if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH) scm_syserror_msg("get-cookie-echo-chunk-cookie",
            "incorrect chunk length", chunk_smob, 0);
    length = ntohs(chunk->length) - CHUNK_HEADER_LENGTH;
    s_cookie = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
    for (i = 0; i < length; i++)
        scm_vector_set_x(s_cookie, scm_ushort2num(i), scm_ushort2num(chunk->data[i]));
    return s_cookie;
}

static SCM make_cookie_ack_chunk()
{
    struct chunk *cookie_ack_chunk;

    cookie_ack_chunk = (struct chunk *) scm_must_malloc(COOKIE_ACK_CHUNK_LENGTH, "chunk");
    memset((void *) cookie_ack_chunk, 0, COOKIE_ACK_CHUNK_LENGTH);

    cookie_ack_chunk->type = COOKIE_ACK_CHUNK_TYPE;
    cookie_ack_chunk->flags = 0;
    cookie_ack_chunk->length = htons(COOKIE_ACK_CHUNK_LENGTH);

    SCM_RETURN_NEWSMOB(chunk_tag, cookie_ack_chunk);
}

static SCM make_ecne_chunk(SCM s_lowest_tsn)
{
    struct ecn_chunk *chunk;
    unsigned long lowest_tsn;

    lowest_tsn = scm_num2ulong(s_lowest_tsn, SCM_ARG1, "make-ecne-chunk");

    chunk = (struct ecn_chunk *) scm_must_malloc(ECNE_CHUNK_LENGTH, "chunk");
    memset((void *) chunk, 0, ECNE_CHUNK_LENGTH);

    chunk->type = ECNE_CHUNK_TYPE;
    chunk->flags = 0;
    chunk->length = htons(ECNE_CHUNK_LENGTH);
    chunk->lowest_tsn = htonl(lowest_tsn);

    SCM_RETURN_NEWSMOB(chunk_tag, chunk);
}

static SCM make_cwr_chunk(SCM s_lowest_tsn)
{
    struct ecn_chunk *chunk;
    unsigned long lowest_tsn;

    lowest_tsn = scm_num2ulong(s_lowest_tsn, SCM_ARG1, "make-cwr-chunk");

    chunk = (struct ecn_chunk *) scm_must_malloc(CWR_CHUNK_LENGTH, "chunk");
    memset((void *) chunk, 0, ECNE_CHUNK_LENGTH);

    chunk->type = CWR_CHUNK_TYPE;
    chunk->flags = 0;
    chunk->length = htons(CWR_CHUNK_LENGTH);
    chunk->lowest_tsn = htonl(lowest_tsn);

    SCM_RETURN_NEWSMOB(chunk_tag, chunk);
}

static SCM get_lowest_tsn(SCM chunk_smob)
{
    struct ecn_chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-lowest-tsn");
    chunk = (struct ecn_chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != ECNE_CHUNK_TYPE) && (chunk->type != CWR_CHUNK_TYPE)) scm_syserror_msg("get-lowest-tsn",
            "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) != ECNE_CHUNK_LENGTH) scm_syserror_msg("get-lowest-tsn", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ulong2num(ntohl(chunk->lowest_tsn));
}

static SCM make_shutdown_complete_chunk(SCM s_t_flag)
{
    struct chunk *shutdown_complete_chunk;

    SCM_ASSERT(SCM_BOOLP(s_t_flag), s_t_flag, SCM_ARG1, "make-shutdown-complete-chunk");

    shutdown_complete_chunk = (struct chunk *) scm_must_malloc(SHUTDOWN_COMPLETE_CHUNK_LENGTH, "chunk");
    memset((void *) shutdown_complete_chunk, 0, SHUTDOWN_COMPLETE_CHUNK_LENGTH);

    shutdown_complete_chunk->type = SHUTDOWN_COMPLETE_CHUNK_TYPE;
    if (SCM_EQ_P(s_t_flag, SCM_BOOL_T)) shutdown_complete_chunk->flags = 1;
    else
        shutdown_complete_chunk->flags = 0;
    shutdown_complete_chunk->length = htons(SHUTDOWN_COMPLETE_CHUNK_LENGTH);
    
    SCM_RETURN_NEWSMOB(chunk_tag, shutdown_complete_chunk);
}

static SCM make_forward_tsn_chunk(SCM s_cum_tsn, SCM s_stream_info)
{
    struct forward_tsn_chunk *forward_tsn_chunk;
    unsigned long cum_tsn, length;
    unsigned short offset, i, ssn, sid;
    SCM s_ssn, s_sid, s_info;

    cum_tsn = scm_num2ulong(s_cum_tsn, SCM_ARG1, "make-forward-tsn-chunk");
    SCM_ASSERT(SCM_VECTORP(s_stream_info), s_stream_info, SCM_ARG2, "make-forward-tsn-chunk");

    length = 8 + 4 * SCM_VECTOR_LENGTH(s_stream_info);
    forward_tsn_chunk = (struct forward_tsn_chunk *) scm_must_malloc(length, "chunk");
    memset((void *) forward_tsn_chunk, 0, length);

    forward_tsn_chunk->type = FORWARD_TSN_CHUNK_TYPE;
    forward_tsn_chunk->flags = 0;
    forward_tsn_chunk->length = htons(length);
    forward_tsn_chunk->cum_tsn = htonl(cum_tsn);

    offset = 0;
    for (i = 0; i < SCM_VECTOR_LENGTH(s_stream_info); i++)
    {
        s_info = SCM_VELTS(s_stream_info)[i];
        SCM_ASSERT(SCM_VECTORP(s_info), s_info, SCM_ARGn, "make-forward-tsn-chunk");
        if (SCM_VECTOR_LENGTH(s_info) != 2) scm_out_of_range("make-forward-tsn-chunk", s_info);
        s_sid = SCM_VELTS(s_info)[0];
        s_ssn = SCM_VELTS(s_info)[1];
        sid = htons(scm_num2ushort(s_sid, SCM_ARGn, "make-forward-tsn-chunk"));
        ssn = htons(scm_num2ushort(s_ssn, SCM_ARGn, "make-forward-tsn-chunk"));
        memcpy((void *) (forward_tsn_chunk->stream_info + offset), (const void *) &sid, 2);
        offset += 2;
        memcpy((void *) (forward_tsn_chunk->stream_info + offset), (const void *) &ssn, 2);
        offset += 2;
    }
    
    SCM_RETURN_NEWSMOB(chunk_tag, forward_tsn_chunk);
}

static SCM get_new_cumulative_tsn(SCM chunk_smob)
{
    struct forward_tsn_chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-new-cumulative-tsn");
    chunk = (struct forward_tsn_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (chunk->type != FORWARD_TSN_CHUNK_TYPE) scm_syserror_msg("get-new-cumulative-tsn", "incorrect chunk type",
            chunk_smob, 0);
    if (ntohs(chunk->length) < FORWARD_TSN_CHUNK_LENGTH) scm_syserror_msg("get-new-cumulative-tsn",
            "incorrect chunk length", chunk_smob, 0);
    return scm_ulong2num(ntohl(chunk->cum_tsn));
}
static SCM get_new_stream_info(SCM chunk_smob)
{
    struct forward_tsn_chunk *forward_tsn_chunk;
    SCM s_stream_info, s_info;
    unsigned short i, length, sid, ssn;
    unsigned long offset;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-new-stream-info");
    forward_tsn_chunk = (struct forward_tsn_chunk *) SCM_SMOB_DATA(chunk_smob);
    if (forward_tsn_chunk->type != FORWARD_TSN_CHUNK_TYPE) scm_syserror_msg("get-new-stream-info",
            "incorrect chunk type", chunk_smob, 0);
    if (ntohs(forward_tsn_chunk->length) < FORWARD_TSN_CHUNK_LENGTH) scm_syserror_msg("get-new-stream-info",
            "incorrect chunk length", chunk_smob, 0);
    length = (ntohs(forward_tsn_chunk->length) - 8) / 4;
    offset = 0;

    s_stream_info = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
    for (i = 0; i < length; i++)
    {
        s_info = scm_make_vector(scm_ushort2num(2), SCM_UNSPECIFIED);
        memcpy((void *) &sid, (const void *) (forward_tsn_chunk->stream_info + offset), 2);
        offset += 2;
        memcpy((void *) &ssn, (const void *) (forward_tsn_chunk->stream_info + offset), 2);
        offset += 2;
        scm_vector_set_x(s_info, scm_ushort2num(0), scm_ushort2num(ntohs(sid)));
        scm_vector_set_x(s_info, scm_ushort2num(1), scm_ushort2num(ntohs(ssn)));
        scm_vector_set_x(s_stream_info, scm_ushort2num(i), s_info);
    }
    return s_stream_info;
}

static SCM make_asconf_chunk(SCM s_serial, SCM s_parameters)
{
    struct asconf_chunk *chunk;
    unsigned long serial;
    unsigned short chunk_length, total_chunk_length, parameters_length;

    serial = scm_num2ulong(s_serial, SCM_ARG1, "make-asconf-chunk");
    SCM_ASSERT(SCM_VECTORP(s_parameters), s_parameters, SCM_ARG1, "make-asconf-chunk");
    parameters_length = scan_tlv_list(s_parameters, parameter_tag, MAX_PARAMETER_LENGTH);
    if (parameters_length > MAX_PARAMETER_LENGTH) scm_syserror_msg("make-asconf-chunk", "parameters too long",
            s_parameters, 0);

    chunk_length = ASCONF_CHUNK_HEADER_LENGTH + parameters_length;
    total_chunk_length = ADD_PADDING(chunk_length);
    chunk = (struct asconf_chunk *) scm_must_malloc(total_chunk_length, "chunk");
    memset((void *) chunk, 0, total_chunk_length);
    chunk->type = ASCONF_CHUNK_TYPE;
    chunk->flags = 0;
    chunk->length = htons(chunk_length);
    chunk->serial = htonl(serial);
    put_tlv_list(chunk->parameters, s_parameters);
    SCM_RETURN_NEWSMOB(chunk_tag, chunk);
}

static SCM get_serial_number(SCM chunk_smob)
{
    struct asconf_chunk *chunk;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-serial-number");
    chunk = (struct asconf_chunk *) SCM_SMOB_DATA(chunk_smob);
    if ((chunk->type != ASCONF_CHUNK_TYPE) && (chunk->type != ASCONF_ACK_CHUNK_TYPE)) scm_syserror_msg(
            "get-serial-number", "incorrect chunk type", chunk_smob, 0);
    if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH + 4) scm_syserror_msg("get-serial-number", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ulong2num(ntohl(chunk->serial));
}

static SCM make_asconf_ack_chunk(SCM s_serial, SCM s_parameters)
{
    struct asconf_chunk *chunk;
    unsigned long serial;
    unsigned short chunk_length, total_chunk_length, parameters_length;

    serial = scm_num2ulong(s_serial, SCM_ARG1, "make-asconf-ack-chunk");
    SCM_ASSERT(SCM_VECTORP(s_parameters), s_parameters, SCM_ARG1, "make-asconf-ack-chunk");
    parameters_length = scan_tlv_list(s_parameters, parameter_tag, MAX_PARAMETER_LENGTH);
    if (parameters_length > MAX_PARAMETER_LENGTH) scm_syserror_msg("make-asconf-ack-chunk", "parameters too long",
            s_parameters, 0);

    chunk_length = ASCONF_CHUNK_HEADER_LENGTH + parameters_length;
    total_chunk_length = ADD_PADDING(chunk_length);
    chunk = (struct asconf_chunk *) scm_must_malloc(total_chunk_length, "chunk");
    memset((void *) chunk, 0, total_chunk_length);
    chunk->type = ASCONF_ACK_CHUNK_TYPE;
    chunk->flags = 0;
    chunk->length = htons(chunk_length);
    chunk->serial = htonl(serial);
    put_tlv_list(chunk->parameters, s_parameters);
    SCM_RETURN_NEWSMOB(chunk_tag, chunk);
}

static SCM make_chunk(SCM s_type, SCM s_flags, SCM s_data)
{
    unsigned short type;
    unsigned short flags;
    struct chunk *chunk;
    SCM s_e;
    unsigned short chunk_data_length, chunk_length, total_length, e, i;

    type = scm_num2ushort(s_type, SCM_ARG1, "make-chunk");
    if (type > 255) scm_out_of_range("make-chunk", s_type);

    flags = scm_num2ushort(s_flags, SCM_ARG2, "make-chunk");
    if (flags > 255) scm_out_of_range("make-chunk", s_flags);

    chunk_data_length = SCM_VECTOR_LENGTH(s_data);
    if (chunk_data_length > MAX_CHUNK_DATA_LENGTH) scm_out_of_range("make-chunk", s_data);
    chunk_length = CHUNK_HEADER_LENGTH + chunk_data_length;
    total_length = ADD_PADDING(chunk_length);
    chunk = (struct chunk *) scm_must_malloc(total_length, "chunk");
    memset((void *) chunk, 0, total_length);

    chunk->type = type;
    chunk->flags = flags;
    chunk->length = htons(chunk_length);
    for (i = 0; i < chunk_data_length; i++)
    {
        s_e = SCM_VELTS(s_data)[i];
        e = scm_num2ushort(s_e, SCM_ARGn, "make-chunk");
        if (e > 255) scm_out_of_range("make-chunk", s_e);
        chunk->data[i] = (unsigned char) e;
    }
    SCM_RETURN_NEWSMOB(chunk_tag, chunk);

}

static void print_generic_chunk(struct chunk *chunk, SCM port, scm_print_state *pstate)
{
    scm_puts("#<chunk: ", port);
    scm_puts("type=", port);
    scm_display(scm_ushort2num(chunk->type), port);
    scm_puts(", flags=", port);
    scm_display(scm_ushort2num(chunk->flags), port);
    scm_puts(", length=", port);
    scm_display(scm_ushort2num(ntohs(chunk->length)), port);
    scm_puts(">", port);
}

/*
 static int
 print_init_chunk (SCM init_chunk_smob, SCM port, scm_print_state *pstate)
 {
 struct init_chunk *init_chunk = (struct init_chunk *) SCM_SMOB_DATA (init_chunk_smob);

 scm_puts("#<init: ", port);
 scm_puts ("tag=", port);
 scm_display (scm_ulong2num(ntohl(init_chunk->initiate_tag)), port);
 scm_puts (", a_rwnd=", port);
 scm_display (scm_ulong2num(ntohl(init_chunk->a_rwnd)), port);
 scm_puts (", mos=", port);
 scm_display (scm_ushort2num(ntohs(init_chunk->mos)), port);
 scm_puts (", mis=", port);
 scm_display (scm_ushort2num(ntohs(init_chunk->mis)), port);
 scm_puts (", tsn=", port);
 scm_display (scm_ulong2num(ntohl(init_chunk->initial_tsn)), port);
 scm_puts (">", port);

 return 1;
 }
 static int
 print_init_ack_chunk (SCM init_ack_chunk_smob, SCM port, scm_print_state *pstate)
 {
 struct init_ack_chunk *init_ack_chunk = (struct init_ack_chunk *) SCM_SMOB_DATA (init_ack_chunk_smob);

 scm_puts("#<init-ack: ", port);
 scm_puts ("tag=", port);
 scm_display (scm_ulong2num(ntohl(init_ack_chunk->initiate_tag)), port);
 scm_puts (", a_rwnd=", port);
 scm_display (scm_ulong2num(ntohl(init_ack_chunk->a_rwnd)), port);
 scm_puts (", mos=", port);
 scm_display (scm_ushort2num(ntohs(init_ack_chunk->mos)), port);
 scm_puts (", mis=", port);
 scm_display (scm_ushort2num(ntohs(init_ack_chunk->mis)), port);
 scm_puts (", tsn=", port);
 scm_display (scm_ulong2num(ntohl(init_ack_chunk->initial_tsn)), port);
 scm_puts (">", port);

 return 1;
 }
 static int
 print_cookie_echo_chunk (SCM cookie_echo_chunk_smob, SCM port, scm_print_state *pstate)
 {
 struct cookie_echo_chunk *cookie_echo_chunk = (struct cookie_echo_chunk *) SCM_SMOB_DATA (cookie_echo_chunk_smob);

 scm_puts("#<cookie_echo: ", port);
 scm_display(scm_ushort2num(ntohs(cookie_echo_chunk->length) - 4), port);
 scm_puts (" bytes cookie>", port);
 return 1;
 }

 static int
 print_cookie_ack_chunk (SCM cookie_ack_chunk_smob, SCM port, scm_print_state *pstate)
 {
 scm_puts("#<cookie_ack> ", port);
 return 1;
 }
 static int
 print_data_chunk (SCM data_chunk_smob, SCM port, scm_print_state *pstate)
 {
 struct data_chunk *data_chunk = (struct data_chunk *) SCM_SMOB_DATA (data_chunk_smob);

 scm_puts("#<data: (", port);
 if (data_chunk->flags & UNORDERED_BIT)
 scm_puts ("U", port);
 if (data_chunk->flags & BEGIN_BIT)
 scm_puts ("B", port);
 if (data_chunk->flags & END_BIT)
 scm_puts ("E", port);
 scm_puts (") tsn=", port);
 scm_display (scm_ulong2num(ntohl(data_chunk->tsn)), port);
 scm_puts (", sid=", port);
 scm_display (scm_ushort2num(ntohs(data_chunk->sid)), port);
 scm_puts (", ssn=", port);
 scm_display (scm_ushort2num(ntohs(data_chunk->ssn)), port);
 scm_puts (", ppi=", port);
 scm_display (scm_ulong2num(ntohl(data_chunk->ppi)), port);
 scm_puts (", ", port);
 scm_display(scm_ushort2num(ntohs(data_chunk->length) - 16), port);
 scm_puts (" bytes user data>", port);

 return 1;
 }
 static int
 print_sack_chunk (SCM sack_chunk_smob, SCM port, scm_print_state *pstate)
 {
 struct sack_chunk *sack_chunk = (struct sack_chunk *) SCM_SMOB_DATA (sack_chunk_smob);

 scm_puts("#<sack:", port);
 scm_puts ("cum tsn ack=", port);
 scm_display (scm_ulong2num(ntohl(sack_chunk->cum_tsn_ack)), port);
 scm_puts (", a_rwnd=", port);
 scm_display (scm_ulong2num(ntohl(sack_chunk->a_rwnd)), port);
 scm_puts (", nr gaps=", port);
 scm_display (scm_ushort2num(ntohs(sack_chunk->nr_of_gaps)), port);
 scm_puts (", nr dups=", port);
 scm_display (scm_ushort2num(ntohs(sack_chunk->nr_of_dups)), port);
 scm_puts (">", port);

 return 1;
 }
 static int
 print_shutdown_chunk (SCM shutdown_chunk_smob, SCM port, scm_print_state *pstate)
 {
 struct shutdown_chunk *shutdown_chunk = (struct shutdown_chunk *) SCM_SMOB_DATA (shutdown_chunk_smob);

 scm_puts("#<shutdownt: ", port);
 scm_puts ("tsn=", port);
 scm_display (scm_ulong2num(ntohl(shutdown_chunk->cumulative_tsn_ack)), port);
 scm_puts (">", port);

 return 1;
 }

 static int
 print_shutdown_ack_chunk (SCM shutdown_ack_chunk_smob, SCM port, scm_print_state *pstate)
 {
 scm_puts("#<shutdown_ack> ", port);
 return 1;
 }

 static int
 print_shutdown_complete_chunk (SCM shutdown_complete_chunk_smob, SCM port, scm_print_state *pstate)
 {
 struct shutdown_complete_chunk *shutdown_complete_chunk = (struct shutdown_complete_chunk *) SCM_SMOB_DATA (shutdown_complete_chunk_smob);

 scm_puts("#<shutdown_complete: ", port);
 if ((shutdown_complete_chunk->flags) &0x01)
 scm_puts ("t-bit=1", port);
 else
 scm_puts ("t-bit=0", port);
 scm_puts (">", port);

 return 1;
 }

 static int
 print_abort_chunk (SCM abort_chunk_smob, SCM port, scm_print_state *pstate)
 {
 struct abort_chunk *abort_chunk = (struct abort_chunk *) SCM_SMOB_DATA (abort_chunk_smob);

 scm_puts("#<abort: ", port);
 if ((abort_chunk->flags) &0x01)
 scm_puts ("t-bit=1", port);
 else
 scm_puts ("t-bit=0", port);
 scm_puts (">", port);

 return 1;
 }

 static int
 print_heartbeat_parameter (SCM heartbeat_parameter_smob, SCM port, scm_print_state *pstate)
 {
 struct heartbeat_parameter *heartbeat_parameter = (struct heartbeat_parameter *) SCM_SMOB_DATA (heartbeat_parameter_smob);

 scm_puts("#<heartbeat: ", port);
 scm_display(scm_ushort2num(ntohs(heartbeat_parameter->length) - 4), port);
 scm_puts (" bytes heartbeat info>", port);
 return 1;
 }

 static int
 print_heartbeat_chunk (SCM heartbeat_chunk_smob, SCM port, scm_print_state *pstate)
 {

 scm_puts("#<heartbeat: ", port);
 scm_puts (">", port);

 return 1;
 }

 */

static int print_chunk(SCM chunk_smob, SCM port, scm_print_state *pstate)
{
    struct chunk *chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);

    if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH) scm_puts("<chunk: formatted bad>", port);
    else
        switch (chunk->type)
        {
            default:
                print_generic_chunk(chunk, port, pstate);
                break;
        }
    return 1;
}

static SCM chunk_p(SCM smob)
{
    if (SCM_SMOB_PREDICATE(chunk_tag, smob)) return SCM_BOOL_T;
    else
        return SCM_BOOL_F;
}

static SCM mark_chunk(SCM chunk_smob)
{
    return SCM_BOOL_F;
}

static size_t free_chunk(SCM chunk_smob)
{
    struct chunk *chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    unsigned short total_length;

    total_length = ADD_PADDING(ntohs(chunk->length));
    free(chunk);
    return (total_length);
}

static SCM equalp_chunk(SCM chunk_1_smob, SCM chunk_2_smob)
{
    unsigned short length;
    struct chunk *chunk_1 = (struct chunk *) SCM_SMOB_DATA(chunk_1_smob);
    struct chunk *chunk_2 = (struct chunk *) SCM_SMOB_DATA(chunk_2_smob);

    if (chunk_1->type != chunk_2->type) return SCM_BOOL_F;

    if (chunk_1->flags != chunk_2->flags) return SCM_BOOL_F;

    if (chunk_1->length != chunk_2->length) return SCM_BOOL_F;

    length = ntohs(chunk_1->length);

    if (length < CHUNK_HEADER_LENGTH) scm_syserror_msg("equalp_chunk", "incorrect chunk length", chunk_1_smob, 0);
    
    if (memcmp((const void *) chunk_1->data, (const void *) chunk_2->data, length - CHUNK_HEADER_LENGTH)) return SCM_BOOL_F;
    else
        return SCM_BOOL_T;
}

static SCM get_chunk_type(SCM chunk_smob)
{
    struct chunk *chunk;
    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-chunk-type");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH) scm_syserror_msg("get-chunk-type", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ushort2num(chunk->type);
}

static SCM get_chunk_flags(SCM chunk_smob)
{
    struct chunk *chunk;
    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-chunk-type");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH) scm_syserror_msg("get-chunk-flags", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ushort2num(chunk->flags);
}

static SCM get_chunk_length(SCM chunk_smob)
{
    struct chunk *chunk;
    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-chunk-length");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH) scm_syserror_msg("get-chunk-length", "incorrect chunk length",
            chunk_smob, 0);
    return scm_ushort2num(ntohs(chunk->length));
}

static SCM get_chunk_data(SCM chunk_smob)
{
    struct chunk *chunk;
    SCM s_value;
    unsigned short i, length;

    SCM_ASSERT(SCM_SMOB_PREDICATE(chunk_tag, chunk_smob), chunk_smob, SCM_ARG1, "get-chunk-data");
    chunk = (struct chunk *) SCM_SMOB_DATA(chunk_smob);
    if (ntohs(chunk->length) < CHUNK_HEADER_LENGTH) scm_syserror_msg("get-chunk-data", "incorrect chunk length",
            chunk_smob, 0);
    length = ntohs(chunk->length) - CHUNK_HEADER_LENGTH;
    s_value = scm_make_vector(scm_ushort2num(length), SCM_UNSPECIFIED);
    for (i = 0; i < length; i++)
        scm_vector_set_x(s_value, scm_ushort2num(i), scm_ushort2num(chunk->data[i]));
    
    return s_value;
}

void init_chunks(void)
{
    chunk_tag = scm_make_smob_type("chunk", 0);

    scm_set_smob_mark(chunk_tag, mark_chunk);
    scm_set_smob_free(chunk_tag, free_chunk);
    scm_set_smob_print(chunk_tag, print_chunk);
    scm_set_smob_equalp(chunk_tag, equalp_chunk);

    scm_c_define_gsubr("make-data-chunk", 5, 3, 0, make_data_chunk);
    scm_c_define_gsubr("get-tsn", 1, 0, 0, get_tsn);
    scm_c_define_gsubr("get-sid", 1, 0, 0, get_sid);
    scm_c_define_gsubr("get-ssn", 1, 0, 0, get_ssn);
    scm_c_define_gsubr("get-ppi", 1, 0, 0, get_ppi);
    scm_c_define_gsubr("get-user-data", 1, 0, 0, get_user_data);
    scm_c_define_gsubr("get-u-bit", 1, 0, 0, get_u_bit);
    scm_c_define_gsubr("get-e-bit", 1, 0, 0, get_e_bit);
    scm_c_define_gsubr("get-b-bit", 1, 0, 0, get_b_bit);
    scm_c_define_gsubr("make-init-chunk", 6, 0, 0, make_init_chunk);
    scm_c_define_gsubr("make-init-ack-chunk", 6, 0, 0, make_init_ack_chunk);
    scm_c_define_gsubr("get-initiate-tag", 1, 0, 0, get_initiate_tag);
    scm_c_define_gsubr("get-a-rwnd", 1, 0, 0, get_a_rwnd);
    scm_c_define_gsubr("get-mos", 1, 0, 0, get_mos);
    scm_c_define_gsubr("get-mis", 1, 0, 0, get_mis);
    scm_c_define_gsubr("get-initial-tsn", 1, 0, 0, get_initial_tsn);
    scm_c_define_gsubr("get-parameters", 1, 0, 0, get_parameters);
    scm_c_define_gsubr("make-sack-chunk", 4, 2, 0, make_sack_chunk);
    scm_c_define_gsubr("get-cumulative-tsn-ack", 1, 0, 0, get_cumulative_tsn_ack);
    scm_c_define_gsubr("get-number-of-gaps", 1, 0, 0, get_nr_of_gaps);
    scm_c_define_gsubr("get-number-of-dups", 1, 0, 0, get_nr_of_dups);
    scm_c_define_gsubr("get-gaps", 1, 0, 0, get_gaps);
    scm_c_define_gsubr("get-dups", 1, 0, 0, get_dups);
    scm_c_define_gsubr("make-heartbeat-chunk", 1, 0, 0, make_heartbeat_chunk);
    scm_c_define_gsubr("make-heartbeat-ack-chunk", 1, 0, 0, make_heartbeat_ack_chunk);
    scm_c_define_gsubr("get-heartbeat-parameter", 1, 0, 0, get_heartbeat_parameter);
    scm_c_define_gsubr("make-abort-chunk", 1, 1, 0, make_abort_chunk);
    scm_c_define_gsubr("get-t-bit", 1, 0, 0, get_t_bit);
    scm_c_define_gsubr("make-shutdown-chunk", 1, 0, 0, make_shutdown_chunk);
    scm_c_define_gsubr("make-shutdown-ack-chunk", 0, 0, 0, make_shutdown_ack_chunk);
    scm_c_define_gsubr("make-error-chunk", 0, 1, 0, make_error_chunk);
    scm_c_define_gsubr("get-causes", 1, 0, 0, get_causes);
    scm_c_define_gsubr("make-cookie-echo-chunk", 1, 0, 0, make_cookie_echo_chunk);
    scm_c_define_gsubr("get-cookie-echo-chunk-cookie", 1, 0, 0, get_cookie_echo_chunk_cookie);
    scm_c_define_gsubr("make-cookie-ack-chunk", 0, 0, 0, make_cookie_ack_chunk);
    scm_c_define_gsubr("make-ecne-chunk", 1, 0, 0, make_ecne_chunk);
    scm_c_define_gsubr("make-cwr-chunk", 1, 0, 0, make_cwr_chunk);
    scm_c_define_gsubr("get-lowest-tsn", 1, 0, 0, get_lowest_tsn);
    scm_c_define_gsubr("make-shutdown-complete-chunk", 1, 0, 0, make_shutdown_complete_chunk);
    scm_c_define_gsubr("make-forward-tsn-chunk", 2, 0, 0, make_forward_tsn_chunk);
    scm_c_define_gsubr("get-new-cummulative-tsn", 1, 0, 0, get_new_cumulative_tsn);
    scm_c_define_gsubr("get-new-stream-info", 1, 0, 0, get_new_stream_info);
    scm_c_define_gsubr("make-asconf-chunk", 2, 0, 0, make_asconf_chunk);
    scm_c_define_gsubr("make-asconf-ack-chunk", 2, 0, 0, make_asconf_ack_chunk);
    scm_c_define_gsubr("get-serial-number", 1, 0, 0, get_serial_number);
    scm_c_define_gsubr("make-chunk", 3, 0, 0, make_chunk);
    scm_c_define_gsubr("chunk?", 1, 0, 0, chunk_p);
    scm_c_define_gsubr("get-chunk-type", 1, 0, 0, get_chunk_type);
    scm_c_define_gsubr("get-chunk-flags", 1, 0, 0, get_chunk_flags);
    scm_c_define_gsubr("get-chunk-length", 1, 0, 0, get_chunk_length);
    scm_c_define_gsubr("get-chunk-data", 1, 0, 0, get_chunk_data);
}
