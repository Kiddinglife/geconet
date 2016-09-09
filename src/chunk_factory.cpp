#include "chunk_factory.h"
#include "geco-malloc.h"
#include <cassert>

error_chunk_t* build_error_chunk()
{
    error_chunk_t* errorChunk = (error_chunk_t*) geco_malloc_ext(
    INIT_CHUNK_TOTAL_SIZE, __FILE__,
    __LINE__);
    if (errorChunk == NULL) ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
    memset(errorChunk, 0, ERROR_CHUNK_TOTAL_SIZE);
    errorChunk->chunk_header.chunk_id = CHUNK_ERROR;
    errorChunk->chunk_header.chunk_flags = 0x00;
    errorChunk->chunk_header.chunk_length = CHUNK_FIXED_SIZE;
    return errorChunk;
}

uint put_ec_unrecognized_chunk(error_cause_t*ecause, uchar* errdata,
        uint errdatalen)
{
    assert(ecause != 0 && errdata != 0 && errdatalen > 0);

    ecause->error_reason_code = htons(VLPARAM_UNRECOGNIZED_PARAM);
    int len = errdatalen + ERR_CAUSE_FIXED_SIZE;
    ecause->error_reason_length = htons(len);
    if (errdatalen > 0 && errdata != NULL)
    {
        memcpy(ecause->error_reason, errdata, errdatalen);
    }
    while (len & 3)
        len++;
    return len;
}
uint put_error_cause(error_cause_t*ecause, ushort errcode, uchar* errdata,
        ushort errdatalen)
{
    ecause->error_reason_code = htons(errcode);
    int len = errdatalen + ERR_CAUSE_FIXED_SIZE;
    ecause->error_reason_length = htons(len);
    if (errdatalen > 0 && errdata != NULL) memcpy(ecause->error_reason, errdata,
            errdatalen);
    while (len & 3)
        len++;
    return len;
}
init_chunk_t* build_init_chunk(unsigned int initTag, unsigned int arwnd,
        unsigned short noOutStreams, unsigned short noInStreams,
        unsigned int initialTSN, uchar id)
{
    init_chunk_t* initChunk = (init_chunk_t*) geco_malloc_ext(
    INIT_CHUNK_TOTAL_SIZE, __FILE__,
    __LINE__);
    if (initChunk == NULL) ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
    memset(initChunk, 0, INIT_CHUNK_TOTAL_SIZE);
    initChunk->chunk_header.chunk_id = id;
    initChunk->chunk_header.chunk_flags = 0x00;
    initChunk->chunk_header.chunk_length = INIT_CHUNK_FIXED_SIZES;
    initChunk->init_fixed.init_tag = htonl(initTag);
    initChunk->init_fixed.rwnd = htonl(arwnd);
    initChunk->init_fixed.outbound_streams = htons(noOutStreams);
    initChunk->init_fixed.inbound_streams = htons(noInStreams);
    initChunk->init_fixed.initial_tsn = htonl(initialTSN);
    return initChunk;
}
int put_init_vlp(uchar *vlPtr, uint pCode, uint len, uchar* data)
{
    *((ushort*) vlPtr) = htons(pCode);
    vlPtr += sizeof(ushort);  // pass by param type
    *((ushort*) vlPtr) = htons(len + VLPARAM_FIXED_SIZE);
    vlPtr += sizeof(ushort);  // pass by param length field
    if (len > 0 && data != NULL) memcpy(vlPtr, data, len);
    len += VLPARAM_FIXED_SIZE;
    while (len & 3)
        len++;
    return len;
}
void put_init_chunk_fixed(init_chunk_t* initChunk, unsigned int initTag,
        unsigned int arwnd, unsigned short noOutStreams,
        unsigned short noInStreams, unsigned int initialTSN)
{
    if (initChunk == NULL) ERRLOG(FALTAL_ERROR_EXIT, "malloc failed!\n");
    memset(initChunk, 0, INIT_CHUNK_TOTAL_SIZE);
    initChunk->chunk_header.chunk_id = CHUNK_INIT;
    initChunk->chunk_header.chunk_flags = 0x00;
    initChunk->chunk_header.chunk_length = INIT_CHUNK_FIXED_SIZES;
    initChunk->init_fixed.init_tag = htonl(initTag);
    initChunk->init_fixed.rwnd = htonl(arwnd);
    initChunk->init_fixed.outbound_streams = htons(noOutStreams);
    initChunk->init_fixed.inbound_streams = htons(noInStreams);
    initChunk->init_fixed.initial_tsn = htonl(initialTSN);
}
uint put_vlp_supported_addr_types(uchar* vlp_start, bool with_ipv4,
        bool with_ipv6, bool with_dns)
{
    ushort num_of_types = 0, position = 0;
    if (with_ipv4) num_of_types++;
    if (with_ipv6) num_of_types++;
    if (with_dns) num_of_types++;
    if (num_of_types == 0)
    ERRLOG(FALTAL_ERROR_EXIT,
            "put_supported_addr_types()::No Supported Address Types -- Program Error\n");
    ushort total_length = VLPARAM_FIXED_SIZE + num_of_types * sizeof(ushort);
    supported_address_types_t* param = (supported_address_types_t*) vlp_start;
    param->vlparam_header.param_type = htons(VLPARAM_SUPPORTED_ADDR_TYPES);
    param->vlparam_header.param_length = htons(total_length);
    if (with_ipv4)
    {
        param->address_type[position] = htons(VLPARAM_IPV4_ADDRESS);
        position++;
    }
    if (with_ipv6)
    {
        param->address_type[position] = htons(VLPARAM_IPV6_ADDRESS);
        position++;
    }
    if (with_dns)
    {
        param->address_type[position] = htons(VLPARAM_HOST_NAME_ADDR);
        position++;
    }
    /* take care of padding */
    if (total_length & 3) total_length += 2;
    return total_length;
}

uint put_vlp_addrlist(uchar* vlp_start,
        sockaddrunion local_addreslist[MAX_NUM_ADDRESSES],
        uint local_addreslist_size)
{
    assert(
            vlp_start != 0 && local_addreslist != 0
                    && local_addreslist_size > 0);

    uint i, length = 0;
    ip_address_t* ip_addr;
    for (i = 0; i < local_addreslist_size; i++)
    {

        ip_addr = (ip_address_t*) (vlp_start + length);
        switch (saddr_family(&(local_addreslist[i])))
        {
            case AF_INET:
                ip_addr->vlparam_header.param_type = htons(VLPARAM_IPV4_ADDRESS);
                ip_addr->vlparam_header.param_length = htons(
                        sizeof(struct in_addr) + VLPARAM_FIXED_SIZE);
                ip_addr->dest_addr_un.ipv4_addr = s4addr(&(local_addreslist[i]));
                assert(sizeof(struct in_addr) + VLPARAM_FIXED_SIZE == 8);
                length += 8;
                break;
            case AF_INET6:
                ip_addr->vlparam_header.param_type = htons(
                VLPARAM_IPV6_ADDRESS);
                ip_addr->vlparam_header.param_length = htons(
                        sizeof(struct in6_addr) + VLPARAM_FIXED_SIZE);
                memcpy(&ip_addr->dest_addr_un.ipv6_addr,
                        &(s6addr(&(local_addreslist[i]))), sizeof(struct in6_addr));
                assert(sizeof(struct in6_addr) + VLPARAM_FIXED_SIZE ==20);
                length += 20;
                break;
            default:
                ERRLOG1(MAJOR_ERROR,
                        "dispatch_layer_t::write_addrlist()::Unsupported Address Family %d",
                        saddr_family(&(local_addreslist[i])));
                break;
        }
    }
    return length;  // no need to align because MUST be 4 bytes aliged
}

/*
 3.3.11.  Cookie Echo (COOKIE ECHO) (10)
 This chunk is used only during the initialization of an association.
 It is sent by the initiator of an association to its peer to complete
 the initialization process.  This chunk MUST precede any DATA chunk
 sent within the association, but MAY be bundled with one or more DATA
 chunks in the same packet.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |   Type = 10   |Chunk  Flags   |         Length                |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 /                     Cookie                                    /
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 Set to 0 on transmit and ignored on receipt.
 5.1.3.  Generating State Cookie
 When sending an INIT ACK as a response to an INIT chunk, the sender
 of INIT ACK creates a State Cookie and sends it in the State Cookie
 parameter of the INIT ACK.  Inside this State Cookie, the sender
 should include a MAC (see [RFC2104] for an example), a timestamp on
 when the State Cookie is created, and the lifespan of the State
 Cookie, along with all the information necessary for it to establish
 the association.

 The following steps SHOULD be taken to generate the State Cookie:
 1)  Create an association TCB using information from both the
 received INIT and the outgoing INIT ACK chunk,
 2)  In the TCB, set the creation time to the current time of day, and
 the lifespan to the protocol parameter 'Valid.Cookie.Life' (see
 Section 15),
 3)  From the TCB, identify and collect the minimal subset of
 information needed to re-create the TCB, and generate a MAC using
 this subset of information and a secret key (see [RFC2104] for an
 example of generating a MAC), and
 4)  Generate the State Cookie by combining this subset of information
 and the resultant MAC.
 */
/** computes a cookie signature.*/
int put_hmac(cookie_param_t* cookieString)
{
    if (cookieString == NULL) return -1;

    cookieString->ck.hmac[0] = 0;
    cookieString->ck.hmac[1] = 0;
    cookieString->ck.hmac[2] = 0;
    cookieString->ck.hmac[3] = 0;

    uint cookieLength = ntohs(
            cookieString->vlparam_header.param_length) - VLPARAM_FIXED_SIZE;
    if (cookieLength == 0) return -1;

    uchar* key = get_secre_key(KEY_READ);
    if (key == NULL) return -1;

    unsigned char digest[HMAC_LEN];
    MD5_CTX ctx;
    MD5Init(&ctx);
    MD5Update(&ctx, (uchar*) cookieString, cookieLength);
    //MD5Update(&ctx, (uchar*) key, SECRET_KEYSIZE);
    MD5Final(digest, &ctx);
    memcpy(cookieString->ck.hmac, digest, sizeof(cookieString->ck.hmac));
    EVENTLOG1(VERBOSE, "Computed MD5 signature : %s", hexdigest(digest, HMAC_LEN));
    return 0;
}

void put_vlp_cookie_fixed(cookie_param_t* cookie, init_chunk_fixed_t* peer_init,
        init_chunk_fixed_t* local_initack, uint cookieLifetime,
        uint local_tie_tag, uint peer_tie_tag, ushort last_dest_port,
        ushort last_src_port, sockaddrunion local_Addresses[],
        uint num_local_Addresses, sockaddrunion peer_Addresses[],
        uint num_peer_Addresses)
{
    cookie->vlparam_header.param_type = htons(VLPARAM_COOKIE);
    cookie->ck.local_initack = *local_initack;
    cookie->ck.peer_init = *peer_init;
    cookie->ck.local_tie_tag = htonl(local_tie_tag);
    cookie->ck.peer_tie_tag = htonl(peer_tie_tag);
    cookie->ck.src_port = htons(last_src_port);
    cookie->ck.dest_port = htons(last_dest_port);

    uint count;
    uint no_local_ipv4_addresses = 0;
    uint no_remote_ipv4_addresses = 0;
    uint no_local_ipv6_addresses = 0;
    uint no_remote_ipv6_addresses = 0;
    for (count = 0; count < num_local_Addresses; count++)
    {
        switch (saddr_family(&(local_Addresses[count])))
        {
            case AF_INET:
                no_local_ipv4_addresses++;
                break;
            case AF_INET6:
                no_local_ipv6_addresses++;
                break;
            default:
                ERRLOG(FALTAL_ERROR_EXIT, "write_cookie: Address Type Error !");
                break;
        }
    }
    for (count = 0; count < num_peer_Addresses; count++)
    {
        switch (saddr_family(&(peer_Addresses[count])))
        {
            case AF_INET:
                no_remote_ipv4_addresses++;
                break;
            case AF_INET6:
                no_remote_ipv6_addresses++;
                break;
            default:
                ERRLOG(FALTAL_ERROR_EXIT, "write_cookie: Address Type Error !");
                break;
        }
    }
    cookie->ck.no_local_ipv4_addresses = htons(no_local_ipv4_addresses);
    cookie->ck.no_remote_ipv4_addresses = htons(no_remote_ipv4_addresses);
    cookie->ck.no_local_ipv6_addresses = htons(no_local_ipv6_addresses);
    cookie->ck.no_remote_ipv6_addresses = htons(no_remote_ipv6_addresses);
    cookie->ck.cookieLifetime = htonl(cookieLifetime);
    cookie->ck.sendingTime = htonl((uint) get_safe_time_ms());
}

uint put_vlp_cookie_life_span(cookie_preservative_t* preserv, unsigned int lifespanIncrement)
{
    ushort len = VLPARAM_FIXED_SIZE + sizeof(unsigned int);
    preserv->vlparam_header.param_type = htons(VLPARAM_COOKIE_PRESEREASONV);
    preserv->vlparam_header.param_length = htons(len);
    preserv->cookieLifetimeInc = htonl(lifespanIncrement);
    return len;
}
