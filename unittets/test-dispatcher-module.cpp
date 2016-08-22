#include "gtest/gtest.h"
#include "gmock/gmock.h"
// @caution because geco-ds-malloc includes geco-thread.h that includes window.h but transport_layer.h includes wsock2.h, as we know, it must include before windows.h so if you uncomment this line, will cause error
//#include "geco-ds-malloc.h"
#include "transport_layer.h"
#include "dispatch_layer.h"
using namespace geco::ds;

static void init_inst(dispatch_layer_t& dlt, geco_instance_t& inst,
        ushort destport, const char** src_ips, uint src_ips_len,
        sockaddrunion* dest)
{
    for (uint i = 0; i < src_ips_len; i++)
    {
        str2saddr(&dest[i], src_ips[i], destport, true);
        //    saddr2str(&local_addres[i], buf, sizeof(local_addres[i]), &port);
        //    af = local_addres[i].sin.sin_family;
        //    EVENTLOG3(VERBOSE, "%s:%u:%u\n", buf, port, af);
    }
    inst.local_addres_size = src_ips_len;
    inst.local_addres_list = dest;
    inst.local_port = destport;
    dlt.geco_instances_.push_back(&inst);
}
// last run and passed on 21 Agu 2016
TEST(DISPATCHER_MODULE, test_find_geco_instance_by_transport_addr)
{
    /* 6) find dctp instancefor this packet
     *  if this packet is for a server dctp instance,
     *  we will find that dctp instance and let it handle this packet
     *  (i.e. we have the dctp instance's localPort set and
     *  it matches the packet's destination port)*/

    dispatch_layer_t dlt;
    geco_instance_t inst;
    const int destaddrsize = 6;
    const char* destipstrs[destaddrsize] =
            { "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4",
                    "192.168.1.5" };
    const ushort destport = 9989;
    sockaddrunion dest_addrs[destaddrsize];
    init_inst(dlt, inst, destport, destipstrs, destaddrsize, dest_addrs);

    sockaddrunion* last_dest_addr;
    ushort last_dest_port;
    geco_instance_t* ret = 0;

    // 1)  if is_in6addr_any and is_inaddr_any are both false
    inst.is_in6addr_any = inst.is_inaddr_any = false;
    // 1.1) if last_dest_port, last_dest_addr and addr family both matches
    last_dest_port = inst.local_port;
    for (uint i = 0; i < inst.local_addres_size; i++)
    {
        last_dest_addr = &inst.local_addres_list[i];
        ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr, last_dest_port);
        //  1.1.1) should found this inst
        EXPECT_EQ(ret, &inst);
    }
    // 1.2) if last_dest_port NOT mathces
    last_dest_port = inst.local_port - 1;
    for (uint i = 0; i < inst.local_addres_size; i++)
    {
        last_dest_addr = &inst.local_addres_list[i];
        ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr, last_dest_port);
        //  1.2.1) should NOT found this inst
        EXPECT_EQ(ret, nullptr);
    }
    // 1.3) if last_dest_addr NOT matches
    last_dest_port = inst.local_port;
    for (uint i = 0; i < inst.local_addres_size; i++)
    {
        sockaddrunion tmp = inst.local_addres_list[i];
        s4addr(&tmp) -= 1;  // just minus to make it different
        last_dest_addr = &tmp;
        ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr, last_dest_port);
        //  1.3.1) should NOT found this inst
        EXPECT_EQ(ret, nullptr);
    }
    // 1.4) if addr family NOT matches
    last_dest_port = inst.local_port;
    for (uint i = 0; i < inst.local_addres_size; i++)
    {
        sockaddrunion tmp = inst.local_addres_list[i];
        saddr_family(&tmp) == AF_INET ?
        saddr_family(&tmp) = AF_INET6 :
                                        saddr_family(&tmp) = AF_INET;
        last_dest_addr = &tmp;
        ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr, last_dest_port);
        //  1.4.1) should NOT found this inst
        EXPECT_EQ(ret, nullptr);
    }
    // 2)  if is_in6addr_any is true
    inst.is_in6addr_any = true;
    // 2.1) last_dest_addr and addr family ALL NOT match, but last_dest_port_matches
    for (uint i = 0; i < inst.local_addres_size; i++)
    {
        sockaddrunion tmp = inst.local_addres_list[i];
        s4addr(&tmp) -= 1;  // just minus to make it different
        saddr_family(&tmp) == AF_INET ?
        saddr_family(&tmp) = AF_INET6 :
                                        saddr_family(&tmp) = AF_INET;
        last_dest_addr = &tmp;
        ret = dlt.find_geco_instance_by_transport_addr(last_dest_addr, last_dest_port);
        //  2.1.1) should still found this inst
        EXPECT_EQ(ret, &inst);
    }
}
static void init_channel(dispatch_layer_t& dlt, channel_t& channel, ushort srcport, ushort destport,
        const char** src_ips, uint src_ips_len,
        const char** dest_ips, uint dest_ips_len,
        sockaddrunion* src,
        sockaddrunion* dest)
{
    for (uint i = 0; i < src_ips_len; i++)
    {
        str2saddr(&src[i], src_ips[i], srcport, true);
    }
    for (uint i = 0; i < dest_ips_len; i++)
    {
        str2saddr(&dest[i], dest_ips[i], destport, true);
    }
    channel.remote_addres = src;
    channel.local_addres = dest;
    channel.remote_port = srcport;
    channel.local_port = destport;
    channel.remote_addres_size = src_ips_len;
    channel.local_addres_size = dest_ips_len;
    channel.deleted = false;
    channel.is_IN6ADDR_ANY = false;
    channel.is_INADDR_ANY = false;
    dlt.channels_.push_back(&channel);
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_find_channel_by_transport_addr)
{
    const int src_ips_size = 3;
    const char* src_ips[src_ips_size] =
            { "192.168.1.0", "192.168.1.1", "192.168.1.2" };
    const int dest_ips_size = 3;
    const char* dest_ips[dest_ips_size] =
            { "192.168.1.3", "192.168.1.4", "192.168.1.5" };
    const ushort ports[] =
            { 100, 101 };  // src-dest
    sockaddrunion remote_addres[src_ips_size];
    sockaddrunion local_addres[dest_ips_size];

    channel_t channel;
    dispatch_layer_t dlt;
    init_channel(dlt, channel,
            ports[0], ports[1],
            src_ips, src_ips_size, dest_ips, dest_ips_size,
            remote_addres, local_addres);

    //temps
    channel_t* found;
    sockaddrunion* last_src_addr;
    sockaddrunion* last_dest_addr;
    ushort last_src_port = channel.remote_port;
    ushort last_dest_port = channel.local_port;
    sockaddrunion tmp_addr;

    //1) if src port not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        last_dest_addr = &channel.local_addres[i];
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            last_src_addr = &channel.remote_addres[j];
            last_src_port -= 1;  //just make it not equal to the one stored in channel
            //1.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
    //2) if dest port not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        last_dest_addr = &channel.local_addres[i];
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            last_src_addr = &channel.remote_addres[j];
            last_dest_port -= 1;            //just make it not equal to the one stored in channel
            //2.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
    //2) if dest port not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        last_dest_addr = &channel.local_addres[i];
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            last_src_addr = &channel.remote_addres[j];
            last_dest_port -= 1;            //just make it not equal to the one stored in channel
            //2.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
    //3) if dest and src port not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        last_dest_addr = &channel.local_addres[i];
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            last_src_addr = &channel.remote_addres[j];
            last_dest_port -= 1;            //just make it not equal to the one stored in channel
            last_src_port -= 1;            //just make it not equal to the one stored in channel
            //3.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
    //4) if dest addr not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        tmp_addr = channel.local_addres[i];
        s4addr(&tmp_addr) -= 1;  // just minus to make it different
        last_dest_addr = &tmp_addr;
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            last_src_addr = &channel.remote_addres[j];
            //3.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
    //5) if  src addr not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        last_dest_addr = &channel.local_addres[i];
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            tmp_addr = channel.remote_addres[i];
            s4addr(&tmp_addr) -= 1;  // just minus to make it different
            last_src_addr = &tmp_addr;
            //5.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
    //6) if  dest and addr not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        tmp_addr = channel.local_addres[i];
        s4addr(&tmp_addr) -= 1;  // just minus to make it different
        last_dest_addr = &tmp_addr;
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            sockaddrunion tmp_addr2;
            tmp_addr2 = channel.remote_addres[i];
            s4addr(&tmp_addr2) -= 1;  // just minus to make it different
            last_src_addr = &tmp_addr2;
            //6.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
    //7) if dest addr family not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        tmp_addr = channel.local_addres[i];
        saddr_family(&tmp_addr) == AF_INET ?
        saddr_family(&tmp_addr) = AF_INET6 :
                                             saddr_family(&tmp_addr) = AF_INET;
        last_dest_addr = &tmp_addr;
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            last_src_addr = &channel.remote_addres[j];
            //7.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
    //8) if src addr family not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        last_dest_addr = &channel.local_addres[i];
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            tmp_addr = channel.remote_addres[i];
            saddr_family(&tmp_addr) == AF_INET ?
            saddr_family(&tmp_addr) = AF_INET6 :
                                                 saddr_family(&tmp_addr) = AF_INET;
            last_src_addr = &tmp_addr;
            //5.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
    //6) if  dest and addr not equal
    for (uint i = 0; i < channel.local_addres_size; i++)
    {
        tmp_addr = channel.local_addres[i];
        saddr_family(&tmp_addr) == AF_INET ?
        saddr_family(&tmp_addr) = AF_INET6 :
                                             saddr_family(&tmp_addr) = AF_INET;
        last_dest_addr = &tmp_addr;
        for (uint j = 0; j < channel.remote_addres_size; j++)
        {
            sockaddrunion tmp_addr2;
            tmp_addr2 = channel.remote_addres[i];
            saddr_family(&tmp_addr2) == AF_INET ?
            saddr_family(&tmp_addr2) = AF_INET6 :
                                                  saddr_family(&tmp_addr2) = AF_INET;
            last_src_addr = &tmp_addr2;
            //6.1) should not find channel
            found = dlt.find_channel_by_transport_addr(last_src_addr, last_src_port,
                    last_dest_port);
            EXPECT_EQ(found, (channel_t*)NULL);
        }
    }
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_validate_dest_addr)
{
    /*8)
     * now we can validate if dest_addr in localaddress
     * this method internally uses curr_geco_instance_ and curr_channel_
     * so we must call it right here
     */
    int i;
    const char* addres[6] =
            { "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4",
                    "192.168.1.5" };
    const int addres_cnt = 6;
    const ushort ports[addres_cnt] =
            { 100, 101 };  // src-dest
    sockaddrunion remote_addres[addres_cnt / 2];
    sockaddrunion local_addres[addres_cnt / 2];

    for (i = 0; i < addres_cnt; i++)
    {
        if (i < addres_cnt / 2)
        {
            str2saddr(&remote_addres[i], addres[i], ports[0], true);
        }
        else
        {
            int idx = i % (addres_cnt / 2);
            str2saddr(&local_addres[idx], addres[i], ports[1], true);
        }
    }

    channel_t channel;
    channel.remote_addres = remote_addres;
    channel.local_addres = local_addres;
    channel.remote_port = ports[0];
    channel.local_port = ports[1];
    channel.remote_addres_size = addres_cnt / 2;
    channel.local_addres_size = addres_cnt / 2;
    channel.deleted = false;

    geco_instance_t inst;
    inst.local_addres_size = addres_cnt / 2;
    inst.local_addres_list = local_addres;
    inst.local_port = ports[1];
    channel.geco_inst = &inst;

    dispatch_layer_t dlt;
    dlt.channels_.push_back(&channel);
    dlt.geco_instances_.push_back(&inst);
    sockaddrunion* last_dest_addr;
    bool ret;

    //1) test return true when both of channel and inst are NULL
    dlt.curr_channel_ = NULL;
    dlt.curr_geco_instance_ = NULL;
    last_dest_addr = local_addres + 2;
    ret = dlt.validate_dest_addr(last_dest_addr);
    EXPECT_EQ(ret, true);

    //2) test return true when curr_channel_ NOT NULL
    dlt.curr_channel_ = &channel;
    dlt.curr_geco_instance_ = &inst;
    last_dest_addr = local_addres + 2;
    ret = dlt.validate_dest_addr(last_dest_addr);
    EXPECT_EQ(ret, true);

    //2) test return true when curr_channel_  NULL,
    // inst NOT NULL, is_inaddr_any false, is_in6addr_any false;
    dlt.curr_channel_ = NULL;
    dlt.curr_geco_instance_ = &inst;
    inst.is_inaddr_any = false;
    inst.is_in6addr_any = false;
    last_dest_addr = local_addres + 2;
    ret = dlt.validate_dest_addr(last_dest_addr);
    EXPECT_EQ(ret, true);

    //3) test return true when curr_channel_  NULL inst NOT NULL, is_inaddr_any true, is_in6addr_any false;
    dlt.curr_channel_ = NULL;
    dlt.curr_geco_instance_ = &inst;
    inst.is_inaddr_any = true;
    inst.is_in6addr_any = false;
    last_dest_addr = local_addres + 2;
    ret = dlt.validate_dest_addr(last_dest_addr);
    EXPECT_EQ(ret, true);

    //3) test return true when curr_channel_  NULL inst NOT NULL, is_inaddr_any false, is_in6addr_any true;
    dlt.curr_channel_ = NULL;
    dlt.curr_geco_instance_ = &inst;
    inst.is_inaddr_any = false;
    inst.is_in6addr_any = true;
    last_dest_addr = local_addres + 2;
    ret = dlt.validate_dest_addr(last_dest_addr);
    EXPECT_EQ(ret, false);

    //3) test return false when curr_channel_  NULL inst NOT NULL, is_inaddr_any false, is_in6addr_any false;
    dlt.curr_channel_ = NULL;
    dlt.curr_geco_instance_ = &inst;
    inst.is_inaddr_any = false;
    inst.is_in6addr_any = false;
    last_dest_addr = remote_addres + 2;  // we use remote addr as local addr that will not be found
    ret = dlt.validate_dest_addr(last_dest_addr);
    EXPECT_EQ(ret, true);

    //3) test return false when curr_channel_  NOT NULL,  is_inaddr_any false, is_in6addr_any false;
    dlt.curr_channel_ = &channel;
    dlt.curr_geco_instance_ = &inst;
    inst.is_inaddr_any = false;
    inst.is_in6addr_any = false;
    last_dest_addr = remote_addres + 2;  // we use remote addr as local addr that will not be found
    ret = dlt.validate_dest_addr(last_dest_addr);
    //should return true
    EXPECT_EQ(ret, true);

}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_find_chunk_types)
{
    /*9)
     *fetch all chunk types contained in this packet value field
     *fetch for use in the folowing curr_geco_packet_value_len_
     *fetch = dctp_packet_len - GECO_PACKET_FIXED_SIZE;
     *fetch chunk_types_arr_ = find_chunk_types(curr_geco_packet_->chunk,
     *fetch curr_geco_packet_value_len_, &total_chunks_count_);
     */
    geco_packet_t geco_packet;
    geco_packet.pk_comm_hdr.checksum = 0;
    geco_packet.pk_comm_hdr.dest_port = htons((generate_random_uint32() % USHRT_MAX));
    geco_packet.pk_comm_hdr.src_port = htons((generate_random_uint32() % USHRT_MAX));
    geco_packet.pk_comm_hdr.verification_tag = htons((generate_random_uint32()));

    // one data chunk
    uint offset = 0;
    uint chunklen = 0;
    uchar* wt = geco_packet.chunk;
    uint datalen = 101;
    chunklen = DATA_CHUNK_FIXED_SIZES + datalen;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_DATA;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    offset += chunklen;
    EXPECT_EQ(offset, 116);
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_DATA);
    wt += chunklen;

    //one sack chunk
    datalen = 31;
    chunklen = datalen + SACK_CHUNK_FIXED_SIZE + CHUNK_FIXED_SIZE;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_SACK;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    //116+4+12+31 = 132+31 = 163
    while (chunklen % 4)
    {
        chunklen++;
    }
    EXPECT_EQ(((chunk_fixed_t* )(geco_packet.chunk + offset))->chunk_id, CHUNK_SACK);
    offset += chunklen;
    EXPECT_EQ(offset, 164);
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_SACK);
    wt += chunklen;

    //one init chunk
    datalen = 21;
    chunklen = datalen + INIT_CHUNK_FIXED_SIZES;  //21+20=41
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_INIT;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    EXPECT_EQ(geco_packet.chunk + offset, wt);
    EXPECT_EQ(((chunk_fixed_t* )(geco_packet.chunk + offset))->chunk_id, CHUNK_INIT);
    offset += chunklen;
    EXPECT_EQ(offset, 208);  // 164+4+16+21= 205
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_INIT);
    wt += chunklen;

    //one init ack chunk
    datalen = 21;
    chunklen = datalen + INIT_CHUNK_FIXED_SIZES;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_INIT_ACK;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    EXPECT_EQ(((chunk_fixed_t* )(geco_packet.chunk + offset))->chunk_id, CHUNK_INIT_ACK);
    offset += chunklen;
    EXPECT_EQ(offset, 252);  // 208+20+21 = 228+21=249
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_INIT_ACK);
    wt += chunklen;

    //CHUNK_SHUTDOWN
    chunklen = 4 + CHUNK_FIXED_SIZE;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_SHUTDOWN;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    offset += chunklen;
    EXPECT_EQ(offset, 260);  // 252+8 = 260
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_SHUTDOWN);
    wt += chunklen;

    //CHUNK_SHUTDOWN_ACK
    chunklen = CHUNK_FIXED_SIZE;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_SHUTDOWN_ACK;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    offset += chunklen;
    EXPECT_EQ(offset, 264);  // 260+4 = 264
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_SHUTDOWN_ACK);
    wt += chunklen;

    //1) test good chunks
    dispatch_layer_t dlt;
    uint total_chunks_count;
    uint chunk_types = dlt.find_chunk_types(geco_packet.chunk, offset, &total_chunks_count);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 2);
    EXPECT_EQ(total_chunks_count, 6);

    //2) test bad chunks whose chun len < CHUNK_FIXED_SIZE
    // this will give us all legal chunks
    //CHUNK_SHUTDOWN_COMPLETE
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_SHUTDOWN_COMPLETE;
    ((chunk_fixed_t*) wt)->chunk_length = htons(3);
    offset += 4;
    EXPECT_EQ(offset, 268);  // 264+4 = 268
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_SHUTDOWN_COMPLETE);
    wt += 4;
    chunk_types = dlt.find_chunk_types(geco_packet.chunk, offset, &total_chunks_count);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types), 0);
    EXPECT_EQ(total_chunks_count, 6);

    //3) test branch chunk_len + read_len > packet_val_len line 3395
    chunk_types = dlt.find_chunk_types(geco_packet.chunk, offset - 4, &total_chunks_count);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types), 0);
    EXPECT_EQ(total_chunks_count, 6);

    //4) one CHUNK_SHUTDOWN_ACK
    chunk_types = dlt.find_chunk_types(wt - 8, offset - 8, &total_chunks_count);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 1);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types), 0);
    EXPECT_EQ(total_chunks_count, 1);

    //5) two repeated CHUNK_SHUTDOWN_ACK contains_chunk returns 1
    // but total_chunks_count is 2
    chunklen = CHUNK_FIXED_SIZE;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_SHUTDOWN_ACK;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    offset += chunklen;
    EXPECT_EQ(offset, 272);  // 260+4 = 264
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_SHUTDOWN_ACK);
    wt += chunklen;

    chunklen = CHUNK_FIXED_SIZE;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_SHUTDOWN_ACK;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    offset += chunklen;
    EXPECT_EQ(offset, 276);  // 260+4 = 264
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_SHUTDOWN_ACK);
    wt += chunklen;
    chunk_types = dlt.find_chunk_types(wt - 8, offset - 8, &total_chunks_count);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT_ACK, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_ACK, chunk_types), 1);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SHUTDOWN_COMPLETE, chunk_types), 0);
    EXPECT_EQ(total_chunks_count, 2);
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_find_first_chunk_of)
{
    geco_packet_t geco_packet;
    geco_packet.pk_comm_hdr.checksum = 0;
    geco_packet.pk_comm_hdr.dest_port = htons((generate_random_uint32() % USHRT_MAX));
    geco_packet.pk_comm_hdr.src_port = htons((generate_random_uint32() % USHRT_MAX));
    geco_packet.pk_comm_hdr.verification_tag = htons((generate_random_uint32()));

    // put one data chunk
    uint offset = 0;
    uint chunklen = 0;
    uchar* wt = geco_packet.chunk;
    uint datalen = 101;
    chunklen = DATA_CHUNK_FIXED_SIZES + datalen;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_DATA;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    offset += chunklen;
    EXPECT_EQ(offset, 116);
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_DATA);
    wt += chunklen;

    //put another data chunk
    datalen = 35;
    chunklen = DATA_CHUNK_FIXED_SIZES + datalen;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_DATA;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    offset += chunklen;
    EXPECT_EQ(offset, 164);
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_DATA);
    wt += chunklen;

    //put one sack chunk
    datalen = 31;
    chunklen = datalen + SACK_CHUNK_FIXED_SIZE + CHUNK_FIXED_SIZE;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_SACK;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    //116+4+12+31 = 132+31 = 163
    while (chunklen % 4)
    {
        chunklen++;
    }
    EXPECT_EQ(((chunk_fixed_t* )(geco_packet.chunk + offset))->chunk_id, CHUNK_SACK);
    offset += chunklen;
    EXPECT_EQ(offset, 212);
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_SACK);
    wt += chunklen;

    dispatch_layer_t dlt;
    EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_DATA), geco_packet.chunk);
    EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_SACK), wt - chunklen);
    EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_INIT), (uchar*)NULL);
    EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset - 45, CHUNK_SACK), (uchar*)NULL);

    //　branchtest:  chunk_len < CHUNK_FIXED_SIZE
    chunklen = 3;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_SHUTDOWN_ACK;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen);
    while (chunklen % 4)
    {
        chunklen++;
    }
    offset += chunklen;
    EXPECT_EQ(offset, 216);
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_SHUTDOWN_ACK);
    wt += chunklen;
    EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_SHUTDOWN_ACK), (uchar*)NULL);

    // branchtest: chunk_len + read_len > packet_val_len
    offset -= chunklen;
    wt -= chunklen;

    chunklen = 4;
    ((chunk_fixed_t*) wt)->chunk_id = CHUNK_INIT_ACK;
    ((chunk_fixed_t*) wt)->chunk_length = htons(chunklen + 1);
    while (chunklen % 4)
    {
        chunklen++;
    }
    offset += chunklen;
    EXPECT_EQ(offset, 216);
    EXPECT_EQ(((chunk_fixed_t* )wt)->chunk_id, CHUNK_INIT_ACK);
    wt += chunklen;
    EXPECT_EQ(dlt.find_first_chunk_of(geco_packet.chunk, offset, CHUNK_INIT_ACK), (uchar*)NULL);
}
static void init_addrlist(bool isip4, ushort port, const char** ipstrs, uint len,
        sockaddrunion* addrlist)
{
    for (uint i = 0; i < len; i++)
    {
        str2saddr(&addrlist[i], ipstrs[i], port, isip4);
    }
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_read_peer_addreslist)
{
    EXPECT_EQ(sizeof(in_addr), 4);
    EXPECT_EQ(sizeof(in6_addr), 16);

    geco_packet_t geco_packet;
    geco_packet.pk_comm_hdr.checksum = 0;
    geco_packet.pk_comm_hdr.dest_port = htons((generate_random_uint32() % USHRT_MAX));
    geco_packet.pk_comm_hdr.src_port = htons((generate_random_uint32() % USHRT_MAX));
    geco_packet.pk_comm_hdr.verification_tag = htons((generate_random_uint32()));

    init_chunk_t* init_chunk = (init_chunk_t*) (geco_packet.chunk);
    init_chunk->chunk_header.chunk_id = CHUNK_INIT;
    init_chunk->chunk_header.chunk_flags = 0;

    int i;
    const char* addres[] =
            { "192.168.1.121", "192.168.1.132", "192.168.34.2" };
    const char* addres6[] =
            { "2001:0db8:0a0b:12f0:0000:0000:0000:0001", "2607:f0d0:1002:0051:0000:0000:0000:0004" };
    sockaddrunion local_addres[3];
    sockaddrunion local_addres6[2];
    init_addrlist(true, 0, addres, 3, local_addres);
    init_addrlist(false, 0, addres6, 2, local_addres6);

    uint offset = 0;
    offset += put_vlp_addrlist(init_chunk->variableParams, local_addres, 3);
    offset += put_vlp_addrlist(init_chunk->variableParams + offset, local_addres6,2);

    EXPECT_EQ(offset, 64);
    init_chunk->chunk_header.chunk_length = htons(
    INIT_CHUNK_FIXED_SIZES + offset);

    sockaddrunion peer_addreslist[MAX_NUM_ADDRESSES];
    dispatch_layer_t dlt;
    dlt.defaultlocaladdrlistsize_ = 0;

    char buf[MAX_IPADDR_STR_LEN];
    ushort port;

    sockaddrunion last_source_addr;
    dlt.last_source_addr_ = &last_source_addr;
    int ret;

    uint peersupportedtypes = 0;
    str2saddr(&last_source_addr, "2607:f0d0:1002:0051:0000:0000:0000:0005", 0, false);
    ret = dlt.read_peer_addreslist(peer_addreslist, geco_packet.chunk,
            offset + INIT_CHUNK_FIXED_SIZES,
            SUPPORT_ADDRESS_TYPE_IPV4, &peersupportedtypes);
    EXPECT_EQ(ret, 3);  //3 ip4 addrs  but last src addr ths is ip6 not supported by us
    EXPECT_EQ(peersupportedtypes, SUPPORT_ADDRESS_TYPE_IPV4);

    for (i = 0; i < 3; ++i)
    {
        saddr2str(&peer_addreslist[i], buf, MAX_IPADDR_STR_LEN, &port);
        EVENTLOG1(VERBOSE, "peer ip4addr: %s\n", buf);
        saddr2str(&local_addres[i], buf, MAX_IPADDR_STR_LEN, &port);
        EVENTLOG1(VERBOSE, "record ip4addr: %s\n", buf);
        EXPECT_TRUE(saddr_equals(&peer_addreslist[i], &local_addres[i], true));
    }
    //EXPECT_TRUE(saddr_equals(&peer_addreslist[3], &last_source_addr, true));

    str2saddr(&last_source_addr, "192.168.5.123", 0, true);
    ret = dlt.read_peer_addreslist(peer_addreslist, geco_packet.chunk,
            offset + INIT_CHUNK_FIXED_SIZES,
            SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6);
    EXPECT_EQ(ret, 6);
    for (i = 0; i < 3; ++i)
    {
        EXPECT_TRUE(saddr_equals(&peer_addreslist[i], &local_addres[i], true));
    }
    for (i = 3; i < 5; ++i)
    {
        EXPECT_TRUE(saddr_equals(&peer_addreslist[i], &local_addres6[i - 3], true));
    }
    EXPECT_TRUE(saddr_equals(&peer_addreslist[5], &last_source_addr, true));
    str2saddr(&last_source_addr, "2607:f0d0:1002:0051:0000:0000:0000:0005", 0, false);
    ret = dlt.read_peer_addreslist(peer_addreslist, geco_packet.chunk,
            offset + INIT_CHUNK_FIXED_SIZES,
            SUPPORT_ADDRESS_TYPE_IPV6);
    EXPECT_EQ(ret, 3);  //2 + last_source_addr_ = 3
    for (i = 0; i < 2; ++i)
    {
        saddr2str(&peer_addreslist[i], buf, MAX_IPADDR_STR_LEN, &port);
        EVENTLOG1(VERBOSE, "peer ip6addr: %s\n", buf);
        saddr2str(&local_addres6[i], buf, MAX_IPADDR_STR_LEN, &port);
        EVENTLOG1(VERBOSE, "record ip6addr: %s\n", buf);
        EXPECT_TRUE(saddr_equals(&peer_addreslist[i], &local_addres6[i], true));
    }
    EXPECT_TRUE(saddr_equals(&peer_addreslist[2], &last_source_addr, true));
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_contain_local_addr)
{
    /**
     * check if local addr is found
     * eg. ip4 loopback 127.0.0.1 or ip4  ethernet local addr 192.168.1.107 or public ip4 addr
     * containslocaladdr(sockaddrunion* addr_list,uint addr_list_num);*/
    int i;
    const char* addres[] =
            { "192.168.1.121", "192.168.1.132", "192.168.34.2" };
    const char* addres6[] =
            { "2001:0db8:0a0b:12f0:0000:0000:0000:0001", "2607:f0d0:1002:0051:0000:0000:0000:0004" };
    sockaddrunion local_addres[3];
    sockaddrunion local_addres6[2];
    for (i = 0; i < 3; i++)
    {
        str2saddr(&local_addres[i], addres[i], 0, true);
    }
    for (i = 0; i < 2; i++)
    {
        str2saddr(&local_addres6[i], addres6[i], 0, false);
    }
    geco_instance_t inst;
    inst.supportedAddressTypes = SUPPORT_ADDRESS_TYPE_IPV4;
    inst.local_addres_size = 3;
    inst.local_addres_list = local_addres;

    dispatch_layer_t dlt;
    dlt.geco_instances_.push_back(&inst);
    sockaddrunion tmpaddr;

    //1) test branch 1 curr geco_inst and curr channel both NULL
    //1.1) test no local addr presents
    EXPECT_FALSE(dlt.contain_local_addr(local_addres, 3));
    EXPECT_FALSE(dlt.contain_local_addr(local_addres6, 2));
    //1.2) test  local addr presents
    tmpaddr = local_addres[1];
    str2saddr(&local_addres[1], "127.0.0.1", 0, true);
    EXPECT_TRUE(dlt.contain_local_addr(local_addres, 3));
    local_addres[1] = tmpaddr;
    tmpaddr = local_addres6[1];
    str2saddr(&local_addres6[1], "::1", 0, false);
    EXPECT_TRUE(dlt.contain_local_addr(local_addres6, 2));
    local_addres6[1] = tmpaddr;

    //2) test branch 2 curr_geco_instance_ NOT NULL
    dlt.curr_geco_instance_ = &inst;
    //2.1) test local addr in curr gecio inst local addres list
    tmpaddr = local_addres[1];
    EXPECT_TRUE(dlt.contain_local_addr(&tmpaddr, 1));
    //2.1) test no local addr in curr gecio inst local addres list
    str2saddr(&tmpaddr, "221.123.45.12", 0, true);
    EXPECT_FALSE(dlt.contain_local_addr(&tmpaddr, 1));
}
// last run and passed on 22 Agu 2016
TEST(DISPATCHER_MODULE, test_find_vlparam_from_setup_chunk)
{
    geco_packet_t geco_packet;
    geco_packet.pk_comm_hdr.checksum = 0;
    geco_packet.pk_comm_hdr.dest_port = htons((generate_random_uint32() % USHRT_MAX));
    geco_packet.pk_comm_hdr.src_port = htons((generate_random_uint32() % USHRT_MAX));
    geco_packet.pk_comm_hdr.verification_tag = htons((generate_random_uint32()));

    init_chunk_t* init_chunk = (init_chunk_t*) (geco_packet.chunk);
    init_chunk->chunk_header.chunk_id = CHUNK_INIT;
    init_chunk->chunk_header.chunk_flags = 0;

    const char* hn = "www.baidu.com";
    ((vlparam_fixed_t*) init_chunk->variableParams)->param_type = htons(
    VLPARAM_HOST_NAME_ADDR);
    ((vlparam_fixed_t*) init_chunk->variableParams)->param_length = htons(4 + strlen(hn));
    strcpy((char*) (init_chunk->variableParams + 4), hn);

    uint len = 4 + strlen(hn) + INIT_CHUNK_FIXED_SIZES;
    init_chunk->chunk_header.chunk_length = htons(len);
    while (len % 4)
        ++len;
    dispatch_layer_t dlt;
    uchar* ret = dlt.find_vlparam_from_setup_chunk(geco_packet.chunk, len,
    VLPARAM_HOST_NAME_ADDR);
    EXPECT_EQ(ret, init_chunk->variableParams);

    ret = dlt.find_vlparam_from_setup_chunk(geco_packet.chunk, len,
    VLPARAM_COOKIE);
    EXPECT_EQ(ret, (uchar*)NULL);
    ret = dlt.find_vlparam_from_setup_chunk(geco_packet.chunk, len,
    VLPARAM_SUPPORTED_ADDR_TYPES);
    EXPECT_EQ(ret, (uchar*)NULL);

}
TEST(DISPATCHER_MODULE, test_alloc_complete_bundle_send_free_simple_chunk)
{
    dispatch_layer_t dlt;
    int rcwnd = 512;
    network_interface_t nit;
    nit.init(&rcwnd, true);
    dlt.transport_layer_ = &nit;
    sockaddrunion last_drc_addr;
    str2saddr(&last_drc_addr, "127.0.0.1", 456);
    dlt.last_source_addr_ = &last_drc_addr;
    dlt.last_dest_port_ = 123;
    dlt.last_src_port_ = 456;
    dlt.last_init_tag_ = 12345;

    uint shutdown_complete_cid = dlt.alloc_simple_chunk(
    CHUNK_SHUTDOWN_COMPLETE, FLAG_NO_CHANNEL);
    simple_chunk_t* simple_chunk_t_ptr_ = dlt.complete_simple_chunk(shutdown_complete_cid);
    EXPECT_EQ(
            dlt.curr_write_pos_[shutdown_complete_cid]
                    + ntohs(dlt.simple_chunks_[shutdown_complete_cid]->chunk_header.chunk_length),
            4);
    //1) test branch < max_geco_
    //1.1) test dest_index == NULL
    dlt.bundle_ctrl_chunk(simple_chunk_t_ptr_, NULL);
    EXPECT_FALSE(dlt.default_bundle_ctrl_.got_send_address);
    EXPECT_EQ(dlt.default_bundle_ctrl_.requested_destination, 0);
    //1.2 ) test dest_index != NULL
    int path = 6;
    dlt.bundle_ctrl_chunk(simple_chunk_t_ptr_, &path);
    EXPECT_TRUE(dlt.default_bundle_ctrl_.got_send_address);
    EXPECT_EQ(dlt.default_bundle_ctrl_.requested_destination, path);

    //2) test branch >= max_geco_ automatically call send
    dlt.curr_write_pos_[shutdown_complete_cid] +=
    MAX_NETWORK_PACKET_VALUE_SIZE - 4;
    simple_chunk_t_ptr_->chunk_header.chunk_length = 4;
    dlt.default_bundle_ctrl_.ctrl_position = UDP_GECO_PACKET_FIXED_SIZES;
    dlt.default_bundle_ctrl_.ctrl_chunk_in_buffer = true;
    simple_chunk_t_ptr_ = dlt.complete_simple_chunk(shutdown_complete_cid);
    EXPECT_EQ(ntohs(simple_chunk_t_ptr_->chunk_header.chunk_length), MAX_NETWORK_PACKET_VALUE_SIZE);
    EXPECT_EQ(dlt.get_bundle_total_size(&dlt.default_bundle_ctrl_), UDP_GECO_PACKET_FIXED_SIZES);
    dlt.bundle_ctrl_chunk(simple_chunk_t_ptr_, &path);
    EXPECT_EQ(dlt.get_bundle_total_size(&dlt.default_bundle_ctrl_), MAX_GECO_PACKET_SIZE);
    dlt.unlock_bundle_ctrl();
    dlt.send_bundled_chunks(&path);
    EXPECT_EQ(dlt.get_bundle_total_size(&dlt.default_bundle_ctrl_), UDP_GECO_PACKET_FIXED_SIZES);
    dlt.free_simple_chunk(shutdown_complete_cid);

    //3) test sack + data+ctrl chunks bundled in one packet TODO
}
TEST(DISPATCHER_MODULE, test_recv_geco_packet)
{
    //fills up addreslist
    int i;
    const char* addres[] =
            { "192.168.1.121", "192.168.1.132", "192.168.34.2" };
    const char* addres6[] =
            { "2001:0db8:0a0b:12f0:0000:0000:0000:0001", "2607:f0d0:1002:0051:0000:0000:0000:0004" };

    const char* dest_ips[] =
            { "192.168.1.122", "192.168.1.131", "192.168.34.1" };
    const char* dest_ips6[] =
            { "2001:0db8:0a0b:12f0:0000:0000:0000:0002", "2607:f0d0:1002:0051:0000:0000:0000:0005" };

    ushort sender_src_port = 123;
    ushort sender_dest_port = 456;

    const char* cannot_found_ips4[] =
            { "192.168.1.123", "192.168.1.101", "192.168.34.5" };
    const char* cannot_found_ips6[] =
            { "2001:0db8:0a0b:12f0:0000:0000:0000:0020", "2607:f0d0:1002:0051:0000:0000:0000:0100" };

    sockaddrunion src_addres[3];  // sender src addr=receiver remote addr
    sockaddrunion src_addres6[2];  // sender src addr=receiver remote addr
    sockaddrunion dest_addres[3];  // sender dest add is receiver local addr
    sockaddrunion dest_addres6[2];  // sender dest addr=receiver local addr
    sockaddrunion cannot_found_addres4[3];  // sender dest add is receiver local addr
    sockaddrunion cannot_found_addres6[2];  // sender dest addr=receiver local addr
    EXPECT_EQ(sizeof(in_addr), 4);
    EXPECT_EQ(sizeof(in6_addr), 16);

    geco_packet_t geco_packet;
    int sfd = 123;
    geco_packet_t* dctp_packet = &geco_packet;
    uint dctp_packet_len;
    sockaddrunion source_addr;
    sockaddrunion dest_addr;

    /*prepare an init chunk*/
    // fills up geco packet hdr
    geco_packet.pk_comm_hdr.checksum = 0;
    geco_packet.pk_comm_hdr.dest_port = htons(sender_dest_port);  //456
    geco_packet.pk_comm_hdr.src_port = htons(sender_src_port);  //123
    geco_packet.pk_comm_hdr.verification_tag = 0;
    // fills up init chunk hdr
    init_chunk_t* init_chunk = (init_chunk_t*) (geco_packet.chunk);
    init_chunk->chunk_header.chunk_id = CHUNK_INIT;
    init_chunk->chunk_header.chunk_flags = 0;
    init_chunk->init_fixed.inbound_streams = htons(5);
    init_chunk->init_fixed.outbound_streams = htons(5);
    init_chunk->init_fixed.init_tag = htonl(generate_random_uint32());
    init_chunk->init_fixed.initial_tsn = init_chunk->init_fixed.init_tag;
    init_chunk->init_fixed.rwnd = htonl(512);
    ip_address_t* ipaddr = (ip_address_t*) init_chunk->variableParams;
    ushort len;
    ushort offset = 0;
    len = sizeof(in_addr) + VLPARAM_FIXED_SIZE;
    EXPECT_EQ(len, 8);
    for (i = 0; i < 3; i++)
    {
        str2saddr(&src_addres[i], addres[i], sender_src_port, true);
        str2saddr(&dest_addres[i], dest_ips[i], sender_dest_port, true);
        str2saddr(&cannot_found_addres4[i], cannot_found_ips4[i], 0, true);
        ipaddr->vlparam_header.param_type = htons(VLPARAM_IPV4_ADDRESS);
        ipaddr->vlparam_header.param_length = htons(len);
        ipaddr->dest_addr_un.ipv4_addr = src_addres[i].sin.sin_addr.s_addr;
        while (len % 4)
            len++;
        offset += len;
        ipaddr = (ip_address_t*) (init_chunk->variableParams + offset);
    }
    len = sizeof(in6_addr) + VLPARAM_FIXED_SIZE;
    EXPECT_EQ(len, 20);
    for (i = 0; i < 2; i++)
    {
        str2saddr(&src_addres6[i], addres6[i], sender_src_port, false);
        str2saddr(&dest_addres6[i], dest_ips6[i], sender_dest_port, false);
        str2saddr(&cannot_found_addres6[i], cannot_found_ips6[i], 0, false);

        ipaddr->vlparam_header.param_type = htons(VLPARAM_IPV6_ADDRESS);
        ipaddr->vlparam_header.param_length = htons(len);
        ipaddr->dest_addr_un.ipv6_addr = src_addres6[i].sin6.sin6_addr;
        while (len % 4)
            len++;
        offset += len;
        ipaddr = (ip_address_t*) (init_chunk->variableParams + offset);
    }
    EXPECT_EQ(offset, 64);
    // fills up support types
    len = sizeof(ushort) * 2 + 4;
    vlparam_fixed_t* saddrtypes = (vlparam_fixed_t*) (init_chunk->variableParams + offset);
    saddrtypes->param_type = htons(VLPARAM_SUPPORTED_ADDR_TYPES);
    saddrtypes->param_length = htons(len);
    *((ushort*) (init_chunk->variableParams + offset + 4)) = htons(
    VLPARAM_IPV4_ADDRESS);
    *((ushort*) (init_chunk->variableParams + offset + 4 + 2)) = htons(
    VLPARAM_IPV6_ADDRESS);
    while (len % 4)
        len++;
    offset += len;
    EXPECT_EQ(offset, 72);

    init_chunk->chunk_header.chunk_length = htons(
    INIT_CHUNK_FIXED_SIZES + offset);
    EXPECT_EQ(INIT_CHUNK_FIXED_SIZES + offset, 92);

    // setup default test variables, they may be manually changed
    // to cater for specified test.
    dispatch_layer_t dlt;
    network_interface_t init;
    int rwnd = 512;
    init.init(&rwnd, true);
    dlt.transport_layer_ = &init;
    geco_instance_t inst;
    inst.supportedAddressTypes = SUPPORT_ADDRESS_TYPE_IPV4 | SUPPORT_ADDRESS_TYPE_IPV6;
    inst.is_inaddr_any = false;
    inst.is_in6addr_any = true;
    inst.noOfInStreams = 12;
    inst.noOfOutStreams = 12;
    inst.local_port = sender_dest_port;
    inst.local_addres_list = dest_addres6;
    inst.local_addres_size = sizeof dest_addres6;
    channel_t channel;
    channel.channel_id = 123;
    channel.remote_addres = src_addres6;
    channel.remote_addres_size = sizeof src_addres6;
    channel.local_addres = dest_addres6;
    channel.local_addres_size = sizeof dest_addres6;
    channel.remote_port = sender_src_port;
    channel.local_port = sender_dest_port;
    channel.deleted = false;
    channel.geco_inst = &inst;
    dlt.channels_.push_back(&channel);
    dlt.geco_instances_.push_back(&inst);

    // use INIT CHUNK as default packet, we may change its chunk id and so
    // on to catter for specified needs. eg, set chunk id to chunk data to
    // to test chunk_abort branch
    dctp_packet_len = offset + INIT_CHUNK_FIXED_SIZES + GECO_PACKET_FIXED_SIZE;
    set_crc32_checksum((char*) &geco_packet,
            offset + INIT_CHUNK_FIXED_SIZES + GECO_PACKET_FIXED_SIZE);

    //1) branch line 364 - 12) try to find an channel for this packet from setup chunks
    // 1.2) test found an existed channel from setup chunks
    str2saddr(&source_addr, cannot_found_ips6[1], sender_src_port, false);  //use unfoundable src addr
    dest_addr = dest_addres6[1];  // use foundable dest addr
    dlt.recv_geco_packet(sfd, (char*) dctp_packet, dctp_packet_len, &source_addr, &dest_addr);
    EXPECT_EQ(dlt.curr_channel_, &channel);
    //1.2) test Not found an existed channel from setup chunks
    //    str2saddr(&source_addr, cannot_found_ips6[1], sender_src_port, false);  //use unfoundable src addr
    //    dest_addr = dest_addres6[1];  // use foundable dest addr
    //    sockaddrunion* tmp_remotes = channel.remote_addres;
    //    uint tmp_remotes_size = channel.remote_addres_size;
    //    channel.remote_addres = cannot_found_addres6;
    //    channel.remote_addres_size = sizeof cannot_found_addres6;
    //    dlt.recv_geco_packet(sfd, (char*) dctp_packet, dctp_packet_len, &source_addr, &dest_addr);
    //    EXPECT_FALSE(dlt.found_existed_channel_from_init_chunks_);

    //    //2) test branch at line 263 -> init, init ack or shutdown complete should be the only chunk
    //    //otherwise will be discarded.
    //    len = CHUNK_FIXED_SIZE;
    //    simple_chunk_t* abort = (simple_chunk_t*) (dctp_packet->chunk + offset
    //            + INIT_CHUNK_FIXED_SIZES);
    //    abort->chunk_header.chunk_id = CHUNK_ABORT;
    //    abort->chunk_header.chunk_flags = 1; // T set reflected verifi tag
    //    abort->chunk_header.chunk_length = htons(len);
    //    while (len % 4)
    //        len++;
    //    offset += len;
    //    dctp_packet_len += len;
    //    EXPECT_EQ(offset, 76);

    //    //3) test branch if (contains_chunk(CHUNK_ABORT, chunk_types_arr_) > 0) at line 699
    //    // SHOULD DISCARD IT
    //    init_chunk->chunk_header.chunk_id = CHUNK_DATA;
    //    set_crc32_checksum((char*) &geco_packet,
    //            offset + INIT_CHUNK_FIXED_SIZES + GECO_PACKET_FIXED_SIZE);
    //    dlt.recv_geco_packet(sfd, (char*) dctp_packet, dctp_packet_len,
    //            &source_addr, &dest_addr);
    //    EXPECT_TRUE(dlt.branchtest_contains_chunk_abort_when_curr_channel_is_null_);

    //    //4) test branch - validate ip addresses -
    //    // switch (saddr_family(dest_addr)) at line 102
    //    // should failed when given a any addr as src address
    //    init_chunk->chunk_header.chunk_id = CHUNK_DATA;
    //    source_addr.sin.sin_addr.s_addr = INADDR_ANY;
    //    set_crc32_checksum((char*) &geco_packet,
    //            offset + INIT_CHUNK_FIXED_SIZES + GECO_PACKET_FIXED_SIZE);
    //    dlt.recv_geco_packet(sfd, (char*) dctp_packet, dctp_packet_len,
    //            &source_addr, &dest_addr);
    //    EXPECT_TRUE(dlt.should_discard_curr_geco_packet_);

    //    //5) test branch if (contains_chunk(CHUNK_ABORT, chunk_types_arr_) > 0) at line 699
    //    // SHOULD DISCARD IT
    //    init_chunk->chunk_header.chunk_id = CHUNK_DATA;
    //    set_crc32_checksum((char*) &geco_packet,
    //            offset + INIT_CHUNK_FIXED_SIZES + GECO_PACKET_FIXED_SIZE);
    //    dlt.recv_geco_packet(sfd, (char*) dctp_packet, dctp_packet_len,
    //            &source_addr, &dest_addr);

    offset -= len;
    dctp_packet_len -= len;

    //    //2.1 test when is_in(6)addr_any both true and local addr and port All different,
    //    // should NOT found geco inst and Not find channel
    //    inst.local_addres_size = 3;
    //    inst.local_addres_list = remote_addres6_geco_channel_not_found;
    //    inst.is_inaddr_any = true;
    //    inst.is_inaddr_any = true;
    //    inst.local_port = 3306; // not found dest port
    //    inst.is_ip4 = true;
    //    inst.is_ip6 = true;
    //    // repeated src addr
    //    str2saddr(&source_addr, "2001:0db8:0a0b:12f0:0000:0000:0000:0001",
    //            ntohs(geco_packet.pk_comm_hdr.src_port), false);
    //    // not found dest addr
    //    str2saddr(&dest_addr, "2001:0db8:0a0b:12f0:0000:0000:0000:0002",
    //            ntohs(geco_packet.pk_comm_hdr.dest_port),false);
    //    init_chunk->chunk_header.chunk_id = CHUNK_INIT;
    //    set_crc32_checksum((char*) &geco_packet,
    //            offset + INIT_CHUNK_FIXED_SIZES + GECO_PACKET_FIXED_SIZE);
    //    dlt.recv_geco_packet(sfd, (char*) dctp_packet, dctp_packet_len,
    //            &source_addr, &dest_addr);

    //2,2  test when is_in(6)addr_any both true and local addr different but dest port same
    // should found geco inst and NOT found channel
    // repeated src addr
    //    inst.local_addres_size = 3;
    //    inst.local_addres_list = remote_addres6_geco_channel_can_found;
    //    inst.is_inaddr_any = false;
    //    inst.is_in6addr_any = true; // this can accept ip4 a d 6 dest addr
    //    inst.local_port = ntohs(geco_packet.pk_comm_hdr.dest_port) ;
    //    inst.is_ip4 = true;
    //    inst.is_ip6 = true;
    //      str2saddr(&source_addr, "2001:0db8:0a0b:12f0:0000:0000:0000:0001",
    //              ntohs(geco_packet.pk_comm_hdr.src_port), false);
    //      // unfoundable dest addr
    //      dest_addr = remote_addres6_geco_channel_not_found[0];
    //    init_chunk->chunk_header.chunk_id = CHUNK_INIT;
    //    set_crc32_checksum((char*) &geco_packet,
    //            offset + INIT_CHUNK_FIXED_SIZES + GECO_PACKET_FIXED_SIZE);
    //    dlt.recv_geco_packet(sfd, (char*) dctp_packet, dctp_packet_len,
    //            &source_addr, &dest_addr);

    //    //2,3  test when is_in(6)addr_any both FALSE and local addr different AND  dest port BOTH same,
    //    // should found geco inst
    //    inst.local_addres_size = 3;
    //    inst.local_addres_list = remote_addres6_geco_channel_can_found;
    //    for (int i = 0; i < inst.local_addres_size; i++)
    //    {
    //        inst.local_addres_list[i].sin6.sin6_port =
    //                geco_packet.pk_comm_hdr.dest_port;
    //    }
    //    inst.is_inaddr_any = false;
    //    inst.is_in6addr_any = false; // this can accept ip4 a d 6 dest addr
    //    inst.local_port = ntohs(geco_packet.pk_comm_hdr.dest_port);
    //    inst.is_ip4 = true;
    //    inst.is_ip6 = true;
    //    str2saddr(&source_addr, "2001:0db8:0a0b:12f0:0000:0000:0000:0001",
    //            ntohs(geco_packet.pk_comm_hdr.src_port), false);
    //    // unfoundable dest addr
    //    dest_addr = remote_addres6_geco_channel_can_found[1];
    //    init_chunk->chunk_header.chunk_id = CHUNK_INIT;
    //    set_crc32_checksum((char*) &geco_packet,
    //            offset + INIT_CHUNK_FIXED_SIZES + GECO_PACKET_FIXED_SIZE);
    //    dlt.recv_geco_packet(sfd, (char*) dctp_packet, dctp_packet_len,
    //            &source_addr, &dest_addr);
}
// last run and passed on 21 Agu 2016 
TEST(DISPATCHER_MODULE, test_contains_chunk)
{
    /**
     * contains_chunk: looks for chunk_type in a newly received geco packet
     * Should be called after find_chunk_types().
     * The chunkArray parameter is inspected. This only really checks for chunks
     * with an ID <= 30. For all other chunks, it just guesses...
     * @return 0 NOT contains, 1 contains and only one, 2 contains and NOT only one
     * @pre: need call find_chunk_types() first
     */
    uint chunk_types;
    dispatch_layer_t dlt;

    chunk_types = 0;
    EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 0);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_HBREQ, chunk_types), 0);

    // INIT must be the only chunk in the packet
    chunk_types = 0;
    chunk_types |= 1 << CHUNK_INIT;
    EXPECT_EQ(dlt.contains_chunk(CHUNK_INIT, chunk_types), 1);

    chunk_types = 0;
    chunk_types |= 1 << CHUNK_DATA;
    chunk_types |= 1 << CHUNK_SACK;
    chunk_types |= 1 << CHUNK_HBREQ;
    EXPECT_EQ(dlt.contains_chunk(CHUNK_DATA, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_SACK, chunk_types), 2);
    EXPECT_EQ(dlt.contains_chunk(CHUNK_HBREQ, chunk_types), 2);
}

