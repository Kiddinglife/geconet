#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "globals.h"

TEST(test_case_logging, test_read_trace_levels)
{
    read_trace_levels();
}

#include "gecotimer.h"
static bool action(timer_id_t& id, void*, void*)
{
    EVENTLOG(VERBOSE, "timer triggered\n");
    return NOT_RESET_TIMER_FROM_CB;
}
TEST(TIMER_MODULE, test_timer_mgr)
{
    timer_mgr tm;
    timer_id_t ret1 = tm.add_timer(TIMER_TYPE_INIT, 1000, action);
    timer_id_t ret2 = tm.add_timer(TIMER_TYPE_SACK, 1, action);
    timer_id_t ret3 = tm.add_timer(TIMER_TYPE_SACK, 15, action);
    tm.print(VERBOSE);
    tm.delete_timer(ret1);
    tm.delete_timer(ret2);
    tm.print(VERBOSE);
}

#include "geco-ds-malloc.h"
#include <algorithm>
using namespace geco::ds;
struct alloc_t
{
        void* ptr;
        size_t allocsize;
};

TEST(test_case_malloc, test_alloc_dealloc)
{
    int j;
    int total = 1000000;
    /*max is 5120 we use 5121 to have the max*/
    size_t allocsize;
    size_t dealloc_idx;
    std::list<alloc_t> allos;
    std::list<alloc_t>::iterator it;

    int alloccnt = 0;
    int deallcnt = 0;

    for (j = 0; j < total; j++)
    {
        if (rand() % 2)
        {
            allocsize = rand() % 5121;
            alloc_t at;
            at.ptr = single_client_alloc::allocate(allocsize);
            at.allocsize = allocsize;
            allos.push_back(at);
            alloccnt++;
        }
        else
        {
            size_t s = allos.size();
            if (s > 0)
            {
                dealloc_idx = rand() % s;
                it = allos.begin();
                std::advance(it, dealloc_idx);
                single_client_alloc::deallocate(it->ptr, it->allocsize);
                allos.erase(it);
                deallcnt++;
            }
        }
    }

    for (auto& p : allos)
    {
        single_client_alloc::deallocate(p.ptr, p.allocsize);
        deallcnt++;
    }
    allos.clear();
    single_client_alloc::destroy();
    EXPECT_EQ(alloccnt, deallcnt);
    EXPECT_EQ(allos.size(), 0);
    printf("alloccnt %d, dealloccnt %d\n", alloccnt, deallcnt);
}

#include "auth.h"
TEST(AUTH_MODULE, test_md5)
{
    const char* testdata = "202cb962ac59075b964b07152d234b70";
    const char* result = "d9b1d7db4cd6e70935368a1efb10e377";
    MD5 md5_0(testdata);
    EVENTLOG1(VERBOSE, "DGEST %s", md5_0.hexdigest().c_str());
    EXPECT_STREQ(md5_0.hexdigest().c_str(), result);

    testdata = "d9b1d7db4cd6e70935368a1efb10e377";
    result = "7363a0d0604902af7b70b271a0b96480";
    MD5 md5_1(testdata);
    EXPECT_STREQ(md5_1.hexdigest().c_str(), result);
    EVENTLOG1(VERBOSE, "DGEST %s", md5_1.hexdigest().c_str());
    int a = 123;
    MD5 md5_2((const char*) &a);
}
TEST(AUTH_MODULE, test_sockaddr2hashcode)
{
    uint ret;
    sockaddrunion localsu;
    str2saddr(&localsu, "192.168.1.107", 36000);
    sockaddrunion peersu;
    str2saddr(&peersu, "192.168.1.107", 36000);
    ret = transportaddr2hashcode(&localsu, &peersu);
    EVENTLOG2(VERBOSE,
            "hash(addr pair { localsu: 192.168.1.107:36001 peersu: 192.168.1.107:36000 }) = %u, %u",
            ret, ret % 100000);

    str2saddr(&localsu, "192.168.1.107", 1234);
    str2saddr(&peersu, "192.168.1.107", 360);
    ret = transportaddr2hashcode(&localsu, &peersu);
    EVENTLOG2(VERBOSE,
            "hash(addr pair { localsu: 192.168.1.107:36001 peersu: 192.168.1.107:36000 }) = %u, %u",
            ret, ret % 100000);
}
TEST(AUTH_MODULE, test_crc32_checksum)
{
    for (int ii = 0; ii < 100; ii++)
    {
        geco_packet_t geco_packet;
        geco_packet.pk_comm_hdr.checksum = 0;
        geco_packet.pk_comm_hdr.dest_port = htons(
                (generate_random_uint32() % USHRT_MAX));
        geco_packet.pk_comm_hdr.src_port = htons(
                (generate_random_uint32() % USHRT_MAX));
        geco_packet.pk_comm_hdr.verification_tag = htons(
                (generate_random_uint32()));
        ((chunk_fixed_t*) geco_packet.chunk)->chunk_id = CHUNK_DATA;
        ((chunk_fixed_t*) geco_packet.chunk)->chunk_length = htons(100);
        ((chunk_fixed_t*) geco_packet.chunk)->chunk_flags =
        DCHUNK_FLAG_UNORDER | DCHUNK_FLAG_FL_FRG;
        for (int i = 0; i < 100; i++)
        {
            uchar* wt = geco_packet.chunk + CHUNK_FIXED_SIZE;
            wt[i] = generate_random_uint32() % UCHAR_MAX;
        }
        set_crc32_checksum((char*) &geco_packet, DATA_CHUNK_FIXED_SIZES + 100);
        bool ret = validate_crc32_checksum((char*) &geco_packet,
        DATA_CHUNK_FIXED_SIZES + 100);
        EXPECT_TRUE(ret);
    }
}

TEST(TEST_SWITCH, SWITCH)
{
    int a = 6;
    switch (a)
    {
        case 1:
            EVENTLOG(VERBOSE, "1");
        case 4:
        case 5:
        case 6:
            EVENTLOG(VERBOSE, "6");
            break;
        case 7:
            EVENTLOG(VERBOSE, "2");
            break;
        default:
            break;
    }
}

