#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "globals.h"

TEST(test_case_logging, test_read_trace_levels)
{
    read_trace_levels();
}

#include "auth.h"
TEST(test_case_auth, test_md5_1)
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
    MD5 md5_2((const char*)&a);
} 

#include "geco-ds-malloc.h"
using namespace geco::ds;
//TEST(test_case_malloc, test_alloc_dealloc)
//{
//    int times = 0;
//    for (int j = 0; j <= 1512; j++)
//    {
//        times++;
//        char* intptr = (char*)single_client_alloc::allocate(j);
//        char* intptr1 = (char*)single_client_alloc::allocate(j);
//        int mod = 0;
//        int i;
//        if (intptr != NULL)
//            memset(intptr, 0, j); //3000ms
//        single_client_alloc::deallocate(intptr, j);
//        single_client_alloc::deallocate(intptr1, j);
//        if (j >= 1512) j = 0;
//        if (times >= 100000) break;
//    }
//    single_client_alloc::destroy();
//}

TEST(test_case_hash, test_sockaddr2hashcode)
{
    sockaddrunion localsu;
    str2saddr(&localsu, "192.168.1.107", 36000);
    sockaddrunion peersu;
    str2saddr(&peersu, "192.168.1.107", 36000);
    EVENTLOG1(VERBOSE, "hash(addr pair { localsu: 192.168.1.107:36000 peersu: 192.168.1.107:36000 }) = %u", sockaddr2hashcode(&localsu, &peersu));

    str2saddr(&localsu, "192.168.1.107", 36001);
    str2saddr(&peersu, "192.168.1.107", 36000);
    EVENTLOG1(VERBOSE, "hash(addr pair { localsu: 192.168.1.107:36001 peersu: 192.168.1.107:36000 }) = %u", sockaddr2hashcode(&localsu, &peersu));
}
