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
