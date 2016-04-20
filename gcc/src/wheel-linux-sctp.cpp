//============================================================================
// Name        : wheel-linux-sctp.cpp
// Author      : Jackie
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
//
#include "globals.h"
#include <iostream>
static void test_logging()
{
    read_trace_levels();
    event_log1(loglvl_extevent, "module1", "test log file %d", 12);
    error_log1(loglvl_fatal_error_exit, "module2", 12, "test log file %d", 12);
    error_log1(loglvl_major_error_abort, "module2", 12, "test log file %d", 12);
}

#include "md5.h"
static void test_md5()
{
    uchar dest[16];
    char* testdata = "HelloJake";
    MD5_CTX ctx;
    MD5Init(&ctx);
    MD5Update(&ctx, (uchar*)testdata, strlen(testdata));
    MD5Final(dest, &ctx);
    event_log1(loglvl_extevent, "test_md5", "::digest of 'HelloJake' {%s}",dest);
}
int main(int arg, char** args)
{
    test_logging();
    test_md5();
    std::cin.get();
    return 0;
}
