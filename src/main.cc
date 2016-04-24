//============================================================================
// Name        : wheel-linux-sctp.cpp
// Author      : Jackie
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
//

#include <globals.h>
#include <iostream>
#include <assert.h>
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
    const char* testdata = "HelloJake";
    MD5_CTX ctx;
    MD5Init(&ctx);
    MD5Update(&ctx, (uchar*)testdata, strlen(testdata));
    MD5Final(dest, &ctx);
    //event_log1(loglvl_extevent, "test_md5", "digest of 'HelloJake' {%x}\n",dest);
    event_logi(loglvl_extevent, "test_md5, digest of HelloJake {%x}\n", dest);
}

#include "gecotimer.h"
static void action(TimerID id, void*, void*)
{
    event_log(loglvl_intevent, "timer triggered\n");
}
#include <vector>
static void test_timer_mgr()
{
    timer_mgr tm;
    timer_mgr::timer_id_t ret1 = tm.add_timer(TIMER_TYPE_INIT, 1000, action);
    timer_mgr::timer_id_t ret2 = tm.add_timer(TIMER_TYPE_SACK, 1, action);
    timer_mgr::timer_id_t ret3 = tm.add_timer(TIMER_TYPE_SACK, 15, action);
    tm.print(loglvl_intevent);
    tm.delete_timer(ret1);
    tm.delete_timer(ret2);
    tm.print(loglvl_intevent);

}
#include <algorithm>
#include <iostream>
#include <iterator>
#include <vector>
#include <list>

using namespace std;
void test_std_find()
{
    //    vector<int> v;
    //    vector<int>::iterator iter;
    //    pair<vector<int>::iterator, vector<int>::iterator> vecpair;
    list<int> v;
    list<int>::iterator iter;
    pair<list<int>::iterator, list<int>::iterator> vecpair;
    for (int i = 1; i <= 20; i++)
    {
        if (i % 6 != 2)
            v.push_back(i % 6);
    }

    //sort(v.begin(), v.end());
    v.sort();
    cout << "array: " << endl << "  ";
    copy(v.begin(), v.end(), ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  lower_bound */
    cout << "lower_bound function, value = 3: " << endl;
    iter = lower_bound(v.begin(), v.end(), 3);
    cout << "  [first, iter] = ";
    copy(v.begin(), iter, ostream_iterator<int>(cout, " "));
    cout << endl;
    cout << "  [iter, last] = ";
    copy(iter, v.end(), ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  upper_bound */
    cout << "upper_bound function, value = 3: " << endl;
    iter = upper_bound(v.begin(), v.end(), 3);
    cout << "  [first, iter] = ";
    copy(v.begin(), iter, ostream_iterator<int>(cout, " "));
    cout << endl;
    cout << "  [iter, last] = ";
    copy(iter, v.end(), ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  equal_range */
    cout << "euqual_range function value = 3: " << endl;
    vecpair = equal_range(v.begin(), v.end(), 3);
    cout << " [vecpair->first, vecpair->second] = ";
    copy(vecpair.first, vecpair.second, ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  lower_bound */
    cout << "lower_bound function, value = 2: " << endl;
    iter = lower_bound(v.begin(), v.end(), 2);
    cout << "  [first, iter] = ";
    copy(v.begin(), iter, ostream_iterator<int>(cout, " "));
    cout << endl;
    cout << "  [iter, last] = ";
    copy(iter, v.end(), ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  upper_bound */
    cout << "upper_bound function, value = 2: " << endl;
    iter = upper_bound(v.begin(), v.end(), 2);
    cout << "  [first, iter] = ";
    copy(v.begin(), iter, ostream_iterator<int>(cout, " "));
    cout << endl;
    cout << "  [iter, last] = ";
    copy(iter, v.end(), ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  equal_range */
    cout << "euqual_range function value = 2: " << endl;
    vecpair = equal_range(v.begin(), v.end(), 2);
    cout << " [vecpair->first, vecpair->second] = ";
    copy(vecpair.first, vecpair.second, ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  lower_bound */
    cout << "lower_bound function, value = 9: " << endl;
    iter = lower_bound(v.begin(), v.end(), 9);
    cout << "  [first, iter] = ";
    copy(v.begin(), iter, ostream_iterator<int>(cout, " "));
    cout << endl;
    cout << "  [iter, last] = ";
    copy(iter, v.end(), ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  upper_bound */
    cout << "upper_bound function, value = 9: " << endl;
    iter = upper_bound(v.begin(), v.end(), 9);
    cout << "  [first, iter] = ";
    copy(v.begin(), iter, ostream_iterator<int>(cout, " "));
    cout << endl;
    cout << "  [iter, last] = ";
    copy(iter, v.end(), ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  equal_range */
    cout << "euqual_range function value = 9: " << endl;
    vecpair = equal_range(v.begin(), v.end(), 9);
    cout << " [vecpair->first, vecpair->second] = ";
    copy(vecpair.first, vecpair.second, ostream_iterator<int>(cout, " "));
    cout << endl << endl;
    /*  lower_bound */
    cout << "lower_bound function, value = -1: " << endl;
    iter = lower_bound(v.begin(), v.end(), -1);
    cout << "  [first, iter] = ";
    copy(v.begin(), iter, ostream_iterator<int>(cout, " "));
    cout << endl;
    cout << "  [iter, last] = ";
    copy(iter, v.end(), ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  upper_bound */
    cout << "upper_bound function, value = -1: " << endl;
    iter = upper_bound(v.begin(), v.end(), -1);
    cout << "  [first, iter] = ";
    copy(v.begin(), iter, ostream_iterator<int>(cout, " "));
    cout << endl;
    cout << "  [iter, last] = ";
    copy(iter, v.end(), ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  equal_range */
    cout << "euqual_range function value = -1: " << endl;
    vecpair = equal_range(v.begin(), v.end(), -1);
    cout << " [vecpair->first, vecpair->second] = ";
    copy(vecpair.first, vecpair.second, ostream_iterator<int>(cout, " "));
    cout << endl << endl;

    /*  binary_search */
    cout << "binary_search function value = 3: " << endl;
    cout << "3 is " << (binary_search(v.begin(), v.end(), 3) ? "" : "not ")
        << " in array" << endl;
    cout << endl;

    /*  binary_search */
    cout << "binary_search function value = : " << endl;
    cout << "6 is " << (binary_search(v.begin(), v.end(), 6) ? "" : "not ")
        << " in array" << endl;
    cout << endl;

    /**
     array:
     0 0 0 1 1 1 1 3 3 3 4 4 4 5 5 5

     lower_bound function, value = 3:
     [first, iter] = 0 0 0 1 1 1 1
     [iter, last] = 3 3 3 4 4 4 5 5 5

     upper_bound function, value = 3:
     [first, iter] = 0 0 0 1 1 1 1 3 3 3
     [iter, last] = 4 4 4 5 5 5

     euqual_range function value = 3:
     [vecpair->first, vecpair->second] = 3 3 3

     lower_bound function, value = 2:
     [first, iter] = 0 0 0 1 1 1 1
     [iter, last] = 3 3 3 4 4 4 5 5 5

     upper_bound function, value = 2:
     [first, iter] = 0 0 0 1 1 1 1
     [iter, last] = 3 3 3 4 4 4 5 5 5

     euqual_range function value = 2:
     [vecpair->first, vecpair->second] =

     binary_search function value = 3:
     3 is  in array

     binary_search function value = :
     6 is not  in array
     */
}
static void test_add_sub_time()
{
    timeval tv;
    fills_timeval(&tv, 1000);

    timeval result;
    sum_time(&tv, 200, &result);
    print_timeval(&result);
    assert(result.tv_sec == 1);
    assert(result.tv_usec == 200000);
    sum_time(&result, 800, &result);
    print_timeval(&result);
    assert(result.tv_sec == 2);
    assert(result.tv_usec == 0);
    subtract_time(&result, 800, &result);
    print_timeval(&result);
    assert(result.tv_sec == 1);
    assert(result.tv_usec == 200000);
    subtract_time(&result, 200, &result);
    print_timeval(&result);
    assert(result.tv_sec == 1);
    assert(result.tv_usec == 0);
    subtract_time(&result, 1000, &result);
    print_timeval(&result);
    assert(result.tv_sec == 0);
    assert(result.tv_usec == 0);
}

#include "poller.h"
static void test_saddr_functions()
{
    sockaddrunion saddr;
    str2saddr(&saddr, "192.168.1.107", 38000);

    char ret[IF_NAMESIZE];
    saddr2str(&saddr, ret, sizeof(ret));
    event_logi(loglvl_intevent, "saddr {%s}\n", ret);
    assert(strcmp(ret, "192.168.1.107") == 0);
    assert(saddr.sa.sa_family == AF_INET);

    sockaddrunion saddr1;
    str2saddr(&saddr1, "192.168.1.107", 38000);
    sockaddrunion saddr2;
    str2saddr(&saddr2, "192.168.1.107", 38000);
    bool flag = saddr_equals(&saddr1, &saddr2);
    assert(flag == true);

    str2saddr(&saddr1, "192.167.1.125", 38000);
    str2saddr(&saddr2, "192.168.1.107", 38000);
    flag = saddr_equals(&saddr1, &saddr2);
    assert(flag == false);

    str2saddr(&saddr1, "192.168.1.107", 3800);
    str2saddr(&saddr2, "192.168.1.107", 38000);
    flag = saddr_equals(&saddr1, &saddr2);
    assert(flag == false);

    str2saddr(&saddr1, "192.168.1.125", 3800);
    str2saddr(&saddr2, "192.168.1.107", 38000);
    flag = saddr_equals(&saddr1, &saddr2);
    assert(flag == false);
}

static void test_open_socket()
{
    int ret;
    WSADATA winsockInfo;
    WSAStartup(MAKEWORD(2, 2), &winsockInfo);

    network_interface_t nit;
    ret = nit.open_ipproto_geco_socket(AF_INET);
    assert(ret > 0);
    ret = nit.open_ipproto_geco_socket(AF_INET6);
    assert(ret > 0);

    sockaddrunion saddr;
    str2saddr(&saddr, "127.0.0.1", 38000);
    assert(saddr.sa.sa_family == AF_INET);
    ret = nit.open_ipproto_udp_socket(&saddr);
    assert(ret > 0);

    WSACleanup();
}

static void test_send_udp_msg()
{
    WSADATA winsockInfo;
    WSAStartup(MAKEWORD(2, 2), &winsockInfo);

    network_interface_t nit;

    int geco_sdespt = nit.open_ipproto_geco_socket(AF_INET);
    assert(geco_sdespt > 0);
    nit.ip4_socket_despt_ = geco_sdespt;

    sockaddrunion saddr;
    str2saddr(&saddr, "127.0.0.1", 38000, true);
    int udpsdepst = nit.open_ipproto_udp_socket(&saddr);
    assert(udpsdepst < 0);
    int sampledata = 27;
    int sentsize = nit.send_udp_msg(udpsdepst, (char*)&sampledata,
        sizeof(int), &saddr);
    assert(sentsize == sizeof(int));
    // this will get error  to send udp data on geco sdespt
    //sentsize = nit.send_udp_msg(geco_sdespt, (char*)&sampledata,
    //    sizeof(int),
    //    "127.0.0.1", 38000);
    WSACleanup();
}

static void test_send_geco_msg()
{
    WSADATA winsockInfo;
    WSAStartup(MAKEWORD(2, 2), &winsockInfo);

    network_interface_t nit;

    int geco_sdespt = nit.open_ipproto_geco_socket(AF_INET);
    assert(geco_sdespt > 0);
    nit.ip4_socket_despt_ = geco_sdespt;

    sockaddrunion saddr;
    str2saddr(&saddr, "127.0.0.1", 38000);

    int sampledata = 27;
    int sentsize = nit.send_geco_msg(geco_sdespt, (char*)&sampledata,
        sizeof(int), &saddr, 3);
    assert(sentsize == sizeof(int));

    WSACleanup();
}

static void test_init_poller()
{
    int rcwnd = 1234567;
    network_interface_t nit;
    nit.init_poller(&rcwnd, true);

}
int main(int arg, char** args)
{
    // get_random();
    //test_logging();
    //test_md5();
    //test_std_find();
    //test_timer_mgr();
    //test_add_sub_time();
    //test_saddr_functions();
    // test_open_socket();
    //  test_send_udp_msg();
    //test_send_geco_msg();
    test_init_poller();
    std::cin.get();
    return 0;
}
