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
    error_log1(major_error_abort, "module2", 12, "test log file %d", 12);
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
static bool action(timer_id_t& id, void*, void*)
{
    event_log(loglvl_intevent, "timer triggered\n");
    return NOT_RESET_TIMER_FROM_CB;
}
#include <vector>
static void test_timer_mgr()
{
    timer_mgr tm;
    timer_id_t ret1 = tm.add_timer(TIMER_TYPE_INIT, 1000, action);
    timer_id_t ret2 = tm.add_timer(TIMER_TYPE_SACK, 1, action);
    timer_id_t ret3 = tm.add_timer(TIMER_TYPE_SACK, 15, action);
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
    ushort port = 0;
    saddr2str(&saddr, ret, sizeof(ret), &port);
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
    transport_layer_t nit;
    ret = nit.open_ipproto_geco_socket(AF_INET);
    assert(ret > 0);
    ret = nit.open_ipproto_geco_socket(AF_INET6);
    assert(ret > 0);

    sockaddrunion saddr;
    str2saddr(&saddr, "127.0.0.1", 38000);
    assert(saddr.sa.sa_family == AF_INET);
    ret = nit.open_ipproto_udp_socket(&saddr);
    assert(ret > 0);
}

static void test_send_udp_msg()
{

    transport_layer_t nit;

    int geco_sdespt = nit.open_ipproto_geco_socket(AF_INET);
    assert(geco_sdespt > 0);
    nit.ip4_socket_despt_ = geco_sdespt;

    sockaddrunion saddr;
    str2saddr(&saddr, "127.0.0.1", 38000, true);
    int udpsdepst = nit.open_ipproto_udp_socket(&saddr);
    assert(udpsdepst < 0);
    int sampledata = 27;
    int sentsize = nit.send_udp_packet(udpsdepst, (char*)&sampledata, sizeof(int),
        &saddr);
    assert(sentsize == sizeof(int));
    // this will get error  to send udp data on geco sdespt
    //sentsize = nit.send_udp_msg(geco_sdespt, (char*)&sampledata,
    //    sizeof(int),
    //    "127.0.0.1", 38000);
}

static void test_send_geco_msg()
{
    transport_layer_t nit;

    int geco_sdespt = nit.open_ipproto_geco_socket(AF_INET);
    assert(geco_sdespt > 0);
    nit.ip4_socket_despt_ = geco_sdespt;

    sockaddrunion saddr;
    str2saddr(&saddr, "127.0.0.1", 38000);

    int sampledata = 27;
    int sentsize = nit.send_ip_packet(geco_sdespt, (char*)&sampledata,
        sizeof(int), &saddr, 3);
    assert(sentsize == sizeof(int));
}

static void test_init_poller()
{
    int rcwnd = 1234567;
    transport_layer_t nit;
    nit.init(&rcwnd, true);
}

static void test_recv_geco_msg()
{
    int rcwnd = 123;
    transport_layer_t nit;
    nit.init(&rcwnd, true);

    sockaddrunion saddr;
    str2saddr(&saddr, "127.0.0.1", USED_UDP_PORT);
    int sampledata = 27;
    uchar tos = IPTOS_DEFAULT;
    int sentsize = nit.send_ip_packet(nit.ip4_socket_despt_, (char*)&sampledata,
        sizeof(int), &saddr, tos);
    assert(sentsize == sizeof(int));
    u_long iMode = 1;
    sockaddrunion from;
    sockaddrunion to;
    char buffer[65535];
    int recvsize = 0;
    recvsize = nit.recv_ip_packet(nit.ip4_socket_despt_, buffer, sizeof(buffer),
        &from, &to);
    assert(recvsize == IP_HDR_SIZE + sizeof(int));
    assert(*(int*)(buffer + IP_HDR_SIZE) == 27);
}

static void test_send_recv_udp_msg()
{
    int rcwnd = 1234;
    transport_layer_t nit;
    nit.init(&rcwnd, true);

    sockaddrunion saddr;
    str2saddr(&saddr, "127.0.0.1", 38000, true);
    int udpsdepst = nit.open_ipproto_udp_socket(&saddr);
    assert(udpsdepst > 0);

    int sampledata = 27;
    int sentsize = nit.send_udp_packet(udpsdepst, (char*)&sampledata, sizeof(int),
        &saddr);
    assert(sentsize == sizeof(int));

    char dest[128];
    sockaddrunion saddr1;
    socklen_t length = sizeof(saddr1);
    sentsize = (int)nit.recv_udp_packet(udpsdepst, dest, 128, &saddr1, &length);
    assert(sentsize == sizeof(int));
    assert(*(int*)dest == 27);
}

static void fd_action_sctp(int sfd, char* data, int datalen,
    const char* addr, ushort port)
{
}
static void fd_action_udp(int sfd, char* data, int datalen,
    const char* addr, ushort port)
{
}
static void fd_action_rounting(int sfd, char* data, int datalen,
    const char* addr, ushort port)
{
}
static void test_add_remove_fd()
{
    // !!! comment wsaselect() in poller::set_event_on_win32_sdespt() 
    // if you run this unit test
    poller_t poller;
    poller.cbunion_.socket_cb_fun = fd_action_sctp;
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_,
        (void*)1);
    poller.cbunion_.socket_cb_fun = fd_action_udp;
    poller.set_expected_event_on_fd(2, EVENTCB_TYPE_UDP, POLLIN, poller.cbunion_,
        (void*)2);
    poller.cbunion_.socket_cb_fun = fd_action_rounting;
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN,
        poller.cbunion_, (void*)1);

    int size = poller.remove_event_handler(1);
    assert(size == 2);
    size = poller.remove_event_handler(200);
    assert(size == 0);
    size = poller.remove_event_handler(200);
    assert(size == 0);
    size = poller.remove_event_handler(2);
    assert(size == 1);
    assert(poller.socket_despts_size_ == 0);
    poller.cbunion_.socket_cb_fun = fd_action_rounting;
    poller.set_expected_event_on_fd(3, EVENTCB_TYPE_ROUTING, POLLIN,
        poller.cbunion_, (void*)1);
    assert(poller.socket_despts_size_ == 1);
    assert(
        poller.socket_despts[poller.socket_despts_size_].event_handler_index
        == 0);
    assert(
        poller.event_callbacks[poller.socket_despts[poller.socket_despts_size_].event_handler_index].action.socket_cb_fun
        == fd_action_rounting);

    size = poller.remove_event_handler(3);
    assert(size == 1);
    assert(poller.socket_despts_size_ == 0);

    size = poller.remove_event_handler(200);
    assert(size == 0);
    assert(poller.socket_despts_size_ == 0);
    for (int i = 0; i < MAX_FD_SIZE; i++)
    {
        assert(poller.socket_despts[i].fd == -1);
    }

    memset(&poller.cbunion_, 0, sizeof(cbunion_t));
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_, (void*)1);
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_UDP, POLLIN, poller.cbunion_, (void*)2);
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN, poller.cbunion_, (void*)1);
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN, poller.cbunion_, (void*)1);
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_ROUTING, POLLIN, poller.cbunion_, (void*)1);
    size = poller.remove_event_handler(1);
    assert(size == 5);
    assert(poller.socket_despts_size_ == 0);

    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_, (void*)1);
    size = poller.remove_event_handler(1);
    assert(size == 1);
    assert(poller.socket_despts_size_ == 0);

    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_, (void*)1);
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_, (void*)1);
    size = poller.remove_event_handler(1);
    assert(size == 2);
    assert(poller.socket_despts_size_ == 0);

    poller.set_expected_event_on_fd(2, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_, (void*)1);
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_, (void*)1);
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_, (void*)1);
    size = poller.remove_event_handler(1);
    assert(size == 2);
    assert(poller.socket_despts_size_ == 1);
    assert(
        poller.event_callbacks[poller.socket_despts[0].event_handler_index].action.socket_cb_fun
        == fd_action_sctp);
    assert(
        poller.event_callbacks[poller.socket_despts[0].event_handler_index].sfd
        == 2);

    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_, (void*)1);
    poller.set_expected_event_on_fd(2, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_,
        (void*)1);
    poller.set_expected_event_on_fd(1, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_, (void*)1);
    poller.set_expected_event_on_fd(2, EVENTCB_TYPE_SCTP, POLLIN, poller.cbunion_,
        (void*)1);
    size = poller.remove_event_handler(1);
    assert(size == 2);
    assert(poller.socket_despts_size_ == 3);
    assert(
        poller.event_callbacks[poller.socket_despts[0].event_handler_index].action.socket_cb_fun
        == fd_action_sctp);
    assert(
        poller.event_callbacks[poller.socket_despts[1].event_handler_index].action.socket_cb_fun
        == fd_action_sctp);
    printf("ALl Done\n");
}
static transport_layer_t nit;
static bool flag = true;
static void process_stdin(char* data, size_t datalen)
{
    event_logii(verbose, "process_stdin()::recvied %d bytes of %s data  from stdin", datalen, data);

    if (strcmp(data, "q") == 0)
    {
        flag = false;
        return;
    }

    sockaddrunion saddr;
    str2saddr(&saddr, "127.0.0.1", USED_UDP_PORT);
    int sampledata = 27;
    uchar tos = IPTOS_DEFAULT;
    int sentsize = nit.send_ip_packet(nit.ip4_socket_despt_, data,
        datalen, &saddr, tos);
    assert(sentsize == datalen);
}
static void socket_cb(int sfd, char* data, int datalen,
    const char* addr, ushort port)
{
    event_logiii(verbose, "socket_cb()::recvied  %d bytes of data %s from dctp fd %d\n",
        datalen, data, sfd);
}
static bool timer_cb(timer_id_t& tid, void* a1, void* a2)
{
    event_logii(verbose, "timer_cb(id %d, type->%d)::\n", tid->timer_id, tid->timer_type);
    nit.restart_timer(tid, 1000);
    return true;
}
static void test_pollsss()
{
    int rcwnd = 512;
    nit.init(&rcwnd, true);

    nit.cbunion_.socket_cb_fun = socket_cb;
    nit.poller_.set_expected_event_on_fd(nit.ip4_socket_despt_, EVENTCB_TYPE_SCTP, POLLIN | POLLPRI, nit.cbunion_, 0);
    // you have to put stdin as last because we test it 
    nit.poller_.add_stdin_cb(process_stdin);
    nit.start_timer(1000, timer_cb, TIMER_TYPE_INIT, 0, 0);
    while (flag)
        nit.poller_.poll();
    nit.poller_.timer_mgr_.timers.clear();
    nit.poller_.remove_stdin_cb();
    nit.poller_.remove_event_handler(nit.ip4_socket_despt_);
}

static void test_getlocaladdr()
{
    int rcwnd = 512;
    nit.init(&rcwnd, true);

    sockaddrunion* saddr = 0;
    int num = 0;
    int maxmtu = 0;
    ushort port = 0;
    char addr[MAX_IPADDR_STR_LEN];
    hide_address_flag_t t = (hide_address_flag_t)(flag_HideLocal | flag_Default);
    nit.get_local_addresses(&saddr, &num, nit.ip4_socket_despt_, true, &maxmtu, t);

    event_logi(verbose, "max mtu  %d\n", maxmtu);

    if (saddr != NULL)
        for (int i = 0; i < num; i++)
        {
            saddr2str(saddr + i, addr, MAX_IPADDR_STR_LEN, &port);
            event_logii(verbose, "ip address %s port %d\n", addr, port);
        }

    sockaddrunion addrs[MAX_COUNT_LOCAL_IP_ADDR];
    num = nit.get_local_ip_addresses(addrs);
    for (int i = 0; i < num; i++)
    {
        saddr2str(addrs + i, addr, MAX_IPADDR_STR_LEN, &port);
        event_logii(verbose, "ip address %s port %d\n", addr, port);
    }
}

//#define GECO_PRINTS
#include "geco-ds-malloc.h"
static void test_alloc_pool()
{
    char* intptr = (char*)geco::ds::single_client_alloc::allocate(8);
    assert(intptr != 0);
    geco::ds::single_client_alloc::deallocate(intptr, 8);

    intptr = (char*)geco::ds::alloc::allocate(8);
    assert(intptr != 0);
    geco::ds::alloc::deallocate(intptr, 8);

    geco::ds::single_client_alloc::destroy();
    geco::ds::alloc::destroy();
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
    // test_init_poller();
    // test_recv_geco_msg();
    // test_send_recv_udp_msg();
    // test_add_remove_fd();
    //std::cin.get();
    //test_pollsss();
    //test_getlocaladdr();
    test_alloc_pool();
    return 0;
}
