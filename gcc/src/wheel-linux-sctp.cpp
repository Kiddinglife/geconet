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
    MD5Update(&ctx, (uchar*) testdata, strlen(testdata));
    MD5Final(dest, &ctx);
    //event_log1(loglvl_extevent, "test_md5", "digest of 'HelloJake' {%x}\n",dest);
    event_logi(loglvl_extevent, "test_md5, digest of HelloJake {%x}\n", dest);
}

#include "gecotimer.h"
static void action(TimerID id, void*, void*)
{
    event_log(loglvl_intevent, "timer triggered\n");
}
static void test_timer_mgr()
{
    geco::ultils::timer_mgr tm;
    uint id = tm.add_timer(TIMER_TYPE_INIT, 100,action);
    event_logi(loglvl_intevent, "added timer id {%ld}",id);
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

int main(int arg, char** args)
{
    //test_logging();
    //test_md5();
    //test_std_find();
    test_timer_mgr();
    std::cin.get();
    return 0;
}
