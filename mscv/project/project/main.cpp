#include "globals.h"
#include <iostream>
int main(int arg, char** args)
{
    read_trace_levels();
    event_log1(loglvl_extevent, "module1", "test log file %d", 12);
    error_log1(loglvl_fatal_error_exit, "module2", 12, "test log file %d", 12);
    error_log1(loglvl_major_error_abort, "module2", 12,"test log file %d", 12);
    std::cin.get();
    return 0;
}