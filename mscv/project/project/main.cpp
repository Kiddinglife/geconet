#include "globals.h"
#include <iostream>
int main(int arg, char** args)
{
    read_trace_levels();
    extern FILE* logfile;
    debug_print(logfile, "%s, %d", "new line", 12);
    std::cin.get();
    return 0;
}