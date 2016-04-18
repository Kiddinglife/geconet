//============================================================================
// Name        : wheel-linux-sctp.cpp
// Author      : Jackie
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
//
#include "my_wheel_src/globals.h"
#include <iostream>
#include <assert.h>
int main(int arg, char** args)
{
    read_trace_levels();
    extern FILE* logfile;
    debug_print(logfile, "%s, %d", "new line", 12);
    std::cin.get();
    return 0;
}
