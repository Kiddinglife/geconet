#include <iostream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "spdlog/spdlog.h"
namespace spd = spdlog;

#if GTEST_OS_WINDOWS_MOBILE
# include <tchar.h>  // NOLINT
GTEST_API_ int _tmain(int argc, TCHAR** argv)
{
#else
  GTEST_API_ int
  main (int argc, char** argv)
  {
#endif  // GTEST_OS_WINDOWS_MOBILE

    // Console logger with color
    auto console = spd::stdout_color_mt ("console");
    //    console->info ("Welcome to spdlog!");
    //    console->error ("Some error message with arg{}..", 1);
    //    // Formatting examples
    //    console->warn("Easy padding in numbers like {:08d}", 12);
    //    console->critical("Support for int: {0:d};  hex: {0:x};  oct: {0:o}; bin: {0:b}", 42);
    //    console->info("Support for floats {:03.2f}", 1.23456);
    //    console->info("Positional args are {1} {0}..", "too", "supported");
    //	  console->info("{:>30}", "left aligned");
    //	  spd::get ("console")->info("loggers can be retrieved from a global registry using the spdlog::get(logger_name) function");
    //    // Create basic file logger (not rotated)
    //    auto my_logger = spd::basic_logger_mt("basic_logger", "logs/basic.txt");
    //    my_logger->info("Some log message");
    //    // Create a file rotating logger with 5mb size max and 3 rotated files
    //    auto rotating_logger = spd::rotating_logger_mt("some_logger_name", "logs/mylogfile", 1048576 * 5, 3);
    //    for (int i = 0; i < 10; ++i)
    //        rotating_logger->info("{} * {} equals {:>10}", i, i, i*i);
    //    auto daily_logger = spd::daily_logger_mt("daily_logger", "logs/daily", 2, 30);
    //    // trigger flush if the log severity is error or higher
    //    daily_logger->flush_on(spd::level::err);
    //    daily_logger->info(123.44);
    //    // Customize msg format for all messages
    //    spd::set_pattern("*** [%H:%M:%S %z] [thread %t] %v ***");
    //    rotating_logger->info("This is another message with custom format");
    //    // Runtime log levels
    spd::set_level (spd::level::trace); //Set global log level to info
    //    console->debug("This message shold not be displayed!");
    //    console->set_level(spd::level::debug); // Set specific logger's log level
    //    console->debug("This message shold be displayed..");

    // Since Google Mock depends on Google Test, InitGoogleMock() is
    // also responsible for initializing Google Test.  Therefore there's
    // no need for calling testing::InitGoogleTest() separately.
    testing::InitGoogleMock (&argc, argv);

    //::testing::GTEST_FLAG(filter) = "GLOBAL_MODULE.*";

    // ::testing::GTEST_FLAG(filter) = "TIMER_MODULE.*";
    //::testing::GTEST_FLAG(filter) = "TIMER_MODULE.test_operations_on_time";
    // ::testing::GTEST_FLAG(filter) = "TIMER_MODULE.test_timer_mgr";
    //::testing::GTEST_FLAG(filter) = "TIMER_MODULE.test_wheel_timer";
    //::testing::GTEST_FLAG(filter) = "TIMER_MODULE.test_bitops";

    // ::testing::GTEST_FLAG(filter) = "MALLOC_MODULE.*";
    // ::testing::GTEST_FLAG(filter) = "MALLOC_MODULE.test_alloc_dealloc";
    // ::testing::GTEST_FLAG(filter) = "MALLOC_MODULE.test_geco_alloc_dealloc";
    // ::testing::GTEST_FLAG(filter) = "MALLOC_MODULE.test_geco_new_delete";

    // ::testing::GTEST_FLAG(filter) = "AUTH_MODULE.*";

    //::testing::GTEST_FLAG(filter) = "UT_HELPER.*";
    //::testing::GTEST_FLAG(filter) = "UT_HELPER.test_make_geco_instance";
    //::testing::GTEST_FLAG(filter) = "UT_HELPER.test_make_geco_channel";

    //::testing::GTEST_FLAG(filter) = "mpath.*";  // passed on 28/02/2017

    //::testing::GTEST_FLAG(filter) = "mpath.test_alg0";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "mpath.test_replace_empty_space";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "mpath.test_reverse_list";  // passed on 28/02/2017
    ::testing::GTEST_FLAG(filter) = "mpath.test_is_pop_order";  // passed on 28/02/2017

    //::testing::GTEST_FLAG(filter) = "mpath.test_set_paths";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "mpath.test_handle_chunks_retx";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "mpath.test_new_and_free";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "mpath.test_heartbeat_timer_expired";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "mpath.test_update_rtt";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "mpath.test_data_chunk_acked";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "mpath.test_hb_ack_received";  // passed on 28/02/2017

    // last pass on 31 Oct 2016
    //::testing::GTEST_FLAG(filter) = "MULP.*";
    //::testing::GTEST_FLAG(filter) = "MULP.test_unused_port";
    //::testing::GTEST_FLAG(filter) = "MULP.test_alloc_and_free_port";
    //::testing::GTEST_FLAG(filter) = "MULP.test_initialize_and_free_library";
    //::testing::GTEST_FLAG(filter) = "MULP.test_mulp_get_lib_params";
    //::testing::GTEST_FLAG(filter) = "MULP.test_mulp_set_lib_params";
    //::testing::GTEST_FLAG(filter) = "MULP.test_mulp_mulp_new_and_delete_geco_instnce";
    //::testing::GTEST_FLAG(filter) = "MULP.test_mdi_new_and_delete_channel";
    //::testing::GTEST_FLAG(filter) = "MULP.test_mulp_connect";
    // current unit test summary locally connection all Ok: loopback 127.0.0.1 and ::1, localaddr 192.168.... cross-machina connection NOT ok
    // ::testing::GTEST_FLAG(filter) = "MULP.test_connection_pharse";

    //::testing::GTEST_FLAG(filter) = "MBU.*";
    //::testing::GTEST_FLAG(filter) = "MBU.test_mbu_new";

    //::testing::GTEST_FLAG(filter) = "TRANSPORT_MODULE.test_process_stdin";

    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.*";
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_find_geco_instance"; // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_find_channel"; // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_bundle_ctrl_chunk";
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_recv_geco_packet";
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_read_peer_addreslist";
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_contain_local_addr"; // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_find_first_chunk_of";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_find_chunk_types";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_validate_dest_addr";
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_find_vlparam_from_setup_chunk"; // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) = "DISPATCHER_MODULE.test_contains_chunk";  // passed on 28/02/2017
    //::testing::GTEST_FLAG(filter) ="DISPATCHER_MODULE.test_mdis_find_geco_instance";

    // Release and close all loggers
    int ret = RUN_ALL_TESTS ();
    spdlog::drop_all ();
    return ret;
  }
