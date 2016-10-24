#include "gtest/gtest.h"
#include "gmock/gmock.h"
//#include "globals.h"
#include "protoco-stack.h"
#include <iostream>

/**
 * Function that needs to be called in advance to all library calls.
 * It initializes all file descriptors etc. and sets up some variables
 * @return 0 for success, 1 for adaptation level error, -1 if already called
 * (i.e. the function has already been called before), -2 for insufficient rights
 * (you need root-rights to open RAW sockets !).
 */
extern int initialize_library(void);
TEST(MULP, test_initialize_library)
{
  initialize_library ();
}

TEST(MULP, test_mulp_get_lib_params)
{
  //precondition lib has been inited
  initialize_library();

  lib_infos_t lib_infos;
  mulp_get_lib_params (&lib_infos);
  EXPECT_EQ(lib_infos.checksum_algorithm, MULP_CHECKSUM_ALGORITHM_MD5);
  EXPECT_EQ(lib_infos.delayed_ack_interval, 200);
  EXPECT_EQ(lib_infos.send_ootb_aborts, true);
  EXPECT_EQ(lib_infos.support_dynamic_addr_config, true);
  EXPECT_EQ(lib_infos.support_particial_reliability, true);
}

TEST(MULP, test_mulp_set_lib_params)
{
  //precondition lib has been inited
  initialize_library();

  lib_infos_t lib_infos;
  mulp_get_lib_params (&lib_infos);

  lib_infos.checksum_algorithm = MULP_CHECKSUM_ALGORITHM_CRC32C;
  lib_infos.delayed_ack_interval = 50; // must be smaller than 500ms
  lib_infos.send_ootb_aborts = false;
  lib_infos.support_dynamic_addr_config = false;
  lib_infos.support_particial_reliability = false;
  mulp_set_lib_params (&lib_infos);

  mulp_get_lib_params (&lib_infos);
  EXPECT_EQ(lib_infos.checksum_algorithm, MULP_CHECKSUM_ALGORITHM_CRC32C);
  EXPECT_EQ(lib_infos.delayed_ack_interval, 50);
  EXPECT_EQ(lib_infos.send_ootb_aborts, false);
  EXPECT_EQ(lib_infos.support_dynamic_addr_config, false);
  EXPECT_EQ(lib_infos.support_particial_reliability, false);
}

