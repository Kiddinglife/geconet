#include "gtest/gtest.h"
#include "gmock/gmock.h"
//#include "globals.h"
#include "protoco-stack.h"
#include <iostream>

TEST(MULP, test_initialize_and_free_library)
{
	initialize_library();
	free_library();
}

TEST(MULP, test_mulp_get_lib_params)
{
	//precondition lib has been inited
	initialize_library();

	lib_params_t lib_infos;
	mulp_get_lib_params(&lib_infos);
	ASSERT_EQ(lib_infos.checksum_algorithm, MULP_CHECKSUM_ALGORITHM_MD5);
	ASSERT_EQ(lib_infos.delayed_ack_interval, 200);
	ASSERT_EQ(lib_infos.send_ootb_aborts, true);
	ASSERT_EQ(lib_infos.support_dynamic_addr_config, true);
	ASSERT_EQ(lib_infos.support_particial_reliability, true);

	free_library();
}

TEST(MULP, test_mulp_set_lib_params)
{
	//precondition lib has been inited
	initialize_library();

	lib_params_t lib_infos;
	mulp_get_lib_params(&lib_infos);

	lib_infos.checksum_algorithm = MULP_CHECKSUM_ALGORITHM_CRC32C;
	lib_infos.delayed_ack_interval = 50; // must be smaller than 500ms
	lib_infos.send_ootb_aborts = false;
	lib_infos.support_dynamic_addr_config = false;
	lib_infos.support_particial_reliability = false;
	mulp_set_lib_params(&lib_infos);

	mulp_get_lib_params(&lib_infos);
	ASSERT_EQ(lib_infos.checksum_algorithm, MULP_CHECKSUM_ALGORITHM_CRC32C);
	ASSERT_EQ(lib_infos.delayed_ack_interval, 50);
	ASSERT_EQ(lib_infos.send_ootb_aborts, false);
	ASSERT_EQ(lib_infos.support_dynamic_addr_config, false);
	ASSERT_EQ(lib_infos.support_particial_reliability, false);

	free_library();
}

//int mulp_new_geco_instance(unsigned short localPort,
//	unsigned short noOfInStreams,
//	unsigned short noOfOutStreams,
//	unsigned int noOfLocalAddresses,
//	unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN],
//	ulp_cbs_t ULPcallbackFunctions);
//int mulp_remove_geco_instnce(int instance_name);
TEST(MULP, test_mulp_mulp_new_and_delete_geco_instnce)
{
	//precondition lib has been inited
	initialize_library();
	unsigned short localPort = 123;
	unsigned short noOfInStreams = 32;
	unsigned short noOfOutStreams = 32;
	unsigned int noOfLocalAddresses = 2;
	unsigned char localAddressList[MAX_NUM_ADDRESSES][MAX_IPADDR_STR_LEN] = { "0.0.0.0", "::0" };
	ulp_cbs_t ULPcallbackFunctions = { 0 };
	int instid = mulp_new_geco_instance(localPort, noOfInStreams, noOfOutStreams, noOfLocalAddresses, localAddressList, ULPcallbackFunctions);
	//TODO VERIFY ALL STATS IN GECO INSTANCE
	geco_instance_t* instptr = 0;
	mulp_delete_geco_instance(instid);
	free_library();
}


TEST(MULP, test_mulp_mulp_remove_geco_instnce)
{
	//precondition lib has been inited
	initialize_library();
	free_library();
}