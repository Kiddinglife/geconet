################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
/home/jackiez/20160219/geco-protocol-stack/unittets/test-main.cc \
/home/jackiez/20160219/geco-protocol-stack/unittets/test-mbu.cc \
/home/jackiez/20160219/geco-protocol-stack/unittets/test-mulp.cc 

CPP_SRCS += \
/home/jackiez/20160219/geco-protocol-stack/unittets/test-dispatcher-module.cpp \
/home/jackiez/20160219/geco-protocol-stack/unittets/unit_tests.cpp 

CC_DEPS += \
./unittets/test-main.d \
./unittets/test-mbu.d \
./unittets/test-mulp.d 

OBJS += \
./unittets/test-dispatcher-module.o \
./unittets/test-main.o \
./unittets/test-mbu.o \
./unittets/test-mulp.o \
./unittets/unit_tests.o 

CPP_DEPS += \
./unittets/test-dispatcher-module.d \
./unittets/unit_tests.d 


# Each subdirectory must supply rules for building sources it contributes
unittets/test-dispatcher-module.o: /home/jackiez/20160219/geco-protocol-stack/unittets/test-dispatcher-module.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -DSERVER_BUILD -DTEST -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googletest/include -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googlemock/include -I/home/jackiez/20160219/geco-protocol-stack/src -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

unittets/test-main.o: /home/jackiez/20160219/geco-protocol-stack/unittets/test-main.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -DSERVER_BUILD -DTEST -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googletest/include -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googlemock/include -I/home/jackiez/20160219/geco-protocol-stack/src -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

unittets/test-mbu.o: /home/jackiez/20160219/geco-protocol-stack/unittets/test-mbu.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -DSERVER_BUILD -DTEST -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googletest/include -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googlemock/include -I/home/jackiez/20160219/geco-protocol-stack/src -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

unittets/test-mulp.o: /home/jackiez/20160219/geco-protocol-stack/unittets/test-mulp.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -DSERVER_BUILD -DTEST -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googletest/include -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googlemock/include -I/home/jackiez/20160219/geco-protocol-stack/src -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

unittets/unit_tests.o: /home/jackiez/20160219/geco-protocol-stack/unittets/unit_tests.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -DSERVER_BUILD -DTEST -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googletest/include -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googlemock/include -I/home/jackiez/20160219/geco-protocol-stack/src -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


