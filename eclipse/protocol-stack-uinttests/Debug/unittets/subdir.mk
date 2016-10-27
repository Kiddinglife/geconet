################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
/home/jackiez/20160219/geco-protocol-stack/unittets/test-main.cc \
/home/jackiez/20160219/geco-protocol-stack/unittets/test-mbu.cc \
/home/jackiez/20160219/geco-protocol-stack/unittets/test-mulp.cc 

CPP_SRCS += \
/home/jackiez/20160219/geco-protocol-stack/unittets/test-mdi.cpp \
/home/jackiez/20160219/geco-protocol-stack/unittets/test-mtra.cpp 

CC_DEPS += \
./unittets/test-main.d \
./unittets/test-mbu.d \
./unittets/test-mulp.d 

OBJS += \
./unittets/test-main.o \
./unittets/test-mbu.o \
./unittets/test-mdi.o \
./unittets/test-mtra.o \
./unittets/test-mulp.o 

CPP_DEPS += \
./unittets/test-mdi.d \
./unittets/test-mtra.d 


# Each subdirectory must supply rules for building sources it contributes
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

unittets/test-mdi.o: /home/jackiez/20160219/geco-protocol-stack/unittets/test-mdi.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -DSERVER_BUILD -DTEST -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googletest/include -I/home/jackiez/20160219/geco-protocol-stack/thirdparty/googlemock/include -I/home/jackiez/20160219/geco-protocol-stack/src -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

unittets/test-mtra.o: /home/jackiez/20160219/geco-protocol-stack/unittets/test-mtra.cpp
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


