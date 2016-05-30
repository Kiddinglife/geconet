################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/unittets/test-main.cc 

CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/unittets/unit_tests.cpp 

CC_DEPS += \
./unittets/test-main.d 

OBJS += \
./unittets/test-main.o \
./unittets/unit_tests.o 

CPP_DEPS += \
./unittets/unit_tests.d 


# Each subdirectory must supply rules for building sources it contributes
unittets/test-main.o: /home/jakez/2016209/geco-sctp-cplus/unittets/test-main.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

unittets/unit_tests.o: /home/jakez/2016209/geco-sctp-cplus/unittets/unit_tests.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


