################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/iocp/AsyncFile.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/iocp/IOThreadPools.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/iocp/UDPEndpoint.cpp 

OBJS += \
./thirdparty/cat/src/iocp/AsyncFile.o \
./thirdparty/cat/src/iocp/IOThreadPools.o \
./thirdparty/cat/src/iocp/UDPEndpoint.o 

CPP_DEPS += \
./thirdparty/cat/src/iocp/AsyncFile.d \
./thirdparty/cat/src/iocp/IOThreadPools.d \
./thirdparty/cat/src/iocp/UDPEndpoint.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/iocp/AsyncFile.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/iocp/AsyncFile.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/iocp/IOThreadPools.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/iocp/IOThreadPools.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/iocp/UDPEndpoint.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/iocp/UDPEndpoint.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


