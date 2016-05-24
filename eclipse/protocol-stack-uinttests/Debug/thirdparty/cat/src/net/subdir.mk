################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/DNSClient.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/IOThreads.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/Sockets.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/UDPEndpoint.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/UDPRecvAllocator.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/UDPSendAllocator.cpp 

OBJS += \
./thirdparty/cat/src/net/DNSClient.o \
./thirdparty/cat/src/net/IOThreads.o \
./thirdparty/cat/src/net/Sockets.o \
./thirdparty/cat/src/net/UDPEndpoint.o \
./thirdparty/cat/src/net/UDPRecvAllocator.o \
./thirdparty/cat/src/net/UDPSendAllocator.o 

CPP_DEPS += \
./thirdparty/cat/src/net/DNSClient.d \
./thirdparty/cat/src/net/IOThreads.d \
./thirdparty/cat/src/net/Sockets.d \
./thirdparty/cat/src/net/UDPEndpoint.d \
./thirdparty/cat/src/net/UDPRecvAllocator.d \
./thirdparty/cat/src/net/UDPSendAllocator.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/net/DNSClient.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/DNSClient.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/net/IOThreads.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/IOThreads.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/net/Sockets.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/Sockets.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/net/UDPEndpoint.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/UDPEndpoint.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/net/UDPRecvAllocator.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/UDPRecvAllocator.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/net/UDPSendAllocator.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/net/UDPSendAllocator.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


