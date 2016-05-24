################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/SecureCompare.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/SecureEqual.cpp 

OBJS += \
./thirdparty/cat/src/crypt/SecureCompare.o \
./thirdparty/cat/src/crypt/SecureEqual.o 

CPP_DEPS += \
./thirdparty/cat/src/crypt/SecureCompare.d \
./thirdparty/cat/src/crypt/SecureEqual.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/crypt/SecureCompare.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/SecureCompare.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/SecureEqual.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/SecureEqual.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


