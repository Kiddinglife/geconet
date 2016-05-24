################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/db/BombayTable.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/db/BombayTableIndex.cpp 

OBJS += \
./thirdparty/cat/src/db/BombayTable.o \
./thirdparty/cat/src/db/BombayTableIndex.o 

CPP_DEPS += \
./thirdparty/cat/src/db/BombayTable.d \
./thirdparty/cat/src/db/BombayTableIndex.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/db/BombayTable.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/db/BombayTable.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/db/BombayTableIndex.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/db/BombayTableIndex.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


