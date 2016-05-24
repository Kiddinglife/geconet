################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/AlignedAllocator.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/BufferAllocator.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/IAllocator.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/LargeAllocator.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/ReuseAllocator.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/StdAllocator.cpp 

OBJS += \
./thirdparty/cat/src/mem/AlignedAllocator.o \
./thirdparty/cat/src/mem/BufferAllocator.o \
./thirdparty/cat/src/mem/IAllocator.o \
./thirdparty/cat/src/mem/LargeAllocator.o \
./thirdparty/cat/src/mem/ReuseAllocator.o \
./thirdparty/cat/src/mem/StdAllocator.o 

CPP_DEPS += \
./thirdparty/cat/src/mem/AlignedAllocator.d \
./thirdparty/cat/src/mem/BufferAllocator.d \
./thirdparty/cat/src/mem/IAllocator.d \
./thirdparty/cat/src/mem/LargeAllocator.d \
./thirdparty/cat/src/mem/ReuseAllocator.d \
./thirdparty/cat/src/mem/StdAllocator.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/mem/AlignedAllocator.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/AlignedAllocator.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/mem/BufferAllocator.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/BufferAllocator.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/mem/IAllocator.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/IAllocator.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/mem/LargeAllocator.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/LargeAllocator.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/mem/ReuseAllocator.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/ReuseAllocator.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/mem/StdAllocator.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/mem/StdAllocator.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


