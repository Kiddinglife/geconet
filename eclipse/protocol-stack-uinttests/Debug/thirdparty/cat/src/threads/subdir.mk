################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/Mutex.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/RWLock.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/Thread.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/WaitableFlag.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/WorkerThreads.cpp 

OBJS += \
./thirdparty/cat/src/threads/Mutex.o \
./thirdparty/cat/src/threads/RWLock.o \
./thirdparty/cat/src/threads/Thread.o \
./thirdparty/cat/src/threads/WaitableFlag.o \
./thirdparty/cat/src/threads/WorkerThreads.o 

CPP_DEPS += \
./thirdparty/cat/src/threads/Mutex.d \
./thirdparty/cat/src/threads/RWLock.d \
./thirdparty/cat/src/threads/Thread.d \
./thirdparty/cat/src/threads/WaitableFlag.d \
./thirdparty/cat/src/threads/WorkerThreads.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/threads/Mutex.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/Mutex.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/threads/RWLock.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/RWLock.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/threads/Thread.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/Thread.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/threads/WaitableFlag.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/WaitableFlag.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/threads/WorkerThreads.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/threads/WorkerThreads.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


