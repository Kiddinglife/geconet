################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/src/auth.cc \
/home/jakez/2016209/geco-sctp-cplus/src/dispatch_layer.cc \
/home/jakez/2016209/geco-sctp-cplus/src/gecotimer.cc \
/home/jakez/2016209/geco-sctp-cplus/src/globals.cc \
/home/jakez/2016209/geco-sctp-cplus/src/poller.cc 

CC_DEPS += \
./src/auth.d \
./src/dispatch_layer.d \
./src/gecotimer.d \
./src/globals.d \
./src/poller.d 

OBJS += \
./src/auth.o \
./src/dispatch_layer.o \
./src/gecotimer.o \
./src/globals.o \
./src/poller.o 


# Each subdirectory must supply rules for building sources it contributes
src/auth.o: /home/jakez/2016209/geco-sctp-cplus/src/auth.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++0x -I"/home/jakez/2016209/geco-sctp-cplus/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

src/dispatch_layer.o: /home/jakez/2016209/geco-sctp-cplus/src/dispatch_layer.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++0x -I"/home/jakez/2016209/geco-sctp-cplus/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

src/gecotimer.o: /home/jakez/2016209/geco-sctp-cplus/src/gecotimer.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++0x -I"/home/jakez/2016209/geco-sctp-cplus/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

src/globals.o: /home/jakez/2016209/geco-sctp-cplus/src/globals.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++0x -I"/home/jakez/2016209/geco-sctp-cplus/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

src/poller.o: /home/jakez/2016209/geco-sctp-cplus/src/poller.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -std=c++0x -I"/home/jakez/2016209/geco-sctp-cplus/include" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


